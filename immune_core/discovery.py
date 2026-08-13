from __future__ import annotations

import os
import platform
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Protocol

from .audit import AuditLedger
from .observability import AnomalyDetector, DependencyGraph, ObservabilityStore, SignalProcessor


class Sensor(Protocol):
    sensor_id: str
    def collect(self) -> Iterable[dict[str, Any]]: ...


@dataclass(frozen=True)
class DiscoveryCycle:
    started_at: float
    completed_at: float
    sensors_total: int
    sensors_ok: int
    sensors_failed: int
    resources_seen: int
    dependencies_seen: int
    signals_seen: int
    duplicates_suppressed: int
    anomalies: int
    evidence_id: str
    inventory_sha256: str


class HostSensor:
    """Zero-dependency host discovery. Richer OSS sensors can attach via adapters."""
    sensor_id = "builtin-host"

    def collect(self) -> Iterable[dict[str, Any]]:
        now = time.time()
        hostname = platform.node() or "localhost"
        root = Path.home().anchor or "/"
        usage = shutil.disk_usage(root)
        yield {"type":"resource","resource_id":f"host:{hostname}","kind":"host","name":hostname,"attributes":{"platform":platform.system(),"release":platform.release(),"machine":platform.machine(),"python":platform.python_version()}}
        yield {"type":"resource","resource_id":f"process:{os.getpid()}","kind":"process","name":Path(sys.executable).name,"attributes":{"pid":os.getpid(),"executable":str(Path(sys.executable).resolve())}}
        yield {"type":"dependency","src":f"process:{os.getpid()}","dst":f"host:{hostname}","relation":"runs_on","attributes":{}}
        yield {"type":"metric","name":"disk.used_ratio","subject":f"host:{hostname}","value":(usage.used/usage.total) if usage.total else 0.0,"labels":{"path":root},"ts":now}
        if hasattr(os,"getloadavg"):
            yield {"type":"metric","name":"load.1m","subject":f"host:{hostname}","value":float(os.getloadavg()[0]),"labels":{},"ts":now}


class PathSensor:
    def __init__(self, sensor_id: str, paths: Iterable[str | Path]):
        self.sensor_id = str(sensor_id)
        self.paths = tuple(Path(p).expanduser() for p in paths)

    def collect(self) -> Iterable[dict[str, Any]]:
        for path in self.paths:
            resolved = path.resolve(strict=False)
            exists = resolved.exists()
            attrs: dict[str, Any] = {"path":str(resolved),"exists":exists}
            if exists:
                st=resolved.stat(); attrs.update({"size":int(st.st_size),"mtime_ns":int(st.st_mtime_ns),"is_dir":resolved.is_dir()})
            yield {"type":"resource","resource_id":f"path:{resolved}","kind":"filesystem","name":resolved.name or str(resolved),"attributes":attrs}
            yield {"type":"signal","kind":"path_health","subject":f"path:{resolved}","severity":"info" if exists else "error","attributes":{"exists":exists,"correlation_key":f"path:{resolved}"}}


class TCPHealthSensor:
    """Compatibility guard: protected-system network checks belong to Immune Gateway."""
    def __init__(self, *args, **kwargs):
        raise RuntimeError("direct network health sensor disabled; use immune_gateway adapter")

class DonorSensorAdapter:
    """Adapter boundary: donor presence never grants execution or authority."""
    def __init__(self, lab_result: Any, collector: Any):
        decision=getattr(lab_result,"decision",None); decision_value=getattr(decision,"value",decision)
        if decision_value != "approved": raise PermissionError("donor sensor is not laboratory-approved")
        if getattr(lab_result,"authority",None) != "adapter-only": raise PermissionError("donor sensor authority must be adapter-only")
        if bool(getattr(lab_result,"executable",True)): raise PermissionError("donor sensor may not be directly executable")
        if not callable(collector): raise TypeError("collector adapter must be callable")
        self.sensor_id=f"donor:{getattr(lab_result,'donor_id','unknown')}"; self._collector=collector
    def collect(self) -> Iterable[dict[str, Any]]: yield from self._collector()


class DiscoveryEngine:
    """Repeated discovery cycles with failure isolation and evidence-first persistence."""
    def __init__(self, sensors: Iterable[Sensor], observability: ObservabilityStore, processor: SignalProcessor, anomaly: AnomalyDetector, *, audit: AuditLedger | None = None):
        self.sensors=tuple(sensors)
        if not self.sensors: raise ValueError("at least one sensor is required")
        ids=[str(s.sensor_id) for s in self.sensors]
        if len(ids)!=len(set(ids)): raise ValueError("sensor ids must be unique")
        self.observability=observability; self.processor=processor; self.anomaly=anomaly; self.graph=DependencyGraph(observability); self.audit=audit

    def run_cycle(self, *, mission_id: str | None = None, now: float | None = None) -> DiscoveryCycle:
        started=time.time() if now is None else float(now)
        sensors_ok=sensors_failed=resources=dependencies=signals=duplicates=anomalies=0; cycle_events=[]
        for sensor in self.sensors:
            sensor_id=str(sensor.sensor_id)
            try:
                observations=list(sensor.collect()); self.observability.update_sensor_health(sensor_id,ok=True,ts=started); sensors_ok+=1
            except Exception as exc:
                sensors_failed+=1; self.observability.update_sensor_health(sensor_id,ok=False,error=f"{type(exc).__name__}: {exc}",ts=started)
                processed=self.processor.ingest("discovery-engine",{"kind":"sensor_failure","subject":sensor_id,"severity":"error","attributes":{"sensor_id":sensor_id,"error_type":type(exc).__name__,"correlation_key":f"sensor:{sensor_id}"}},ts=started)
                signals+=1; duplicates+=int(processed.duplicate); cycle_events.append({"sensor":sensor_id,"status":"failed","error_type":type(exc).__name__}); continue
            for obs in observations:
                typ=str(obs.get("type","")).lower()
                if typ=="resource":
                    self.observability.upsert_resource(str(obs["resource_id"]),str(obs.get("kind","resource")),str(obs.get("name",obs["resource_id"])),dict(obs.get("attributes") or {}),ts=started); resources+=1
                elif typ=="dependency":
                    self.graph.add(str(obs["src"]),str(obs["dst"]),str(obs.get("relation","depends_on")),attributes=dict(obs.get("attributes") or {}),ts=started); dependencies+=1
                elif typ=="metric":
                    metric_ts=float(obs.get("ts",started)); result=self.anomaly.observe(str(obs["name"]),str(obs["subject"]),float(obs["value"]),ts=metric_ts,labels=dict(obs.get("labels") or {}))
                    if result["anomaly"]:
                        processed=self.processor.ingest("anomaly-detector",{"kind":"metric_anomaly","subject":str(obs["subject"]),"severity":"warning","attributes":{"metric":str(obs["name"]),"value":float(obs["value"]),"baseline":result["baseline"],"score":result["score"],"correlation_key":f"metric:{obs['subject']}:{obs['name']}"}},ts=metric_ts)
                        anomalies+=1; signals+=1; duplicates+=int(processed.duplicate)
                elif typ=="signal":
                    processed=self.processor.ingest(sensor_id,obs,ts=started); signals+=1; duplicates+=int(processed.duplicate)
                elif typ=="log":
                    self.observability.record_log(sensor_id,str(obs.get("level","INFO")),str(obs.get("message","")),fields=dict(obs.get("fields") or {}),ts=float(obs.get("ts",started)))
                else:
                    processed=self.processor.ingest("discovery-engine",{"kind":"invalid_sensor_observation","subject":sensor_id,"severity":"warning","attributes":{"observation_type":typ or "missing","correlation_key":f"sensor:{sensor_id}"}},ts=started); signals+=1; duplicates+=int(processed.duplicate)
            cycle_events.append({"sensor":sensor_id,"status":"ok","observations":len(observations)})
        snapshot=self.observability.inventory_snapshot(); completed=time.time() if now is None else float(now)
        evidence=self.observability.evidence(kind="discovery_cycle",mission_id=mission_id,ts=completed,payload={"started_at":started,"completed_at":completed,"sensors_total":len(self.sensors),"sensors_ok":sensors_ok,"sensors_failed":sensors_failed,"events":cycle_events,"inventory_sha256":snapshot["sha256"],"resources_seen":resources,"dependencies_seen":dependencies,"signals_seen":signals,"duplicates_suppressed":duplicates,"anomalies":anomalies})
        if self.audit: self.audit.append(actor="discovery-engine",action="discovery_cycle_completed",mission_id=mission_id,payload={"evidence_id":evidence.id,"inventory_sha256":snapshot["sha256"],"sensors_failed":sensors_failed},now=completed)
        return DiscoveryCycle(started,completed,len(self.sensors),sensors_ok,sensors_failed,resources,dependencies,signals,duplicates,anomalies,evidence.id,snapshot["sha256"])
