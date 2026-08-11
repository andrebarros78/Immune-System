#!/usr/bin/env python3
from __future__ import annotations
import ast,hashlib,json,sys,tempfile
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from immune_core.audit import AuditLedger
from immune_core.discovery import DiscoveryEngine
from immune_core.observability import AnomalyDetector,DependencyGraph,ObservabilityStore,SignalProcessor
from immune_core.storage import SQLiteStateStore
from immune_lab.admission import build_catalog
checks=[]; failures=[]
def ok(name,condition,detail=""):
    passed=bool(condition); checks.append({"name":name,"passed":passed,"detail":str(detail)})
    if not passed: failures.append(name)
for phase in (1,2,3,4):
    path=ROOT/f"PHASE{phase}_STATUS.md"; ok(f"phase{phase}_baseline_proven",path.is_file() and f"PHASE{phase}_PROVEN" in path.read_text(encoding="utf-8"))
required=["immune_core/observability.py","immune_core/discovery.py","tests/phase5/test_discovery.py","scripts/validate_phase5.py","adr/ADR-0005-discovery-observability.md",".github/workflows/phase5-observability.yml"]
for rel in required: ok(f"artifact:{rel}",(ROOT/rel).is_file())
for rel in ("immune_core/observability.py","immune_core/discovery.py"):
    try: ast.parse((ROOT/rel).read_text(encoding="utf-8")); ok(f"ast:{rel}",True)
    except SyntaxError as exc: ok(f"ast:{rel}",False,exc)
obs_text=(ROOT/"immune_core/observability.py").read_text(encoding="utf-8"); disc_text=(ROOT/"immune_core/discovery.py").read_text(encoding="utf-8")
ok("vendor_neutral_models","ObservabilityStore" in obs_text and "SignalProcessor" in obs_text); ok("signal_deduplication","recent_fingerprint_count" in obs_text); ok("signal_correlation","recent_correlation_count" in obs_text); ok("robust_baseline_anomaly","statistics.median" in obs_text and "mad" in obs_text.lower()); ok("evidence_sha256","payload_sha256" in obs_text and "verify_evidence" in obs_text); ok("structured_metrics","obs_metrics" in obs_text); ok("structured_logs","obs_logs" in obs_text); ok("structured_traces","obs_traces" in obs_text); ok("sensor_health_isolated","consecutive_failures" in obs_text and "continue" in disc_text); ok("dependency_graph","DependencyGraph" in obs_text); ok("configured_health_check","TCPHealthSensor" in disc_text and "does not scan arbitrary ports" in disc_text); ok("donor_adapter_gate",'decision_value != "approved"' in disc_text and "adapter-only" in disc_text and "executable" in disc_text)
lock=json.loads((ROOT/"donors/LOCK.json").read_text(encoding="utf-8")); catalog=build_catalog(lock["donors"]); ok("donor_inventory_44",catalog["summary"]["total"]==44,catalog["summary"]); ok("real_donors_still_unapproved",catalog["summary"]["approved"]==0,catalog["summary"]); ok("real_donors_no_authority",all(item["authority"]=="none" and not item["executable"] for item in catalog["donors"]))
class GoodSensor:
    sensor_id="proof-good"
    def __init__(self,value): self.value=value
    def collect(self): return [{"type":"resource","resource_id":"service:api","kind":"service","name":"api","attributes":{"version":"1"}},{"type":"dependency","src":"service:api","dst":"service:db","relation":"depends_on","attributes":{}},{"type":"metric","name":"latency","subject":"service:api","value":self.value},{"type":"signal","kind":"health_check","subject":"service:api","severity":"info","attributes":{"reachable":True,"correlation_key":"service:api"}},{"type":"log","level":"INFO","message":"healthy","fields":{"service":"api"}}]
class BadSensor:
    sensor_id="proof-bad"
    def collect(self): raise RuntimeError("sensor-down")
with tempfile.TemporaryDirectory() as td:
    state=SQLiteStateStore(Path(td)/"state.db"); audit=AuditLedger(state); obs=ObservabilityStore(state,audit); processor=SignalProcessor(obs,dedupe_window_seconds=60,correlation_window_seconds=300); anomaly=AnomalyDetector(obs,min_samples=5,threshold=4)
    for i,value in enumerate((10.0,10.0,10.0,10.0,10.0),1): DiscoveryEngine([GoodSensor(value)],obs,processor,anomaly,audit=audit).run_cycle(mission_id="m",now=float(i))
    spike=DiscoveryEngine([BadSensor(),GoodSensor(100.0)],obs,processor,anomaly,audit=audit).run_cycle(mission_id="m",now=10.0); ok("e2e_sensor_failure_isolated",spike.sensors_failed==1 and spike.sensors_ok==1); ok("e2e_anomaly_detected",spike.anomalies==1); ok("e2e_evidence_persisted",obs.verify_evidence(spike.evidence_id)); snap1=obs.inventory_snapshot(); obs.upsert_resource("service:api","service","api",{"version":"1"},ts=11); snap2=obs.inventory_snapshot(); ok("e2e_inventory_reproducible",snap1["sha256"]==snap2["sha256"]); ok("e2e_dependency_mapped","service:db" in DependencyGraph(obs).upstream("service:api")); hg=obs.sensor_health("proof-good"); hb=obs.sensor_health("proof-bad"); ok("e2e_health_states",hg["state"]=="HEALTHY" and hb["state"]=="DEGRADED"); trace,span=obs.start_span("proof",ts=10); obs.end_span(span,status="OK",ts=11); ok("e2e_trace_available",state.conn.execute("SELECT COUNT(*) FROM obs_traces WHERE trace_id=?",(trace,)).fetchone()[0]==1); ok("e2e_logs_available",state.conn.execute("SELECT COUNT(*) FROM obs_logs").fetchone()[0]>=1); valid,bad_seq=audit.verify_chain(); ok("e2e_audit_chain_valid",valid and bad_seq is None,bad_seq); state.close()
controlled=["immune_core/observability.py","immune_core/discovery.py","tests/phase5/test_discovery.py","scripts/validate_phase5.py","adr/ADR-0005-discovery-observability.md",".github/workflows/phase5-observability.yml"]; hashes={rel:hashlib.sha256((ROOT/rel).read_bytes()).hexdigest() for rel in controlled}; summary={"total":len(checks),"passed":sum(1 for c in checks if c["passed"]),"failed":len(failures)}; evidence={"schema":1,"phase":"PHASE_5_DISCOVERY_AND_OBSERVABILITY","validated_at":datetime.now(timezone.utc).isoformat(),"checks":checks,"summary":summary,"controlled_file_sha256":hashes,"result":"PHASE5_PROVEN" if not failures else "PHASE5_FAILED","scope_note":"PHASE5_PROVEN proves vendor-neutral discovery, observability, signal processing, evidence persistence and failure-isolated sensors. Real donor sensors remain unapproved until laboratory evidence exists. It is not MISSION_PROVEN for the complete product."}; (ROOT/"evidence").mkdir(exist_ok=True); (ROOT/"evidence/phase5-validation.json").write_text(json.dumps(evidence,indent=2,ensure_ascii=False,sort_keys=True)+"\n",encoding="utf-8"); status=evidence["result"]; (ROOT/"PHASE5_STATUS.md").write_text("# Fase 5 — Descoberta e Observabilidade\n\n"+f"**Estado: {status}**\n\n"+f"Checks: {summary['passed']}/{summary['total']} aprovados.\n\n"+"Capacidades: descoberta reproduzível, sensores isolados, métricas/logs/traces, health checks configurados, normalização, deduplicação, correlação, baseline/anomalias, mapa de dependências e evidência SHA-256.\n\nDoadores OSS reais permanecem sem autoridade automática; o produto completo permanece sem MISSION_PROVEN.\n",encoding="utf-8"); print(json.dumps(summary,sort_keys=True));
if failures: print("FAILED:",", ".join(failures)); raise SystemExit(1)
print("PHASE5_PROVEN")
