from __future__ import annotations

import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from immune_core.audit import AuditLedger
from immune_core.discovery import DiscoveryEngine, DonorSensorAdapter, HostSensor, PathSensor, TCPHealthSensor
from immune_core.observability import AnomalyDetector, DependencyGraph, ObservabilityStore, SignalProcessor
from immune_core.storage import SQLiteStateStore
from immune_lab.admission import Decision, LabResult, build_catalog

class StaticSensor:
    def __init__(self,sensor_id,observations): self.sensor_id=sensor_id; self.observations=observations
    def collect(self): return list(self.observations)
class FailingSensor:
    sensor_id="failing"
    def collect(self): raise RuntimeError("synthetic sensor failure")

class Phase5Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name); self.state=SQLiteStateStore(self.root/"state.db"); self.audit=AuditLedger(self.state); self.obs=ObservabilityStore(self.state,self.audit); self.processor=SignalProcessor(self.obs,dedupe_window_seconds=60,correlation_window_seconds=300); self.anomaly=AnomalyDetector(self.obs,min_samples=5,threshold=4.0)
    def tearDown(self): self.state.close(); self.tmp.cleanup()
    def test_inventory_digest_reproducible(self):
        self.obs.upsert_resource("r:1","service","one",{"version":"1"},ts=1); a=self.obs.inventory_snapshot(); self.obs.upsert_resource("r:1","service","one",{"version":"1"},ts=2); b=self.obs.inventory_snapshot(); self.assertEqual(a["sha256"],b["sha256"])
    def test_signal_dedup_and_correlation(self):
        o={"kind":"health","subject":"svc:a","severity":"error","attributes":{"incident_key":"inc:a","reachable":False}}; first=self.processor.ingest("s1",o,ts=100); second=self.processor.ingest("s2",o,ts=101); self.assertFalse(first.duplicate); self.assertTrue(second.duplicate); self.assertEqual(first.correlation_count,1); self.assertEqual(second.correlation_count,1)
    def test_anomaly_uses_prior_baseline(self):
        for i,v in enumerate((10.0,10.1,9.9,10.0,10.05),1): self.assertFalse(self.anomaly.observe("cpu","host:a",v,ts=float(i))["anomaly"])
        self.assertTrue(self.anomaly.observe("cpu","host:a",90.0,ts=10.0)["anomaly"])
    def test_sensor_failure_is_isolated_and_health_persisted(self):
        good=StaticSensor("good",[{"type":"resource","resource_id":"svc:ok","kind":"service","name":"ok","attributes":{}}]); cycle=DiscoveryEngine([FailingSensor(),good],self.obs,self.processor,self.anomaly,audit=self.audit).run_cycle(mission_id="m",now=100); self.assertEqual(cycle.sensors_ok,1); self.assertEqual(cycle.sensors_failed,1); self.assertEqual(self.obs.sensor_health("good")["state"],"HEALTHY"); self.assertEqual(self.obs.sensor_health("failing")["state"],"DEGRADED"); self.assertTrue(self.obs.verify_evidence(cycle.evidence_id))
    def test_repeated_failures_mark_sensor_failed(self):
        engine=DiscoveryEngine([FailingSensor()],self.obs,self.processor,self.anomaly)
        for i in range(3): engine.run_cycle(now=100+i)
        self.assertEqual(self.obs.sensor_health("failing")["state"],"FAILED")
    def test_dependency_graph(self):
        graph=DependencyGraph(self.obs); graph.add("app","db",ts=1); graph.add("api","app",ts=1); self.assertEqual(graph.upstream("app"),["db"]); self.assertEqual(graph.downstream("app"),["api"])
    def test_evidence_tamper_detection(self):
        ref=self.obs.evidence(kind="proof",payload={"x":1},ts=1); self.assertTrue(self.obs.verify_evidence(ref.id)); self.state.conn.execute("UPDATE obs_evidence SET payload_json=? WHERE id=?",('{"x":2}',ref.id)); self.state.conn.commit(); self.assertFalse(self.obs.verify_evidence(ref.id))
    def test_logs_and_traces_are_structured(self):
        digest=self.obs.record_log("sensor","warning","message",fields={"k":"v"},ts=1); self.assertEqual(len(digest),64); trace,span=self.obs.start_span("cycle",ts=1); self.obs.end_span(span,status="OK",attributes={"count":1},ts=2); row=self.state.conn.execute("SELECT * FROM obs_traces WHERE span_id=?",(span,)).fetchone(); self.assertEqual(row["trace_id"],trace); self.assertEqual(row["status"],"OK")
    def test_host_sensor_discovers_host_without_external_dependency(self):
        observations=list(HostSensor().collect()); self.assertTrue(any(o["type"]=="resource" and o["kind"]=="host" for o in observations)); self.assertTrue(any(o["type"]=="metric" for o in observations))
    def test_path_sensor_health(self):
        path=self.root/"present.txt"; path.write_text("ok"); signals=[o for o in PathSensor("paths",[path,self.root/"missing"]).collect() if o["type"]=="signal"]; self.assertEqual([s["severity"] for s in signals],["info","error"])
    def test_tcp_health_check_configured_endpoint(self):
        listener=socket.socket(); listener.bind(("127.0.0.1",0)); listener.listen(1); port=listener.getsockname()[1]; done=threading.Event()
        def accept_once():
            try: conn,_=listener.accept(); conn.close()
            finally: listener.close(); done.set()
        threading.Thread(target=accept_once,daemon=True).start(); observations=list(TCPHealthSensor("tcp-test","127.0.0.1",port,timeout_seconds=1).collect()); done.wait(2); health=[o for o in observations if o["type"]=="signal"][0]; self.assertTrue(health["attributes"]["reachable"])
    def test_real_donors_are_not_autoapproved(self):
        lock=json.loads((Path(__file__).resolve().parents[2]/"donors"/"LOCK.json").read_text(encoding="utf-8")); catalog=build_catalog(lock["donors"]); self.assertEqual(catalog["summary"]["total"],44); self.assertEqual(catalog["summary"]["approved"],0); self.assertTrue(all(not item["executable"] for item in catalog["donors"]))
    def test_donor_adapter_rejects_quarantined(self):
        result=LabResult("d","sensor",Decision.QUARANTINED,"none",False,("security_scan",),"missing")
        with self.assertRaises(PermissionError): DonorSensorAdapter(result,lambda:[])
    def test_donor_adapter_accepts_only_adapter_only_nonexecutable(self):
        result=LabResult("d","sensor",Decision.APPROVED,"adapter-only",False,(),"ok"); adapter=DonorSensorAdapter(result,lambda:[{"type":"resource","resource_id":"d:r","kind":"service","name":"d","attributes":{}}]); self.assertEqual(list(adapter.collect())[0]["resource_id"],"d:r")
    def test_cycle_detects_metric_anomaly_without_stopping(self):
        for i,v in enumerate((10,10,10,10,10),1): DiscoveryEngine([StaticSensor(f"s{i}",[{"type":"metric","name":"latency","subject":"svc","value":v}])],self.obs,self.processor,self.anomaly).run_cycle(now=float(i))
        cycle=DiscoveryEngine([StaticSensor("spike",[{"type":"metric","name":"latency","subject":"svc","value":100}])],self.obs,self.processor,self.anomaly).run_cycle(now=10); self.assertEqual(cycle.anomalies,1)
    def test_audit_chain_valid_after_cycles(self):
        engine=DiscoveryEngine([HostSensor()],self.obs,self.processor,self.anomaly,audit=self.audit); engine.run_cycle(mission_id="m",now=1); engine.run_cycle(mission_id="m",now=2); valid,bad_seq=self.audit.verify_chain(); self.assertTrue(valid,bad_seq)

if __name__=="__main__": unittest.main()
