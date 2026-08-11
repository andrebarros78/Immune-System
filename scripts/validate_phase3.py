#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_core.audit import AuditLedger
from immune_core.checkpoints import CheckpointManager, WorkspaceManager
from immune_core.engine import DurableLoopEngine
from immune_core.execution import PrivilegedExecutor, SafeExecutor, WorkerManifest
from immune_core.identity import IdentityAuthority
from immune_core.policy import PolicyGuard
from immune_core.privilege import PrivilegeAuthority, PrivilegeError
from immune_core.storage import SQLiteStateStore
from immune_core.workers import WorkerRunner

checks=[]
failures=[]
def ok(name, condition, detail=""):
    passed=bool(condition); checks.append({"name":name,"passed":passed,"detail":str(detail)})
    if not passed: failures.append(name)

ok("phase1_baseline_proven", "PHASE1_PROVEN" in (ROOT/"PHASE1_STATUS.md").read_text(encoding="utf-8"))
ok("phase2_baseline_proven", "PHASE2_PROVEN" in (ROOT/"PHASE2_STATUS.md").read_text(encoding="utf-8"))
required=["immune_core/checkpoints.py","immune_core/privilege.py","immune_core/execution.py","immune_core/workers.py","tests/phase3/test_execution.py","adr/ADR-0003-isolated-execution.md",".github/workflows/phase3-execution.yml"]
for rel in required: ok(f"artifact:{rel}",(ROOT/rel).is_file())
execution_text=(ROOT/"immune_core/execution.py").read_text(encoding="utf-8")
priv_text=(ROOT/"immune_core/privilege.py").read_text(encoding="utf-8")
checkpoint_text=(ROOT/"immune_core/checkpoints.py").read_text(encoding="utf-8")
worker_text=(ROOT/"immune_core/workers.py").read_text(encoding="utf-8")
markers={
"execution_no_shell":"shell=False" in execution_text,
"execution_stdin_disabled":"stdin=subprocess.DEVNULL" in execution_text,
"execution_timeout":"timeout=timeout" in execution_text,
"execution_active_mission_barrier":"ACTIVE_EXECUTION_STATES" in execution_text,
"execution_allowlist":"executable outside worker allowlist" in execution_text,
"execution_minimal_environment":"environment variable not allowlisted" in execution_text,
"execution_task_lease_binding":"worker does not own task lease" in execution_text,
"privilege_one_use_table":"used_privilege_grants" in priv_text,
"privilege_ttl_300":"MAX_TTL_SECONDS = 300" in priv_text,
"privilege_exact_target":"privilege grant target mismatch" in priv_text,
"checkpoint_hash_inventory":"sha256" in checkpoint_text and "inventory" in checkpoint_text,
"checkpoint_tamper_fail_closed":"checkpoint integrity verification failed" in checkpoint_text,
"workspace_derived":"_safe_component(mission_id)" in checkpoint_text and "_safe_component(task_id)" in checkpoint_text,
"worker_external_privilege_authorizer":"privilege_authorizer_token" in worker_text,
}
for name,condition in markers.items(): ok(name,condition)
# Detect executable self-elevation primitives, not explanatory documentation strings.
lower=(execution_text+"\n"+worker_text).lower()
for forbidden in ("shell=true","shellexecutew","verb=\"runas\"","['sudo'","[\"sudo\"","set-executionpolicy bypass"):
    ok(f"no_self_elevation_primitive:{forbidden}", forbidden not in lower)

with tempfile.TemporaryDirectory() as td:
    root=Path(td); store=SQLiteStateStore(root/"state.db"); audit=AuditLedger(store)
    identities=IdentityAuthority(b"I"*32); policy=PolicyGuard.from_repository(ROOT,identities,audit)
    workspaces=WorkspaceManager(root/"workspaces"); checkpoints=CheckpointManager(root/"checkpoints",workspaces,audit)
    privileges=PrivilegeAuthority(b"P"*32,identities,store,audit); engine=DurableLoopEngine(store,audit)
    safe=SafeExecutor(store,audit,policy,workspaces,checkpoints); privileged=PrivilegedExecutor(store,audit,policy,workspaces,checkpoints)
    runner=WorkerRunner(engine,safe,privileged,workspaces,checkpoints,privileges)
    pyexe=str(Path(sys.executable).resolve()); pyname=Path(pyexe).name
    sm=WorkerManifest("proof-safe",("command",),("write",),"task-scoped",(pyname,),max_runtime_seconds=2,max_output_bytes=4096)
    pm=WorkerManifest("proof-priv",("command",),("host-change",),"privileged-ephemeral",(pyname,),max_runtime_seconds=2,max_output_bytes=4096)
    now=int(time.time())
    st=identities.issue("proof-safe","worker",("execute:safe",),ttl_seconds=600,now=now)
    pt=identities.issue("proof-priv","worker",("execute:privileged",),ttl_seconds=600,now=now)
    at=identities.issue("proof-controller","controller",("grant:privileged",),ttl_seconds=600,now=now)
    engine.create_mission("m-safe","sys"); engine.transition_mission("m-safe","AUTHORIZED","proof"); engine.transition_mission("m-safe","RUNNING","proof")
    tid=engine.submit_task("m-safe","command",{"mode":"safe","argv":[pyexe,"-c","from pathlib import Path; Path('safe.txt').write_text('ok')"]},idempotency_key="safe")
    out=runner.run_once(sm,st); ws=workspaces.for_task("m-safe",tid)
    ok("e2e_safe_task_completed",out.state=="COMPLETED"); ok("e2e_safe_effect",(ws/"safe.txt").read_text()=="ok")
    engine.create_mission("m-rb","sys"); engine.transition_mission("m-rb","AUTHORIZED","proof"); engine.transition_mission("m-rb","RUNNING","proof")
    tid2=engine.submit_task("m-rb","command",{"mode":"safe","material_change":True,"argv":[pyexe,"-c","from pathlib import Path; Path('state.txt').write_text('bad'); raise SystemExit(17)"]},idempotency_key="rb",max_attempts=1)
    ws2=workspaces.for_task("m-rb",tid2); (ws2/"state.txt").write_text("before")
    rb=runner.run_once(sm,st); ok("e2e_failed_change_detected",rb.returncode==17); ok("e2e_rollback_applied",rb.rolled_back); ok("e2e_rollback_restored",(ws2/"state.txt").read_text()=="before")
    engine.create_mission("m-p","sys"); engine.transition_mission("m-p","AUTHORIZED","proof"); engine.transition_mission("m-p","RUNNING","proof")
    tid3=engine.submit_task("m-p","command",{"mode":"privileged","action":"host-change","argv":[pyexe,"-c","from pathlib import Path; Path('priv.txt').write_text('ok')"]},idempotency_key="priv")
    po=runner.run_once(pm,pt,privilege_authorizer_token=at); pws=workspaces.for_task("m-p",tid3)
    ok("e2e_privileged_completed",po.state=="COMPLETED"); ok("e2e_privileged_effect",(pws/"priv.txt").read_text()=="ok")
    grant=privileges.issue(at,mission_id="m",task_id="t",worker_id="w",action="a",checkpoint_id="c")
    privileges.consume(grant.token,mission_id="m",task_id="t",worker_id="w",action="a",checkpoint_id="c")
    reused=False
    try: privileges.consume(grant.token,mission_id="m",task_id="t",worker_id="w",action="a",checkpoint_id="c")
    except PrivilegeError: reused=True
    ok("e2e_privilege_one_use",reused)
    engine.create_mission("m-block","sys"); store.set_mission_state("m-block","BLOCKED","proof")
    bid=engine.submit_task("m-block","command",{"mode":"safe","argv":[pyexe,"-c","from pathlib import Path; Path('bad').write_text('x')"]},idempotency_key="blocked")
    bo=runner.run_once(sm,st); bws=workspaces.for_task("m-block",bid)
    ok("e2e_inactive_mission_blocked",bo.state=="BLOCKED"); ok("e2e_inactive_mission_no_effect",not (bws/"bad").exists())
    valid,bad_seq=audit.verify_chain(); ok("e2e_audit_chain_valid",valid and bad_seq is None)
    store.close()

controlled=["immune_core/checkpoints.py","immune_core/privilege.py","immune_core/execution.py","immune_core/workers.py","tests/phase3/test_execution.py","scripts/validate_phase3.py","adr/ADR-0003-isolated-execution.md",".github/workflows/phase3-execution.yml"]
hashes={rel:hashlib.sha256((ROOT/rel).read_bytes()).hexdigest() for rel in controlled}
evidence={"schema":1,"phase":"PHASE_3_ISOLATED_EXECUTION","validated_at":datetime.now(timezone.utc).isoformat(),"checks":checks,"summary":{"total":len(checks),"passed":sum(1 for c in checks if c["passed"]),"failed":len(failures)},"controlled_file_sha256":hashes,"result":"PHASE3_PROVEN" if not failures else "PHASE3_FAILED","scope_note":"PHASE3_PROVEN proves isolated task execution, checkpoint/rollback and sovereign privilege authorization. It does not claim host OS privilege escalation and is not MISSION_PROVEN for the complete product."}
ev=ROOT/"evidence/phase3-validation.json"; ev.parent.mkdir(parents=True,exist_ok=True); ev.write_text(json.dumps(evidence,indent=2,ensure_ascii=False,sort_keys=True)+"\n",encoding="utf-8")
(ROOT/"PHASE3_STATUS.md").write_text("# Fase 3 — Execução Isolada\n\n"+("**Estado: PHASE3_PROVEN**\n" if not failures else "**Estado: PHASE3_FAILED**\n")+f"\nChecks: {evidence['summary']['passed']}/{evidence['summary']['total']} aprovados.\n\nCapacidades: Workers task-scoped, Executor Seguro, fronteira privilegiada efêmera, workspaces derivados, checkpoints íntegros e rollback verificável.\n\nO Executor Privilegiado não contorna UAC/root e o produto completo permanece sem MISSION_PROVEN.\n",encoding="utf-8")
print(json.dumps(evidence["summary"],sort_keys=True))
if failures:
    print("FAILED:",", ".join(failures)); raise SystemExit(1)
print("PHASE3_PROVEN")
