from __future__ import annotations

import json
import re
import subprocess
import uuid
from dataclasses import dataclass
from typing import Mapping, Sequence


class SandboxIsolationError(RuntimeError):
    pass


_SENSITIVE_ENV = re.compile(r"(SECRET|TOKEN|PASSWORD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)", re.IGNORECASE)


@dataclass(frozen=True)
class ContainerIsolationPolicy:
    """Fail-closed disposable container policy for untrusted Workers/Adapters."""

    network_mode: str = "none"
    pids_limit: int = 1
    memory_bytes: int = 134_217_728
    cpus: float = 0.5
    read_only_root: bool = True
    cap_drop: tuple[str, ...] = ("ALL",)
    no_new_privileges: bool = True
    tmpfs: str = "/tmp:rw,noexec,nosuid,nodev,size=16m"
    env_allowlist: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.network_mode != "none":
            raise SandboxIsolationError("closed-lab sandbox network must be deny-all")
        if not 1 <= self.pids_limit <= 64:
            raise SandboxIsolationError("sandbox pids limit outside sovereign bounds")
        if not 32 * 1024 * 1024 <= self.memory_bytes <= 2 * 1024 * 1024 * 1024:
            raise SandboxIsolationError("sandbox memory limit outside sovereign bounds")
        if not 0.1 <= self.cpus <= 2.0:
            raise SandboxIsolationError("sandbox cpu limit outside sovereign bounds")
        if not self.read_only_root or "ALL" not in self.cap_drop or not self.no_new_privileges:
            raise SandboxIsolationError("sandbox cannot relax root/capability/privilege containment")

    def create_args(
        self,
        *,
        image_ref: str,
        command: Sequence[str] = (),
        env: Mapping[str, str] | None = None,
        container_name: str | None = None,
    ) -> tuple[str, ...]:
        image_ref = str(image_ref).strip()
        if not image_ref or any(ch.isspace() for ch in image_ref):
            raise SandboxIsolationError("bounded image_ref is required")
        name = container_name or f"immune-sandbox-{uuid.uuid4().hex[:16]}"
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", name):
            raise SandboxIsolationError("invalid sandbox container name")

        requested = dict(env or {})
        allowed = set(self.env_allowlist)
        for key in requested:
            if key not in allowed:
                raise SandboxIsolationError(f"sandbox environment key not allowlisted: {key}")
            if _SENSITIVE_ENV.search(key):
                raise SandboxIsolationError(f"secret-like environment key forbidden in sandbox: {key}")

        args = [
            "docker", "create", "--name", name,
            "--network", self.network_mode,
            "--pids-limit", str(self.pids_limit),
            "--memory", str(self.memory_bytes),
            "--cpus", str(self.cpus),
            "--read-only",
            "--tmpfs", self.tmpfs,
            "--security-opt", "no-new-privileges:true",
        ]
        for capability in self.cap_drop:
            args.extend(("--cap-drop", capability))
        for key, value in sorted(requested.items()):
            args.extend(("--env", f"{key}={value}"))
        args.append(image_ref)
        args.extend(str(item) for item in command)
        return tuple(args)


class ContainerSandboxRunner:
    """Ring-4/6 broker. Creates, validates, runs and destroys a disposable sandbox."""

    def __init__(self, policy: ContainerIsolationPolicy | None = None) -> None:
        self.policy = policy or ContainerIsolationPolicy()

    @staticmethod
    def _run(argv: Sequence[str], *, timeout: float = 20.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(tuple(argv), shell=False, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False)

    def image_sha256(self, image_ref: str, *, timeout: float = 20.0) -> str:
        completed = self._run(("docker", "image", "inspect", "--format", "{{.Id}}", image_ref), timeout=timeout)
        if completed.returncode != 0:
            raise SandboxIsolationError("sandbox image inspection failed")
        value = completed.stdout.strip().lower().removeprefix("sha256:")
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise SandboxIsolationError("sandbox image sha256 digest invalid")
        return value

    def run_json_probe(
        self,
        *,
        image_ref: str,
        command: Sequence[str] = (),
        env: Mapping[str, str] | None = None,
        timeout: float = 20.0,
    ) -> dict:
        name = f"immune-sandbox-{uuid.uuid4().hex[:16]}"
        create = self._run(self.policy.create_args(image_ref=image_ref, command=command, env=env, container_name=name), timeout=timeout)
        if create.returncode != 0:
            raise SandboxIsolationError(f"sandbox create failed rc={create.returncode}")
        try:
            inspect = self._run(("docker", "inspect", name), timeout=timeout)
            if inspect.returncode != 0:
                raise SandboxIsolationError("sandbox inspect failed")
            try:
                meta = json.loads(inspect.stdout)[0]
                host = meta["HostConfig"]
            except Exception as exc:
                raise SandboxIsolationError("sandbox inspect contract invalid") from exc
            if host.get("NetworkMode") != "none":
                raise SandboxIsolationError("sandbox network isolation not enforced")
            if int(host.get("PidsLimit") or 0) != self.policy.pids_limit:
                raise SandboxIsolationError("sandbox pids isolation not enforced")
            if int(host.get("Memory") or 0) != self.policy.memory_bytes:
                raise SandboxIsolationError("sandbox memory isolation not enforced")
            expected_nano_cpus = int(self.policy.cpus * 1_000_000_000)
            if int(host.get("NanoCpus") or 0) != expected_nano_cpus:
                raise SandboxIsolationError("sandbox cpu isolation not enforced")
            if not bool(host.get("ReadonlyRootfs")):
                raise SandboxIsolationError("sandbox root filesystem is writable")
            tmpfs = host.get("Tmpfs") or {}
            if "/tmp" not in tmpfs:
                raise SandboxIsolationError("sandbox ephemeral tmpfs missing")
            cap_drop = {str(x).upper() for x in (host.get("CapDrop") or [])}
            if "ALL" not in cap_drop:
                raise SandboxIsolationError("sandbox capabilities were not dropped")
            security_opt = {str(x).lower() for x in (host.get("SecurityOpt") or [])}
            if not any("no-new-privileges" in x for x in security_opt):
                raise SandboxIsolationError("sandbox no-new-privileges missing")

            started = self._run(("docker", "start", "--attach", name), timeout=timeout)
            if started.returncode != 0:
                raise SandboxIsolationError(f"sandbox probe failed rc={started.returncode}")
            lines = [line.strip() for line in started.stdout.splitlines() if line.strip()]
            if not lines:
                raise SandboxIsolationError("sandbox probe produced no structured result")
            try:
                result = json.loads(lines[-1])
            except json.JSONDecodeError as exc:
                raise SandboxIsolationError("sandbox probe result is not JSON") from exc
            if not isinstance(result, dict):
                raise SandboxIsolationError("sandbox probe result must be an object")
            return result
        finally:
            removed = self._run(("docker", "rm", "--force", name), timeout=timeout)
            if removed.returncode != 0:
                raise SandboxIsolationError("sandbox teardown failed")
