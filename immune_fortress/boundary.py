from __future__ import annotations

import ast
from pathlib import Path


# Ring 1 must not gain any direct transport, process, FFI, dynamic-loader or UI-launch authority.
FORBIDDEN_CORE_IMPORTS = {
    "socket", "subprocess", "urllib", "requests", "http", "httpx", "ssl", "ftplib", "smtplib",
    "telnetlib", "xmlrpc", "webbrowser", "multiprocessing", "ctypes", "pty", "importlib",
}
FORBIDDEN_CORE_PREFIXES = {
    "immune_gateway", "immune_execution_broker", "immune_provider_proxy", "immune_twin",
    "immune_presentation", "immune_control_plane",
}
FORBIDDEN_DYNAMIC_CALLS = {"eval", "exec", "__import__"}
FORBIDDEN_OS_CALLS = {
    "system", "popen", "startfile",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
}
FORBIDDEN_ASYNCIO_CALLS = {"create_subprocess_exec", "create_subprocess_shell"}


def _root_name(name: str) -> str:
    return name.split(".", 1)[0]


def core_boundary_violations(root: str | Path) -> list[str]:
    root = Path(root)
    violations: list[str] = []
    for path in sorted((root / "immune_core").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        aliases: dict[str, str] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    full = alias.name
                    local = alias.asname or _root_name(full)
                    aliases[local] = full
                    top = _root_name(full)
                    if top in FORBIDDEN_CORE_IMPORTS or top in FORBIDDEN_CORE_PREFIXES:
                        violations.append(f"{path.name}:{getattr(node, 'lineno', 0)}:import:{full}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                full = node.module
                top = _root_name(full)
                if top in FORBIDDEN_CORE_IMPORTS or top in FORBIDDEN_CORE_PREFIXES:
                    violations.append(f"{path.name}:{getattr(node, 'lineno', 0)}:import:{full}")
                for alias in node.names:
                    local = alias.asname or alias.name
                    aliases[local] = f"{full}.{alias.name}"

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            lineno = getattr(node, "lineno", 0)
            if isinstance(node.func, ast.Name):
                name = node.func.id
                if name in FORBIDDEN_DYNAMIC_CALLS:
                    violations.append(f"{path.name}:{lineno}:dynamic:{name}")
                target = aliases.get(name, "")
                if target.startswith("os.") and target.rsplit(".", 1)[-1] in FORBIDDEN_OS_CALLS:
                    violations.append(f"{path.name}:{lineno}:process:{target}")
                if target.startswith("asyncio.") and target.rsplit(".", 1)[-1] in FORBIDDEN_ASYNCIO_CALLS:
                    violations.append(f"{path.name}:{lineno}:process:{target}")
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                base = node.func.value.id
                attr = node.func.attr
                resolved_base = aliases.get(base, base)
                if _root_name(resolved_base) == "os" and attr in FORBIDDEN_OS_CALLS:
                    violations.append(f"{path.name}:{lineno}:process:os.{attr}")
                if _root_name(resolved_base) == "asyncio" and attr in FORBIDDEN_ASYNCIO_CALLS:
                    violations.append(f"{path.name}:{lineno}:process:asyncio.{attr}")

        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                base = aliases.get(node.value.id, node.value.id)
                if _root_name(base) == "os" and node.attr in {"environ", "getenv"}:
                    violations.append(f"{path.name}:{getattr(node, 'lineno', 0)}:environment:{node.attr}")
    return sorted(set(violations))
