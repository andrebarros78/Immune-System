from __future__ import annotations

import ast
from pathlib import Path


FORBIDDEN_CORE_IMPORTS = {
    "socket", "subprocess", "urllib", "requests", "http", "ssl", "ftplib", "smtplib", "importlib",
}
FORBIDDEN_CORE_PREFIXES = {"immune_gateway", "immune_execution_broker", "immune_provider_proxy", "immune_twin", "immune_presentation", "immune_control_plane"}
FORBIDDEN_DYNAMIC_CALLS = {"eval", "exec", "__import__"}


def core_boundary_violations(root: str | Path) -> list[str]:
    root = Path(root)
    violations: list[str] = []
    for path in sorted((root / "immune_core").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                top = name.split(".", 1)[0]
                if top in FORBIDDEN_CORE_IMPORTS or top in FORBIDDEN_CORE_PREFIXES:
                    violations.append(f"{path.name}:{getattr(node, 'lineno', 0)}:import:{name}")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_DYNAMIC_CALLS:
                violations.append(f"{path.name}:{getattr(node, 'lineno', 0)}:dynamic:{node.func.id}")
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr in {"environ", "getenv"}:
                violations.append(f"{path.name}:{getattr(node, 'lineno', 0)}:environment:{node.attr}")
    return violations
