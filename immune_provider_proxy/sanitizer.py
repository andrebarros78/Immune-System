from __future__ import annotations

from typing import Any


SECRET_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "cookie", "session", "private_key", "credential",
}
INJECTION_MARKERS = (
    "ignore previous", "system prompt", "developer message", "call tool",
    "execute command", "bypass policy", "disable security",
)
QUARANTINED_INSTRUCTION = "[QUARANTINED_UNTRUSTED_INSTRUCTION]"


def _clean_text(value: str, max_len: int = 4096) -> tuple[str, bool]:
    value = "".join(ch for ch in value if ch in "\n\t" or ord(ch) >= 32)[:max_len]
    lower = value.lower()
    flagged = any(marker in lower for marker in INJECTION_MARKERS)
    return (QUARANTINED_INSTRUCTION if flagged else value), flagged


def sanitize(value: Any, *, depth: int = 0) -> tuple[Any, bool]:
    if depth > 8:
        return "[TRUNCATED_DEPTH]", False
    flagged = False
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= 128:
                break
            key = str(k)
            if key.strip().lower() in SECRET_KEYS:
                out[key] = "[REDACTED]"
                continue
            child, child_flag = sanitize(v, depth=depth + 1)
            out[key] = child
            flagged = flagged or child_flag
        return out, flagged
    if isinstance(value, list):
        out = []
        for item in value[:128]:
            child, child_flag = sanitize(item, depth=depth + 1)
            out.append(child)
            flagged = flagged or child_flag
        return out, flagged
    if isinstance(value, str):
        return _clean_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value, False
    return str(value)[:1024], False
