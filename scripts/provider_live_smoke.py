from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_core.provider_runtime import ProviderRuntimeConfig
from immune_core.providers import OpenAICompatibleHTTPProvider, ProviderError, ProviderProtocolError, ProviderRequest, ProviderUnavailable

EXPECTED_TEST_MODE = "GITHUB_ISOLATED"
EXPECTED_HOST = "api.z.ai"


def emit(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True))


def main() -> int:
    test_mode = os.environ.get("IMMUNE_TEST_MODE", "")
    github_actions = os.environ.get("GITHUB_ACTIONS", "").strip().lower() == "true"
    if test_mode != EXPECTED_TEST_MODE:
        emit({"ok": False, "status": "ISOLATED_TEST_MODE_REQUIRED"})
        return 3

    default_config = ROOT / "config" / "provider-live-test.json"
    config = ProviderRuntimeConfig.from_environment(default_config)
    profiles = config.enabled_profiles()
    if len(profiles) != 1:
        emit({"ok": False, "status": "ISOLATED_PROVIDER_COUNT_INVALID", "provider_count": len(profiles)})
        return 3

    profile = profiles[0]
    endpoint_host = (urlparse(profile.endpoint).hostname or "").lower()
    if endpoint_host != EXPECTED_HOST:
        emit({"ok": False, "status": "ISOLATED_ENDPOINT_REJECTED", "endpoint_host": endpoint_host})
        return 3

    credential_present = bool(profile.api_key_env and os.environ.get(profile.api_key_env))
    public_base = {
        "provider_id": profile.id,
        "model": profile.model,
        "endpoint_host": endpoint_host,
        "credential_env": profile.api_key_env,
        "credential_present": credential_present,
        "owner_scope": config.owner_scope,
        "test_mode": test_mode,
        "github_actions": github_actions,
    }
    if not credential_present:
        emit({**public_base, "ok": False, "status": "CREDENTIAL_MISSING"})
        return 2

    # A live secret is allowed only on a GitHub-hosted workflow configured for this isolated test.
    if not github_actions:
        emit({**public_base, "ok": False, "status": "LIVE_SECRET_EXECUTION_REQUIRES_GITHUB_ACTIONS"})
        return 4

    provider = OpenAICompatibleHTTPProvider(
        profile.id,
        profile.endpoint,
        profile.model,
        locality=profile.locality,
        cost_per_call=profile.cost_per_call,
        api_key_env=profile.api_key_env,
        request_options=profile.request_options,
        owner_scope=config.owner_scope,
    )
    request = ProviderRequest(
        mission_id="github-isolated-provider-live-smoke",
        objective=(
            "Validate only the cognitive provider contract inside an isolated GitHub test runner. "
            "Return strict proposal JSON. For this smoke set hypotheses to [] and recommended_tasks to []; "
            "summary must be a non-empty string and confidence must be a number from 0 to 1. "
            "Do not recommend execution, tools, privileges, writes, network targets, protected systems, or external actions."
        ),
        untrusted_observations=(
            {"kind": "synthetic.provider-smoke", "state": "synthetic", "safe": True},
        ),
        max_tokens=128,
    )

    started = time.monotonic()
    try:
        proposal = provider.propose(request, timeout_seconds=60.0)
    except ProviderError as exc:
        diagnostic = {
            **public_base,
            "ok": False,
            "status": "PROVIDER_CONTRACT_FAILED",
            "error_class": type(exc).__name__,
            "duration_seconds": round(time.monotonic() - started, 3),
        }
        cause = exc.__cause__
        if cause is not None:
            diagnostic["cause_class"] = type(cause).__name__
        if isinstance(cause, urllib.error.HTTPError):
            diagnostic["http_status"] = int(cause.code)
            diagnostic["http_reason"] = str(cause.reason)[:80]
        elif isinstance(cause, urllib.error.URLError):
            diagnostic["network_error_class"] = type(cause.reason).__name__
        elif isinstance(exc, ProviderProtocolError):
            diagnostic["protocol_error"] = str(exc)[:160]
        elif isinstance(exc, ProviderUnavailable):
            diagnostic["provider_unavailable"] = True
        emit(diagnostic)
        annotation = "Provider live smoke failed: " + json.dumps(
            {k: diagnostic[k] for k in ("error_class", "cause_class", "http_status", "http_reason", "network_error_class", "protocol_error", "provider_unavailable") if k in diagnostic},
            sort_keys=True,
        )
        escaped = annotation.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        if diagnostic.get("http_status") == 429:
            print("::warning title=Immune provider rate limit::" + escaped)
            return 75
        if isinstance(exc, ProviderUnavailable) and "http_status" not in diagnostic:
            print("::warning title=Immune provider transient unavailable::" + escaped)
            return 76
        print("::error title=Immune provider smoke::" + escaped)
        return 1

    result = {
        **public_base,
        "ok": True,
        "status": "LIVE_PROVIDER_CONTRACT_PROVEN",
        "duration_seconds": round(time.monotonic() - started, 3),
        "proposal_provider_id": proposal.provider_id,
        "degraded": proposal.degraded,
        "confidence_in_range": 0.0 <= proposal.confidence <= 1.0,
        "hypothesis_count": len(proposal.hypotheses),
        "recommended_task_count": len(proposal.recommended_tasks),
        "summary_nonempty": bool(proposal.summary.strip()),
    }
    emit(result)
    return 0 if result["proposal_provider_id"] == profile.id and not proposal.degraded else 1


if __name__ == "__main__":
    raise SystemExit(main())
