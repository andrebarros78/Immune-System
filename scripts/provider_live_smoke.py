from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_core.provider_runtime import ProviderRuntimeConfig
from immune_core.providers import OpenAICompatibleHTTPProvider, ProviderError, ProviderRequest

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
            "Return strict proposal JSON. Do not recommend execution, tools, privileges, writes, "
            "network targets, protected systems, or external actions."
        ),
        untrusted_observations=(
            {"kind": "synthetic.provider-smoke", "state": "synthetic", "safe": True},
        ),
        max_tokens=256,
    )

    started = time.monotonic()
    try:
        proposal = provider.propose(request, timeout_seconds=30.0)
    except ProviderError as exc:
        emit(
            {
                **public_base,
                "ok": False,
                "status": "PROVIDER_CONTRACT_FAILED",
                "error_class": type(exc).__name__,
                "duration_seconds": round(time.monotonic() - started, 3),
            }
        )
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
