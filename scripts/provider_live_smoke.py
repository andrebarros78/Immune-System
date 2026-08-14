from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_core.provider_runtime import ProviderRuntimeConfig
from immune_core.providers import OpenAICompatibleHTTPProvider, ProviderError, ProviderRequest


def main() -> int:
    config = ProviderRuntimeConfig.load(ROOT / "config" / "provider-runtime.json")
    profiles = config.enabled_profiles()
    if not profiles:
        print(json.dumps({"ok": False, "status": "NO_ENABLED_PROVIDER"}, sort_keys=True))
        return 2

    profile = profiles[0]
    credential_present = bool(profile.api_key_env and os.environ.get(profile.api_key_env))
    public_base = {
        "provider_id": profile.id,
        "model": profile.model,
        "endpoint_host": profile.endpoint.split("/", 3)[2],
        "credential_env": profile.api_key_env,
        "credential_present": credential_present,
        "owner_scope": config.owner_scope,
    }
    if not credential_present:
        print(json.dumps({**public_base, "ok": False, "status": "CREDENTIAL_MISSING"}, sort_keys=True))
        return 2

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
        mission_id="github-provider-live-smoke",
        objective=(
            "Validate the cognitive provider boundary. Return a strict proposal JSON. "
            "Do not recommend execution, tools, privileges, writes, or external actions."
        ),
        untrusted_observations=(
            {"kind": "provider-smoke", "state": "synthetic", "safe": True},
        ),
        max_tokens=256,
    )

    started = time.monotonic()
    try:
        proposal = provider.propose(request, timeout_seconds=30.0)
    except ProviderError as exc:
        print(
            json.dumps(
                {
                    **public_base,
                    "ok": False,
                    "status": "PROVIDER_CONTRACT_FAILED",
                    "error_class": type(exc).__name__,
                    "duration_seconds": round(time.monotonic() - started, 3),
                },
                sort_keys=True,
            )
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
    print(json.dumps(result, sort_keys=True))
    return 0 if result["proposal_provider_id"] == profile.id and not proposal.degraded else 1


if __name__ == "__main__":
    raise SystemExit(main())
