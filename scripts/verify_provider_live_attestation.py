from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config" / "provider-live-attestation.json"


class ProviderAttestationError(RuntimeError):
    pass


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *args),
        cwd=ROOT,
        shell=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _api(url: str) -> object:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "immune-provider-attestation"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def evaluate(config_path: str | Path = DEFAULT_CONFIG) -> dict:
    raw = json.loads(Path(config_path).read_text(encoding="utf-8-sig"))
    if raw.get("schema") != 1:
        raise ProviderAttestationError("provider attestation schema invalid")
    repository = str(raw.get("repository", "")).strip()
    baseline = str(raw.get("baseline_commit", "")).strip().lower()
    run_id = int(raw.get("github_run_id", 0))
    workflow_name = str(raw.get("workflow_name", "")).strip()
    required_job = str(raw.get("required_job_name", "")).strip()
    paths = tuple(str(x).strip() for x in raw.get("surface_paths", []) if str(x).strip())
    if repository != "andrebarros78/Immune-System":
        raise ProviderAttestationError("provider attestation repository mismatch")
    if not re.fullmatch(r"[0-9a-f]{40}", baseline) or run_id <= 0 or not workflow_name or not required_job or not paths:
        raise ProviderAttestationError("provider attestation metadata incomplete")
    if any(path.startswith(("/", "..")) or "\\" in path for path in paths):
        raise ProviderAttestationError("provider surface path is not repository-relative")

    exists = _git("cat-file", "-e", f"{baseline}^{{commit}}")
    if exists.returncode != 0:
        raise ProviderAttestationError("provider attestation baseline commit unavailable")

    diff = _git("diff", "--quiet", baseline, "HEAD", "--", *paths)
    if diff.returncode not in {0, 1}:
        raise ProviderAttestationError("provider surface comparison failed")
    if diff.returncode == 1:
        return {
            "status": "LIVE_PROVIDER_REQUIRED",
            "reusable": False,
            "baseline_commit": baseline,
            "github_run_id": run_id,
            "surface_paths": list(paths),
        }

    base_url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
    run = _api(base_url)
    if not isinstance(run, dict):
        raise ProviderAttestationError("provider proof run response invalid")
    if (
        str(run.get("head_sha", "")).lower() != baseline
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("name") != workflow_name
    ):
        raise ProviderAttestationError("external provider proof run is not valid")

    jobs_doc = _api(base_url + "/jobs?per_page=100")
    if not isinstance(jobs_doc, dict) or not isinstance(jobs_doc.get("jobs"), list):
        raise ProviderAttestationError("provider proof jobs response invalid")
    matches = [job for job in jobs_doc["jobs"] if job.get("name") == required_job]
    if len(matches) != 1 or matches[0].get("status") != "completed" or matches[0].get("conclusion") != "success":
        raise ProviderAttestationError("external provider live job is not successful")

    return {
        "status": "LIVE_PROVIDER_ATTESTATION_REUSED",
        "reusable": True,
        "baseline_commit": baseline,
        "github_run_id": run_id,
        "provider_job_id": int(matches[0].get("id", 0)),
        "surface_paths": list(paths),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    args = parser.parse_args(argv)
    try:
        result = evaluate(args.config)
    except Exception as exc:
        print(json.dumps({"status": "PROVIDER_ATTESTATION_INVALID", "error_class": type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"reuse={'true' if result['reusable'] else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
