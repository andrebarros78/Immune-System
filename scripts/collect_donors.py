#!/usr/bin/env python3
"""Collect clean OSS donor capsules and bounded source snapshots.

This script never executes upstream code. It resolves an immutable commit,
verifies the declared OSS license from the upstream repository root, stores
provenance material, and only then copies source for donors explicitly marked
as capture=snapshot. Git metadata is always removed.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "donors" / "registry.json"
OUT = ROOT / "donors" / "collected"
LOCK = ROOT / "donors" / "LOCK.json"

ALLOWED_LICENSES = {
    "MIT": ("MIT License",),
    "Apache-2.0": ("Apache License", "Version 2.0"),
    "BSD-2-Clause": ("Redistribution and use in source and binary forms",),
    "BSD-3-Clause": ("Redistribution and use in source and binary forms",),
    "MPL-2.0": ("Mozilla Public License", "2.0"),
}

LICENSE_NAMES = (
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "COPYING",
    "COPYING.txt",
    "COPYRIGHT",
)
README_NAMES = ("README.md", "README.rst", "README.txt", "README")


def run(args: list[str], cwd: Path | None = None) -> str:
    p = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return p.stdout.strip()


def raw_url(repo: str, sha: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"


def fetch_first(repo: str, sha: str, names: tuple[str, ...]) -> tuple[str, str] | None:
    headers = {"User-Agent": "Immune-System-Donor-Collector/1.0"}
    for name in names:
        try:
            req = urllib.request.Request(raw_url(repo, sha, name), headers=headers)
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
            return name, data.decode("utf-8", errors="replace")
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            continue
    return None


def resolve_sha(repo: str, ref: str) -> str:
    remote = f"https://github.com/{repo}.git"
    candidates = [f"refs/heads/{ref}", f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}", ref]
    for candidate in candidates:
        try:
            output = run(["git", "ls-remote", remote, candidate])
        except subprocess.CalledProcessError:
            continue
        if output:
            return output.splitlines()[0].split()[0]
    raise RuntimeError(f"cannot resolve {repo}@{ref}")


def verify_license(expected: str, text: str) -> bool:
    markers = ALLOWED_LICENSES.get(expected)
    if not markers:
        return False
    lowered = text.lower()
    return all(marker.lower() in lowered for marker in markers)


def tree_hash(path: Path) -> str:
    h = hashlib.sha256()
    for file in sorted(p for p in path.rglob("*") if p.is_file()):
        rel = file.relative_to(path).as_posix().encode()
        h.update(len(rel).to_bytes(8, "big"))
        h.update(rel)
        with file.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    return h.hexdigest()


def size_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def clean_snapshot(repo: str, ref: str, sha: str, destination: Path, max_mb: int) -> dict:
    remote = f"https://github.com/{repo}.git"
    with tempfile.TemporaryDirectory(prefix="immune-donor-") as temp:
        checkout = Path(temp) / "repo"
        run(["git", "clone", "--depth", "1", "--branch", ref, "--single-branch", remote, str(checkout)])
        actual = run(["git", "rev-parse", "HEAD"], cwd=checkout)
        if actual != sha:
            # Upstream moved during collection. Resolve once more and require exact agreement.
            current = resolve_sha(repo, ref)
            if actual != current:
                raise RuntimeError(f"upstream moved inconsistently: expected={sha} clone={actual} now={current}")
            sha = actual

        shutil.rmtree(checkout / ".git", ignore_errors=True)
        shutil.rmtree(checkout / ".github", ignore_errors=True)
        for name in (".gitmodules", ".gitattributes"):
            p = checkout / name
            if p.exists():
                p.unlink()

        nbytes = size_bytes(checkout)
        limit = max_mb * 1024 * 1024
        if nbytes > limit:
            return {
                "snapshot": False,
                "snapshot_reason": f"working tree {nbytes} bytes exceeds {max_mb} MiB vault limit",
                "resolved_commit": sha,
            }

        if destination.exists():
            shutil.rmtree(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(checkout, destination)
        return {
            "snapshot": True,
            "snapshot_bytes": nbytes,
            "snapshot_tree_sha256": tree_hash(destination),
            "resolved_commit": sha,
        }


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    max_mb = int(registry.get("snapshot_max_mb", 30))
    donors = registry["donors"]
    OUT.mkdir(parents=True, exist_ok=True)

    lock_entries: list[dict] = []
    collected_at = dt.datetime.now(dt.timezone.utc).isoformat()

    for donor in donors:
        donor_id = donor["id"]
        repo = donor["repo"]
        ref = donor["ref"]
        expected_license = donor["license"]
        capsule = OUT / donor_id
        capsule.mkdir(parents=True, exist_ok=True)
        entry = dict(donor)
        entry["collected_at"] = collected_at
        entry["status"] = "failed"

        try:
            if expected_license not in ALLOWED_LICENSES:
                raise RuntimeError(f"license {expected_license} is not in OSS allowlist")

            sha = resolve_sha(repo, ref)
            entry["resolved_commit"] = sha
            entry["source_archive"] = f"https://github.com/{repo}/archive/{sha}.tar.gz"

            license_result = fetch_first(repo, sha, LICENSE_NAMES)
            if not license_result:
                raise RuntimeError("no root license file found")
            license_name, license_text = license_result
            if not verify_license(expected_license, license_text):
                raise RuntimeError(f"license text does not match declared SPDX {expected_license}")

            (capsule / "UPSTREAM_LICENSE.txt").write_text(license_text, encoding="utf-8")
            entry["license_file"] = license_name
            entry["license_verified"] = True
            entry["license_sha256"] = hashlib.sha256(license_text.encode()).hexdigest()

            readme_result = fetch_first(repo, sha, README_NAMES)
            if readme_result:
                readme_name, readme_text = readme_result
                (capsule / "UPSTREAM_README.txt").write_text(readme_text, encoding="utf-8")
                entry["readme_file"] = readme_name
                entry["readme_sha256"] = hashlib.sha256(readme_text.encode()).hexdigest()

            if donor["capture"] == "snapshot":
                snap = clean_snapshot(repo, ref, sha, capsule / "src", max_mb)
                entry.update(snap)
            else:
                entry["snapshot"] = False
                entry["snapshot_reason"] = "capsule mode: upstream runtime is kept external and replaceable"

            entry["status"] = "collected"
        except Exception as exc:  # isolate donor failures by design
            entry["status"] = "rejected_or_failed"
            entry["error"] = f"{type(exc).__name__}: {exc}"
            shutil.rmtree(capsule / "src", ignore_errors=True)

        write_json(capsule / "DONOR.json", entry)
        lock_entries.append(entry)

    lock = {
        "schema": 1,
        "generated_at": collected_at,
        "policy": registry.get("policy"),
        "donor_count": len(lock_entries),
        "collected": sum(1 for x in lock_entries if x["status"] == "collected"),
        "rejected_or_failed": sum(1 for x in lock_entries if x["status"] != "collected"),
        "donors": lock_entries,
    }
    write_json(LOCK, lock)
    print(json.dumps({k: lock[k] for k in ("donor_count", "collected", "rejected_or_failed")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
