from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.verify_provider_live_attestation import ProviderAttestationError, evaluate


BASE = "f5d15f5f4bf01654bdfc7040ed22bbb98cee8afa"
RUN_ID = 32136856684


class ProviderLiveAttestationTests(unittest.TestCase):
    def _config(self, root: Path) -> Path:
        path = root / "attestation.json"
        path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "repository": "andrebarros78/Immune-System",
                    "baseline_commit": BASE,
                    "github_run_id": RUN_ID,
                    "workflow_name": "BRAIN_FORTRESS_PROVEN - Seven Ring Isolated Validation",
                    "required_job_name": "GLM Live via Provider Proxy",
                    "surface_paths": ["immune_provider_proxy", "scripts/provider_live_smoke.py"],
                }
            ),
            encoding="utf-8",
        )
        return path

    @staticmethod
    def _cp(rc: int) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(("git",), rc, stdout="", stderr="")

    def test_attestation_reuse_requires_unchanged_surface_and_external_success(self):
        with tempfile.TemporaryDirectory(prefix="immune-provider-attest-") as td:
            config = self._config(Path(td))
            run = {
                "head_sha": BASE,
                "status": "completed",
                "conclusion": "success",
                "name": "BRAIN_FORTRESS_PROVEN - Seven Ring Isolated Validation",
            }
            jobs = {
                "jobs": [
                    {
                        "id": 95710280924,
                        "name": "GLM Live via Provider Proxy",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]
            }
            with patch("scripts.verify_provider_live_attestation._git", side_effect=[self._cp(0), self._cp(0)]), patch(
                "scripts.verify_provider_live_attestation._api", side_effect=[run, jobs]
            ):
                result = evaluate(config)
            self.assertTrue(result["reusable"])
            self.assertEqual(result["status"], "LIVE_PROVIDER_ATTESTATION_REUSED")

    def test_provider_surface_change_forces_fresh_live_proof_without_reusing_attestation(self):
        with tempfile.TemporaryDirectory(prefix="immune-provider-change-") as td:
            config = self._config(Path(td))
            with patch("scripts.verify_provider_live_attestation._git", side_effect=[self._cp(0), self._cp(1)]), patch(
                "scripts.verify_provider_live_attestation._api"
            ) as api:
                result = evaluate(config)
            self.assertFalse(result["reusable"])
            self.assertEqual(result["status"], "LIVE_PROVIDER_REQUIRED")
            api.assert_not_called()

    def test_failed_or_mismatched_external_run_cannot_be_reused(self):
        with tempfile.TemporaryDirectory(prefix="immune-provider-bad-run-") as td:
            config = self._config(Path(td))
            bad_run = {
                "head_sha": BASE,
                "status": "completed",
                "conclusion": "failure",
                "name": "BRAIN_FORTRESS_PROVEN - Seven Ring Isolated Validation",
            }
            with patch("scripts.verify_provider_live_attestation._git", side_effect=[self._cp(0), self._cp(0)]), patch(
                "scripts.verify_provider_live_attestation._api", return_value=bad_run
            ):
                with self.assertRaises(ProviderAttestationError):
                    evaluate(config)


if __name__ == "__main__":
    unittest.main()
