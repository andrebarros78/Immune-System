import unittest

from immune_lab.admission import Decision, REQUIRED_EVIDENCE, build_catalog, evaluate_donor


DONOR = {
    "id": "example",
    "purpose": "bounded test capability",
    "resolved_commit": "a" * 40,
    "status": "collected",
}


class DonorLabTests(unittest.TestCase):
    def test_collected_is_not_approved(self):
        result = evaluate_donor(DONOR)
        self.assertEqual(result.decision, Decision.QUARANTINED)
        self.assertEqual(result.authority, "none")
        self.assertFalse(result.executable)

    def test_missing_provenance_is_rejected(self):
        result = evaluate_donor({"id": "bad", "purpose": "x", "status": "collected"})
        self.assertEqual(result.decision, Decision.REJECTED)

    def test_all_gates_allow_adapter_only(self):
        evidence = {gate: True for gate in REQUIRED_EVIDENCE}
        result = evaluate_donor(DONOR, evidence)
        self.assertEqual(result.decision, Decision.APPROVED)
        self.assertEqual(result.authority, "adapter-only")
        self.assertFalse(result.executable)

    def test_catalog_keeps_sovereign_boundary(self):
        catalog = build_catalog([DONOR])
        self.assertFalse(catalog["sovereign_boundary"]["direct_execution"])
        self.assertTrue(catalog["sovereign_boundary"]["policy_guard_required"])
        self.assertEqual(catalog["summary"]["quarantined"], 1)


if __name__ == "__main__":
    unittest.main()
