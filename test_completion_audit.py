import unittest

from completion_audit import EXCLUDED_EXTERNAL_PROOFS, run_audit
from proposal_readiness import TOPICS


class CompletionAuditTests(unittest.TestCase):
    def test_internal_scope_is_complete(self) -> None:
        audit = run_audit()
        self.assertTrue(audit["internal_scope_complete"])

    def test_external_proofs_are_explicit_for_every_topic(self) -> None:
        self.assertEqual(set(EXCLUDED_EXTERNAL_PROOFS), set(TOPICS))

    def test_audit_does_not_claim_operational_completion(self) -> None:
        audit = run_audit()
        self.assertIn("does not mean operational validation", audit["scope_boundary"])


if __name__ == "__main__":
    unittest.main()
