import unittest

from proposal_readiness import REQUIRED_FIELDS, TOPICS, validate_topics


class ProposalReadinessTests(unittest.TestCase):
    def test_all_topics_have_complete_packets(self) -> None:
        self.assertEqual(validate_topics(TOPICS), [])

    def test_required_fields_cover_submission_logic(self) -> None:
        for field in (
            "proposal_claim",
            "first_month_proof",
            "phase_i_base_demo",
            "phase_i_option_demo",
            "failure_condition",
            "do_not_overclaim",
            "external_access_request",
        ):
            self.assertIn(field, REQUIRED_FIELDS)

    def test_statuses_match_current_go_no_go(self) -> None:
        self.assertEqual(TOPICS["NV059"]["status"], "GO")
        self.assertEqual(TOPICS["NV061"]["status"], "GO")
        self.assertEqual(TOPICS["NV063"]["status"], "GO")
        self.assertEqual(TOPICS["NV065"]["status"], "GO")
        self.assertEqual(TOPICS["NV062"]["status"], "CONDITIONAL GO")
        self.assertEqual(TOPICS["QSPARX"]["status"], "CONDITIONAL GO")
        self.assertEqual(TOPICS["NP002"]["status"], "PARTNER GO")


if __name__ == "__main__":
    unittest.main()
