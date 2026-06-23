import unittest

from run_experiments import (
    run_np002,
    run_nv059,
    run_nv061,
    run_nv062,
    run_nv063,
    run_nv065,
    run_qsparx,
)


class FeasibilityTests(unittest.TestCase):
    def test_qsparx_inventory_and_migration_scoring_are_feasible(self):
        result = run_qsparx()
        self.assertGreaterEqual(result["f1"], 0.90)
        self.assertEqual(result["inventory_coverage_pct"], 100.0)
        self.assertEqual(result["migration_mapping_coverage_pct"], 100.0)

    def test_nv059_local_zero_trust_and_receipts_are_feasible(self):
        result = run_nv059()
        self.assertEqual(result["false_allows"], 0)
        self.assertEqual(result["false_denies"], 0)
        self.assertTrue(result["receipt_signatures_verified"])
        self.assertLess(result["local_decision_p95_us"], 10_000.0)

    def test_nv062_secure_task_envelope_is_feasible(self):
        result = run_nv062()
        self.assertEqual(result["valid_tasks_accepted"], result["valid_tasks"])
        self.assertEqual(result["tampered_tasks_blocked"], result["tampered_tasks"])
        self.assertEqual(result["replay_attempts_blocked"], result["replay_attempts"])
        self.assertGreater(result["modeled_tasking_time_reduction_pct"], 90.0)

    def test_nv063_explainable_pol_is_feasible(self):
        result = run_nv063()
        self.assertGreaterEqual(result["f1"], 0.75)
        self.assertLessEqual(result["false_positive_rate"], 0.10)
        self.assertFalse(result["large_historical_database_required"])

    def test_nv061_forecast_and_priority_are_feasible(self):
        result = run_nv061()
        self.assertGreater(result["improvement_vs_hold_pct"], 10.0)
        self.assertGreater(result["priority_recall_at_threat_count"], 0.65)

    def test_nv065_adaptive_allocation_responds_to_novel_threats(self):
        result = run_nv065()
        self.assertGreater(result["novel_threat_quality_improvement_pct"], 20.0)
        self.assertLess(result["recommendation_runtime_p95_us"], 100_000.0)

    def test_np002_swarm_anomaly_lane_is_feasible(self):
        result = run_np002()
        self.assertGreaterEqual(result["f1"], 0.75)
        self.assertLessEqual(result["false_positive_rate"], 0.10)
        self.assertFalse(result["neutralization_claimed"])


if __name__ == "__main__":
    unittest.main()
