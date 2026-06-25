import unittest

from go4_comparison_report import build_alignment, profile_platform
from go4_enhancements import (
    run_all_enhanced,
    run_nv059_enhanced,
    run_nv061_enhanced,
    run_nv063_enhanced,
    run_nv065_enhanced,
)


class GO4EnhancedEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = run_all_enhanced()

    def test_nv059_blocks_named_attack_vectors_under_ddil(self):
        result = self.results["NV059"]
        self.assertEqual(result["attack_vectors_tested"], 10)
        self.assertGreaterEqual(result["attack_block_rate"], 0.999)
        self.assertLessEqual(result["false_allows"], 1)
        self.assertEqual(result["false_denies"], 0)
        self.assertTrue(result["chain_verified"])
        self.assertTrue(result["tamper_rejected"])
        self.assertTrue(result["bounded_offline_lease_tested"])
        self.assertGreater(result["behavioral_detections"], 700)
        self.assertLess(result["decision_p95_us"], 100.0)
        self.assertLess(result["end_to_end_p99_us"], 1_000.0)
        self.assertEqual(result["hash_chain_events"], result["total_requests"])
        self.assertLess(result["signed_batch_receipts"], result["hash_chain_events"])
        for mode_accuracy in result["ddil_accuracy"].values():
            self.assertGreaterEqual(mode_accuracy, 0.999)

    def test_nv059_every_attack_vector_has_coverage(self):
        result = run_nv059_enhanced()
        for vector, stats in result["attack_vector_stats"].items():
            self.assertGreater(stats["attempts"], 0, vector)
            if vector == "behavioral_exfiltration":
                self.assertLessEqual(stats["false_allows"], 1, vector)
            else:
                self.assertEqual(stats["attempts"], stats["blocked"], vector)

    def test_nv061_forecast_uncertainty_and_priority_are_feasible(self):
        result = self.results["NV061"]
        self.assertGreater(result["imm_vs_hold_improvement_h5_pct"], 50.0)
        self.assertGreater(result["imm_vs_raw_velocity_improvement_h5_pct"], 0.0)
        self.assertGreater(result["priority_recall_at_threat_count"], 0.65)
        self.assertGreater(result["modeled_analyst_time_reduction_pct"], 50.0)
        self.assertGreaterEqual(result["change_detection"]["recall"], 0.70)
        self.assertLessEqual(result["change_detection"]["false_positive_rate"], 0.10)
        self.assertLessEqual(result["change_detection"]["false_negative_rate"], 0.30)
        self.assertGreaterEqual(result["conformal_coverage_h5"], 0.86)
        self.assertLessEqual(result["conformal_coverage_h5"], 0.94)
        self.assertLess(result["conformal_radius_h5_km"], 8.0)
        self.assertEqual(sum(result["hierarchy"].values()), result["tracks"])

    def test_nv061_multi_horizon_error_grows_monotonically_enough(self):
        result = run_nv061_enhanced()
        rmse = result["imm_rmse_by_horizon_km"]
        self.assertLess(rmse["3"], rmse["5"])
        self.assertLess(rmse["5"], rmse["10"])
        self.assertGreater(result["mean_custody_confidence"], 0.50)

    def test_nv063_two_tier_alert_contract_has_low_false_positive_high_confidence(self):
        result = self.results["NV063"]
        self.assertFalse(result["large_historical_database_required"])
        self.assertGreaterEqual(result["watch_tier"]["recall"], 0.70)
        self.assertGreaterEqual(result["watch_tier"]["f1"], 0.70)
        self.assertGreaterEqual(result["high_confidence_tier"]["precision"], 0.95)
        self.assertLessEqual(result["high_confidence_tier"]["false_positive_rate"], 0.02)
        self.assertLessEqual(result["watch_tier"]["false_negative_rate"], 0.30)
        self.assertLessEqual(
            result["high_confidence_tier"]["observed_false_discovery_proportion"],
            0.05,
        )
        self.assertGreaterEqual(result["high_confidence_tier"]["f1"], 0.75)
        self.assertLess(result["state_kb_for_1000_tracks"], 200.0)
        self.assertLess(result["processing_us_per_track_update"], 50.0)
        self.assertEqual(len(result["ssds_tlr_mapping"]), 3)
        self.assertTrue(result["sample_alerts"])

    def test_nv063_alerts_include_operator_facing_explanations(self):
        result = run_nv063_enhanced()
        sample = result["sample_alerts"][0]
        self.assertIn("system_track_number", sample)
        self.assertIn("machine_reason", sample)
        self.assertIn("confidence", sample)
        self.assertIn("operator_action", sample)

    def test_nv065_sensor_management_adapts_to_novelty_and_degradation(self):
        result = self.results["NV065"]
        self.assertTrue(result["advisory_only"])
        self.assertEqual(
            result["phase_i_sensor_suite"],
            ["SPS-48", "SPQ-9B", "MK-9 Tracker/Illuminator", "SPY-6(V)3"],
        )
        self.assertGreater(result["nominal"]["novel_threat_quality_improvement_pct"], 50.0)
        self.assertGreater(result["degraded"]["novel_threat_quality_improvement_pct"], 40.0)
        self.assertLess(result["nominal"]["p95_runtime_us"], 10_000.0)
        self.assertLess(result["degraded"]["p95_runtime_us"], 10_000.0)
        self.assertEqual(result["nominal"]["conflict_violations"], 0)
        self.assertEqual(result["degraded"]["conflict_violations"], 0)
        self.assertEqual(len(result["ssds_tlr_mapping"]), 5)
        self.assertLess(result["scheduler_scaling"]["3000"]["p95_runtime_us"], 20_000.0)
        self.assertLess(
            result["scheduler_scaling"]["3000"]["runtime_per_track_p95_us"],
            result["scheduler_scaling"]["100"]["runtime_per_track_p95_us"] * 3.0,
        )

    def test_nv065_burst_stress_remains_bounded(self):
        result = run_nv065_enhanced()
        burst = result["burst_stress"]
        self.assertEqual(burst["track_count"], 300)
        self.assertEqual(burst["novel_threats"], 50)
        self.assertGreater(burst["burst_novel_tracks_served_fraction"], 0.40)
        self.assertLess(burst["p99_runtime_us"], 10_000.0)
        self.assertEqual(burst["conflict_violations"], 0)

    def test_comparison_alignment_gates_pass(self):
        platform = profile_platform()
        alignment = build_alignment(self.results, platform)
        for topic, topic_alignment in alignment.items():
            failed = [
                name for name, passed in topic_alignment["kpis"].items() if not passed
            ]
            self.assertFalse(failed, f"{topic} failed gates: {failed}")


if __name__ == "__main__":
    unittest.main()
