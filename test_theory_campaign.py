import unittest

from theory_campaign import (
    AIS_PATH,
    load_real_ais_tracks,
    run_anytime_valid_access_monitor,
    run_conformal_alert_control,
    run_conformal_trajectory,
    run_crypto_agility_graph,
    run_distribution_shift_stress,
    run_robust_sensor_scheduling,
    run_unknown_correlation_fusion,
)


class TheoryCampaignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tracks = load_real_ais_tracks(AIS_PATH, maximum_tracks=220)

    def test_conformal_trajectory_is_calibrated(self):
        result = run_conformal_trajectory(self.tracks)
        self.assertGreaterEqual(result["global"]["empirical_coverage"], 0.87)
        self.assertGreaterEqual(
            result["speed_conditioned"]["empirical_coverage"],
            0.87,
        )

    def test_conformal_alerting_controls_discoveries(self):
        result = run_conformal_alert_control(self.tracks)
        self.assertLessEqual(
            result["high_confidence"]["empirical_false_discovery_proportion"],
            0.10,
        )
        self.assertGreaterEqual(result["watch"]["recall"], 0.60)

    def test_covariance_intersection_prevents_overconfidence(self):
        result = run_unknown_correlation_fusion(trials=5_000)
        self.assertGreater(
            result["covariance_intersection"]["nominal_95pct_ellipse_coverage"],
            result["naive_independence"]["nominal_95pct_ellipse_coverage"],
        )

    def test_rolling_conformal_adapts_after_shift(self):
        result = run_distribution_shift_stress(self.tracks)
        shifted = result["stress"][2]
        self.assertGreater(
            shifted["rolling_coverage_after_warmup"],
            shifted["static_coverage"],
        )
        self.assertGreaterEqual(
            shifted["rolling_coverage_after_warmup"],
            0.87,
        )

    def test_anytime_access_monitor(self):
        result = run_anytime_valid_access_monitor(sequences=1_000)
        self.assertLessEqual(result["nominal_false_alarm_rate"], 0.02)
        self.assertGreaterEqual(result["attack_detection_rate"], 0.90)

    def test_crypto_graph_and_robust_scheduler(self):
        crypto = run_crypto_agility_graph(assets=100)
        scheduling = run_robust_sensor_scheduling(scenarios=500)
        self.assertEqual(crypto["dependency_safe_violations"], 0)
        self.assertGreater(scheduling["robust_p05_improvement_pct"], 0)


if __name__ == "__main__":
    unittest.main()
