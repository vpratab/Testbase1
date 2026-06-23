import unittest

from run_wave4_campaign import NASA_ROOT, OPENSKY_LONG, rescore, validate
from trl4_wave4 import (
    evaluate_opensky_air_anomalies,
    run_composite_track_interface,
    run_cross_domain_gateway_controls,
    run_cross_domain_priority_ranking,
    run_enterprise_crypto_range,
    run_multi_provider_sar_return,
    run_network_microsegmentation_gateway,
    run_traceable_radar_scheduler,
    run_uas_typed_track_fusion,
)


class WaveFourTests(unittest.TestCase):
    def test_enterprise_crypto_range(self):
        result = run_enterprise_crypto_range(8)
        self.assertEqual(result["endpoint_inventory_accuracy"], 1.0)
        self.assertGreaterEqual(result["dependency_edges"], 20)

    def test_network_microsegmentation(self):
        result = run_network_microsegmentation_gateway(12, 6)
        self.assertEqual(
            result["authorized_completed"],
            result["authorized_requests"],
        )
        self.assertEqual(
            result["unauthorized_denied"],
            result["unauthorized_requests"],
        )
        self.assertFalse(result["direct_tcp_backend_exposure"])

    def test_provider_returns_and_cross_domain_controls(self):
        providers = run_multi_provider_sar_return()
        controls = run_cross_domain_gateway_controls(transactions=120)
        self.assertEqual(providers["real_provider_data_returns"], 2)
        self.assertTrue(providers["all_hybrid_verified"])
        self.assertEqual(controls["authorization"]["f1"], 1.0)

    def test_typed_uas_tracking(self):
        result = run_uas_typed_track_fusion(NASA_ROOT)
        self.assertGreater(
            result["acoustic_typed_accuracy"],
            result["position_only_accuracy"],
        )
        self.assertLess(
            result["acoustic_typed_identity_switches"],
            result["position_only_identity_switches"],
        )

    def test_air_anomaly_and_composite_interface(self):
        air = evaluate_opensky_air_anomalies(OPENSKY_LONG)
        interface = run_composite_track_interface(1000)
        self.assertGreaterEqual(air["f1"], 0.90)
        self.assertEqual(
            interface["tamper_rejected"],
            interface["tamper_cases"],
        )
        self.assertEqual(
            interface["replays_rejected"],
            interface["replays_tested"],
        )

    def test_traceable_radar_scheduler(self):
        result = run_traceable_radar_scheduler()
        self.assertEqual(result["invalid_schedules"], 0)
        self.assertAlmostEqual(
            result["radar_equation_validation"]["double_power_db"],
            3.0103,
            places=2,
        )
        self.assertAlmostEqual(
            result["radar_equation_validation"]["double_range_db"],
            -12.0412,
            places=2,
        )

    def test_priority_and_full_validation(self):
        results = {
            "QSPARX": run_enterprise_crypto_range(16),
            "NV059": run_network_microsegmentation_gateway(12, 6),
            "NV061": run_cross_domain_priority_ranking(OPENSKY_LONG),
            "NV062": {
                "providers": run_multi_provider_sar_return(),
                "controls": run_cross_domain_gateway_controls(transactions=120),
            },
            "NP002": run_uas_typed_track_fusion(NASA_ROOT),
            "NV063": {
                "air": evaluate_opensky_air_anomalies(OPENSKY_LONG),
                "interface": run_composite_track_interface(1000),
            },
            "NV065": run_traceable_radar_scheduler(),
        }
        validate(results)


if __name__ == "__main__":
    unittest.main()
