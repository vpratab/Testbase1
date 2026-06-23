import unittest
from pathlib import Path

from trl4_extensions import (
    evaluate_calibrated_ais_pol,
    evaluate_mixed_domain_custody,
    run_cuas_scale_and_fusion_stress,
    run_opcua_enforcement_proxy,
    run_qsparx_extension,
    run_secure_provider_workflow_extension,
    run_sensor_constraint_stress,
)
from trl4_tracks import load_real_ais_tracks
from run_extended_campaign import validate_results


ROOT = Path(__file__).resolve().parent
AIS_PATH = ROOT / "data" / "processed" / "noaa_ais_puget_sound_2020_02_15.csv"
OPENSKY_PATH = ROOT / "data" / "external" / "opensky" / "puget_sound_states.json"


class ExtendedCyberTests(unittest.TestCase):
    def test_active_tls_and_dependency_discovery(self):
        result = run_qsparx_extension([ROOT])
        self.assertEqual(
            result["active_tls_discovery"]["handshakes_succeeded"],
            1,
        )
        self.assertGreaterEqual(
            result["key_and_config_dependencies"]["dependency_edges"],
            2,
        )
        self.assertTrue(result["evidence"]["verified"])

    def test_actual_opcua_enforcement_and_partition_behavior(self):
        result = run_opcua_enforcement_proxy(requests=40)
        self.assertTrue(result["direct_protected_write_blocked"])
        self.assertEqual(result["authorization"]["f1"], 1.0)
        self.assertGreater(result["offline_partition_decisions"], 0)

    def test_provider_lifecycle_and_return_integrity(self):
        result = run_secure_provider_workflow_extension(tasks=8)
        self.assertEqual(result["accepted"], 8)
        self.assertEqual(result["duplicate_blocked"], 8)
        self.assertEqual(
            result["return_integrity_verified"],
            result["tampered_return_blocked"],
        )


class ExtendedMissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tracks = load_real_ais_tracks(AIS_PATH, maximum_tracks=500)

    def test_cuas_scales_to_150(self):
        result = run_cuas_scale_and_fusion_stress()
        self.assertEqual(result["maximum_uas"], 150)
        self.assertGreater(result["scale"]["150"]["assignment_accuracy"], 0.98)
        self.assertLess(result["scale"]["150"]["p95_update_ms"], 100.0)

    def test_mixed_domain_source_custody_reduces_switches(self):
        result = evaluate_mixed_domain_custody(self.tracks, OPENSKY_PATH)
        self.assertGreater(
            result["source_aware_accuracy"],
            result["position_only_accuracy"],
        )
        self.assertLess(
            result["source_aware_identity_switches"],
            result["position_only_identity_switches"],
        )

    def test_persistent_ais_alerts_reduce_false_alerts(self):
        result = evaluate_calibrated_ais_pol(self.tracks, seed=63)
        self.assertGreaterEqual(result["recall"], 0.68)
        self.assertLessEqual(result["false_positive_rate"], 0.12)

    def test_sensor_constraints_eliminate_invalid_schedules(self):
        result = run_sensor_constraint_stress()
        self.assertGreater(result["naive_invalid_sensor_schedules"], 0)
        self.assertEqual(result["constrained_invalid_sensor_schedules"], 0)
        self.assertLess(result["scheduler_p95_us"], 100_000)

    def test_campaign_validation_accepts_measured_results(self):
        results = {
            "QSPARX": run_qsparx_extension([ROOT]),
            "NV059": run_opcua_enforcement_proxy(requests=20),
            "NV062": run_secure_provider_workflow_extension(tasks=4),
            "NP002": run_cuas_scale_and_fusion_stress(),
            "NV061": evaluate_mixed_domain_custody(
                self.tracks,
                OPENSKY_PATH,
            ),
            "NV063": {
                "robustness": {
                    "false_positive_rate_mean": 0.092,
                    "recall_mean": 0.752,
                }
            },
            "NV065": run_sensor_constraint_stress(),
        }
        validate_results(results)


if __name__ == "__main__":
    unittest.main()
