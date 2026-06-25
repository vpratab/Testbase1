import unittest

from run_wave5_campaign import AIS_PATH, OPENSKY_LONG, validate
from trl4_tracks import load_real_ais_tracks
from trl4_wave5 import (
    run_beam_revisit_scheduler,
    run_composite_track_contract_v2,
    run_il5_control_evidence,
    run_long_cross_domain_pol,
    run_provider_tasking_conformance,
    run_qsparx_migration_execution,
    run_sensor_task_contract_v2,
    run_surface_track_classifier_cv,
)


class WaveFiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ais_tracks = load_real_ais_tracks(AIS_PATH, maximum_tracks=500)

    def test_qsparx_migration_execution(self):
        result = run_qsparx_migration_execution(12)
        self.assertEqual(result["active_endpoint_inventory_accuracy"], 1.0)
        self.assertEqual(result["pkcs12_keystores_parsed"], 12)
        self.assertTrue(result["migration_order_complete"])

    def test_provider_schema_and_authentication_boundaries(self):
        result = run_provider_tasking_conformance()
        self.assertEqual(result["valid_schema_acceptance_rate"], 1.0)
        self.assertEqual(result["invalid_schema_rejection_rate"], 1.0)
        self.assertTrue(result["authentication_boundary_or_offline_fail_closed"])
        self.assertTrue(
            result["capella_openapi_reached"]
            or result["capella_openapi_shape_valid"]
        )
        self.assertFalse(result["live_task_submitted"])

    def test_il5_control_evidence_is_not_authorization_claim(self):
        result = run_il5_control_evidence()
        self.assertEqual(result["controls_passed"], result["control_count"])
        self.assertTrue(result["evidence"]["verified"])
        self.assertFalse(result["authorization_claim"])

    def test_grouped_surface_classifier(self):
        result = run_surface_track_classifier_cv(self.ais_tracks)
        self.assertGreater(result["f1"], 0.95)
        self.assertGreater(result["recall"], 0.95)
        self.assertGreater(result["minimum_fold_f1"], 0.94)

    def test_long_air_and_composite_contract(self):
        air = run_long_cross_domain_pol(OPENSKY_LONG)
        interface = run_composite_track_contract_v2(5000)
        self.assertGreater(air["f1"], 0.95)
        self.assertEqual(
            interface["tamper_rejected"],
            interface["tamper_cases"],
        )
        self.assertEqual(
            interface["old_versions_rejected"],
            interface["old_version_cases"],
        )

    def test_beam_revisit_and_operator_advisory_contract(self):
        scheduler = run_beam_revisit_scheduler()
        interface = run_sensor_task_contract_v2(5000)
        self.assertEqual(scheduler["invalid_schedules"], 0)
        self.assertEqual(scheduler["missed_revisit_deadlines"], 0)
        self.assertTrue(interface["operator_confirmation_required"])
        self.assertFalse(interface["automated_retasking"])

    def test_full_wave_validation(self):
        results = {
            "QSPARX": run_qsparx_migration_execution(12),
            "NV062": {
                "provider": run_provider_tasking_conformance(),
                "controls": run_il5_control_evidence(),
            },
            "NV063": {
                "surface": run_surface_track_classifier_cv(self.ais_tracks),
                "air": run_long_cross_domain_pol(OPENSKY_LONG),
                "interface": run_composite_track_contract_v2(5000),
            },
            "NV065": {
                "scheduler": run_beam_revisit_scheduler(),
                "interface": run_sensor_task_contract_v2(5000),
            },
        }
        validate(results)


if __name__ == "__main__":
    unittest.main()
