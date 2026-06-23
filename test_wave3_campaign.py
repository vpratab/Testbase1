import unittest
from pathlib import Path

from run_wave3_campaign import NASA_ROOT, OPENSKY_LONG, validate
from trl4_extensions import (
    evaluate_real_opensky_forecasting,
    run_dds_authorization_proxy,
    run_public_stac_return_integration,
    run_secure_opcua_channel,
)
from trl4_uas_acoustics import evaluate_nasa_uas_acoustics


class WaveThreeTests(unittest.TestCase):
    def test_secure_opcua_rejects_unsecured_and_round_trips(self):
        result = run_secure_opcua_channel(transactions=12)
        self.assertTrue(result["unsecured_client_rejected"])
        self.assertEqual(
            result["successful_round_trips"],
            result["transactions"],
        )

    def test_actual_cyclone_dds_authorization(self):
        result = run_dds_authorization_proxy(requests=40)
        self.assertEqual(result["authorization"]["f1"], 1.0)
        self.assertTrue(result["evidence"]["tamper_detected"])

    def test_real_stac_return_uses_hybrid_verification(self):
        result = run_public_stac_return_integration()
        self.assertTrue(result["provider_api_reached"])
        self.assertTrue(result["hybrid_return_verified"])
        self.assertFalse(result["collection_tasking_claim"])

    def test_nasa_acoustic_recording_holdouts(self):
        result = evaluate_nasa_uas_acoustics(NASA_ROOT)
        self.assertGreater(result["detection"]["f1"], 0.90)
        self.assertGreater(
            result["type_classification"]["macro_f1"],
            0.85,
        )
        self.assertGreater(
            min(fold["type_macro_f1"] for fold in result["recording_level_folds"]),
            0.80,
        )

    def test_long_opensky_forecast(self):
        result = evaluate_real_opensky_forecasting(OPENSKY_LONG)
        self.assertGreater(result["forecast_intervals"], 500)
        self.assertGreater(result["improvement_vs_hold_pct"], 50.0)

    def test_wave_three_validation(self):
        results = {
            "NV059": {
                "secure_opcua": run_secure_opcua_channel(transactions=6),
                "dds": run_dds_authorization_proxy(requests=20),
            },
            "NV062": {"stac": run_public_stac_return_integration()},
            "NP002": {
                "nasa_acoustics": evaluate_nasa_uas_acoustics(NASA_ROOT)
            },
            "NV061": {
                "opensky_forecast": evaluate_real_opensky_forecasting(
                    OPENSKY_LONG
                )
            },
        }
        validate(results)


if __name__ == "__main__":
    unittest.main()
