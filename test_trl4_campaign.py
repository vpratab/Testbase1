import base64
import unittest
from pathlib import Path

from trl4_common import EvidenceChain, tamper_test
from trl4_cyber import (
    HybridTaskGateway,
    benchmark_pqc,
    build_modbus_frame,
    create_piv_surrogate,
    normalize_provider_payload,
    open_hybrid_task,
    parse_modbus_tcp,
    provider_payload,
    run_nv059_trl4,
    verify_certificate_chain,
    verify_key_possession,
)
from trl4_tracks import (
    evaluate_real_ais_pol,
    evaluate_real_ais_forecasting,
    load_real_ais_tracks,
    run_np002_trl4,
    run_nv061_trl4,
    run_nv065_trl4,
)


ROOT = Path(__file__).resolve().parent
AIS_SUBSET = ROOT / "data" / "processed" / "noaa_ais_puget_sound_2020_02_15.csv"


class CommonEvidenceTests(unittest.TestCase):
    def test_signed_chain_verifies_and_tampering_fails(self):
        chain = EvidenceChain(b"test")
        chain.append("test", {"value": 1})
        chain.append("test", {"value": 2})
        self.assertTrue(EvidenceChain.verify(chain.records, chain.public_key))
        self.assertTrue(tamper_test(chain.records, chain.public_key))


class CyberTRL4Tests(unittest.TestCase):
    def test_actual_pqc_operations(self):
        result = benchmark_pqc(iterations=3)
        self.assertEqual(result["ml_kem_768"]["valid_shared_secrets"], 3)
        self.assertEqual(result["ml_dsa_65"]["valid_signatures"], 3)
        self.assertEqual(result["ml_dsa_65"]["tamper_rejected"], 3)

    def test_piv_surrogate_chain_challenge_and_revocation(self):
        piv = create_piv_surrogate()
        self.assertTrue(
            verify_certificate_chain(
                piv["client"],
                piv["intermediate"],
                piv["root"],
                set(),
            )
        )
        self.assertTrue(verify_key_possession(piv["client_private"], piv["client"]))
        self.assertFalse(
            verify_certificate_chain(
                piv["client"],
                piv["intermediate"],
                piv["root"],
                {piv["client"].serial_number},
            )
        )

    def test_modbus_adapter_parses_and_rejects(self):
        parsed = parse_modbus_tcp(build_modbus_frame(1, 7, 6))
        self.assertEqual(parsed["action"], "command")
        with self.assertRaises(ValueError):
            parse_modbus_tcp(b"\x00")

    def test_nv059_surrogate(self):
        result = run_nv059_trl4(requests=400)
        self.assertGreaterEqual(result["authorization"]["f1"], 0.98)
        self.assertTrue(result["evidence"]["verified"])

    def test_hybrid_task_opens_and_tampering_fails(self):
        gateway = HybridTaskGateway()
        payload = normalize_provider_payload(0, provider_payload(0, 1))
        envelope = gateway.seal(payload)
        opened = gateway.open_once(envelope)
        self.assertEqual(opened["task_id"], payload["task_id"])

        modified = dict(gateway.seal(normalize_provider_payload(1, provider_payload(1, 2))))
        ciphertext = bytearray(base64.b64decode(modified["ciphertext"]))
        ciphertext[0] ^= 1
        modified["ciphertext"] = base64.b64encode(ciphertext).decode()
        with self.assertRaises(Exception):
            open_hybrid_task(
                modified,
                gateway.x25519_private,
                gateway.mlkem_secret,
                gateway.sender_ed25519_private.public_key(),
                gateway.sender_mldsa_public,
            )


class TrackTRL4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ais_tracks = load_real_ais_tracks(AIS_SUBSET, maximum_tracks=500)

    def test_real_ais_pol_reaches_phase1_feasibility_floor(self):
        result = evaluate_real_ais_pol(self.ais_tracks)
        self.assertGreaterEqual(result["f1"], 0.70)
        self.assertLessEqual(result["false_positive_rate"], 0.25)
        self.assertTrue(result["evidence"]["verified"])

    def test_cuas_tracking_and_behavior(self):
        result = run_np002_trl4(scenarios=20)
        self.assertGreaterEqual(result["behavior_detection"]["f1"], 0.85)
        self.assertGreaterEqual(
            result["track_association"]["mean_assignment_accuracy"],
            0.75,
        )

    def test_predictive_tracking_and_hierarchy(self):
        result = run_nv061_trl4(object_count=100)
        self.assertGreater(result["forecast"]["improvement_vs_hold_pct"], 50.0)
        self.assertGreater(result["track_custody"]["assignment_accuracy"], 0.90)
        self.assertGreater(
            result["hierarchy"]["priority_recall_at_threat_count"],
            0.60,
        )
        real = evaluate_real_ais_forecasting(self.ais_tracks[:150])
        self.assertGreater(real["improvement_vs_hold_pct"], 0.0)
        self.assertGreater(real["improvement_vs_raw_velocity_pct"], 10.0)

    def test_sensor_management(self):
        result = run_nv065_trl4()
        self.assertGreater(result["novel_threat_quality_improvement_pct"], 70.0)
        self.assertLess(result["recommendation_runtime_p95_us"], 100_000.0)
        self.assertTrue(result["evidence"]["tamper_detected"])


if __name__ == "__main__":
    unittest.main()
