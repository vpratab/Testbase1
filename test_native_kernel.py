import unittest

from assure_core.native_kernel import build_native_kernel, run_native_kernel
from assure_core.wire import TRACK_FRAME_BYTES, decode_authenticated_track
from assure_core.rtvlas import (
    EvidenceChannel,
    SequentialEvidenceAccumulator,
    custody_confidence,
    marginal_information_value,
    priority_score,
)


class NativeKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_native_kernel()

    def test_native_and_python_decisions_conform(self):
        native = run_native_kernel("conformance", build=False)
        custody = custody_confidence(
            association_distance=0.2,
            velocity_difference=0.1,
            misses=1,
            identity_consistency=0.95,
        )
        priority = priority_score(
            anomaly=0.8,
            forecasted_proximity=0.7,
            closing_rate=0.6,
            uncertainty=0.3,
            custody=custody,
        )
        information = marginal_information_value(
            prior_variance=0.5,
            measurement_variance=0.02,
            mission_priority=1.0,
            task_cost=1.0,
            conflict_penalty=0.05,
        )
        monitor = SequentialEvidenceAccumulator(
            (
                EvidenceChannel("first", 1.0, 0.5, 2.0, 5.0, 0.9),
                EvidenceChannel("second", 1.2, 0.25, 1.5, 4.0, 0.8),
            )
        )
        monitor.scores = {"first": 1.0, "second": 2.0}
        evidence = monitor.update({"first": 3.0, "second": 3.0})

        self.assertAlmostEqual(native["custody"], custody, places=12)
        self.assertAlmostEqual(native["priority"], priority, places=12)
        self.assertAlmostEqual(
            native["information_value"]["utility"],
            information["utility"],
            places=12,
        )
        self.assertEqual(native["evidence_decision"], evidence["decision"])
        self.assertEqual(
            native["evidence_scores"],
            [evidence["scores"]["first"], evidence["scores"]["second"]],
        )
        self.assertTrue(native["track_round_trip"])
        self.assertTrue(native["tamper_rejected"])
        self.assertTrue(native["replay_rejected"])
        self.assertAlmostEqual(native["covariance_intersection_weight"], 0.5, places=2)
        self.assertTrue(native["anytime_alarm"])
        self.assertEqual(native["track_frame_bytes"], 136)

    def test_release_performance_has_large_safety_margin(self):
        result = run_native_kernel("benchmark", "50000", build=False)
        self.assertLess(result["evidence_ns_per_operation"], 10_000)
        self.assertLess(result["custody_priority_ns_per_operation"], 5_000)
        self.assertLess(result["track_decode_ns_per_operation"], 100_000)
        self.assertLess(result["scheduler_ns_per_operation"], 1_000_000)
        self.assertLess(result["association_ns_per_operation"], 10_000_000)
        self.assertEqual(result["scheduler_candidates"], 240)
        self.assertEqual(result["association_objects"], 1_000)

    def test_wire_vector_is_independently_decodable(self):
        vector = run_native_kernel("vector", build=False)
        frame = bytes.fromhex(vector["frame_hex"])
        key = bytes.fromhex(vector["key_hex"])
        decoded = decode_authenticated_track(frame, key)
        self.assertEqual(len(frame), TRACK_FRAME_BYTES)
        self.assertEqual(decoded["sequence"], vector["track"]["sequence"])
        self.assertEqual(decoded["track_id"], vector["track"]["track_id"])
        self.assertAlmostEqual(decoded["quality"], vector["track"]["quality"], places=6)
        for index in range(0, len(frame), 17):
            tampered = bytearray(frame)
            tampered[index] ^= 1
            with self.assertRaises(ValueError):
                decode_authenticated_track(bytes(tampered), key)


if __name__ == "__main__":
    unittest.main()
