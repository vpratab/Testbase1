import time
import unittest

from compile_tuned_systems import build_ablations
from assure_core.profiles import TOPIC_DESIGNS, validate_design_set
from assure_core.pzdr import CryptoAssetNode, PurposeBoundIntent, TrustLease
from assure_core.systems import (
    MaritimePolSystem,
    PredictiveMovementSystem,
    QsparxSystem,
    SecureTaskSystem,
    SensorManagementSystem,
    SwarmIntentSystem,
    ZeroTrustSystem,
)


class DesignTests(unittest.TestCase):
    def test_all_seven_designs_are_distinct_and_valid(self):
        validate_design_set()
        self.assertEqual(len(TOPIC_DESIGNS), 7)
        self.assertEqual(
            len({design.fingerprint for design in TOPIC_DESIGNS.values()}),
            7,
        )
        self.assertEqual(
            len({design.mission_question for design in TOPIC_DESIGNS.values()}),
            7,
        )

    def test_topic_evidence_semantics_are_not_generic(self):
        proves = {
            topic: design.evidence.proves
            for topic, design in TOPIC_DESIGNS.items()
        }
        self.assertEqual(len({value for value in proves.values()}), 7)

    def test_all_philosophy_ablations_change_the_expected_decision(self):
        ablations = build_ablations()
        self.assertEqual(
            ablations["NV059"]["persistent_sequence_action"],
            "deny",
        )
        self.assertNotEqual(
            ablations["NV062"]["first_use_action"],
            ablations["NV062"]["replay_action"],
        )
        self.assertNotEqual(
            ablations["NP002"]["transient_action"],
            ablations["NP002"]["sustained_action"],
        )
        self.assertNotEqual(
            ablations["NV063"]["transient_alert_tier"],
            ablations["NV063"]["sustained_alert_tier"],
        )
        self.assertNotEqual(
            ablations["NV065"]["without_conflict"],
            ablations["NV065"]["with_conflict"],
        )


class PzdrPhilosophyTests(unittest.TestCase):
    def test_qsparx_dependency_order_prevents_breakage(self):
        assets = [
            CryptoAssetNode("root", "rsa2048", 80, set(), "ml-dsa", 2),
            CryptoAssetNode("service", "rsa2048", 95, {"root"}, "ml-kem", 1),
        ]
        decision = QsparxSystem(assets).decide()
        self.assertEqual(decision.topic, "QSPARX")
        self.assertEqual(decision.evidence_payload["asset_id"], "service")
        self.assertEqual(decision.evidence_payload["migration_wave"], 2)

    def test_zero_trust_lease_expires_and_persistent_behavior_denies(self):
        now = time.time()
        system = ZeroTrustSystem(
            TrustLease(
                policy_version="7",
                identity_version="3",
                issued_at=now - 10,
                expires_at=now + 60,
                permitted_actions=frozenset({"read"}),
                permitted_resources=frozenset({"track-17"}),
                issuer_signature_valid=True,
            )
        )
        first = system.decide(
            request_id="1",
            subject_id="operator",
            resource_id="track-17",
            action="read",
            now=now,
            behavior_evidence={"request_rate": 0.5},
        )
        self.assertEqual(first.action, "allow")
        denied = None
        for index in range(8):
            denied = system.decide(
                request_id=f"attack-{index}",
                subject_id="operator",
                resource_id="track-17",
                action="read",
                now=now,
                behavior_evidence={
                    "request_rate": 4.0,
                    "failed_access": 3.0,
                    "data_volume": 4.0,
                },
            )
        self.assertIsNotNone(denied)
        self.assertEqual(denied.action, "deny")
        expired = system.decide(
            request_id="expired",
            subject_id="operator",
            resource_id="track-17",
            action="read",
            now=now + 120,
            behavior_evidence={},
        )
        self.assertEqual(expired.action, "deny")

    def test_secure_task_is_purpose_bound_and_single_use(self):
        now = time.time()
        intent = PurposeBoundIntent(
            intent_id="task-9",
            purpose="maritime collection",
            subject="government-gateway",
            object_id="provider-alpha",
            action="task",
            valid_from=now - 1,
            valid_until=now + 60,
        )
        system = SecureTaskSystem()
        accepted = system.decide(intent, now=now, provider="provider-alpha")
        replay = system.decide(intent, now=now, provider="provider-alpha")
        self.assertEqual(accepted.action, "release_task")
        self.assertEqual(replay.action, "quarantine_task")


class RtvlasPhilosophyTests(unittest.TestCase):
    def test_swarm_requires_persistent_evidence(self):
        system = SwarmIntentSystem()
        first = system.decide(
            swarm_id="s1",
            protected_asset="ship",
            evidence={"centroid_closing": 1.0},
            custody_quality=0.9,
        )
        self.assertEqual(first.action, "continue_monitoring")
        final = first
        for _ in range(8):
            final = system.decide(
                swarm_id="s1",
                protected_asset="ship",
                evidence={
                    "centroid_closing": 3.0,
                    "formation_contraction": 2.5,
                    "members_toward_asset": 3.0,
                    "zone_penetration": 2.0,
                },
                custody_quality=0.9,
            )
        self.assertEqual(final.action, "activate_protective_measure")

    def test_weak_custody_reduces_priority_confidence(self):
        system = PredictiveMovementSystem()
        strong = system.decide(
            object_id="o1",
            forecast_state=[1, 2],
            forecast_uncertainty=0.4,
            association_distance=0.1,
            velocity_difference=0.1,
            misses=0,
            identity_consistency=0.99,
            anomaly=0.8,
            proximity=0.8,
            closing=0.7,
        )
        weak = system.decide(
            object_id="o1",
            forecast_state=[1, 2],
            forecast_uncertainty=0.4,
            association_distance=7.0,
            velocity_difference=3.0,
            misses=4,
            identity_consistency=0.45,
            anomaly=0.8,
            proximity=0.8,
            closing=0.7,
        )
        self.assertGreater(strong.confidence, weak.confidence)
        self.assertNotEqual(
            strong.evidence_payload["priority_level"],
            weak.evidence_payload["priority_level"],
        )

    def test_maritime_pol_has_watch_then_high_confidence(self):
        system = MaritimePolSystem()
        decisions = []
        for _ in range(8):
            decisions.append(
                system.decide(
                    track_number="101",
                    evidence={"heading": 3.0, "closing": 2.5},
                    details={"speed": 12},
                    local_context="shipping lane",
                )
            )
        tiers = [decision.evidence_payload["alert_tier"] for decision in decisions]
        self.assertIn("watch", tiers)
        self.assertIn("high_confidence", tiers)

    def test_sensor_conflict_can_reverse_recommendation(self):
        system = SensorManagementSystem()
        useful = system.decide(
            sensor_id="SPY-6 surrogate",
            released_task="maintain-good-track",
            candidate_task="cue-novel-track",
            affected_track="T7",
            prior_variance=0.5,
            measurement_variance=0.02,
            mission_priority=1.0,
            task_cost=1.0,
            conflict_penalty=0.0,
        )
        conflicted = system.decide(
            sensor_id="SPY-6 surrogate",
            released_task="maintain-good-track",
            candidate_task="cue-novel-track",
            affected_track="T7",
            prior_variance=0.5,
            measurement_variance=0.02,
            mission_priority=1.0,
            task_cost=1.0,
            conflict_penalty=1.0,
        )
        self.assertEqual(useful.action, "recommend_reallocation")
        self.assertEqual(conflicted.action, "retain_current_task")


if __name__ == "__main__":
    unittest.main()
