"""RTVLAS-derived primitives: predict, compare, accumulate, explain, preserve."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np


@dataclass(frozen=True)
class EvidenceChannel:
    name: str
    weight: float
    slack: float
    flag_threshold: float
    reject_threshold: float
    decay: float = 0.92


class SequentialEvidenceAccumulator:
    """Accumulates weak contradictions without treating one sample as truth."""

    def __init__(self, channels: Iterable[EvidenceChannel]) -> None:
        self.channels = {channel.name: channel for channel in channels}
        self.scores = {channel.name: 0.0 for channel in channels}

    def update(self, evidence: dict[str, float]) -> dict[str, object]:
        reasons: list[str] = []
        reject = False
        flag = False
        weighted_total = 0.0
        for name, channel in self.channels.items():
            value = max(float(evidence.get(name, 0.0)), 0.0)
            score = max(
                0.0,
                self.scores[name] * channel.decay + value - channel.slack,
            )
            self.scores[name] = score
            weighted_total += score * channel.weight
            if score >= channel.reject_threshold:
                reject = True
                reasons.append(f"{name}_persistent_reject")
            elif score >= channel.flag_threshold:
                flag = True
                reasons.append(f"{name}_persistent_flag")
        decision = "reject" if reject else "flag" if flag else "accept"
        return {
            "decision": decision,
            "reasons": reasons or ["evidence_within_expected_envelope"],
            "scores": dict(self.scores),
            "weighted_total": weighted_total,
        }


@dataclass(frozen=True)
class ForecastWithUncertainty:
    state: np.ndarray
    covariance: np.ndarray
    horizon: int

    @property
    def uncertainty(self) -> float:
        return float(np.trace(self.covariance))


def consistency_residual(
    observation: np.ndarray,
    forecast: ForecastWithUncertainty,
    observation_covariance: np.ndarray,
) -> float:
    residual = observation - forecast.state
    covariance = forecast.covariance + observation_covariance
    solved = np.linalg.solve(covariance, residual)
    return float(residual.T @ solved)


def custody_confidence(
    *,
    association_distance: float,
    velocity_difference: float,
    misses: int,
    identity_consistency: float,
) -> float:
    penalty = (
        0.08 * association_distance
        + 0.18 * velocity_difference
        + 0.12 * misses
    )
    return float(
        np.clip(identity_consistency * np.exp(-penalty), 0.0, 1.0)
    )


def priority_score(
    *,
    anomaly: float,
    forecasted_proximity: float,
    closing_rate: float,
    uncertainty: float,
    custody: float,
) -> float:
    """Priority falls when custody is weak, instead of hiding uncertainty."""
    raw = (
        0.38 * anomaly
        + 0.24 * forecasted_proximity
        + 0.18 * closing_rate
        + 0.12 * uncertainty
        + 0.08 * custody
    )
    return float(np.clip(raw * (0.55 + 0.45 * custody), 0.0, 1.0))


def marginal_information_value(
    *,
    prior_variance: float,
    measurement_variance: float,
    mission_priority: float,
    task_cost: float,
    conflict_penalty: float,
) -> dict[str, float]:
    posterior = 1.0 / (
        1.0 / max(prior_variance, 1.0e-12)
        + 1.0 / max(measurement_variance, 1.0e-12)
    )
    gain = max(prior_variance - posterior, 0.0)
    utility = (
        gain
        * max(mission_priority, 0.0)
        / max(task_cost, 1.0e-12)
        - max(conflict_penalty, 0.0)
    )
    return {
        "posterior_variance": posterior,
        "information_gain": gain,
        "utility": utility,
    }
