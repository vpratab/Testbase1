#!/usr/bin/env python3
"""Theory-driven experiments that strengthen the seven Phase I arguments.

These experiments focus on defensible guarantees and failure behavior:

- finite-sample conformal trajectory coverage;
- false-discovery-rate-controlled maritime alerting;
- covariance intersection under unknown sensor correlation;
- anytime-valid sequential evidence for zero-trust monitoring;
- dependency-safe cryptographic migration;
- robust sensor scheduling under degraded measurements.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from assure_core.pzdr import CryptoAssetNode, MigrationWavePlanner
from trl4_common import runtime_metadata, write_json
from trl4_tracks import (
    MaritimeTrack,
    ais_pol_score,
    inject_track_anomaly,
    load_real_ais_tracks,
)


ROOT = Path(__file__).resolve().parent
AIS_PATH = ROOT / "data" / "processed" / "noaa_ais_puget_sound_2020_02_15.csv"
OUTPUT = ROOT / "results" / "theory_campaign"


def finite_sample_quantile(values: Iterable[float], coverage: float) -> float:
    ordered = np.sort(np.asarray(list(values), dtype=float))
    if ordered.size == 0:
        raise ValueError("at least one calibration value is required")
    rank = min(
        int(math.ceil((ordered.size + 1) * coverage)) - 1,
        ordered.size - 1,
    )
    return float(ordered[max(rank, 0)])


def trajectory_examples(
    tracks: list[MaritimeTrack],
    *,
    horizon: int,
    window: int,
    gain: float,
) -> list[tuple[float, float]]:
    """Return (forecast error, recent speed) without crossing track boundaries."""
    examples: list[tuple[float, float]] = []
    for track in tracks:
        positions = track.positions
        if len(positions) < window + horizon + 5:
            continue
        for step in range(window, len(positions) - horizon):
            recent_velocity = np.diff(
                positions[step - window : step + 1],
                axis=0,
            )
            smoothed_velocity = np.mean(recent_velocity, axis=0)
            prediction = positions[step] + gain * horizon * smoothed_velocity
            error = float(np.linalg.norm(prediction - positions[step + horizon]))
            speed = float(np.linalg.norm(smoothed_velocity))
            examples.append((error, speed))
    return examples


def run_conformal_trajectory(
    tracks: list[MaritimeTrack],
    *,
    coverage: float = 0.90,
    horizon: int = 5,
) -> dict[str, Any]:
    if len(tracks) < 60:
        raise ValueError("at least 60 independent tracks are required")
    tuning = tracks[: max(20, len(tracks) // 5)]
    calibration = tracks[len(tuning) : len(tuning) + max(30, len(tracks) // 4)]
    evaluation = tracks[len(tuning) + len(calibration) :]

    best: tuple[float, int, float] | None = None
    for window in (2, 3, 5, 8):
        for gain in (0.2, 0.3, 0.4, 0.5, 0.6, 0.7):
            errors = [
                error
                for error, _ in trajectory_examples(
                    tuning,
                    horizon=horizon,
                    window=window,
                    gain=gain,
                )
            ]
            rmse = float(np.sqrt(np.mean(np.square(errors))))
            if best is None or rmse < best[0]:
                best = (rmse, window, gain)
    assert best is not None
    _, window, gain = best

    calibration_examples = trajectory_examples(
        calibration,
        horizon=horizon,
        window=window,
        gain=gain,
    )
    evaluation_examples = trajectory_examples(
        evaluation,
        horizon=horizon,
        window=window,
        gain=gain,
    )
    calibration_errors = np.asarray(
        [error for error, _ in calibration_examples],
        dtype=float,
    )
    evaluation_errors = np.asarray(
        [error for error, _ in evaluation_examples],
        dtype=float,
    )
    evaluation_speeds = np.asarray(
        [speed for _, speed in evaluation_examples],
        dtype=float,
    )

    global_radius = finite_sample_quantile(calibration_errors, coverage)
    global_coverage = float(np.mean(evaluation_errors <= global_radius))

    calibration_speeds = np.asarray(
        [speed for _, speed in calibration_examples],
        dtype=float,
    )
    speed_boundary = float(np.median(calibration_speeds))
    low_radius = finite_sample_quantile(
        calibration_errors[calibration_speeds <= speed_boundary],
        coverage,
    )
    high_radius = finite_sample_quantile(
        calibration_errors[calibration_speeds > speed_boundary],
        coverage,
    )
    adaptive_radii = np.where(
        evaluation_speeds <= speed_boundary,
        low_radius,
        high_radius,
    )
    adaptive_coverage = float(np.mean(evaluation_errors <= adaptive_radii))

    return {
        "coverage_target": coverage,
        "forecast_horizon_steps": horizon,
        "selected_window": window,
        "selected_gain": gain,
        "independent_track_split": {
            "tuning": len(tuning),
            "calibration": len(calibration),
            "evaluation": len(evaluation),
        },
        "examples": {
            "calibration": len(calibration_examples),
            "evaluation": len(evaluation_examples),
        },
        "global": {
            "radius_km": global_radius,
            "empirical_coverage": global_coverage,
            "mean_region_area_km2": math.pi * global_radius**2,
        },
        "speed_conditioned": {
            "speed_boundary_km_per_step": speed_boundary,
            "low_speed_radius_km": low_radius,
            "high_speed_radius_km": high_radius,
            "empirical_coverage": adaptive_coverage,
            "mean_region_area_km2": float(np.mean(math.pi * adaptive_radii**2)),
            "area_reduction_vs_global_pct": 100.0
            * (
                1.0
                - float(np.mean(adaptive_radii**2))
                / max(global_radius**2, 1.0e-12)
            ),
        },
        "boundary": (
            "finite-sample empirical coverage on held-out public AIS tracks; "
            "exchangeability can fail under operational distribution shift"
        ),
    }


def run_distribution_shift_stress(
    tracks: list[MaritimeTrack],
    *,
    coverage: float = 0.90,
    horizon: int = 5,
    rolling_window: int = 500,
) -> dict[str, Any]:
    tuning = tracks[: max(20, len(tracks) // 5)]
    calibration = tracks[len(tuning) : len(tuning) + max(30, len(tracks) // 4)]
    evaluation = tracks[len(tuning) + len(calibration) :]
    best: tuple[float, int, float] | None = None
    for window in (2, 3, 5, 8):
        for gain in (0.2, 0.3, 0.4, 0.5, 0.6, 0.7):
            errors = [
                value
                for value, _ in trajectory_examples(
                    tuning,
                    horizon=horizon,
                    window=window,
                    gain=gain,
                )
            ]
            rmse = float(np.sqrt(np.mean(np.square(errors))))
            if best is None or rmse < best[0]:
                best = (rmse, window, gain)
    assert best is not None
    _, window, gain = best
    calibration_errors = [
        value
        for value, _ in trajectory_examples(
            calibration,
            horizon=horizon,
            window=window,
            gain=gain,
        )
    ]
    evaluation_errors = np.asarray(
        [
            value
            for value, _ in trajectory_examples(
                evaluation,
                horizon=horizon,
                window=window,
                gain=gain,
            )
        ],
        dtype=float,
    )
    static_radius = finite_sample_quantile(calibration_errors, coverage)
    stress = []
    for factor in (1.0, 1.25, 1.5, 2.0):
        shifted = evaluation_errors * factor
        static_coverage = float(np.mean(shifted <= static_radius))
        history = list(calibration_errors[-rolling_window:])
        covered = []
        radii = []
        for error in shifted:
            radius = finite_sample_quantile(history, coverage)
            covered.append(error <= radius)
            radii.append(radius)
            history.append(float(error))
            if len(history) > rolling_window:
                history.pop(0)
        warmup = min(rolling_window, len(covered) // 3)
        stress.append(
            {
                "error_scale": factor,
                "static_coverage": static_coverage,
                "rolling_coverage_after_warmup": float(
                    np.mean(covered[warmup:])
                ),
                "rolling_final_radius_km": float(np.median(radii[-rolling_window:])),
                "warmup_examples": warmup,
            }
        )
    return {
        "coverage_target": coverage,
        "rolling_window": rolling_window,
        "static_radius_km": static_radius,
        "stress": stress,
        "boundary": (
            "rolling recalibration uses only previously realized forecast errors; "
            "it cannot guarantee immediate coverage after abrupt shift"
        ),
    }


def benjamini_hochberg(p_values: np.ndarray, false_discovery_rate: float) -> np.ndarray:
    order = np.argsort(p_values)
    ordered = p_values[order]
    thresholds = false_discovery_rate * np.arange(1, len(p_values) + 1) / len(p_values)
    passing = np.flatnonzero(ordered <= thresholds)
    selected = np.zeros(len(p_values), dtype=bool)
    if passing.size:
        cutoff = ordered[passing[-1]]
        selected = p_values <= cutoff
    return selected


def run_conformal_alert_control(
    tracks: list[MaritimeTrack],
    *,
    false_discovery_rate: float = 0.10,
    watch_false_discovery_rate: float = 0.20,
    seed: int = 63063,
    alert_batch_size: int = 10,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    tuning_count = max(35, len(tracks) // 5)
    calibration_count = max(40, len(tracks) // 4)
    tuning = tracks[:tuning_count]
    calibration = tracks[tuning_count : tuning_count + calibration_count]
    evaluation = tracks[tuning_count + calibration_count :]

    def features(track: MaritimeTrack) -> np.ndarray:
        positions = track.positions
        velocity = np.diff(positions, axis=0)
        speed = np.linalg.norm(velocity, axis=1)
        acceleration = np.diff(velocity, axis=0)
        heading = np.unwrap(np.arctan2(velocity[:, 1], velocity[:, 0]))
        turn = np.diff(heading)
        distance = np.linalg.norm(positions, axis=1)
        closing = distance[:-1] - distance[1:]
        score, channel_features, _ = ais_pol_score(track)
        score = score[25:]
        channel_features = channel_features[25:]
        return np.asarray(
            [
                np.max(score),
                np.percentile(score, 95),
                np.mean(score),
                np.std(score),
                np.mean(score > 8),
                np.max(speed),
                np.mean(speed),
                np.std(speed),
                np.max(np.abs(acceleration)),
                np.mean(np.linalg.norm(acceleration, axis=1)),
                np.max(np.abs(turn)),
                np.mean(np.abs(turn)),
                np.max(closing),
                np.mean(closing),
                np.min(distance),
                np.mean(~track.cooperative),
                *np.max(channel_features, axis=0),
                *np.mean(channel_features, axis=0),
            ],
            dtype=float,
        )

    anomaly_types = ("intercept", "route_deviation", "speed_surge", "dark_contact")
    train_x: list[np.ndarray] = []
    train_y: list[bool] = []
    for index, track in enumerate(tuning):
        train_x.append(features(track))
        train_y.append(False)
        for type_index, anomaly_type in enumerate(anomaly_types):
            train_x.append(
                features(
                    inject_track_anomaly(
                        track,
                        anomaly_type,
                        seed * 1000 + index * 10 + type_index,
                    )
                )
            )
            train_y.append(True)
    model = RandomForestClassifier(
        n_estimators=256,
        min_samples_leaf=2,
        max_features=0.8,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(train_x, train_y)
    calibration_scores = model.predict_proba(
        np.vstack([features(track) for track in calibration])
    )[:, 1]

    scored: list[float] = []
    truth: list[bool] = []
    for index, track in enumerate(evaluation):
        scored.append(float(model.predict_proba(features(track)[None, :])[0, 1]))
        truth.append(False)
        anomaly_type = anomaly_types[index % len(anomaly_types)]
        anomalous = inject_track_anomaly(track, anomaly_type, 91_000 + index)
        scored.append(
            float(model.predict_proba(features(anomalous)[None, :])[0, 1])
        )
        truth.append(True)

    scores = np.asarray(scored)
    # Randomized conformal p-values preserve validity while avoiding a
    # resolution floor that otherwise prevents BH discoveries with a modest
    # track-level calibration set.
    greater = np.sum(calibration_scores[:, None] > scores[None, :], axis=0)
    equal = np.sum(calibration_scores[:, None] == scores[None, :], axis=0)
    p_values = (
        greater + rng.random(len(scores)) * (equal + 1.0)
    ) / (len(calibration_scores) + 1.0)
    # SSDS-style alerting is naturally evaluated in bounded scan/update
    # batches, not as one unbounded lifetime hypothesis family.
    truth_array = np.asarray(truth, dtype=bool)
    actual_anomalies = int(np.sum(truth_array))

    def tier(rate: float) -> dict[str, Any]:
        selected = np.zeros(len(p_values), dtype=bool)
        for start in range(0, len(p_values), alert_batch_size):
            stop = min(start + alert_batch_size, len(p_values))
            selected[start:stop] = benjamini_hochberg(
                p_values[start:stop],
                rate,
            )
        discoveries = int(np.sum(selected))
        false_discoveries = int(np.sum(selected & ~truth_array))
        true_discoveries = int(np.sum(selected & truth_array))
        return {
            "target_false_discovery_rate": rate,
            "discoveries": discoveries,
            "true_discoveries": true_discoveries,
            "false_discoveries": false_discoveries,
            "empirical_false_discovery_proportion": (
                false_discoveries / max(discoveries, 1)
            ),
            "recall": true_discoveries / max(actual_anomalies, 1),
        }

    return {
        "alert_batch_size": alert_batch_size,
        "model": "256-tree grouped-track random forest with split-conformal wrapper",
        "tuning_tracks": len(tuning),
        "calibration_tracks": len(calibration),
        "evaluation_nominal_tracks": len(evaluation),
        "evaluation_anomalous_tracks": actual_anomalies,
        "high_confidence": tier(false_discovery_rate),
        "watch": tier(watch_false_discovery_rate),
        "minimum_p_value": float(np.min(p_values)),
        "p_value_method": "randomized split-conformal track-level p-values",
        "boundary": (
            "FDR control assumes calibration nominal tracks represent future "
            "nominal traffic; injected deviations are not hostile ground truth"
        ),
    }


def covariance_intersection(
    estimates: list[np.ndarray],
    covariances: list[np.ndarray],
) -> tuple[np.ndarray, np.ndarray, float]:
    best: tuple[float, np.ndarray, np.ndarray, float] | None = None
    inverse = [np.linalg.inv(value) for value in covariances]
    for weight in np.linspace(0.0, 1.0, 101):
        information = weight * inverse[0] + (1.0 - weight) * inverse[1]
        covariance = np.linalg.inv(information)
        estimate = covariance @ (
            weight * inverse[0] @ estimates[0]
            + (1.0 - weight) * inverse[1] @ estimates[1]
        )
        objective = float(np.linalg.slogdet(covariance)[1])
        if best is None or objective < best[0]:
            best = (objective, estimate, covariance, float(weight))
    assert best is not None
    return best[1], best[2], best[3]


def run_unknown_correlation_fusion(
    *,
    trials: int = 20_000,
    correlation: float = 0.85,
    seed: int = 9061,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    covariance_a = np.diag([1.0, 4.0])
    covariance_b = np.diag([4.0, 1.0])
    cross = correlation * np.diag(
        np.sqrt(np.diag(covariance_a) * np.diag(covariance_b))
    )
    joint = np.block([[covariance_a, cross], [cross, covariance_b]])
    errors = rng.multivariate_normal(np.zeros(4), joint, size=trials)
    truth = rng.normal(0.0, 20.0, size=(trials, 2))
    observations_a = truth + errors[:, :2]
    observations_b = truth + errors[:, 2:]

    independent_covariance = np.linalg.inv(
        np.linalg.inv(covariance_a) + np.linalg.inv(covariance_b)
    )
    independent_estimate = (
        observations_a @ np.linalg.inv(covariance_a).T
        + observations_b @ np.linalg.inv(covariance_b).T
    ) @ independent_covariance.T

    _, ci_covariance, weight = covariance_intersection(
        [observations_a[0], observations_b[0]],
        [covariance_a, covariance_b],
    )
    inverse_a = np.linalg.inv(covariance_a)
    inverse_b = np.linalg.inv(covariance_b)
    ci_estimate = (
        observations_a @ (weight * inverse_a).T
        + observations_b @ ((1.0 - weight) * inverse_b).T
    ) @ ci_covariance.T

    def consistency(estimates: np.ndarray, covariance: np.ndarray) -> dict[str, float]:
        residual = estimates - truth
        inverse_covariance = np.linalg.inv(covariance)
        nees = np.einsum("ni,ij,nj->n", residual, inverse_covariance, residual)
        return {
            "rmse": float(np.sqrt(np.mean(np.sum(residual**2, axis=1)))),
            "mean_nees": float(np.mean(nees)),
            "nominal_95pct_ellipse_coverage": float(np.mean(nees <= 5.991)),
        }

    return {
        "trials": trials,
        "unknown_error_correlation": correlation,
        "naive_independence": consistency(
            independent_estimate,
            independent_covariance,
        ),
        "covariance_intersection": {
            **consistency(ci_estimate, ci_covariance),
            "selected_weight": weight,
        },
        "boundary": (
            "synthetic correlated-Gaussian study; representative sensor "
            "cross-correlation must be measured with synchronized hardware"
        ),
    }


def run_anytime_valid_access_monitor(
    *,
    sequences: int = 4_000,
    samples: int = 500,
    attack_onset: int = 250,
    nominal_rate: float = 0.02,
    attack_rate: float = 0.15,
    alpha: float = 0.01,
    seed: int = 59059,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    threshold = 1.0 / alpha

    def evaluate(attacked: bool) -> tuple[int, list[int]]:
        alerts = 0
        delays: list[int] = []
        for _ in range(sequences):
            probabilities = np.full(samples, nominal_rate)
            if attacked:
                probabilities[attack_onset:] = attack_rate
            observations = rng.random(samples) < probabilities
            log_evidence = 0.0
            alarm = None
            for index, event in enumerate(observations):
                log_evidence += (
                    math.log(attack_rate / nominal_rate)
                    if event
                    else math.log((1.0 - attack_rate) / (1.0 - nominal_rate))
                )
                if log_evidence >= math.log(threshold):
                    alarm = index
                    break
            if alarm is not None:
                alerts += 1
                if attacked and alarm >= attack_onset:
                    delays.append(alarm - attack_onset)
        return alerts, delays

    nominal_alerts, _ = evaluate(False)
    attacked_alerts, delays = evaluate(True)
    return {
        "nominal_event_rate": nominal_rate,
        "attack_event_rate": attack_rate,
        "anytime_false_alarm_target": alpha,
        "nominal_sequences": sequences,
        "nominal_false_alarm_rate": nominal_alerts / sequences,
        "attacked_sequences": sequences,
        "attack_detection_rate": attacked_alerts / sequences,
        "median_detection_delay_samples": float(np.median(delays)),
        "p95_detection_delay_samples": float(np.quantile(delays, 0.95)),
        "boundary": (
            "the anytime guarantee is valid under the specified nominal event "
            "model; misspecification requires conservative calibration"
        ),
    }


def run_crypto_agility_graph(*, assets: int = 200, seed: int = 17017) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    nodes: list[CryptoAssetNode] = []
    for index in range(assets):
        possible = list(range(index))
        dependency_count = min(len(possible), int(rng.integers(0, 4)))
        dependencies = (
            set(
                f"asset-{value}"
                for value in rng.choice(
                    possible,
                    size=dependency_count,
                    replace=False,
                )
            )
            if dependency_count
            else set()
        )
        nodes.append(
            CryptoAssetNode(
                asset_id=f"asset-{index}",
                algorithm=("rsa2048", "ecdsa-p256", "ed25519")[index % 3],
                risk=float(rng.uniform(20, 100)),
                dependencies=dependencies,
                migration_target=("ml-kem-768" if index % 2 else "ml-dsa-65"),
                effort=float(rng.uniform(0.5, 4.0)),
            )
        )
    graph = {node.asset_id: node for node in nodes}
    unsafe_order = [
        node.asset_id for node in sorted(nodes, key=lambda item: item.risk, reverse=True)
    ]
    migrated: set[str] = set()
    unsafe_violations = 0
    for asset_id in unsafe_order:
        if not graph[asset_id].dependencies.issubset(migrated):
            unsafe_violations += 1
        migrated.add(asset_id)

    safe = MigrationWavePlanner(nodes).plan(lanes=8)
    migrated.clear()
    safe_violations = 0
    maximum_wave_effort = 0.0
    for wave in safe["waves"]:
        for asset_id in wave:
            if not graph[asset_id].dependencies.issubset(migrated):
                safe_violations += 1
        maximum_wave_effort = max(
            maximum_wave_effort,
            sum(graph[asset_id].effort for asset_id in wave),
        )
        migrated.update(wave)
    return {
        "assets": assets,
        "dependency_edges": sum(len(node.dependencies) for node in nodes),
        "unsafe_risk_order_dependency_violations": unsafe_violations,
        "dependency_safe_violations": safe_violations,
        "migration_waves": len(safe["waves"]),
        "estimated_parallel_effort_reduction_pct": safe["estimated_reduction_pct"],
        "maximum_wave_total_effort": maximum_wave_effort,
        "unresolved": safe["unresolved_cycle_or_missing_dependency"],
        "boundary": (
            "synthetic acyclic enterprise graph; authoritative AFDW dependencies "
            "and rollback procedures remain required"
        ),
    }


@dataclass(frozen=True)
class SensorCandidate:
    track: int
    sensor: int
    priority: float
    prior_variance: float
    nominal_variance: float
    degraded_variance: float
    cost: float


def select_sensor_tasks(
    candidates: list[SensorCandidate],
    *,
    budget: float,
    robust: bool,
) -> list[int]:
    selected: list[int] = []
    spent = 0.0
    if robust:
        def portfolio_utility(indices: list[int], failed_sensor: int) -> float:
            precision: dict[int, float] = {}
            prior: dict[int, float] = {}
            priority: dict[int, float] = {}
            for index in indices:
                candidate = candidates[index]
                variance = (
                    candidate.degraded_variance
                    if candidate.sensor == failed_sensor
                    else candidate.nominal_variance
                )
                prior[candidate.track] = candidate.prior_variance
                priority[candidate.track] = candidate.priority
                precision[candidate.track] = precision.get(
                    candidate.track,
                    1.0 / candidate.prior_variance,
                ) + 1.0 / variance
            return sum(
                priority[track]
                * math.log(prior[track] / (1.0 / track_precision))
                for track, track_precision in precision.items()
            )

        remaining = set(range(len(candidates)))
        current_worst = 0.0
        while remaining:
            best: tuple[float, float, int] | None = None
            for index in remaining:
                candidate = candidates[index]
                if spent + candidate.cost > budget:
                    continue
                proposed = selected + [index]
                worst = min(
                    portfolio_utility(proposed, failed)
                    for failed in (-1, 0, 1, 2, 3)
                )
                score = (worst - current_worst) / candidate.cost
                if best is None or score > best[0]:
                    best = (score, worst, index)
            if best is None or best[0] <= 0:
                break
            index = best[2]
            selected.append(index)
            spent += candidates[index].cost
            current_worst = best[1]
            remaining.remove(index)
        return selected

    precision_by_track: dict[int, float] = {}
    remaining = set(range(len(candidates)))
    while remaining:
        best: tuple[float, int] | None = None
        for index in remaining:
            candidate = candidates[index]
            if spent + candidate.cost > budget:
                continue
            current_precision = precision_by_track.get(
                candidate.track,
                1.0 / candidate.prior_variance,
            )
            variance = candidate.nominal_variance
            current_variance = 1.0 / current_precision
            posterior_variance = 1.0 / (current_precision + 1.0 / variance)
            marginal = candidate.priority * math.log(
                current_variance / posterior_variance
            )
            score = marginal / candidate.cost
            if best is None or score > best[0]:
                best = (score, index)
        if best is None:
            break
        index = best[1]
        candidate = candidates[index]
        variance = candidate.nominal_variance
        precision_by_track[candidate.track] = precision_by_track.get(
            candidate.track,
            1.0 / candidate.prior_variance,
        ) + 1.0 / variance
        spent += candidate.cost
        selected.append(index)
        remaining.remove(index)
    return selected


def run_robust_sensor_scheduling(
    *,
    scenarios: int = 2_000,
    seed: int = 65065,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    candidates: list[SensorCandidate] = []
    for track in range(30):
        priority = float(rng.uniform(0.2, 1.0))
        prior = float(rng.uniform(2.0, 12.0))
        for sensor in range(4):
            nominal = (0.18, 0.35, 0.65, 1.0)[sensor] * float(
                rng.uniform(0.8, 1.2)
            )
            degradation = (18.0, 5.0, 2.0, 1.35)[sensor]
            candidates.append(
                SensorCandidate(
                    track=track,
                    sensor=sensor,
                    priority=priority,
                    prior_variance=prior,
                    nominal_variance=nominal,
                    degraded_variance=nominal * degradation,
                    cost=(1.8, 1.25, 0.85, 0.65)[sensor],
                )
            )
    budget = 30.0
    nominal_selection = select_sensor_tasks(candidates, budget=budget, robust=False)
    robust_selection = select_sensor_tasks(candidates, budget=budget, robust=True)

    def utility_for_degradation(
        selection: list[int],
        degraded_by_sensor: dict[int, bool],
    ) -> float:
        precision: dict[int, float] = {}
        prior: dict[int, float] = {}
        priority: dict[int, float] = {}
        for index in selection:
            candidate = candidates[index]
            variance = (
                candidate.degraded_variance
                if degraded_by_sensor[candidate.sensor]
                else candidate.nominal_variance
            )
            prior[candidate.track] = candidate.prior_variance
            priority[candidate.track] = candidate.priority
            precision[candidate.track] = precision.get(
                candidate.track,
                1.0 / candidate.prior_variance,
            ) + 1.0 / variance
        return sum(
            priority[track] * math.log(prior[track] / (1.0 / track_precision))
            for track, track_precision in precision.items()
        )

    def realized_utility(selection: list[int]) -> np.ndarray:
        values = []
        for _ in range(scenarios):
            # Sensor degradation is correlated across all tasks from the same
            # aperture/processing chain, which is the operationally important
            # tail-risk case that nominal scheduling tends to ignore.
            degraded_by_sensor = {
                0: rng.random() < 0.30,
                1: rng.random() < 0.15,
                2: rng.random() < 0.08,
                3: rng.random() < 0.04,
            }
            values.append(utility_for_degradation(selection, degraded_by_sensor))
        return np.asarray(values)

    nominal_values = realized_utility(nominal_selection)
    robust_values = realized_utility(robust_selection)
    nominal_outages = [
        utility_for_degradation(
            nominal_selection,
            {sensor: sensor == failed for sensor in range(4)},
        )
        for failed in range(4)
    ]
    robust_outages = [
        utility_for_degradation(
            robust_selection,
            {sensor: sensor == failed for sensor in range(4)},
        )
        for failed in range(4)
    ]
    return {
        "candidates": len(candidates),
        "budget": budget,
        "nominal_selected": len(nominal_selection),
        "robust_selected": len(robust_selection),
        "nominal": {
            "mean_utility": float(np.mean(nominal_values)),
            "p05_utility": float(np.quantile(nominal_values, 0.05)),
        },
        "robust": {
            "mean_utility": float(np.mean(robust_values)),
            "p05_utility": float(np.quantile(robust_values, 0.05)),
        },
        "robust_p05_improvement_pct": 100.0
        * (
            np.quantile(robust_values, 0.05)
            / max(np.quantile(nominal_values, 0.05), 1.0e-12)
            - 1.0
        ),
        "single_sensor_degradation": {
            "nominal_minimum_utility": min(nominal_outages),
            "robust_minimum_utility": min(robust_outages),
            "minimum_utility_improvement_pct": 100.0
            * (
                min(robust_outages) / max(min(nominal_outages), 1.0e-12)
                - 1.0
            ),
        },
        "boundary": (
            "synthetic degradation distributions; sponsor radar and ES sensor "
            "failure statistics are required for operational calibration"
        ),
    }


def validate(results: dict[str, Any]) -> None:
    checks = {
        "conformal global coverage": (
            results["conformal_trajectory"]["global"]["empirical_coverage"]
            >= results["conformal_trajectory"]["coverage_target"] - 0.03
        ),
        "conformal adaptive coverage": (
            results["conformal_trajectory"]["speed_conditioned"][
                "empirical_coverage"
            ]
            >= results["conformal_trajectory"]["coverage_target"] - 0.03
        ),
        "FDR alert control": (
            results["conformal_alert_control"]["high_confidence"][
                "empirical_false_discovery_proportion"
            ]
            <= 0.10
        ),
        "FDR watch recall": (
            results["conformal_alert_control"]["watch"]["recall"] >= 0.60
        ),
        "shift adaptation": (
            results["distribution_shift_stress"]["stress"][2][
                "rolling_coverage_after_warmup"
            ]
            >= 0.87
            and results["distribution_shift_stress"]["stress"][2][
                "rolling_coverage_after_warmup"
            ]
            > results["distribution_shift_stress"]["stress"][2][
                "static_coverage"
            ]
        ),
        "CI consistency": (
            results["unknown_correlation_fusion"]["covariance_intersection"][
                "nominal_95pct_ellipse_coverage"
            ]
            >= 0.93
        ),
        "CI improves consistency": (
            results["unknown_correlation_fusion"]["covariance_intersection"][
                "nominal_95pct_ellipse_coverage"
            ]
            > results["unknown_correlation_fusion"]["naive_independence"][
                "nominal_95pct_ellipse_coverage"
            ]
        ),
        "anytime false alarm": (
            results["anytime_access_monitor"]["nominal_false_alarm_rate"] <= 0.015
        ),
        "anytime detection": (
            results["anytime_access_monitor"]["attack_detection_rate"] >= 0.90
        ),
        "safe crypto migration": (
            results["crypto_agility"]["dependency_safe_violations"] == 0
            and not results["crypto_agility"]["unresolved"]
        ),
        "robust scheduling": (
            results["robust_sensor_scheduling"]["robust_p05_improvement_pct"] > 0
        ),
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise AssertionError("theory campaign validation failed: " + ", ".join(failed))


def render(campaign: dict[str, Any]) -> str:
    r = campaign["results"]
    return f"""# Theory-Driven Assurance Campaign

Generated: {campaign["metadata"]["generated_at"]}

These are locally reproducible research results, not operational guarantees.

| Contribution | Measured result | Topic leverage |
| --- | --- | --- |
| Conformal trajectory regions | global coverage {r["conformal_trajectory"]["global"]["empirical_coverage"]:.3f}; speed-conditioned coverage {r["conformal_trajectory"]["speed_conditioned"]["empirical_coverage"]:.3f} | NV061, NV063 |
| FDR-controlled PoL alerts | high-confidence recall/FDP {r["conformal_alert_control"]["high_confidence"]["recall"]:.3f}/{r["conformal_alert_control"]["high_confidence"]["empirical_false_discovery_proportion"]:.3f}; watch recall/FDP {r["conformal_alert_control"]["watch"]["recall"]:.3f}/{r["conformal_alert_control"]["watch"]["empirical_false_discovery_proportion"]:.3f} | NV063 |
| Distribution-shift adaptation | at 1.5x error scale, static coverage {r["distribution_shift_stress"]["stress"][2]["static_coverage"]:.3f}; rolling coverage after warmup {r["distribution_shift_stress"]["stress"][2]["rolling_coverage_after_warmup"]:.3f} | NV061, NV063 |
| Unknown-correlation fusion | naive 95% coverage {r["unknown_correlation_fusion"]["naive_independence"]["nominal_95pct_ellipse_coverage"]:.3f}; covariance-intersection coverage {r["unknown_correlation_fusion"]["covariance_intersection"]["nominal_95pct_ellipse_coverage"]:.3f} | NV061, NV065, NP002 |
| Anytime-valid access evidence | false-alarm rate {r["anytime_access_monitor"]["nominal_false_alarm_rate"]:.4f}; attack detection {r["anytime_access_monitor"]["attack_detection_rate"]:.3f} | NV059, QSPARX |
| Dependency-safe crypto agility | unsafe ordering violations {r["crypto_agility"]["unsafe_risk_order_dependency_violations"]}; safe violations {r["crypto_agility"]["dependency_safe_violations"]} | QSPARX, NV062 |
| Robust sensor scheduling | fifth-percentile utility improvement {r["robust_sensor_scheduling"]["robust_p05_improvement_pct"]:.1f}% | NV065, NP002 |

## Interpretation

- Conformal methods add empirically calibrated uncertainty and alert-budget
  semantics without replacing the existing predictor or PoL detector.
- Covariance intersection prevents unjustified confidence when sensor
  cross-correlation is unknown.
- The access e-process supports continuous monitoring with an anytime-valid
  false-alarm interpretation under a calibrated nominal model.
- Dependency-safe scheduling turns crypto inventory into executable migration
  order while preserving interoperability.
- Robust scheduling trades a small amount of nominal optimism for stronger
  degraded-sensor performance.

Every result retains an explicit boundary in the JSON artifact.
"""


def run() -> dict[str, Any]:
    tracks = load_real_ais_tracks(AIS_PATH, maximum_tracks=220)
    results = {
        "conformal_trajectory": run_conformal_trajectory(tracks),
        "conformal_alert_control": run_conformal_alert_control(tracks),
        "distribution_shift_stress": run_distribution_shift_stress(tracks),
        "unknown_correlation_fusion": run_unknown_correlation_fusion(),
        "anytime_access_monitor": run_anytime_valid_access_monitor(),
        "crypto_agility": run_crypto_agility_graph(),
        "robust_sensor_scheduling": run_robust_sensor_scheduling(),
    }
    validate(results)
    campaign = {
        "metadata": runtime_metadata(),
        "results": results,
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    write_json(OUTPUT / "theory_campaign_results.json", campaign)
    (OUTPUT / "THEORY_CAMPAIGN_REPORT.md").write_text(render(campaign))
    return campaign


def main() -> None:
    print(render(run()))


if __name__ == "__main__":
    main()
