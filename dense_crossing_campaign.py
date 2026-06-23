#!/usr/bin/env python3
"""Compare bounded greedy and sparse component-optimal track association.

The campaign uses synthetic truth because public AIS/ADS-B data does not
provide authoritative identity through deliberately constructed dense
crossings. It measures accuracy, identity switching, latency, and candidate
graph size under controlled ambiguity.
"""

from __future__ import annotations

import argparse
import json
import math
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import numpy as np
from scipy.optimize import linear_sum_assignment


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "results" / "dense_crossing"


@dataclass
class TrackerState:
    position: np.ndarray
    velocity: np.ndarray
    signature: np.ndarray
    prior_truth: list[int | None]


def assignment_cost(
    tracks: TrackerState,
    detections: np.ndarray,
    detection_velocities: np.ndarray,
    position_gate: float,
    velocity_weight: float,
    track_signatures: np.ndarray | None = None,
    detection_signatures: np.ndarray | None = None,
    signature_weight: float = 0.0,
) -> tuple[np.ndarray, np.ndarray]:
    position_delta = tracks.position[:, None, :] - detections[None, :, :]
    velocity_delta = tracks.velocity[:, None, :] - detection_velocities[None, :, :]
    position_squared = np.sum(position_delta * position_delta, axis=2)
    cost = position_squared + velocity_weight * np.sum(
        velocity_delta * velocity_delta,
        axis=2,
    )
    if (
        signature_weight > 0.0
        and track_signatures is not None
        and detection_signatures is not None
    ):
        signature_delta = (
            track_signatures[:, None, :] - detection_signatures[None, :, :]
        )
        cost += signature_weight * np.sum(signature_delta * signature_delta, axis=2)
    return cost, position_squared <= position_gate * position_gate


def greedy_assignment(cost: np.ndarray, valid: np.ndarray) -> list[tuple[int, int]]:
    rows, columns = np.nonzero(valid)
    edges = sorted(
        zip(cost[rows, columns], rows, columns),
        key=lambda item: (float(item[0]), int(item[1]), int(item[2])),
    )
    used_rows: set[int] = set()
    used_columns: set[int] = set()
    selected: list[tuple[int, int]] = []
    for _, row, column in edges:
        row = int(row)
        column = int(column)
        if row in used_rows or column in used_columns:
            continue
        used_rows.add(row)
        used_columns.add(column)
        selected.append((row, column))
    return sorted(selected)


def _optimal_component(
    track_indices: list[int],
    detection_indices: list[int],
    cost: np.ndarray,
    valid: np.ndarray,
) -> list[tuple[int, int]]:
    track_count = len(track_indices)
    detection_count = len(detection_indices)
    size = track_count + detection_count
    finite = cost[valid]
    unmatched_cost = max(float(np.max(finite)) + 1.0 if finite.size else 1.0, 1.0)
    prohibited = unmatched_cost * (size + 2)
    matrix = np.full((size, size), prohibited)
    for local_track, track in enumerate(track_indices):
        for local_detection, detection in enumerate(detection_indices):
            if valid[track, detection]:
                matrix[local_track, local_detection] = cost[track, detection]
        matrix[local_track, detection_count + local_track] = unmatched_cost
    for local_detection in range(detection_count):
        matrix[track_count + local_detection, local_detection] = unmatched_cost
    matrix[track_count:, detection_count:] = 0.0
    rows, columns = linear_sum_assignment(matrix)
    selected = []
    for row, column in zip(rows, columns):
        if row >= track_count or column >= detection_count:
            continue
        track = track_indices[int(row)]
        detection = detection_indices[int(column)]
        if valid[track, detection]:
            selected.append((track, detection))
    return selected


def component_optimal_assignment(
    cost: np.ndarray,
    valid: np.ndarray,
    maximum_component: int = 96,
) -> tuple[list[tuple[int, int]], dict[str, int]]:
    track_neighbors = [set(np.flatnonzero(valid[row])) for row in range(len(valid))]
    detection_neighbors = [
        set(np.flatnonzero(valid[:, column])) for column in range(valid.shape[1])
    ]
    visited_tracks: set[int] = set()
    visited_detections: set[int] = set()
    selected: list[tuple[int, int]] = []
    largest_component = 0
    escalated_components = 0
    capped_components = 0

    for start in range(len(track_neighbors)):
        if start in visited_tracks or not track_neighbors[start]:
            continue
        tracks: set[int] = set()
        detections: set[int] = set()
        queue: deque[tuple[str, int]] = deque([("track", start)])
        while queue:
            kind, index = queue.popleft()
            if kind == "track":
                if index in visited_tracks:
                    continue
                visited_tracks.add(index)
                tracks.add(index)
                queue.extend(("detection", value) for value in track_neighbors[index])
            else:
                if index in visited_detections:
                    continue
                visited_detections.add(index)
                detections.add(index)
                queue.extend(("track", value) for value in detection_neighbors[index])
        track_list = sorted(tracks)
        detection_list = sorted(detections)
        component_size = max(len(track_list), len(detection_list))
        largest_component = max(largest_component, component_size)
        edge_count = int(
            np.sum(valid[np.ix_(track_list, detection_list)])
        )
        ambiguous = edge_count > min(len(track_list), len(detection_list))
        if not ambiguous:
            local = greedy_assignment(
                cost[np.ix_(track_list, detection_list)],
                valid[np.ix_(track_list, detection_list)],
            )
            selected.extend(
                (track_list[row], detection_list[column])
                for row, column in local
            )
        elif component_size <= maximum_component:
            escalated_components += 1
            selected.extend(
                _optimal_component(track_list, detection_list, cost, valid)
            )
        else:
            capped_components += 1
            local = greedy_assignment(
                cost[np.ix_(track_list, detection_list)],
                valid[np.ix_(track_list, detection_list)],
            )
            selected.extend(
                (track_list[row], detection_list[column])
                for row, column in local
            )
    return sorted(selected), {
        "largest_component": largest_component,
        "escalated_components": escalated_components,
        "capped_components": capped_components,
    }


def dense_hungarian_assignment(
    cost: np.ndarray,
    valid: np.ndarray,
) -> list[tuple[int, int]]:
    tracks = list(range(cost.shape[0]))
    detections = list(range(cost.shape[1]))
    return _optimal_component(tracks, detections, cost, valid)


def crossing_truth(
    object_count: int,
    frames: int,
    rng: np.random.Generator,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    groups = math.ceil(object_count / 8)
    positions = np.zeros((frames, object_count, 2))
    velocities = np.zeros((object_count, 2))
    signatures = rng.normal(size=(object_count, 6))
    signatures /= np.maximum(
        np.linalg.norm(signatures, axis=1, keepdims=True),
        1.0e-9,
    )
    crossing_frame = frames // 2
    for index in range(object_count):
        group = index // 8
        member = index % 8
        angle = 2.0 * math.pi * member / 8.0 + rng.normal(0.0, 0.025)
        speed = rng.uniform(0.78, 1.18)
        velocity = np.array([math.cos(angle), math.sin(angle)]) * speed
        center = np.array(
            [(group % 4) * 34.0, (group // 4) * 34.0],
            dtype=float,
        )
        start = center - crossing_frame * velocity
        velocities[index] = velocity
        for frame in range(frames):
            positions[frame, index] = start + frame * velocity
    return positions, velocities, signatures


def initialize_state(
    truth_positions: np.ndarray,
    truth_velocities: np.ndarray,
    truth_signatures: np.ndarray,
    rng: np.random.Generator,
    noise: float,
) -> TrackerState:
    return TrackerState(
        position=truth_positions + rng.normal(0.0, noise * 0.25, truth_positions.shape),
        velocity=truth_velocities + rng.normal(0.0, noise * 0.08, truth_velocities.shape),
        signature=truth_signatures.copy(),
        prior_truth=[None] * len(truth_positions),
    )


def run_method(
    method: str,
    truth: np.ndarray,
    truth_velocities: np.ndarray,
    truth_signatures: np.ndarray,
    seed: int,
    noise: float,
    detection_probability: float,
    clutter_rate: float,
    position_gate: float,
    velocity_weight: float,
    maximum_component: int,
) -> dict[str, float | int]:
    rng = np.random.default_rng(seed)
    state = initialize_state(
        truth[0],
        truth_velocities,
        truth_signatures,
        rng,
        noise,
    )
    assignments = 0
    correct = 0
    switches = 0
    missed_truth = 0
    candidate_edges = 0
    dense_cells = 0
    runtimes_ns: list[int] = []
    largest_component = 0
    escalated_components = 0
    capped_components = 0

    methods: dict[
        str,
        Callable[[np.ndarray, np.ndarray], list[tuple[int, int]]],
    ] = {
        "greedy": greedy_assignment,
        "hungarian": dense_hungarian_assignment,
    }

    for frame in range(1, len(truth)):
        state.position = state.position + state.velocity
        present = rng.random(len(truth_velocities)) <= detection_probability
        truth_ids = list(np.flatnonzero(present))
        detections = truth[frame, present] + rng.normal(
            0.0, noise, (len(truth_ids), 2)
        )
        detection_velocities = truth_velocities[present] + rng.normal(
            0.0, noise * 0.32, (len(truth_ids), 2)
        )
        detection_signatures = truth_signatures[present] + rng.normal(
            0.0,
            0.13,
            (len(truth_ids), truth_signatures.shape[1]),
        )
        for _ in range(rng.poisson(clutter_rate)):
            detections = np.vstack((detections, rng.uniform(-20.0, 120.0, 2)))
            detection_velocities = np.vstack(
                (detection_velocities, rng.normal(0.0, 1.5, 2))
            )
            clutter_signature = rng.normal(size=(1, truth_signatures.shape[1]))
            clutter_signature /= max(
                float(np.linalg.norm(clutter_signature)),
                1.0e-9,
            )
            detection_signatures = np.vstack(
                (detection_signatures, clutter_signature)
            )
            truth_ids.append(-1)
        order = rng.permutation(len(detections))
        detections = detections[order]
        detection_velocities = detection_velocities[order]
        detection_signatures = detection_signatures[order]
        truth_ids = [truth_ids[index] for index in order]
        custody_aware = method == "custody_component"
        cost, valid = assignment_cost(
            state,
            detections,
            detection_velocities,
            position_gate,
            velocity_weight,
            state.signature,
            detection_signatures,
            signature_weight=7.0 if custody_aware else 0.0,
        )
        candidate_edges += int(np.sum(valid))
        dense_cells += int(cost.size)
        started = time.perf_counter_ns()
        if method in {"component", "custody_component"}:
            selected, metadata = component_optimal_assignment(
                cost,
                valid,
                maximum_component=maximum_component,
            )
            largest_component = max(
                largest_component,
                metadata["largest_component"],
            )
            escalated_components += metadata["escalated_components"]
            capped_components += metadata["capped_components"]
        else:
            selected = methods[method](cost, valid)
        runtimes_ns.append(time.perf_counter_ns() - started)

        assigned_tracks: set[int] = set()
        observed_truth: set[int] = set()
        for track, detection in selected:
            assigned_tracks.add(track)
            truth_id = truth_ids[detection]
            if truth_id >= 0:
                assignments += 1
                correct += int(track == truth_id)
                observed_truth.add(truth_id)
                previous = state.prior_truth[track]
                switches += int(previous is not None and previous != truth_id)
                state.prior_truth[track] = truth_id
            innovation_velocity = detections[detection] - state.position[track]
            state.position[track] = detections[detection]
            state.velocity[track] = (
                0.55 * state.velocity[track]
                + 0.25 * detection_velocities[detection]
                + 0.20 * innovation_velocity
            )
            state.signature[track] = (
                0.92 * state.signature[track]
                + 0.08 * detection_signatures[detection]
            )
        missed_truth += int(np.sum(present)) - len(observed_truth)
        for track in set(range(len(state.position))) - assigned_tracks:
            state.velocity[track] *= 0.995

    ordered_runtime = sorted(runtimes_ns)
    return {
        "assignment_accuracy": correct / max(assignments, 1),
        "identity_switches": switches,
        "truth_misses": missed_truth,
        "assignments": assignments,
        "candidate_edges": candidate_edges,
        "dense_cost_cells": dense_cells,
        "candidate_fraction": candidate_edges / max(dense_cells, 1),
        "latency_median_us": float(np.median(runtimes_ns)) / 1_000.0,
        "latency_p95_us": float(
            ordered_runtime[max(0, math.ceil(0.95 * len(ordered_runtime)) - 1)]
        )
        / 1_000.0,
        "largest_component": largest_component,
        "escalated_components": escalated_components,
        "capped_components": capped_components,
    }


def run_campaign(
    seeds: int = 12,
    frames: int = 28,
) -> dict[str, object]:
    configurations = [
        {"objects": 16, "noise": 0.55, "dropout": 0.03, "clutter": 1.0},
        {"objects": 64, "noise": 0.70, "dropout": 0.06, "clutter": 3.0},
        {"objects": 256, "noise": 0.85, "dropout": 0.09, "clutter": 8.0},
    ]
    methods = ("greedy", "component", "custody_component", "hungarian")
    raw: list[dict[str, object]] = []
    for configuration in configurations:
        for seed in range(seeds):
            truth_rng = np.random.default_rng(81000 + seed)
            truth, velocities, signatures = crossing_truth(
                configuration["objects"],
                frames,
                truth_rng,
            )
            for method in methods:
                metrics = run_method(
                    method,
                    truth,
                    velocities,
                    signatures,
                    seed=91000 + seed,
                    noise=configuration["noise"],
                    detection_probability=1.0 - configuration["dropout"],
                    clutter_rate=configuration["clutter"],
                    position_gate=3.4,
                    velocity_weight=1.8,
                    maximum_component=96,
                )
                raw.append(
                    {
                        "configuration": configuration,
                        "seed": seed,
                        "method": method,
                        "metrics": metrics,
                    }
                )

    summary: dict[str, object] = {}
    for configuration in configurations:
        key = str(configuration["objects"])
        summary[key] = {}
        for method in methods:
            selected = [
                item["metrics"]
                for item in raw
                if item["configuration"]["objects"] == configuration["objects"]
                and item["method"] == method
            ]
            summary[key][method] = {
                metric: {
                    "mean": float(np.mean([item[metric] for item in selected])),
                    "minimum": float(np.min([item[metric] for item in selected])),
                    "maximum": float(np.max([item[metric] for item in selected])),
                }
                for metric in (
                    "assignment_accuracy",
                    "identity_switches",
                    "truth_misses",
                    "candidate_fraction",
                    "latency_median_us",
                    "latency_p95_us",
                    "largest_component",
                    "capped_components",
                )
            }
    result = {
        "methodology": {
            "seeds": seeds,
            "frames": frames,
            "configuration_count": len(configurations),
            "truth_boundary": (
                "synthetic controlled dense crossings; not operational field truth"
            ),
            "greedy": "globally sorted valid edges, matching the native kernel policy",
            "component": (
                "spatially gated connected components; Hungarian optimization "
                "only within ambiguous components, capped at 96"
            ),
            "custody_component": (
                "component-optimal association plus noisy stable source/type "
                "signature evidence; no truth identity is provided"
            ),
            "hungarian": "dense globally optimal assignment baseline",
        },
        "summary": summary,
        "raw": raw,
    }
    hardest = summary["256"]["custody_component"]
    result["sanity_gates"] = {
        "hardest_case_accuracy": {
            "passed": hardest["assignment_accuracy"]["mean"] >= 0.80,
            "value": hardest["assignment_accuracy"]["mean"],
            "threshold": 0.80,
        },
        "hardest_case_p95_latency": {
            "passed": hardest["latency_p95_us"]["mean"] < 10_000.0,
            "value_us": hardest["latency_p95_us"]["mean"],
            "threshold_us": 10_000.0,
        },
        "component_cap": {
            "passed": hardest["capped_components"]["maximum"] == 0.0,
            "maximum_capped_components": hardest["capped_components"]["maximum"],
        },
    }
    return result


def write_report(result: dict[str, object]) -> None:
    lines = [
        "# Dense Crossing Association Campaign",
        "",
        "Controlled synthetic truth compares the bounded greedy policy, a new",
        "sparse component-optimal policy, and a dense Hungarian baseline.",
        "",
        "| Objects | Method | Mean accuracy | Mean switches | Mean p95 latency | Candidate fraction |",
        "| ---: | --- | ---: | ---: | ---: | ---: |",
    ]
    for objects, methods in result["summary"].items():
        for method, metrics in methods.items():
            lines.append(
                f"| {objects} | {method} | "
                f"{metrics['assignment_accuracy']['mean']:.4f} | "
                f"{metrics['identity_switches']['mean']:.1f} | "
                f"{metrics['latency_p95_us']['mean']:.1f} us | "
                f"{metrics['candidate_fraction']['mean']:.4f} |"
            )
    hardest = result["summary"]["256"]
    greedy = hardest["greedy"]
    custody = hardest["custody_component"]
    accuracy_gain = 100.0 * (
        custody["assignment_accuracy"]["mean"]
        / greedy["assignment_accuracy"]["mean"]
        - 1.0
    )
    switch_reduction = 100.0 * (
        1.0
        - custody["identity_switches"]["mean"]
        / greedy["identity_switches"]["mean"]
    )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The custody-aware method uses a noisy six-dimensional stable",
            "signature as a surrogate for available source, type, RF, acoustic,",
            "or appearance evidence. It is initialized before the crossing and",
            "updated from assigned detections. Truth identity is used only for",
            "scoring after assignment, never in the assignment cost.",
            "",
            f"In the 256-object case it improved mean assignment accuracy by",
            f"`{accuracy_gain:.1f}%` relative to greedy and reduced identity",
            f"switches by `{switch_reduction:.1f}%`. Its mean p95 Python",
            f"latency was `{custody['latency_p95_us']['mean'] / 1000.0:.2f} ms`.",
            "",
            "This campaign tests association quality under deliberately ambiguous",
            "crossings. It does not establish performance on Navy sensor data.",
            "The component-optimal method keeps the sparse gate and escalates only",
            "ambiguous connected components. Components above the declared cap",
            "fall back to bounded greedy assignment and are counted explicitly.",
            "",
        ]
    )
    (OUTPUT / "DENSE_CROSSING_REPORT.md").write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=12)
    parser.add_argument("--frames", type=int, default=28)
    arguments = parser.parse_args()
    result = run_campaign(seeds=arguments.seeds, frames=arguments.frames)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "dense_crossing_results.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    write_report(result)
    print(f"wrote {(OUTPUT / 'dense_crossing_results.json').relative_to(ROOT)}")
    print(f"wrote {(OUTPUT / 'DENSE_CROSSING_REPORT.md').relative_to(ROOT)}")
    if not all(gate["passed"] for gate in result["sanity_gates"].values()):
        raise SystemExit("one or more dense-crossing sanity gates failed")


if __name__ == "__main__":
    main()
