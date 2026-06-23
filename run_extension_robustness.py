#!/usr/bin/env python3
"""Repeat the new extension experiments across seeds and report lower bounds."""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any, Callable

from trl4_common import write_json
from trl4_extensions import (
    evaluate_mixed_domain_custody,
    run_cuas_scale_and_fusion_stress,
    run_opcua_enforcement_proxy,
    run_secure_provider_workflow_extension,
    run_sensor_constraint_stress,
)
from trl4_tracks import load_real_ais_tracks


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "results" / "trl4_extensions"
AIS_PATH = ROOT / "data" / "processed" / "noaa_ais_puget_sound_2020_02_15.csv"
OPENSKY_PATH = ROOT / "data" / "external" / "opensky" / "puget_sound_states.json"


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "minimum": min(values),
        "mean": statistics.fmean(values),
        "maximum": max(values),
    }


def repeat(
    seeds: list[int],
    runner: Callable[[int], dict[str, Any]],
    metrics: dict[str, Callable[[dict[str, Any]], float]],
) -> dict[str, Any]:
    runs = [runner(seed) for seed in seeds]
    return {
        "seeds": seeds,
        "metrics": {
            name: summarize([float(extractor(run)) for run in runs])
            for name, extractor in metrics.items()
        },
    }


def render(result: dict[str, Any]) -> str:
    return f"""# Extension Robustness

All numbers below are repeated over five seeds unless noted otherwise.

| Topic | Robustness result |
| --- | --- |
| NV059 | authorization F1 minimum {result["NV059"]["metrics"]["f1"]["minimum"]:.3f}; p95 latency maximum {result["NV059"]["metrics"]["p95_us"]["maximum"]:.1f} us |
| NV062 | replay-block rate minimum {result["NV062"]["metrics"]["replay_block_rate"]["minimum"]:.3f}; return-tamper block rate minimum {result["NV062"]["metrics"]["return_tamper_block_rate"]["minimum"]:.3f} |
| NP002 | 150-UAS association minimum {result["NP002"]["metrics"]["association_150"]["minimum"]:.3f}; p95 maximum {result["NP002"]["metrics"]["p95_ms_150"]["maximum"]:.2f} ms |
| NV061 | source-aware accuracy minimum {result["NV061"]["metrics"]["source_accuracy"]["minimum"]:.3f}; position-only mean {result["NV061"]["metrics"]["position_accuracy"]["mean"]:.3f} |
| NV065 | constrained invalid schedules maximum {result["NV065"]["metrics"]["invalid_schedules"]["maximum"]:.0f}; scheduler p95 maximum {result["NV065"]["metrics"]["scheduler_p95_us"]["maximum"]:.1f} us |
"""


def main() -> None:
    tracks = load_real_ais_tracks(AIS_PATH, maximum_tracks=100)
    seeds = [1, 2, 3, 4, 5]
    result = {
        "NV059": repeat(
            [5901, 5902, 5903],
            lambda seed: run_opcua_enforcement_proxy(seed, requests=80),
            {
                "f1": lambda run: run["authorization"]["f1"],
                "p95_us": lambda run: run["performance"]["p95_us"],
                "direct_write_blocked": lambda run: float(
                    run["direct_protected_write_blocked"]
                ),
            },
        ),
        "NV062": repeat(
            [6201, 6202, 6203],
            lambda seed: run_secure_provider_workflow_extension(seed, tasks=16),
            {
                "replay_block_rate": lambda run: run["duplicate_blocked"]
                / run["tasks"],
                "return_tamper_block_rate": lambda run: run[
                    "tampered_return_blocked"
                ]
                / max(run["return_integrity_verified"], 1),
                "p95_us": lambda run: run["performance"]["p95_us"],
            },
        ),
        "NP002": repeat(
            seeds,
            run_cuas_scale_and_fusion_stress,
            {
                "association_150": lambda run: run["scale"]["150"][
                    "assignment_accuracy"
                ],
                "p95_ms_150": lambda run: run["scale"]["150"]["p95_update_ms"],
                "fusion_f1": lambda run: run["synthetic_front_end_fusion"]["f1"],
            },
        ),
        "NV061": repeat(
            seeds,
            lambda seed: evaluate_mixed_domain_custody(
                tracks,
                OPENSKY_PATH,
                seed=6100 + seed,
            ),
            {
                "source_accuracy": lambda run: run["source_aware_accuracy"],
                "position_accuracy": lambda run: run["position_only_accuracy"],
                "source_switches": lambda run: run[
                    "source_aware_identity_switches"
                ],
                "position_switches": lambda run: run[
                    "position_only_identity_switches"
                ],
            },
        ),
        "NV065": repeat(
            seeds,
            lambda seed: run_sensor_constraint_stress(6500 + seed),
            {
                "invalid_schedules": lambda run: run[
                    "constrained_invalid_sensor_schedules"
                ],
                "scheduler_p95_us": lambda run: run["scheduler_p95_us"],
                "utility_retention": lambda run: run["mean_constrained_utility"]
                / run["mean_naive_utility"],
            },
        ),
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    write_json(OUTPUT / "extension_robustness.json", result)
    (OUTPUT / "EXTENSION_ROBUSTNESS.md").write_text(render(result))
    print(render(result))
    print(json.dumps({"output": str(OUTPUT)}, indent=2))


if __name__ == "__main__":
    main()
