#!/usr/bin/env python3
"""Repeat each feasibility experiment across multiple deterministic seeds."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from run_experiments import (
    run_np002,
    run_nv059,
    run_nv061,
    run_nv062,
    run_nv063,
    run_nv065,
    run_qsparx,
)


def summarize(values: list[float]) -> dict[str, float]:
    array = np.asarray(values, dtype=float)
    return {
        "minimum": float(np.min(array)),
        "median": float(np.median(array)),
        "maximum": float(np.max(array)),
        "mean": float(np.mean(array)),
    }


def main() -> None:
    seeds = list(range(10, 20))
    qsparx = [run_qsparx(seed) for seed in seeds]
    nv59 = [run_nv059(seed) for seed in seeds]
    nv63 = [run_nv063(seed) for seed in seeds]
    nv61 = [run_nv061(seed) for seed in seeds]
    nv62 = [run_nv062(seed) for seed in seeds]
    nv65 = [run_nv065(seed) for seed in seeds]
    np2 = [run_np002(seed) for seed in seeds]
    results = {
        "seeds": seeds,
        "QSPARX": {
            "f1": summarize([result["f1"] for result in qsparx]),
            "recall": summarize([result["recall"] for result in qsparx]),
            "modeled_schedule_reduction_pct": summarize(
                [result["modeled_schedule_reduction_pct"] for result in qsparx]
            ),
        },
        "NV059": {
            "local_decision_p95_us": summarize(
                [result["local_decision_p95_us"] for result in nv59]
            ),
            "false_allows": summarize(
                [float(result["false_allows"]) for result in nv59]
            ),
            "false_denies": summarize(
                [float(result["false_denies"]) for result in nv59]
            ),
        },
        "NV063": {
            "f1": summarize([result["f1"] for result in nv63]),
            "recall": summarize([result["recall"] for result in nv63]),
            "false_positive_rate": summarize(
                [result["false_positive_rate"] for result in nv63]
            ),
        },
        "NV061": {
            "forecast_improvement_vs_hold_pct": summarize(
                [result["improvement_vs_hold_pct"] for result in nv61]
            ),
            "priority_recall_at_threat_count": summarize(
                [result["priority_recall_at_threat_count"] for result in nv61]
            ),
        },
        "NV062": {
            "measured_crypto_roundtrip_p95_us": summarize(
                [result["measured_crypto_roundtrip_p95_us"] for result in nv62]
            ),
            "modeled_tasking_time_reduction_pct": summarize(
                [result["modeled_tasking_time_reduction_pct"] for result in nv62]
            ),
            "tamper_block_rate": summarize(
                [
                    result["tampered_tasks_blocked"] / result["tampered_tasks"]
                    for result in nv62
                ]
            ),
        },
        "NV065": {
            "novel_threat_quality_improvement_pct": summarize(
                [result["novel_threat_quality_improvement_pct"] for result in nv65]
            ),
            "recommendation_runtime_p95_us": summarize(
                [result["recommendation_runtime_p95_us"] for result in nv65]
            ),
        },
        "NP002": {
            "f1": summarize([result["f1"] for result in np2]),
            "recall": summarize([result["recall"] for result in np2]),
            "false_positive_rate": summarize(
                [result["false_positive_rate"] for result in np2]
            ),
            "mean_detection_delay_steps": summarize(
                [result["mean_detection_delay_steps"] for result in np2]
            ),
        },
    }
    output = Path(__file__).resolve().parent / "results" / "robustness_sweep.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    print(json.dumps(results, indent=2, sort_keys=True))
    print(f"\nOutput: {output}")


if __name__ == "__main__":
    main()
