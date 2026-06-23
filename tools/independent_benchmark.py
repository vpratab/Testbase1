#!/usr/bin/env python3
"""Repeat native benchmarks across independent processes and report dispersion.

This harness intentionally sits outside the Rust benchmark binary. It records
the exact executable hash, source-tree hash, raw observations, run-to-run
dispersion, and deterministic conformance. It is host performance evidence,
not a target-hardware WCET claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "native" / "assure-kernel" / "Cargo.toml"
EXECUTABLE = (
    ROOT
    / "native"
    / "assure-kernel"
    / "target"
    / "release"
    / ("assure-kernel.exe" if sys.platform == "win32" else "assure-kernel")
)
OUTPUT_DIRECTORY = ROOT / "results" / "independent_benchmark"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_tree_sha256() -> str:
    included_names = {"Makefile", "requirements.txt", "requirements-lock.txt"}
    included_suffixes = {
        ".c",
        ".h",
        ".lock",
        ".md",
        ".py",
        ".rs",
        ".toml",
        ".yaml",
        ".yml",
    }
    excluded_roots = {".git", ".venv", "data", "results", "target", "__pycache__"}
    digest = hashlib.sha256()
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in excluded_roots for part in relative.parts):
            continue
        if path.name not in included_names and path.suffix not in included_suffixes:
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def capture_json(arguments: list[str]) -> tuple[dict[str, Any], float]:
    started = time.perf_counter_ns()
    completed = subprocess.run(
        arguments,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    return json.loads(completed.stdout), elapsed_ms


def nearest_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def summarize(values: list[float]) -> dict[str, float | int]:
    mean = statistics.fmean(values)
    return {
        "samples": len(values),
        "minimum": min(values),
        "median": statistics.median(values),
        "p95": nearest_rank(values, 0.95),
        "maximum": max(values),
        "mean": mean,
        "coefficient_of_variation": (
            statistics.pstdev(values) / mean
            if len(values) > 1 and mean != 0.0
            else 0.0
        ),
    }


def aggregate_benchmarks(runs: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = [
        "evidence_ns_per_operation",
        "custody_priority_ns_per_operation",
        "track_decode_ns_per_operation",
        "scheduler_ns_per_operation",
        "association_ns_per_operation",
    ]
    return {
        metric: summarize([float(run[metric]) for run in runs])
        for metric in metrics
    }


def aggregate_scaling(runs: list[dict[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for family in ("association", "scheduler"):
        by_size: dict[int, list[float]] = {}
        for run in runs:
            for point in run[family]:
                by_size.setdefault(int(point["size"]), []).append(
                    float(point["ns_per_update"])
                )
        output[family] = {
            str(size): summarize(values)
            for size, values in sorted(by_size.items())
        }
    return output


def format_time(ns: float) -> str:
    if ns >= 1_000_000.0:
        return f"{ns / 1_000_000.0:.3f} ms"
    if ns >= 1_000.0:
        return f"{ns / 1_000.0:.3f} us"
    return f"{ns:.1f} ns"


def write_markdown(result: dict[str, Any]) -> None:
    benchmark = result["aggregate"]["benchmark"]
    scaling = result["aggregate"]["scaling"]
    process = result["aggregate"]["process_wall_ms"]
    gates = result["sanity_gates"]

    rows = [
        (
            "Authenticated 136-byte decode",
            benchmark["track_decode_ns_per_operation"],
        ),
        ("240-candidate schedule", benchmark["scheduler_ns_per_operation"]),
        ("1,000-object association", benchmark["association_ns_per_operation"]),
        ("10,000-object association", scaling["association"]["10000"]),
        ("3,840-candidate schedule", scaling["scheduler"]["3840"]),
    ]
    table = "\n".join(
        f"| {name} | {format_time(values['median'])} | "
        f"{format_time(values['p95'])} | {format_time(values['maximum'])} | "
        f"{values['coefficient_of_variation'] * 100.0:.1f}% |"
        for name, values in rows
    )
    gate_table = "\n".join(
        f"| {name} | {'PASS' if gate['passed'] else 'FAIL'} | {gate['detail']} |"
        for name, gate in gates.items()
    )

    report = f"""# Independent Repeated Native Benchmark

Generated: `{result["metadata"]["generated_at_utc"]}`

- Host: `{result["metadata"]["platform"]}`
- Machine: `{result["metadata"]["machine"]}`
- Rust: `{result["metadata"]["rustc"]}`
- Executable SHA-256: `{result["metadata"]["executable_sha256"]}`
- Source-tree SHA-256: `{result["metadata"]["source_tree_sha256"]}`

## Method

- Release binary built once before measurement.
- One unreported warm-up process.
- {result["configuration"]["benchmark_runs"]} independent benchmark processes
  at {result["configuration"]["iterations_per_benchmark_run"]:,} iterations.
- {result["configuration"]["scaling_runs"]} independent scaling processes.
- {result["configuration"]["conformance_runs"]} independent conformance
  processes compared for byte-equivalent JSON results.
- Percentiles below are across process-level results, not individual
  operations and not worst-case execution-time bounds.

## Results

| Path | Median | Process p95 | Process max | CV |
| --- | ---: | ---: | ---: | ---: |
{table}

Median benchmark-process wall time was
`{process["benchmark"]["median"]:.2f} ms`; median scaling-process wall time was
`{process["scaling"]["median"]:.2f} ms`.

## Sanity gates

These intentionally loose gates detect catastrophic regressions on a shared
host. They are not sponsor acceptance criteria.

| Gate | Result | Evidence |
| --- | --- | --- |
{gate_table}

## Interpretation limits

This benchmark establishes executable feasibility and run-to-run behavior on
this host. It does not establish target-platform WCET, real-time scheduling,
end-to-end sensor latency, power/thermal performance, dense-clutter tracking
quality, or operational mission effectiveness. The association geometry is
spatially gated and favorable. A representative Linux x86/ARM hardware matrix,
CPU pinning, fixed power state, memory profiling, dense-crossing accuracy, and
sponsor data remain required.
"""
    (OUTPUT_DIRECTORY / "INDEPENDENT_BENCHMARK.md").write_text(report)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark-runs", type=int, default=15)
    parser.add_argument("--scaling-runs", type=int, default=10)
    parser.add_argument("--conformance-runs", type=int, default=10)
    parser.add_argument("--iterations", type=int, default=100_000)
    arguments = parser.parse_args()
    if min(
        arguments.benchmark_runs,
        arguments.scaling_runs,
        arguments.conformance_runs,
        arguments.iterations,
    ) < 1:
        raise SystemExit("all run counts and iterations must be positive")

    subprocess.run(
        [
            "cargo",
            "build",
            "--quiet",
            "--release",
            "--manifest-path",
            str(MANIFEST),
        ],
        cwd=ROOT,
        check=True,
    )
    if not EXECUTABLE.exists():
        raise SystemExit(f"missing release executable: {EXECUTABLE}")

    capture_json([str(EXECUTABLE), "benchmark", str(arguments.iterations)])

    benchmark_runs: list[dict[str, Any]] = []
    benchmark_wall_ms: list[float] = []
    for _ in range(arguments.benchmark_runs):
        observation, elapsed_ms = capture_json(
            [str(EXECUTABLE), "benchmark", str(arguments.iterations)]
        )
        benchmark_runs.append(observation)
        benchmark_wall_ms.append(elapsed_ms)

    scaling_runs: list[dict[str, Any]] = []
    scaling_wall_ms: list[float] = []
    for _ in range(arguments.scaling_runs):
        observation, elapsed_ms = capture_json([str(EXECUTABLE), "scaling"])
        scaling_runs.append(observation)
        scaling_wall_ms.append(elapsed_ms)

    conformance_runs: list[dict[str, Any]] = []
    conformance_wall_ms: list[float] = []
    for _ in range(arguments.conformance_runs):
        observation, elapsed_ms = capture_json([str(EXECUTABLE), "conformance"])
        conformance_runs.append(observation)
        conformance_wall_ms.append(elapsed_ms)

    canonical_conformance = [
        json.dumps(observation, sort_keys=True, separators=(",", ":"))
        for observation in conformance_runs
    ]
    conformance_deterministic = len(set(canonical_conformance)) == 1
    benchmark_aggregate = aggregate_benchmarks(benchmark_runs)
    scaling_aggregate = aggregate_scaling(scaling_runs)

    gates = {
        "deterministic_conformance": {
            "passed": conformance_deterministic,
            "detail": (
                f"{arguments.conformance_runs} independent processes agreed"
            ),
        },
        "authenticated_decode": {
            "passed": (
                benchmark_aggregate["track_decode_ns_per_operation"]["p95"]
                < 50_000.0
            ),
            "detail": (
                f"process p95 "
                f"{format_time(benchmark_aggregate['track_decode_ns_per_operation']['p95'])} "
                f"< 50 us"
            ),
        },
        "bounded_scheduler": {
            "passed": (
                scaling_aggregate["scheduler"]["3840"]["p95"] < 5_000_000.0
            ),
            "detail": (
                f"3,840-candidate process p95 "
                f"{format_time(scaling_aggregate['scheduler']['3840']['p95'])} "
                f"< 5 ms"
            ),
        },
        "sparse_association": {
            "passed": (
                scaling_aggregate["association"]["10000"]["p95"]
                < 50_000_000.0
            ),
            "detail": (
                f"10,000-object process p95 "
                f"{format_time(scaling_aggregate['association']['10000']['p95'])} "
                f"< 50 ms"
            ),
        },
    }
    result: dict[str, Any] = {
        "metadata": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "rustc": subprocess.run(
                ["rustc", "--version"],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip(),
            "executable_bytes": EXECUTABLE.stat().st_size,
            "executable_sha256": sha256(EXECUTABLE),
            "source_tree_sha256": source_tree_sha256(),
            "measurement_scope": (
                "release-mode host benchmark across independent processes; "
                "not target-hardware WCET"
            ),
        },
        "configuration": {
            "benchmark_runs": arguments.benchmark_runs,
            "scaling_runs": arguments.scaling_runs,
            "conformance_runs": arguments.conformance_runs,
            "iterations_per_benchmark_run": arguments.iterations,
        },
        "aggregate": {
            "benchmark": benchmark_aggregate,
            "scaling": scaling_aggregate,
            "process_wall_ms": {
                "benchmark": summarize(benchmark_wall_ms),
                "scaling": summarize(scaling_wall_ms),
                "conformance": summarize(conformance_wall_ms),
            },
        },
        "sanity_gates": gates,
        "raw": {
            "benchmark": benchmark_runs,
            "benchmark_process_wall_ms": benchmark_wall_ms,
            "scaling": scaling_runs,
            "scaling_process_wall_ms": scaling_wall_ms,
            "conformance": conformance_runs,
            "conformance_process_wall_ms": conformance_wall_ms,
        },
    }

    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    output = OUTPUT_DIRECTORY / "independent_benchmark.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    write_markdown(result)
    print(f"wrote {output.relative_to(ROOT)}")
    print(
        f"wrote "
        f"{(OUTPUT_DIRECTORY / 'INDEPENDENT_BENCHMARK.md').relative_to(ROOT)}"
    )
    if not all(gate["passed"] for gate in gates.values()):
        raise SystemExit("one or more independent benchmark sanity gates failed")


if __name__ == "__main__":
    main()
