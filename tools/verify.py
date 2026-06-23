#!/usr/bin/env python3
"""One-command verification for the Phase I feasibility workspace."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "native" / "assure-kernel" / "Cargo.toml"
RESULTS = ROOT / "results" / "performance"
EVIDENCE = ROOT / "results" / "evidence"


def run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def capture_json(command: list[str]) -> dict:
    print("+", " ".join(command), flush=True)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def write_source_manifest() -> Path:
    included_names = {"Makefile", "requirements.txt", "requirements-lock.txt"}
    included_suffixes = {
        ".h",
        ".c",
        ".lock",
        ".md",
        ".py",
        ".rs",
        ".toml",
        ".yaml",
        ".yml",
    }
    excluded_roots = {".git", ".venv", "data", "results", "target", "__pycache__"}
    entries = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in excluded_roots for part in relative.parts):
            continue
        if path.name not in included_names and path.suffix not in included_suffixes:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {relative.as_posix()}")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    output = EVIDENCE / "source_manifest.sha256"
    output.write_text("\n".join(sorted(entries)) + "\n")
    return output


def verify_c_abi() -> None:
    release = ROOT / "native" / "assure-kernel" / "target" / "release"
    include = ROOT / "native" / "assure-kernel" / "include"
    source = ROOT / "tools" / "c_abi_smoke.c"
    with tempfile.TemporaryDirectory(prefix="assure-c-abi-") as directory:
        executable = Path(directory) / "assure-c-abi-smoke"
        run(
            [
                "cc",
                str(source),
                "-I",
                str(include),
                "-L",
                str(release),
                "-lassure_kernel",
                "-lm",
                "-o",
                str(executable),
            ]
        )
        environment = os.environ.copy()
        variable = (
            "DYLD_LIBRARY_PATH"
            if sys.platform == "darwin"
            else "PATH"
            if sys.platform == "win32"
            else "LD_LIBRARY_PATH"
        )
        environment[variable] = (
            str(release)
            + os.pathsep
            + environment.get(variable, "")
        )
        print("+", executable, flush=True)
        subprocess.run([str(executable)], cwd=ROOT, env=environment, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--full",
        action="store_true",
        help="run all Python test modules instead of the shared-core tests",
    )
    parser.add_argument(
        "--campaign",
        action="store_true",
        help="rerun the complete Wave 5 evidence campaign",
    )
    parser.add_argument(
        "--benchmark-iterations",
        type=int,
        default=250_000,
    )
    arguments = parser.parse_args()

    if sys.version_info < (3, 9):
        raise SystemExit("Python 3.9 or newer is required")

    run(
        [
            "cargo",
            "fmt",
            "--manifest-path",
            str(MANIFEST),
            "--all",
            "--",
            "--check",
        ]
    )
    run(
        [
            "cargo",
            "clippy",
            "--manifest-path",
            str(MANIFEST),
            "--all-targets",
            "--release",
            "--",
            "-D",
            "warnings",
        ]
    )
    run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(MANIFEST),
            "--release",
        ]
    )
    verify_c_abi()
    run([sys.executable, "-m", "compileall", "-q", "assure_core"])
    if arguments.full:
        run([sys.executable, "-m", "unittest", "discover", "-v"])
    else:
        run(
            [
                sys.executable,
                "-m",
                "unittest",
                "-v",
                "test_assure_core.py",
                "test_native_kernel.py",
            ]
        )

    executable = (
        ROOT
        / "native"
        / "assure-kernel"
        / "target"
        / "release"
        / ("assure-kernel.exe" if sys.platform == "win32" else "assure-kernel")
    )
    benchmark = capture_json(
        [
            str(executable),
            "benchmark",
            str(arguments.benchmark_iterations),
        ]
    )
    benchmark["metadata"] = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "measurement_scope": (
            "release-mode host benchmark; not target-hardware WCET"
        ),
    }
    benchmark["binary_bytes"] = executable.stat().st_size
    RESULTS.mkdir(parents=True, exist_ok=True)
    output = RESULTS / "native_kernel_benchmark.json"
    output.write_text(json.dumps(benchmark, indent=2, sort_keys=True) + "\n")
    print(f"wrote {output.relative_to(ROOT)}")
    report = RESULTS / "EFFICIENCY_REPORT.md"
    report.write_text(
        f"""# Native Kernel Efficiency Report

Host: `{benchmark["metadata"]["platform"]}`

This is a release-mode host measurement, not target-hardware worst-case
execution-time evidence.

| Measurement | Result |
| --- | ---: |
| Evidence update | {benchmark["evidence_ns_per_operation"]:.1f} ns/op |
| Custody and priority | {benchmark["custody_priority_ns_per_operation"]:.1f} ns/op |
| Authenticated track decode | {benchmark["track_decode_ns_per_operation"]:.1f} ns/op |
| 240-candidate bounded schedule | {benchmark["scheduler_ns_per_operation"]:.1f} ns/op |
| 1,000-object sparse association | {benchmark["association_ns_per_operation"] / 1_000.0:.1f} us/update |
| Authenticated track frame | {benchmark["track_frame_bytes"]} bytes |
| Release executable | {benchmark["binary_bytes"] / 1024.0:.1f} KiB |

The verification gate is intentionally loose enough to tolerate shared CI
hosts while still detecting major regressions. Representative x86 and ARM
hardware profiling remains a Phase I transition task.
"""
    )
    print(f"wrote {report.relative_to(ROOT)}")
    manifest = write_source_manifest()
    print(f"wrote {manifest.relative_to(ROOT)}")

    if arguments.campaign:
        run([sys.executable, "run_wave5_campaign.py"])
        run([sys.executable, "run_wave5_robustness.py"])


if __name__ == "__main__":
    main()
