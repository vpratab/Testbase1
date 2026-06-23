"""Build and invoke the native assurance-kernel verification binary.

The subprocess interface is deliberately limited to conformance and benchmark
workflows. Operational integrations should link the Rust library directly
through a C ABI or platform-native service boundary instead of spawning a
process for each decision.
"""

from __future__ import annotations

import json
import os
import subprocess
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
    / ("assure-kernel.exe" if os.name == "nt" else "assure-kernel")
)


def build_native_kernel() -> Path:
    """Build the deterministic release binary and return its path."""
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
    return EXECUTABLE


def run_native_kernel(
    command: str,
    *arguments: str,
    build: bool = True,
) -> dict[str, Any]:
    """Run one bounded verification command and parse its JSON response."""
    executable = build_native_kernel() if build or not EXECUTABLE.exists() else EXECUTABLE
    completed = subprocess.run(
        [str(executable), command, *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)
