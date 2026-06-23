#!/usr/bin/env python3
"""Generate a dependency inventory and release-integrity manifest."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "results" / "supply_chain"
MANIFEST = ROOT / "native" / "assure-kernel" / "Cargo.toml"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def python_components() -> list[dict[str, Any]]:
    components = []
    for line in (ROOT / "requirements-lock.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, version = line.split("==", 1)
        components.append(
            {
                "ecosystem": "pypi",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name.lower()}@{version}",
                "scope": "direct",
            }
        )
    return components


def rust_components() -> list[dict[str, Any]]:
    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--manifest-path",
            str(MANIFEST),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(completed.stdout)
    root_package = next(
        package for package in metadata["packages"] if package["name"] == "assure-kernel"
    )
    direct = {dependency["name"] for dependency in root_package["dependencies"]}
    components = []
    for package in metadata["packages"]:
        components.append(
            {
                "ecosystem": "cargo",
                "name": package["name"],
                "version": package["version"],
                "purl": f'pkg:cargo/{package["name"]}@{package["version"]}',
                "license": package.get("license"),
                "source": package.get("source") or "workspace",
                "scope": (
                    "workspace"
                    if package["name"] == "assure-kernel"
                    else "direct"
                    if package["name"] in direct
                    else "transitive"
                ),
            }
        )
    return sorted(components, key=lambda item: (item["name"], item["version"]))


def source_tree_root() -> tuple[str, int]:
    manifest = ROOT / "results" / "evidence" / "source_manifest.sha256"
    lines = sorted(
        line.strip() for line in manifest.read_text().splitlines() if line.strip()
    )
    digest = hashlib.sha256("\n".join(lines).encode()).hexdigest()
    return digest, len(lines)


def main() -> None:
    components = python_components() + rust_components()
    inventory = {
        "format": "assureedge-component-inventory/v1",
        "component_count": len(components),
        "components": components,
        "boundary": (
            "lockfile-derived component inventory; not a vulnerability scan "
            "or third-party software-composition-analysis attestation"
        ),
    }
    source_root, source_files = source_tree_root()
    artifact_paths = [
        ROOT / "native" / "assure-kernel" / "Cargo.lock",
        ROOT / "requirements-lock.txt",
        ROOT / "data" / "processed" / "noaa_ais_puget_sound_2020_02_15.csv",
        ROOT / "data" / "processed" / "noaa_ais_new_york_2020_03_15.csv",
        ROOT
        / "data"
        / "processed"
        / "noaa_ais_new_york_2020_03_15.metadata.json",
        ROOT / "results" / "trl4_wave5" / "wave5_campaign_results.json",
        ROOT / "results" / "theory_campaign" / "theory_campaign_results.json",
        ROOT / "results" / "performance" / "native_kernel_benchmark.json",
        ROOT / "results" / "performance" / "native_kernel_scaling.json",
        ROOT
        / "results"
        / "independent_benchmark"
        / "independent_benchmark.json",
        ROOT
        / "results"
        / "independent_benchmark"
        / "INDEPENDENT_BENCHMARK.md",
        ROOT / "results" / "dense_crossing" / "dense_crossing_results.json",
        ROOT / "results" / "dense_crossing" / "DENSE_CROSSING_REPORT.md",
        ROOT / "results" / "frozen_region" / "frozen_region_results.json",
        ROOT / "results" / "frozen_region" / "FROZEN_REGION_REPORT.md",
    ]
    release = {
        "format": "assureedge-release-manifest/v1",
        "source_manifest_root_sha256": source_root,
        "source_files": source_files,
        "artifacts": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
            for path in artifact_paths
        ],
        "component_inventory_sha256": hashlib.sha256(
            json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "boundary": (
            "local integrity manifest; signing, independent timestamping, and "
            "external artifact storage remain release-process tasks"
        ),
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "component_inventory.json").write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n"
    )
    (OUTPUT / "release_manifest.json").write_text(
        json.dumps(release, indent=2, sort_keys=True) + "\n"
    )
    print(
        json.dumps(
            {
                "components": len(components),
                "source_files": source_files,
                "artifacts": len(artifact_paths),
                "output": str(OUTPUT),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
