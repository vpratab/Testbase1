#!/usr/bin/env python3
"""Range-extract a bounded NASA small-UAS acoustics subset."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from remotezip import RemoteZip


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "data" / "external" / "nasa_uas_acoustics"
ARCHIVE_URL = "https://data.nasa.gov/docs/datasets/rfk401li/small_uav_acoustics.zip"
SELECTED = (
    "Data Description 20160203.pdf",
    "Flight Number Description.xlsx",
    "data/hex_flyover_205.mat",
    "data/hex_flyover_206.mat",
    "data/hex_flyover_216.mat",
    "data/edge_flyover_043.mat",
    "data/edge_flyover_053.mat",
    "data/edge_flyover_065.mat",
    "data/phantom_flyover_120.mat",
    "data/phantom_flyover_121.mat",
    "data/phantom_flyover_122.mat",
    "data/y6_hover_200.mat",
    "data/y6_hover_201.mat",
    "data/y6_hover_202.mat",
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def prepare(output: Path = OUTPUT) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    extracted = []
    with RemoteZip(ARCHIVE_URL, initial_buffer_size=1024 * 1024) as archive:
        info = {item.filename: item for item in archive.infolist()}
        for name in SELECTED:
            if name not in info:
                raise FileNotFoundError(f"NASA archive member not found: {name}")
            destination = output / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists() or destination.stat().st_size != info[name].file_size:
                with archive.open(name) as source, destination.open("wb") as target:
                    while chunk := source.read(1024 * 1024):
                        target.write(chunk)
            extracted.append(
                {
                    "archive_member": name,
                    "path": str(destination),
                    "bytes": destination.stat().st_size,
                    "sha256": digest(destination),
                }
            )
    manifest = {
        "source": ARCHIVE_URL,
        "selection_basis": (
            "three separate recordings for each of four UAS configurations, "
            "plus the authoritative NASA data description and flight index"
        ),
        "files": extracted,
        "total_bytes": sum(item["bytes"] for item in extracted),
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True)
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    manifest = prepare(args.output)
    print(
        json.dumps(
            {
                "files": len(manifest["files"]),
                "total_bytes": manifest["total_bytes"],
                "output": str(args.output),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
