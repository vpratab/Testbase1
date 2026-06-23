#!/usr/bin/env python3
"""Create a compact, reproducible Puget Sound subset from an official NOAA AIS day."""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

import pandas as pd


SOURCE_URL = (
    "https://coast.noaa.gov/htdata/CMSP/AISDataHandler/2020/"
    "AIS_2020_02_15.zip"
)


def prepare(source: Path, output: Path, maximum_rows: int = 180_000) -> dict:
    columns = ["MMSI", "BaseDateTime", "LAT", "LON", "SOG", "COG", "Heading", "VesselType"]
    selected: list[pd.DataFrame] = []
    rows = 0
    with zipfile.ZipFile(source) as archive:
        member = archive.namelist()[0]
        with archive.open(member) as stream:
            for chunk in pd.read_csv(
                stream,
                usecols=columns,
                chunksize=250_000,
                low_memory=False,
            ):
                region = chunk[
                    chunk["LAT"].between(46.8, 49.1)
                    & chunk["LON"].between(-124.2, -121.6)
                    & chunk["SOG"].between(0.0, 80.0)
                ].copy()
                if region.empty:
                    continue
                selected.append(region)
                rows += len(region)
                if rows >= maximum_rows:
                    break
    frame = pd.concat(selected, ignore_index=True).head(maximum_rows)
    frame["BaseDateTime"] = pd.to_datetime(frame["BaseDateTime"], utc=True)
    frame.sort_values(["MMSI", "BaseDateTime"], inplace=True)
    counts = frame.groupby("MMSI").size()
    keep = counts[counts >= 25].index
    frame = frame[frame["MMSI"].isin(keep)].copy()
    output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output, index=False)
    metadata = {
        "source_url": SOURCE_URL,
        "source_archive": str(source),
        "output": str(output),
        "region": {
            "latitude": [46.8, 49.1],
            "longitude": [-124.2, -121.6],
        },
        "rows": int(len(frame)),
        "vessels": int(frame["MMSI"].nunique()),
        "first_timestamp": str(frame["BaseDateTime"].min()),
        "last_timestamp": str(frame["BaseDateTime"].max()),
    }
    output.with_suffix(".metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    )
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        default="data/external/noaa_ais/AIS_2020_02_15.zip",
    )
    parser.add_argument(
        "--output",
        default="data/processed/noaa_ais_puget_sound_2020_02_15.csv",
    )
    parser.add_argument("--maximum-rows", type=int, default=180_000)
    args = parser.parse_args()
    print(
        json.dumps(
            prepare(Path(args.source), Path(args.output), args.maximum_rows),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
