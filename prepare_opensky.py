#!/usr/bin/env python3
"""Collect a small reproducible OpenSky state-vector series for air-track tests."""

from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT = ROOT / "data" / "external" / "opensky" / "puget_sound_states.json"
ENDPOINT = "https://opensky-network.org/api/states/all"


def fetch_snapshot(
    *,
    lamin: float = 46.0,
    lomin: float = -124.0,
    lamax: float = 49.0,
    lomax: float = -121.0,
    timeout: float = 30.0,
) -> dict[str, Any]:
    query = urllib.parse.urlencode(
        {"lamin": lamin, "lomin": lomin, "lamax": lamax, "lomax": lomax}
    )
    request = urllib.request.Request(
        f"{ENDPOINT}?{query}",
        headers={"User-Agent": "AssureEdge-Phase-I-Feasibility/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    return {
        "api_time": payload.get("time"),
        "states": payload.get("states") or [],
        "received_at": datetime.now(timezone.utc).isoformat(),
    }


def collect(
    output: Path,
    *,
    samples: int = 6,
    interval_seconds: float = 5.0,
) -> dict[str, Any]:
    snapshots: list[dict[str, Any]] = []
    for index in range(samples):
        snapshots.append(fetch_snapshot())
        if index + 1 < samples:
            time.sleep(interval_seconds)
    result = {
        "source": ENDPOINT,
        "license_note": "OpenSky Network data used for research feasibility testing",
        "bounding_box": {
            "lamin": 46.0,
            "lomin": -124.0,
            "lamax": 49.0,
            "lomax": -121.0,
        },
        "sample_interval_seconds": interval_seconds,
        "snapshots": snapshots,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--samples", type=int, default=6)
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()
    result = collect(
        args.output,
        samples=args.samples,
        interval_seconds=args.interval,
    )
    unique = {
        state[0]
        for snapshot in result["snapshots"]
        for state in snapshot["states"]
        if state and state[0]
    }
    print(
        json.dumps(
            {
                "snapshots": len(result["snapshots"]),
                "unique_aircraft": len(unique),
                "output": str(args.output),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
