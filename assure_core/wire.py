"""Independent Python verifier for the native authenticated track frame."""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Any


TRACK_BODY = struct.Struct(">4sHHQQBB2xQ3d3f6f2f")
TRACK_FRAME_BYTES = TRACK_BODY.size + hashlib.sha256().digest_size


def decode_authenticated_track(frame: bytes, key: bytes) -> dict[str, Any]:
    if len(frame) != TRACK_FRAME_BYTES:
        raise ValueError("invalid authenticated-track frame length")
    body = frame[: TRACK_BODY.size]
    provided = frame[TRACK_BODY.size :]
    expected = hmac.new(key, body, hashlib.sha256).digest()
    if not hmac.compare_digest(provided, expected):
        raise ValueError("authenticated-track HMAC verification failed")
    values = TRACK_BODY.unpack(body)
    if values[0] != b"ATK1":
        raise ValueError("invalid authenticated-track magic")
    if values[1] != 1:
        raise ValueError("unsupported authenticated-track version")
    covariance = list(values[14:20])
    quality, anomaly = values[20:22]
    if values[5] not in {1, 2, 3}:
        raise ValueError("invalid authenticated-track source")
    if any(value < 0 for value in covariance):
        raise ValueError("negative covariance component")
    if not 0.0 <= quality <= 1.0 or not 0.0 <= anomaly <= 1.0:
        raise ValueError("invalid authenticated-track probability")
    return {
        "version": values[1],
        "flags": values[2],
        "sequence": values[3],
        "track_id": values[4],
        "source": values[5],
        "classification": values[6],
        "timestamp_ns": values[7],
        "position": list(values[8:11]),
        "velocity": list(values[11:14]),
        "covariance_upper": covariance,
        "quality": quality,
        "anomaly": anomaly,
    }
