"""Real NASA small-UAS acoustic detection and type-classification experiment."""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
from scipy.io import loadmat
from scipy.signal import welch
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

from trl4_common import EvidenceChain, binary_metrics, tamper_test


VEHICLE_LABELS = ("edge", "hex", "phantom", "y6")


def _vehicle_distance(
    vehicle: Any,
    times: np.ndarray,
) -> tuple[np.ndarray, bool]:
    rtk_time = np.asarray(vehicle.rtk_utc_time, dtype=float).reshape(-1)
    rtk_position = np.asarray(vehicle.rtk_ned_meters, dtype=float)
    if rtk_position.ndim != 2 or rtk_position.shape[1] != 3:
        rtk_position = np.empty((0, 3))
    status = (
        np.asarray(vehicle.rtk_status).reshape(-1).astype(bool)
        if hasattr(vehicle, "rtk_status")
        else np.ones(len(rtk_time), dtype=bool)
    )
    usable = (
        status
        & np.isfinite(rtk_time)
        & np.all(np.isfinite(rtk_position), axis=1)
    )
    if np.sum(usable) < 3:
        rtk_time = np.asarray(vehicle.gps_utc_time, dtype=float).reshape(-1)
        rtk_position = np.asarray(vehicle.gps_ned_meters, dtype=float)
        if rtk_position.ndim != 2 or rtk_position.shape[1] != 3:
            rtk_position = np.empty((0, 3))
        usable = np.isfinite(rtk_time) & np.all(
            np.isfinite(rtk_position),
            axis=1,
        )
    if np.sum(usable) < 3:
        return np.zeros(len(times), dtype=float), False
    interpolated = np.column_stack(
        [
            np.interp(times, rtk_time[usable], rtk_position[usable, axis])
            for axis in range(3)
        ]
    )
    return np.linalg.norm(interpolated, axis=1), True


def _window_features(signal: np.ndarray, sample_rate: float) -> np.ndarray:
    signal = np.asarray(signal, dtype=float)
    signal = signal - np.mean(signal)
    rms = float(np.sqrt(np.mean(np.square(signal))) + 1.0e-12)
    frequencies, density = welch(
        signal,
        fs=sample_rate,
        nperseg=min(2048, len(signal)),
        noverlap=min(1024, max(len(signal) // 4, 0)),
    )
    density = np.maximum(density, 1.0e-20)
    total = float(np.sum(density))
    centroid = float(np.sum(frequencies * density) / total)
    bandwidth = float(
        np.sqrt(np.sum(np.square(frequencies - centroid) * density) / total)
    )
    cumulative = np.cumsum(density)
    rolloff = float(frequencies[np.searchsorted(cumulative, 0.90 * total)])
    geometric = float(np.exp(np.mean(np.log(density))))
    flatness = geometric / max(float(np.mean(density)), 1.0e-20)
    zero_crossing = float(
        np.mean(np.signbit(signal[1:]) != np.signbit(signal[:-1]))
    )
    crest = float(np.max(np.abs(signal)) / rms)
    bands = (
        (40, 80),
        (80, 160),
        (160, 315),
        (315, 630),
        (630, 1250),
        (1250, 2500),
        (2500, 4000),
        (4000, 6300),
        (6300, 9000),
    )
    band_features = []
    for lower, upper in bands:
        selected = (frequencies >= lower) & (frequencies < upper)
        energy = float(np.sum(density[selected]))
        band_features.append(np.log10(energy + 1.0e-20))
    return np.asarray(
        [
            np.log10(rms),
            centroid / sample_rate,
            bandwidth / sample_rate,
            rolloff / sample_rate,
            flatness,
            zero_crossing,
            crest,
            *band_features,
        ],
        dtype=float,
    )


def extract_recording_features(
    path: Path,
    *,
    window_seconds: float = 1.0,
    step_seconds: float = 1.0,
) -> dict[str, Any]:
    loaded = loadmat(path, squeeze_me=True, struct_as_record=False)
    acoustics = loaded["acoustics"]
    vehicle = loaded["vehicle_data"]
    pressure = np.asarray(acoustics.incident_pascals, dtype=float)
    times = np.asarray(acoustics.utc_time, dtype=float).reshape(-1)
    if pressure.ndim == 1:
        pressure = pressure[:, None]
    sample_rate = 1.0 / float(np.median(np.diff(times)))
    window = int(round(window_seconds * sample_rate))
    step = int(round(step_seconds * sample_rate))
    centers = np.arange(window // 2, len(times) - window // 2, step)
    center_times = times[centers]
    distances, position_available = _vehicle_distance(vehicle, center_times)
    if position_available:
        near_limit = max(35.0, float(np.quantile(distances, 0.35)))
        far_limit = max(
            near_limit + 50.0,
            float(np.quantile(distances, 0.80)),
        )
    else:
        near_limit = 0.0
        far_limit = float("inf")
    features: list[np.ndarray] = []
    active: list[bool] = []
    selected_distances: list[float] = []
    for center, distance in zip(centers, distances):
        if position_available and distance > near_limit and distance < far_limit:
            continue
        start = center - window // 2
        stop = start + window
        if stop > len(pressure):
            continue
        for microphone in range(pressure.shape[1]):
            features.append(
                _window_features(
                    pressure[start:stop, microphone],
                    sample_rate,
                )
            )
            active.append(
                bool(distance <= near_limit) if position_available else True
            )
            selected_distances.append(float(distance))
    label = path.name.split("_", 1)[0]
    return {
        "path": str(path),
        "recording": path.stem,
        "vehicle": label,
        "sample_rate_hz": sample_rate,
        "microphones": pressure.shape[1],
        "near_limit_m": near_limit,
        "far_limit_m": far_limit,
        "vehicle_position_available": position_available,
        "features": np.vstack(features),
        "active": np.asarray(active, dtype=bool),
        "distances_m": np.asarray(selected_distances),
    }


def _recording_folds(recordings: list[dict[str, Any]]) -> list[list[str]]:
    by_vehicle: dict[str, list[str]] = {label: [] for label in VEHICLE_LABELS}
    for recording in recordings:
        by_vehicle[recording["vehicle"]].append(recording["recording"])
    if any(len(values) < 3 for values in by_vehicle.values()):
        raise ValueError("three recordings per vehicle are required")
    for values in by_vehicle.values():
        values.sort()
    return [
        [by_vehicle[label][fold] for label in VEHICLE_LABELS]
        for fold in range(3)
    ]


def evaluate_nasa_uas_acoustics(data_root: Path) -> dict[str, Any]:
    paths = sorted((data_root / "data").glob("*.mat"))
    recordings = [
        extract_recording_features(path)
        for path in paths
        if path.name.split("_", 1)[0] in VEHICLE_LABELS
    ]
    folds = _recording_folds(recordings)
    detection_truth: list[bool] = []
    detection_predictions: list[bool] = []
    type_truth: list[str] = []
    type_predictions: list[str] = []
    fold_details = []
    started = time.perf_counter_ns()
    for fold, held_out in enumerate(folds):
        train = [
            recording
            for recording in recordings
            if recording["recording"] not in held_out
        ]
        test = [
            recording
            for recording in recordings
            if recording["recording"] in held_out
        ]
        train_x = np.vstack([recording["features"] for recording in train])
        test_x = np.vstack([recording["features"] for recording in test])
        train_active = np.concatenate(
            [recording["active"] for recording in train]
        )
        test_active = np.concatenate(
            [recording["active"] for recording in test]
        )
        detector = RandomForestClassifier(
            n_estimators=220,
            min_samples_leaf=3,
            class_weight="balanced",
            random_state=900 + fold,
            n_jobs=-1,
        )
        detector.fit(train_x, train_active)
        detected = detector.predict(test_x)
        detection_truth.extend(test_active.tolist())
        detection_predictions.extend(detected.tolist())

        train_type_x = np.vstack(
            [
                recording["features"][recording["active"]]
                for recording in train
            ]
        )
        train_type_y = np.concatenate(
            [
                np.repeat(
                    recording["vehicle"],
                    int(np.sum(recording["active"])),
                )
                for recording in train
            ]
        )
        test_type_x = np.vstack(
            [
                recording["features"][recording["active"]]
                for recording in test
            ]
        )
        test_type_y = np.concatenate(
            [
                np.repeat(
                    recording["vehicle"],
                    int(np.sum(recording["active"])),
                )
                for recording in test
            ]
        )
        classifier = ExtraTreesClassifier(
            n_estimators=300,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=1200 + fold,
            n_jobs=-1,
        )
        classifier.fit(train_type_x, train_type_y)
        classified = classifier.predict(test_type_x)
        type_truth.extend(test_type_y.tolist())
        type_predictions.extend(classified.tolist())
        fold_details.append(
            {
                "fold": fold,
                "held_out_recordings": held_out,
                "detection_f1": f1_score(test_active, detected),
                "type_accuracy": accuracy_score(test_type_y, classified),
                "type_macro_f1": f1_score(
                    test_type_y,
                    classified,
                    average="macro",
                ),
            }
        )
    elapsed_ms = (time.perf_counter_ns() - started) / 1.0e6
    detection = binary_metrics(detection_truth, detection_predictions)
    labels = list(VEHICLE_LABELS)
    confusion = confusion_matrix(
        type_truth,
        type_predictions,
        labels=labels,
    ).tolist()
    type_accuracy = accuracy_score(type_truth, type_predictions)
    type_macro_f1 = f1_score(
        type_truth,
        type_predictions,
        average="macro",
    )
    manifest_path = data_root / "manifest.json"
    dataset_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    evidence = EvidenceChain(b"nasa-uas-acoustics")
    evidence.append(
        "NP002",
        {
            "dataset_manifest_sha256": dataset_digest,
            "recordings": len(recordings),
            "detection_f1": detection["f1"],
            "type_accuracy": type_accuracy,
            "type_macro_f1": type_macro_f1,
        },
    )
    return {
        "source": "NASA Langley Small UAS Acoustic Data",
        "data_root": str(data_root),
        "dataset_manifest_sha256": dataset_digest,
        "recordings": len(recordings),
        "vehicles": dict(Counter(recording["vehicle"] for recording in recordings)),
        "recording_level_folds": fold_details,
        "detection": detection,
        "type_classification": {
            "labels": labels,
            "accuracy": type_accuracy,
            "macro_f1": type_macro_f1,
            "confusion_matrix": confusion,
            "majority_baseline_accuracy": 0.25,
        },
        "feature_count": int(recordings[0]["features"].shape[1]),
        "windows": sum(len(recording["features"]) for recording in recordings),
        "evaluation_ms": elapsed_ms,
        "label_semantics": (
            "near/far detection labels derive from vehicle-to-microphone "
            "distance; type labels derive from NASA recording filenames"
        ),
        "limitations": [
            "far windows still contain the same aircraft at lower signal level",
            "four vehicle configurations from one NASA campaign",
            "classification does not identify payload or establish hostility",
        ],
        "evidence": {
            "records": len(evidence.records),
            "head": evidence.head,
            "verified": EvidenceChain.verify(evidence.records, evidence.public_key),
            "tamper_detected": tamper_test(evidence.records, evidence.public_key),
        },
    }


def write_result(data_root: Path, output: Path) -> dict[str, Any]:
    result = evaluate_nasa_uas_acoustics(data_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True))
    return result
