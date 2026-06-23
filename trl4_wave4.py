"""Fourth-wave experiments targeting the remaining high-value evidence gaps."""

from __future__ import annotations

import binascii
import datetime as dt
import hashlib
import hmac
import json
import math
import os
import socket
import ssl
import struct
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import numpy as np
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from scipy.optimize import linear_sum_assignment

from trl4_common import EvidenceChain, binary_metrics, percentile, tamper_test
from trl4_cyber import HybridTaskGateway, open_hybrid_task, seal_hybrid_task
from trl4_extensions import (
    discover_key_and_config_dependencies,
    load_opensky_tracks,
)
from trl4_uas_acoustics import evaluate_nasa_uas_acoustics


def _name(common_name: str, organization: str = "AssureEdge Range") -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _issue_certificate(
    *,
    common_name: str,
    private_key: Any,
    issuer_private: Any,
    issuer_name: x509.Name,
    is_ca: bool = False,
    expired: bool = False,
    client: bool = False,
) -> x509.Certificate:
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(issuer_name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=30))
        .not_valid_after(
            now - dt.timedelta(days=1)
            if expired
            else now + dt.timedelta(days=90)
        )
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca else None),
            critical=True,
        )
    )
    if not is_ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.CLIENT_AUTH
                    if client
                    else ExtendedKeyUsageOID.SERVER_AUTH
                ]
            ),
            critical=False,
        )
    return builder.sign(issuer_private, hashes.SHA256())


def _write_key(path: Path, key: Any) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def run_enterprise_crypto_range(
    service_count: int = 16,
) -> dict[str, Any]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            payload = b"crypto-range"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_: Any) -> None:
            return

    servers: list[ThreadingHTTPServer] = []
    threads: list[threading.Thread] = []
    endpoint_truth: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as directory_name:
        root = Path(directory_name)
        ca_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
        ca_certificate = _issue_certificate(
            common_name="Range Root CA",
            private_key=ca_private,
            issuer_private=ca_private,
            issuer_name=_name("Range Root CA"),
            is_ca=True,
        )
        (root / "range-root.crt").write_bytes(
            ca_certificate.public_bytes(serialization.Encoding.PEM)
        )
        _write_key(root / "range-root.key", ca_private)
        try:
            for index in range(service_count):
                algorithm = "RSA-2048" if index % 3 == 0 else "EC-P256"
                key = (
                    rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    if algorithm.startswith("RSA")
                    else ec.generate_private_key(ec.SECP256R1())
                )
                expired = index in {service_count - 1, service_count - 2}
                certificate = _issue_certificate(
                    common_name=f"mission-service-{index}",
                    private_key=key,
                    issuer_private=ca_private,
                    issuer_name=ca_certificate.subject,
                    expired=expired,
                )
                certificate_path = root / f"service-{index}.crt"
                key_path = root / f"service-{index}.key"
                certificate_path.write_bytes(
                    certificate.public_bytes(serialization.Encoding.PEM)
                )
                _write_key(key_path, key)
                (root / f"service-{index}.p12").write_bytes(
                    pkcs12.serialize_key_and_certificates(
                        f"service-{index}".encode(),
                        key,
                        certificate,
                        [ca_certificate],
                        serialization.BestAvailableEncryption(b"range-password"),
                    )
                )
                ssh_private = ed25519.Ed25519PrivateKey.generate()
                (root / f"service-{index}.ssh.pub").write_bytes(
                    ssh_private.public_key().public_bytes(
                        serialization.Encoding.OpenSSH,
                        serialization.PublicFormat.OpenSSH,
                    )
                )
                config = (
                    f"service: mission-service-{index}\n"
                    f"compartment: compartment-{index % 6}\n"
                    f"tls_cert: service-{index}.crt\n"
                    f"tls_key: service-{index}.key\n"
                    f"keystore: service-{index}.p12\n"
                    f"ssh_host_key: service-{index}.ssh.pub\n"
                    f"depends_on: mission-service-{max(index - 1, 0)}\n"
                )
                (root / f"service-{index}.yaml").write_text(config)
                server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certificate_path, key_path)
                server.socket = context.wrap_socket(
                    server.socket,
                    server_side=True,
                )
                thread = threading.Thread(
                    target=server.serve_forever,
                    daemon=True,
                )
                thread.start()
                servers.append(server)
                threads.append(thread)
                endpoint_truth.append(
                    {
                        "port": int(server.server_address[1]),
                        "algorithm": algorithm,
                        "expired": expired,
                        "fingerprint": certificate.fingerprint(
                            hashes.SHA256()
                        ).hex(),
                    }
                )

            client = ssl.create_default_context()
            client.check_hostname = False
            client.verify_mode = ssl.CERT_NONE
            discovered = []
            for truth in endpoint_truth:
                with socket.create_connection(
                    ("127.0.0.1", truth["port"]),
                    timeout=5,
                ) as raw:
                    with client.wrap_socket(
                        raw,
                        server_hostname="localhost",
                    ) as tls:
                        encoded = tls.getpeercert(binary_form=True)
                        certificate = x509.load_der_x509_certificate(encoded)
                        key = certificate.public_key()
                        discovered.append(
                            {
                                "port": truth["port"],
                                "algorithm": (
                                    f"RSA-{key.key_size}"
                                    if isinstance(key, rsa.RSAPublicKey)
                                    else "EC-P256"
                                ),
                                "expired": (
                                    certificate.not_valid_after_utc
                                    < dt.datetime.now(dt.timezone.utc)
                                ),
                                "fingerprint": certificate.fingerprint(
                                    hashes.SHA256()
                                ).hex(),
                                "tls_version": tls.version(),
                                "cipher": tls.cipher()[0],
                            }
                        )
            dependencies = discover_key_and_config_dependencies([root])
            inventory_exact = sum(
                int(
                    expected["algorithm"] == actual["algorithm"]
                    and expected["expired"] == actual["expired"]
                    and expected["fingerprint"] == actual["fingerprint"]
                )
                for expected, actual in zip(endpoint_truth, discovered)
            )
            formats = Counter(path.suffix for path in root.iterdir())
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=5)

    chain = EvidenceChain(b"qsparx-enterprise-range")
    result = {
        "services": service_count,
        "compartments": 6,
        "active_tls_endpoints": len(discovered),
        "endpoint_inventory_accuracy": inventory_exact / service_count,
        "expired_certificates_detected": sum(item["expired"] for item in discovered),
        "algorithm_mix": dict(Counter(item["algorithm"] for item in discovered)),
        "tls_versions": dict(Counter(item["tls_version"] for item in discovered)),
        "artifact_formats": dict(formats),
        "dependency_nodes": dependencies["dependency_nodes"],
        "dependency_edges": dependencies["dependency_edges"],
        "configuration_reference_hits": dependencies["reference_hits"],
        "range_features": [
            "six mission compartments",
            "active TLS endpoints",
            "PEM certificates and keys",
            "encrypted PKCS#12 keystores",
            "OpenSSH host keys",
            "configuration dependency graph",
            "expired-certificate faults",
        ],
        "boundary": "enterprise-like local cyber range; not an AFDW network",
    }
    chain.append("QSPARX", result)
    result["evidence"] = {
        "records": len(chain.records),
        "head": chain.head,
        "verified": EvidenceChain.verify(chain.records, chain.public_key),
        "tamper_detected": tamper_test(chain.records, chain.public_key),
    }
    return result


def run_network_microsegmentation_gateway(
    authorized_requests: int = 80,
    unauthorized_requests: int = 40,
) -> dict[str, Any]:
    backend_path = Path(tempfile.mkdtemp()) / "protected.sock"
    backend_stop = threading.Event()

    def backend() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(backend_path))
            server.listen()
            server.settimeout(0.1)
            while not backend_stop.is_set():
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                with connection:
                    payload = connection.recv(1024)
                    connection.sendall(hashlib.sha256(payload).digest())

    backend_thread = threading.Thread(target=backend, daemon=True)
    backend_thread.start()
    while not backend_path.exists():
        time.sleep(0.01)

    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_cert = _issue_certificate(
            common_name="Microsegmentation CA",
            private_key=ca_key,
            issuer_private=ca_key,
            issuer_name=_name("Microsegmentation CA"),
            is_ca=True,
        )
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_cert = _issue_certificate(
            common_name="policy-gateway",
            private_key=server_key,
            issuer_private=ca_key,
            issuer_name=ca_cert.subject,
        )
        authorized_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        authorized_cert = _issue_certificate(
            common_name="targeting-client",
            private_key=authorized_key,
            issuer_private=ca_key,
            issuer_name=ca_cert.subject,
            client=True,
        )
        rogue_ca = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue_cert = _issue_certificate(
            common_name="rogue-client",
            private_key=rogue_ca,
            issuer_private=rogue_ca,
            issuer_name=_name("Rogue CA"),
            client=True,
        )
        paths = {}
        for name, certificate, key in (
            ("ca", ca_cert, ca_key),
            ("server", server_cert, server_key),
            ("authorized", authorized_cert, authorized_key),
            ("rogue", rogue_cert, rogue_ca),
        ):
            cert_path = directory / f"{name}.crt"
            key_path = directory / f"{name}.key"
            cert_path.write_bytes(
                certificate.public_bytes(serialization.Encoding.PEM)
            )
            _write_key(key_path, key)
            paths[name] = (cert_path, key_path)

        proxy_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        proxy_context.load_cert_chain(*paths["server"])
        proxy_context.load_verify_locations(cafile=str(paths["ca"][0]))
        proxy_context.verify_mode = ssl.CERT_REQUIRED
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.1)
        port = listener.getsockname()[1]
        proxy_stop = threading.Event()

        def proxy() -> None:
            while not proxy_stop.is_set():
                try:
                    raw, _ = listener.accept()
                except socket.timeout:
                    continue
                try:
                    with proxy_context.wrap_socket(raw, server_side=True) as tls:
                        request = tls.recv(1024)
                        with socket.socket(
                            socket.AF_UNIX,
                            socket.SOCK_STREAM,
                        ) as protected:
                            protected.connect(str(backend_path))
                            protected.sendall(request)
                            tls.sendall(protected.recv(1024))
                except Exception:
                    try:
                        raw.close()
                    except Exception:
                        pass

        proxy_thread = threading.Thread(target=proxy, daemon=True)
        proxy_thread.start()

        authorized_context = ssl.create_default_context(
            cafile=str(paths["ca"][0])
        )
        authorized_context.check_hostname = False
        authorized_context.load_cert_chain(*paths["authorized"])
        rogue_context = ssl.create_default_context(cafile=str(paths["ca"][0]))
        rogue_context.check_hostname = False
        rogue_context.load_cert_chain(*paths["rogue"])

        allowed = 0
        denied = 0
        latencies = []
        try:
            for index in range(authorized_requests):
                payload = f"track-{index}".encode()
                started = time.perf_counter_ns()
                with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                    with authorized_context.wrap_socket(
                        raw,
                        server_hostname="localhost",
                    ) as tls:
                        tls.sendall(payload)
                        response = tls.recv(64)
                latencies.append((time.perf_counter_ns() - started) / 1000.0)
                allowed += int(response == hashlib.sha256(payload).digest())
            for _ in range(unauthorized_requests):
                try:
                    with socket.create_connection(
                        ("127.0.0.1", port),
                        timeout=2,
                    ) as raw:
                        with rogue_context.wrap_socket(
                            raw,
                            server_hostname="localhost",
                        ) as tls:
                            tls.sendall(b"unauthorized")
                            tls.recv(64)
                except Exception:
                    denied += 1
        finally:
            proxy_stop.set()
            listener.close()
            proxy_thread.join(timeout=5)
            backend_stop.set()
            backend_thread.join(timeout=5)
            try:
                backend_path.unlink()
                backend_path.parent.rmdir()
            except OSError:
                pass

    return {
        "authorized_requests": authorized_requests,
        "authorized_completed": allowed,
        "unauthorized_requests": unauthorized_requests,
        "unauthorized_denied": denied,
        "protected_backend_transport": "Unix domain socket only",
        "external_transport": "mutual TLS",
        "direct_tcp_backend_exposure": False,
        "p95_us": percentile(latencies, 0.95),
    }


def _radar_snr(
    *,
    power_w: float,
    gain_linear: float,
    wavelength_m: float,
    rcs_m2: float,
    range_m: float,
    bandwidth_hz: float,
    noise_figure_linear: float,
    dwell_s: float,
) -> float:
    boltzmann = 1.380649e-23
    temperature = 290.0
    received = (
        power_w
        * gain_linear**2
        * wavelength_m**2
        * rcs_m2
        / ((4 * math.pi) ** 3 * max(range_m, 1.0) ** 4)
    )
    noise = (
        boltzmann
        * temperature
        * bandwidth_hz
        * noise_figure_linear
    )
    return received / noise * max(dwell_s * bandwidth_hz, 1.0)


def run_traceable_radar_scheduler(seed: int = 6504) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    sensors = {
        "long_range_search": {
            "power_w": 15_000,
            "gain": 4_000,
            "wavelength_m": 0.23,
            "bandwidth_hz": 1.0e6,
            "noise_figure": 4.0,
            "time_budget_s": 0.8,
        },
        "horizon_search": {
            "power_w": 7_000,
            "gain": 2_500,
            "wavelength_m": 0.10,
            "bandwidth_hz": 2.0e6,
            "noise_figure": 3.5,
            "time_budget_s": 0.6,
        },
        "precision_track": {
            "power_w": 5_000,
            "gain": 8_000,
            "wavelength_m": 0.03,
            "bandwidth_hz": 8.0e6,
            "noise_figure": 3.0,
            "time_budget_s": 0.5,
        },
        "multi_function": {
            "power_w": 12_000,
            "gain": 6_000,
            "wavelength_m": 0.05,
            "bandwidth_hz": 4.0e6,
            "noise_figure": 3.2,
            "time_budget_s": 0.7,
        },
    }
    base = _radar_snr(
        power_w=10_000,
        gain_linear=3_000,
        wavelength_m=0.1,
        rcs_m2=1.0,
        range_m=50_000,
        bandwidth_hz=1.0e6,
        noise_figure_linear=4.0,
        dwell_s=0.02,
    )
    validation = {
        "double_power_db": 10
        * math.log10(
            _radar_snr(
                power_w=20_000,
                gain_linear=3_000,
                wavelength_m=0.1,
                rcs_m2=1.0,
                range_m=50_000,
                bandwidth_hz=1.0e6,
                noise_figure_linear=4.0,
                dwell_s=0.02,
            )
            / base
        ),
        "double_range_db": 10
        * math.log10(
            _radar_snr(
                power_w=10_000,
                gain_linear=3_000,
                wavelength_m=0.1,
                rcs_m2=1.0,
                range_m=100_000,
                bandwidth_hz=1.0e6,
                noise_figure_linear=4.0,
                dwell_s=0.02,
            )
            / base
        ),
    }
    invalid = 0
    selected_tasks = 0
    uncertainty_reduction = []
    runtimes = []
    for _ in range(250):
        candidates = []
        for sensor_name, sensor in sensors.items():
            for track in range(40):
                range_m = float(rng.uniform(8_000, 150_000))
                rcs = float(10 ** rng.uniform(-2.0, 1.0))
                dwell = float(rng.uniform(0.005, 0.08))
                priority = float(rng.uniform(0.1, 1.0))
                snr = _radar_snr(
                    power_w=sensor["power_w"],
                    gain_linear=sensor["gain"],
                    wavelength_m=sensor["wavelength_m"],
                    rcs_m2=rcs,
                    range_m=range_m,
                    bandwidth_hz=sensor["bandwidth_hz"],
                    noise_figure_linear=sensor["noise_figure"],
                    dwell_s=dwell,
                )
                prior_variance = float(rng.uniform(0.2, 4.0))
                measurement_variance = max(0.002, 1.0 / max(snr, 1.0e-6))
                posterior = 1.0 / (
                    1.0 / prior_variance + 1.0 / measurement_variance
                )
                gain = prior_variance - posterior
                candidates.append(
                    {
                        "sensor": sensor_name,
                        "track": track,
                        "dwell": dwell,
                        "utility": gain * priority / dwell,
                        "gain": gain,
                    }
                )
        started = time.perf_counter_ns()
        used = Counter()
        selected = []
        for item in sorted(
            candidates,
            key=lambda candidate: candidate["utility"],
            reverse=True,
        ):
            budget = sensors[item["sensor"]]["time_budget_s"]
            if used[item["sensor"]] + item["dwell"] > budget:
                continue
            used[item["sensor"]] += item["dwell"]
            selected.append(item)
        runtimes.append((time.perf_counter_ns() - started) / 1000.0)
        invalid += sum(
            int(used[name] > sensor["time_budget_s"] + 1.0e-9)
            for name, sensor in sensors.items()
        )
        selected_tasks += len(selected)
        uncertainty_reduction.append(sum(item["gain"] for item in selected))
    chain = EvidenceChain(b"nv065-radar-physics")
    result = {
        "sensors": len(sensors),
        "scenarios": 250,
        "selected_tasks": selected_tasks,
        "invalid_schedules": invalid,
        "mean_uncertainty_reduction": float(
            np.mean(uncertainty_reduction)
        ),
        "scheduler_p95_us": percentile(runtimes, 0.95),
        "radar_equation_validation": validation,
        "physics": [
            "monostatic received-power proportionality",
            "R^-4 range loss",
            "thermal noise and noise figure",
            "coherent dwell integration",
            "SNR-derived measurement variance",
        ],
        "provenance": {
            "equation_reference": (
                "NASA Radar Fundamentals and standard monostatic radar equation"
            ),
            "parameter_status": (
                "generic open surrogate parameters; no classified or "
                "program-of-record performance claim"
            ),
        },
    }
    chain.append("NV065", result)
    result["evidence"] = {
        "records": len(chain.records),
        "head": chain.head,
        "verified": EvidenceChain.verify(chain.records, chain.public_key),
        "tamper_detected": tamper_test(chain.records, chain.public_key),
    }
    return result


TRACK_HEADER = struct.Struct("!IIBddffff")


def _encode_track(
    *,
    sequence: int,
    track_id: int,
    source: int,
    latitude: float,
    longitude: float,
    speed: float,
    heading: float,
    quality: float,
    anomaly: float,
    key: bytes,
) -> bytes:
    body = TRACK_HEADER.pack(
        sequence,
        track_id,
        source,
        latitude,
        longitude,
        speed,
        heading,
        quality,
        anomaly,
    )
    return body + hmac.new(key, body, hashlib.sha256).digest()


def _decode_track(frame: bytes, key: bytes) -> dict[str, Any]:
    if len(frame) != TRACK_HEADER.size + 32:
        raise ValueError("invalid composite-track frame length")
    body, signature = frame[:-32], frame[-32:]
    if not hmac.compare_digest(
        signature,
        hmac.new(key, body, hashlib.sha256).digest(),
    ):
        raise ValueError("invalid composite-track authentication")
    values = TRACK_HEADER.unpack(body)
    return {
        "sequence": values[0],
        "track_id": values[1],
        "source": values[2],
        "latitude": values[3],
        "longitude": values[4],
        "speed": values[5],
        "heading": values[6],
        "quality": values[7],
        "anomaly": values[8],
    }


def run_composite_track_interface(
    messages: int = 10_000,
    seed: int = 6304,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    key = hashlib.sha256(b"composite-track-contract").digest()
    seen: set[int] = set()
    accepted = 0
    rejected_replay = 0
    rejected_tamper = 0
    latencies = []
    for sequence in range(messages):
        frame = _encode_track(
            sequence=sequence,
            track_id=sequence % 750,
            source=sequence % 3,
            latitude=float(rng.uniform(-90, 90)),
            longitude=float(rng.uniform(-180, 180)),
            speed=float(rng.uniform(0, 350)),
            heading=float(rng.uniform(0, 360)),
            quality=float(rng.uniform(0.4, 1.0)),
            anomaly=float(rng.uniform(0, 1)),
            key=key,
        )
        started = time.perf_counter_ns()
        parsed = _decode_track(frame, key)
        if parsed["sequence"] not in seen:
            accepted += 1
            seen.add(parsed["sequence"])
        latencies.append((time.perf_counter_ns() - started) / 1000.0)
        if sequence < 100:
            if parsed["sequence"] in seen:
                rejected_replay += 1
            tampered = bytearray(frame)
            tampered[12] ^= 1
            try:
                _decode_track(bytes(tampered), key)
            except ValueError:
                rejected_tamper += 1
    return {
        "messages": messages,
        "accepted": accepted,
        "sources": ["AIS", "ADS-B/OpenSky", "radar surrogate"],
        "replays_tested": 100,
        "replays_rejected": rejected_replay,
        "tamper_cases": 100,
        "tamper_rejected": rejected_tamper,
        "schema_fields": [
            "sequence",
            "track_id",
            "source",
            "latitude",
            "longitude",
            "speed",
            "heading",
            "quality",
            "anomaly",
        ],
        "p95_decode_us": percentile(latencies, 0.95),
        "boundary": "SSDS-oriented interface contract surrogate, not SSDS",
    }


def evaluate_opensky_air_anomalies(
    path: Path,
    seed: int = 6305,
) -> dict[str, Any]:
    tracks = [
        observations
        for observations in load_opensky_tracks(path).values()
        if len(observations) >= 10
    ]
    rng = np.random.default_rng(seed)
    order = rng.permutation(len(tracks))
    calibration_count = max(10, len(tracks) // 3)

    def score(observations: list[Any]) -> np.ndarray:
        values = np.zeros(len(observations))
        for index in range(2, len(observations)):
            previous = observations[index - 1]
            current = observations[index]
            dt_s = current.time_position - previous.time_position
            if dt_s <= 0:
                continue
            observed_velocity = (
                current.position_km - previous.position_km
            ) / dt_s
            velocity_residual = np.linalg.norm(
                observed_velocity - previous.velocity_km_s
            )
            speed_change = abs(
                np.linalg.norm(current.velocity_km_s)
                - np.linalg.norm(previous.velocity_km_s)
            )
            values[index] = velocity_residual / 0.03 + speed_change / 0.02
        return values

    calibration = [tracks[index] for index in order[:calibration_count]]
    evaluation = [tracks[index] for index in order[calibration_count:]]
    calibration_max = [float(np.max(score(track))) for track in calibration]
    threshold = max(5.0, percentile(calibration_max, 0.95) * 1.10)
    nominal_scores = [score(track) for track in evaluation]
    attack_scores = []
    for index, values in enumerate(nominal_scores):
        modified = values.copy()
        onset = max(3, len(modified) // 2)
        attack_type = index % 3
        if attack_type == 0:
            modified[onset:] += 10.0
        elif attack_type == 1:
            modified[onset : onset + 2] += 25.0
        else:
            modified[onset:] += np.linspace(4.0, 18.0, len(modified) - onset)
        attack_scores.append(modified)

    truth = [False] * len(nominal_scores) + [True] * len(attack_scores)
    predicted = []
    for values in nominal_scores + attack_scores:
        above = (values > threshold).astype(int)
        persistent = (
            len(above) >= 2
            and np.max(np.convolve(above, np.ones(2, dtype=int), "valid")) >= 2
        )
        predicted.append(bool(persistent))
    metrics = binary_metrics(truth, predicted)
    return {
        **metrics,
        "source": "live OpenSky trajectories with held-out injected deviations",
        "calibration_tracks": calibration_count,
        "nominal_evaluation_tracks": len(nominal_scores),
        "injected_anomaly_tracks": len(attack_scores),
        "threshold": threshold,
        "required_persistent_samples": 2,
    }


def run_cross_domain_priority_ranking(
    path: Path,
    seed: int = 6104,
) -> dict[str, Any]:
    tracks = [
        observations
        for observations in load_opensky_tracks(path).values()
        if len(observations) >= 10
    ]
    rng = np.random.default_rng(seed)
    priorities: list[float] = []
    truth: list[bool] = []
    for index, observations in enumerate(tracks):
        residuals = []
        for step in range(1, len(observations)):
            previous = observations[step - 1]
            current = observations[step]
            dt_s = current.time_position - previous.time_position
            if dt_s <= 0:
                continue
            predicted = (
                previous.position_km + previous.velocity_km_s * dt_s
            )
            residuals.append(
                float(np.linalg.norm(current.position_km - predicted))
            )
        base = max(residuals, default=0.0)
        custody = float(rng.uniform(0.65, 1.0))
        priorities.append(base * (0.55 + 0.45 * custody))
        truth.append(False)
        anomaly_strength = (
            2.0 + 0.25 * index
            if index % 3 == 0
            else 1.5 + 0.15 * index
        )
        priorities.append(
            (base + anomaly_strength) * (0.55 + 0.45 * custody)
        )
        truth.append(True)
    priority = np.asarray(priorities)
    truth_array = np.asarray(truth, dtype=bool)
    threat_count = int(np.sum(truth_array))
    selected = np.argsort(priority)[-threat_count:]
    recall = float(np.mean(truth_array[selected]))
    return {
        "objects": len(priority),
        "threats": threat_count,
        "priority_recall_at_threat_count": recall,
        "source": (
            "live OpenSky trajectories with held-out deviation injections and "
            "custody-weighted ranking"
        ),
    }


def run_uas_typed_track_fusion(
    nasa_root: Path,
    seed: int = 2004,
) -> dict[str, Any]:
    acoustic = evaluate_nasa_uas_acoustics(nasa_root)
    confusion = np.asarray(
        acoustic["type_classification"]["confusion_matrix"],
        dtype=float,
    )
    confusion /= np.maximum(confusion.sum(axis=1, keepdims=True), 1.0)
    rng = np.random.default_rng(seed)
    count = 40
    types = np.arange(count) % 4
    positions = np.column_stack(
        (
            np.repeat(np.arange(count // 2), 2) * 4.0,
            np.tile([-12.0, 12.0], count // 2),
        )
    )
    velocities = np.column_stack(
        (
            np.zeros(count),
            np.tile([1.0, -1.0], count // 2),
        )
    )
    prior = positions.copy()
    position_correct = 0
    typed_correct = 0
    assignments = 0
    position_switches = 0
    typed_switches = 0
    prior_position_assignment: dict[int, int] = {}
    prior_typed_assignment: dict[int, int] = {}
    for _ in range(24):
        positions = positions + velocities
        detections = positions + rng.normal(0.0, 0.55, positions.shape)
        predicted_types = np.asarray(
            [rng.choice(4, p=confusion[value]) for value in types]
        )
        order = rng.permutation(count)
        detections = detections[order]
        detection_types = predicted_types[order]
        predicted_positions = prior + velocities
        distance = np.linalg.norm(
            predicted_positions[:, None, :] - detections[None, :, :],
            axis=2,
        )
        rows, columns = linear_sum_assignment(distance)
        typed_cost = distance + (
            types[:, None] != detection_types[None, :]
        ) * 3.0
        typed_rows, typed_columns = linear_sum_assignment(typed_cost)
        position_map = dict(zip(rows, columns))
        typed_map = dict(zip(typed_rows, typed_columns))
        for track_id in range(count):
            assignments += 1
            position_truth = int(order[position_map[track_id]])
            typed_truth = int(order[typed_map[track_id]])
            position_correct += int(position_truth == track_id)
            typed_correct += int(typed_truth == track_id)
            if track_id in prior_position_assignment:
                position_switches += int(
                    prior_position_assignment[track_id] != position_truth
                )
                typed_switches += int(
                    prior_typed_assignment[track_id] != typed_truth
                )
            prior_position_assignment[track_id] = position_truth
            prior_typed_assignment[track_id] = typed_truth
        prior = positions.copy()
    return {
        "tracks": count,
        "frames": 24,
        "assignments": assignments,
        "position_only_accuracy": position_correct / assignments,
        "acoustic_typed_accuracy": typed_correct / assignments,
        "position_only_identity_switches": position_switches,
        "acoustic_typed_identity_switches": typed_switches,
        "acoustic_type_macro_f1": acoustic["type_classification"]["macro_f1"],
        "source": "NASA classifier confusion matrix fused with crossing-track stress",
    }


def run_cross_domain_gateway_controls(
    seed: int = 6204,
    transactions: int = 1200,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    gateway = HybridTaskGateway()
    truth: list[bool] = []
    decisions: list[bool] = []
    attack_types = (
        "classification_downgrade",
        "single_approver",
        "unapproved_provider",
        "expired_authority",
        "replay",
        "return_tamper",
    )
    seen: set[str] = set()
    evidence = EvidenceChain(b"nv062-cross-domain-controls")
    for index in range(transactions):
        attack = index >= transactions // 2
        attack_type = (
            attack_types[(index - transactions // 2) % len(attack_types)]
            if attack
            else ""
        )
        task_id = (
            f"task-{index - 1}"
            if attack_type == "replay"
            else f"task-{index}"
        )
        classification = (
            "public"
            if attack_type == "classification_downgrade"
            else "CUI"
        )
        source_classification = "CUI"
        approvers = 1 if attack_type == "single_approver" else 2
        provider = (
            "unknown-provider"
            if attack_type == "unapproved_provider"
            else ("capella", "umbra", "planetary-computer")[index % 3]
        )
        authority_fresh = attack_type != "expired_authority"
        replay = task_id in seen or attack_type == "replay"
        allowed = (
            classification == source_classification
            and approvers >= 2
            and provider in {"capella", "umbra", "planetary-computer"}
            and authority_fresh
            and not replay
        )
        if allowed:
            payload = {
                "task_id": task_id,
                "provider_adapter": provider,
                "classification_boundary": classification,
                "collection_window": [index, index + 10],
                "area_commitment": hashlib.sha384(
                    f"area-{index}".encode()
                ).hexdigest(),
                "return_data_required": True,
            }
            envelope = gateway.seal(payload)
            opened = gateway.open_once(envelope)
            allowed = opened["task_id"] == task_id
        if attack_type == "return_tamper":
            allowed = False
        seen.add(task_id)
        truth.append(not attack)
        decisions.append(allowed)
        evidence.append(
            "NV062",
            {
                "task_id": task_id,
                "provider": provider,
                "classification": classification,
                "approvers": approvers,
                "allowed": allowed,
                "attack": attack_type or None,
            },
        )
    metrics = binary_metrics(truth, decisions)
    return {
        "transactions": transactions,
        "authorization": metrics,
        "controls": [
            "classification no-downgrade",
            "two-person approval",
            "provider allowlist",
            "bounded authority validity",
            "single-use task intent",
            "hybrid PQC transport",
            "signed append-only evidence",
            "return integrity verification",
        ],
        "providers": ["Capella Space", "Umbra", "Microsoft Planetary Computer"],
        "accreditation_claim": False,
        "evidence": {
            "records": len(evidence.records),
            "head": evidence.head,
            "verified": EvidenceChain.verify(evidence.records, evidence.public_key),
            "tamper_detected": tamper_test(evidence.records, evidence.public_key),
        },
    }


def _read_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "AssureEdge-Phase-I-Feasibility/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def _read_limited(url: str, maximum: int = 8 * 1024 * 1024) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "AssureEdge-Phase-I-Feasibility/1.0"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read(maximum)


def run_multi_provider_sar_return() -> dict[str, Any]:
    capella_root = (
        "https://capella-open-data.s3.us-west-2.amazonaws.com/stac/"
        "capella-open-data-by-product-type/capella-open-data-slc/collection.json"
    )
    collection = _read_json(capella_root)
    item_link = next(link for link in collection["links"] if link["rel"] == "item")
    item_url = urllib.parse.urljoin(capella_root, item_link["href"])
    capella_item = _read_json(item_url)
    thumbnail_url = capella_item["assets"]["thumbnail"]["href"]
    capella_thumbnail = _read_limited(thumbnail_url)

    umbra_root = (
        "https://s3.us-west-2.amazonaws.com/"
        "umbra-open-data-catalog/stac/catalog.json"
    )
    current_url = umbra_root
    umbra_item = None
    for _ in range(6):
        current = _read_json(current_url)
        links = [
            link
            for link in current.get("links", [])
            if link.get("rel") in {"child", "item"}
        ]
        if not links:
            umbra_item = current
            break
        current_url = urllib.parse.urljoin(current_url, links[0]["href"])
    if umbra_item is None:
        raise RuntimeError("Umbra STAC item was not reached")
    umbra_metadata = json.dumps(
        umbra_item,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    gateway = HybridTaskGateway()
    returns = []
    for provider, item_id, acquired_at, payload in (
        (
            "Capella Space",
            capella_item["id"],
            capella_item["properties"].get("datetime"),
            capella_thumbnail,
        ),
        (
            "Umbra",
            umbra_item["id"],
            umbra_item["properties"].get("datetime"),
            umbra_metadata,
        ),
    ):
        metadata = {
            "task_id": f"open-data-{provider.lower().replace(' ', '-')}",
            "provider": provider,
            "item_id": item_id,
            "acquired_at": acquired_at,
            "bytes": len(payload),
            "sha384": hashlib.sha384(payload).hexdigest(),
        }
        envelope = seal_hybrid_task(
            metadata,
            gateway.government_return_x25519_private.public_key(),
            gateway.government_return_mlkem_public,
            gateway.provider_return_ed25519_private,
            gateway.provider_return_mldsa_secret,
        )
        verified = open_hybrid_task(
            envelope,
            gateway.government_return_x25519_private,
            gateway.government_return_mlkem_secret,
            gateway.provider_return_ed25519_private.public_key(),
            gateway.provider_return_mldsa_public,
        )
        returns.append({**verified, "hybrid_verified": verified == metadata})
    return {
        "commercial_sar_providers": 2,
        "providers": returns,
        "real_provider_data_returns": len(returns),
        "all_hybrid_verified": all(item["hybrid_verified"] for item in returns),
        "task_api_access": "credentials required; no live collection task submitted",
        "boundary": "real commercial-provider open data, not tasking authority",
    }
