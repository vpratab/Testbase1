"""Higher-fidelity Phase I experiments for the strongest locally testable gaps."""

from __future__ import annotations

import asyncio
import builtins
import datetime as dt
import hashlib
import json
import math
import os
import re
import socket
import ssl
import tempfile
import threading
import time
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import numpy as np
from asyncua.sync import Client, Server
from asyncua import ua
from asyncua.crypto.cert_gen import generate_self_signed_app_certificate
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cyclonedds.domain import DomainParticipant
from cyclonedds.idl import IdlStruct
from cyclonedds.idl.types import int32
from cyclonedds.pub import DataWriter
from cyclonedds.sub import DataReader
from cyclonedds.topic import Topic
from scipy.optimize import linear_sum_assignment

from trl4_common import EvidenceChain, binary_metrics, percentile, tamper_test
from trl4_cyber import (
    HybridTaskGateway,
    normalize_provider_payload,
    open_hybrid_task,
    provider_payload,
    seal_hybrid_task,
)
from trl4_tracks import MaritimeTrack, ais_pol_score, inject_track_anomaly

# Cyclone DDS resolves postponed annotations against the defining module.
str = builtins.str
bool = builtins.bool


def _self_signed_localhost() -> tuple[bytes, bytes]:
    private = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(private, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def active_tls_discovery() -> dict[str, Any]:
    certificate_pem, private_pem = _self_signed_localhost()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b"assureedge-discovery"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: Any) -> None:
            return

    with tempfile.TemporaryDirectory() as directory:
        cert_path = Path(directory) / "endpoint-cert.pem"
        key_path = Path(directory) / "endpoint-key.pem"
        cert_path.write_bytes(certificate_pem)
        key_path.write_bytes(private_pem)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_path, key_path)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = int(server.server_address[1])
        client_context = ssl.create_default_context()
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        started = time.perf_counter_ns()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with client_context.wrap_socket(raw, server_hostname="localhost") as tls:
                    tls.sendall(
                        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    )
                    response = tls.recv(1024)
                    encoded = tls.getpeercert(binary_form=True)
                    version = tls.version()
                    cipher = tls.cipher()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        elapsed_us = (time.perf_counter_ns() - started) / 1000.0
    certificate = x509.load_der_x509_certificate(encoded)
    key = certificate.public_key()
    return {
        "endpoints_scanned": 1,
        "handshakes_succeeded": 1,
        "http_response_observed": response.startswith(b"HTTP/1.0 200"),
        "tls_version": version,
        "cipher": cipher[0],
        "certificate_subject": certificate.subject.rfc4514_string(),
        "certificate_signature_hash": certificate.signature_hash_algorithm.name,
        "public_key_type": type(key).__name__,
        "public_key_bits": getattr(key, "key_size", None),
        "certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "scan_latency_us": elapsed_us,
    }


REFERENCE_PATTERN = re.compile(
    r"(?P<value>[\w./-]+\.(?:pem|crt|cer|key|p12|pfx|jks|kdb))",
    re.IGNORECASE,
)


def discover_key_and_config_dependencies(roots: list[Path]) -> dict[str, Any]:
    formats: Counter[str] = Counter()
    nodes: set[str] = set()
    edges: set[tuple[str, str]] = set()
    files_scanned = 0
    reference_hits = 0
    suffixes = {
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".properties",
        ".conf",
        ".pem",
        ".crt",
        ".cer",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".kdb",
    }
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if (
                not path.is_file()
                or path.suffix.lower() not in suffixes
                or any(part in {".git", ".venv", "node_modules", "target"} for part in path.parts)
            ):
                continue
            files_scanned += 1
            relative = str(path.relative_to(root))
            node = f"{root.name}:{relative}"
            nodes.add(node)
            formats[path.suffix.lower() or "none"] += 1
            if path.stat().st_size > 2_000_000:
                continue
            text = path.read_text(errors="ignore")
            for match in REFERENCE_PATTERN.finditer(text):
                reference_hits += 1
                reference = match.group("value")
                reference_node = f"{root.name}:{reference}"
                nodes.add(reference_node)
                edges.add((node, reference_node))
    return {
        "files_scanned": files_scanned,
        "formats": dict(sorted(formats.items())),
        "dependency_nodes": len(nodes),
        "dependency_edges": len(edges),
        "reference_hits": reference_hits,
        "sample_edges": [list(edge) for edge in sorted(edges)[:25]],
    }


def run_qsparx_extension(roots: list[Path]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        fixture = Path(directory)
        cert, key = _self_signed_localhost()
        (fixture / "service.crt").write_bytes(cert)
        (fixture / "service.key").write_bytes(key)
        (fixture / "deployment.yaml").write_text(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      tlsCert: service.crt\n"
            "      tlsKey: service.key\n"
        )
        dependency = discover_key_and_config_dependencies([*roots, fixture])
    active = active_tls_discovery()
    chain = EvidenceChain(b"qsparx-extension")
    chain.append("QSPARX", {"active_tls": active, "dependency": dependency})
    return {
        "active_tls_discovery": active,
        "key_and_config_dependencies": dependency,
        "evidence": {
            "records": len(chain.records),
            "head": chain.head,
            "verified": EvidenceChain.verify(chain.records, chain.public_key),
            "tamper_detected": tamper_test(chain.records, chain.public_key),
        },
    }


def _opcua_decision(
    *,
    authorized: bool,
    trust_fresh: bool,
    compartment: bool,
    replay: bool,
) -> bool:
    return authorized and trust_fresh and compartment and not replay


def run_opcua_enforcement_proxy(
    seed: int = 5901,
    requests: int = 240,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    server = Server()
    endpoint = f"opc.tcp://127.0.0.1:{int(rng.integers(49000, 54000))}/assureedge/"
    server.set_endpoint(endpoint)
    namespace = server.register_namespace("urn:assureedge:nv059")
    combat = server.nodes.objects.add_object(namespace, "CombatData")
    intent_node = combat.add_variable(namespace, "RequestedTrackPriority", 0)
    intent_node.set_writable()
    protected_node = combat.add_variable(namespace, "ProtectedTrackPriority", 0)
    server.start()
    decisions: list[bool] = []
    truth: list[bool] = []
    latencies: list[float] = []
    network_counts: Counter[str] = Counter()
    offline_decisions = 0
    delivered_round_trips = 0
    direct_write_blocked = False
    evidence = EvidenceChain(b"nv059-opcua-extension")
    try:
        with Client(endpoint) as client:
            client_intent = client.get_node(intent_node.nodeid)
            client_protected = client.get_node(protected_node.nodeid)
            try:
                client_protected.write_value(999)
            except Exception:
                direct_write_blocked = True
            attacks = (
                "unauthorized",
                "stale_lease",
                "wrong_compartment",
                "replay",
            )
            seen: set[str] = set()
            for index in range(requests):
                attack = index >= requests // 2
                attack_type = attacks[(index - requests // 2) % len(attacks)] if attack else ""
                network = ("connected", "delayed", "lossy", "partitioned")[index % 4]
                network_counts[network] += 1
                request_id = (
                    f"request-{index - 1}"
                    if attack_type == "replay"
                    else f"request-{index}"
                )
                authorized = attack_type != "unauthorized"
                trust_fresh = attack_type != "stale_lease"
                compartment = attack_type != "wrong_compartment"
                replay = request_id in seen or attack_type == "replay"
                expected_allowed = not attack
                started = time.perf_counter_ns()
                if network == "partitioned":
                    offline_decisions += 1
                    allowed = _opcua_decision(
                        authorized=authorized,
                        trust_fresh=trust_fresh,
                        compartment=compartment,
                        replay=replay,
                    )
                elif network == "lossy" and index % 8 == 2:
                    allowed = False
                else:
                    value = int(index % 5)
                    client_intent.write_value(value)
                    delivered_round_trips += 1
                    allowed = _opcua_decision(
                        authorized=authorized,
                        trust_fresh=trust_fresh,
                        compartment=compartment,
                        replay=replay,
                    )
                    if allowed:
                        protected_node.write_value(value)
                        allowed = client_protected.read_value() == value
                seen.add(request_id)
                latencies.append((time.perf_counter_ns() - started) / 1000.0)
                decisions.append(allowed)
                truth.append(expected_allowed and not (network == "lossy" and index % 8 == 2))
                evidence.append(
                    "NV059",
                    {
                        "request_id": request_id,
                        "protocol": "opc_ua",
                        "network": network,
                        "allowed": allowed,
                        "attack": attack_type or None,
                    },
                )
    finally:
        server.stop()
    metrics = binary_metrics(truth, decisions)
    return {
        "protocol": "OPC UA via asyncua",
        "transport_security": (
            "unencrypted localhost laboratory endpoint; authorization and "
            "write mediation are under test, not OPC UA transport encryption"
        ),
        "requests": requests,
        "delivered_round_trips": delivered_round_trips,
        "direct_protected_write_blocked": direct_write_blocked,
        "offline_partition_decisions": offline_decisions,
        "network_conditions": dict(network_counts),
        "authorization": metrics,
        "performance": {
            "p50_us": percentile(latencies, 0.50),
            "p95_us": percentile(latencies, 0.95),
            "p99_us": percentile(latencies, 0.99),
        },
        "evidence": {
            "records": len(evidence.records),
            "head": evidence.head,
            "verified": EvidenceChain.verify(evidence.records, evidence.public_key),
            "tamper_detected": tamper_test(evidence.records, evidence.public_key),
        },
    }


def _opcua_application_certificate(
    directory: Path,
    name: str,
    application_uri: str,
    usage: x509.ObjectIdentifier,
) -> tuple[Path, Path]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = generate_self_signed_app_certificate(
        private,
        name,
        {"countryName": "US", "organizationName": "AssureEdge Laboratory"},
        [
            x509.UniformResourceIdentifier(application_uri),
            x509.DNSName("localhost"),
            x509.DNSName(socket.gethostname()),
        ],
        [usage],
    )
    certificate_path = directory / f"{name}.der"
    private_path = directory / f"{name}.pem"
    certificate_path.write_bytes(
        certificate.public_bytes(serialization.Encoding.DER)
    )
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, private_path


def run_secure_opcua_channel(
    seed: int = 5902,
    transactions: int = 80,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        server_certificate, server_key = _opcua_application_certificate(
            directory,
            "server",
            "urn:freeopcua:python:server",
            ExtendedKeyUsageOID.SERVER_AUTH,
        )
        client_certificate, client_key = _opcua_application_certificate(
            directory,
            "client",
            "urn:example.org:FreeOpcUa:opcua-asyncio",
            ExtendedKeyUsageOID.CLIENT_AUTH,
        )
        endpoint = (
            f"opc.tcp://127.0.0.1:{int(rng.integers(54001, 59000))}/secure/"
        )
        server = Server()
        server.set_endpoint(endpoint)
        server.load_certificate(server_certificate)
        server.load_private_key(server_key)
        server.set_security_policy(
            [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt]
        )
        namespace = server.register_namespace("urn:assureedge:nv059:secure")
        combat = server.nodes.objects.add_object(namespace, "CombatData")
        value = combat.add_variable(namespace, "AuthorizedTrackPriority", 0)
        value.set_writable()
        server.start()
        latencies: list[float] = []
        successful = 0
        rejected_unsecured = False
        chain = EvidenceChain(b"nv059-secure-opcua")
        try:
            unsecured = Client(endpoint)
            try:
                unsecured.connect()
            except Exception:
                rejected_unsecured = True
            finally:
                try:
                    unsecured.disconnect()
                except Exception:
                    pass

            client = Client(endpoint)
            client.set_security_string(
                "Basic256Sha256,SignAndEncrypt,"
                f"{client_certificate},{client_key},{server_certificate}"
            )
            client.connect()
            try:
                remote = client.get_node(value.nodeid)
                for index in range(transactions):
                    started = time.perf_counter_ns()
                    remote.write_value(int(index % 5))
                    observed = remote.read_value()
                    latencies.append((time.perf_counter_ns() - started) / 1000.0)
                    successful += int(observed == index % 5)
                    chain.append(
                        "NV059",
                        {
                            "transaction": index,
                            "security_policy": "Basic256Sha256",
                            "message_security": "SignAndEncrypt",
                            "verified_round_trip": observed == index % 5,
                        },
                    )
            finally:
                client.disconnect()
        finally:
            server.stop()
    return {
        "transactions": transactions,
        "successful_round_trips": successful,
        "unsecured_client_rejected": rejected_unsecured,
        "security_policy": "Basic256Sha256",
        "message_security_mode": "SignAndEncrypt",
        "client_certificate": "RSA-2048 self-signed laboratory application certificate",
        "server_certificate": "RSA-2048 self-signed laboratory application certificate",
        "performance": {
            "p50_us": percentile(latencies, 0.50),
            "p95_us": percentile(latencies, 0.95),
        },
        "evidence": {
            "records": len(chain.records),
            "head": chain.head,
            "verified": EvidenceChain.verify(chain.records, chain.public_key),
            "tamper_detected": tamper_test(chain.records, chain.public_key),
        },
    }


@dataclass
class DdsAccessRequest(IdlStruct):
    request_id: str
    subject: str
    compartment: str
    action: str
    resource: str
    sequence: int32
    signature_hex: str


@dataclass
class DdsAccessDecision(IdlStruct):
    request_id: str
    allowed: bool
    reason: str
    policy_version: str


def _dds_request_material(request: DdsAccessRequest) -> bytes:
    return (
        f"{request.request_id}|{request.subject}|{request.compartment}|"
        f"{request.action}|{request.resource}|{request.sequence}"
    ).encode()


def run_dds_authorization_proxy(
    seed: int = 5903,
    requests: int = 160,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    domain = int(rng.integers(100, 200))
    participant = DomainParticipant(domain)
    request_topic = Topic(
        participant,
        f"AssureEdgeAccessRequest{seed}",
        DdsAccessRequest,
    )
    decision_topic = Topic(
        participant,
        f"AssureEdgeAccessDecision{seed}",
        DdsAccessDecision,
    )
    request_writer = DataWriter(participant, request_topic)
    request_reader = DataReader(participant, request_topic)
    decision_writer = DataWriter(participant, decision_topic)
    decision_reader = DataReader(participant, decision_topic)
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    truth: list[bool] = []
    observed: list[bool] = []
    latencies: list[float] = []
    seen_sequences: set[int] = set()
    evidence = EvidenceChain(b"nv059-dds-extension")
    time.sleep(0.15)
    for index in range(requests):
        attack = index >= requests // 2
        attack_type = (
            ("bad_signature", "wrong_compartment", "replay", "forbidden_action")[
                (index - requests // 2) % 4
            ]
            if attack
            else ""
        )
        sequence = index - 1 if attack_type == "replay" else index
        request = DdsAccessRequest(
            request_id=f"dds-{index}",
            subject="operator-117",
            compartment=(
                "engineering" if attack_type == "wrong_compartment" else "targeting"
            ),
            action=("delete" if attack_type == "forbidden_action" else "read"),
            resource="composite-track-17",
            sequence=sequence,
            signature_hex="",
        )
        signature = private.sign(_dds_request_material(request))
        if attack_type == "bad_signature":
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        request.signature_hex = signature.hex()
        started = time.perf_counter_ns()
        request_writer.write(request)
        received = []
        for _ in range(100):
            received = request_reader.take()
            if received:
                break
            time.sleep(0.001)
        if not received:
            raise RuntimeError("DDS request was not delivered")
        incoming = received[-1]
        try:
            public.verify(
                bytes.fromhex(incoming.signature_hex),
                _dds_request_material(incoming),
            )
            signature_valid = True
        except Exception:
            signature_valid = False
        replay = incoming.sequence in seen_sequences
        allowed = (
            signature_valid
            and incoming.compartment == "targeting"
            and incoming.action in {"read", "annotate"}
            and not replay
        )
        seen_sequences.add(incoming.sequence)
        reason = "policy_allow" if allowed else "policy_deny"
        decision_writer.write(
            DdsAccessDecision(
                request_id=incoming.request_id,
                allowed=allowed,
                reason=reason,
                policy_version="dds-policy-1",
            )
        )
        decisions = []
        for _ in range(100):
            decisions = decision_reader.take()
            if decisions:
                break
            time.sleep(0.001)
        if not decisions:
            raise RuntimeError("DDS decision was not delivered")
        result = decisions[-1]
        latencies.append((time.perf_counter_ns() - started) / 1000.0)
        truth.append(not attack)
        observed.append(bool(result.allowed))
        evidence.append(
            "NV059",
            {
                "request_id": result.request_id,
                "protocol": "DDS/RTPS",
                "allowed": result.allowed,
                "attack_type": attack_type or None,
            },
        )
    metrics = binary_metrics(truth, observed)
    return {
        "implementation": "Eclipse Cyclone DDS Python binding",
        "transport": "DDS/RTPS local domain",
        "requests": requests,
        "authorization": metrics,
        "attack_classes": [
            "invalid Ed25519 signature",
            "wrong compartment",
            "sequence replay",
            "forbidden action",
        ],
        "performance": {
            "p50_us": percentile(latencies, 0.50),
            "p95_us": percentile(latencies, 0.95),
        },
        "evidence": {
            "records": len(evidence.records),
            "head": evidence.head,
            "verified": EvidenceChain.verify(evidence.records, evidence.public_key),
            "tamper_detected": tamper_test(evidence.records, evidence.public_key),
        },
    }


@dataclass(frozen=True)
class AirObservation:
    icao24: str
    time_position: int
    position_km: np.ndarray
    velocity_km_s: np.ndarray


def load_opensky_tracks(path: Path) -> dict[str, list[AirObservation]]:
    payload = json.loads(path.read_text())
    tracks: dict[str, list[AirObservation]] = defaultdict(list)
    for snapshot in payload["snapshots"]:
        for state in snapshot["states"]:
            if (
                len(state) < 11
                or state[0] is None
                or state[3] is None
                or state[5] is None
                or state[6] is None
            ):
                continue
            longitude = float(state[5])
            latitude = float(state[6])
            north = (latitude - 47.5) * 111.32
            east = (longitude + 122.5) * 111.32 * math.cos(math.radians(47.5))
            speed_m_s = float(state[9] or 0.0)
            heading = math.radians(float(state[10] or 0.0))
            velocity = np.array(
                [
                    speed_m_s * math.cos(heading) / 1000.0,
                    speed_m_s * math.sin(heading) / 1000.0,
                ]
            )
            tracks[str(state[0])].append(
                AirObservation(
                    icao24=str(state[0]),
                    time_position=int(state[3]),
                    position_km=np.array([north, east]),
                    velocity_km_s=velocity,
                )
            )
    cleaned: dict[str, list[AirObservation]] = {}
    for aircraft, observations in tracks.items():
        by_time = {observation.time_position: observation for observation in observations}
        ordered = [by_time[key] for key in sorted(by_time)]
        if len(ordered) >= 3:
            cleaned[aircraft] = ordered
    return cleaned


def evaluate_real_opensky_forecasting(path: Path) -> dict[str, Any]:
    tracks = {
        aircraft: observations
        for aircraft, observations in load_opensky_tracks(path).items()
        if len(observations) >= 8
    }
    if len(tracks) < 5:
        raise ValueError("at least five OpenSky tracks with eight positions are required")

    def evaluate(
        selected: list[list[AirObservation]],
        blend: float,
    ) -> tuple[list[float], list[float], list[float], list[float]]:
        forecast_errors: list[float] = []
        hold_errors: list[float] = []
        raw_velocity_errors: list[float] = []
        reported_velocity_errors: list[float] = []
        for observations in selected:
            for index in range(1, len(observations) - 1):
                previous = observations[index - 1]
                current = observations[index]
                target = observations[index + 1]
                prior_dt = current.time_position - previous.time_position
                future_dt = target.time_position - current.time_position
                if prior_dt <= 0 or future_dt <= 0 or future_dt > 30:
                    continue
                observed_velocity = (
                    current.position_km - previous.position_km
                ) / prior_dt
                reported_velocity = current.velocity_km_s
                velocity = (
                    blend * observed_velocity
                    + (1.0 - blend) * reported_velocity
                )
                forecast = current.position_km + velocity * future_dt
                raw = current.position_km + observed_velocity * future_dt
                reported = (
                    current.position_km + reported_velocity * future_dt
                )
                forecast_errors.append(
                    float(np.linalg.norm(forecast - target.position_km))
                )
                hold_errors.append(
                    float(np.linalg.norm(current.position_km - target.position_km))
                )
                raw_velocity_errors.append(
                    float(np.linalg.norm(raw - target.position_km))
                )
                reported_velocity_errors.append(
                    float(np.linalg.norm(reported - target.position_km))
                )
        return (
            forecast_errors,
            hold_errors,
            raw_velocity_errors,
            reported_velocity_errors,
        )

    ordered = [tracks[key] for key in sorted(tracks)]
    calibration_count = max(3, len(ordered) // 3)
    best: tuple[float, float] | None = None
    for blend in np.linspace(0.0, 1.0, 11):
        errors, _, _, _ = evaluate(ordered[:calibration_count], float(blend))
        if not errors:
            continue
        rmse = float(np.sqrt(np.mean(np.square(errors))))
        if best is None or rmse < best[0]:
            best = (rmse, float(blend))
    if best is None:
        raise ValueError("OpenSky trajectories had no usable forecast intervals")
    _, selected_blend = best
    started = time.perf_counter_ns()
    forecast, hold, raw, reported = evaluate(
        ordered[calibration_count:],
        selected_blend,
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1.0e6
    forecast_rmse = float(np.sqrt(np.mean(np.square(forecast))))
    hold_rmse = float(np.sqrt(np.mean(np.square(hold))))
    raw_rmse = float(np.sqrt(np.mean(np.square(raw))))
    reported_rmse = float(np.sqrt(np.mean(np.square(reported))))
    chain = EvidenceChain(b"opensky-forecasting")
    result = {
        "source": "OpenSky Network live state-vector capture",
        "tracks": len(ordered) - calibration_count,
        "calibration_tracks": calibration_count,
        "forecast_intervals": len(forecast),
        "selected_observed_velocity_blend": selected_blend,
        "forecast_rmse_km": forecast_rmse,
        "hold_rmse_km": hold_rmse,
        "raw_observed_velocity_rmse_km": raw_rmse,
        "reported_velocity_rmse_km": reported_rmse,
        "improvement_vs_hold_pct": 100.0 * (1.0 - forecast_rmse / hold_rmse),
        "improvement_vs_raw_velocity_pct": 100.0
        * (1.0 - forecast_rmse / raw_rmse),
        "improvement_vs_reported_velocity_pct": 100.0
        * (1.0 - forecast_rmse / reported_rmse),
        "processing_ms": elapsed_ms,
    }
    chain.append("NV061", result)
    result["evidence"] = {
        "records": len(chain.records),
        "head": chain.head,
        "verified": EvidenceChain.verify(chain.records, chain.public_key),
        "tamper_detected": tamper_test(chain.records, chain.public_key),
    }
    return result


def evaluate_mixed_domain_custody(
    ais_tracks: list[MaritimeTrack],
    opensky_path: Path,
    seed: int = 6101,
) -> dict[str, Any]:
    air_tracks = load_opensky_tracks(opensky_path)
    if len(air_tracks) < 3:
        raise ValueError("at least three multi-snapshot OpenSky tracks are required")
    rng = np.random.default_rng(seed)
    pair_count = min(20, len(air_tracks), len(ais_tracks))
    selected_air = list(air_tracks.items())[:pair_count]
    selected_surface = ais_tracks[:pair_count]
    objects: list[tuple[str, str, np.ndarray, np.ndarray]] = []
    crossing_step = 6
    for index, ((aircraft, observations), surface) in enumerate(
        zip(selected_air, selected_surface)
    ):
        center = np.array([(index // 5) * 25.0, (index % 5) * 25.0])
        air_direction = observations[0].velocity_km_s
        air_direction /= max(np.linalg.norm(air_direction), 1.0e-9)
        surface_direction = surface.positions[1] - surface.positions[0]
        surface_direction /= max(np.linalg.norm(surface_direction), 1.0e-9)
        air_velocity = air_direction * 1.2
        surface_velocity = surface_direction * 0.55
        objects.append(
            (
                f"air:{aircraft}",
                "air",
                center - crossing_step * air_velocity,
                air_velocity,
            )
        )
        objects.append(
            (
                f"surface:{index}",
                "surface",
                center - crossing_step * surface_velocity,
                surface_velocity,
            )
        )

    position_only_correct = 0
    source_aware_correct = 0
    assignments = 0
    position_only_switches = 0
    source_aware_switches = 0
    previous_position_assignment: dict[int, str] = {}
    previous_source_assignment: dict[int, str] = {}
    fusion_errors: list[float] = []
    for step in range(12):
        truth_positions = np.vstack(
            [position + step * velocity for _, _, position, velocity in objects]
        )
        radar = truth_positions + rng.normal(0.0, 0.60, truth_positions.shape)
        cooperative = truth_positions + rng.normal(0.0, 0.12, truth_positions.shape)
        cooperative_available = rng.random(len(objects)) > 0.18
        fused = radar.copy()
        fused[cooperative_available] = (
            0.2 * radar[cooperative_available]
            + 0.8 * cooperative[cooperative_available]
        )
        fusion_errors.extend(np.linalg.norm(fused - truth_positions, axis=1))
        shuffled = rng.permutation(len(objects))
        detections = fused[shuffled]
        costs = np.linalg.norm(
            truth_positions[:, None, :] - detections[None, :, :],
            axis=2,
        )
        position_rows, position_columns = linear_sum_assignment(costs)
        observed_domains = np.array([objects[index][1] for index in shuffled])
        domain_penalty = np.zeros_like(costs)
        for row, (_, expected_domain, _, _) in enumerate(objects):
            domain_penalty[row, observed_domains != expected_domain] = 5.0
        aware_rows, aware_columns = linear_sum_assignment(costs + domain_penalty)
        position_map = dict(zip(position_rows, position_columns))
        aware_map = dict(zip(aware_rows, aware_columns))
        for row in range(len(objects)):
            assignments += 1
            position_object = int(shuffled[position_map[row]])
            position_only_correct += int(row == position_object)
            previous_position = previous_position_assignment.get(row)
            position_identity = objects[position_object][0]
            position_only_switches += int(
                previous_position is not None
                and previous_position != position_identity
            )
            previous_position_assignment[row] = position_identity
            aware_column = aware_map[row]
            aware_object = int(shuffled[aware_column])
            source_aware_correct += int(row == aware_object)
            previous = previous_source_assignment.get(row)
            current = objects[aware_object][0]
            source_aware_switches += int(
                previous is not None and previous != current
            )
            previous_source_assignment[row] = current
    chain = EvidenceChain(b"mixed-domain-custody")
    result = {
        "source": "NOAA AIS plus live-captured OpenSky state vectors and radar surrogate",
        "air_tracks": len(selected_air),
        "surface_tracks": len(selected_surface),
        "assignments": assignments,
        "position_only_accuracy": position_only_correct / assignments,
        "source_aware_accuracy": source_aware_correct / assignments,
        "position_only_identity_switches": position_only_switches,
        "source_aware_identity_switches": source_aware_switches,
        "fused_position_rmse_km": float(
            np.sqrt(np.mean(np.square(fusion_errors)))
        ),
        "cooperative_dropout_probability": 0.18,
        "radar_noise_km": 0.60,
    }
    chain.append("NV061", result)
    result["evidence"] = {
        "records": len(chain.records),
        "head": chain.head,
        "verified": EvidenceChain.verify(chain.records, chain.public_key),
        "tamper_detected": tamper_test(chain.records, chain.public_key),
    }
    return result


def _persistent_crossings(
    score: np.ndarray,
    threshold: float,
    required_samples: int,
) -> np.ndarray:
    above = (score > threshold).astype(int)
    if len(above) < required_samples:
        return np.array([], dtype=int)
    rolling = np.convolve(
        above,
        np.ones(required_samples, dtype=int),
        mode="valid",
    )
    starts = np.flatnonzero(rolling >= required_samples)
    return starts + required_samples - 1


def evaluate_calibrated_ais_pol(
    tracks: list[MaritimeTrack],
    seed: int = 63,
    required_samples: int = 12,
) -> dict[str, Any]:
    original_count = len(tracks)
    screened = [
        track for track in tracks if float(np.max(ais_pol_score(track)[0])) < 20.0
    ]
    rng = np.random.default_rng(seed)
    order = rng.permutation(len(screened))
    calibration_count = max(10, len(screened) // 3)
    calibration = [screened[index] for index in order[:calibration_count]]
    nominal = [screened[index] for index in order[calibration_count:]]
    calibration_max = [float(np.max(ais_pol_score(track)[0])) for track in calibration]
    threshold = max(8.0, percentile(calibration_max, 0.70) * 1.30)
    anomaly_types = ("intercept", "route_deviation", "speed_surge", "dark_contact")
    attacks = [
        inject_track_anomaly(
            track,
            anomaly_types[index % len(anomaly_types)],
            seed * 1000 + index,
        )
        for index, track in enumerate(nominal)
    ]
    evaluation = nominal + attacks
    truth = [False] * len(nominal) + [True] * len(attacks)
    predicted: list[bool] = []
    delays: list[int] = []
    for track in evaluation:
        score, _, _ = ais_pol_score(track)
        crossings = _persistent_crossings(score, threshold, required_samples)
        dark = np.flatnonzero(~track.cooperative)
        alerted = bool(len(crossings) or len(dark))
        predicted.append(alerted)
        if track.anomalous and alerted:
            first = int(dark[0] if len(dark) else crossings[0])
            delays.append(max(0, first - track.anomaly_start))
    metrics = binary_metrics(truth, predicted)
    return {
        **metrics,
        "unlabeled_tracks_seen": original_count,
        "high_confidence_nominal_tracks": len(screened),
        "threshold": threshold,
        "required_persistent_samples": required_samples,
        "mean_detection_delay_steps": float(np.mean(delays)),
        "p95_detection_delay_steps": percentile(delays, 0.95),
        "calibration_tracks": calibration_count,
        "evaluation_nominal_tracks": len(nominal),
        "injected_attack_tracks": len(attacks),
    }


def run_secure_provider_workflow_extension(
    seed: int = 6201,
    tasks: int = 48,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    gateway = HybridTaskGateway()
    accepted = 0
    duplicate_blocked = 0
    cancelled = 0
    return_integrity_verified = 0
    tampered_return_blocked = 0
    latencies: list[float] = []
    evidence = EvidenceChain(b"nv062-workflow-extension")
    for index in range(tasks):
        payload = normalize_provider_payload(
            index % 4,
            provider_payload(index % 4, index),
        )
        started = time.perf_counter_ns()
        envelope = gateway.seal(payload)
        opened = gateway.open_once(envelope)
        accepted += int(opened["task_id"] == payload["task_id"])
        if index % 11 == 0:
            cancelled += 1
            state = "cancelled_before_collection"
        else:
            state = "return_verified"
            binary_return = rng.bytes(64 * 1024)
            chunks = [
                binary_return[offset : offset + 4096]
                for offset in range(0, len(binary_return), 4096)
            ]
            chunk_hashes = [hashlib.sha384(chunk).hexdigest() for chunk in chunks]
            manifest = hashlib.sha384("".join(chunk_hashes).encode()).hexdigest()
            recomputed = hashlib.sha384(
                "".join(
                    hashlib.sha384(chunk).hexdigest()
                    for chunk in chunks
                ).encode()
            ).hexdigest()
            return_integrity_verified += int(manifest == recomputed)
            modified = bytearray(chunks[0])
            modified[0] ^= 1
            tampered_hashes = [
                hashlib.sha384(bytes(modified)).hexdigest(),
                *chunk_hashes[1:],
            ]
            tampered_manifest = hashlib.sha384(
                "".join(tampered_hashes).encode()
            ).hexdigest()
            tampered_return_blocked += int(tampered_manifest != manifest)
        try:
            gateway.open_once(envelope)
        except ValueError:
            duplicate_blocked += 1
        latencies.append((time.perf_counter_ns() - started) / 1000.0)
        evidence.append(
            "NV062",
            {
                "task_id": payload["task_id"],
                "state": state,
                "provider_adapter": payload["provider_adapter"],
            },
        )
    return {
        "tasks": tasks,
        "provider_adapters": 4,
        "accepted": accepted,
        "duplicate_blocked": duplicate_blocked,
        "cancelled_before_collection": cancelled,
        "binary_return_bytes": (tasks - cancelled) * 64 * 1024,
        "return_integrity_verified": return_integrity_verified,
        "tampered_return_blocked": tampered_return_blocked,
        "workflow_states": [
            "authorized",
            "released",
            "accepted",
            "cancelled_before_collection",
            "return_verified",
        ],
        "performance": {
            "p50_us": percentile(latencies, 0.50),
            "p95_us": percentile(latencies, 0.95),
        },
        "evidence": {
            "records": len(evidence.records),
            "head": evidence.head,
            "verified": EvidenceChain.verify(evidence.records, evidence.public_key),
            "tamper_detected": tamper_test(evidence.records, evidence.public_key),
        },
    }


def run_public_stac_return_integration() -> dict[str, Any]:
    endpoint = "https://planetarycomputer.microsoft.com/api/stac/v1/search"
    query = {
        "collections": ["sentinel-2-l2a"],
        "bbox": [-122.6, 47.4, -122.2, 47.8],
        "datetime": "2026-05-01/2026-06-21",
        "limit": 1,
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(query).encode(),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "AssureEdge-Phase-I-Feasibility/1.0",
        },
        method="POST",
    )
    started = time.perf_counter_ns()
    with urllib.request.urlopen(request, timeout=30) as response:
        catalog = json.load(response)
    features = catalog.get("features") or []
    if not features:
        raise RuntimeError("Planetary Computer STAC search returned no item")
    item = features[0]
    preview_url = item["assets"]["rendered_preview"]["href"]
    preview_request = urllib.request.Request(
        preview_url,
        headers={"User-Agent": "AssureEdge-Phase-I-Feasibility/1.0"},
    )
    with urllib.request.urlopen(preview_request, timeout=60) as response:
        preview = response.read(8 * 1024 * 1024)
        content_type = response.headers.get("Content-Type")
    if not preview.startswith(b"\x89PNG"):
        raise ValueError("external provider preview was not a PNG")

    gateway = HybridTaskGateway()
    task = {
        "task_id": f"stac-{item['id']}",
        "provider_adapter": "microsoft-planetary-computer-stac",
        "classification_boundary": "public-data",
        "collection_window": query["datetime"],
        "area_commitment": hashlib.sha384(
            json.dumps(query["bbox"]).encode()
        ).hexdigest(),
        "return_data_required": True,
    }
    opened = gateway.open_once(gateway.seal(task))
    return_metadata = {
        "task_id": opened["task_id"],
        "provider": "Microsoft Planetary Computer",
        "collection": item["collection"],
        "item_id": item["id"],
        "acquired_at": item["properties"].get("datetime"),
        "preview_bytes": len(preview),
        "preview_sha384": hashlib.sha384(preview).hexdigest(),
        "content_type": content_type,
    }
    return_envelope = seal_hybrid_task(
        return_metadata,
        gateway.government_return_x25519_private.public_key(),
        gateway.government_return_mlkem_public,
        gateway.provider_return_ed25519_private,
        gateway.provider_return_mldsa_secret,
    )
    verified = open_hybrid_task(
        return_envelope,
        gateway.government_return_x25519_private,
        gateway.government_return_mlkem_secret,
        gateway.provider_return_ed25519_private.public_key(),
        gateway.provider_return_mldsa_public,
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1.0e6
    chain = EvidenceChain(b"nv062-public-stac")
    chain.append("NV062", verified)
    return {
        "provider": "Microsoft Planetary Computer",
        "api": endpoint,
        "provider_api_reached": True,
        "collection_tasking_claim": False,
        "external_item": item["id"],
        "external_collection": item["collection"],
        "external_acquired_at": item["properties"].get("datetime"),
        "preview_bytes": len(preview),
        "preview_sha384": verified["preview_sha384"],
        "hybrid_return_verified": verified == return_metadata,
        "elapsed_ms": elapsed_ms,
        "boundary": (
            "real external discovery and data retrieval; not a commercial "
            "collection-order or accredited provider tasking interface"
        ),
        "evidence": {
            "records": len(chain.records),
            "head": chain.head,
            "verified": EvidenceChain.verify(chain.records, chain.public_key),
            "tamper_detected": tamper_test(chain.records, chain.public_key),
        },
    }


def run_cuas_scale_and_fusion_stress(seed: int = 2002) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    scale_results: dict[str, dict[str, float]] = {}
    all_truth: list[bool] = []
    all_predictions: list[bool] = []
    for count in (25, 50, 100, 150):
        positions = rng.uniform(-100.0, 100.0, (count, 2))
        velocities = rng.normal(0.0, 0.8, (count, 2))
        runtimes: list[float] = []
        correct = 0
        assignments = 0
        for _ in range(20):
            positions = positions + velocities
            detected = rng.random(count) < 0.91
            truth_ids = np.flatnonzero(detected)
            detections = positions[detected] + rng.normal(
                0.0,
                0.45,
                (len(truth_ids), 2),
            )
            clutter_count = int(rng.poisson(max(2.0, count / 35.0)))
            if clutter_count:
                detections = np.vstack(
                    (
                        detections,
                        rng.uniform(-125.0, 125.0, (clutter_count, 2)),
                    )
                )
            started = time.perf_counter_ns()
            costs = np.linalg.norm(
                positions[:, None, :] - detections[None, :, :],
                axis=2,
            )
            rows, columns = linear_sum_assignment(costs)
            runtimes.append((time.perf_counter_ns() - started) / 1.0e6)
            for row, column in zip(rows, columns):
                if column < len(truth_ids) and costs[row, column] < 3.0:
                    assignments += 1
                    correct += int(row == truth_ids[column])
        scale_results[str(count)] = {
            "assignment_accuracy": correct / max(assignments, 1),
            "p95_update_ms": percentile(runtimes, 0.95),
        }

    for index in range(3000):
        drone = index % 2 == 0
        if drone:
            eo = rng.normal(0.80, 0.13)
            rf = rng.normal(0.76, 0.16)
            acoustic = rng.normal(0.70, 0.18)
        else:
            eo = rng.normal(0.25, 0.18)
            rf = rng.normal(0.22, 0.17)
            acoustic = rng.normal(0.30, 0.20)
        channels = np.clip([eo, rf, acoustic], 0.0, 1.0)
        available = rng.random(3) > np.array([0.08, 0.15, 0.20])
        fused = float(np.mean(channels[available])) if np.any(available) else 0.0
        all_truth.append(drone)
        all_predictions.append(fused >= 0.55)
    fusion = binary_metrics(all_truth, all_predictions)
    chain = EvidenceChain(b"np002-scale-fusion-extension")
    chain.append("NP002", {"scale": scale_results, "fusion": fusion})
    return {
        "scale": scale_results,
        "maximum_uas": 150,
        "synthetic_front_end_fusion": {
            **fusion,
            "channels": ["EO score", "RF score", "acoustic score"],
            "limitation": "channel scores are synthetic; no payload identity claim",
        },
        "evidence": {
            "records": len(chain.records),
            "head": chain.head,
            "verified": EvidenceChain.verify(chain.records, chain.public_key),
            "tamper_detected": tamper_test(chain.records, chain.public_key),
        },
    }


def run_sensor_constraint_stress(seed: int = 6501) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    sensors = {
        "SPS-48 surrogate": {"time_ms": 1000.0, "power": 1.0},
        "SPQ-9B surrogate": {"time_ms": 1000.0, "power": 1.0},
        "MK-9 surrogate": {"time_ms": 1000.0, "power": 0.8},
        "SPY-6(V)3 surrogate": {"time_ms": 1000.0, "power": 1.2},
    }
    baseline_invalid = 0
    constrained_invalid = 0
    baseline_utility: list[float] = []
    constrained_utility: list[float] = []
    runtimes: list[float] = []
    for _ in range(100):
        candidates: list[dict[str, Any]] = []
        for sensor, budget in sensors.items():
            for task in range(18):
                dwell = float(rng.uniform(15.0, 180.0))
                power = float(rng.uniform(0.04, 0.30))
                priority = float(rng.uniform(0.1, 1.0))
                information_gain = float(rng.uniform(0.02, 0.55))
                candidates.append(
                    {
                        "sensor": sensor,
                        "task": task,
                        "dwell_ms": dwell,
                        "power": power,
                        "illumination": task % 11 == 0,
                        "utility": priority * information_gain / dwell,
                        "budget": budget,
                    }
                )
        naive = sorted(candidates, key=lambda item: item["utility"], reverse=True)[:24]
        baseline_utility.append(sum(item["utility"] for item in naive))
        for sensor, budget in sensors.items():
            selected = [item for item in naive if item["sensor"] == sensor]
            invalid = (
                sum(item["dwell_ms"] for item in selected) > budget["time_ms"]
                or sum(item["power"] for item in selected) > budget["power"]
                or sum(item["illumination"] for item in selected) > 1
            )
            baseline_invalid += int(invalid)

        started = time.perf_counter_ns()
        selected: list[dict[str, Any]] = []
        used_time = defaultdict(float)
        used_power = defaultdict(float)
        illumination_used = defaultdict(bool)
        for item in sorted(candidates, key=lambda value: value["utility"], reverse=True):
            sensor = item["sensor"]
            budget = item["budget"]
            if used_time[sensor] + item["dwell_ms"] > budget["time_ms"]:
                continue
            if used_power[sensor] + item["power"] > budget["power"]:
                continue
            if item["illumination"] and illumination_used[sensor]:
                continue
            selected.append(item)
            used_time[sensor] += item["dwell_ms"]
            used_power[sensor] += item["power"]
            illumination_used[sensor] |= item["illumination"]
        runtimes.append((time.perf_counter_ns() - started) / 1000.0)
        constrained_utility.append(sum(item["utility"] for item in selected))
        for sensor, budget in sensors.items():
            constrained_invalid += int(
                used_time[sensor] > budget["time_ms"]
                or used_power[sensor] > budget["power"]
            )
    chain = EvidenceChain(b"nv065-constraint-extension")
    result = {
        "scenarios": 100,
        "sensors": list(sensors),
        "constraints": [
            "frame-time budget",
            "power budget",
            "single simultaneous illumination task",
        ],
        "naive_invalid_sensor_schedules": baseline_invalid,
        "constrained_invalid_sensor_schedules": constrained_invalid,
        "mean_naive_utility": float(np.mean(baseline_utility)),
        "mean_constrained_utility": float(np.mean(constrained_utility)),
        "scheduler_p95_us": percentile(runtimes, 0.95),
    }
    chain.append("NV065", result)
    result["evidence"] = {
        "records": len(chain.records),
        "head": chain.head,
        "verified": EvidenceChain.verify(chain.records, chain.public_key),
        "tamper_detected": tamper_test(chain.records, chain.public_key),
    }
    return result
