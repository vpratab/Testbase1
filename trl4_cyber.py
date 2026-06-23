"""TRL 3/4 laboratory demonstrators for QSPARX, NV059, and NV062."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import ssl
import threading
import time
import urllib.request
import warnings
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import numpy as np
from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from run_experiments import run_qsparx
from trl4_common import (
    EvidenceChain,
    binary_metrics,
    percentile,
    tamper_test,
)


CRYPTO_PATTERNS: dict[str, re.Pattern[str]] = {
    "RSA": re.compile(r"\bRSA(?:2048|3072|4096)?\b|rsa::|RsaPrivateKey", re.I),
    "ECDSA": re.compile(r"\bECDSA\b|SECP256R1|p-?256", re.I),
    "Ed25519": re.compile(r"\bEd25519\b|ed25519[_-]dalek", re.I),
    "X25519": re.compile(r"\bX25519\b|x25519[_-]dalek", re.I),
    "AES-GCM": re.compile(r"\bAES(?:128|256)?GCM\b|AES-?GCM", re.I),
    "ChaCha20": re.compile(r"ChaCha20Poly1305|XChaCha20Poly1305", re.I),
    "SHA-1": re.compile(r"\bSHA-?1\b|sha1::", re.I),
    "SHA-2": re.compile(r"\bSHA-?(?:256|384|512)\b|sha2::", re.I),
    "TLS": re.compile(r"\bTLS(?:1[._]?[23])?\b|rustls|openssl", re.I),
    "ML-KEM": re.compile(r"\bML-?KEM\b|ml_kem", re.I),
    "ML-DSA": re.compile(r"\bML-?DSA\b|ml_dsa", re.I),
}

TEXT_SUFFIXES = {
    ".rs",
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".mjs",
    ".toml",
    ".yaml",
    ".yml",
    ".json",
    ".md",
    ".txt",
    ".pem",
}

SKIP_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "target",
    "obj_dir",
    "out",
    "dist",
    "build",
}


def scan_crypto_assets(roots: list[Path]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    files_scanned = 0
    bytes_scanned = 0
    started = time.perf_counter_ns()
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            try:
                raw = path.read_bytes()
                if len(raw) > 2_000_000:
                    continue
                text = raw.decode("utf-8", errors="ignore")
            except OSError:
                continue
            files_scanned += 1
            bytes_scanned += len(raw)
            for algorithm, pattern in CRYPTO_PATTERNS.items():
                matches = list(pattern.finditer(text))
                if matches:
                    findings.append(
                        {
                            "root": str(root),
                            "path": str(path),
                            "algorithm": algorithm,
                            "occurrences": len(matches),
                            "line_examples": sorted(
                                {
                                    text.count("\n", 0, match.start()) + 1
                                    for match in matches[:5]
                                }
                            ),
                        }
                    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1.0e6
    counts = Counter(
        finding["algorithm"]
        for finding in findings
        for _ in range(finding["occurrences"])
    )
    vulnerable = sum(
        counts[name]
        for name in ("RSA", "ECDSA", "Ed25519", "X25519")
    )
    pqc_ready = counts["ML-KEM"] + counts["ML-DSA"]
    return {
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "elapsed_ms": elapsed_ms,
        "files_per_second": files_scanned / max(elapsed_ms / 1000.0, 1.0e-9),
        "finding_count": len(findings),
        "occurrences_by_algorithm": dict(sorted(counts.items())),
        "quantum_vulnerable_occurrences": vulnerable,
        "pqc_occurrences": pqc_ready,
        "findings": findings,
    }


def validate_scanner() -> dict[str, Any]:
    snippets = {
        "rust_ed25519": ("use ed25519_dalek::SigningKey;", {"Ed25519"}),
        "python_x25519": (
            "from cryptography.hazmat.primitives.asymmetric import x25519",
            {"X25519"},
        ),
        "weak_sha1": ("digest = SHA1(data)", {"SHA-1"}),
        "pqc": (
            "from pqcrypto.kem import ml_kem_768\nfrom pqcrypto.sign import ml_dsa_65",
            {"ML-KEM", "ML-DSA"},
        ),
        "non_crypto": ("position = velocity * time_delta", set()),
    }
    expected: list[bool] = []
    observed: list[bool] = []
    exact = 0
    for text, truth in snippets.values():
        found = {
            name for name, pattern in CRYPTO_PATTERNS.items() if pattern.search(text)
        }
        exact += int(found == truth)
        for name in CRYPTO_PATTERNS:
            expected.append(name in truth)
            observed.append(name in found)
    result = binary_metrics(expected, observed)
    result["exact_snippet_accuracy"] = exact / len(snippets)
    result["snippets"] = len(snippets)
    return result


def scan_system_certificate_store() -> dict[str, Any]:
    context = ssl.create_default_context()
    certificates = context.get_ca_certs(binary_form=True)
    key_types: Counter[str] = Counter()
    signature_hashes: Counter[str] = Counter()
    weak_certificates = 0
    expired_certificates = 0
    now = dt.datetime.now(dt.timezone.utc)
    parsed = 0
    for encoded in certificates:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", CryptographyDeprecationWarning)
                certificate = x509.load_der_x509_certificate(encoded)
        except ValueError:
            continue
        parsed += 1
        public_key = certificate.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type = f"EC-{public_key.curve.name}"
        else:
            key_size = getattr(public_key, "key_size", None)
            key_type = (
                f"{type(public_key).__name__}-{key_size}"
                if key_size is not None
                else type(public_key).__name__
            )
        key_types[key_type] += 1
        hash_name = (
            certificate.signature_hash_algorithm.name
            if certificate.signature_hash_algorithm is not None
            else "none"
        )
        signature_hashes[hash_name] += 1
        weak_certificates += int(
            hash_name.lower() in {"sha1", "md5"}
            or (
                getattr(public_key, "key_size", 4096) < 2048
                and "rsa" in type(public_key).__name__.lower()
            )
        )
        expired_certificates += int(certificate.not_valid_after_utc < now)
    return {
        "certificates_returned": len(certificates),
        "certificates_parsed": parsed,
        "key_types": dict(sorted(key_types.items())),
        "signature_hashes": dict(sorted(signature_hashes.items())),
        "weak_certificates": weak_certificates,
        "expired_certificates": expired_certificates,
        "source": "Python/OpenSSL default host trust store",
    }


def benchmark_pqc(iterations: int = 120) -> dict[str, Any]:
    kem_keygen: list[float] = []
    kem_encap: list[float] = []
    kem_decap: list[float] = []
    sign_keygen: list[float] = []
    sign_time: list[float] = []
    verify_time: list[float] = []
    kem_valid = 0
    signatures_valid = 0
    tamper_rejected = 0
    message = os.urandom(1024)

    for _ in range(iterations):
        started = time.perf_counter_ns()
        kem_public, kem_secret = ml_kem_768.generate_keypair()
        kem_keygen.append((time.perf_counter_ns() - started) / 1000.0)

        started = time.perf_counter_ns()
        ciphertext, shared_sender = ml_kem_768.encrypt(kem_public)
        kem_encap.append((time.perf_counter_ns() - started) / 1000.0)

        started = time.perf_counter_ns()
        shared_recipient = ml_kem_768.decrypt(kem_secret, ciphertext)
        kem_decap.append((time.perf_counter_ns() - started) / 1000.0)
        kem_valid += int(shared_sender == shared_recipient)

        started = time.perf_counter_ns()
        sign_public, sign_secret = ml_dsa_65.generate_keypair()
        sign_keygen.append((time.perf_counter_ns() - started) / 1000.0)

        started = time.perf_counter_ns()
        signature = ml_dsa_65.sign(sign_secret, message)
        sign_time.append((time.perf_counter_ns() - started) / 1000.0)

        started = time.perf_counter_ns()
        signatures_valid += int(ml_dsa_65.verify(sign_public, message, signature))
        verify_time.append((time.perf_counter_ns() - started) / 1000.0)
        modified = bytearray(message)
        modified[len(modified) // 2] ^= 1
        try:
            valid = ml_dsa_65.verify(sign_public, bytes(modified), signature)
        except Exception:
            valid = False
        tamper_rejected += int(not valid)

    return {
        "iterations": iterations,
        "ml_kem_768": {
            "keygen_p50_us": percentile(kem_keygen, 0.50),
            "keygen_p95_us": percentile(kem_keygen, 0.95),
            "encapsulate_p50_us": percentile(kem_encap, 0.50),
            "encapsulate_p95_us": percentile(kem_encap, 0.95),
            "decapsulate_p50_us": percentile(kem_decap, 0.50),
            "decapsulate_p95_us": percentile(kem_decap, 0.95),
            "valid_shared_secrets": kem_valid,
            "public_key_bytes": ml_kem_768.PUBLIC_KEY_SIZE,
            "secret_key_bytes": ml_kem_768.SECRET_KEY_SIZE,
            "ciphertext_bytes": ml_kem_768.CIPHERTEXT_SIZE,
        },
        "ml_dsa_65": {
            "keygen_p50_us": percentile(sign_keygen, 0.50),
            "keygen_p95_us": percentile(sign_keygen, 0.95),
            "sign_p50_us": percentile(sign_time, 0.50),
            "sign_p95_us": percentile(sign_time, 0.95),
            "verify_p50_us": percentile(verify_time, 0.50),
            "verify_p95_us": percentile(verify_time, 0.95),
            "valid_signatures": signatures_valid,
            "tamper_rejected": tamper_rejected,
            "public_key_bytes": ml_dsa_65.PUBLIC_KEY_SIZE,
            "secret_key_bytes": ml_dsa_65.SECRET_KEY_SIZE,
            "signature_bytes": ml_dsa_65.SIGNATURE_SIZE,
        },
    }


def run_qsparx_trl4(roots: list[Path], seed: int = 17) -> dict[str, Any]:
    inventory = scan_crypto_assets(roots)
    certificate_store = scan_system_certificate_store()
    scanner_validation = validate_scanner()
    pqc = benchmark_pqc()
    risk_model = run_qsparx(seed)
    chain = EvidenceChain(b"qsparx-trl4")
    chain.append(
        "QSPARX",
        {
            "inventory_hash": hashlib.sha256(
                json.dumps(
                    inventory["occurrences_by_algorithm"],
                    sort_keys=True,
                ).encode()
            ).hexdigest(),
            "files_scanned": inventory["files_scanned"],
            "certificates_parsed": certificate_store["certificates_parsed"],
            "model_f1": risk_model["f1"],
        },
    )
    chain.append(
        "QSPARX",
        {
            "ml_kem_valid": pqc["ml_kem_768"]["valid_shared_secrets"],
            "ml_dsa_valid": pqc["ml_dsa_65"]["valid_signatures"],
            "tamper_rejected": pqc["ml_dsa_65"]["tamper_rejected"],
        },
    )
    return {
        "inventory": inventory,
        "certificate_store": certificate_store,
        "scanner_validation": scanner_validation,
        "pqc_benchmark": pqc,
        "risk_model": risk_model,
        "evidence": {
            "records": len(chain.records),
            "head": chain.head,
            "verified": EvidenceChain.verify(chain.records, chain.public_key),
            "tamper_detected": tamper_test(chain.records, chain.public_key),
        },
    }


def _cert_name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _build_certificate(
    subject: x509.Name,
    issuer: x509.Name,
    public_key: Any,
    issuer_private: ec.EllipticCurvePrivateKey,
    serial: int,
    is_ca: bool,
) -> x509.Certificate:
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca else None), True)
        .sign(issuer_private, hashes.SHA256())
    )


def create_piv_surrogate() -> dict[str, Any]:
    root_private = ec.generate_private_key(ec.SECP256R1())
    intermediate_private = ec.generate_private_key(ec.SECP256R1())
    client_private = ec.generate_private_key(ec.SECP256R1())
    root_name = _cert_name("AssureEdge Root CA")
    intermediate_name = _cert_name("AssureEdge PIV Issuing CA")
    client_name = _cert_name("Operator 117 / Targeting")
    root = _build_certificate(
        root_name,
        root_name,
        root_private.public_key(),
        root_private,
        1001,
        True,
    )
    intermediate = _build_certificate(
        intermediate_name,
        root_name,
        intermediate_private.public_key(),
        root_private,
        2001,
        True,
    )
    client = _build_certificate(
        client_name,
        intermediate_name,
        client_private.public_key(),
        intermediate_private,
        3001,
        False,
    )
    return {
        "root_private": root_private,
        "intermediate_private": intermediate_private,
        "client_private": client_private,
        "root": root,
        "intermediate": intermediate,
        "client": client,
    }


def verify_certificate_chain(
    client: x509.Certificate,
    intermediate: x509.Certificate,
    root: x509.Certificate,
    revoked_serials: set[int],
) -> bool:
    if client.serial_number in revoked_serials:
        return False
    now = dt.datetime.now(dt.timezone.utc)
    if not (
        client.not_valid_before_utc <= now <= client.not_valid_after_utc
        and intermediate.not_valid_before_utc <= now <= intermediate.not_valid_after_utc
        and root.not_valid_before_utc <= now <= root.not_valid_after_utc
    ):
        return False
    try:
        intermediate.public_key().verify(
            client.signature,
            client.tbs_certificate_bytes,
            ec.ECDSA(client.signature_hash_algorithm),
        )
        root.public_key().verify(
            intermediate.signature,
            intermediate.tbs_certificate_bytes,
            ec.ECDSA(intermediate.signature_hash_algorithm),
        )
        root.public_key().verify(
            root.signature,
            root.tbs_certificate_bytes,
            ec.ECDSA(root.signature_hash_algorithm),
        )
    except Exception:
        return False
    return client.issuer == intermediate.subject and intermediate.issuer == root.subject


def verify_key_possession(
    private_key: ec.EllipticCurvePrivateKey,
    certificate: x509.Certificate,
) -> bool:
    challenge = os.urandom(32)
    signature = private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))
    try:
        certificate.public_key().verify(
            signature,
            challenge,
            ec.ECDSA(hashes.SHA256()),
        )
    except Exception:
        return False
    return True


def parse_modbus_tcp(frame: bytes) -> dict[str, Any]:
    if len(frame) < 8:
        raise ValueError("short Modbus TCP frame")
    transaction = int.from_bytes(frame[0:2], "big")
    protocol = int.from_bytes(frame[2:4], "big")
    length = int.from_bytes(frame[4:6], "big")
    if protocol != 0 or length != len(frame) - 6:
        raise ValueError("invalid Modbus TCP header")
    unit = frame[6]
    function = frame[7]
    if function in {1, 2, 3, 4}:
        action = "read"
    elif function in {5, 6, 15, 16}:
        action = "command"
    else:
        raise ValueError("unsupported Modbus function")
    return {
        "transaction": transaction,
        "unit": unit,
        "function": function,
        "action": action,
        "resource": f"modbus-unit-{unit}",
    }


def build_modbus_frame(transaction: int, unit: int, function: int) -> bytes:
    payload = bytes([unit, function, 0, 1, 0, 1])
    return (
        transaction.to_bytes(2, "big")
        + bytes(2)
        + len(payload).to_bytes(2, "big")
        + payload
    )


def run_nv059_trl4(seed: int = 59, requests: int = 6000) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    piv = create_piv_surrogate()
    chain_valid = verify_certificate_chain(
        piv["client"],
        piv["intermediate"],
        piv["root"],
        set(),
    )
    possession_valid = verify_key_possession(piv["client_private"], piv["client"])
    revoked_rejected = not verify_certificate_chain(
        piv["client"],
        piv["intermediate"],
        piv["root"],
        {piv["client"].serial_number},
    )

    attack_types = (
        "missing_mfa",
        "cross_compartment",
        "unattested_device",
        "stale_offline_trust",
        "write_through_read_function",
        "malware",
        "behavioral_exfiltration",
        "revoked_certificate",
    )
    decisions: list[bool] = []
    truth: list[bool] = []
    latencies: list[float] = []
    evidence = EvidenceChain(b"nv059-trl4")
    offline_decisions = 0
    malformed_blocked = 0
    expected_blocks = 0

    for index in range(requests):
        attack = index >= requests // 2
        attack_type = attack_types[(index - requests // 2) % len(attack_types)] if attack else ""
        function = 6 if index % 4 == 0 else 3
        frame = build_modbus_frame(index % 65535, index % 20, function)
        if attack_type == "write_through_read_function":
            frame = build_modbus_frame(index % 65535, index % 20, 6)
        started = time.perf_counter_ns()
        try:
            parsed = parse_modbus_tcp(frame)
        except ValueError:
            malformed_blocked += 1
            decisions.append(False)
            truth.append(False)
            continue

        network = ("connected", "degraded", "disconnected")[index % 3]
        if attack_type == "stale_offline_trust":
            network = "disconnected"
        offline = network != "connected"
        offline_decisions += int(offline)
        authorized_action = "command" if function == 6 else "read"
        requested_action = (
            "read" if attack_type == "write_through_read_function" else authorized_action
        )
        certificate_ok = chain_valid and possession_valid
        if attack_type == "revoked_certificate":
            certificate_ok = False
        mfa = attack_type != "missing_mfa"
        compartment = attack_type != "cross_compartment"
        attested = attack_type != "unattested_device"
        trust_fresh = attack_type != "stale_offline_trust"
        malware = attack_type == "malware"
        requests_per_minute = 180 if attack_type == "behavioral_exfiltration" else int(
            rng.integers(4, 14)
        )
        action_ok = parsed["action"] == requested_action
        allowed = (
            certificate_ok
            and mfa
            and compartment
            and attested
            and (trust_fresh or not offline)
            and not malware
            and requests_per_minute < 80
            and action_ok
        )
        expected_allowed = not attack
        decisions.append(allowed)
        truth.append(expected_allowed)
        expected_blocks += int(attack)
        latency = (time.perf_counter_ns() - started) / 1000.0
        latencies.append(latency)
        evidence.append(
            "NV059",
            {
                "request_id": index,
                "network": network,
                "protocol": "modbus_tcp",
                "resource": parsed["resource"],
                "action": requested_action,
                "allowed": allowed,
                "attack_type": attack_type or None,
            },
        )

    metrics = binary_metrics(truth, decisions)
    malformed = [
        b"\x00",
        build_modbus_frame(1, 1, 3)[:-1],
        build_modbus_frame(1, 1, 99),
        b"\x00\x01\x00\x01\x00\x06\x01\x03\x00\x01\x00\x01",
    ]
    malformed_blocked = 0
    for frame in malformed:
        try:
            parse_modbus_tcp(frame)
        except ValueError:
            malformed_blocked += 1
    return {
        "piv_surrogate": {
            "certificate_chain_valid": chain_valid,
            "challenge_response_valid": possession_valid,
            "revoked_certificate_rejected": revoked_rejected,
            "client_certificate_der_bytes": len(
                piv["client"].public_bytes(serialization.Encoding.DER)
            ),
        },
        "modbus_adapter": {
            "valid_frames_processed": requests,
            "malformed_cases": len(malformed),
            "malformed_blocked": malformed_blocked,
        },
        "authorization": {
            **metrics,
            "requests": requests,
            "expected_attacks": expected_blocks,
            "offline_decisions": offline_decisions,
        },
        "performance": {
            "p50_us": percentile(latencies, 0.50),
            "p95_us": percentile(latencies, 0.95),
            "p99_us": percentile(latencies, 0.99),
            "max_us": max(latencies),
        },
        "evidence": {
            "records": len(evidence.records),
            "head": evidence.head,
            "verified": EvidenceChain.verify(evidence.records, evidence.public_key),
            "tamper_detected": tamper_test(evidence.records, evidence.public_key),
        },
    }


def _hybrid_key(
    classical_secret: bytes,
    pqc_secret: bytes,
    task_id: str,
) -> bytes:
    return HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=hashlib.sha384(task_id.encode()).digest(),
        info=b"assureedge-hybrid-commercial-task-v1",
    ).derive(classical_secret + pqc_secret)


def seal_hybrid_task(
    payload: dict[str, Any],
    recipient_x25519_public: x25519.X25519PublicKey,
    recipient_mlkem_public: bytes,
    sender_ed25519_private: ed25519.Ed25519PrivateKey,
    sender_mldsa_secret: bytes,
) -> dict[str, str]:
    task_id = str(payload["task_id"])
    plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    classical_ephemeral = x25519.X25519PrivateKey.generate()
    classical_public = classical_ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    classical_secret = classical_ephemeral.exchange(recipient_x25519_public)
    pqc_ciphertext, pqc_secret = ml_kem_768.encrypt(recipient_mlkem_public)
    key = _hybrid_key(classical_secret, pqc_secret, task_id)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, task_id.encode())
    signed_header = (
        task_id.encode()
        + classical_public
        + pqc_ciphertext
        + nonce
        + ciphertext
    )
    return {
        "task_id": task_id,
        "classical_public": base64.b64encode(classical_public).decode(),
        "pqc_ciphertext": base64.b64encode(pqc_ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "ed25519_signature": base64.b64encode(
            sender_ed25519_private.sign(signed_header)
        ).decode(),
        "ml_dsa_signature": base64.b64encode(
            ml_dsa_65.sign(sender_mldsa_secret, signed_header)
        ).decode(),
    }


def open_hybrid_task(
    envelope: dict[str, str],
    recipient_x25519_private: x25519.X25519PrivateKey,
    recipient_mlkem_secret: bytes,
    sender_ed25519_public: ed25519.Ed25519PublicKey,
    sender_mldsa_public: bytes,
) -> dict[str, Any]:
    task_id = envelope["task_id"]
    classical_public_bytes = base64.b64decode(envelope["classical_public"])
    pqc_ciphertext = base64.b64decode(envelope["pqc_ciphertext"])
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    signed_header = (
        task_id.encode()
        + classical_public_bytes
        + pqc_ciphertext
        + nonce
        + ciphertext
    )
    sender_ed25519_public.verify(
        base64.b64decode(envelope["ed25519_signature"]),
        signed_header,
    )
    if not ml_dsa_65.verify(
        sender_mldsa_public,
        signed_header,
        base64.b64decode(envelope["ml_dsa_signature"]),
    ):
        raise ValueError("ML-DSA signature rejected")
    classical_public = x25519.X25519PublicKey.from_public_bytes(
        classical_public_bytes
    )
    classical_secret = recipient_x25519_private.exchange(classical_public)
    pqc_secret = ml_kem_768.decrypt(recipient_mlkem_secret, pqc_ciphertext)
    key = _hybrid_key(classical_secret, pqc_secret, task_id)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, task_id.encode())
    return json.loads(plaintext)


def provider_payload(provider: int, index: int) -> dict[str, Any]:
    start = 1_800_000_000 + index * 60
    if provider == 0:
        return {
            "orderId": f"task-{index}",
            "aoi": {"lat": 34.1, "lon": -119.2, "radiusKm": 8},
            "start": start,
            "end": start + 900,
        }
    if provider == 1:
        return {
            "request_id": f"task-{index}",
            "geometry": "hash:4b2d",
            "window": [start, start + 900],
            "mode": "spotlight",
        }
    if provider == 2:
        return {
            "mission": {"id": f"task-{index}", "priority": "urgent"},
            "target": [34.1, -119.2],
            "collect_after": start,
            "collect_before": start + 900,
        }
    return {
        "task": f"task-{index}",
        "collection": {
            "center": {"latitude": 34.1, "longitude": -119.2},
            "earliest": start,
            "latest": start + 900,
        },
    }


def normalize_provider_payload(provider: int, payload: dict[str, Any]) -> dict[str, Any]:
    if provider == 0:
        task_id = payload["orderId"]
        start, end = payload["start"], payload["end"]
    elif provider == 1:
        task_id = payload["request_id"]
        start, end = payload["window"]
    elif provider == 2:
        task_id = payload["mission"]["id"]
        start, end = payload["collect_after"], payload["collect_before"]
    else:
        task_id = payload["task"]
        start = payload["collection"]["earliest"]
        end = payload["collection"]["latest"]
    return {
        "task_id": task_id,
        "provider_adapter": provider,
        "classification_boundary": "CUI-IL5-surrogate",
        "collection_window": [start, end],
        "area_commitment": hashlib.sha384(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest(),
        "return_data_required": True,
    }


class HybridTaskGateway:
    def __init__(self) -> None:
        self.x25519_private = x25519.X25519PrivateKey.generate()
        self.mlkem_public, self.mlkem_secret = ml_kem_768.generate_keypair()
        self.sender_ed25519_private = ed25519.Ed25519PrivateKey.generate()
        self.sender_mldsa_public, self.sender_mldsa_secret = (
            ml_dsa_65.generate_keypair()
        )
        self.government_return_x25519_private = x25519.X25519PrivateKey.generate()
        (
            self.government_return_mlkem_public,
            self.government_return_mlkem_secret,
        ) = ml_kem_768.generate_keypair()
        self.provider_return_ed25519_private = ed25519.Ed25519PrivateKey.generate()
        (
            self.provider_return_mldsa_public,
            self.provider_return_mldsa_secret,
        ) = ml_dsa_65.generate_keypair()
        self.seen: set[str] = set()
        self.evidence = EvidenceChain(b"nv062-trl4")

    def seal(self, payload: dict[str, Any]) -> dict[str, str]:
        return seal_hybrid_task(
            payload,
            self.x25519_private.public_key(),
            self.mlkem_public,
            self.sender_ed25519_private,
            self.sender_mldsa_secret,
        )

    def open_once(self, envelope: dict[str, str]) -> dict[str, Any]:
        payload = open_hybrid_task(
            envelope,
            self.x25519_private,
            self.mlkem_secret,
            self.sender_ed25519_private.public_key(),
            self.sender_mldsa_public,
        )
        task_id = payload["task_id"]
        if task_id in self.seen:
            raise ValueError("replay detected")
        self.seen.add(task_id)
        self.evidence.append(
            "NV062",
            {
                "task_id": task_id,
                "provider_adapter": payload["provider_adapter"],
                "accepted": True,
            },
        )
        return payload


def run_gateway_http_integration(
    gateway: HybridTaskGateway,
    tasks: int = 120,
) -> dict[str, Any]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            try:
                payload = gateway.open_once(body)
                return_payload = {
                    "task_id": payload["task_id"],
                    "provider_adapter": payload["provider_adapter"],
                    "return_type": "collection-status-and-data-commitment",
                    "status": "accepted",
                    "data_commitment": hashlib.sha384(
                        f'return:{payload["task_id"]}'.encode()
                    ).hexdigest(),
                }
                return_envelope = seal_hybrid_task(
                    return_payload,
                    gateway.government_return_x25519_private.public_key(),
                    gateway.government_return_mlkem_public,
                    gateway.provider_return_ed25519_private,
                    gateway.provider_return_mldsa_secret,
                )
                response = {
                    "accepted": True,
                    "task_id": payload["task_id"],
                    "return_envelope": return_envelope,
                }
                status = 200
            except Exception as error:
                response = {"accepted": False, "error": type(error).__name__}
                status = 400
            encoded = json.dumps(response).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *_: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/task"
    latencies: list[float] = []
    accepted = 0
    return_verified = 0
    envelopes: list[dict[str, str]] = []
    try:
        for index in range(tasks):
            payload = normalize_provider_payload(index % 4, provider_payload(index % 4, index))
            started = time.perf_counter_ns()
            envelope = gateway.seal(payload)
            request = urllib.request.Request(
                url,
                data=json.dumps(envelope).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                result = json.load(response)
            accepted += int(result["accepted"])
            returned = open_hybrid_task(
                result["return_envelope"],
                gateway.government_return_x25519_private,
                gateway.government_return_mlkem_secret,
                gateway.provider_return_ed25519_private.public_key(),
                gateway.provider_return_mldsa_public,
            )
            return_verified += int(
                returned["task_id"] == payload["task_id"]
                and returned["status"] == "accepted"
            )
            latencies.append((time.perf_counter_ns() - started) / 1000.0)
            envelopes.append(envelope)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return {
        "tasks": tasks,
        "accepted": accepted,
        "return_data_verified": return_verified,
        "p50_us": percentile(latencies, 0.50),
        "p95_us": percentile(latencies, 0.95),
        "p99_us": percentile(latencies, 0.99),
        "max_us": max(latencies),
        "envelopes": envelopes,
    }


def run_nv062_trl4(seed: int = 62) -> dict[str, Any]:
    del seed
    gateway = HybridTaskGateway()
    integration = run_gateway_http_integration(gateway)
    tamper_blocked = 0
    tamper_cases = 30
    for original in integration["envelopes"][:tamper_cases]:
        modified = dict(original)
        ciphertext = bytearray(base64.b64decode(modified["ciphertext"]))
        ciphertext[len(ciphertext) // 2] ^= 1
        modified["ciphertext"] = base64.b64encode(ciphertext).decode()
        try:
            open_hybrid_task(
                modified,
                gateway.x25519_private,
                gateway.mlkem_secret,
                gateway.sender_ed25519_private.public_key(),
                gateway.sender_mldsa_public,
            )
        except Exception:
            tamper_blocked += 1

    replay_blocked = 0
    replay_cases = 30
    for envelope in integration["envelopes"][:replay_cases]:
        try:
            gateway.open_once(envelope)
        except ValueError:
            replay_blocked += 1

    return {
        "hybrid_crypto": {
            "classical_kem": "X25519",
            "pqc_kem": "ML-KEM-768 / FIPS 203",
            "classical_signature": "Ed25519",
            "pqc_signature": "ML-DSA-65 / FIPS 204",
            "aead": "AES-256-GCM",
            "kdf": "HKDF-SHA384",
        },
        "provider_adapters": 4,
        "http_integration": {
            key: value
            for key, value in integration.items()
            if key != "envelopes"
        },
        "adversarial": {
            "tamper_cases": tamper_cases,
            "tamper_blocked": tamper_blocked,
            "replay_cases": replay_cases,
            "replay_blocked": replay_blocked,
        },
        "evidence": {
            "records": len(gateway.evidence.records),
            "head": gateway.evidence.head,
            "verified": EvidenceChain.verify(
                gateway.evidence.records,
                gateway.evidence.public_key,
            ),
            "tamper_detected": tamper_test(
                gateway.evidence.records,
                gateway.evidence.public_key,
            ),
        },
        "workflow_model": {
            "manual_baseline_hours": 336.0,
            "automated_p95_hours": 28.5,
            "reduction_pct": 91.52,
            "status": "modeled, not measured against a commercial provider",
        },
    }
