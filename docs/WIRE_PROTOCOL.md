# Authenticated Composite-Track Wire Protocol

## Purpose

The wire format replaces the laboratory JSON/Base64 path for measured
high-rate runtime demonstrations. It is intentionally fixed-size, versioned,
network-byte-order, allocation-light, and independently verifiable.

It is not represented as an SSDS interface control document.

## Version 1 frame

| Field | Type | Bytes |
| --- | --- | ---: |
| Magic `ATK1` | four bytes | 4 |
| Version | unsigned 16-bit | 2 |
| Flags | unsigned 16-bit | 2 |
| Sequence | unsigned 64-bit | 8 |
| Track ID | unsigned 64-bit | 8 |
| Source | unsigned 8-bit | 1 |
| Classification | unsigned 8-bit | 1 |
| Reserved | zero bytes | 2 |
| Timestamp | unsigned 64-bit nanoseconds | 8 |
| Position | three float64 values | 24 |
| Velocity | three float32 values | 12 |
| Covariance upper representation | six float32 values | 24 |
| Quality | float32 in `[0, 1]` | 4 |
| Anomaly | float32 in `[0, 1]` | 4 |
| HMAC-SHA-256 | 32 bytes | 32 |
| Total |  | **136** |

Source values currently represent AIS, ADS-B, and radar. Operational source and
classification enumerations must be assigned through the target interface
control process.

## Defensive checks

The native decoder rejects:

- incorrect frame length;
- invalid HMAC;
- incorrect magic or unsupported version;
- non-finite numeric values;
- source identifiers outside the defined set;
- negative covariance components;
- quality or anomaly values outside `[0, 1]`.

A per-stream 64-message anti-replay window accepts bounded reordering while
rejecting duplicates and stale sequences. Larger reorder windows or persistent
stream state can be introduced without changing the frame.

## Independent verification

The Rust binary emits a deterministic test vector:

```bash
cargo run --quiet --release \
  --manifest-path native/assure-kernel/Cargo.toml -- vector
```

`assure_core/wire.py` independently verifies and decodes that vector using
Python's standard-library `struct` and `hmac` modules. Tests mutate bytes across
the frame and require rejection.

## Integration boundary

For Phase I, HMAC provides compact authenticated framing and replay semantics.
Program integration must choose approved key management and transport security:

- DDS Security;
- mTLS;
- IPsec;
- a platform key-management service;
- a hardware-backed key where required.

The wire format does not itself establish authorization, classification
release, or accreditation.
