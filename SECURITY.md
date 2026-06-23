# Security Policy and Research Boundary

## Current status

This repository is a Phase I feasibility and TRL 3-4 research artifact. It is
not accredited, certified, approved for classified processing, or authorized
for operational control of combat systems.

## Supported security reports

Report suspected vulnerabilities privately to the repository owner. Include:

- affected commit and platform;
- reproduction steps;
- whether confidentiality, integrity, availability, authorization, replay, or
  evidence verification is affected;
- a minimal test case where possible.

Do not include classified, export-controlled, personal, credential, or
operational mission data in a report.

## Security properties currently tested

- fixed-length authenticated track framing;
- HMAC verification before parsing;
- invalid length, version, source, probability, covariance, and non-finite
  value rejection;
- per-stream replay-window behavior;
- purpose-bound and single-use task intent;
- expiring offline trust leases;
- certificate challenge and revocation surrogates;
- PQC and classical signature tamper rejection;
- source-manifest and release-artifact hashing;
- Rust formatting, zero-warning Clippy, unit tests, cross-language verification,
  and C ABI execution.

## Out of scope for current claims

- protection against a compromised operating system or hypervisor;
- side-channel resistance;
- production key generation, storage, rotation, escrow, or destruction;
- FIPS 140 validation;
- DISA authorization or IL5/IL6 accreditation;
- SSDS, AFDW, DoD PKI, classified-network, or program-of-record integration;
- RF-layer detection;
- safety certification;
- guaranteed detection of novel attacks;
- external artifact signing and timestamp anchoring.

## Release expectations

A transition release should add:

- signed provenance and externally stored build attestations;
- vulnerability scanning and license review;
- hardware-backed keys;
- target-platform hardening;
- deterministic or hermetic build infrastructure;
- an independent penetration test;
- sponsor-approved incident response and logging policy.
