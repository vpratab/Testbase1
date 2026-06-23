# Release Readiness Snapshot

## Verified locally

- 65 Python tests passed across core, feasibility, theory, protocol, campaign,
  and robustness suites.
- 9 native Rust tests passed.
- Rust formatting and zero-warning Clippy passed.
- The Rust library compiled and executed through a C program.
- A Rust-generated authenticated-track vector was decoded and tamper-tested by
  an independent Python implementation.
- Python dependency consistency passed.
- Wave 5 and robustness campaigns passed.
- Source, dataset, lockfile, campaign, theory, performance, and scaling
  artifacts have SHA-256 records.

## Measured native performance

Current macOS ARM64 release-host measurements:

| Path | Measurement |
| --- | ---: |
| Authenticated 136-byte track decode | about 1 microsecond mean |
| 240-candidate constrained scheduling | about 3-4 microseconds mean |
| 1,000-object sparse association | about 0.35 milliseconds mean |
| 10,000-object sparse association | about 5.5 milliseconds |
| 3,840-candidate scheduling | about 0.20 milliseconds |

The percentile values in `EFFICIENCY_REPORT.md` are distributions of repeated
batch-average measurements. They reduce timer noise but are not target-hardware
WCET proofs.

## Software supply chain

- 35 lockfile-derived components recorded:
  - 11 Python direct dependencies;
  - 24 Cargo workspace/direct/transitive components.
- Cargo and Python top-level versions are locked.
- A local release manifest binds seven principal artifacts by SHA-256.
- Current inventory is not a vulnerability scan, license legal opinion,
  SLSA attestation, signed provenance statement, or independent timestamp.

## Release blockers before sponsor delivery

- Re-run verification on clean Linux x86_64 and representative ARM hardware.
- Add signed build provenance and independent artifact storage.
- Perform vulnerability and license scans.
- Remove or clearly license any data that cannot be redistributed.
- Obtain export-control and CUI handling review.
- Add sponsor-approved key management and logging profiles.
- Perform an independent technical review and penetration test.
- Obtain external data-access and integration agreements identified in
  `TRANSITION_GATE_CHECKLIST.md`.

## Reproduction

```bash
make bootstrap
make verify
make full
make theory
```

Network-dependent provider tests and external datasets may require connectivity
or separately prepared data.
