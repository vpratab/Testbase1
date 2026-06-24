# Independent Repeated Native Benchmark

Generated: `2026-06-24T05:15:37.119840+00:00`

- Host: `macOS-26.1-arm64-arm-64bit`
- Machine: `arm64`
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Executable SHA-256: `27fe1adcd9d14a44618e6e1b7372c559c92342505a7f14a128767b77d7f32ad8`
- Source-tree SHA-256: `014571f237a5fabbf9fa70f680bcfefaf377cf291cf52998978349afc93d0861`

## Method

- Release binary built once before measurement.
- One unreported warm-up process.
- 20 independent benchmark processes
  at 150,000 iterations.
- 15 independent scaling processes.
- 20 independent conformance
  processes compared for byte-equivalent JSON results.
- Percentiles below are across process-level results, not individual
  operations and not worst-case execution-time bounds.

## Results

| Path | Median | Process p95 | Process max | CV |
| --- | ---: | ---: | ---: | ---: |
| Authenticated 136-byte decode | 1.007 us | 1.045 us | 1.079 us | 3.6% |
| 240-candidate schedule | 3.313 us | 3.342 us | 3.343 us | 2.7% |
| 1,000-object association | 355.610 us | 368.915 us | 387.597 us | 3.9% |
| 10,000-object association | 4.608 ms | 4.895 ms | 4.895 ms | 3.2% |
| 3,840-candidate schedule | 225.775 us | 258.519 us | 258.519 us | 7.0% |

Median benchmark-process wall time was
`288.19 ms`; median scaling-process wall time was
`82.51 ms`.

## Sanity gates

These intentionally loose gates detect catastrophic regressions on a shared
host. They are not sponsor acceptance criteria.

| Gate | Result | Evidence |
| --- | --- | --- |
| deterministic_conformance | PASS | 20 independent processes agreed |
| authenticated_decode | PASS | process p95 1.045 us < 50 us |
| bounded_scheduler | PASS | 3,840-candidate process p95 258.519 us < 5 ms |
| sparse_association | PASS | 10,000-object process p95 4.895 ms < 50 ms |

## Interpretation limits

This benchmark establishes executable feasibility and run-to-run behavior on
this host. It does not establish target-platform WCET, real-time scheduling,
end-to-end sensor latency, power/thermal performance, dense-clutter tracking
quality, or operational mission effectiveness. The association geometry is
spatially gated and favorable. A representative Linux x86/ARM hardware matrix,
CPU pinning, fixed power state, memory profiling, dense-crossing accuracy, and
sponsor data remain required.
