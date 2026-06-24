# Independent Repeated Native Benchmark

Generated: `2026-06-24T19:35:26.181926+00:00`

- Host: `macOS-26.1-arm64-arm-64bit`
- Machine: `arm64`
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Executable SHA-256: `27fe1adcd9d14a44618e6e1b7372c559c92342505a7f14a128767b77d7f32ad8`
- Source-tree SHA-256: `2d4a97b542898b4ccd0c6eeaca7d9168a7ebbf2b75f152a88934b23d8090e0bb`

## Method

- Release binary built once before measurement.
- One unreported warm-up process.
- 15 independent benchmark processes
  at 100,000 iterations.
- 10 independent scaling processes.
- 15 independent conformance
  processes compared for byte-equivalent JSON results.
- Percentiles below are across process-level results, not individual
  operations and not worst-case execution-time bounds.

## Results

| Path | Median | Process p95 | Process max | CV |
| --- | ---: | ---: | ---: | ---: |
| Authenticated 136-byte decode | 965.9 ns | 1.149 us | 1.149 us | 4.8% |
| 240-candidate schedule | 3.224 us | 3.468 us | 3.468 us | 3.1% |
| 1,000-object association | 349.855 us | 445.473 us | 445.473 us | 7.1% |
| 10,000-object association | 4.604 ms | 4.995 ms | 4.995 ms | 2.8% |
| 3,840-candidate schedule | 227.957 us | 302.402 us | 302.402 us | 13.6% |

Median benchmark-process wall time was
`215.33 ms`; median scaling-process wall time was
`82.73 ms`.

## Sanity gates

These intentionally loose gates detect catastrophic regressions on a shared
host. They are not sponsor acceptance criteria.

| Gate | Result | Evidence |
| --- | --- | --- |
| deterministic_conformance | PASS | 15 independent processes agreed |
| authenticated_decode | PASS | process p95 1.149 us < 50 us |
| bounded_scheduler | PASS | 3,840-candidate process p95 302.402 us < 5 ms |
| sparse_association | PASS | 10,000-object process p95 4.995 ms < 50 ms |

## Interpretation limits

This benchmark establishes executable feasibility and run-to-run behavior on
this host. It does not establish target-platform WCET, real-time scheduling,
end-to-end sensor latency, power/thermal performance, dense-clutter tracking
quality, or operational mission effectiveness. The association geometry is
spatially gated and favorable. A representative Linux x86/ARM hardware matrix,
CPU pinning, fixed power state, memory profiling, dense-crossing accuracy, and
sponsor data remain required.
