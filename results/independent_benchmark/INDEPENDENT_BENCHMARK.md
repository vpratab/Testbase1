# Independent Repeated Native Benchmark

Generated: `2026-06-25T22:59:08.508996+00:00`

- Host: `macOS-26.1-arm64-arm-64bit`
- Machine: `arm64`
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Executable SHA-256: `27fe1adcd9d14a44618e6e1b7372c559c92342505a7f14a128767b77d7f32ad8`
- Source-tree SHA-256: `d517e35138e126782270935424719636c577e2c3960270dca9f018156d9eec5e`

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
| Authenticated 136-byte decode | 1.019 us | 1.970 us | 1.970 us | 23.6% |
| 240-candidate schedule | 3.301 us | 4.906 us | 4.906 us | 12.4% |
| 1,000-object association | 363.837 us | 527.428 us | 527.428 us | 12.8% |
| 10,000-object association | 4.493 ms | 5.117 ms | 5.117 ms | 4.7% |
| 3,840-candidate schedule | 236.707 us | 274.175 us | 274.175 us | 8.7% |

Median benchmark-process wall time was
`223.90 ms`; median scaling-process wall time was
`82.54 ms`.

## Sanity gates

These intentionally loose gates detect catastrophic regressions on a shared
host. They are not sponsor acceptance criteria.

| Gate | Result | Evidence |
| --- | --- | --- |
| deterministic_conformance | PASS | 15 independent processes agreed |
| authenticated_decode | PASS | process p95 1.970 us < 50 us |
| bounded_scheduler | PASS | 3,840-candidate process p95 274.175 us < 5 ms |
| sparse_association | PASS | 10,000-object process p95 5.117 ms < 50 ms |

## Interpretation limits

This benchmark establishes executable feasibility and run-to-run behavior on
this host. It does not establish target-platform WCET, real-time scheduling,
end-to-end sensor latency, power/thermal performance, dense-clutter tracking
quality, or operational mission effectiveness. The association geometry is
spatially gated and favorable. A representative Linux x86/ARM hardware matrix,
CPU pinning, fixed power state, memory profiling, dense-crossing accuracy, and
sponsor data remain required.
