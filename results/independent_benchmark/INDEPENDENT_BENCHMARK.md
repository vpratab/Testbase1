# Independent Repeated Native Benchmark

Generated: `2026-06-23T06:04:35.498251+00:00`

- Host: `macOS-26.1-arm64-arm-64bit`
- Machine: `arm64`
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Executable SHA-256: `27fe1adcd9d14a44618e6e1b7372c559c92342505a7f14a128767b77d7f32ad8`
- Source-tree SHA-256: `8be5f09679cb49634799fb9d420e3733e829272a0bdf35a73bad606c8944de67`

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
| Authenticated 136-byte decode | 1.043 us | 1.154 us | 1.712 us | 14.1% |
| 240-candidate schedule | 3.326 us | 8.436 us | 8.551 us | 39.9% |
| 1,000-object association | 363.503 us | 479.755 us | 775.943 us | 23.6% |
| 10,000-object association | 4.534 ms | 5.984 ms | 5.984 ms | 8.5% |
| 3,840-candidate schedule | 227.733 us | 270.462 us | 270.462 us | 7.8% |

Median benchmark-process wall time was
`297.60 ms`; median scaling-process wall time was
`81.81 ms`.

## Sanity gates

These intentionally loose gates detect catastrophic regressions on a shared
host. They are not sponsor acceptance criteria.

| Gate | Result | Evidence |
| --- | --- | --- |
| deterministic_conformance | PASS | 20 independent processes agreed |
| authenticated_decode | PASS | process p95 1.154 us < 50 us |
| bounded_scheduler | PASS | 3,840-candidate process p95 270.462 us < 5 ms |
| sparse_association | PASS | 10,000-object process p95 5.984 ms < 50 ms |

## Interpretation limits

This benchmark establishes executable feasibility and run-to-run behavior on
this host. It does not establish target-platform WCET, real-time scheduling,
end-to-end sensor latency, power/thermal performance, dense-clutter tracking
quality, or operational mission effectiveness. The association geometry is
spatially gated and favorable. A representative Linux x86/ARM hardware matrix,
CPU pinning, fixed power state, memory profiling, dense-crossing accuracy, and
sponsor data remain required.
