# Independent Repeated Native Benchmark

Generated: `2026-06-23T05:24:08.374928+00:00`

- Host: `macOS-26.1-arm64-arm-64bit`
- Machine: `arm64`
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Executable SHA-256: `27fe1adcd9d14a44618e6e1b7372c559c92342505a7f14a128767b77d7f32ad8`
- Source-tree SHA-256: `fdbe1ddf62ca0ed7874da146afb9c7db9a428673199e866c933ac22b8cb946b4`

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
| Authenticated 136-byte decode | 1.018 us | 1.217 us | 1.304 us | 7.9% |
| 240-candidate schedule | 3.324 us | 4.395 us | 5.778 us | 17.7% |
| 1,000-object association | 363.098 us | 441.299 us | 532.496 us | 11.5% |
| 10,000-object association | 4.394 ms | 5.144 ms | 5.144 ms | 5.5% |
| 3,840-candidate schedule | 215.960 us | 381.708 us | 381.708 us | 20.0% |

Median benchmark-process wall time was
`296.55 ms`; median scaling-process wall time was
`78.49 ms`.

## Sanity gates

These intentionally loose gates detect catastrophic regressions on a shared
host. They are not sponsor acceptance criteria.

| Gate | Result | Evidence |
| --- | --- | --- |
| deterministic_conformance | PASS | 20 independent processes agreed |
| authenticated_decode | PASS | process p95 1.217 us < 50 us |
| bounded_scheduler | PASS | 3,840-candidate process p95 381.708 us < 5 ms |
| sparse_association | PASS | 10,000-object process p95 5.144 ms < 50 ms |

## Interpretation limits

This benchmark establishes executable feasibility and run-to-run behavior on
this host. It does not establish target-platform WCET, real-time scheduling,
end-to-end sensor latency, power/thermal performance, dense-clutter tracking
quality, or operational mission effectiveness. The association geometry is
spatially gated and favorable. A representative Linux x86/ARM hardware matrix,
CPU pinning, fixed power state, memory profiling, dense-crossing accuracy, and
sponsor data remain required.
