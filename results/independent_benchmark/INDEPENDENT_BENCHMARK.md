# Independent Repeated Native Benchmark

Generated: `2026-06-23T05:53:05.238888+00:00`

- Host: `macOS-26.1-arm64-arm-64bit`
- Machine: `arm64`
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Executable SHA-256: `27fe1adcd9d14a44618e6e1b7372c559c92342505a7f14a128767b77d7f32ad8`
- Source-tree SHA-256: `69e6b503d6afb1495c3d9f882b881bbdcdd5c7eac3a43ccff3e7814606f63411`

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
| Authenticated 136-byte decode | 1.013 us | 1.708 us | 2.002 us | 23.3% |
| 240-candidate schedule | 3.324 us | 6.542 us | 24.137 us | 101.7% |
| 1,000-object association | 361.577 us | 773.837 us | 1.171 ms | 46.3% |
| 10,000-object association | 4.758 ms | 7.839 ms | 7.839 ms | 16.1% |
| 3,840-candidate schedule | 235.883 us | 257.429 us | 257.429 us | 4.7% |

Median benchmark-process wall time was
`297.12 ms`; median scaling-process wall time was
`83.72 ms`.

## Sanity gates

These intentionally loose gates detect catastrophic regressions on a shared
host. They are not sponsor acceptance criteria.

| Gate | Result | Evidence |
| --- | --- | --- |
| deterministic_conformance | PASS | 20 independent processes agreed |
| authenticated_decode | PASS | process p95 1.708 us < 50 us |
| bounded_scheduler | PASS | 3,840-candidate process p95 257.429 us < 5 ms |
| sparse_association | PASS | 10,000-object process p95 7.839 ms < 50 ms |

## Interpretation limits

This benchmark establishes executable feasibility and run-to-run behavior on
this host. It does not establish target-platform WCET, real-time scheduling,
end-to-end sensor latency, power/thermal performance, dense-clutter tracking
quality, or operational mission effectiveness. The association geometry is
spatially gated and favorable. A representative Linux x86/ARM hardware matrix,
CPU pinning, fixed power state, memory profiling, dense-crossing accuracy, and
sponsor data remain required.
