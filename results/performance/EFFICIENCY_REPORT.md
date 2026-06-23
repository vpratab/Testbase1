# Native Kernel Efficiency Report

Host: `macOS-26.1-arm64-arm-64bit`

This is a release-mode host measurement, not target-hardware worst-case
execution-time evidence.

| Measurement | Result |
| --- | ---: |
| Evidence update | 87.8 ns/op |
| Custody and priority | 5.2 ns/op |
| Authenticated track decode mean / batch-p99 | 972.2 / 1026.2 ns |
| 240-candidate schedule mean / batch-p99 | 3190.9 / 3640.8 ns |
| 1,000-object association mean / batch-p99 | 342.3 / 355.8 us |
| 10,000-object sparse association | 4.53 ms/update |
| 3,840-candidate bounded schedule | 219.9 us/update |
| Authenticated track frame | 136 bytes |
| Release executable | 441.2 KiB |

The verification gate is intentionally loose enough to tolerate shared CI
hosts while still detecting major regressions. Representative x86 and ARM
hardware profiling remains a Phase I transition task. Percentiles are computed
over repeated batch-average measurements and are not WCET proofs.
