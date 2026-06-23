# Native Kernel Efficiency Report

Host: `macOS-26.1-arm64-arm-64bit`

This is a release-mode host measurement, not target-hardware worst-case
execution-time evidence.

| Measurement | Result |
| --- | ---: |
| Evidence update | 85.8 ns/op |
| Custody and priority | 5.0 ns/op |
| Authenticated track decode | 972.6 ns/op |
| 240-candidate bounded schedule | 3158.9 ns/op |
| 1,000-object sparse association | 341.8 us/update |
| Authenticated track frame | 136 bytes |
| Release executable | 408.9 KiB |

The verification gate is intentionally loose enough to tolerate shared CI
hosts while still detecting major regressions. Representative x86 and ARM
hardware profiling remains a Phase I transition task.
