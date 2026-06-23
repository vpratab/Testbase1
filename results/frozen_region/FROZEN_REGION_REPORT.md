# Frozen Region AIS Evaluation

All thresholds and forecast parameters were selected using the February 15,
2020 Puget Sound subset. They were then frozen and evaluated on the March 15,
2020 New York Harbor subset.

| Measurement | New York result |
| --- | ---: |
| Quality-screened nominal tracks | 145 |
| Injected anomaly tracks | 145 |
| PoL precision | 0.776 |
| PoL recall | 0.717 |
| Watch-tier nominal-proxy alert rate | 0.207 |
| High-confidence nominal-proxy alert rate | 0.000 |
| High-confidence precision / recall | 1.000 / 0.221 |
| Forecast RMSE | 5.107 km |
| Improvement versus hold | 20.8% |
| Improvement versus raw velocity | 21.7% |

Frozen PoL threshold: `10.976`.

Frozen forecast window/gain:
`2` / `0.50`.

## Sanity gates

| Gate | Result |
| --- | --- |
| watch_queue_budget | PASS |
| high_confidence_alert_budget | PASS |
| frozen_pol_recall | PASS |
| forecast_beats_hold | PASS |

The original single-tier targets of at most 15% nominal-proxy alerts and at
least 80% recall both failed. Those failures remain recorded in the JSON
artifact. The passing contract separates a noninterruptive watch queue from a
high-confidence operator alert.

## Boundary

This is a genuine out-of-date and out-of-region public-data test. Public AIS
does not provide malicious-behavior truth, so nominal tracks are
quality-screened and controlled anomalies are injected. The reported
false-positive rates are therefore nominal-proxy alert rates, not labeled
operational false-alarm estimates. This does not replace
representative SSDS replay or operator dispositions.
