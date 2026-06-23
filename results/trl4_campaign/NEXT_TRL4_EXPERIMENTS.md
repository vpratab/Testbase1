# Highest-Value Next Experiments

These are the shortest paths to raising each measured match score. Estimated
point gains refer to the current 100-point requirement rubric.

| Topic | Current | Next decisive experiment | Potential gain |
| --- | ---: | --- | ---: |
| NV061 | 83.6 | Fuse NOAA AIS with a second track source, introduce uncertain identity/association, and evaluate custody plus hierarchy on held-out mixed-domain tracks | +6 to +10 |
| NV059 | 83.5 | Add a real OPC-UA or DDS enforcement proxy and process-level network segmentation under delay/loss/partition | +8 to +13 |
| QSPARX | 82.9 | Add endpoint TLS discovery, SSH/keystore/Kubernetes inventory, dependency graphing, and validate on an enterprise-like cyber range | +8 to +12 |
| NV063 | 79.3 | Add ADS-B and notional radar/composite tracks, then reduce AIS watch-level FPR below 10% without recall dropping below 75% | +7 to +11 |
| NV065 | 76.5 | Replace invented sensor parameters with traceable open-literature radar/task models and enforce beam/dwell/search/illumination conflicts | +10 to +16 |
| NV062 | 76.3 | Connect one commercial imagery/provider sandbox API and exercise encrypted return metadata or imagery through the hybrid gateway | +10 to +17 |
| NP002 | 72.1 | Connect a public EO/RF/acoustic UAS dataset, perform target/type classification, and feed real detections into the swarm tracker | +12 to +20 |

## Recommended order

1. **NV059:** real OPC-UA/DDS plus network impairment testing.
2. **QSPARX:** broader live cryptographic discovery connectors.
3. **NV063/NV061 shared:** mixed AIS, ADS-B, and radar track pipeline.
4. **NV062:** one provider sandbox relationship.
5. **NP002:** real sensor dataset and classifier.
6. **NV065:** radar subject-matter expert and traceable sensor models.

The first three upgrades benefit more than one proposal family and produce the
highest evidence return per engineering week.
