# NP002 Field-Validation Path

## Proposal lane

Position the current technology as a low-cost defensive sensing, track-custody,
identification, and handoff module for an existing C-UAS architecture. Do not
claim a complete neutralization system.

## Credible test-access paths

The FAA currently lists nine UAS Test Sites. The most relevant initial
conversations are:

- Mid-Atlantic Aviation Partnership in Virginia for controlled flight and
  proximity to the DHS Richmond C-UAS testbed;
- New York UAS Test Site for instrumented UAS operations;
- Texas A&M University-Corpus Christi Autonomy Research Institute for a
  coastal/maritime environment;
- Northern Plains UAS Test Site for range-scale operations and environmental
  diversity.

DHS Science and Technology has also conducted live C-UAS demonstrations and
maintains a Richmond urban testbed. These sources establish that controlled,
instrumented defensive C-UAS evaluation is a realistic transition path; they
do not imply access or endorsement.

## Minimum collection

Request a bounded defensive collection with:

- Group 1 and Group 2-or-below cooperative test aircraft;
- synchronized timestamps across available radar, EO/IR, RF, acoustic, and
  Remote ID sources;
- aircraft type, route, altitude, and truth position;
- birds, ground vehicles, benign aircraft, multipath, and background clutter;
- weather and sensor-placement metadata;
- system track identifiers, confidence, latency, drops, and handoff events;
- no payload, engagement, or defeat-control authority.

## Phase I measurements

- detection probability and range by modality;
- classification precision/recall including birds and vehicles;
- track continuity, identity switches, and reacquisition;
- watch/high-confidence alert burden;
- end-to-end observation-to-handoff latency;
- memory, CPU, and power on selected low-cost hardware;
- degradation when one or more modalities are unavailable;
- downstream handoff completeness and freshness.

## Base/Option structure

**Base:** finalize the existing-system interface, ingest a recorded
representative collection, freeze metrics, adapt the native custody kernel,
and demonstrate replayable detection/tracking/identification evidence.

**Option:** run or support an instrumented field collection, profile selected
low-cost hardware, and demonstrate a non-authoritative handoff to the existing
C-UAS command-and-control or defeat subsystem.

## Go condition

NP002 becomes a clean GO proposal when at least one of the following is named
in the proposal:

- a test-site or field-data partner;
- an existing C-UAS system and interface owner;
- a defensive sensor partner able to provide synchronized recorded data.

Without one of those, the technical work remains credible but the transition
story is weaker than the other six proposals.

## Sources

- [FAA UAS Test Site Program](https://www.faa.gov/uas/programs_partnerships/test_sites)
- [FAA UAS Test Site locations](https://www.faa.gov/uas/programs_partnerships/test_sites/locations)
- [DHS Richmond C-UAS Testbed](https://www.dhs.gov/science-and-technology/publication/richmond-counter-uas-testbed-fact-sheet)
- [DHS C-UAS Purchasing Tool](https://www.dhs.gov/science-and-technology/publication/c-uas-purchasing-tool)
- [DHS live C-UAS testing](https://www.dhs.gov/science-and-technology/news/2024/02/27/feature-article-st-tests-cutting-edge-counter-drone-technology)
- [Echodyne defensive radar integration example](https://www.echodyne.com/critical-infrastructure/law-enforcement)
