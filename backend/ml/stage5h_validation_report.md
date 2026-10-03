# AI-NIDS Stage 5H Core Objective Validation

Test date: 2026-09-03

## Scope

This evidence validates the completed AI-NIDS detection pipeline. It does not
retrain the model, generate attack traffic, alter the CIC-IDS2017 dataset, or
change the database schema. Temporary controlled database records use TEST-NET
addresses and are deleted by exact ID after each test.

## System Objectives

1. **Low-cost implementation:** Python, Flask, TShark/Wireshark, MySQL,
   HTML/CSS/JavaScript, Chart.js, and scikit-learn Random Forest are used.
   These are open-source or freely available development components.
2. **Threat-pattern differentiation and prioritisation:** the model returns
   classification and confidence; the central policy separately returns
   severity, priority, and recommended action.
3. **Visual monitoring:** persisted threat data feeds Dashboard, Threat
   Alerts, Analytics, Reports, and the Live Monitoring status/results view.

## Model and Held-Out Evidence

- Algorithm: Random Forest (`n_estimators=80`, class-balanced)
- Runtime features: 20, matching the saved feature schema
- Supported classes: BENIGN, DDoS, FTP-Patator, PortScan, SSH-Patator
- Held-out CIC-IDS2017 test-set size: 190,583 rows
- Held-out accuracy: 99.9071%
- Held-out macro F1: 98.8477%
- Important class-specific limitation: SSH-Patator has the lowest held-out
  recall (93.0127%) and F1 (94.3598%) among the five supported classes.

These are held-out CIC-IDS2017 test-set results, not real-world detection
accuracy claims.

## Representative Runtime Class Matrix

| Expected | Predicted | Confidence | Severity (policy) | Priority (policy) | Result |
|---|---|---:|---|---|---|
| BENIGN | BENIGN | 100.00% | Informational | Monitor | Correct |
| PortScan | PortScan | 100.00% | Medium | Review | Correct |
| FTP-Patator | FTP-Patator | 93.61% | High | Investigate | Correct |
| SSH-Patator | SSH-Patator | 77.56% | High | Investigate | Correct |
| DDoS | DDoS | 100.00% | Critical | Immediate Attention | Correct |

The focused Stage 5H check processed three held-out runtime rows per class
(15 total): 14 were correctly classified. The one representative-sample error
was SSH-Patator predicted as BENIGN; this is recorded rather than hidden.

## Controlled Pipeline and Propagation Evidence

The Stage 5H validation used correct held-out model outputs with temporary
TEST-NET metadata to exercise the real persistence path.

- BENIGN was visible as a model result and stored **zero** threats.
- PortScan, FTP-Patator, SSH-Patator, and DDoS created four threats with
  policy-derived severity, status `New`, confidence, and endpoint metadata.
- Repeating the same four records triggered four deduplication suppressions.
- Threat API returned attack type, confidence, policy fields, recommended
  action, and status consistently.
- Dashboard counts, recent threats, analytics distributions/trend, and the
  period report increased by the expected four threats.
- All temporary threat and report IDs were verified deleted afterward.

## Live Sensor and PCAP Evidence

Stage 5G authorised Wi-Fi sensor observation (autonomous mode) recorded 1,009
packets, 2 flows analysed while active, and 57 flows after stop flush. It
returned 56 BENIGN model outputs and persisted zero threats. One non-port flow
was safely skipped because it could not meet the 20-feature input contract.

The authorised `demo.pcapng` file remains valid for both workflows:

- Stage 3 PCAP upload: 30 packets
- Stage 4 AI PCAP analysis: 22 flows/predictions, all BENIGN, zero threats

Live and PCAP classifications are model outputs, not verified ground-truth
labels for those captures.

## Test Evidence Table

| ID | Scenario | Expected result | Actual result | Status |
|---|---|---|---|---|
| H01 | Model/schema load | 20-feature Random Forest loads | Loaded successfully | PASS |
| H02-H06 | Five representative classes | Classification and policy available | All matrix representatives correct | PASS |
| H07 | BENIGN persistence | No threat insertion | Zero insertions | PASS |
| H08 | Malicious persistence | Four supported classes stored | Four records stored | PASS |
| H09 | Policy consistency | Central policy mapping used | Expected severity/priority returned | PASS |
| H10 | Deduplication | Repeat records suppressed | Four suppressions | PASS |
| H11 | Threat API propagation | Fields remain consistent | API fields verified | PASS |
| H12 | Dashboard propagation | Counts and recent items update | Expected +4 changes | PASS |
| H13 | Analytics propagation | Four aggregations update | Expected distributions/trend | PASS |
| H14 | Report propagation | Persisted threat totals update | Expected +4 / +1 critical | PASS |
| H15 | Manual monitoring | Starts only on request | Verified in Stage 5G | PASS |
| H16 | Autonomous monitoring | Configured sensor starts once | Verified in Stage 5G | PASS |
| H17 | Live status | Safe counters/results available | Verified in Stages 5F-5G | PASS |
| H18 | PCAP upload | Packet inspection remains separate | 30-packet demo upload | PASS |
| H19 | AI PCAP analysis | Flow predictions returned | 22 BENIGN predictions | PASS |
| H20 | Sensor cleanup | TShark/worker stop | Verified after monitoring stop | PASS |

## Limitations

- CIC-IDS2017 is a controlled dataset; live traffic may have a different
  distribution.
- Only five network-flow classes are supported.
- Inference is near-real-time and flow-based; timeout and FIN behaviour affect
  when a prediction becomes available.
- The system detects supported patterns; it does not block traffic, scan files
  for malware, or guarantee zero-day detection.
- Autonomous monitoring requires a correctly configured authorised interface.
- BENIGN results are intentionally not stored as threat-history records.
- SPAN/mirror-port deployment is an architectural design, not switch hardware
  configuration performed by this project stage.
