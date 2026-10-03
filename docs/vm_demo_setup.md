# NetSentry AI VM demonstration setup and validation guide

## Purpose

This guide prepares the final undergraduate FYP demonstration environment. It is platform-neutral because the VM platform, virtual network mode, VM operating systems, and monitoring interface have not yet been selected.

This document is preparation only. Do not mark any live VM result as passed until the authorised environment exists and the checklist below has been completed.

## Planned topology

```text
                    Windows host
       ┌────────────────────────────────┐
       │ AI-NIDS                         │
       │ Flask · MySQL · TShark          │
       │ Random Forest                   │
       └───────────────┬────────────────┘
                       │ AI-NIDS-visible interface
                Authorised virtual network
                       │
              ┌────────┴────────┐
              │                 │
       VM 1: normal client  VM 2: normal service
                       │
                  Benign traffic
```

## Environment placeholders

| Item | Current value |
|---|---|
| VM platform | **TO BE SELECTED** |
| Virtual network mode | **TO BE SELECTED** |
| AI-NIDS-visible interface | **TO BE DISCOVERED** |
| VM 1 | **TO BE CONFIGURED** |
| VM 2 | **TO BE CONFIGURED** |

The selected virtual network must allow authorised VM communication, provide host capture visibility where required, remain isolated from unnecessary external systems, and be repeatable for an examiner. Host-only, internal, NAT, and bridged modes do not all expose VM-to-VM traffic to host TShark in the same way; confirm actual visibility after setup.

## Safety boundary

Use ordinary authorised traffic only: normal web access to an authorised local service, DNS where appropriate, an ordinary TCP connection, simple client/server communication, or permitted ICMP connectivity verification.

Do not use scans, brute force, denial-of-service, exploit activity, malware, offensive tools, active host discovery, or unauthorised traffic interception.

## Interface discovery

The monitoring interface ID is not known in advance and must never be committed to source control.

1. Start MySQL and the AI-NIDS backend.
2. Sign in with an authorised account.
3. Record available interfaces from `GET /api/capture/interfaces` before configuring VM networking.
4. Configure and start the selected VM environment.
5. List interfaces again.
6. Identify the virtual adapter associated with the authorised lab.
7. Confirm the adapter is authorised for capture.
8. Start a manual capture and generate ordinary VM traffic.
9. Confirm that the packet counter increases, then set `AI_NIDS_MONITOR_INTERFACE` to the discovered TShark ID.

## Monitoring modes

### Manual setup and troubleshooting

```dotenv
AI_NIDS_AUTO_MONITORING=false
AI_NIDS_MONITOR_INTERFACE=
```

Use this mode first to verify the correct interface through Manual AI Capture before enabling automatic capture.

### Final FYP demonstration

```dotenv
AI_NIDS_AUTO_MONITORING=true
AI_NIDS_MONITOR_INTERFACE=<validated-virtual-network-TShark-ID>
```

Save these values in the local `backend/.env` file, not source control. The reusable example is `backend/.env.example`.

## Three AI monitoring workflows

- **Live Sensor** (`pages/live-sensor.html`): autonomous IDS-style observation when `AI_NIDS_AUTO_MONITORING=true` and a validated interface is configured. It does not require manual interface selection during normal operation.
- **Manual AI Capture** (`pages/manual-capture.html`): user-controlled selection, Start, and Stop for authorised interface troubleshooting/testing. It cannot start a second session while the autonomous sensor is running.
- **AI Detection** (`pages/ai-detection.html`): existing offline `.pcap`/`.pcapng` upload and AI analysis.

All workflows reuse the existing Random Forest, 20 runtime features, flow aggregator, threat policy, persistence, and result APIs. They differ only in traffic source and start/control method.

## Benign live validation

After the VMs are configured:

1. Start both authorised VMs if two are used.
2. Confirm normal VM communication.
3. Start AI-NIDS in manual mode first, or restart in autonomous mode after interface validation.
4. Generate ordinary authorised client/service activity.
5. Open Manual AI Capture for a manual session, or Live Sensor for autonomous observation, and verify packets, active flows, completed flows, and AI predictions.
6. Confirm BENIGN results do not create threat records.
7. Check Connected Devices only if private RFC1918 IP and MAC metadata is visible; do not fabricate device records.
8. Check Security Logs for the monitoring lifecycle event.
9. Check Dashboard, Threat Alerts, Analytics, and Reports remain truthful.
10. Stop monitoring and verify remaining flows flush, then verify TShark and the worker terminate.
11. Start monitoring once more to verify clean restart.

AI-NIDS makes predictions for completed flows, not individual packets. A flow may wait for both TCP FIN packets, its timeout, or a Stop flush before inference appears.

## Future live-validation checklist

- [ ] VM platform identified
- [ ] Virtual network identified
- [ ] VM 1 started
- [ ] VM 2 started if used
- [ ] VM communication works
- [ ] TShark interface discovered
- [ ] Correct monitoring interface selected
- [ ] AI-NIDS starts
- [ ] Random Forest loads once
- [ ] Monitoring starts
- [ ] Exactly one TShark capture session
- [ ] Exactly one monitoring worker
- [ ] Packet counter increases
- [ ] Active flows appear
- [ ] Completed flows appear
- [ ] AI predictions appear
- [ ] BENIGN traffic is not persisted as a threat
- [ ] Connected Devices updates if private IP/MAC metadata is visible
- [ ] Security Logs records monitoring lifecycle
- [ ] Dashboard updates
- [ ] Threat Alerts remains truthful
- [ ] Analytics remains truthful
- [ ] Reports remain functional
- [ ] Stop flushes remaining flows
- [ ] TShark terminates
- [ ] Worker terminates
- [ ] Monitoring restarts cleanly

## Expected versus actual results

| Validation | Expected | Actual | Status |
|---|---|---|---|
| VM communication | Works | NOT TESTED | Pending |
| TShark visibility | Packets visible | NOT TESTED | Pending |
| Packet counter | Increases | NOT TESTED | Pending |
| Flow aggregation | Flows appear | NOT TESTED | Pending |
| AI inference | Predictions appear | NOT TESTED | Pending |
| BENIGN persistence | No threat row | NOT TESTED | Pending |
| Device observation | Updates when metadata is visible | NOT TESTED | Pending |
| Security logging | Lifecycle events recorded | NOT TESTED | Pending |
| Clean stop | Worker and TShark stop | NOT TESTED | Pending |

## Troubleshooting

### TShark interface is not visible

Check the TShark interface listing, selected VM adapter, whether the network mode is host-visible, capture permissions, and TShark installation. Do not create adapters or reconfigure VM networking from AI-NIDS.

### Packet count remains zero

Check the selected interface, VM communication, virtual network mode, and monitoring state. Return to manual mode to verify the interface before enabling autonomous mode.

### Packets appear but no immediate flows/predictions

This is expected for flow-based inference. Wait for a valid TCP teardown or configured timeout, or use Stop Monitoring to flush remaining eligible flows.

### Connected Devices remains empty

Stage 5I requires a private RFC1918 IPv4 address and MAC metadata. The virtual platform may not expose suitable metadata. Do not create fake devices.

### Threat Alerts remains empty

Normal benign VM traffic may produce no malicious detection. This is expected. Do not generate attacks merely to populate the page.

### A classification differs from expectation

Live traffic differs from CIC-IDS2017. A model result is a prediction, not confirmed ground truth.

## Examiner demonstration sequence

1. Show login.
2. Show the Dashboard before monitoring.
3. Show the authorised VM environment.
4. Show the discovered/configured monitoring interface.
5. Start AI-NIDS or show autonomous sensor status.
6. Generate normal authorised VM activity.
7. Show Live Sensor counters, flows, and predictions (or Manual AI Capture when demonstrating a manual session).
8. Show Connected Devices if metadata is available.
9. Show Security Logs.
10. Show Dashboard and Analytics.
11. Show safe threat evidence separately.
12. Show Threat Alerts and Reports.
13. Show offline PCAP analysis.
14. Stop monitoring and demonstrate clean shutdown if appropriate.

## Threat evidence is separate from the live VM test

The live VM sensor demonstration is for capture, flow aggregation, normal AI operation, passive devices, logs, and dashboard updates. Show PortScan, FTP-Patator, SSH-Patator, and DDoS evidence using the existing held-out CIC-IDS2017 validation, controlled feature rows, authorised prepared PCAP evidence, or Stage 5H results. Do not claim malicious traffic was generated in the VM environment.

## Future real-switch migration

Keep [deployment_environments.md](deployment_environments.md) for the later migration:

```text
FYP VM demo: virtual network → AI-NIDS-visible interface
Real deployment: managed switch → SPAN/mirror → AI-NIDS monitoring NIC
```

`FlowAggregator`, the 20 features, Random Forest, `FlowPredictor`, `ThreatPriority`, `ThreatPersistence`, Dashboard, Analytics, and Reports remain unchanged.
