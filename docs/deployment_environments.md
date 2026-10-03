# NetSentry AI deployment environments

## Purpose

NetSentry AI is a detection-focused AI-Based Network Intrusion Detection System (AI-NIDS). It observes authorised traffic, aggregates packets into bidirectional flows, classifies supported network-flow patterns, applies the existing threat policy, and presents/persists the resulting data. It does not block traffic and is not an IPS.

This guide separates the undergraduate FYP demonstration environment from a future managed-switch deployment. The traffic source and monitoring interface change between environments; the AI detection pipeline does not.

## Environment comparison

| Component | FYP VM demonstration | Real deployment |
|---|---|---|
| Traffic source | Authorised virtual-network traffic | Authorised company-network traffic |
| Traffic copy | Virtual networking visibility | Managed-switch SPAN/mirror copy |
| Sensor interface | VM/lab-visible NIC | NIC connected to mirror destination port |
| AI pipeline | Same | Same |
| ML model | Same Random Forest | Same Random Forest |
| Dashboard and reports | Same | Same |
| Configuration change | Interface ID | Interface ID plus switch configuration |

## FYP VM demonstration architecture

```text
                 Windows host
┌──────────────────────────────────────────────┐
│ AI-NIDS: Flask + MySQL + TShark               │
│                     │                         │
└─────────────────────┼─────────────────────────┘
                      │ monitoring interface
              Authorised virtual network
                      │
              ┌───────┴────────┐
              │                │
       VM 1: normal client   VM 2: test/service
```

Only ordinary authorised traffic should be used: normal web access, DNS, TCP connections, benign service/file access, or VM-to-VM communication. Do not use brute force, denial-of-service, scanning, exploit, or penetration-testing traffic.

The VM platform is intentionally not prescribed. Configure the eventual virtual networking platform only after it is selected and authorised.

## Real managed-switch deployment architecture

```text
Normal network ports
        ↓
Managed switch
        ↓ copies approved traffic through SPAN/mirror
Mirror destination port
        ↓
AI-NIDS monitoring NIC
        ↓
TShark → Flow Aggregator → 20 runtime features → Random Forest
       → Threat Policy → Persistence → Dashboard / Alerts / Analytics / Reports
```

The switch copies traffic. AI-NIDS only observes the copy. AI-NIDS does not configure the switch automatically, change routes/firewall rules, or block traffic.

For production, a management interface may provide Flask/dashboard access while a separate monitoring interface receives mirror traffic. The FYP VM demonstration may use one interface when that is the authorised available design.

## FYP VM DEMO → REAL SWITCH MIGRATION

### Change

- Network topology: virtual network becomes managed-switch traffic copy.
- Monitoring interface: select the NIC receiving the current environment's traffic.
- `AI_NIDS_MONITOR_INTERFACE`: set it to that NIC's TShark interface ID.
- Real deployment only: have an authorised network administrator configure SPAN/mirror and connect its destination port to the monitoring NIC.

### Do not change the AI pipeline

Do **not** change any of the following when moving environments:

- Random Forest model
- 20-feature schema
- `FlowAggregator`
- `FlowPredictor`
- `ThreatPriority`
- `ThreatPersistence`
- Threat database logic
- Dashboard, Analytics, Reports, or AI PCAP analysis

Only the authorised traffic source and selected monitoring interface change.

## Configuration

Use the existing settings in `backend/.env`:

```dotenv
# Manual/development mode: application starts idle.
AI_NIDS_AUTO_MONITORING=false

# FYP VM sensor mode: choose the VM/lab monitoring interface ID discovered by TShark.
AI_NIDS_AUTO_MONITORING=true
AI_NIDS_MONITOR_INTERFACE=<VM-or-lab-TShark-interface-ID>

# Real switch sensor mode: choose the monitoring NIC connected to the mirror port.
AI_NIDS_AUTO_MONITORING=true
AI_NIDS_MONITOR_INTERFACE=<mirror-NIC-TShark-interface-ID>
```

Never hardcode an interface number. Interface IDs differ across computers, VM platforms, adapters, and deployments.

## Interface discovery and health verification

1. Start MySQL and AI-NIDS.
2. Sign in with an authorised account.
3. Retrieve `GET /api/capture/interfaces` or use the Manual AI Capture selector.
4. Identify the interface associated with the authorised VM/lab network or mirror NIC.
5. Set `AI_NIDS_MONITOR_INTERFACE` in `backend/.env`.
6. Set `AI_NIDS_AUTO_MONITORING=true` only when autonomous sensor mode is intended.
7. Restart AI-NIDS and check `GET /api/capture/status`.
8. Confirm the selected interface is correct, one capture session and one worker are active, and the packet counter changes when authorised traffic exists.

If the interface is unavailable, Flask remains available and reports a safe sensor configuration error. Correct the configuration, then start monitoring manually or restart the application.

## Startup procedures

### FYP VM demonstration

1. Start MySQL.
2. Start the authorised VM(s) and confirm their virtual network.
3. Start AI-NIDS and verify that the model loaded.
4. List TShark interfaces and identify the authorised VM/lab interface.
5. Configure autonomous monitoring if desired, or select the interface and use manual Start Monitoring.
6. Verify the status page shows mode, interface, packet count, active flows, and analysed flows.
7. Generate only normal authorised VM traffic.
8. Observe BENIGN model outputs where applicable, dashboard data, passive Connected Devices entries, and Security Logs.

### Real switch deployment

1. An authorised network administrator configures SPAN/mirror on the confirmed managed switch.
2. Connect the mirror destination port to the AI-NIDS monitoring NIC.
3. Confirm the monitoring NIC appears in `GET /api/capture/interfaces`.
4. Set `AI_NIDS_MONITOR_INTERFACE` to its displayed TShark ID.
5. Set `AI_NIDS_AUTO_MONITORING=true`.
6. Start the AI-NIDS service.
7. Verify copied traffic reaches TShark, then verify flow analysis and dashboard data.

## Shutdown procedure

```text
Stop Monitoring → flush remaining flows → final eligible inference
→ monitoring worker stops → TShark terminates → application can stop safely
```

The existing Stop action is also a maintenance control in autonomous mode. It does not auto-restart capture within the same application session after an operator deliberately stops it.

## Sensor health checklist

- MySQL, Flask/dashboard, model, and TShark are available.
- The configured interface is valid and the autonomous/manual mode is correct.
- Exactly one TShark session and one monitoring worker are active.
- Packet counter increases when authorised traffic exists; active and completed flows appear.
- Dashboard, Threat Alerts, Analytics, Reports, Security Logs, and Connected Devices are available.

## Connected Devices and Security Logs

Connected Devices uses passive observation only. A device is recorded only when captured traffic provides both an RFC1918 private IPv4 address and MAC address; no probes or scans are sent. Uncertain device types remain `Unknown`.

Security Logs records meaningful application events such as authentication, monitoring lifecycle events, persisted malicious detections, and PCAP analysis. It does not create a log entry for every packet.

## Live and offline evidence

Live mode demonstrates the sensor pipeline with authorised traffic:

```text
VM/lab traffic or switch-mirror traffic → continuous sensor monitoring
```

Offline mode remains separate:

```text
PCAP upload → AI flow analysis
```

Supported threat-class evidence (PortScan, FTP-Patator, SSH-Patator, DDoS) must be presented through held-out CIC-IDS2017 samples, controlled backend validation rows, or authorised prepared PCAP evidence. Do not claim these classes were generated live unless verified evidence exists.

## Real switch configuration — future deployment

No vendor-specific commands are included. Before adding them, confirm the switch manufacturer, model, firmware/operating system, source port(s) or VLAN, destination mirror port, and required direction (ingress, egress, or both).

## Known limitations

- No VM platform was configured or tested from this workspace.
- No physical switch/SPAN session was configured or tested.
- Capture visibility depends on the authorised virtual network or mirror configuration.
- The model supports only its trained flow classes and remains detection-focused.
- AI-NIDS does not scan devices, inspect malware files, block traffic, or detect every possible/zero-day attack.
