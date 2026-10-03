# NetSentry AI

NetSentry AI is an AI-Based Network Intrusion Detection System (AI-NIDS) designed to monitor network traffic, classify supported network threat patterns, and provide security visualization and incident-response support. This undergraduate Final Year Project uses Flask, MySQL, TShark, bidirectional flow aggregation, and a trained Random Forest. It is detection-focused: it does not block traffic or operate as an IPS.

> See [Deployment Environments](docs/deployment_environments.md) for the authorised FYP VM demonstration and future managed-switch sensor deployment guide.

## Architecture

```text
HTML/CSS/JavaScript frontend → Fetch API → Flask REST API → MySQL (ai_nids)
```

Flask also serves the existing frontend, so the browser and API use one local address: `http://127.0.0.1:5000`.

## Technologies

- HTML5, CSS3, vanilla JavaScript, Chart.js
- Python and Flask
- MySQL and MySQL Connector/Python

## Database design

`users`, `network_traffic`, `threats`, `devices`, `security_logs`, `reports`, and `system_settings` are normalized tables with a primary key each. `threats.traffic_id` is an optional foreign key to `network_traffic.traffic_id`: a traffic record can later produce zero or more AI predictions. It remains optional because some demo threats are not tied to one captured flow.

Unique constraints protect username, email, device IP, MAC address, and setting name. Indexes support common timestamp, severity, status, protocol, and IP searches. Passwords are stored as hashes only.

## Setup

1. Install Python 3.10+ and MySQL Server 8+.
2. In a terminal, create and activate a virtual environment:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r backend\requirements.txt
   ```

3. Copy `backend/.env.example` to `backend/.env` and set your MySQL credentials. Do not commit `.env`.
4. Create the database and seed its demo records:

   ```powershell
   mysql -u root -p < database\schema.sql
   mysql -u root -p ai_nids < database\seed.sql
   ```

5. Start the application from the backend folder:

   ```powershell
   cd backend
   python app.py
   ```

6. Browse to `http://127.0.0.1:5000`.

The seed file contains test-only fixture accounts. For LAN use, create or rotate
accounts locally and do not use credentials documented in repository files.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/login` | Session-based demo login |
| POST | `/api/register` | Create a hashed-password user |
| GET | `/api/dashboard/stats` | Dashboard statistics |
| GET | `/api/dashboard/network-activity` | Traffic chart data |
| GET | `/api/dashboard/threat-overview` | Threat chart data |
| GET/POST | `/api/traffic` | List/add traffic records |
| GET | `/api/traffic/<id>` | Retrieve one traffic record |
| GET/POST | `/api/threats` | List/add threats |
| GET/PUT | `/api/threats/<id>` | Retrieve/update a threat status |
| GET/POST | `/api/devices` | List/add devices |
| GET/PUT | `/api/devices/<id>` | Retrieve/update a device |
| GET/POST | `/api/logs` | List/add logs; optional severity/status/event_type filters |
| GET/POST | `/api/reports` | List/create reports |
| GET | `/api/settings` | List settings |
| PUT | `/api/settings/<id>` | Update a setting |

Example test:

```powershell
Invoke-RestMethod http://127.0.0.1:5000/api/dashboard/stats
```

## Frontend integration

Dashboard, Live Sensor, Manual AI Capture, Threat Alerts, Connected Devices, Security Logs, and Reports use `fetch()` through `js/app.js`. Current production pages use the Flask API and show an honest empty or unavailable state when that API is unavailable; they do not fall back to sample records.

The AI Detection page deliberately remains a demo interface. No AI/ML model and no real packet capture are implemented in Stage 2.

## Stage 3: controlled capture and access preparation

Set the local `TSHARK_PATH` in `backend/.env` for the machine running AI-NIDS. The server never accepts arbitrary TShark arguments from the browser. Administrators can start one controlled capture at a time through Manual AI Capture, while AI Detection supports authenticated offline `.pcap` or `.pcapng` analysis. Live capture results are aggregated into completed flows before AI classification.

Before using the new Stage 3 database features, back up MySQL and run this migration once:

```powershell
mysql -u root -p ai_nids < database\migrations\001_stage3_capture_and_access.sql
```

New endpoints include `GET /api/capture/interfaces`, `GET /api/capture/status`, `POST /api/capture/start`, `POST /api/capture/stop`, and `POST /api/pcap/upload`. Capture is intended only for an isolated lab environment that you own or are authorized to monitor.

Public registration has been removed. Administrators create accounts through `POST /api/users`; those users must change their temporary password through `POST /api/change-password`. Password-reset requests are admin-reviewed, with no SMTP service required in this demo stage.

## Known limitations and Stage 4

- MySQL must be running and database migrations must be applied for database-backed workflows.
- `AI_NIDS_AUTO_MONITORING` defaults to `false`; set `AI_NIDS_MONITOR_INTERFACE` only after using the authorised TShark interface listing.
- Capture permissions depend on local Npcap/TShark permissions.
- No switch configuration, active scanning, attack generation, or packet blocking is included.
