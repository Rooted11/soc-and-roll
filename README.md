# AI-Powered Security Operations Center (AI-SOC)

A fully functional, end-to-end SOC prototype with:

- **AI/ML anomaly detection** — Isolation Forest scores every log event
- **Automated playbooks** — isolate host, revoke credentials, block IP, send alerts
- **Threat intelligence** — multi-feed IOC ingestion and correlation
- **Decision support dashboard** — React UI with incidents, trends, and AI advisor
- **Executive report generation** — one-click AI-generated reports

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Docker Compose                       │
│                                                         │
│  ┌──────────┐    REST API    ┌──────────────────────┐   │
│  │  React   │ ◄────────────► │  FastAPI Backend     │   │
│  │ Frontend │                │  ┌────────────────┐  │   │
│  │  :3000   │                │  │ Isolation      │  │   │
│  └──────────┘                │  │ Forest ML      │  │   │
│                              │  ├────────────────┤  │   │
│                              │  │ Playbook       │  │   │
│                              │  │ Executor       │  │   │
│                              │  ├────────────────┤  │   │
│                              │  │ Threat Intel   │  │   │
│                              │  │ Correlator     │  │   │
│                              │  └────────────────┘  │   │
│                              │         │            │   │
│                              └─────────┼────────────┘   │
│                                        │                │
│                              ┌─────────▼────────────┐   │
│                              │  PostgreSQL :5432     │   │
│                              └──────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Docker + Docker Compose)
- Git

### 1. Clone / enter the project

```bash
cd ai-soc
```

### 2. Start all services

```bash
docker compose up --build
```

First build takes ~2-3 minutes (Python deps + npm install). Subsequent starts are fast.

### 3. Seed the database with sample data

In a second terminal:

```bash
docker compose exec backend python /data/../scripts/init_db.py
```

Or directly via Python (if you have Python 3.10+ locally):

```bash
python scripts/init_db.py
```

### 4. Open the dashboard

```
http://localhost:3000
```

### 5. Simulate live log traffic

```bash
# Send 3 logs every 5 seconds (mix of normal + attack events)
python scripts/simulate_logs.py

# One-shot batch (useful for testing)
python scripts/simulate_logs.py --once --count 20

# Custom rate
python scripts/simulate_logs.py --interval 2 --count 5
```

### 6. Regenerate threat feed

```bash
python scripts/simulate_threat_feed.py --count 50 --push-url http://localhost:8000
```

---

## API Reference

The FastAPI backend exposes an automatic interactive API explorer at:

```
http://localhost:8000/docs
```

### Key endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/logs/ingest` | Ingest log batch → auto anomaly score + incident creation |
| GET  | `/api/logs` | Paginated log list with filters |
| GET  | `/api/logs/stats` | Log summary statistics |
| GET  | `/api/incidents` | Paginated incident list |
| GET  | `/api/incidents/stats` | Dashboard statistics + 7-day trend |
| GET  | `/api/incidents/{id}` | Full incident detail |
| PATCH| `/api/incidents/{id}` | Update status / severity |
| POST | `/api/incidents/{id}/respond` | Trigger or override a playbook |
| GET  | `/api/incidents/{id}/actions` | Playbook audit log |
| GET  | `/api/threat-intel` | Threat indicators + landscape summary |
| POST | `/api/threat-intel/refresh` | Pull fresh IOCs |
| GET  | `/api/assets` | Internal asset inventory |

---

## Folder Structure

```
ai-soc/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI app, lifespan, middleware
│   │   ├── routes/
│   │   │   ├── logs.py              # Log ingestion & analysis endpoints
│   │   │   └── incidents.py         # Incident, playbook & threat-intel endpoints
│   │   └── services/
│   │       ├── database.py          # SQLAlchemy models + session helpers
│   │       ├── anomaly_detection.py # Isolation Forest ML pipeline
│   │       ├── playbook.py          # Automated response playbooks
│   │       └── threat_intel.py      # Feed ingestion, IOC correlation, AI enrichment
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx                  # Root layout + navigation
│   │   ├── main.jsx                 # React entry point
│   │   ├── index.css                # Tailwind base styles
│   │   ├── components/
│   │   │   ├── Dashboard.jsx        # Stats cards, 7-day trend, recent incidents
│   │   │   ├── IncidentList.jsx     # Full incident table + detail panel
│   │   │   ├── ThreatTrends.jsx     # IOC table, severity/type bar charts
│   │   │   └── AIAdvisor.jsx        # AI recommendation panel + freeform Q&A
│   │   └── services/
│   │       └── api.js               # All fetch calls to the backend
│   ├── package.json
│   ├── tailwind.config.js
│   ├── vite.config.js
│   ├── Dockerfile
│   └── nginx.conf
├── data/
│   ├── sample_logs.json             # 10 realistic log events (normal + attack)
│   └── dummy_threat_feed.json       # 12 hand-crafted IOCs
├── scripts/
│   ├── simulate_logs.py             # Continuous log generator
│   ├── simulate_threat_feed.py      # Threat feed regenerator
│   └── init_db.py                   # One-shot seed script
├── docker-compose.yml
└── README.md
```

---

## AI/ML Design Notes

### Anomaly Detection — Isolation Forest

Located in `backend/app/services/anomaly_detection.py`.

**Why Isolation Forest?**
- Unsupervised — no labelled attack data required to bootstrap
- O(n log n) training, O(log n) inference — fast enough for real-time log processing
- Handles mixed numeric feature types naturally

**Feature vector (15 dimensions):**

| # | Feature | Intuition |
|---|---------|-----------|
| 0 | Hour of day | After-hours logins are suspicious |
| 1 | Day of week | Weekend access stands out |
| 2 | Source IP bucket | Novel IPs score as anomalous |
| 3 | Destination IP bucket | Unusual destinations |
| 4 | Log level | Error/critical events are higher risk |
| 5 | Event type | Malware/C2/lateral movement encoded higher |
| 6 | Message length | Long messages may carry payloads |
| 7 | Auth failure count | Brute-force detection |
| 8 | Distinct destinations | Fan-out = scanning / C2 |
| 9 | Privileged port | dst_port < 1024 |
| 10 | External source IP | Non-RFC-1918 source |
| 11 | Rapid connections | Rate spike |
| 12 | Service account interactive | Unusual account usage |
| 13 | Lateral movement | Cross-subnet internal traffic |
| 14 | Timezone anomaly | Off-hours + external IP |

**Risk scoring:**
```
IsolationForest.decision_function() → raw score (positive=normal, negative=anomalous)
→ clamped to [-0.5, 0.5]
→ inverted and scaled to 0-100 risk score
→ severity label: critical ≥80, high ≥60, medium ≥40, low ≥20
```

### Threat Intelligence Correlation

Located in `backend/app/services/threat_intel.py`.

Every log field (`ip_src`, `ip_dst`, `user`, `raw_data.domain`, `raw_data.file_hash`)
is checked against the `threat_indicators` table. Matches trigger incident escalation.

### AI Recommendation Engine

Template-based NLP (production: swap `generate_ai_recommendation()` for a Claude API call):

```python
import anthropic

client = anthropic.Anthropic()
response = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=1024,
    messages=[{
        "role": "user",
        "content": f"You are a SOC analyst. Analyse this incident and give "
                   f"prioritised response steps:\n\n{incident_context}"
    }]
)
recommendation = response.content[0].text
```

---

## Playbooks

All playbooks are in `backend/app/services/playbook.py`.

| Playbook | Trigger | Actions |
|----------|---------|---------|
| `isolate_host` | Malware / C2 / lateral movement | EDR quarantine → Slack alert |
| `revoke_credentials` | Privilege escalation / brute-force | Disable AD account → Email manager |
| `block_ip` | Any | Firewall deny-list entry |
| `send_alert` | High severity | Slack + email + PagerDuty |
| `full_response` | Critical | Isolate + revoke + block + forensics + alert |

All actions are **simulated** in this prototype. Replace the `_do_*` stubs
with your vendor API calls (CrowdStrike, Okta, Palo Alto, etc.).

---

## Database Schema

```sql
assets             -- internal hosts, IP, department, criticality, is_isolated
logs               -- raw log events + anomaly_score, risk_score, explanation
incidents          -- auto-created from anomalous logs, severity, status, ai_recommendation
alerts             -- dispatched notifications (channel, recipient, message)
threat_indicators  -- IOCs from feeds (ip/domain/hash, threat_type, confidence)
playbook_actions   -- audit log of every automated response step
```

---

## Extending the Prototype

| Goal | Where to change |
|------|----------------|
| Add a real ML model (LSTM, Transformer) | `anomaly_detection.py` — replace `IsolationForest` |
| Connect to a real SIEM | `routes/logs.py` — add a Kafka/Elasticsearch consumer |
| Add real EDR integration | `playbook.py` — replace `_do_isolate_host()` |
| Use Claude API for recommendations | `threat_intel.py` — replace `generate_ai_recommendation()` |
| Add TAXII/STIX threat feeds | `threat_intel.py` — replace `fetch_live_feed()` |
| Add user authentication | Add FastAPI JWT middleware + login route |

---

## Troubleshooting

**DB connection refused on first start:**
The backend starts before PostgreSQL is ready. Docker Compose health-checks handle this,
but if you see connection errors just wait 10-15 s and reload.

**Frontend shows "API error":**
Ensure the backend is running (`docker compose ps`). Check `http://localhost:8000/health`.

**No incidents appearing:**
Run `python scripts/init_db.py` or `python scripts/simulate_logs.py --once` to seed data.

**Port conflicts:**
Edit `docker-compose.yml` to change `3000:3000` or `8000:8000` if those ports are in use.
