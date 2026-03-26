# GOATGuard Server

Centralized collector and analysis backend for the GOATGuard network monitoring system. Receives captured traffic and system metrics from distributed agents, assembles PCAP files, processes them with Zeek for deep protocol inspection, calculates per-device and network-wide metrics, discovers network devices via ARP scanning, enriches device identity with OUI vendor lookup and reverse DNS, monitors ISP health via ICMP probing, detects anomalies using adaptive EWMA baselines with Z-score classification, exposes data through a REST API with JWT authentication and real-time WebSocket push, and persists everything in PostgreSQL.

## Architecture

The server runs as two separate processes sharing PostgreSQL:

```
┌─────────┐  TCP (packets)   ┌───────────┐          ┌──────┐        ┌─────────────┐
│ Agent 1 │─────────────────►│           │  rotate  │      │  logs  │             │
├─────────┤                  │   TCP     │─────────►│ PCAP │───────►│    Zeek     │
│ Agent 2 │─────────────────►│ Receiver  │          │ File │        │  (Docker)   │
├─────────┤                  │           │          └──────┘        └─────┬───────┘
│ Agent N │─────────────────►│ (thread   │                                │
└─────────┘                  │  per      │                                ▼
                             │  client)  │                         ┌─────────────┐
┌─────────┐  UDP (metrics)   │           │                         │ Log Parser  │
│ Agent 1 │─────────────────►├───────────┤                         └─────┬───────┘
├─────────┤                  │   UDP     │                               │
│ Agent 2 │─────────────────►│ Receiver  │                               ▼
├─────────┤                  │           │                         ┌─────────────┐
│ Agent N │─────────────────►│           │                         │  Metrics    │
└─────────┘                  └─────┬─────┘                         │ Calculator  │
                                   │                               └─────┬───────┘
  ┌──────────────────┐             │                                     │
  │  ISP Probe       │─► ICMP     │                                     ▼
  │  Health Checker  │─► HB       │                               ┌──────────┐
  │  ARP Scanner     │─► L2       │         writes                │Repository│
  │  IP Enrichment   │─► OUI/DNS  │        ────────►              └────┬─────┘
  └────────┬─────────┘            ▼                                    │
           │                ┌──────────┐                               │
           └───────────────►│PostgreSQL│◄──────────────────────────────┘
                            │   :5432  │
  ┌──────────────────┐      └────┬─────┘
  │ Detection Engine │           │
  │  EWMA + Z-Score  │◄──reads───┘
  │  Alert Manager   │───writes──►
  │  Insight Gen.    │───push────►─────────┐
  └──────────────────┘                     │
                                 ┌─────────▼────┐
                                 │  FastAPI     │
                            ┌───►│  REST + WS   │
                            │    │  JWT Auth    │
                            │    │  :8000       │
                            │    └──────┬───────┘
                         reads          │
                            │    ┌──────▼───────┐
                            └────│  Mobile App  │
                                 │  (Flutter)   │
                                 └──────────────┘

  Process 1: python run.py          Process 2: python run_api.py
  (pipeline + monitors + detection)  (API + WebSocket)
```

## Requirements

- Python 3.10+
- Docker Desktop (PostgreSQL + Zeek)
- Ports: 9999 (TCP), 9998 (UDP), 8000 (API), 5432 (PostgreSQL)

### Windows
- Npcap installed (for ARP scanning): https://npcap.com
- Run terminal as Administrator (ARP and ICMP require elevated privileges)

### Linux (Ubuntu/Debian)
- libpcap-dev: `sudo apt install libpcap-dev`
- Root privileges required for ARP scanning and ICMP probing

## Installation

```bash
git clone https://github.com/JPabloCarvajal/goatguard-server.git
cd goatguard-server
```

### Windows (PowerShell as Administrator)
```powershell
pip install pyyaml sqlalchemy psycopg2-binary scapy pythonping mac-vendor-lookup fastapi uvicorn pyjwt bcrypt websockets
docker pull zeek/zeek
docker compose up -d
```

### Linux (Ubuntu/Debian)
```bash
sudo apt install python3-full python3-venv libpcap-dev
python3 -m venv .venv
source .venv/bin/activate
pip install pyyaml sqlalchemy psycopg2-binary scapy pythonping mac-vendor-lookup fastapi uvicorn pyjwt bcrypt websockets
docker pull zeek/zeek
docker compose up -d
```

## Configuration

Edit `config/server_config.yaml`:

```yaml
server:
  tcp_port: 9999
  udp_port: 9998
  api_port: 8000
  host: "0.0.0.0"
  subnet: "192.168.1.0/24"    # YOUR LAN subnet

pcap:
  output_dir: "pcap_output"
  rotation_seconds: 30
  max_file_size_mb: 100

database:
  host: "localhost"
  port: 5432
  name: "goatguard"
  user: "goatguard"
  password: "goatguard"

security:
  jwt_secret: "goatguard-dev-secret-change-in-production"
  jwt_algorithm: "HS256"
  jwt_expiration_hours: 24

logging:
  level: "INFO"
  file: "goatguard_server.log"
```

For production, environment variables override YAML values. See `.env.example`.

## Usage

Two terminals, two processes:

### Windows (PowerShell as Administrator)
```powershell
# Terminal 1: Pipeline + detection engine
python run.py

# Terminal 2: API
python run_api.py
```

### Linux
```bash
source .venv/bin/activate

# Terminal 1: Pipeline + detection engine (sudo for ARP + ICMP)
sudo .venv/bin/python3 run.py

# Terminal 2: API (no sudo needed)
python3 run_api.py
```

Swagger docs: http://localhost:8000/docs

## API Endpoints

All endpoints except auth require `Authorization: Bearer <token>`.

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /auth/register | Create admin account, returns JWT |
| POST | /auth/login | Login, returns JWT |

### Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /dashboard/summary | System overview: status, device counts, ISP health, top consumer |

### Devices

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /devices/ | List all devices |
| GET | /devices/{id} | Device detail with current metrics |
| GET | /devices/{id}/history?hours=4 | Historical metrics for trend graphs |
| GET | /devices/{id}/connections | External connections with resolved hostnames |
| GET | /devices/comparison?metric=bandwidth_in | Compare all devices by a metric |
| PATCH | /devices/{id}/alias | Update device display name |

### Network

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /network/metrics | Network health + ISP status |
| GET | /network/top-talkers | Bandwidth consumption ranking |
| GET | /network/history?hours=4 | Historical network metrics |
| GET | /network/top-talkers/history?hours=4 | Historical bandwidth rankings |
| GET | /network/traffic-distribution | Traffic breakdown by protocol, port, direction |
| GET | /network/isp-health | Detailed ISP health with 1h stats and status classification |

### Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /alerts/ | List alerts (filters: seen, severity) |
| GET | /alerts/count | Unseen + total count |
| PATCH | /alerts/{id}/seen | Mark alert as read |

### WebSocket

| Protocol | Endpoint | Description |
|----------|----------|-------------|
| WS | /ws?token=JWT | Real-time push: periodic state updates + instant alert notifications |

WebSocket message types:
- `state_update` — every 5s: network metrics, device summaries, unseen alert count
- `alert_created` — instant: anomaly detected with severity and insight text

## Project Structure

```
goatguard-server/
├── config/
│   └── server_config.yaml
├── src/
│   ├── config/                    # YAML + dataclasses + env overrides
│   ├── receivers/
│   │   ├── tcp_receiver.py        # Thread-per-client binary protocol
│   │   └── udp_receiver.py        # JSON metrics + heartbeat routing
│   ├── ingestion/
│   │   └── pcap_assembler.py      # PCAP writing + timed rotation
│   ├── analysis/
│   │   ├── pipeline.py            # Zeek -> Parser -> Calculator -> DB
│   │   ├── zeek_runner.py         # Docker execution wrapper
│   │   ├── log_parser.py          # conn.log + dns.log parsing
│   │   └── metrics_calculator.py  # Per-device + network metrics
│   ├── monitoring/
│   │   ├── health_checker.py      # Heartbeat timeout detection
│   │   └── isp_probe.py           # ICMP latency/loss/jitter
│   ├── discovery/
│   │   ├── arp_scanner.py         # ARP LAN enumeration
│   │   └── enrichment.py          # OUI vendor + reverse DNS
│   ├── detection/                 # Anomaly detection engine
│   │   ├── baseline.py            # EWMA + EWMV adaptive baseline (Strategy)
│   │   ├── anomaly_detector.py    # Per-device and network detectors
│   │   ├── insight_generator.py   # Z-score to human-readable text
│   │   ├── alert_manager.py       # Alert persistence + deduplication
│   │   └── engine.py              # Detection orchestrator (Mediator)
│   ├── database/
│   │   ├── connection.py          # SQLAlchemy engine + sessions
│   │   ├── models.py              # ORM table definitions
│   │   └── repository.py          # All DB operations
│   └── api/
│       ├── app.py                 # FastAPI factory
│       ├── auth.py                # JWT + bcrypt
│       ├── dependencies.py        # DB session + auth injection
│       ├── websocket.py           # Connection manager + broadcast + alert queue
│       └── routes/
│           ├── auth.py            # /auth/*
│           ├── dashboard.py       # /dashboard/*
│           ├── devices.py         # /devices/*
│           ├── network.py         # /network/*
│           └── alerts.py          # /alerts/*
├── tests/
├── docker-compose.yml             # PostgreSQL 15
├── run.py                         # Entry point: pipeline + detection
├── run_api.py                     # Entry point: API + WebSocket
├── .env.example                   # Production secrets template
└── .github/workflows/ci.yml      # Lint + tests + PostgreSQL
```

## Data Flow

### Captured Traffic (TCP)
```
Agent -> sanitize -> TCP -> Receiver -> PCAP Assembler -> rotate every 30s
  -> Zeek (Docker) -> Log Parser -> Enrichment (reverse DNS)
  -> Metrics Calculator -> Repository -> PostgreSQL
  -> Historical Snapshots (endpoint + network + top talkers)
  -> Recent Connections (grouped by destination with resolved hostnames)
  -> WebSocket push
```

### System Metrics (UDP)
```
Agent -> JSON -> UDP -> Receiver -> route by "type" field
  -> metrics: UPSERT device_current_metrics
  -> heartbeat: update agent.last_heartbeat
```

### Discovery + Monitoring
```
ARP Scanner (60s)   -> discover devices -> register with OUI vendor
ISP Probe (30s)     -> ping 8.8.8.8 -> latency, loss, jitter
Health Checker (30s) -> heartbeat timeout -> mark disconnected/active
```

### Anomaly Detection
```
Every 30s:
  -> Detection Engine reads current metrics from PostgreSQL
  -> Per-device EWMA baselines calculate Z-scores
  -> Persistence filter: 2 consecutive cycles above threshold required
  -> Alert Manager generates insight text + saves to DB
  -> Instant push via WebSocket alert_queue -> mobile app
```

## Anomaly Detection

The detection engine uses EWMA (Exponentially Weighted Moving Average) with adaptive Z-score thresholds instead of fixed thresholds. Each metric of each device maintains its own baseline that adapts over time.

Detection parameters:
- Alpha: 0.10 (baseline memory ~22 minutes)
- Warm-up: 30 cycles (15 minutes before generating alerts)
- Persistence filter: 2/2 consecutive cycles required (95.4% false positive reduction)

Severity classification:
- WARNING: |Z| > 2.0 sustained (4.56% normal probability)
- CRITICAL: |Z| > 3.0 sustained (0.27% normal probability)

Monitored metrics per device: cpu_pct, ram_pct, bandwidth_in, bandwidth_out, tcp_retransmissions, failed_connections, unique_destinations, bytes_ratio, dns_response_time.

Monitored network metrics: isp_latency_avg, packet_loss_pct, jitter.

## Database

```bash
docker compose up -d       # Start
docker compose down        # Stop (data preserved)
docker compose down -v     # Stop + delete data
```

Useful queries:
```bash
docker exec -it goatguard-db psql -U goatguard -c \
  "SELECT id, hostname, ip, mac, detected_type, has_agent, status FROM device ORDER BY ip;"

docker exec -it goatguard-db psql -U goatguard -c \
  "SELECT device_id, cpu_pct, ram_pct, bandwidth_in, bandwidth_out FROM device_current_metrics;"

docker exec -it goatguard-db psql -U goatguard -c \
  "SELECT isp_latency_avg, packet_loss_pct, jitter, active_connections FROM network_current_metrics;"

docker exec -it goatguard-db psql -U goatguard -c \
  "SELECT id, anomaly_type, severity, substring(description, 1, 80) as insight FROM alert ORDER BY id DESC LIMIT 10;"
```

## Development

### Windows
```powershell
pip install pytest ruff pytest-html httpx
python -m ruff check src/
python -m pytest tests/ -v
```

### Linux
```bash
source .venv/bin/activate
pip install pytest ruff pytest-html httpx
python -m ruff check src/
python -m pytest tests/ -v
```

### Test Report
```bash
python -m pytest tests/ -v --html=test_report.html --self-contained-html
```

### Infrastructure Monitoring
```bash
pip install glances[web]
python -m glances -w          # http://localhost:61208
```

Git workflow: `main` (stable, protected) <- PR <- `develop` (integration) <- `feature/*`

## Roadmap

- [x] Sprint 1: TCP Receiver + PCAP Assembler
- [x] Sprint 2: UDP Receiver + PostgreSQL + Repository
- [x] Sprint 3: Zeek Runner + Log Parser
- [x] Sprint 4: Metrics Calculator + Analysis Pipeline
- [x] Sprint 5: ISP Probe + Health Checker
- [x] Sprint 6: ARP Discovery + IP Enrichment
- [x] Sprint 7: REST API + WebSocket + JWT Auth
- [x] Sprint 8: Historical Snapshots + Dashboard + Device Connections + Traffic Distribution
- [x] Sprint 9: EWMA Anomaly Detection Engine + Alert Manager + Insight Generator
- [ ] Sprint 10: CD pipeline + Dockerfile

## CI/CD

**CI** (`ci.yml`) — Runs on push to `main`/`develop`. PostgreSQL service container + ruff + pytest.
