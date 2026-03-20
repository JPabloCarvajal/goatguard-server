# GOATGuard Server

Centralized collector and analysis backend for the GOATGuard network monitoring system. Receives captured traffic and system metrics from distributed agents, assembles PCAP files, processes them with Zeek for deep protocol inspection, calculates per-device and network-wide metrics, discovers network devices via ARP scanning, enriches device identity with OUI vendor lookup and reverse DNS, monitors ISP health via ICMP probing, exposes data through a REST API with JWT authentication and real-time WebSocket push, and persists everything in PostgreSQL.

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
                             │  client)  │                         ┌────────────┐
┌─────────┐  UDP (metrics)   │           │                         │ Log Parser │
│ Agent 1 │─────────────────►├───────────┤                         └─────┬──────┘
├─────────┤                  │   UDP     │                               │
│ Agent 2 │─────────────────►│ Receiver  │                               ▼
├─────────┤                  │           │                         ┌────────────┐
│ Agent N │─────────────────►│           │                         │  Metrics   │
└─────────┘                  └─────┬─────┘                         │ Calculator │
                                   │                               └─────┬──────┘
  ┌──────────────────┐             │                                     │
  │  ISP Probe       │─► ICMP      │                                     │
  │  Health Checker  │─► HB        │                                     ▼
  │  ARP Scanner     │─► L2        │                               ┌──────────┐
  │  IP Enrichment   │─► OUI/DNS   │         writes                │Repository│
  └────────┬─────────┘             ▼        ────────►              └────┬─────┘
           │                ┌──────────┐                                │
           └───────────────►│PostgreSQL│◄───────────────────────────────┘
                            │   :5432  │
                            └────┬─────┘
                                 │ reads
                                 ▼
                            ┌──────────────┐
                            │  FastAPI      │
                            │  REST + WS    │
                            │  JWT Auth     │
                            │  :8000        │
                            └──────┬───────┘
                                   │
                            ┌──────▼───────┐
                            │  Mobile App   │
                            │  (Flutter)    │
                            └──────────────┘

  Process 1: python run.py          Process 2: python run_api.py
  (pipeline + monitors)             (API + WebSocket)
```

## Requirements

- Python 3.10+
- Docker Desktop (PostgreSQL + Zeek)
- Ports: 9999 (TCP), 9998 (UDP), 8000 (API), 5432 (PostgreSQL)

### Windows
- Npcap installed (for ARP scanning): https://npcap.com
- Run terminal as Administrator (ARP and ICMP require elevated privileges)

### Linux (Ubuntu/Debian/Idk if fedora works with dnf packages commands "not tested xd")
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
# Terminal 1: Pipeline
python run.py

# Terminal 2: API
python run_api.py
```

### Linux
```bash
source .venv/bin/activate

# Terminal 1: Pipeline (sudo for ARP + ICMP)
sudo .venv/bin/python3 run.py

# Terminal 2: API (no sudo needed)
python3 run_api.py
```

Swagger docs: http://localhost:8000/docs

## API Endpoints

All endpoints except auth require `Authorization: Bearer <token>`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /auth/register | Create admin account, returns JWT |
| POST | /auth/login | Login, returns JWT |
| GET | /devices/ | List all devices |
| GET | /devices/{id} | Device detail with metrics |
| PATCH | /devices/{id}/alias | Update device alias |
| GET | /network/metrics | Network health + ISP status |
| GET | /network/top-talkers | Bandwidth ranking |
| GET | /alerts/ | List alerts (filters: seen, severity) |
| GET | /alerts/count | Unseen + total count |
| PATCH | /alerts/{id}/seen | Mark alert as read |
| WS | /ws?token=JWT | Real-time push (every 5s) |

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
│   ├── database/
│   │   ├── connection.py          # SQLAlchemy engine + sessions
│   │   ├── models.py              # ORM table definitions
│   │   └── repository.py          # All DB operations
│   └── api/
│       ├── app.py                 # FastAPI factory
│       ├── auth.py                # JWT + bcrypt
│       ├── dependencies.py        # DB session + auth injection
│       ├── websocket.py           # Connection manager + broadcast
│       └── routes/
│           ├── auth.py            # /auth/register, /auth/login
│           ├── devices.py         # /devices/*
│           ├── network.py         # /network/*
│           └── alerts.py          # /alerts/*
├── tests/
├── docker-compose.yml             # PostgreSQL 15
├── run.py                         # Entry point: pipeline
├── run_api.py                     # Entry point: API
├── .env.example                   # Production secrets template
└── .github/workflows/ci.yml      # Lint + tests + PostgreSQL
```

## Data Flow

### Captured Traffic (TCP)
```
Agent -> sanitize -> TCP -> Receiver -> PCAP Assembler -> rotate every 30s
  -> Zeek (Docker) -> Log Parser -> Enrichment (reverse DNS)
  -> Metrics Calculator -> Repository -> PostgreSQL -> WebSocket push
```

### System Metrics (UDP)
```
Agent -> JSON -> UDP -> Receiver -> route by "type" field
  -> metrics: UPSERT device_current_metrics
  -> heartbeat: update agent.last_heartbeat
```

### Discovery + Monitoring
```
ARP Scanner (60s)  -> discover devices -> register with OUI vendor
ISP Probe (30s)    -> ping 8.8.8.8 -> latency, loss, jitter
Health Checker (30s) -> heartbeat timeout -> mark disconnected/active
```

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
```

## Development

### Windows
```powershell
pip install pytest ruff
python -m ruff check src/
python -m pytest tests/ -v
```

### Linux
```bash
source .venv/bin/activate
pip install pytest ruff
python -m ruff check src/
python -m pytest tests/ -v
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
- [ ] Sprint 8: Historical Snapshots
- [ ] Sprint 9: Feature Extractor + ML Classifier (Random Forest)
- [ ] Sprint 10: Alert Manager + Insight Generator

## CI/CD

**CI** (`ci.yml`) — Runs on push to `main`/`develop`. PostgreSQL service container + ruff + pytest.
