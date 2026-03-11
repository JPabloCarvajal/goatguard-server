# GOATGuard Server

Centralized collector and analysis backend for the GOATGuard network monitoring system. Receives captured traffic and system metrics from distributed agents, assembles PCAP files, processes them with Zeek for deep protocol inspection, calculates per-device and network-wide metrics, and persists everything in PostgreSQL.

Integrative Project III — UPB

## Architecture
```
┌─────────┐  TCP (packets)  ┌───────────┐         ┌──────┐       ┌────────────┐
│ Agent 1 │────────────────►│           │  rotate │      │  logs │            │
├─────────┤                 │   TCP     │────────►│ PCAP │──────►│    Zeek    │
│ Agent 2 │────────────────►│ Receiver  │         │ File │       │ (Docker)   │
├─────────┤                 │           │         └──────┘       └─────┬──────┘
│ Agent N │────────────────►│ (thread   │                              │
└─────────┘                 │  per      │                              ▼
                            │  client)  │                        ┌───────────┐
┌─────────┐  UDP (metrics)  │           │                        │ Log Parser│
│ Agent 1 │────────────────►├───────────┤                        └─────┬─────┘
├─────────┤                 │   UDP     │                              │
│ Agent 2 │────────────────►│ Receiver  │                              ▼
├─────────┤                 │           │                        ┌───────────┐
│ Agent N │────────────────►│           │                        │  Metrics  │
└─────────┘                 └─────┬─────┘                        │Calculator │
                                  │                              └─────┬─────┘
                                  │                                    │
                                  ▼                                    ▼
                            ┌──────────┐                         ┌──────────┐
                            │PostgreSQL│◄────────────────────────│Repository│
                            │          │                         └──────────┘
                            └────┬─────┘
                                 │
                                 ▼
                            ┌──────────┐
                            │ API REST │ (Sprint 6)
                            │WebSocket │
                            └────┬─────┘
                                 │
                                 ▼
                            ┌──────────┐
                            │Mobile App│
                            └──────────┘
```

## Requirements

- Python 3.10 or higher
- Docker Desktop (for PostgreSQL and Zeek)
- Available ports: 9999 (TCP), 9998 (UDP), 8000 (API), 5432 (PostgreSQL)

## Installation
```bash
git clone https://github.com/YOUR_ORG/goatguard-server.git
cd goatguard-server
pip install pyyaml sqlalchemy psycopg2-binary
```

Pull the Zeek Docker image (first time only):
```bash
docker pull zeek/zeek
```

Start PostgreSQL:
```bash
docker compose up -d
```

Verify PostgreSQL is running:
```bash
docker ps
```

## Usage
```bash
python run.py
```

The server starts listening on TCP 9999 (captured packets) and UDP 9998 (metrics/heartbeats). Every 30 seconds, captured packets are assembled into a PCAP file, processed by Zeek, and the resulting metrics are persisted in PostgreSQL.

## Configuration

The file `config/server_config.yaml` controls all server behavior:
```yaml
server:
  tcp_port: 9999            # TCP port for captured traffic from agents
  udp_port: 9998            # UDP port for metrics and heartbeats
  api_port: 8000            # REST API and WebSocket port
  host: "0.0.0.0"           # Bind address (0.0.0.0 = all interfaces)

pcap:
  output_dir: "pcap_output" # Directory for assembled PCAP files
  rotation_seconds: 30      # How often to rotate PCAP files
  max_file_size_mb: 100     # Safety limit per file

database:
  host: "localhost"
  port: 5432
  name: "goatguard"
  user: "goatguard"
  password: "goatguard"

logging:
  level: "INFO"             # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: "goatguard_server.log"
```

## Project Structure
```
goatguard-server/
├── config/
│   └── server_config.yaml         # Server configuration
├── src/
│   ├── config/                    # YAML loading and validation
│   │   ├── models.py              # Configuration dataclasses
│   │   ├── loader.py              # YAML reading and parsing
│   │   └── __init__.py            # Re-exports
│   ├── receivers/                 # Data reception from agents
│   │   ├── tcp_receiver.py        # Multi-client TCP (thread per client)
│   │   └── udp_receiver.py        # Metrics and heartbeat receiver
│   ├── ingestion/                 # PCAP file assembly
│   │   └── pcap_assembler.py      # Packet writing and file rotation
│   ├── analysis/                  # Traffic analysis pipeline
│   │   ├── pipeline.py            # Orchestrates the full analysis chain
│   │   ├── zeek_runner.py         # Executes Zeek via Docker
│   │   ├── log_parser.py          # Parses Zeek log files
│   │   └── metrics_calculator.py  # Per-device and network metrics
│   ├── database/                  # PostgreSQL persistence
│   │   ├── connection.py          # SQLAlchemy engine and sessions
│   │   ├── models.py              # ORM table definitions
│   │   └── repository.py          # Data access layer
│   ├── detection/                 # Anomaly detection (planned)
│   ├── interpretation/            # Insight generation (planned)
│   └── api/                       # REST API and WebSocket (planned)
├── tests/                         # Unit tests
├── pcap_output/                   # Generated PCAP files (gitignored)
├── zeek_output/                   # Zeek analysis results (gitignored)
├── docker-compose.yml             # PostgreSQL container
├── run.py                         # Entry point
└── .env.example                   # Environment variables template
```

## Data Flow

### Captured Traffic (TCP)
```
Agent captures packet
  → Sanitizer truncates payload (preserves headers + orig_len)
  → TCP sender transmits with 20-byte binary header
  → TCP Receiver reads using length-prefix protocol (thread per client)
  → PCAP Assembler writes Global Header (24 bytes) + Packet Header (16 bytes) + data
  → Every 30 seconds: file rotates → Zeek processes → Parser extracts → Calculator computes
  → Repository persists: device_current_metrics, network_current_metrics, top_talker_current
```

### System Metrics (UDP)
```
Agent reads CPU, RAM, disk, link speed, uptime
  → JSON serialization → UDP datagram
  → UDP Receiver parses JSON, routes by "type" field
  → Metrics: Repository creates/updates device + device_current_metrics
  → Heartbeat: Repository updates agent.last_heartbeat
```

## Analysis Pipeline

When a PCAP file rotates, the following chain executes automatically:

1. **Zeek** (Docker container) processes the PCAP and generates structured logs
2. **Log Parser** reads conn.log and dns.log into Python dictionaries
3. **Metrics Calculator** computes per-device metrics:
   - Bandwidth in/out (bytes per second)
   - TCP retransmissions
   - Failed connections (S0, REJ, RSTO states)
   - Unique destinations contacted
   - Traffic ratio (sent/received)
4. **Metrics Calculator** computes network-wide metrics:
   - Active connections and rate per minute
   - Internal vs external traffic split
   - Global failed connections
   - Top talkers ranking with hog detection
5. **Repository** persists all results via UPSERT to PostgreSQL

## Database Schema

The database implements a **current state + history** separation pattern:

**Current state tables** (one row per entity, updated via UPSERT):
- `device_current_metrics` — latest metrics per endpoint
- `network_current_metrics` — latest network health indicators
- `top_talker_current` — current bandwidth ranking

**Historical tables** (append-only, grow over time):
- `endpoint_snapshot` — timestamped endpoint metrics
- `network_snapshot` — timestamped network metrics
- `top_talker` — historical rankings

**Structural tables:**
- `network` — monitored LAN segments
- `device` — discovered devices (with or without agent)
- `agent` — registered capture agents
- `alert` — generated anomaly alerts
- `user`, `session`, `push_token` — mobile app authentication
- `ml_prediction` — ML classification results (planned)
- `insight` — human-readable observations (planned)

## Querying the Database
```bash
# List registered devices
docker exec -it goatguard-db psql -U goatguard -c "SELECT id, hostname, ip, has_agent FROM device;"

# Current device metrics
docker exec -it goatguard-db psql -U goatguard -c "SELECT device_id, cpu_pct, ram_pct, bandwidth_in, bandwidth_out FROM device_current_metrics;"

# Network status
docker exec -it goatguard-db psql -U goatguard -c "SELECT * FROM network_current_metrics;"

# Top talkers
docker exec -it goatguard-db psql -U goatguard -c "SELECT tc.rank, d.hostname, tc.total_consumption, tc.is_hog FROM top_talker_current tc JOIN device d ON tc.device_id = d.id ORDER BY tc.rank;"
```

## Docker Services

**PostgreSQL** (persistent service via docker-compose):
```bash
docker compose up -d      # Start
docker compose down        # Stop
docker compose down -v     # Stop and delete data
```

**Zeek** (ephemeral container, runs automatically):
```bash
docker pull zeek/zeek      # Pre-pull image (optional)
```

## Development Roadmap

- [x] Sprint 1: TCP Receiver + PCAP Assembler
- [x] Sprint 2: UDP Receiver + PostgreSQL + Repository
- [x] Sprint 3: Zeek Runner + Log Parser
- [x] Sprint 4: Metrics Calculator + Analysis Pipeline
- [ ] Sprint 5: ISP Probe (latency, packet loss, jitter)
- [ ] Sprint 6: Feature Extractor + ML Classifier (Random Forest)
- [ ] Sprint 7: REST API + WebSocket
- [ ] Sprint 8: Alert Manager + Insight Generator
- [ ] Sprint 9: ARP Discovery + IP Enrichment (reverse DNS, OUI lookup)

## CI/CD

**CI** (`ci.yml`) — Runs on every push to `main` and `develop`. Executes linter (ruff) and tests (pytest) with a PostgreSQL service container.
