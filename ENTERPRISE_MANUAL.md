# 🛡️ NetGuard IDS — Enterprise Product & Operations Manual (MNC Edition)

```
Document Reference : NGD-ENG-SOP-2026-V35
Document Class     : Enterprise Technical & Operations Manual
Target Audience    : SOC Engineers, Network Architects, DevSecOps, Platform Integrators
Platform Version   : NetGuard IDS v2.2.0-hardened / v3.5 (Industrial IoT & DPI Core)
Maturity Level     : TRL-8 (System Qualified & Pilot Ready)
Compliance Scope   : Purdue Model Levels 1–3, OSI Layers 3, 4, & 7, RFC 5424, CEF, NIST SP 800-82r3
```

---

## 1. Executive Summary & System Overview

**NetGuard IDS** is an enterprise-grade **Network Detection and Response (NDR)** and **Network Intrusion Prevention System (NIPS)** built specifically to secure industrial IoT (IIoT), SCADA infrastructure, and enterprise networks. 

Operating simultaneously across **Purdue Model Levels 1–3** (Field I/O, Controller Networks, and Operations Management) and **OSI Layers 3 (Network), 4 (Transport), and 7 (Application)**, the system combines:
1. **Supervised Multi-Class Machine Learning** (XGBoost benchmarked on 8.2M flows with a 90.25% Macro F1-score).
2. **Unsupervised Zero-Day Threat Discovery** (Isolation Forest with domain-adaptive IoT port scoring).
3. **Industrial Deep Packet Inspection (DPI)** (Modbus TCP, MQTT, CoAP, and OPC-UA protocol decoders).
4. **Automated Sub-Second Host Containment** (Windows Advanced Firewall and Linux `iptables` rule injection).
5. **Native Explainable AI (XAI)** (Exact mathematical Shapley value feature attribution via TreeSHAP).
6. **Rolling In-Memory PCAP Forensics** (Circular buffer with automated incident snapshot dumps to Wireshark `.pcap`).
7. **Hybrid High-Speed Dual Storage** (1ms local SQLite WAL paired with automated 30s background sync to Neon Cloud PostgreSQL).
8. **Enterprise Cryptographic Licensing & Multi-Tenancy** (Asymmetric Ed25519/RSA digital signatures with tenant isolation).

```
   ┌────────────────────────────────────────────────────────────────────────┐
   │                  NetGuard IDS Enterprise Architecture                  │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
     ┌─────────────────────────────────┼─────────────────────────────────┐
     ▼                                 ▼                                 ▼
┌─────────────────────────┐ ┌─────────────────────────┐ ┌─────────────────────────┐
│     Ingestion Layer     │ │      Dual-ML Engine     │ │   Storage & Forensics   │
│ • Scapy Raw Capture     │ │ • XGBoost Classifier    │ │ • SQLite WAL (1ms local)│
│ • Industrial DPI Engine │ │   (90.25% Macro F1)     │ │ • Neon Cloud PostgreSQL │
│ • Redis Flow Streams    │ │ • Isolation Forest      │ │ • Rolling 60s PCAP Ring │
│ • Mutex Process Guard   │ │   (Zero-Day Anomaly)    │ │ • TreeSHAP Exact XAI    │
└────────────┬────────────┘ └────────────┬────────────┘ └────────────┬────────────┘
             │                           │                           │
             └───────────────────────────┼───────────────────────────┘
                                         ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                   Containment & SOC Integration Layer                  │
   │ • Host Firewall: Windows `netsh advfirewall` & Linux `iptables`        │
   │ • Alerts: SMTP SSL HTML Email + HMAC-Protected Telegram Actions        │
   │ • SIEM Exporters: RFC 5424 / CEF Syslog (Splunk, QRadar) + Webhooks   │
   │ • Presentation: React 19 SOC Console (:5174) & FastAPI Engine (:8081)  │
   └────────────────────────────────────────────────────────────────────────┘
```

---

## 2. System Prerequisites & Environment Matrix

### 2.1 Hardware Requirements
| Node Profile | CPU Architecture | Minimum RAM | Recommended RAM | Storage | Network Interface |
|:---|:---|:---|:---|:---|:---|
| **Edge Appliance / Sensor** (e.g. Raspberry Pi 4/5, Advantech Box PC) | ARM64 / x86_64 (2+ Cores) | 2 GB | 4 GB | 16 GB eMMC/SSD | 1x GbE Promiscuous / Mirror Port |
| **Enterprise SOC Gateway / Server** | x86_64 (4+ Cores) | 4 GB | 8 GB | 64 GB NVMe SSD | 1x Dedicated Management + 1x SPAN/TAP Port |

### 2.2 Software & Driver Prerequisites
1. **Operating System**:
   - **Windows**: Windows 10/11 (64-bit) or Windows Server 2019/2022 (Administrator privileges required for `netsh advfirewall` containment).
   - **Linux**: Ubuntu Server 20.04/22.04/24.04 LTS, Debian 12, or Raspberry Pi OS (64-bit) with kernel capabilities `CAP_NET_RAW` and `CAP_NET_ADMIN`.
2. **Runtime Engines**:
   - **Python**: Version `3.11+` (Required for typing extensions and Scapy protocol stack).
   - **Node.js**: Version `18.0+` & `npm 9+` (Required for React 19 Vite dashboard).
3. **Packet Capture Libraries**:
   - **Windows**: [Npcap](https://npcap.com/) (Installed with *"WinPcap API-compatible Mode"* enabled).
   - **Linux**: `libpcap-dev` (`sudo apt install libpcap-dev`).
4. **Network Scanning Engine**:
   - [Nmap](https://nmap.org/download.html) Version `7.90+` installed and present in system `PATH`.
5. **In-Memory Buffer Engine (Optional / High-Throughput)**:
   - Redis Server Version `7.0+` (Runs on `localhost:6379` or Docker container).

---

## 3. Installation & Deployment Procedures

### Option A: Unified 1-Click Launch (Windows Quick Start)

Open PowerShell as **Administrator** and execute:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
cd C:\iot-ids
.\run-netguard.ps1
```
*The launcher validates runtimes, provisions Python `venv`, builds Node dependencies, launches the FastAPI engine on port `8081`, starts the React UI on port `5174`, and opens the default browser.*

---

### Option B: Bare-Metal Manual Installation (Windows & Linux)

#### Step 1: Environment & Dependency Provisioning
```bash
# 1. Clone repository
git clone https://github.com/nikhildehariya/netguard-ids.git
cd netguard-ids

# 2. Initialize Python virtual environment
python -m venv venv

# Windows activation
venv\Scripts\activate
# Linux activation
source venv/bin/activate

# 3. Install core dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 2: React Dashboard Build
```bash
cd react-dashboard
npm install
npm run build    # Produces production assets in react-dashboard/dist
cd ..
```

#### Step 3: Launch Services
In Terminal 1 (FastAPI Backend):
```bash
# Windows (Admin PowerShell) or Linux (sudo)
python -m uvicorn api.main:app --host 0.0.0.0 --port 8081
```

In Terminal 2 (React Frontend Development Server):
```bash
cd react-dashboard
npm run dev -- --port 5174
```

---

### Option C: 24/7 Production Deployment via Windows NSSM

To run NetGuard IDS permanently as managed Windows background services that automatically restart on failure:

```powershell
# Open Administrator PowerShell
# 1. Backend API Service
nssm install NetGuard-API "C:\iot-ids\venv\Scripts\uvicorn.exe" "api.main:app --host 0.0.0.0 --port 8081"
nssm set NetGuard-API AppDirectory "C:\iot-ids"
nssm set NetGuard-API Start SERVICE_AUTO_START

# 2. React UI Service
nssm install NetGuard-UI "C:\Program Files\nodejs\npx.cmd" "serve -s dist -l 5174"
nssm set NetGuard-UI AppDirectory "C:\iot-ids\react-dashboard"
nssm set NetGuard-UI Start SERVICE_AUTO_START

# 3. Dedicated Capture Service
nssm install NetGuard-Capture "C:\iot-ids\venv\Scripts\python.exe" "src/capture.py --iface ""Wi-Fi"""
nssm set NetGuard-Capture AppDirectory "C:\iot-ids"
nssm set NetGuard-Capture Start SERVICE_AUTO_START

# Start All Services
nssm start NetGuard-API
nssm start NetGuard-UI
nssm start NetGuard-Capture
```

---

### Option D: Native Linux Edge Appliance Deployment (`systemd`)

The repository includes enterprise `systemd` unit files and an automated installer under `deploy/install.sh`:

```bash
# Make installer executable and run with root privileges
chmod +x deploy/install.sh
sudo ./deploy/install.sh
```

**Unit Configuration Details**:
- **API Unit**: `deploy/systemd/netguard-api.service`
- **Worker Unit**: `deploy/systemd/netguard-worker.service`
- **UI Unit**: `deploy/systemd/netguard-ui.service`

To control manually:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now netguard-api netguard-worker netguard-ui
sudo systemctl status netguard-api
```

---

### Option E: Containerized Fleet Deployment (Docker Compose)

The system includes a multi-container stack orchestrated via `docker-compose.yml`:

```yaml
version: '3.8'
services:
  redis:
    image: redis:7-alpine
    container_name: netguard_redis
    restart: unless-stopped
    ports: ["6379:6379"]

  api:
    build: { context: ., dockerfile: Dockerfile.api }
    container_name: netguard_api
    restart: unless-stopped
    cap_add: [NET_RAW, NET_ADMIN]
    network_mode: "host"
    env_file: [.env]
    volumes:
      - ./logs:/app/logs
      - ./models:/app/models
      - ./reports:/app/reports
    depends_on: [redis]

  frontend:
    build: { context: ., dockerfile: Dockerfile.frontend }
    container_name: netguard_frontend
    restart: unless-stopped
    ports: ["80:80"]
    depends_on: [api]
```

**Launch Cluster**:
```bash
docker compose up -d --build
```
*Access dashboard on port `80`, reverse-proxied to the FastAPI engine.*

---

## 4. Master Configuration Specification (`.env`)

All platform parameters are configured in the root `.env` file and parsed via `src/config.py`:

```ini
# ==============================================================================
# NETGUARD IDS ENTERPRISE CONFIGURATION SPECIFICATION
# ==============================================================================

# ── API & Network Binding ─────────────────────────────────────────────────────
API_PORT=8081
API_HOST=0.0.0.0
ALLOWED_ORIGINS=http://localhost:5174,http://127.0.0.1:5174

# ── Hybrid Cloud Database (Neon PostgreSQL) ──────────────────────────────────
# Connection URI for persistent remote cloud synchronization
DATABASE_URL=postgresql://neondb_owner:npg_key@ep-cool-base.us-east-2.aws.neon.tech/neondb?sslmode=require
USE_POSTGRES=false

# ── Redis Stream Flow Buffer ─────────────────────────────────────────────────
USE_REDIS_BUFFER=true
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_STREAM_KEY=netguard:flow_stream
REDIS_CONSUMER_GROUP=netguard_inference_group

# ── Cryptographic Security & RBAC ────────────────────────────────────────────
# 64-character persistent hex secret for JWT token signatures
SECRET_KEY=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
# Internal packet capture agent key (prevents unauthenticated /predict spam)
AGENT_SECRET_KEY=9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b

# Default Initial Administrator Credentials
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=netguard123

# ── Active Automated Containment (Firewall) ──────────────────────────────────
AUTO_BLOCK_ENABLED=true
# Minimum consecutive attacks before auto-containment triggers
AUTO_BLOCK_THRESHOLD=3
# Minimum model confidence required to execute automated firewall rule
AUTO_BLOCK_CONFIDENCE=0.95
# Time-To-Live for active blocks in seconds (3600 = 1 hour, 0 = permanent)
AUTO_BLOCK_TTL=3600
# Comma-separated severities eligible for auto-containment
AUTO_BLOCK_SEVERITIES=critical
# Whitelisted IP addresses that CANNOT be blocked under any condition
WHITELISTED_IPS=127.0.0.1,8.8.8.8,8.8.4.4,1.1.1.1

# ── SOC Alerting: SMTP SSL Email ─────────────────────────────────────────────
ALERT_FROM_EMAIL=soc-alerts@enterprise.com
ALERT_TO_EMAIL=incident-response@enterprise.com
ALERT_PASSWORD=app_specific_secure_password

# ── SOC Alerting: Telegram Bot with Expiring Action Links ────────────────────
TELEGRAM_BOT_TOKEN=7123456789:AAExampleBotTokenString
TELEGRAM_CHAT_ID=-1001234567890

# ── SIEM & Enterprise Webhook Dispatch ───────────────────────────────────────
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/XXXXX
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/000/XXXXX
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/XXXXX
SYSLOG_HOST=127.0.0.1
SYSLOG_PORT=514

# ── GenAI Security Copilot ───────────────────────────────────────────────────
GEMINI_API_KEY=AIzaSyExampleGeminiKey
HF_TOKEN=hf_ExampleHuggingFaceToken
```

---

## 5. Architectural Deep-Dive: Core Functionalities

### 5.1 Dual-ML Engine: XGBoost + Isolation Forest Zero-Day Detection

NetGuard avoids reliance on brittle static signatures. In `src/predict.py`, it runs a two-tier hybrid ML pipeline:

```
                          ┌────────────────────────┐
                          │ Incoming Flow Features │
                          │     (80 Metrics)       │
                          └───────────┬────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 ▼                                         ▼
   ┌───────────────────────────┐             ┌───────────────────────────┐
   │    XGBoost Classifier     │             │     Isolation Forest      │
   │  Supervised Multi-Class   │             │   Unsupervised Zero-Day   │
   │  (CIC-IDS2018 benchmark)  │             │   (Outlier Contamination) │
   └─────────────┬─────────────┘             └─────────────┬─────────────┘
                 │ Label & Confidence                      │ Anomaly Score
                 └────────────────────┬────────────────────┘
                                      ▼
                        ┌───────────────────────────┐
                        │  Domain-Adaptive Arbiter  │
                        │   (IoT Port Thresholds)   │
                        └─────────────┬─────────────┘
                                      ▼
                      Final Prediction & Severity Class
```

#### Multi-Class Supervised Classification (XGBoost)
- **Trained Model**: `models/xgb_model.pkl`
- **Training Set**: CIC-IDS2018 (8.2 million flows across 80 bidirectional flow attributes).
- **Classification Categories**:
  - `NORMAL` (Class 0): Benign enterprise and sensor traffic.
  - `BRUTE_FORCE` (Class 1): SSH/FTP credential stuffing.
  - `DOS_DDOS` (Class 2): Slowloris, GoldenEye, Hulk, LOIC/HOIC UDP/TCP floods.
  - `WEB_ATTACK` (Class 3): SQL Injection, Cross-Site Scripting (XSS).
  - `INFILTRATION` (Class 4): Port scanning, C2 beaconing, internal reconnaissance.

#### Unsupervised Zero-Day Anomaly Detection (Isolation Forest)
- **Trained Model**: `models/iforest_model.pkl`
- **Algorithm**: Tree-based space-partitioning measuring the isolation path length:
  $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
  where $E(h(x))$ is the average path length across isolation trees, and $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree.
- **Domain-Adaptive Thresholding**:
  If the target destination port is a known industrial protocol (Modbus `502`, MQTT `1883`/`8883`, CoAP `5683`, OPC-UA `4840`) or the packet rate exceeds 1,000 pkts/s, the anomaly sensitivity threshold dynamically adjusts from $0.65 \to 0.55$.
- **Arbiter Decision Logic**: If XGBoost predicts `NORMAL` but the Isolation Forest flags an anomaly score exceeding the threshold, NetGuard overrides the verdict to `ZERO_DAY_ANOMALY` with `critical` severity.

---

### 5.2 Industrial IoT Deep Packet Inspection (DPI)

Implemented in `src/dpi_decoders.py`, the DPI engine dissects raw application-layer payloads on industrial ports:

1. **Modbus TCP (Port 502)**:
   - Validates the 7-byte MBAP Header: `Transaction ID (2B) | Protocol ID (2B == 0) | Length (2B) | Unit ID (1B)`.
   - Inspects the **Function Code**: Differentiates legitimate reads (`0x01` Read Coils, `0x03` Read Holding Registers) from critical actuator writes (`0x05` Write Single Coil, `0x06` Write Single Register, `0x0F` Write Multiple Coils, `0x10` Write Multiple Registers).
   - Generates an immediate protocol anomaly alert whenever unauthorized coil or register modifications are detected.
2. **MQTT (Ports 1883 / 8883)**:
   - Decodes MQTT fixed and variable headers across 15 packet types (`CONNECT`, `PUBLISH`, `SUBSCRIBE`, `PINGREQ`, etc.).
   - Detects topic reconnaissance and wildcard sniffing attempts (`#` or `+` wildcard subscriptions).
   - Flags suspicious publish actions to critical command topics (e.g., `cmd/actuator`, `system/reboot`, `admin/override`).
3. **CoAP (Constrained Application Protocol - Port 5683)**:
   - Unpacks binary CoAP headers: `Version (2b) | Type (2b) | Token Length (4b) | Code (8b) | Message ID (16b)`.
   - Identifies destructive `DELETE` methods or suspicious remote code requests against constrained IoT sensors.

---

### 5.3 Automated Rolling PCAP Forensics

Located in `src/pcap_forensics.py`:
- **Ring Buffer**: Maintains an in-memory `collections.deque` circular ring buffer capturing the trailing 60 seconds (up to 2,500 raw Scapy packets) with **zero disk write overhead** during peacetime.
- **Trigger Condition**: When an incident with severity `critical` or `high` is identified by the ML or DPI pipeline, a background worker dumps the buffer into a forensically tagged Wireshark file:
  `reports/forensics/alert_<IP>_<PREDICTION>_<TIMESTAMP>.pcap`
- **Retention & Path Traversal Guard**: Capped at 50 PCAP files with automated FIFO pruning. File downloads via `GET /forensics/download/{filename}` enforce strict relative path containment (`is_relative_to`) and filename sanitization.

---

### 5.4 Explainable AI (XAI) via Production TreeSHAP

Implemented in `src/xai.py` and `src/explainable.py`:
- Unlike heuristic mock explainers, NetGuard embeds the official `shap.TreeExplainer` directly on the trained XGBoost model.
- Calculates exact mathematical **Shapley Additive Explanations**:
  $$f(x) = \phi_0 + \sum_{i=1}^{M} \phi_i(x)$$
  where $\phi_i(x)$ quantifies the exact directional push (positive towards attack, negative towards normal) that feature $i$ contributed to the classifier's output.
- Returns the Top-5 influential features, raw values, scaled contributions, and natural-language rationale via `POST /explain`.

---

### 5.5 Live Packet Sniffing & Flow Reconstruction (`capture.py`)

Located in `src/capture.py`:
- **Promiscuous Ingestion**: Hooks into Scapy `sniff()` across physical adapters (`Wi-Fi`, `Ethernet`, or Linux `eth0`).
- **Stateful 5-Tuple Tracking**: Maintains an in-memory dictionary tracking flows by `(src_ip, dst_ip, src_port, dst_port, protocol)`.
- **Statistical Feature Extraction**: Reconstructs 80 flow statistics in real-time, including Inter-Arrival Times (IAT Mean/Std/Max/Min), packet size distributions, flag counters (FIN, SYN, RST, PSH, ACK, URG), and window byte sizes.
- **Dual Flush Mechanism**:
  1. **Packet Count Flush**: Emits flow record every 5 packets or upon `TCP FIN`/`RST`.
  2. **Timer Flush**: A dedicated background thread sweeps every 2 seconds, flushing idle flows to keep the SOC dashboard updated in real-time.
- **System-Wide Process Mutex**: Employs OS-level file locking (`msvcrt.locking` on Windows, `fcntl.flock` on Linux) on `logs/capture.lock` to prevent duplicate sniffer processes.

---

### 5.6 High-Burst Redis Streams Buffer

Located in `src/stream_producer.py` and `src/stream_consumer.py`:
- **Producer**: When high-volume packet bursts occur, flows are dispatched to Redis Stream `netguard:flow_stream` via `XADD`.
- **Consumer**: A non-blocking background daemon reads batches of up to 100 flows via `XREADGROUP`, distributing them across worker threads.
- **Graceful Fallback**: If Redis is offline or not installed, the producer automatically switches to direct, thread-pooled HTTP ingestion to the FastAPI backend without dropping flows.

---

### 5.7 Hybrid Dual-Database Engine (SQLite WAL + Neon Cloud PostgreSQL)

Located in `src/database.py` and `src/detections_db.py`:
- **Local SQLite WAL (`logs/detections.db`)**: Configured with `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=NORMAL`, achieving sub-millisecond local writes (`<1ms`) to avoid blocking line-rate packet capture.
- **Neon Cloud PostgreSQL Synchronization**: Every 30 seconds, a background daemon in `api/main.py` runs `scripts/migrate_sqlite_to_pg.py` to sync local detection logs, user accounts, and blocklist records to the remote Neon Cloud PostgreSQL instance over SSL.

---

### 5.8 Cryptographic Licensing Engine (RSA / Ed25519)

Located in `src/license.py`:
- **Digital Signatures**: Licenses are signed with either Ed25519 (recommended, 32-byte keys) or RSA-2048 with PSS/SHA-256 padding.
- **Payload Structure**: Base64URL-encoded payload containing `license_id`, `licensee`, `tier`, `issued_at`, `expires_at`, `max_devices`, and `hardware_id`.
- **Hardware Binding**: Soft-bound to the machine's hardware fingerprint (SHA-256 hash of OS, architecture, and network MAC).
- **Tier Enforcement**:
  - **Trial Tier**: Basic supervised ML detection, local storage.
  - **Pro Tier**: Adds TreeSHAP XAI explainability (`POST /explain`), automated firewall containment, and custom reports.
  - **Enterprise Tier**: Adds GenAI Copilot (`/assistant/*`), SIEM RFC 5424 Syslog export, multi-tenancy, and unlimited monitored endpoints.
- **Grace Period**: Operates under an automatic 3-day grace period post-expiry to prevent sudden disruption.

---

### 5.9 Automated Containment & Firewall Enforcement

Located in `src/blocklist.py`:
- **Windows Firewall**: Adds bidirectional rules via `netsh advfirewall firewall add rule name="NetGuard-Block-<IP>-in" dir=in action=block remoteip=<IP>`.
- **Linux iptables**: Injects blocking rules across `INPUT`, `OUTPUT`, and `FORWARD` chains (`iptables -I INPUT 1 -s <IP> -j DROP`).
- **Protected Whitelist**: Enforces strict exemptions for loopback (`127.0.0.0/8`, `::1`), default gateway IP, local host IP, and corporate DNS servers (`8.8.8.8`, `1.1.1.1`).
- **TTL Auto-Pruning**: A background thread checks the blocklist every 60 seconds; expired temporary blocks are automatically removed from both the firewall and the database.

---

### 5.10 Multi-Channel Alerting & SIEM Integration

Located in `src/alert.py` and `src/webhook_exporters.py`:
- **HTML Email**: Styled alert report sent via SMTP over SSL (`smtplib.SMTP_SSL`).
- **Telegram Bot**: Pushes incident cards with severity badges, confidence ratings, and an expiring HMAC-signed quick-block action URL (`/api/telegram/block?ip=...&sig=...&expires=...`).
- **Webhook Integrations**: Dispatches JSON payloads to Slack Incoming Webhooks, Discord Webhooks, and Microsoft Teams Connectors.
- **SIEM RFC 5424 / CEF Syslog**: Dispatches Common Event Format (CEF) UDP datagrams to central SIEM log collectors (Splunk, IBM QRadar, Wazuh):
  ```
  CEF:0|NetGuard|NetGuard-IDS|2.2|DOS_DDOS|Network Intrusion Event: DOS_DDOS|8|src=192.168.1.105 dst=10.0.0.1 msg=High-confidence attack detected
  ```

---

### 5.11 Network Device Scanner

Located in `src/scanner.py`:
- **Fast ARP Scan**: Transmits Scapy `ARP(pdst=subnet)` requests wrapped in `Ether(dst="ff:ff:ff:ff:ff:ff")` to discover active IP/MAC addresses in 2–3 seconds.
- **Detailed Nmap Scan**: Executes `python-nmap` port sweeps against discovered devices, identifying open ports (e.g., 22, 80, 443, 502, 1883), running services, and OS fingerprints.
- **Gateway Identification**: Automatically discovers the default gateway, subnet mask, and resolves vendor names via IEEE OUI database lookups.

---

### 5.12 GenAI Security Copilot & Threat Assistant

Located in `src/genai_assistant.py`:
- **Supported Backends**:
  1. **Google Gemini API**: Uses `gemini-flash-latest` or `gemini-pro-latest` via HTTPS REST.
  2. **Local Ollama**: Connects to `http://localhost:11434/api/generate` with `llama3.2` for air-gapped environments.
  3. **HuggingFace Inference API**: Uses models such as `Qwen/Qwen2.5-Coder-32B-Instruct`.
  4. **Rule-Based Fallback**: An internal rule engine that provides triage advice even if all external AI APIs are unreachable.
- **Capabilities**:
  - `/assistant/insights`: Generates executive threat briefing summaries.
  - `/assistant/chat`: Natural-language conversational interface answering questions about active attacks, top attacking IPs, and recommended mitigation steps.

---

### 5.13 Multi-Tenancy & RBAC Access Control

Located in `src/auth.py`:
- **Tenant Isolation**: Every database table (`users`, `detections`, `blocked_ips`) includes a `tenant_id` column. User JWT tokens encode the `tenant_id` claim, preventing cross-organization data leakage.
- **Password Security**: Passwords are hashed using **PBKDF2-HMAC-SHA256** with 260,000 iterations and unique 16-byte cryptographic salts.
- **Brute Force Lockout**: Accounts are locked for 15 minutes after 5 consecutive failed login attempts.
- **Refresh Token Rotation (RTR)**: Every call to `/auth/refresh` invalidates the existing refresh token and issues a fresh, single-use token pair.
- **Role-Based Permission Matrix**:
  | Permission | Admin | Analyst | Viewer |
  |:---|:---:|:---:|:---:|
  | `view` (Dashboard, Stats, History) | ✅ | ✅ | ✅ |
  | `capture` (Start/Stop Sniffing, Forensics) | ✅ | ✅ | ❌ |
  | `block_ip` (Firewall Block) | ✅ | ✅ | ❌ |
  | `unblock_ip` (Firewall Unblock) | ✅ | ❌ | ❌ |
  | `report` (Export PDF / CSV) | ✅ | ✅ | ❌ |
  | `manage_users` (User Admin, Licensing) | ✅ | ❌ | ❌ |

---

## 6. Comprehensive REST API Reference

The backend exposes 35+ REST endpoints on `http://127.0.0.1:8081`. Interactive Swagger documentation is available at `/docs`.

### 6.1 Authentication & User Management
| Method | Path | Required Permission | Description |
|:---|:---|:---|:---|
| `POST` | `/auth/login` | None | Authenticate with username & password; returns access & refresh JWTs |
| `POST` | `/auth/refresh` | None | Exchange valid refresh token for a new access token (with RTR) |
| `POST` | `/auth/logout` | None | Revoke refresh token |
| `GET` | `/auth/me` | Any valid user | Return current authenticated profile and permissions |
| `POST` | `/auth/users` | `manage_users` (Admin) | Register a new system user |
| `GET` | `/auth/users` | `manage_users` (Admin) | List all registered user accounts |
| `PATCH`| `/auth/users/{username}/role` | `manage_users` (Admin) | Change user role (`admin`, `analyst`, `viewer`) |
| `PATCH`| `/auth/users/{username}/toggle`| `manage_users` (Admin) | Enable or disable user account |
| `DELETE`| `/auth/users/{username}` | `manage_users` (Admin) | Permanently delete user account |

### 6.2 Inference, Detection & Diagnostics
| Method | Path | Required Permission / Header | Description |
|:---|:---|:---|:---|
| `POST` | `/predict` | `X-Agent-Key` or `view` | Submit a single 80-feature network flow record for real-time classification |
| `POST` | `/predict/batch` | `view` | Submit an array of flow records for high-throughput batch classification |
| `POST` | `/explain` | `view` (Requires Pro Tier) | Compute TreeSHAP Shapley values and feature importance for a flow |
| `GET` | `/history` | `view` | Retrieve historical detection logs with optional limit and time filtering |
| `GET` | `/stats` | `view` | Fetch aggregate threat metrics, attack breakdown, and detection rates |
| `GET` | `/health` | None | Service liveness probe returning detector and database status |
| `GET` | `/research/metrics`| `view` | Retrieve empirical performance metrics, F1-scores, and latency percentiles |
| `GET` | `/research/figure/{filename}` | `view` | Download empirical evaluation charts (ROC, confusion matrix, SHAP plots) |

### 6.3 Containment & Blocklist
| Method | Path | Required Permission | Description |
|:---|:---|:---|:---|
| `GET` | `/blocked-ips` | `view` | List all currently blocked IP addresses and expiry timestamps |
| `POST` | `/blocked-ips` | `block_ip` (Analyst/Admin) | Block an IP address on the host firewall with optional TTL |
| `DELETE`| `/blocked-ips/{ip}` | `unblock_ip` (Admin only) | Unblock an IP address and remove associated firewall rules |
| `POST` | `/blocked-ips/bulk-block` | `block_ip` (Analyst/Admin) | Block multiple IP addresses in a single request |
| `POST` | `/blocked-ips/bulk-unblock` | `unblock_ip` (Admin only) | Bulk unblock IP addresses |
| `GET` | `/blocked-ips/audit` | `manage_users` (Admin) | Retrieve the audit trail of all block/unblock actions |
| `GET` | `/api/telegram/block` | Expiring HMAC Token | One-click containment endpoint from Telegram alert messages |

### 6.4 Packet Sniffer & Rolling Forensics
| Method | Path | Required Permission | Description |
|:---|:---|:---|:---|
| `GET` | `/capture/interfaces` | `capture` (Analyst/Admin) | List all available network adapters with IP and MAC info |
| `GET` | `/capture/status` | `view` | Check if packet capture is active, packet count, and bound interface |
| `POST` | `/capture/start` | `capture` (Analyst/Admin) | Start live promiscuous packet capture on a specified adapter |
| `POST` | `/capture/stop` | `capture` (Analyst/Admin) | Terminate active packet capture |
| `GET` | `/forensics/pcaps` | `view` | List all available automated forensic PCAP incident files |
| `GET` | `/forensics/download/{filename}` | `view` | Securely download a forensic PCAP file |
| `POST` | `/forensics/trigger-dump` | `capture` (Analyst/Admin) | Manually trigger a 60-second forensic PCAP snapshot from the ring buffer |

### 6.5 Network Device Scanner
| Method | Path | Required Permission | Description |
|:---|:---|:---|:---|
| `POST` | `/network/scan/arp` | `capture` (Analyst/Admin) | Run a fast ARP ping sweep across the local subnet |
| `POST` | `/network/scan` | `capture` (Analyst/Admin) | Run a full ARP + Nmap port scan with OS detection |
| `GET` | `/network/devices` | `view` | Retrieve cached network devices from the most recent scan |

### 6.6 Commercial Licensing & Copilot
| Method | Path | Required Permission | Description |
|:---|:---|:---|:---|
| `GET` | `/api/license/status` | None | Query current cryptographic license status, tier, and days remaining |
| `POST` | `/api/license/activate` | `manage_users` (Admin) | Activate a signed license key string |
| `GET` | `/assistant/insights` | `view` (Enterprise Tier) | Generate an AI-synthesized threat briefing |
| `POST` | `/assistant/chat` | `view` (Enterprise Tier) | Conversational security assistant query interface |
| `GET` | `/reports/export` | `report` (Analyst/Admin) | Generate and download an executive PDF threat report |

---

## 7. React 19 SOC Dashboard Operator Guide

The React dashboard runs on `http://localhost:5174` and is structured into 9 dedicated operational modules:

1. **Overview & Telemetry Pulse (`OverviewTab.jsx`)**:
   - Real-time 1-second telemetry heartbeat showing packets/sec, active threats, and system status.
   - Recharts dynamic flow timeline displaying event velocity over time.
   - Attack severity distribution cards (`Normal`, `Critical`, `High`).
2. **Live Incident Feed (`IncidentsTab.jsx`)**:
   - Stream of incoming network events with color-coded severity badges.
   - One-click **"Block IP"** button to immediately contain suspicious sources.
   - **"Explain"** button that opens the TreeSHAP modal.
3. **Packet Capture Controller (`CaptureTab.jsx`)**:
   - Dropdown of physical network interfaces detected by the OS.
   - One-click Start/Stop capture controls with live packet and byte counters.
   - Rolling PCAP Forensics table with one-click Wireshark download links.
4. **Network Device Scanner (`DevicesTab.jsx`)**:
   - Quick ARP Scan (2–3s) and Detailed Nmap Scan controls.
   - Discovered devices table listing IP, MAC address, vendor OUI, open ports, and device type.
5. **Containment Blocklist (`BlocklistTab.jsx`)**:
   - Active host firewall blocks with creation timestamps and TTL expiration countdowns.
   - Manual block input field with reason and duration configuration.
   - Historical audit log recording every containment and unblock event.
6. **AI Security Copilot (`AssistantTab.jsx`)**:
   - Executive Threat Briefing generator with one-click refresh.
   - Interactive chat window for querying recent threat patterns and security advice.
7. **Research Benchmarks & Diagnostics (`ResearchTab.jsx`)**:
   - Real-time display of empirical latency percentiles ($p_{50}$, $p_{95}$, $p_{99}$), memory footprint, and model disk sizes.
   - Visual ROC curves and confusion matrices comparing NetGuard against baseline models.
8. **User & Access Management (`UsersTab.jsx` - Admin Only)**:
   - Create, edit, toggle, or delete user accounts and assign RBAC roles.
   - Update SOC notification email addresses and configure alert thresholds.
9. **License Management & Activation**:
   - Displays active license tier (`Trial`, `Pro`, `Enterprise`), licensee name, expiration date, and device cap.
   - Paste-and-activate form for applying new cryptographic license keys.

---

## 8. Enterprise Pilot Provisioning & Script Reference

### 8.1 Automated Customer Pilot Provisioning
To onboard a new enterprise customer or facility with an isolated tenant scope, dedicated admin account, and cryptographically signed license:

```powershell
python scripts/provision_pilot.py `
  --company "Acme Industrial" `
  --email "admin@acme-corp.com" `
  --password "SecurePilotPass2026!" `
  --tier ENTERPRISE `
  --days 30 `
  --devices 100
```

**Artifacts Generated**:
- Provisions tenant record `acme_industrial` in the database.
- Issues an Ed25519-signed commercial license key.
- Creates `pilot_deployments/acme_industrial/.env.pilot` pre-configured for the customer's deployment.

---

### 8.2 End-to-End System Verification Suite
To verify all 5 architectural layers in a single automated test run:

```powershell
python tests/verify_all.py
```
*Validates: (1) Dual-ML inference, (2) Native TreeSHAP mathematical reasoning, (3) Multi-tenant telemetry isolation, (4) Cryptographic asymmetric licensing, and (5) SIEM RFC 5424 / CEF Syslog dispatch.*

---

### 8.3 Diagnostics & Hardware Latency Profiler
To measure empirical edge hardware performance across 3,000 live inference cycles:

```powershell
python scripts/run_diagnostics.py
```

**Benchmark Results**:
- **Median Inference Latency ($p_{50}$)**: `17.6 – 19.1 ms`
- **95th Percentile Latency ($p_{95}$)**: `28.1 – 42.8 ms`
- **99th Percentile Latency ($p_{99}$)**: `31.2 – 148.9 ms`
- **Active In-Memory RAM Footprint**: `9.78 MB`
- **Total Serialized Model Size**: `5.03 MB`
- **False Alarm Rate (FAR)**: `0.145%`
- **Benign IoT Telemetry Accuracy**: `100.0%` (Zero false alarms on legitimate sensor traffic)

---

## 9. Security Hardening & Audit Verification

NetGuard IDS has undergone a line-by-line security audit. The following vulnerabilities have been remediated and verified:

| Vulnerability & Location | Severity | Mitigation Implemented |
|:---|:---:|:---|
| **Path Traversal** (`/research/figure/{filename}`) | Critical | Enforces `os.path.basename`, whitelist extension checks (`.png`, `.svg`), and strict `is_relative_to` directory containment. |
| **Path Traversal** (`/forensics/download/{filename}`) | Critical | Rejects relative paths; ensures requested file resides strictly within `reports/forensics/`. |
| **Dev License Backdoors** (`api/main.py`, `license.py`) | High | Removed all development bypass keys (`NETGUARD-DEV`, `DEV-MASTER`); license activation requires `manage_users` permission. |
| **Disabled SSL Verification** (`genai_assistant.py`) | High | Removed `CERT_NONE`; outbound requests to Google Gemini and Hugging Face enforce standard platform CA certificates. |
| **Wildcard CORS** (`api/main.py`) | Medium | Replaced wildcard `*` with strict `ALLOWED_ORIGINS` whitelist matching the configured dashboard port and production domains. |
| **Shared IP Lockout DoS** (`auth.py`) | Medium | Separated account lockout from IP spray defense; exempts loopback (`127.0.0.1`) from shared lockout denial-of-service. |
| **Replay-Prone Telegram Action Links** (`api/main.py`) | Medium | HMAC signatures now bind to a UNIX expiration timestamp; links past expiration return `403 Link Expired`. |
| **Predict Spam Denial of Service** (`api/main.py`) | Medium | The `/predict` endpoint requires either a valid internal `X-Agent-Key` or an authenticated user token. |
| **Subnet Command Injection** (`scanner.py`) | Low | Validates subnet strings with `ipaddress.ip_network(subnet, strict=False)` before executing sweeps. |

---

## 10. Operational Troubleshooting & Runbook

### Issue 1: Port 8081 or 5174 Already in Use
**Symptom**: `[Errno 10048] error while attempting to bind on address ('0.0.0.0', 8081)`.  
**Remediation**:
```powershell
# Identify and terminate process holding port 8081
Get-NetTCPConnection -LocalPort 8081 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
# For port 5174
Get-NetTCPConnection -LocalPort 5174 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```

### Issue 2: Packet Sniffer Exits Immediately or Captures 0 Packets
**Symptom**: Dashboard shows `Capture: STOPPED` or packet counters remain at zero.  
**Root Causes & Fixes**:
1. **Npcap Missing / Not in WinPcap Mode (Windows)**: Reinstall Npcap with the *"Install Npcap in WinPcap API-compatible Mode"* checkbox enabled.
2. **Missing Administrative Privileges**: Scapy requires administrative permissions to open raw sockets. Ensure PowerShell was launched via **"Run as Administrator"** (or `sudo` on Linux).
3. **Capture Process Lock Held**: If a previous sniffer crashed abruptly, delete the stale lock file:
   ```powershell
   Remove-Item "logs\capture.lock" -Force -ErrorAction SilentlyContinue
   ```

### Issue 3: Firewall Rules Not Applying on Attack Detection
**Symptom**: Console logs show `DB Blocklist active (Windows Firewall requires Run as Admin)`.  
**Remediation**: The backend process must run under an elevated Administrator token to interact with `netsh advfirewall`. Restart the API service from an elevated command prompt or install it as a Windows Service via NSSM.

### Issue 4: License Expired — UI Access Recovery
**Symptom**: Screen prompts that the software license has expired.  
**Remediation**: Log in as an Administrator (`admin` / `netguard123`), navigate to the license renewal prompt, and paste a newly issued license key generated via:
```powershell
python scripts/generate_license.py --tier PRO --days 365
```

---

## 11. Maintenance, Backup & Support Contacts

### Database Backup
- **Local SQLite Logs**: Back up `logs/detections.db`, `logs/auth.db`, and `logs/blocklist.db`.
- **Neon Cloud PostgreSQL**: Managed cloud backups with continuous WAL point-in-time recovery on AWS `us-east-2`.

### System Maintenance Commands
```powershell
# Reset local SQLite detection logs
Remove-Item "logs\detections.db*" -Force

# Run end-to-end automated smoke test
.\smoke-test.ps1

# Clean Python caches
Get-ChildItem -Path . -Filter "__pycache__" -Recurse | Remove-Item -Recurse -Force
```

### Support & Engineering Contact
- **Lead Architect & Maintainer**: Nikhil Dehariya
- **Email**: `nikhildehariya101@gmail.com`
- **Location**: Bhopal, Madhya Pradesh, India
- **Repository**: https://github.com/nikhildehariya/netguard-ids
