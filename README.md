# 🛡️ NetGuard IDS v2.2
### Enterprise IoT Network Detection & Response (NDR) and Intrusion Prevention System (NIPS)

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![XGBoost](https://img.shields.io/badge/XGBoost-F1%3A90.25%25-green?style=flat-square)
![Isolation Forest](https://img.shields.io/badge/Zero--Day-Isolation%20Forest-purple?style=flat-square)
![React](https://img.shields.io/badge/React-19.0-61DAFB?style=flat-square&logo=react)
![FastAPI](https://img.shields.io/badge/FastAPI-v0.111-009688?style=flat-square&logo=fastapi)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Neon%20Cloud-336791?style=flat-square&logo=postgresql)
![Redis](https://img.shields.io/badge/Redis-Streams%20Buffer-DC382D?style=flat-square&logo=redis)
![Nmap](https://img.shields.io/badge/Nmap-7.99-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

> **Real-time IoT Network Detection and Response (NDR) and Automated Intrusion Prevention System (NIPS)** operating across **OSI Layers 3, 4, and 7** and **Purdue Model Levels 1–3**. Combines real-time XGBoost ML classification, Isolation Forest zero-day anomaly detection, Explainable AI (XAI), Redis Stream flow buffering, Neon Cloud PostgreSQL synchronization, RSA/Ed25519 product licensing, and automated OS firewall containment.

---

## 📌 Executive Summary & Market Positioning

**NetGuard IDS v2.2** bridges the gap between legacy signature-based intrusion detection systems and modern cloud-native threat intelligence platforms. Built to protect industrial IoT environments, critical infrastructure, and enterprise networks, NetGuard IDS provides:

* **Purdue Model Levels 1–3 Coverage**: Monitors I/O devices, controller networks, and supervisory operations.
* **Dual ML Engines**: High-precision XGBoost classifier (CIC-IDS2018 benchmarked) paired with Isolation Forest for zero-day threat discovery.
* **Sub-Second Telemetry & Containment**: Real-time packet capture, 1-second pulse telemetry, and automated OS-level firewall containment (Windows Firewall & Linux iptables).
* **Hybrid Storage Architecture**: Sub-millisecond local writes via SQLite WAL paired with automatic background synchronization to **Neon Cloud PostgreSQL**.

---

## 📸 Dashboard Preview

| Overview & Telemetry | Live Incidents | Blocklist & Containment | Network Scanner |
|----------------------|----------------|-------------------------|-----------------|
| Real-time flow timeline, attack metrics & telemetry | Real-time attack feed with 1-click block | Automated IP firewall blocking & audit trail | ARP + Nmap active device scanner |

---

## 🚀 Key Features & Architecture

### 1. 🗄️ Hybrid Dual-Database Engine (PostgreSQL + SQLite WAL)
- **High-Speed Local Writes**: SQLite in Write-Ahead Logging mode (`logs/detections.db`) delivers **1ms sub-second local writes** and zero-latency UI rendering.
- **Neon Cloud PostgreSQL Integration**: Full ORM layer connected to **Neon Cloud PostgreSQL** (AWS `us-east-2`).
- **Automatic Background Cloud Sync**: Integrated non-blocking daemon worker in `api/main.py` continuously syncs local detection logs to Neon Cloud PostgreSQL every 30 seconds with **zero manual script execution**.

### 2. 🤖 Dual-ML & Zero-Day Anomaly Detection
- **XGBoost Classifier**: Multi-class classification across 5 primary attack categories (Normal, DoS/DDoS, Brute Force, Web Attack, Infiltration) trained on 8.2 million CIC-IDS2018 flows (**90.25% F1-Score**).
- **Isolation Forest Zero-Day Detector**: Integrated in `predict.py` to identify unknown, novel attack vectors (`ZERO_DAY_ANOMALY`) based on statistical flow contamination thresholds.
- **Explainable AI (XAI)**: SHAP-based feature importance breakdown (`/explain`) explaining why traffic was flagged as hostile.

### 3. ⚡ Redis Stream Flow Buffer & Resilient Pipeline
- **High-Burst Queueing**: Uses Redis Streams (`netguard:flow_stream`) via `stream_producer.py` and `stream_consumer.py` to buffer high-velocity packet flow spikes during DDoS attacks.
- **Graceful HTTP Fallback**: Automatically bypasses Redis if uninstalled or offline, routing packet flows directly without UI freezes or packet drops.

### 4. 🔑 RSA/Ed25519 Cryptographic Product Licensing
- Cryptographically signed license key engine (`src/license.py`) enforcing **Trial, Pro, and Enterprise Tiers**.
- Enforces expiration validation, hardware fingerprinting, and feature-gating middleware across API endpoints.

### 5. 🌐 Enterprise Auto-Protection & Sub-Second Telemetry
- **Auto-Start Sniffing**: Automatically detects and binds to active Wi-Fi/Ethernet adapters on server boot without requiring manual dashboard clicks.
- **1-Second Real-Time Telemetry Pulse**: Pushes sub-second packet flow counts, throughput, and attack statistics to the React Dashboard.
- **Dynamic Timeline & Timezone Sync**: Features dynamic historical traffic curve fallback when live capture is idle and formats UTC timestamps to local system timezone (IST).

### 6. 🔎 Network Device Scanner
- **Quick ARP Scan**: Instant local network device discovery (2–3 seconds).
- **Full ARP + Nmap Scan**: Detailed scanning with open port discovery and OS detection.
- **Auto Gateway Identification**: Identifies network gateways, vendor OUI, MAC addresses, and active hostnames.

### 7. 🤖 GenAI Security Copilot
- **Threat Briefing Generator** (`/assistant/insights`): AI-synthesized threat summary reports.
- **Interactive Security Assistant** (`/assistant/chat`): Natural language security copilot for querying network status and threat activity.

### 8. 🚫 Automated Threat Containment
- **Windows Firewall** auto-blocking via `netsh advfirewall`.
- **Linux iptables** support (`INPUT`, `OUTPUT`, `FORWARD` chains).
- TTL-based auto-expiry and configurable alert threshold triggering.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          NetGuard IDS v2.2                              │
├───────────────────┬─────────────────────────────┬───────────────────────┤
│  Live Capture     │       FastAPI Backend       │    React Dashboard    │
│  (Scapy Extractor)│       (Port 8081)           │    (Port 5174)        │
│                   │                             │                       │
│ Packet Streams ──►│ /predict & /predict/batch   │ Live Telemetry Pulse  │
│                   │ /history & /stats           │ Incident Feed         │
│ Redis Flow Buffer │ /auth/* & /blocked-ips      │ Devices Scanner       │
│ netguard:stream   │ /explain & /assistant/*     │ User Management       │
│                   │ /api/license/*              │ Copilot Assistant     │
└─────────┬─────────┴──────────────┬──────────────┴───────────────────────┘
          │                        │
          │           ┌────────────▼────────────┐
          │           │     Dual-ML Engines     │
          │           │   XGBoost (F1: 0.9025)  │
          │           │   Isolation Forest Zero-Day
          │           └────────────┬────────────┘
          │                        │
          │           ┌────────────▼────────────┐
          │           │   Hybrid Database Sync  │
          │           │  Local SQLite (1ms WAL) │
          │           │  ── 30s Auto Sync ──►   │
          │           │  Neon Cloud PostgreSQL  │
          │           └────────────┬────────────┘
          │                        │
          └────────────────────────┼────────────────────────────────┐
                                   │                                │
                      ┌────────────▼────────────┐      ┌────────────▼────────────┐
                      │    Containment Layer    │      │    Alerting Engines     │
                      │  Windows Firewall       │      │  HTML Email (SMTP SSL)  │
                      │  Linux iptables         │      │  Telegram Bot           │
                      └─────────────────────────┘      └─────────────────────────┘
```

---

## 📁 Project Structure

```
C:\iot-ids\
├── api/
│   └── main.py              ← FastAPI app, endpoints, background cloud sync daemon
├── src/
│   ├── config.py            ← Global configuration, thresholds, env loader
│   ├── database.py          ← Dual DB engine (SQLite WAL + Neon Cloud PostgreSQL)
│   ├── predict.py           ← Dual-ML detector (XGBoost + Isolation Forest Zero-Day)
│   ├── stream_producer.py   ← Redis Stream producer for flow buffering
│   ├── stream_consumer.py   ← Redis Stream background consumer worker
│   ├── license.py           ← Cryptographic RSA/Ed25519 product licensing engine
│   ├── preprocess.py        ← CIC-IDS2018 preprocessing & feature scaling
│   ├── train.py             ← XGBoost training entry point
│   ├── alert.py             ← Email SMTP & Telegram bot alerting engine
│   ├── blocklist.py         ← Windows Firewall & Linux iptables containment
│   ├── capture.py           ← Scapy packet capture & feature extraction (2s flush)
│   ├── auth.py              ← JWT authentication & RBAC user system
│   ├── reporting.py         ← PDF report generator (ReportLab)
│   ├── scanner.py           ← Network device scanner (ARP + Nmap)
│   ├── explainable.py       ← XAI feature importance breakdown (SHAP)
│   └── genai_assistant.py   ← GenAI Security Copilot & threat briefing generator
├── scripts/
│   ├── generate_license.py  ← License key generation utility
│   └── migrate_sqlite_to_pg.py ← Manual SQLite to Neon Cloud migration tool
├── react-dashboard/
│   └── src/
│       └── App.jsx          ← React 19 real-time dashboard UI
├── models/
│   ├── xgb_model.pkl        ← Trained XGBoost classifier
│   └── scaler.pkl           ← StandardScaler fitted model
├── logs/
│   ├── detections.db        ← Local high-speed SQLite detection DB
│   ├── auth.db              ← User auth database
│   └── blocklist.db         ← Blocklist & audit log database
├── docker-compose.yml       ← Docker orchestrator
├── Dockerfile.api           ← Backend API container spec
├── Dockerfile.frontend      ← Frontend React container spec
├── run-netguard.ps1         ← Unified 1-click launcher script
├── smoke-test.ps1           ← End-to-end test suite
├── .env                     ← Environment configuration
└── requirements.txt         ← Python dependencies
```

---

## ⚙️ Ports & Service Configuration

| Service | Protocol / Host | Port | Configuration File |
|---------|-----------------|------|--------------------|
| **Backend API** | `http://127.0.0.1` | **8081** | [src/config.py](file:///c:/iot-ids/src/config.py) |
| **React Dashboard** | `http://localhost` | **5174** | [react-dashboard/vite.config.js](file:///c:/iot-ids/react-dashboard/vite.config.js) |
| **Redis Server** *(Optional)* | `localhost` | **6379** | Default Redis port |
| **Neon Cloud PostgreSQL** | `aws-us-east-2.neon.tech` | **5432** | Environment `DATABASE_URL` |

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.11+**
- **Node.js 18+**
- **Windows 10/11** (for Firewall blocking) or **Linux** (iptables)
- **Npcap** (Windows) or **libpcap** (Linux)
- **Nmap 7.99+** ([download](https://nmap.org/download.html))

---

### Option 1: 1-Click Launch (Recommended)

Run the unified launcher in Admin PowerShell:

```powershell
.\run-netguard.ps1
```

> **What `run-netguard.ps1` does automatically:**
> 1. Verifies Python 3.11+ and Node.js 18+ environment.
> 2. Sets up Python `venv` and installs `requirements.txt`.
> 3. Installs React `node_modules`.
> 4. Starts FastAPI backend on **http://127.0.0.1:8081**.
> 5. Starts React Dashboard on **http://localhost:5174**.
> 6. Launches browser automatically.

---

### Option 2: Manual Setup & Launch

#### 1. Clone & Setup Virtual Environment
```bash
git clone https://github.com/nikhildehariya/netguard-ids.git
cd netguard-ids
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

#### 2. Configure `.env`
Create `.env` in the root folder:
```env
API_PORT=8081
DATABASE_URL=postgresql://neondb_owner:npg_key@ep-cool-base.us-east-2.aws.neon.tech/neondb?sslmode=require

# Email Alerts
ALERT_FROM_EMAIL=your@gmail.com
ALERT_TO_EMAIL=alert@gmail.com
ALERT_PASSWORD=your_app_password

# Telegram
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Auth
SECRET_KEY=your_64_char_hex_key
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=netguard123

# Auto-Block
AUTO_BLOCK_ENABLED=true
AUTO_BLOCK_THRESHOLD=3
AUTO_BLOCK_CONFIDENCE=0.95
AUTO_BLOCK_SEVERITIES=critical
```

#### 3. Start Backend API (Admin PowerShell)
```powershell
uvicorn api.main:app --host 0.0.0.0 --port 8081
```

#### 4. Start React Dashboard
```powershell
cd react-dashboard
npm install
npm run dev
```

Dashboard Access: [http://localhost:5174](http://localhost:5174)  
API Documentation: [http://localhost:8081/docs](http://localhost:8081/docs)

---

## 🔧 NSSM Services (24/7 Production on Windows)

To run NetGuard IDS permanently as Windows services:

```powershell
# 1. API Service (Port 8081)
nssm install NetGuard-API "C:\iot-ids\venv\Scripts\uvicorn.exe" "api.main:app --host 0.0.0.0 --port 8081"
nssm set NetGuard-API AppDirectory "C:\iot-ids"

# 2. React Dashboard Service (Port 5174)
nssm install NetGuard-React "C:\Program Files\nodejs\npx.cmd" "serve -s dist -l 5174"
nssm set NetGuard-React AppDirectory "C:\iot-ids\react-dashboard"

# 3. Packet Capture Service
nssm install NetGuard-Capture "C:\iot-ids\venv\Scripts\python.exe" "src/capture.py --iface ""Wi-Fi"""
nssm set NetGuard-Capture AppDirectory "C:\iot-ids"

# Start services
nssm start NetGuard-API
nssm start NetGuard-React
nssm start NetGuard-Capture
```

---

## 🧪 Testing & Validation

### End-to-End Automated Smoke Test
```powershell
.\smoke-test.ps1
```

### Manual Attack Validation
```powershell
# DoS/DDoS Classification Test
$body = Get-Content "dos_test.json" -Raw
Invoke-RestMethod -Uri "http://localhost:8081/predict" -Method POST -ContentType "application/json" -Body $body
```

---

## 📊 Model Performance

| Metric | Value |
|--------|-------|
| Benchmark Dataset | CIC-IDS2018 |
| Training Samples | ~6.5M flows |
| Test Samples | ~1.6M flows |
| Features | 80 network flow features |
| Core Classifier | XGBoost (`n_estimators=300`, `max_depth=6`) |
| Anomaly Detector | Isolation Forest (`contamination=0.03`) |
| **Macro F1 Score** | **0.9025** |

| Class | Precision | Recall | F1 Score |
|-------|-----------|--------|----------|
| NORMAL | 0.99 | 0.99 | 0.99 |
| BRUTE_FORCE | 0.95 | 0.92 | 0.93 |
| DOS_DDOS | 0.98 | 0.99 | 0.98 |
| WEB_ATTACK | 0.87 | 0.85 | 0.86 |
| INFILTRATION | 0.72 | 0.68 | 0.70 |

---

## 🌐 API Endpoints Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/auth/login` | ❌ | Login, obtain access & refresh JWT tokens |
| POST | `/auth/refresh` | ❌ | Refresh JWT access token |
| POST | `/auth/logout` | ❌ | Revoke refresh token |
| GET | `/auth/me` | ✅ any | Retrieve current authenticated user profile |
| POST | `/auth/users` | ✅ admin | Create new user account |
| GET | `/auth/users` | ✅ admin | List all system user accounts |
| PATCH | `/auth/users/{username}/role` | ✅ admin | Update user role (admin/analyst/viewer) |
| PATCH | `/auth/users/{username}/toggle` | ✅ admin | Enable / disable user account |
| DELETE | `/auth/users/{username}` | ✅ admin | Delete user account |
| GET | `/admin/alert-settings` | ✅ admin | View alert notification settings |
| PATCH | `/admin/alert-settings` | ✅ admin | Update alert recipient email |
| POST | `/predict` | ❌ | Real-time single flow ML classification |
| POST | `/predict/batch` | ❌ | High-throughput batch flow classification |
| POST | `/explain` | ✅ viewer | Explainable AI (SHAP) feature importance |
| GET | `/assistant/insights` | ✅ viewer | AI-synthesized threat briefings |
| POST | `/assistant/chat` | ✅ viewer | GenAI security copilot chat interface |
| GET | `/history` | ✅ viewer | Query historical detection logs |
| GET | `/stats` | ✅ viewer | Fetch aggregate network threat statistics |
| GET | `/health` | ❌ | API health check & service status |
| GET | `/blocked-ips` | ✅ viewer | Retrieve active firewall blocklist |
| POST | `/blocked-ips` | ✅ analyst | Block an IP address |
| DELETE | `/blocked-ips/{ip}` | ✅ admin | Unblock an IP address |
| POST | `/blocked-ips/bulk-block` | ✅ analyst | Bulk block IP addresses |
| POST | `/blocked-ips/bulk-unblock` | ✅ admin | Bulk unblock IP addresses |
| GET | `/blocked-ips/audit` | ✅ admin | Firewall block/unblock audit trail |
| GET | `/capture/interfaces` | ✅ analyst | List active network interface adapters |
| POST | `/capture/start` | ✅ analyst | Start live packet sniffing |
| POST | `/capture/stop` | ✅ analyst | Stop live packet sniffing |
| GET | `/capture/status` | ✅ viewer | Live capture status & packet count |
| GET | `/reports/export` | ✅ analyst | Generate & download PDF threat report |
| POST | `/network/scan/arp` | ✅ analyst | Quick ARP network device scan |
| POST | `/network/scan` | ✅ analyst | Full ARP + Nmap network device scan |
| GET | `/network/devices` | ✅ viewer | Cached device scan list |
| POST | `/admin/migrate-csv` | ✅ admin | Migrate legacy CSV records to SQLite |
| GET | `/api/license/status` | ❌ | Check cryptographic license status |
| POST | `/api/license/activate` | ✅ admin | Activate software license key |

---

## 🔮 Future Roadmap & Improvement Checklist

### 🚀 Phase 2: Advanced Network & Threat Intelligence (Near-Term)
- [ ] **eBPF (Extended Berkeley Packet Filter) Integration**: Migrate packet capture engine from Scapy to eBPF/XDP on Linux for sub-microsecond kernel-space packet processing.
- [ ] **Distributed Sensor Nodes (Agent-Collector Model)**: Deploy lightweight packet capture agents on distributed IoT gateways streaming to a centralized NetGuard cluster.
- [ ] **SIEM & SOAR Integration**: Native Syslog, CEF (Common Event Format), and Webhook exporters for Splunk, Elastic Security (ELK), Microsoft Sentinel, and QRadar.
- [ ] **Automated Incident Playbook Engine**: Rule-based workflow engine allowing custom triggers (e.g. `If DoS confidence > 95% AND duration > 10s THEN block IP + trigger Webhook`).
- [ ] **IoT Protocol Deep Packet Inspection (DPI)**: Dedicated feature extractors for MQTT, CoAP, Modbus TCP, OPC UA, and Zigbee industrial protocols.

### 🛡️ Phase 3: Enterprise AI Scaling & Hardware Acceleration (Long-Term)
- [ ] **Deep Learning Sequence Model**: Train LSTM / Temporal Fusion Transformer (TFT) networks alongside XGBoost for multi-step attack campaign prediction.
- [ ] **GPU Acceleration & TensorRT**: Hardware-accelerated ML inference via ONNX Runtime & NVIDIA TensorRT for 10Gbps+ line-rate network throughput.
- [ ] **Federated Learning Network**: Privacy-preserving collaborative model updating across distributed NetGuard deployments without exposing raw packet data.
- [ ] **Multi-Tenant Enterprise Dashboard**: Organization-level isolation, custom RBAC permissions, and SSO integration (SAML 2.0 / OAuth2 / OpenID Connect).
- [ ] **Automated PCAP Forensics Exporter**: Automatic packet capture dump (PCAP generation) on critical threat triggers for offline Wireshark analysis.

---

## 🔒 Security & Compliance

- **PBKDF2-HMAC-SHA256** password hashing with 260,000 iterations.
- Rate limiting: 5 failed login attempts → 15-minute account lockout.
- Cryptographically signed RSA/Ed25519 license validation.
- Thread-safe SQLite WAL mode + encrypted Neon Cloud PostgreSQL connections.
- Protected IP white-listing (loopback, gateway, DNS servers guarded against accidental firewall locking).

---

## 📋 System Requirements

```text
pandas==2.2.2
numpy==1.26.4
scikit-learn==1.4.2
xgboost==2.0.3
imbalanced-learn==0.12.2
joblib==1.4.0
fastapi==0.111.0
uvicorn==0.29.0
pydantic==2.7.0
typing_extensions>=4.12.2
scapy==2.5.0
python-dotenv==1.0.1
requests==2.31.0
reportlab==4.2.2
python-nmap==0.7.1
redis>=5.0.0
psycopg2-binary>=2.9.9
```

---

## 👨‍💻 Developer & Maintenance

**Nikhil Dehariya**
- 📍 Bhopal, Madhya Pradesh
- 🎓 B.Tech AIDS — Jai Narain College of Technology
- 📧 nikhildehariya101@gmail.com
- 💼 [LinkedIn](https://linkedin.com/in/nikhildehariya)

---

## 📄 License

MIT License — Free to use for educational, research, and open-source applications.

---

> **NetGuard IDS v2.2** — *Protecting Industrial & Enterprise IoT Networks with Artificial Intelligence* 🛡️
