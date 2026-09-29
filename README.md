# 🛡️ NetGuard IDS v2.1
### IoT Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![XGBoost](https://img.shields.io/badge/XGBoost-F1%3A90.25%25-green?style=flat-square)
![React](https://img.shields.io/badge/React-Dashboard-61DAFB?style=flat-square&logo=react)
![FastAPI](https://img.shields.io/badge/FastAPI-v0.111-009688?style=flat-square&logo=fastapi)
![Nmap](https://img.shields.io/badge/Nmap-7.99-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

> **Real-time IoT network traffic classification and automated threat response system** built on CIC-IDS2018 dataset with XGBoost classifier, JWT authentication, live packet capture, network device scanning, automated firewall blocking, Explainable AI (XAI), and GenAI Security Copilot.

---

## 📸 Dashboard Preview

| Overview | Incidents | Blocklist | Devices |
|----------|-----------|-----------|---------|
| Live traffic timeline, attack stats | Real-time attack feed with block button | IP blocking with audit trail | ARP + Nmap network scanner |

---

## ✨ Features

### 🤖 Machine Learning & XAI
- **XGBoost Classifier** trained on CIC-IDS2018 (8.2M flows, 80 features)
- **90.25% Macro F1 Score** across 5 attack classes
- **Per-class confidence thresholds** for precision tuning
- **Explainable AI (XAI)** feature importance breakdown per detection (`/explain`)
- Real-time single & batch flow inference via REST API

### 🔍 Attack Detection
| Class | Type | Severity | Confidence |
|-------|------|----------|------------|
| NORMAL | Benign Traffic | None | — |
| BRUTE_FORCE | FTP/SSH Brute Force | 🟠 HIGH | 83.92% |
| DOS_DDOS | DoS/DDoS Attacks | 🔴 CRITICAL | 100% |
| WEB_ATTACK | SQLi, XSS, Brute Force Web | 🟠 HIGH | 98.44% |
| INFILTRATION | Bot, Advanced Infiltration | 🔴 CRITICAL | Adaptive |

### 🌐 Live Packet Capture
- **Scapy-based** network flow extractor
- Bidirectional flow analysis (80 CIC features)
- TCP flag analysis, IAT computation, window size tracking
- **Auto-flush every 2 seconds** for active flows to ensure immediate dashboard updates
- WiFi + SPAN/TAP port support

### 🔎 Network Device Scanner
- **Quick ARP Scan** — fast device discovery (2-3 seconds)
- **Full ARP + Nmap Scan** — detailed scan with open ports + OS detection
- Shows IP address, MAC address, hostname, vendor, open ports
- Gateway and self-device auto-identification
- One-click block suspicious devices directly from dashboard
- Cached results for instant reload

### 🤖 GenAI Security Copilot
- **Threat Briefing Generator** (`/assistant/insights`) — AI-synthesized incident summaries
- **Interactive Security Assistant** (`/assistant/chat`) — natural language copilot for network query and analysis

### 🔐 Security & Authentication
- **JWT-based auth** with access + refresh tokens
- **Role-based access control (RBAC)**
  - `admin` → Full access (users, block, unblock, reports, capture, scan, settings)
  - `analyst` → Monitor, capture, block IPs, scan network, export reports
  - `viewer` → Read-only dashboard
- **PBKDF2-HMAC-SHA256** password hashing (260,000 iterations)
- Rate limiting — 5 failed attempts → 15 min lockout
- Persistent `SECRET_KEY` via `.env`

### 🚨 Alerting
- **HTML Email alerts** (Gmail SMTP SSL)
- **Telegram Bot** real-time notifications with 1-click block actions
- Configurable confidence threshold (default: 85%)
- Severity-based filtering

### 🚫 Automated Response
- **Windows Firewall** auto-block (`netsh advfirewall`)
- **Linux iptables** support (INPUT + OUTPUT + FORWARD)
- TTL-based auto-expiry
- Threshold-based auto-block (configurable)
- Full audit trail in SQLite

### 📊 Dashboard
- **React + Vite** frontend (Port 5174)
- Live timeline chart, pie chart by class
- Incident feed with one-click block
- PDF report export (dark theme, professional)
- Capture mode: WiFi / SPAN / Manual interface
- **Network Devices tab** — ARP + Nmap scanner
- **Users tab** — Admin user management

### 🗄️ Storage
- **SQLite** for detections, auth, blocklist
- WAL mode for concurrent access
- CSV → SQLite migration endpoint
- 164,380+ detections stored

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      NetGuard IDS v2.1                      │
├──────────────┬──────────────────────┬───────────────────────┤
│  Capture     │   FastAPI Backend    │   React Dashboard     │
│  (Scapy)     │   (Port 8080)        │   (Port 5174)         │
│              │                      │                       │
│ Network      │ /predict             │ Overview              │
│ Packets  ──► │ /history             │ Capture Control       │
│              │ /stats               │ Incidents             │
│ Flow         │ /auth/*              │ Validate              │
│ Features ──► │ /blocked-ips         │ Blocklist             │
│              │ /reports/export      │ Devices Scanner       │
│              │ /network/scan        │ User Management       │
│              │ /explain             │ Copilot Assistant     │
│              │ /assistant/*         │                       │
└──────────────┴────────┬─────────────┴───────────────────────┘
                        │
           ┌────────────▼────────────┐
           │      XGBoost Model      │
           │   (xgb_model.pkl)       │
           │   F1 Score: 0.9025      │
           └────────────┬────────────┘
                        │
           ┌────────────▼────────────┐
           │      SQLite DBs         │
           │  detections.db          │
           │  auth.db                │
           │  blocklist.db           │
           └────────────┬────────────┘
                        │
           ┌────────────▼────────────┐
           │     Response Layer      │
           │  Windows Firewall       │
           │  Linux iptables         │
           │  Email (SMTP SSL)       │
           │  Telegram Bot           │
           └─────────────────────────┘
```

---

## 📁 Project Structure

```
C:\iot-ids\
├── api/
│   └── main.py              ← FastAPI app, all endpoints, JWT middleware
├── src/
│   ├── config.py            ← All configuration, labels, paths, env vars
│   ├── preprocess.py        ← Data loading, cleaning, feature scaling
│   ├── train.py             ← XGBoost training entry point
│   ├── predict.py           ← Singleton detector, real-time inference
│   ├── alert.py             ← Email + Telegram alerts + SQLite logging
│   ├── blocklist.py         ← Windows Firewall + iptables blocking engine
│   ├── capture.py           ← Scapy packet capture + flow extraction
│   ├── auth.py              ← JWT auth, RBAC, user management
│   ├── detections_db.py     ← SQLite CRUD operations + CSV migration
│   ├── reporting.py         ← PDF report generation (ReportLab)
│   ├── scanner.py           ← Network device scanner (ARP + Nmap)
│   ├── explainable.py       ← XAI feature importance breakdown
│   └── genai_assistant.py   ← GenAI Security Copilot & briefings
├── react-dashboard/
│   └── src/
│       └── App.jsx          ← Full React dashboard
├── models/
│   ├── xgb_model.pkl        ← Trained XGBoost model (~45 MB)
│   └── scaler.pkl           ← StandardScaler fitted on training data
├── logs/
│   ├── detections.db        ← All detections (164,380+ records)
│   ├── auth.db              ← Users, tokens, login attempts
│   ├── blocklist.db         ← Blocked IPs + full audit log
│   └── capture.log          ← Live capture output
├── run-netguard.ps1         ← Unified 1-click launcher script
├── smoke-test.ps1           ← End-to-end API & DB test script
├── data/                    ← CIC-IDS2018 CSVs (not in repo)
├── reports/                 ← Generated PDF reports
├── .env                     ← Secrets and credentials (not in repo)
└── requirements.txt
```

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.11+**
- **Node.js 18+**
- **Windows 10/11** (for Firewall blocking) or **Linux** (iptables)
- **Npcap** (Windows) or **libpcap** (Linux) — for live packet capture
- **Nmap 7.99+** — for network device scanning ([download](https://nmap.org/download.html))

---

### Option 1: 1-Click Launch (Recommended)

Run the unified PowerShell launcher script in Admin PowerShell:

```powershell
.\run-netguard.ps1
```

> **What `run-netguard.ps1` does automatically:**
> 1. Verifies Python 3.11+ and Node.js 18+ prerequisites.
> 2. Creates the Python `venv` and installs dependencies from `requirements.txt`.
> 3. Installs frontend `node_modules` inside `react-dashboard`.
> 4. Starts the FastAPI backend on `http://127.0.0.1:8080`.
> 5. Starts the React Dashboard on `http://localhost:5174`.
> 6. Opens the web dashboard automatically in your default browser.

---

### Option 2: Manual Setup & Launch

#### 1. Clone & Setup Python Environment
```bash
git clone https://github.com/nikhildehariya/netguard-ids.git
cd netguard-ids
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

#### 2. Configure `.env`
Create a `.env` file in the root directory:
```env
# Email Alerts
ALERT_FROM_EMAIL=your@gmail.com
ALERT_TO_EMAIL=alert@gmail.com
ALERT_PASSWORD=your_app_password

# Telegram
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Auth — generate key: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=your_64_char_hex_key
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=netguard123

# Auto-block
AUTO_BLOCK_ENABLED=true
AUTO_BLOCK_THRESHOLD=3
AUTO_BLOCK_CONFIDENCE=0.95
AUTO_BLOCK_SEVERITIES=critical
```

#### 3. Train Model (Optional — Pre-trained Model Included)
```bash
# Place CIC-IDS2018 CSVs in data/ folder
python src/train.py
# Expected output: Macro F1 ≈ 0.9025
```

#### 4. Start Services Manually

**Terminal 1 — API Backend** (Admin PowerShell / Terminal):
```powershell
uvicorn api.main:app --host 0.0.0.0 --port 8080
```

**Terminal 2 — React Dashboard**:
```powershell
cd react-dashboard
npm install
npm run dev
```

#### 5. Access Services
- **Dashboard**: [http://localhost:5174](http://localhost:5174)
- **API Documentation**: [http://localhost:8080/docs](http://localhost:8080/docs)
- **Default Login Credentials**: `admin` / `netguard123`

---

## 🔧 NSSM Services (24/7 Production on Windows)

To run NetGuard IDS permanently in the background as Windows services using NSSM:

```powershell
# 1. Install NetGuard API Service (Admin PowerShell)
nssm install NetGuard-API "C:\iot-ids\venv\Scripts\uvicorn.exe" "api.main:app --host 0.0.0.0 --port 8080"
nssm set NetGuard-API AppDirectory "C:\iot-ids"

# 2. Install NetGuard React Dashboard Service (Port 5174)
nssm install NetGuard-React "C:\Program Files\nodejs\npx.cmd" "serve -s dist -l 5174"
nssm set NetGuard-React AppDirectory "C:\iot-ids\react-dashboard"

# 3. Install NetGuard Packet Capture Service
# Note: Replace "Wi-Fi" with your interface name from GET /capture/interfaces
nssm install NetGuard-Capture "C:\iot-ids\venv\Scripts\python.exe" "src/capture.py --iface ""Wi-Fi"""
nssm set NetGuard-Capture AppDirectory "C:\iot-ids"

# Start all services
nssm start NetGuard-API
nssm start NetGuard-React
nssm start NetGuard-Capture
```

---

## 🧪 Testing & Validation

### End-to-End Automated Smoke Test
Run the automated test suite against a running server:
```powershell
.\smoke-test.ps1
```

### Manual Attack Validation Examples

#### DoS/DDoS Classification Test
```powershell
$body = Get-Content "dos_test.json" -Raw
Invoke-RestMethod -Uri "http://localhost:8080/predict" -Method POST -ContentType "application/json" -Body $body
# Expected output: DOS_DDOS | 100% confidence | CRITICAL
```

#### Brute Force Test
- Via Dashboard → **Validate** tab → Select **"Brute Force SSH"** preset.
- Expected output: `BRUTE_FORCE` | ~83.92% confidence | `HIGH`

#### Network Device Scan API
```powershell
$login = Invoke-RestMethod -Uri "http://localhost:8080/auth/login" -Method POST -ContentType "application/json" -Body '{"username":"admin","password":"netguard123"}'
$headers = @{Authorization = "Bearer $($login.access_token)"}
Invoke-RestMethod -Uri "http://localhost:8080/network/scan/arp" -Method POST -Headers $headers
```

---

## 📊 Model Performance

| Metric | Value |
|--------|-------|
| Dataset | CIC-IDS2018 |
| Training samples | ~6.5M flows |
| Test samples | ~1.6M flows |
| Features | 80 network flow features |
| Algorithm | XGBoost (`n_estimators=300`, `max_depth=6`) |
| **Macro F1 Score** | **0.9025** |

| Class | Precision | Recall | F1 |
|-------|-----------|--------|----|
| NORMAL | 0.99 | 0.99 | 0.99 |
| BRUTE_FORCE | 0.95 | 0.92 | 0.93 |
| DOS_DDOS | 0.98 | 0.99 | 0.98 |
| WEB_ATTACK | 0.87 | 0.85 | 0.86 |
| INFILTRATION | 0.72 | 0.68 | 0.70 |

---

## 🌐 API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/auth/login` | ❌ | Authenticate user, return JWT tokens |
| POST | `/auth/refresh` | ❌ | Refresh access token |
| POST | `/auth/logout` | ❌ | Revoke refresh token |
| GET | `/auth/me` | ✅ any | Current authenticated user info |
| POST | `/auth/users` | ✅ admin | Create new user account |
| GET | `/auth/users` | ✅ admin | List all user accounts |
| PATCH | `/auth/users/{username}/role` | ✅ admin | Update user role |
| PATCH | `/auth/users/{username}/toggle` | ✅ admin | Enable / disable user account |
| DELETE | `/auth/users/{username}` | ✅ admin | Delete user account |
| GET | `/admin/alert-settings` | ✅ admin | Get alert notification settings |
| PATCH | `/admin/alert-settings` | ✅ admin | Update alert notification recipient |
| POST | `/predict` | ❌ | Single flow real-time classification |
| POST | `/predict/batch` | ❌ | Batch flow classification |
| POST | `/explain` | ✅ viewer | Explainable AI feature contribution |
| GET | `/assistant/insights` | ✅ viewer | AI-generated threat briefings |
| POST | `/assistant/chat` | ✅ viewer | GenAI security copilot assistant chat |
| GET | `/history` | ✅ viewer | Historical detection logs |
| GET | `/stats` | ✅ viewer | Aggregate dashboard statistics |
| GET | `/health` | ❌ | API health check endpoint |
| GET | `/blocked-ips` | ✅ viewer | List active firewall blocked IPs |
| POST | `/blocked-ips` | ✅ analyst | Block an IP address |
| DELETE | `/blocked-ips/{ip}` | ✅ admin | Unblock an IP address |
| POST | `/blocked-ips/bulk-block` | ✅ analyst | Bulk block IP addresses |
| POST | `/blocked-ips/bulk-unblock` | ✅ admin | Bulk unblock IP addresses |
| GET | `/blocked-ips/audit` | ✅ admin | Firewall block/unblock audit trail |
| GET | `/capture/interfaces` | ✅ analyst | List available network interfaces |
| POST | `/capture/start` | ✅ analyst | Start live packet capture |
| POST | `/capture/stop` | ✅ analyst | Stop live packet capture |
| GET | `/capture/status` | ✅ viewer | Current packet capture status |
| GET | `/reports/export` | ✅ analyst | Export PDF security report |
| POST | `/network/scan/arp` | ✅ analyst | Quick ARP network device scan |
| POST | `/network/scan` | ✅ analyst | Full ARP + Nmap network device scan |
| GET | `/network/devices` | ✅ viewer | Retrieve cached device scan list |
| POST | `/admin/migrate-csv` | ✅ admin | Migrate legacy CSV data to SQLite |
| GET | `/api/license/status` | ❌ | Check system license status |
| POST | `/api/license/activate` | ✅ admin | Activate system license key |

---

## 🔒 Security Features

- JWT access & refresh tokens with secure signatures & expiration.
- **PBKDF2-HMAC-SHA256** password hashing with 260,000 iterations.
- Rate limiting: 5 consecutive failed logins → 15-minute lockout.
- Protected IP ranges (loopback, local gateway, multicast) guarded against accidental blocking.
- Thread-safe SQLite databases with Write-Ahead Logging (WAL) enabled.
- Cryptographic audit logging for all firewall block/unblock actions.
- Persistent `SECRET_KEY` via `.env` to keep active sessions alive across server restarts.

---

## 📋 Requirements

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
```

> **System Note:** Install [Nmap 7.99+](https://nmap.org/download.html) and [Npcap](https://npcap.com/) separately on Windows.

---

## 👨‍💻 Developer

**Nikhil Dehariya**
- 📍 Bhopal, Madhya Pradesh
- 🎓 B.Tech AIDS — Jai Narain College of Technology
- 📧 nikhildehariya101@gmail.com
- 💼 [LinkedIn](https://linkedin.com/in/nikhildehariya)

---

## 📄 License

MIT License — Free to use for educational and research purposes.

---

> **NetGuard IDS** — *Protecting IoT Networks with Machine Learning & AI* 🛡️
