# 🛡️ NetGuard IDS v2.1
### IoT Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![XGBoost](https://img.shields.io/badge/XGBoost-F1%3A90.25%25-green?style=flat-square)
![React](https://img.shields.io/badge/React-Dashboard-61DAFB?style=flat-square&logo=react)
![FastAPI](https://img.shields.io/badge/FastAPI-v0.100-009688?style=flat-square&logo=fastapi)
![Nmap](https://img.shields.io/badge/Nmap-7.99-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

> **Real-time IoT network traffic classification and automated threat response system** built on CIC-IDS2018 dataset with XGBoost classifier, JWT authentication, live packet capture, network device scanning, and automated firewall blocking.

---

## 📸 Dashboard Preview

| Overview | Incidents | Blocklist | Devices |
|----------|-----------|-----------|---------|
| Live traffic timeline, attack stats | Real-time attack feed with block button | IP blocking with audit trail | ARP + Nmap network scanner |

---

## ✨ Features

### 🤖 Machine Learning
- **XGBoost Classifier** trained on CIC-IDS2018 (8.2M flows, 80 features)
- **90.25% Macro F1 Score** across 5 attack classes
- **Per-class confidence thresholds** for precision tuning
- Real-time inference via REST API

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
- Auto-flush every 30 seconds for long-lived flows
- WiFi + SPAN/TAP port support

### 🔎 Network Device Scanner
- **Quick ARP Scan** — fast device discovery (2-3 seconds)
- **Full ARP + Nmap Scan** — detailed scan with open ports + OS detection
- Shows IP address, MAC address, hostname, vendor, open ports
- Gateway and self-device auto-identification
- One-click block suspicious devices directly from dashboard
- Cached results for instant reload

### 🔐 Security & Authentication
- **JWT-based auth** with access + refresh tokens
- **Role-based access control (RBAC)**
  - `admin` → Full access (users, block, unblock, reports, capture, scan)
  - `analyst` → Monitor, capture, block IPs, scan network, export reports
  - `viewer` → Read-only dashboard
- **PBKDF2-HMAC-SHA256** password hashing (260,000 iterations)
- Rate limiting — 5 failed attempts → 15 min lockout
- Persistent `SECRET_KEY` via `.env`

### 🚨 Alerting
- **HTML Email alerts** (Gmail SMTP SSL)
- **Telegram Bot** real-time notifications
- Configurable confidence threshold (default: 85%)
- Severity-based filtering

### 🚫 Automated Response
- **Windows Firewall** auto-block (netsh advfirewall)
- **Linux iptables** support (INPUT + OUTPUT + FORWARD)
- TTL-based auto-expiry
- Threshold-based auto-block (configurable)
- Full audit trail in SQLite

### 📊 Dashboard
- **React + Vite** frontend
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
│  (Scapy)     │   (Port 8080)        │   (Port 5173)         │
│              │                      │                       │
│ Network      │ /predict             │ Overview              │
│ Packets  ──► │ /history             │ Capture Control       │
│              │ /stats               │ Incidents             │
│ Flow         │ /auth/*              │ Validate              │
│ Features ──► │ /blocked-ips         │ Blocklist             │
│              │ /reports/export      │ Devices Scanner       │
│              │ /network/scan        │ User Management       │
│              │ /network/scan/arp    │                       │
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
│   └── scanner.py           ← Network device scanner (ARP + Nmap)
├── react-dashboard/
│   └── src/
│       └── App.jsx          ← Full React dashboard (single file)
├── models/
│   ├── xgb_model.pkl        ← Trained XGBoost model (~45 MB)
│   └── scaler.pkl           ← StandardScaler fitted on training data
├── logs/
│   ├── detections.db        ← All detections (164,380+ records)
│   ├── auth.db              ← Users, tokens, login attempts
│   ├── blocklist.db         ← Blocked IPs + full audit log
│   └── capture.log          ← Live capture output
├── data/                    ← CIC-IDS2018 CSVs (not in repo)
├── reports/                 ← Generated PDF reports
├── .env                     ← Secrets and credentials (not in repo)
└── requirements.txt
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- Windows 10/11 (for firewall blocking) or Linux
- Npcap (Windows) or libpcap (Linux) — for packet capture
- **Nmap 7.99+** — for network device scanning ([download](https://nmap.org/download.html))

### 1. Clone & Setup
```bash
git clone https://github.com/nikhildehariya/netguard-ids.git
cd netguard-ids
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

### 2. Configure `.env`
```env
# Email Alerts
ALERT_FROM_EMAIL=your@gmail.com
ALERT_TO_EMAIL=alert@gmail.com
ALERT_PASSWORD=your_app_password

# Telegram
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Auth — generate: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=your_64_char_hex_key
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=netguard123

# Auto-block
AUTO_BLOCK_ENABLED=true
AUTO_BLOCK_THRESHOLD=3
AUTO_BLOCK_CONFIDENCE=0.95
AUTO_BLOCK_SEVERITIES=critical
```

### 3. Train Model
```bash
# Place CIC-IDS2018 CSVs in data/ folder
python src/train.py
# Expected: Macro F1 ≈ 0.9025
```

### 4. Start Services
```bash
# API (Admin PowerShell)
uvicorn api.main:app --host 0.0.0.0 --port 8080

# Dashboard
cd react-dashboard
npm install
npm run build
serve -s dist -l 5173
```

### 5. Access
- Dashboard: http://localhost:5173
- API Docs: http://localhost:8080/docs
- Default login: `admin` / `netguard123`

---

## 🔧 NSSM Services (24/7 on Windows)

```powershell
# Install as Windows services (Admin PowerShell)
nssm install NetGuard-API "C:\iot-ids\venv\Scripts\uvicorn.exe" "api.main:app --host 0.0.0.0 --port 8080"
nssm set NetGuard-API AppDirectory "C:\iot-ids"

nssm install NetGuard-React serve "-s dist -l 5173"
nssm set NetGuard-React AppDirectory "C:\iot-ids\react-dashboard"

nssm install NetGuard-Capture "C:\iot-ids\venv\Scripts\python.exe" "src/capture.py --iface YOUR_INTERFACE"
nssm set NetGuard-Capture AppDirectory "C:\iot-ids"

# Start all
nssm start NetGuard-API
nssm start NetGuard-React
nssm start NetGuard-Capture
```

---

## 🧪 Attack Validation

### DoS/DDoS Test
```powershell
$body = Get-Content "dos_test.json" -Raw
Invoke-RestMethod -Uri "http://localhost:8080/predict" -Method POST -ContentType "application/json" -Body $body
# Expected: DOS_DDOS | 100% confidence | CRITICAL
```

### Brute Force Test
```powershell
# Via dashboard → Validate tab → "Brute Force SSH" preset
# Expected: BRUTE_FORCE | 83.92% | HIGH
```

### Web Attack Test
```powershell
# Via dashboard → Validate tab → custom payload
# Expected: WEB_ATTACK | 98.44% | HIGH
```

### Network Device Scan
```powershell
$login = Invoke-RestMethod -Uri "http://localhost:8080/auth/login" -Method POST -ContentType "application/json" -Body '{"username":"admin","password":"netguard123"}'
$headers = @{Authorization = "Bearer $($login.access_token)"}
Invoke-RestMethod -Uri "http://localhost:8080/network/scan/arp" -Method POST -Headers $headers
# Returns: all connected devices with IP, MAC, hostname
```

---

## 📊 Model Performance

| Metric | Value |
|--------|-------|
| Dataset | CIC-IDS2018 |
| Training samples | ~6.5M flows |
| Test samples | ~1.6M flows |
| Features | 80 network flow features |
| Algorithm | XGBoost (n_estimators=300, max_depth=6) |
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
| POST | `/auth/login` | ❌ | Login, get JWT tokens |
| POST | `/auth/refresh` | ❌ | Refresh access token |
| POST | `/auth/logout` | ❌ | Revoke refresh token |
| GET | `/auth/me` | ✅ any | Current user info |
| POST | `/auth/users` | ✅ admin | Create new user |
| GET | `/auth/users` | ✅ admin | List all users |
| PATCH | `/auth/users/{u}/role` | ✅ admin | Update user role |
| DELETE | `/auth/users/{u}` | ✅ admin | Delete user |
| POST | `/predict` | ❌ | Single flow classification |
| GET | `/history` | ✅ viewer | Detection history |
| GET | `/stats` | ✅ viewer | Aggregate statistics |
| GET | `/health` | ❌ | API health check |
| GET | `/blocked-ips` | ✅ viewer | List blocked IPs |
| POST | `/blocked-ips` | ✅ analyst | Block an IP |
| DELETE | `/blocked-ips/{ip}` | ✅ admin | Unblock an IP |
| POST | `/blocked-ips/bulk-block` | ✅ analyst | Block multiple IPs |
| POST | `/blocked-ips/bulk-unblock` | ✅ admin | Unblock multiple IPs |
| GET | `/blocked-ips/audit` | ✅ admin | Block/unblock audit log |
| GET | `/capture/interfaces` | ✅ analyst | List network interfaces |
| POST | `/capture/start` | ✅ analyst | Start packet capture |
| POST | `/capture/stop` | ✅ analyst | Stop packet capture |
| GET | `/capture/status` | ✅ viewer | Capture status |
| GET | `/reports/export` | ✅ analyst | Export PDF report |
| POST | `/network/scan/arp` | ✅ analyst | Quick ARP device scan |
| POST | `/network/scan` | ✅ analyst | Full ARP + Nmap scan |
| GET | `/network/devices` | ✅ viewer | Cached device list |
| POST | `/admin/migrate-csv` | ✅ admin | Migrate CSV to SQLite |

---

## 🔒 Security Features

- JWT tokens with expiry (60 min access, 7 day refresh)
- PBKDF2-HMAC-SHA256 password hashing (260,000 iterations)
- Rate limiting: 5 attempts → 15 min lockout
- Protected IP ranges (loopback, multicast) never blocked
- Thread-safe SQLite with WAL mode
- Audit trail for all block/unblock events
- Persistent SECRET_KEY via `.env` — tokens survive restarts

---

## 📋 Requirements

```
fastapi
uvicorn
xgboost
scikit-learn
joblib
pandas
numpy
scapy
requests
python-dotenv
reportlab
imbalanced-learn
python-nmap
```

> **Note:** Also install [Nmap 7.99+](https://nmap.org/download.html) separately on your OS.

---

## 👨‍💻 Developer

**Nikhil Dehariya**
- 📍 Bhopal, Madhya Pradesh
- 🎓 B.Tech AIDS — Jai Narain College of Technology
- 📧 nikhildehariya101@gmail.com
- 💼 [LinkedIn](https://linkedin.com/in/nikhildehariya)

---

## 📄 License

MIT License — Free to use for educational purposes.

---

> **NetGuard IDS** — *Protecting IoT Networks with Machine Learning* 🛡️