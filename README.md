# 🛡️ NetGuard IDS v2.1
### IoT Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![XGBoost](https://img.shields.io/badge/XGBoost-F1%3A90.25%25-green?style=flat-square)
![React](https://img.shields.io/badge/React-Dashboard-61DAFB?style=flat-square&logo=react)
![FastAPI](https://img.shields.io/badge/FastAPI-v0.100-009688?style=flat-square&logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

> **Real-time IoT network traffic classification and automated threat response system** built on CIC-IDS2018 dataset with XGBoost classifier, JWT authentication, live packet capture, and automated firewall blocking.

---

## 📸 Dashboard Preview

| Overview | Incidents | Blocklist |
|----------|-----------|-----------|
| Live traffic timeline, attack stats | Real-time attack feed with block button | IP blocking with audit trail |

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

### 🔐 Security & Authentication
- **JWT-based auth** with access + refresh tokens
- **Role-based access control (RBAC)**
  - `admin` → Full access (users, block, unblock, reports, capture)
  - `analyst` → Monitor, capture, block IPs, export reports
  - `viewer` → Read-only dashboard
- **bcrypt-inspired PBKDF2** password hashing (260,000 iterations)
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

### 🗄️ Storage
- **SQLite** for detections, auth, blocklist
- WAL mode for concurrent access
- CSV → SQLite migration endpoint
- 164,380+ detections stored

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    NetGuard IDS v2.1                    │
├──────────────┬──────────────────┬───────────────────────┤
│  Capture     │   FastAPI        │   React Dashboard     │
│  (Scapy)     │   (Port 8080)    │   (Port 5173)         │
│              │                  │                       │
│ Network      │ /predict         │ Overview              │
│ Packets  ──► │ /history         │ Capture Control       │
│              │ /stats           │ Incidents             │
│ Flow         │ /auth/*          │ Validate              │
│ Features ──► │ /blocked-ips     │ Blocklist             │
│              │ /reports/export  │ User Management       │
└──────────────┴────────┬─────────┴───────────────────────┘
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
           └─────────────────────────┘
```

---

## 📁 Project Structure

```
C:\iot-ids\
├── api/
│   └── main.py              ← FastAPI app, all endpoints, JWT middleware
├── src/
│   ├── config.py            ← All configuration, labels, paths
│   ├── preprocess.py        ← Data loading, cleaning, scaling
│   ├── train.py             ← XGBoost training entry point
│   ├── predict.py           ← Singleton detector, inference
│   ├── alert.py             ← Email + Telegram + SQLite logging
│   ├── blocklist.py         ← Firewall blocking engine
│   ├── capture.py           ← Scapy packet capture + flow extraction
│   ├── auth.py              ← JWT auth, RBAC, user management
│   ├── detections_db.py     ← SQLite storage + CSV migration
│   └── reporting.py         ← PDF report generation (ReportLab)
├── react-dashboard/
│   └── src/
│       └── App.jsx          ← Full React dashboard (single file)
├── models/
│   ├── xgb_model.pkl        ← Trained XGBoost model
│   └── scaler.pkl           ← StandardScaler
├── logs/
│   ├── detections.db        ← All detections (164,380+)
│   ├── auth.db              ← Users, tokens, login attempts
│   ├── blocklist.db         ← Blocked IPs + audit log
│   └── capture.log          ← Live capture output
├── data/                    ← CIC-IDS2018 CSVs (not in repo)
├── reports/                 ← Generated PDF reports
├── .env                     ← Secrets (not in repo)
└── requirements.txt
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- Windows 10/11 (for firewall blocking) or Linux
- Npcap (Windows) or libpcap (Linux) for packet capture

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

# Auth
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
npm run dev
```

### 5. Access
- Dashboard: http://localhost:5173
- API Docs: http://localhost:8080/docs
- Default login: `admin` / `netguard123`

---

## 🔧 NSSM Services (24/7)

```powershell
# Install as Windows services
nssm install NetGuard-API python "C:\iot-ids\venv\Scripts\uvicorn" "api.main:app --host 0.0.0.0 --port 8080"
nssm install NetGuard-React serve "-s dist -l 5173"
nssm install NetGuard-Capture python "C:\iot-ids\src\capture.py" "--iface YOUR_INTERFACE"

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
| GET | `/auth/me` | ✅ | Current user info |
| POST | `/predict` | ❌ | Single flow prediction |
| GET | `/history` | ✅ viewer | Detection history |
| GET | `/stats` | ✅ viewer | Aggregate statistics |
| GET | `/blocked-ips` | ✅ viewer | List blocked IPs |
| POST | `/blocked-ips` | ✅ analyst | Block an IP |
| DELETE | `/blocked-ips/{ip}` | ✅ admin | Unblock an IP |
| GET | `/reports/export` | ✅ analyst | Export PDF report |
| POST | `/capture/start` | ✅ analyst | Start packet capture |
| POST | `/admin/migrate-csv` | ✅ admin | Migrate CSV to SQLite |

---

## 🔒 Security Features

- JWT tokens with expiry (60 min access, 7 day refresh)
- PBKDF2-HMAC-SHA256 password hashing (260,000 iterations)
- Rate limiting: 5 attempts → 15 min lockout
- Protected IP ranges (loopback, multicast) never blocked
- Thread-safe SQLite with WAL mode
- Audit trail for all block/unblock events

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
```

---

## 👨‍💻 Developer

**Nikhil Dehariya**
- 📍 Bhopal, Madhya Pradesh
- 🎓 College Project — IoT Security
- 📧 nikhildehariya101@gmail.com
- 💼 [LinkedIn](https://linkedin.com/in/nikhildehariya)

---

## 📄 License

MIT License — Free to use for educational purposes.

---

> **NetGuard IDS** — *Protecting IoT Networks with Machine Learning* 🛡️
