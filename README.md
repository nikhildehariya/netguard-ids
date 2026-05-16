# NetGuard IDS

**IoT Network Intrusion Detection System**

A real-time, flow-based Intrusion Detection System for IoT and campus networks. NetGuard captures live network traffic, extracts CIC-IDS2018-compatible flow features, classifies them using a trained XGBoost model, and triggers alerts with email notification, PDF reporting, and Windows Firewall IP blocking.

```
Live Traffic → Flow Feature Extraction → XGBoost Inference → Alert + Block + Report
```

---

## Features

- **Real-time packet capture** using Scapy on Windows (Npcap)
- **ML-based classification** with XGBoost (F1: 0.9025, trained on 8.2M CIC-IDS2018 flows)
- **4 attack classes detected:** DoS/DDoS, Brute Force, Web Attack, Infiltration
- **Automated alerting** via email (SMTP) on detection
- **IP blocking** via Windows Firewall (requires Administrator)
- **PDF reports** with detection history and statistics
- **REST API** (FastAPI) for integration and external queries
- **Web dashboard** (Streamlit) with live charts, device scanner, and manual controls
- **False positive baseline** validated against home and college Wi-Fi

---

## Detection Performance

| Attack Class  | Confidence | Severity |
|---------------|-----------|----------|
| DoS / DDoS    | 100%      | CRITICAL |
| Brute Force   | 83.92%    | HIGH     |
| Web Attack    | 98.44%    | HIGH     |
| Infiltration  | —         | HIGH     |

> **Note on Infiltration:** Infiltration is inherently low-and-slow traffic designed to blend with normal flows. Single-flow detection is unreliable for this class — this is a known limitation of flow-based IDS across the industry, not specific to this model. CIC-IDS2018 Infiltration labels also contain mislabeled normal flows. Behavioral baseline and multi-flow correlation are the recommended mitigations for production deployments.

---

## Project Structure

```
C:\iot-ids\
├── api/
│   └── main.py              FastAPI app — /predict, /stats, /block, /report endpoints
├── dashboard/
│   └── app.py               Streamlit dashboard — login, charts, device scanner
├── src/
│   ├── capture.py           Live packet capture and CIC-IDS2018 feature extraction
│   ├── predict.py           Model inference and threshold logic
│   ├── alert.py             Detection logging and email alerting
│   ├── blocklist.py         Windows Firewall IP block/unblock helpers
│   ├── reporting.py         PDF report generation and detection history
│   ├── preprocess.py        Feature scaling and preprocessing
│   ├── config.py            Paths, labels, feature list, thresholds
│   ├── train.py             Model training script (offline)
│   ├── validate_capture.py  Checks generated flow feature coverage
│   ├── analyze_test_flows.py Correlates flow samples with detections
│   └── baseline_report.py   Baseline false-positive summary
├── models/
│   ├── xgb_model.pkl        Trained XGBoost classifier
│   └── scaler.pkl           Feature scaler
├── data/                    CIC-IDS2018 CSVs (02-14-2018 to 03-02-2018)
├── logs/
│   └── detections.csv       Runtime detection log
├── reports/                 Generated PDF reports
├── .env                     Credentials and config (not committed)
├── requirements.txt
└── README.md
```

---

## Requirements

- Windows 10/11 (Administrator privileges required for capture and IP blocking)
- Python 3.10+
- [Npcap](https://npcap.com/) installed (WinPcap-compatible mode)
- VS Code or any terminal

---

## Installation

```powershell
# Clone or copy project to C:\iot-ids
cd C:\iot-ids

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Configuration

Edit `.env` with your settings:

```env
EMAIL_SENDER=your@gmail.com
EMAIL_PASSWORD=your_app_password
EMAIL_RECEIVER=alert@yourdomain.com
DASHBOARD_USER=admin
DASHBOARD_PASS=netguard123
```

---

## Running NetGuard

**Always run VS Code (or PowerShell) as Administrator.**

### Terminal 1 — API Server

```powershell
cd C:\iot-ids
venv\Scripts\activate
uvicorn api.main:app --host 0.0.0.0 --port 8080
```

API available at: `http://localhost:8080`

### Terminal 2 — Dashboard

```powershell
cd C:\iot-ids
venv\Scripts\activate
streamlit run dashboard/app.py
```

Dashboard available at: `http://localhost:8501`
Login: `admin` / `netguard123`

### Terminal 3 — Live Capture

```powershell
cd C:\iot-ids
venv\Scripts\activate
python src/capture.py --iface "\Device\NPF_{YOUR-ADAPTER-GUID}"
```

Find your adapter GUID:

```powershell
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/predict` | POST | Classify a flow (JSON body with 80 features) |
| `/stats` | GET | Detection counts and recent alerts |
| `/block` | POST | Block an IP via Windows Firewall |
| `/report` | GET | Generate and download PDF report |
| `/health` | GET | API health check |

### Example — Manual Prediction

```powershell
$body = '{ ...80 flow features as JSON... }'
Invoke-RestMethod -Uri "http://localhost:8080/predict" -Method POST -ContentType "application/json" -Body $body
```

Response:

```json
{
  "prediction": "DOS_DDOS",
  "confidence": 1.0,
  "severity": "CRITICAL",
  "all_scores": { "NORMAL": 0.0, "BRUTE_FORCE": 0.0, "DOS_DDOS": 1.0, "WEB_ATTACK": 0.0, "INFILTRATION": 0.0 },
  "timestamp": "2026-05-10T14:25:17"
}
```

---

## Validating a Capture Run

```powershell
python src/validate_capture.py
python src/analyze_test_flows.py
python src/baseline_report.py --context "current run"
Invoke-RestMethod "http://localhost:8080/stats?mode=all"
```

Expected healthy output:

```
Present feature columns : 72/72
Missing columns         : none
Matched by flow_id      : above 95%
Actionable alerts       : 0  (on clean traffic)
```

---

## 24/7 Deployment — Windows Service (NSSM)

```powershell
# Download NSSM and place in PATH, then:
nssm install NetGuardAPI "C:\iot-ids\venv\Scripts\python.exe" "-m uvicorn api.main:app --host 0.0.0.0 --port 8080"
nssm set NetGuardAPI AppDirectory "C:\iot-ids"

nssm install NetGuardDashboard "C:\iot-ids\venv\Scripts\streamlit.exe" "run dashboard/app.py"
nssm set NetGuardDashboard AppDirectory "C:\iot-ids"

nssm start NetGuardAPI
nssm start NetGuardDashboard
```

---

## College / Campus Deployment

A standard Wi-Fi client cannot observe all devices on a campus network. For full network visibility, NetGuard must be placed at an approved monitoring point:

- **SPAN / Mirror Port** on a managed switch
- **Network TAP** inline on the uplink
- **Gateway or firewall** with packet capture support

Coordinate with your network administrator before deploying in a campus environment.

---

## Model Details

| Property | Value |
|----------|-------|
| Dataset | CIC-IDS 2018 |
| Training samples | ~8.2 million flows |
| Features | 80 (CIC-IDS2018 standard) |
| Algorithm | XGBoost |
| F1 Score (macro) | 0.9025 |
| Classes | NORMAL, BRUTE_FORCE, DOS_DDOS, WEB_ATTACK, INFILTRATION |

---

## Developer

**Nikhil**
Windows 11 · Acer Laptop · VS Code
Network: Killer Wi-Fi 6E AX1675i