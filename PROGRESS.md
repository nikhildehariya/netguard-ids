# 🚀 NetGuard IDS — Master Startup Roadmap & Progress Tracker

> **Product**: NetGuard IDS — Real-Time IoT/OT Network Threat Detection & Response Platform  
> **Current Version**: `v2.2.0-hardened`  
> **Startup Phase**: 🟡 **Pre-Seed Functional MVP → Enterprise Pilot Ready**  
> **Current Maturity Score**: `9.0 / 10` ➔ **Target**: `9.5 / 10`  
> **Founder / Lead Engineer**: Nikhil Dehariya  
> **Last Synchronized**: November 2026  

---

## 🧭 High-Level Milestone Architecture

```
 [v1.0 Core ML] ──► [v2.0 NIPS & UI] ──► [v2.1 Hybrid Dual-DB] ──► [v2.2 XAI & Edge-IIoTset] ──► [v2.2-Hardened] ──► [v3.0 SaaS/Docker Edge]
   (Completed)         (Completed)             (Completed)                 (Completed)             (ACTIVE SPRINT)           (NEXT MILESTONE)
```

| Phase | Version | Core Strategic Focus | Status | Milestone Deliverable |
| :--- | :---: | :--- | :---: | :--- |
| **Phase 1** | `v1.0` | XGBoost Core Classifier, 80 Flow Features, CIC-IDS2018 | ✅ **Completed** | 90.25% Macro F1 detection engine |
| **Phase 2** | `v2.0` | React Dashboard, Windows Firewall Auto-Block, JWT RBAC | ✅ **Completed** | Full GUI + sub-millisecond host defense |
| **Phase 3** | `v2.1` | Dual-DB (SQLite WAL + Neon Postgres), Redis Streams, Isolation Forest | ✅ **Completed** | Zero-day anomaly detection + cloud sync |
| **Phase 4** | `v2.2` | Native TreeSHAP XAI, Edge-IIoTset Real Benchmark, Diagnostics Tab | ✅ **Completed** | Mathematical explainability & IEEE metrics |
| **Phase 5** | `v2.2-H`| **Enterprise Security Hardening (Patch 8 Audit Vulnerabilities)** | ✅ **COMPLETED** | **Zero-vulnerability vendor grade trust** |
| **Phase 6** | `v3.0` | **Docker Containerization, Linux Edge Deployment & Pilot Launch** | ⏳ **Queued (Q1 2027)** | **1-click install, multi-tenant fleet mgmt** |
| **Phase 7** | `v3.5` | Kernel eBPF/XDP capture, C/Rust probes, Industrial IoT DPI | 🔮 **Future (Q2 2027)**| 10Gbps line-rate hardware acceleration |

---

## ✅ 1. Completed Core Capabilities (The Product Moat)

### 🤖 Dual-ML Detection Engine
- [x] **XGBoost Supervised Classifier**: Trained on 8.2M flows (CIC-IDS2018), 80 features, achieving **90.25% Macro F1-score**.
- [x] **Per-Class Calibrated Thresholds**: DoS/DDoS (100%), Web Attacks (98.4%), Brute Force (83.9%), Infiltration (70.2%).
- [x] **Unsupervised Isolation Forest**: Real-time outlier detection flagging zero-day attacks (`ZERO_DAY_ANOMALY`).
- [x] **Sub-Millisecond Inference**: Thread-safe, in-memory singleton pipeline with median latency under **19.1 ms**.

### 🧠 Native Explainable AI (TreeSHAP) & Validation
- [x] **Production TreeSHAP Explainer (`src/xai.py`)**: Real mathematical Shapley value computations (zero mock heuristic fallback).
- [x] **Industrial Edge-IIoTset Validator (`src/iot_validator.py`)**: Verified against 100% benign industrial telemetry baseline (zero false positives on legit IoT sensors).
- [x] **Root Figures & Benchmarks Sync (`static/figures/`)**: Automated export of ROC curves, confusion matrices, and SHAP beeswarm plots.
- [x] **Interactive UI Diagnostics**: `"🔬 Diagnostics & Metrics"` tab and `"✓ TreeSHAP Engine"` modal live in React dashboard.

### ⚡ Resilient Data Ingestion & Dual-Database
- [x] **Dual-DB Architecture**: Ultra-low latency SQLite WAL (`logs/detections.db`) + non-blocking background sync (every 30s) to **Neon Cloud PostgreSQL (AWS us-east-2)**.
- [x] **Redis Streams Buffer**: `netguard:flow_stream` buffering high-burst packet floods with automatic graceful HTTP fallback.
- [x] **Packet Sniffer (`src/capture.py`)**: Real-time bidirectional flow reconstruction across active Ethernet and Wi-Fi adapters.

### 🛡️ Active Containment & Defense
- [x] **Automated Firewall Rule Injection**: Instant blocking via `netsh advfirewall` (Windows) & `iptables` (Linux).
- [x] **Fail-Safe IP Protection**: Protected whitelist preventing accidental lockouts of gateway, loopback (`127.0.0.1`), and DNS servers.
- [x] **Time-to-Live (TTL) Auto-Pruning**: Temporary containment with automated expiry.
- [x] **Cryptographic Audit Trail**: Full SQLite/PostgreSQL audit logging of every containment event with operator metadata.

### 💼 Commercial Monetization & Copilot
- [x] **Cryptographic Licensing Engine (`src/license.py`)**: Asymmetric RSA & Ed25519 digital signature validation enforcing **Trial**, **Pro**, and **Enterprise** feature gates with hardware fingerprinting.
- [x] **GenAI Security Copilot (`src/genai_assistant.py`)**: Natural-language security assistant supporting Google Gemini, Ollama (local Llama3), and HuggingFace.
- [x] **Modern React 19 Frontend**: Standalone Vite client with 10 dedicated modules, permanently built into `react-dashboard/dist` on port **5174**.

---

## 🚨 2. Current Active Sprint: Enterprise Security Hardening (Top Priority)

> **Mandatory Goal**: Before deploying to any pilot client or presenting to investors, eliminate all 8 vulnerabilities discovered during the security audit.

| Priority | Vulnerability & Location | Risk Description | Remediation Plan | Status |
| :---: | :--- | :--- | :--- | :---: |
| 🚨 **CRITICAL** | **Arbitrary File Read (Path Traversal)**<br>`api/main.py:1046` (`/research/figure/{filename}`) | Unauthenticated remote attacker can traverse paths (`../../.env`) to read cloud DB passwords and secret keys. | Sanitize input with `os.path.basename()`, enforce strict directory boundaries, and require authentication. | ✅ **FIXED** |
| ⚠️ **HIGH** | **Unauthenticated License Activation & Backdoor Bypass**<br>`api/main.py:923` & `src/license.py:310` | `/api/license/activate` lacks auth; `NETGUARD-DEV` / `DEV-MASTER` hardcoded strings grant free Enterprise tier. | Require `manage_users` permission on activation endpoint; strip all developer backdoor bypass strings. | ✅ **FIXED** |
| ⚠️ **HIGH** | **Disabled TLS/SSL Verification**<br>`src/genai_assistant.py:109` (`TLSAdapter`) | `ctx.check_hostname = False` and `CERT_NONE` allow Man-in-the-Middle credential interception. | Remove `CERT_NONE` and re-enable standard platform CA verification for all outbound LLM requests. | ✅ **FIXED** |
| ⚡ **MEDIUM** | **Wildcard CORS Policy**<br>`api/main.py:60` | `allow_origins=["*"]` allows malicious browser tabs to query local NetGuard API on port 8081. | Restrict CORS strictly to `["http://localhost:5174", "http://127.0.0.1:5174"]` and configured frontend domains. | ✅ **FIXED** |
| ⚡ **MEDIUM** | **Shared IP Lockout Denial of Service**<br>`src/auth.py:207` | 5 failed logins for any username locks out the entire IP, locking out valid admins on shared/localhost networks. | Separate rate-limiting per username (account defense) from IP-based rate limiting (DDoS defense). | ✅ **FIXED** |
| ⚡ **MEDIUM** | **Replay-Prone Telegram Quick-Block Link**<br>`api/main.py:731` | HMAC signature does not include an expiration timestamp; stale links can block IPs indefinitely. | Append expiration UNIX timestamp (`f"{ip}:{expires_at}"`) into the HMAC payload and reject expired links. | ✅ **FIXED** |
| ℹ️ **LOW** | **Plaintext DB Fallback Credentials**<br>`src/config.py:152` | Neon PostgreSQL credentials exist as fallback strings in source code, risking leak on public Git push. | Remove cleartext password fallbacks; enforce strict loading from `.env` or system environment variables. | ✅ **FIXED** |
| ℹ️ **LOW** | **Stateless JWT Active User Check Gap**<br>`src/auth.py:86` | Disabled users (`is_active = 0`) can still use valid JWT access tokens until 60-min expiration. | Add database check for `is_active` status during protected operations or shorten token lifespan. | ✅ **FIXED** |

---

## 📦 3. Phase 3: Commercial Packaging & Startup Launch Sprint (Q4 2026 - Q1 2027)

To transform NetGuard from a local workstation project into an installable product:

- [ ] **Docker Containerization (`docker-compose.yml`)**:
  - `netguard-api`: Containerized FastAPI backend with Python ML runtime.
  - `netguard-ui`: Containerized Nginx serving React production build.
  - `netguard-redis`: Redis stream broker container.
  - One-command startup: `docker compose up -d`.
- [ ] **Linux Edge Appliance Support**:
  - Native `systemd` unit files replacing Windows NSSM.
  - Tested compatibility on Ubuntu Server 22.04 LTS and Raspberry Pi 4/5 (ARM64).
  - Headless installation script (`install.sh`).
- [ ] **Multi-Tenant Organization Accounts**:
  - Company-level account isolation (Company A cannot see Company B's network telemetry).
  - Centralized Cloud Console where MSPs can manage 10+ distributed sensor appliances.
- [ ] **SIEM & Incident Webhook Exporters**:
  - Native integration with Slack, Microsoft Teams, Discord, and Syslog/Splunk for instant SOC alerting.
- [ ] **Commercial Pilot Launch (Customer POCs)**:
  - Deploy free 30-day trial units to 3 friendly external environments (manufacturing plant, college lab, local business).
  - Gather real-world detection telemetry and customer testimonials.

---

## 🔮 4. Phase 4: Enterprise Hardware Acceleration & Scaled AI (Long-Term 2027)

- [ ] **eBPF / XDP Kernel Capture**: Bypass Python user-space bottlenecks; analyze packets directly in Linux kernel space at 10Gbps+ line-rates.
- [ ] **Lightweight Edge Sensor Probe**: Ultra-fast C/Rust packet collector daemon streaming flow records to centralized NetGuard cluster.
- [ ] **Deep Learning Sequence Modeling**: Bi-LSTM / Temporal Fusion Transformers (TFT) correlated with XGBoost to detect multi-stage APT campaigns.
- [ ] **Industrial IoT DPI Decoders**: Deep packet inspection decoders for Modbus TCP, MQTT, OPC-UA, and CoAP.
- [ ] **Automated PCAP Forensics**: Automated 30-second rolling packet dump on critical alerts for immediate Wireshark post-mortem analysis.

---

## 🖥️ Live Service & Infrastructure Registry

| Component | Target Port | Technology | Default State | Role |
| :--- | :---: | :--- | :---: | :--- |
| **React Web Dashboard** | `5174` | Vite / React 19 / Recharts | **Auto-Start** | Primary User & SOC Interface |
| **FastAPI Backend Server**| `8081` | Python 3.11 / Uvicorn | **Auto-Start** | Core REST API, Auth, & ML Inference |
| **Interactive Docs** | `8081` | Swagger / OpenAPI (`/docs`) | **Available** | API Schema & Integration Sandbox |
| **PostgreSQL Database** | `5432` | Neon Cloud (AWS `us-east-2`)| **Cloud Managed** | Persistent Historical Store & Multi-Tenant Data |
| **Redis Stream Buffer** | `6379` | Redis In-Memory Engine | **Optional / Auto** | High-Burst Ingestion Queue (`netguard:flow_stream`) |
| **Local SQLite WAL** | N/A | `logs/detections.db` | **Embedded** | Sub-Millisecond Local Audit & Write Cache |

---

## 📈 Startup Health Dashboard Summary

```
Technology Readiness Level (TRL): TRL-7 (Integrated system prototype validated in operational environment)
Product Moat: Dual-ML + Native TreeSHAP Explainability + Dual-DB Resilience + Enterprise Hardened Security
Primary Blocker: None (All 8 Phase 5 Security Vulnerabilities Remediated & Validated)
Next Commercial Milestone: Phase 6 Docker Packaging & 3-Site Beta Pilot Testing
```
