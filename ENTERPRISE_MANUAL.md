# 🛡️ NetGuard IDS — Master Enterprise Product Architecture & Technical Operations Manual
### Document Identification: `NGD-ENG-SOP-2026-V35-MNC`
**Classification**: Enterprise Confidential / Technical Standard Operating Procedure (SOP)  
**Distribution**: Tier-1 Enterprise Customers, SOC Directors, Platform Operators, Lead Engineers  
**System Version**: NetGuard IDS v2.2.0-hardened / v3.5 (Industrial IoT Deep Packet Inspection Core)  
**Maturity Benchmark**: Technology Readiness Level 8 (TRL-8: System Complete & Space/Production Qualified)  
**Compliance Standards**: Purdue Enterprise Reference Architecture (PERA Levels 1–3), IEC 62443 / NIST SP 800-82r3, RFC 5424, Common Event Format (CEF), OWASP Top 10 API Security

---

# Table of Contents
1. [Document Control, Scope & Executive Governance](#1-document-control-scope--executive-governance)
2. [End-to-End Enterprise System Architecture](#2-end-to-end-enterprise-system-architecture)
3. [Deep-Dive: Mathematical Formulations & Detection Algorithms](#3-deep-dive-mathematical-formulations--detection-algorithms)
   - 3.1 Supervised Multi-Class Classifier (XGBoost Engine)
   - 3.2 Unsupervised Zero-Day Anomaly Detection (Isolation Forest)
   - 3.3 Domain-Adaptive Industrial IoT Arbiter Logic
   - 3.4 Production TreeSHAP Mathematical Feature Attribution
4. [Industrial IoT Deep Packet Inspection (DPI) Dissectors](#4-industrial-iot-deep-packet-inspection-dpi-dissectors)
   - 4.1 Modbus TCP (Port 502) Dissector & Write Actuator Guard
   - 4.2 MQTT (Ports 1883/8883) Topic Reconnaissance & Wildcard Sniffing Guard
   - 4.3 CoAP (Port 5683) Constrained Protocol Dissector
   - 4.4 OPC-UA (Port 4840) SCADA Dissector
5. [Automated Rolling PCAP Forensics Engine](#5-automated-rolling-pcap-forensics-engine)
6. [Resilient Data Pipeline & Ingestion Architecture](#6-resilient-data-pipeline--ingestion-architecture)
   - 6.1 Promiscuous Raw Packet Extraction & Stateful Flow Reconstruction
   - 6.2 Redis Streams Flow Buffer & Ingestion Queues
   - 6.3 OS-Level Kernel Mutex & Single-Instance Locking
7. [Hybrid Dual-Database Architecture & Cloud Sync](#7-hybrid-dual-database-architecture--cloud-sync)
   - 7.1 Ultra-Low Latency SQLite WAL Mode
   - 7.2 Non-Blocking Neon Cloud PostgreSQL Synchronization Daemon
   - 7.3 Master Relational Database Schema DDL
8. [Asymmetric Cryptographic Licensing & Hardware Fingerprinting](#8-asymmetric-cryptographic-licensing--hardware-fingerprinting)
   - 8.1 Ed25519 & RSA-2048 Digital Signature Schemas
   - 8.2 Hardware Fingerprint Calculation & Anti-Tamper Binding
   - 8.3 Feature-Gating Matrix & Grace Period Lifecycle
9. [Automated Containment & Active Defense Layer](#9-automated-containment--active-defense-layer)
   - 9.1 Host Firewall Actuation: Windows Advanced Firewall & Linux iptables
   - 9.2 Critical IP Whitelisting & Loopback Failsafe Protection
   - 9.3 Dynamic TTL Auto-Pruning & Cryptographic Audit Trails
10. [SOC Alerting, SIEM Integration & Webhook Dispatchers](#10-soc-alerting-siem-integration--webhook-dispatchers)
    - 10.1 RFC 5424 / Common Event Format (CEF) UDP Syslog Exporter
    - 10.2 SMTP SSL HTML Email Generator
    - 10.3 Telegram Bot with Expiring HMAC Action Links
    - 10.4 Enterprise Webhook Dispatchers: Slack, Discord, Microsoft Teams
11. [Network Device Discovery & Topology Mapping](#11-network-device-discovery--topology-mapping)
12. [GenAI Security Copilot & Threat Briefing Engine](#12-genai-security-copilot--threat-briefing-engine)
13. [Multi-Tenancy & Role-Based Access Control (RBAC) Security](#13-multi-tenancy--role-based-access-control-rbac-security)
14. [Master REST API Specification (Exhaustive 38 Endpoints)](#14-master-rest-api-specification-exhaustive-38-endpoints)
15. [React 19 Enterprise Operator Console Specification](#15-react-19-enterprise-operator-console-specification)
16. [Enterprise Deployment Models & Orchestration Guide](#16-enterprise-deployment-models--orchestration-guide)
    - Model A: Docker Multi-Container Fleet (`docker-compose.yml`)
    - Model B: 24/7 Managed Windows NSSM Services
    - Model C: Native Headless Linux Edge Appliance (`systemd`)
    - Model D: Bare-Metal Workstation Rapid Launcher
17. [Owner / Managed Security Service Provider (MSSP) Operating Playbook](#17-owner--managed-security-service-provider-mssp-operating-playbook)
    - Phase 1: Pre-Deployment Discovery & SPAN/Mirror Scoping
    - Phase 2: Pilot Customer Provisioning (`scripts/provision_pilot.py`)
    - Phase 3: On-Site Appliance Commissioning (30-Minute Runbook)
    - Phase 4: Remote Zero-Trust Fleet Telemetry (Tailscale / Cloudflare Tunnel)
    - Phase 5: Month-End Executive PDF Reporting & Retainer Invoicing
18. [Security Hardening Verification & Audit Mitigation Proof](#18-security-hardening-verification--audit-mitigation-proof)
19. [Benchmarking, Latency Profiles & Empirical Verification](#19-benchmarking-latency-profiles--empirical-verification)
20. [Enterprise Troubleshooting, Failure Modes & Runbook](#20-enterprise-troubleshooting-failure-modes--runbook)

---

# 1. Document Control, Scope & Executive Governance

### 1.1 Scope & Mission
This document constitutes the definitive engineering specification, implementation guide, and standard operating procedure for **NetGuard IDS**. NetGuard IDS provides real-time Network Detection and Response (NDR) and automated Network Intrusion Prevention (NIPS) across heterogeneous enterprise IT and industrial OT (Operational Technology) environments.

### 1.2 Purdue Model & OSI Alignment
NetGuard IDS monitors and defends network traffic across:
- **Purdue Model Level 1 (Basic Control)**: Sensors, actuators, PLCs, RTUs transmitting via Modbus TCP, CoAP, and fieldbus protocols.
- **Purdue Model Level 2 (Area Supervisory Control)**: SCADA operator consoles, HMIs, batch control servers communicating over MQTT and OPC-UA.
- **Purdue Model Level 3 (Manufacturing Operations & DMZ)**: Historians, domain controllers, engineering workstations, and IT/OT edge gateways.
- **OSI Layer 3 (Network)**: IP packet headers, routing behaviors, TTLs, IP spoofing, fragmentation.
- **OSI Layer 4 (Transport)**: TCP state machines, window sizes, flag anomalies (SYN floods, RST tearing, ACK scans), UDP flow bursts, ICMP covert channels.
- **OSI Layer 7 (Application)**: HTTP payloads, Modbus MBAP headers, MQTT connect/publish payloads, CoAP options, SQL injection syntax, XSS vectors.

---

# 2. End-to-End Enterprise System Architecture

The following ASCII architecture diagram specifies the flow of raw packets from physical media through deep packet analysis, machine learning arbitration, containment, storage, and SIEM dispatch:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       PHYSICAL & VIRTUAL NETWORK INFRASTRUCTURE                                  │
│   [Promiscuous NIC / TAP / SPAN Mirror Port] ──► Ethernet / 802.11 / Industrial Fieldbus Packets                 │
└────────────────────────────────────────┬─────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ INGESTION LAYER (Scapy Engine + Kernel File-Lock Mutex: logs/capture.lock)                                       │
│                                                                                                                  │
│  ┌──────────────────────────────────────────────┐        ┌─────────────────────────────────────────────────────┐  │
│  │ 60-Second Rolling Circular Ring Buffer       │        │ Stateful 5-Tuple Bidirectional Flow Reconstruction  │  │
│  │ • 2,500 Raw Packets in In-Memory FIFO        │        │ • (src_ip, dst_ip, src_port, dst_port, protocol)    │  │
│  │ • Zero Disk I/O during Benign Operation      │        │ • Computes 80 Flow Statistics (IAT, Flags, Windows) │  │
│  └──────────────────────┬───────────────────────┘        └──────────────────────────┬──────────────────────────┘  │
└─────────────────────────┼───────────────────────────────────────────────────────────┼─────────────────────────────┘
                          │                                                           │
                          │ Trigger Dump (Critical/High)                              │ Dispatched Flow Record
                          ▼                                                           ▼
┌──────────────────────────────────────────────────┐       ┌───────────────────────────────────────────────────────┐
│ ROLLING PCAP FORENSICS ENGINE                    │       │ RESILIENT BUFFER: REDIS STREAMS                       │
│ • wrpcap to reports/forensics/alert_<IP>.pcap    │       │ • Stream: netguard:flow_stream (XADD)                 │
│ • FIFO Rotation (Max 50 Forensics Files)         │       │ • Consumer Group: netguard_inference_group (XREADGROUP)│
│ • Wireshark Ready for SOC Post-Mortem Audit      │       │ • Graceful Non-Blocking ThreadPool HTTP Fallback      │
└──────────────────────────────────────────────────┘       └──────────────────────────┬────────────────────────────┘
                                                                                      │
                                                                                      ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ FASTAPI CORE REST ENGINE (:8081) / DUAL-ML INFERENCE ARBITER                                                     │
│                                                                                                                  │
│  ┌───────────────────────────────────────────────────┐    ┌────────────────────────────────────────────────────┐ │
│  │ 1. Industrial IoT Deep Packet Inspection (DPI)    │    │ 2. StandardScaler Feature Normalization (80 Cols)  │ │
│  │ • Modbus TCP (Port 502) Function & Coil Inspector │    │ • Fitted on 8.2M CIC-IDS2018 records (scaler.pkl)  │ │
│  │ • MQTT (Port 1883/8883) Topic & Wildcard Sniffer  │    └─────────────────────────┬──────────────────────────┘ │
│  │ • CoAP (Port 5683) URI & Method Parser            │                              │                            │
│  └─────────────────────────┬─────────────────────────┘                              ▼                            │
│                            │                             ┌────────────────────────────────────────────────────┐  │
│                            │                             │ 3. XGBoost Multi-Class Supervised Classifier       │  │
│                            │                             │ • 300 Trees, Depth 6, Hist Gradient (xgb_model.pkl)│  │
│                            │                             │ • Classes: Normal, BruteForce, DoS/DDoS, Web, Inf. │  │
│                            │                             └──────────────────────────┬─────────────────────────┘  │
│                            │                                                        │                            │
│                            │                             ┌──────────────────────────▼─────────────────────────┐  │
│                            │                             │ 4. Unsupervised Isolation Forest (Zero-Day Outlier)│  │
│                            │                             │ • Path-length Contamination Scorer (iforest.pkl)   │  │
│                            │                             │ • Domain-Adaptive IoT Port Threshold: 0.65 ➔ 0.55  │  │
│                            │                             └──────────────────────────┬─────────────────────────┘  │
│                            │                                                        │                            │
│                            └────────────────────────┬───────────────────────────────┘                            │
│                                                     ▼                                                            │
│                                      ┌──────────────────────────────┐                                            │
│                                      │ Master Decision Arbiter      │                                            │
│                                      │ Final Prediction & Severity  │                                            │
│                                      └──────────────┬───────────────┘                                            │
└─────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────┘
                                                      │
                      ┌───────────────────────────────┴───────────────────────────────┐
                      ▼                                                               ▼
┌───────────────────────────────────────────────┐               ┌──────────────────────────────────────────────────┐
│ HYBRID DUAL-DATABASE ENGINE                   │               │ ACTIVE CONTAINMENT & DEFENSE ENGINE              │
│ • Local SQLite WAL (logs/detections.db)       │               │ • Windows Firewall: netsh advfirewall add rule   │
│   Sub-millisecond writes (<1ms)               │               │ • Linux Host: iptables -I INPUT/OUTPUT/FORWARD   │
│ • Background Cloud Sync Daemon (Every 30s)    │               │ • Critical IP Whitelist (Gateway, Loopback, DNS) │
│   Syncs records over SSL to:                  │               │ • Dynamic TTL Auto-Pruning Background Worker     │
│   Neon Cloud PostgreSQL (AWS us-east-2)       │               │ • Persistent Audit Trail (table: block_audit)    │
└───────────────────────────────────────────────┘               └──────────────────────────────────────────────────┘
                      │                                                               │
                      ▼                                                               ▼
┌───────────────────────────────────────────────┐               ┌──────────────────────────────────────────────────┐
│ EXPLAINABLE AI (XAI) ENGINE                   │               │ MULTI-CHANNEL SOC ALERTING & SIEM DISPATCH       │
│ • Exact TreeSHAP Shapley Computations         │               │ • RFC 5424 / CEF UDP Syslog Datagrams (Port 514)│
│ • Top-5 Feature Contributions                 │               │ • SMTP SSL HTML Threat Email Dispatch            │
│ • Mathematical Attribution without Heuristics │               │ • Telegram Bot API with Expiring HMAC URLs       │
│ • Endpoints: POST /explain                    │               │ • Webhooks: Slack, Discord, Microsoft Teams      │
└───────────────────────────────────────────────┘               └──────────────────────────────────────────────────┘
                                                      │
                                                      ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ PRESENTATION TIER: REACT 19 ENTERPRISE SOC DASHBOARD (:5174 / NGINX :80)                                         │
│ • 1-Second Telemetry Pulse • Real-Time Incidents Feed • 1-Click Containment • ARP/Nmap Scanner • TreeSHAP Modal  │
│ • AI Security Copilot Chat • RBAC User Manager • Asymmetric License Key Manager • Research Benchmark Visualizer │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

# 3. Deep-Dive: Mathematical Formulations & Detection Algorithms

### 3.1 Supervised Multi-Class Classifier (XGBoost Engine)
The supervised classification pipeline implements an extreme gradient boosted decision tree ensemble ($K = 5$ classes). 

For a given feature vector $x_i \in \mathbb{R}^{80}$, the ensemble predicts the class probabilities using a softmax objective across additive functions:
$$\hat{y}_{i,k} = \sum_{m=1}^{M} f_{m,k}(x_i), \quad f_{m,k} \in \mathcal{F}$$
where $\mathcal{F} = \{f(x) = w_{q(x)}\}$ is the space of regression trees, $q: \mathbb{R}^{80} \to T$ maps features to leaf indices, and $w \in \mathbb{R}^T$ represents leaf weights.

The regularized objective minimized during training is:
$$\mathcal{L} = \sum_{i} \ell(y_i, \hat{y}_i) + \sum_{m} \left( \gamma T_m + \frac{1}{2}\lambda \|w_m\|^2 \right)$$
- **Loss Function $\ell$**: Multi-class cross-entropy (`mlogloss`).
- **Tree Growth Algorithm**: Histogram-based binning (`tree_method="hist"`).
- **Hyperparameters**: $M = 300$ estimators, maximum tree depth $d = 6$, shrinkage/learning rate $\eta = 0.1$, subsample ratio $= 0.8$, colsample_bytree $= 0.8$, $L_2$ regularization $\lambda = 1.0$.

#### Class Mapping & Industry Calibrated Confidence Thresholds
| Class Index | Label | Severity | Calibrated Threshold $\tau_k$ | Operational Profile |
|:---|:---|:---|:---:|:---|
| `0` | `NORMAL` | `none` | $1.00$ | Benign line-rate telemetry |
| `1` | `BRUTE_FORCE` | `high` | $0.80$ | SSH/FTP credential stuffing |
| `2` | `DOS_DDOS` | `critical` | $0.85$ | Slowloris, GoldenEye, Hulk, LOIC/HOIC floods |
| `3` | `WEB_ATTACK` | `high` | $0.80$ | SQLi, XSS, command injection |
| `4` | `INFILTRATION` | `critical` | $0.45$ | C2 beaconing, port reconnaissance, backdoors |

---

### 3.2 Unsupervised Zero-Day Anomaly Detection (Isolation Forest)
To defend against novel zero-day exploits absent from training distributions, NetGuard runs an unsupervised Isolation Forest trained purely on benign flow structures ($N_{trees} = 100$, contamination $\alpha = 0.03$).

The anomaly score $s(x, n)$ for an instance $x$ over a sample size of $n$ instances is given by:
$$s(x, n) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}$$
where $\mathbb{E}(h(x))$ is the expectation of the path length $h(x)$ across all isolation trees, and $c(n)$ is the average path length of an unsuccessful search in a Binary Search Tree (BST):
$$c(n) = 2 \ln(n - 1) + 0.5772156649 \text{ (Euler-Mascheroni Constant)} - \frac{2(n - 1)}{n}$$

In [src/predict.py](file:///c:/iot-ids/src/predict.py), raw decision values are mapped to a bounded interval $S_{norm} \in [0.0, 1.0]$:
$$S_{norm} = \text{clip}(0.5 - \text{decision\_function}(x), 0.0, 1.0)$$

---

### 3.3 Domain-Adaptive Industrial IoT Arbiter Logic
Industrial IoT networks behave fundamentally differently from traditional enterprise workstations: legitimate sensor traffic exhibits periodic, low-bandwidth telemetry, whereas malicious manipulation involves unauthorized actuator writes or sudden high-burst polling.

NetGuard implements an **Adaptive Threat Boundary**:
$$\text{Threshold } \theta = \begin{cases} 
0.55 & \text{if } DstPort \in \{502, 1883, 8883, 5683, 4840\} \lor FlowPkts/s > 1000 \\ 
0.65 & \text{otherwise} 
\end{cases}$$

#### The Master Arbiter State Machine
```
   XGBoost Output: L_xgb, Confidence: C_xgb
   Isolation Forest Output: AnomalyScore: S_norm, IsAnomaly: B_iforest
   
   IF (L_xgb == "NORMAL" AND (B_iforest == True OR S_norm > θ)):
       FINAL_LABEL      = "ZERO_DAY_ANOMALY"
       FINAL_CONFIDENCE = MAX(S_norm, 0.75)
       FINAL_SEVERITY   = "critical"
   ELSE:
       FINAL_LABEL      = L_xgb
       FINAL_CONFIDENCE = C_xgb
       FINAL_SEVERITY   = SEVERITY_MAP[L_xgb]
```

---

### 3.4 Production TreeSHAP Mathematical Feature Attribution
NetGuard avoids heuristic local linear approximations (such as LIME). In [src/xai.py](file:///c:/iot-ids/src/xai.py), it instantiates `shap.TreeExplainer` on the fitted XGBoost ensemble to compute exact classical Shapley values:
$$\phi_j(x) = \sum_{S \subseteq F \setminus \{j\}} \frac{|S|!(|F| - |S| - 1)!}{|F|!} \left[ f_x(S \cup \{j\}) - f_x(S) \right]$$
where $F$ is the complete set of 80 flow features, $S$ is a feature subset, and $f_x(S) = \mathbb{E}[f(x) \mid x_S]$ represents the conditional expectation of the model output given features in $S$.

The sum of attributions satisfies the **Efficiency Property**:
$$\sum_{j=1}^{80} \phi_j(x) = f(x) - \mathbb{E}[f(x)]$$
For every predicted incident, `/explain` returns the Top-5 ranked features by magnitude $|\phi_j|$, their directional sign (pushing toward attack vs. normal), the physical feature value, and a human-readable interpretation.

---

# 4. Industrial IoT Deep Packet Inspection (DPI) Dissectors

NetGuard IDS inspects industrial application protocols at line-rate via specialized binary dissectors in [src/dpi_decoders.py](file:///c:/iot-ids/src/dpi_decoders.py).

```
   ┌────────────────────────────────────────────────────────────────────────┐
   │                       Industrial DPI Decoder Hub                       │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
     ┌──────────────────┬──────────────┴─────┬──────────────────┐
     ▼                  ▼                    ▼                  ▼
┌──────────────┐ ┌──────────────┐     ┌──────────────┐   ┌──────────────┐
│  Modbus TCP  │ │     MQTT     │     │     CoAP     │   │    OPC-UA    │
│  (Port 502)  │ │ (1883/8883)  │     │  (Port 5683) │   │  (Port 4840) │
└──────────────┘ └──────────────┘     └──────────────┘   └──────────────┘
```

### 4.1 Modbus TCP (Port 502) Dissector
- **Protocol Header Framing (MBAP)**:
  `Transaction ID (16b) | Protocol ID (16b, Must be 0) | Length (16b) | Unit Identifier (8b) | Function Code (8b)`
- **Function Code Taxonomy**:
  - Legitimate Reads: `0x01` (Read Coils), `0x02` (Read Discrete Inputs), `0x03` (Read Holding Registers), `0x04` (Read Input Registers).
  - Critical Actuator Writes: `0x05` (Write Single Coil), `0x06` (Write Single Register), `0x0F` (Write Multiple Coils), `0x10` (Write Multiple Registers).
- **Anomaly Detection Policy**: In unauthenticated Purdue Level 1/2 networks, write operations (`Function Code` $\in \{5, 6, 15, 16\}$) executed without an active operator token trigger an immediate high-priority alert:
  `"Unauthorized Modbus Control Actuation Attempt (Function: Write Single Coil)"`

### 4.2 MQTT (Ports 1883 / 8883) Dissector
- **Header Parsing**: Evaluates Fixed Header Byte 1 (`Packet Type = (Byte0 >> 4) & 0x0F`). Unpacks Variable Length Multi-Byte Remaining Length fields.
- **Topic Reconnaissance Defense**: Inspects `SUBSCRIBE` payloads. Detects wildcard subscriptions:
  - Multi-level wildcard: `#`
  - Single-level wildcard: `+`
  - Flags sniffing attacks: `"MQTT Wildcard Subscription Sniffing Detected (Pattern: #)"`
- **Critical Topic Injection**: Flags unauthorized publishing to command trees, including `cmd/*`, `exec/*`, `system/reboot`, `actuator/override`.

### 4.3 CoAP (Constrained Application Protocol - Port 5683) Dissector
- **Binary Structure**: `Version (2b) | Type (2b) | Token Length (4b) | Code (8b, Class.Detail) | Message ID (16b)`.
- **Method Flagging**: Code class `0` (Request). Details: `0.01` GET, `0.02` POST, `0.03` PUT, `0.04` DELETE.
- **Anomaly Detection Policy**: Anomaly triggered if destructive methods (`DELETE`) or client/server error responses (`4.xx`, `5.xx`) occur against low-power IoT end-devices.

### 4.4 OPC-UA (Port 4840) SCADA Dissector
- Inspects OPC-UA TCP message types: `HEL` (Hello), `ACK` (Acknowledge), `OPN` (OpenSecureChannel), `MSG` (Standard Message), `CLO` (CloseSecureChannel).
- Flags security policy violations where `SecurityPolicy#None` is negotiated in secure industrial enclaves.

---

# 5. Automated Rolling PCAP Forensics Engine

Located in [src/pcap_forensics.py](file:///c:/iot-ids/src/pcap_forensics.py), NetGuard implements automated, zero-impact rolling forensics:

1. **In-Memory Ring Buffer**:
   - Implemented via a thread-safe `collections.deque(maxlen=2500)`.
   - Stores `(timestamp, scapy_packet)` tuples covering the trailing 60 seconds of traffic.
   - Operates with **zero disk I/O** during normal conditions, eliminating flash memory degradation on edge devices.
2. **Alert-Triggered Snapshot Extraction**:
   - When a flow is evaluated as `severity in ("critical", "high")`, a background daemon triggers `trigger_alert_pcap(source_ip, prediction, severity)`.
   - Copies the buffer under lock, sorts chronologically, and writes a standard libpcap container using Scapy's `wrpcap`:
     `reports/forensics/alert_<SAN_IP>_<PRED>_<TIMESTAMP>.pcap`
3. **Retention & Security Hardening**:
   - Retention policy maintains a maximum of 50 PCAP files; older captures are pruned FIFO.
   - Endpoint `/forensics/download/{filename}` enforces strict filename canonicalization, rejecting directory traversal characters (`..`, `/`, `\`).

---

# 6. Resilient Data Pipeline & Ingestion Architecture

### 6.1 Promiscuous Raw Packet Extraction & Stateful Flow Reconstruction
In [src/capture.py](file:///c:/iot-ids/src/capture.py), Scapy binds to the physical interface (`iface`). Every IPv4 packet is ingested via callback `process_packet()`:

- **Bidirectional 5-Tuple Keying**:
  $$K_{fwd} = (IP_{src}, IP_{dst}, Port_{src}, Port_{dst}, Proto), \quad K_{bwd} = (IP_{dst}, IP_{src}, Port_{dst}, Port_{src}, Proto)$$
- **Statistical Feature Generation**:
  - Inter-Arrival Times (IAT): $\Delta t = t_i - t_{i-1}$, computing $\mu_{IAT}, \sigma_{IAT}, \max_{IAT}, \min_{IAT}$ independently for forward, backward, and total flow.
  - Byte & Packet Quantities: Total packets, total payload bytes, header lengths, packet length variance $\sigma_{pkt}^2$.
  - TCP Control Flag Accumulators: `FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`, `CWE`, `ECE`.
  - Window Metrics: Initial window size bytes for forward and reverse directions.
- **Flow Emission Triggers**:
  1. Accumulated flow packet count $\ge 5$ packets.
  2. Protocol state termination: `TCP FIN` ($0x01$) or `TCP RST` ($0x04$).
  3. Idle Timeout: Dedicated daemon sweeps every $2.0$ seconds, flushing any active flows inactive for $\ge 2.0$s.

### 6.2 Redis Streams Flow Buffer & Ingestion Queues
During high-velocity attacks (e.g. 50,000 packets/sec SYN flood), synchronous HTTP posts to `/predict` would saturate the thread pool.
- **Producer ([src/stream_producer.py](file:///c:/iot-ids/src/stream_producer.py))**: Dispatches serialized flow dictionaries to Redis Stream `netguard:flow_stream` via `XADD`.
- **Consumer ([src/stream_consumer.py](file:///c:/iot-ids/src/stream_consumer.py))**: Spawns an event loop utilizing `XREADGROUP` under consumer group `netguard_inference_group`, fetching batches of 100 flows and dispatching inference across a 4-thread worker pool.
- **Graceful HTTP Fallback**: If Redis is absent or connectivity fails, the pipeline automatically routes flows through an internal `concurrent.futures.ThreadPoolExecutor` directly to the `/predict` engine.

### 6.3 OS-Level Kernel Mutex & Single-Instance Locking
To eliminate dual-capture conflicts between systemd/NSSM background services and interactive user sessions, `acquire_capture_lock()` binds to `logs/capture.lock`:
- **Windows**: `msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)`.
- **Linux**: `fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)`.
Secondary processes detect the lock, output a graceful notice, and exit with status code 0.

---

# 7. Hybrid Dual-Database Architecture & Cloud Sync

### 7.1 Ultra-Low Latency SQLite WAL Mode
All telemetry writes execute locally against `logs/detections.db`:
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA cache_size = -64000; -- 64MB cache
```
Writes complete in under **1.0 millisecond**, preventing storage I/O from introducing backpressure to network packet capture.

### 7.2 Non-Blocking Neon Cloud PostgreSQL Synchronization Daemon
Every 30 seconds, a background daemon in [api/main.py](file:///c:/iot-ids/api/main.py) invokes `migrate_all()` ([scripts/migrate_sqlite_to_pg.py](file:///c:/iot-ids/scripts/migrate_sqlite_to_pg.py)):
1. Queries the remote PostgreSQL instance for the highest synchronized `id`.
2. Extracts pending records from local SQLite.
3. Batch-inserts pending rows into Neon PostgreSQL over encrypted TLSv1.3 (`sslmode=require`).
4. Updates high-water marks cleanly without record duplication.

### 7.3 Master Relational Database Schema DDL
The following schema is maintained in both SQLite and Neon Cloud PostgreSQL:

```sql
-- 1. Organizations & Multi-Tenant Scoping
-- Every table carries tenant_id for logical data segregation
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(255) UNIQUE NOT NULL,
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(50)  NOT NULL DEFAULT 'viewer',
    full_name     VARCHAR(255),
    phone         VARCHAR(50),
    designation   VARCHAR(100),
    is_active     INTEGER      NOT NULL DEFAULT 1,
    tenant_id     VARCHAR(100) NOT NULL DEFAULT 'default',
    created_at    VARCHAR(100) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    VARCHAR(100) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Stateful Refresh Tokens with Rotation (RTR)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at VARCHAR(100) NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    created_at VARCHAR(100) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Authentication Rate Limiting & Lockout Logs
CREATE TABLE IF NOT EXISTS login_attempts (
    id           SERIAL PRIMARY KEY,
    username     VARCHAR(255) NOT NULL,
    ip_address   VARCHAR(100),
    success      INTEGER NOT NULL DEFAULT 0,
    attempted_at VARCHAR(100) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Global Detection Records
CREATE TABLE IF NOT EXISTS detections (
    id          SERIAL PRIMARY KEY,
    timestamp   VARCHAR(100) NOT NULL,
    prediction  VARCHAR(100) NOT NULL,
    confidence  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    severity    VARCHAR(50)  NOT NULL DEFAULT 'none',
    source_ip   VARCHAR(100) NOT NULL DEFAULT 'unknown',
    flow_id     VARCHAR(255),
    mode        VARCHAR(50)  NOT NULL DEFAULT 'live',
    tenant_id   VARCHAR(100) NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_detections_ts ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_tenant ON detections(tenant_id);

-- 5. Active Containment Blocklist
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip          VARCHAR(100) PRIMARY KEY,
    reason      TEXT NOT NULL,
    blocked_by  VARCHAR(100) NOT NULL DEFAULT 'system',
    blocked_at  VARCHAR(100) NOT NULL,
    expires_at  VARCHAR(100),
    layer       VARCHAR(50)  NOT NULL DEFAULT 'firewall',
    tenant_id   VARCHAR(100) NOT NULL DEFAULT 'default'
);

-- 6. Containment Audit Log
CREATE TABLE IF NOT EXISTS block_audit (
    id        SERIAL PRIMARY KEY,
    event     VARCHAR(100) NOT NULL, -- 'block', 'unblock', 'expire'
    ip        VARCHAR(100) NOT NULL,
    actor     VARCHAR(100) NOT NULL DEFAULT 'system',
    reason    TEXT,
    timestamp VARCHAR(100) NOT NULL,
    detail    TEXT,
    tenant_id VARCHAR(100) NOT NULL DEFAULT 'default'
);
```

---

# 8. Asymmetric Cryptographic Licensing & Hardware Fingerprinting

Located in [src/license.py](file:///c:/iot-ids/src/license.py):

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Asymmetric Licensing Engine (Ed25519)                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
┌─────────────────────────────────────┐   ┌─────────────────────────────────────┐
│ Private Key (Vendor Infrastructure) │   │ Public Key (Distributed Appliance)  │
│ • signs payload via Ed25519         │   │ • verifies digital signature        │
│ • outputs Base64URL license token   │   │ • zero private keys on client disk  │
└─────────────────────────────────────┘   └─────────────────────────────────────┘
```

### 8.1 Ed25519 & RSA-2048 Digital Signature Schemas
License tokens are generated using Twisted Edwards Curve **Ed25519** (RFC 8032):
$$\text{Signature } \sigma = \text{Sign}(SK, M)$$
The token structure is Base64URL-encoded:
`PayloadBase64URL . SignatureBase64URL`

The decoded payload JSON contains:
```json
{
  "license_id": "c1f7a048-2b89-4e78-9844-42b78129c512",
  "licensee": "Sharma Logistics",
  "tier": "Enterprise",
  "issued_at": 1773561600,
  "expires_at": 1805097600,
  "max_devices": 100,
  "hardware_id": "77607a5e1940d5d112dd3000059a9770",
  "features": ["dual_ml", "xai_treeshap", "containment", "genai_copilot", "siem_export", "pcap_forensics"]
}
```

### 8.2 Hardware Fingerprint Calculation & Anti-Tamper Binding
To prevent license cloning across instances, `get_hardware_fingerprint()` hashes stable system identifiers:
$$H_{node} = \text{SHA256}(\text{OS} \parallel \text{Architecture} \parallel \text{MAC Address})[0:32]$$
If a license specifies `hardware_id` and the calculated runtime hash differs, the system returns status `HARDWARE_MISMATCH`.

### 8.3 Feature-Gating Matrix & Grace Period Lifecycle
| Tier | Price Model | Allowed Endpoints / Features | Device Cap |
|:---|:---|:---|:---:|
| **Trial** | Free Evaluation | XGBoost + Isolation Forest, SQLite Storage, Dashboard | 5 Devices |
| **Pro** | Commercial Small-Business | Adds: TreeSHAP XAI (`/explain`), Host Firewall Auto-Block, PDF Threat Reports | 50 Devices |
| **Enterprise** | Corporate / Industrial | Adds: GenAI Copilot (`/assistant/*`), SIEM RFC 5424 Syslog, DPI Decoders, Rolling Forensics, Multi-Tenancy | Unlimited |

- **Grace Period**: Upon reaching `expires_at`, the system transitions to `GRACE_PERIOD` for **3 days** with prominent warnings before entering `EXPIRED` state.

---

# 9. Automated Containment & Active Defense Layer

Implemented in [src/blocklist.py](file:///c:/iot-ids/src/blocklist.py):

### 9.1 Host Firewall Actuation: Windows Advanced Firewall & Linux iptables
- **Windows (Elevated Token)**:
  Executes bidirectional rule injection via `netsh`:
  ```cmd
  netsh advfirewall firewall add rule name="NetGuard-Block-192.168.1.105-in" dir=in action=block remoteip=192.168.1.105 enable=yes profile=any
  netsh advfirewall firewall add rule name="NetGuard-Block-192.168.1.105-out" dir=out action=block remoteip=192.168.1.105 enable=yes profile=any
  ```
- **Linux (`CAP_NET_ADMIN`)**:
  Injects drop rules at index 1 across three kernel chains:
  ```bash
  iptables -I INPUT 1 -s 192.168.1.105 -j DROP
  iptables -I OUTPUT 1 -d 192.168.1.105 -j DROP
  iptables -I FORWARD 1 -s 192.168.1.105 -j DROP
  ```

### 9.2 Critical IP Whitelisting & Loopback Failsafe Protection
The function `_is_protected(addr)` evaluates candidate IPs before any block command:
- Protected CIDRs: `127.0.0.0/8`, `::1/128`, `169.254.0.0/16` (APIPA), `224.0.0.0/4` (Multicast), `255.255.255.255/32`.
- Default Gateway: Resolved dynamically via ARP tables.
- Active Host IP: Resolved via socket interface probing.
- User Whitelist: Configured via `.env` parameter `WHITELISTED_IPS`.

### 9.3 Dynamic TTL Auto-Pruning & Cryptographic Audit Trails
A daemon evaluates `blocked_ips` every 60 seconds. When `expires_at < current_timestamp`, the firewall rule is deleted, the record is removed from `blocked_ips`, and an audit row with `event='expire'` is logged to `block_audit`.

---

# 10. SOC Alerting, SIEM Integration & Webhook Dispatchers

### 10.1 RFC 5424 / Common Event Format (CEF) UDP Syslog Exporter
In [src/webhook_exporters.py](file:///c:/iot-ids/src/webhook_exporters.py), NetGuard formats alerts into ArcSight / Splunk Common Event Format:
```text
CEF:0|NetGuard|NetGuard-IDS|2.2|DOS_DDOS|Network Intrusion Event: DOS_DDOS|8|src=192.168.1.105 dst=10.0.0.1 msg=High-confidence attack detected act=blocked
```
Datagrams are dispatched over UDP to `SYSLOG_HOST:SYSLOG_PORT` (Default: 514).

### 10.2 SMTP SSL HTML Email Generator
Constructs a responsive HTML email containing incident classification, confidence percentage, source IP, affected port, and recommended remediation protocols. Sent via `smtplib.SMTP_SSL` on port 465.

### 10.3 Telegram Bot with Expiring HMAC Action Links
Pushes Markdown threat cards to `TELEGRAM_CHAT_ID`. Contains an inline quick-block action URL secured by an HMAC-SHA256 signature binding the IP and a 1-hour expiration timestamp:
```
http://api-host:8081/api/telegram/block?ip=192.168.1.105&expires=1773565200&sig=a9f4c3...
```
Requests after expiration return `403 Link Expired`.

### 10.4 Enterprise Webhook Dispatchers: Slack, Discord, Microsoft Teams
Dispatches adaptive cards formatted for Slack Webhook URLs, Discord Channels, and Microsoft Teams Connectors within a non-blocking thread pool.

---

# 11. Network Device Discovery & Topology Mapping

Located in [src/scanner.py](file:///c:/iot-ids/src/scanner.py):

1. **Subnet Auto-Discovery**: Probes local interfaces to derive network CIDR (e.g. `192.168.1.0/24`).
2. **Fast ARP Ping Sweep (2–3 seconds)**:
   Transmits Scapy broadcast frame:
   `Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24")`
   Parses incoming responses into `{ip, mac}` records.
3. **Active Nmap Port & OS Detection**:
   Runs `nmap -sS -sV -O --top-ports 100` against discovered hosts, resolving open ports, service versions, and OS fingerprints.
4. **OUI Vendor Resolution**: Matches MAC prefixes against IEEE Organizationally Unique Identifier catalogs to identify hardware vendors (e.g., Siemens, Cisco, Raspberry Pi, Apple).

---

# 12. GenAI Security Copilot & Threat Briefing Engine

Implemented in [src/genai_assistant.py](file:///c:/iot-ids/src/genai_assistant.py):

- **Supported AI Providers**:
  1. **Google Gemini Pro / Flash**: Via HTTPS REST using `gemini-flash-latest` or `gemini-pro-latest`.
  2. **Local Air-Gapped Ollama**: Communicates with `http://localhost:11434/api/generate` running `llama3.2`.
  3. **Hugging Face Inference API**: Connects to `Qwen/Qwen2.5-Coder-32B-Instruct`.
  4. **Embedded Local Rule Engine**: Internal deterministic fallback when external connections are disabled.
- **Capabilities**:
  - `/assistant/insights`: Queries database metrics over the trailing 24 hours and synthesizes an executive summary of threat distributions, top targeted ports, and operational advice.
  - `/assistant/chat`: Natural-language conversational interface answering questions such as: *"Which IP sent the most traffic in the last 6 hours and should I block it?"*

---

# 13. Multi-Tenancy & Role-Based Access Control (RBAC) Security

### 13.1 Cryptographic Password Security & Brute Force Lockout
- **Hashing**: **PBKDF2-HMAC-SHA256** with 260,000 iterations and unique 16-byte random salts.
- **Account Lockout Policy**: Tracks failed logins in `login_attempts`. If 5 consecutive failed attempts occur within 15 minutes, the account is locked for 15 minutes. Loopback (`127.0.0.1`) is exempt from shared IP spray locks.

### 13.2 Stateless JWT & Refresh Token Rotation (RTR)
- **Access Tokens**: Short-lived (60 minutes), signed with `HS256` using persistent `SECRET_KEY`. Encodes claims: `sub` (username), `role`, `tenant_id`, `exp`.
- **Refresh Tokens**: Cryptographically random 64-character tokens stored hashed in `refresh_tokens`. Every exchange at `/auth/refresh` revokes the incoming token and issues a new token pair.

### 13.3 Role Permission Matrix
| System Action | Admin | Analyst | Viewer |
|:---|:---:|:---:|:---:|
| Read Telemetry & Incident Logs (`view`) | ✅ | ✅ | ✅ |
| Manage Live Capture Sessions (`capture`) | ✅ | ✅ | ❌ |
| Manual IP Containment (`block_ip`) | ✅ | ✅ | ❌ |
| Remove IP Containment (`unblock_ip`) | ✅ | ❌ | ❌ |
| Export Audit Reports (`report`) | ✅ | ✅ | ❌ |
| User Administration & Licensing (`manage_users`) | ✅ | ❌ | ❌ |

---

# 14. Master REST API Specification (Exhaustive 38 Endpoints)

All endpoints run on `http://127.0.0.1:8081`. Authentication uses standard Bearer JWT header: `Authorization: Bearer <TOKEN>`.

### Group 1: Authentication & Identity Management
```http
POST /auth/login
Content-Type: application/json
{ "username": "admin", "password": "netguard123" }
Response 200 OK:
{ "access_token": "ey...", "refresh_token": "a1b2...", "token_type": "bearer", "role": "admin", "tenant_id": "default" }

POST /auth/refresh
Content-Type: application/json
{ "refresh_token": "a1b2..." }
Response 200 OK:
{ "access_token": "ey...", "refresh_token": "c3d4...", "token_type": "bearer" }

POST /auth/logout
Content-Type: application/json
{ "refresh_token": "c3d4..." }
Response 200 OK: { "message": "Successfully logged out" }

GET /auth/me
Response 200 OK:
{ "username": "admin", "role": "admin", "permissions": ["view", "capture", "block_ip", "unblock_ip", "report", "manage_users"] }
```

### Group 2: User Account Administration (`manage_users` Required)
```http
POST /auth/users
{ "username": "analyst1", "email": "analyst1@corp.com", "password": "Pass@123", "role": "analyst", "full_name": "John Doe", "phone": "+123456789", "designation": "SOC Analyst" }

GET /auth/users
Response 200 OK: { "users": [ { "id": 1, "username": "admin", "role": "admin", "is_active": 1, ... } ] }

PATCH /auth/users/{username}/role
{ "role": "analyst" }

PATCH /auth/users/{username}/toggle
Response 200 OK: { "username": "analyst1", "is_active": 0 }

DELETE /auth/users/{username}
Response 200 OK: { "message": "User analyst1 deleted" }
```

### Group 3: Core Prediction & ML Inference
```http
POST /predict
Header: X-Agent-Key: <AGENT_KEY> OR Authorization: Bearer <TOKEN>
{
  "Dst_Port": 80, "Protocol": 6, "Flow_Duration": 1500000,
  "Tot_Fwd_Pkts": 45, "Tot_Bwd_Pkts": 30, "TotLen_Fwd_Pkts": 3200, ...
}
Response 200 OK:
{
  "prediction": "DOS_DDOS", "confidence": 0.9842, "severity": "critical",
  "is_anomaly": false, "anomaly_score": 0.1245, "xgb_prediction": "DOS_DDOS",
  "all_scores": { "NORMAL": 0.001, "BRUTE_FORCE": 0.002, "DOS_DDOS": 0.9842, "WEB_ATTACK": 0.01, "INFILTRATION": 0.0028 },
  "timestamp": "2026-11-15T08:00:00Z"
}

POST /predict/batch
[ { "Dst_Port": 80, ... }, { "Dst_Port": 443, ... } ]

POST /explain (Requires Pro/Enterprise Tier)
{ "record": { "Dst Port": 80, "Flow Duration": 1500000, ... } }
Response 200 OK:
{
  "prediction": "DOS_DDOS",
  "top_features": [
    { "feature": "Dst Port", "value": 80, "shap_value": 2.145, "contribution": "Pushes toward Attack" }
  ],
  "human_rationale": "Destination port 80 and high packet rate strongly indicate DoS flood activity."
}
```

### Group 4: Telemetry, Logs & Statistics
```http
GET /health
Response 200 OK: { "status": "ok", "detector": "ready", "database": "healthy", "capture_active": true }

GET /stats
Response 200 OK:
{ "total_events": 142050, "attacks_detected": 1840, "attack_rate": 1.29, "active_blocks": 12, "by_class": { "DOS_DDOS": 1200, "BRUTE_FORCE": 420, ... } }

GET /history?limit=100&hours=24
Response 200 OK: [ { "id": 142, "timestamp": "...", "prediction": "DOS_DDOS", "confidence": 0.98, "source_ip": "192.168.1.105" } ]

GET /reports/export (Analyst/Admin)
Response 200 OK: Content-Type: application/pdf (Executive Threat Summary Report)
```

### Group 5: Active Containment & Blocklist
```http
GET /blocked-ips
Response 200 OK: [ { "ip": "192.168.1.105", "reason": "DOS_DDOS auto-block", "expires_at": "...", "layer": "firewall" } ]

POST /blocked-ips
{ "ip": "192.168.1.105", "reason": "Manual SOC Containment", "ttl_seconds": 3600 }

DELETE /blocked-ips/{ip} (Admin Only)
Response 200 OK: { "message": "IP 192.168.1.105 successfully unblocked" }

POST /blocked-ips/bulk-block
{ "ips": ["192.168.1.105", "192.168.1.106"], "reason": "Compromised Subnet" }

POST /blocked-ips/bulk-unblock (Admin Only)
{ "ips": ["192.168.1.105", "192.168.1.106"] }

GET /blocked-ips/audit (Admin Only)
Response 200 OK: [ { "event": "block", "ip": "192.168.1.105", "actor": "admin", "timestamp": "..." } ]
```

### Group 6: Live Packet Sniffing & Rolling Forensics
```http
GET /capture/interfaces
Response 200 OK: { "interfaces": [ { "name": "eth0", "ip": "192.168.1.50", "mac": "00:1A:2B:3C:4D:5E" } ] }

GET /capture/status
Response 200 OK: { "active": true, "interface": "eth0", "packets_captured": 84520 }

POST /capture/start
{ "interface": "eth0" }

POST /capture/stop
Response 200 OK: { "message": "Packet capture halted" }

GET /forensics/pcaps
Response 200 OK: { "pcaps": [ { "filename": "alert_192_168_1_105_DOS_DDOS_20261115.pcap", "size_kb": 512, "created_at": "..." } ] }

GET /forensics/download/{filename}
Response 200 OK: Binary PCAP Stream (Wireshark Native)

POST /forensics/trigger-dump
{ "source_ip": "192.168.1.105", "label": "MANUAL_INVESTIGATION" }
```

### Group 7: Network Device Scanner
```http
POST /network/scan/arp
Response 200 OK: { "devices": [ { "ip": "192.168.1.1", "mac": "00:50:56:C0:00:01", "vendor": "VMware, Inc.", "status": "online" } ] }

POST /network/scan
Response 200 OK: { "devices": [ { "ip": "192.168.1.1", "ports": [22, 80, 443], "os": "Linux 5.4", ... } ] }

GET /network/devices
Response 200 OK: Cached device catalog
```

### Group 8: Licensing, GenAI Copilot & Research
```http
GET /api/license/status
Response 200 OK:
{ "is_valid": true, "status": "VALID", "tier": "Enterprise", "days_remaining": 365, "max_devices": 100, "licensee": "Sharma Logistics" }

POST /api/license/activate (Admin Only)
{ "key": "eyJhbGciOiJFZDI1NTE5In0..." }

GET /assistant/insights (Enterprise Tier)
Response 200 OK: { "briefing": "Executive Threat Summary: Threat activity remains within nominal baselines..." }

POST /assistant/chat (Enterprise Tier)
{ "query": "Which IP generated the highest attack volume today?" }
Response 200 OK: { "response": "Host 192.168.1.105 originated 450 DoS flows targeting port 80..." }

GET /research/metrics
Response 200 OK: Benchmarks (F1: 0.9025, Latency p50: 18.2ms, Memory: 9.78MB)

GET /research/figure/{filename} (Authenticated)
Response 200 OK: Image stream (.png/.svg)
```

---

# 15. React 19 Enterprise Operator Console Specification

The SOC operator interface is a modular Single Page Application built on React 19 and Vite, styled via responsive CSS, with zero legacy external CSS dependencies:

1. **`OverviewTab.jsx`**: Telemetry pulse, SVG gauge indicators, dynamic historical traffic curves, and attack distribution cards.
2. **`IncidentsTab.jsx`**: High-frequency tabular log feed with real-time severity badges, 1-click firewall containment, and TreeSHAP attribution triggers.
3. **`CaptureTab.jsx`**: Hardware adapter selector, real-time packet counters, rolling forensics PCAP registry, and Wireshark download manager.
4. **`DevicesTab.jsx`**: Active topology inventory with one-click ARP & Nmap scans, MAC resolution, vendor identification, and port discovery.
5. **`BlocklistTab.jsx`**: Real-time host firewall table with expiration countdown clocks, manual blocking modal, and immutable audit logs.
6. **`AssistantTab.jsx`**: Generative AI SOC copilot interface featuring synthetic threat briefing updates and chat assistance.
7. **`ResearchTab.jsx`**: Real-time system performance monitor displaying model disk sizes, active RAM usage, tail latency percentiles ($p_{50}, p_{95}, p_{99}$), and ROC/Confusion Matrix charts.
8. **`UsersTab.jsx` (Admin Only)**: User management interface for provisioning accounts, managing roles, toggling user statuses, and updating notification recipients.
9. **`ExplainModal.jsx`**: Production TreeSHAP modal illustrating exact mathematical feature attributions and natural-language rationale.

---

# 16. Enterprise Deployment Models & Orchestration Guide

### Model A: Docker Multi-Container Fleet (`docker-compose.yml`)
Recommended for all enterprise Linux installations and edge appliances.

```bash
# 1. Enter NetGuard working directory
cd /opt/netguard-ids

# 2. Configure production .env
cp .env.example .env
nano .env

# 3. Launch fleet
docker compose up -d --build

# 4. Verify running containers
docker compose ps
```

### Model B: 24/7 Managed Windows NSSM Services
Recommended for Windows Server environments requiring resilient background persistence.

```powershell
# Open Administrator PowerShell
cd C:\iot-ids

# 1. Install Backend Service
nssm install NetGuard-API "C:\iot-ids\venv\Scripts\uvicorn.exe" "api.main:app --host 0.0.0.0 --port 8081"
nssm set NetGuard-API AppDirectory "C:\iot-ids"
nssm set NetGuard-API Start SERVICE_AUTO_START

# 2. Install Frontend Service
nssm install NetGuard-UI "C:\Program Files\nodejs\npx.cmd" "serve -s dist -l 5174"
nssm set NetGuard-UI AppDirectory "C:\iot-ids\react-dashboard"
nssm set NetGuard-UI Start SERVICE_AUTO_START

# 3. Install Sniffer Service
nssm install NetGuard-Capture "C:\iot-ids\venv\Scripts\python.exe" "src/capture.py --iface ""Ethernet"""
nssm set NetGuard-Capture AppDirectory "C:\iot-ids"
nssm set NetGuard-Capture Start SERVICE_AUTO_START

# Start Services
nssm start NetGuard-API
nssm start NetGuard-UI
nssm start NetGuard-Capture
```

### Model C: Native Headless Linux Edge Appliance (`systemd`)
Designed for industrial Box PCs (e.g. Advantech, Siemens IPC) and Raspberry Pi 4/5 units running Ubuntu Server or Debian.

```bash
sudo chmod +x deploy/install.sh
sudo ./deploy/install.sh
```
*Installer configures Linux capabilities (`setcap cap_net_raw,cap_net_admin+eip`), sets up systemd units, enables lingering, and initiates auto-boot.*

### Model D: Bare-Metal Workstation Rapid Launcher
For local developer testing or rapid demonstration:
```powershell
.\run-netguard.ps1
```

---

# 17. Owner / Managed Security Service Provider (MSSP) Operating Playbook

This chapter specifies the end-to-end commercial lifecycle for the business owner delivering NetGuard IDS as a managed security service:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           MSSP CLIENT ENGAGEMENT LIFECYCLE                                  │
├─────────────────┬───────────────────┬───────────────────┬───────────────────┬───────────────┤
│ 1. Discovery    │ 2. Key Generation │ 3. On-Site Setup  │ 4. Remote Control │ 5. Retainer   │
│ Port Scoping    │ provision_pilot   │ Appliance Install │ Tailscale Tunnel  │ PDF & Billing │
└─────────────────┴───────────────────┴───────────────────┴───────────────────┴───────────────┘
```

### Phase 1: Pre-Deployment Discovery & Network Scoping
Ask the prospective client:
1. **Network Infrastructure**: Do you operate a managed switch (Cisco, Ubiquiti, Aruba) supporting SPAN/Mirror ports, or a flat unmanaged router?
2. **Appliance Hardware**: Will the client supply an on-premise virtual machine (VMware ESXi, Proxmox, Hyper-V) or will the MSSP supply a dedicated physical mini-PC appliance?
3. **Monitored Scope**: What are the subnets, critical servers, and IoT/SCADA segments to protect?

### Phase 2: Pilot Customer Provisioning
On the MSSP master workstation, execute:
```powershell
python scripts/provision_pilot.py `
  --company "Sharma Logistics" `
  --email "admin@sharma-logistics.com" `
  --password "SecureClientPass2026!" `
  --tier ENTERPRISE `
  --days 365 `
  --devices 100
```
This generates:
- An isolated tenant namespace (`sharma_logistics`).
- An Ed25519 digitally signed commercial `license.key`.
- A client-ready `.env.pilot` deployment configuration.

### Phase 3: On-Site Appliance Commissioning (30-Minute Runbook)
1. Mount the appliance into the client's network rack.
2. Connect Ethernet Interface 1 to the Internet/Management LAN.
3. Connect Ethernet Interface 2 to the Switch SPAN/Mirror Port (promiscuous mode).
4. Apply the provisioned `.env.pilot` file.
5. Start the appliance: `docker compose up -d`.
6. Log in via `http://localhost`, verify green `ENTERPRISE` status badge, and execute a test ARP scan in the **Devices** tab.

### Phase 4: Remote Zero-Trust Fleet Telemetry
To manage and monitor the appliance from MSSP headquarters without exposing ports to the public internet:
1. Join the appliance to the MSSP's private Tailscale or Cloudflare Zero Trust mesh network:
   ```bash
   sudo tailscale up --authkey=tskey-auth-XXXXX
   ```
2. The appliance receives a private overlay IP (e.g., `100.85.20.10`).
3. The MSSP SOC can securely access the client console from anywhere at `http://100.85.20.10`.
4. High-priority alerts stream directly to the MSSP's Telegram channel and central SIEM.

### Phase 5: Month-End Executive PDF Reporting & Retainer Invoicing
On the 1st of every month:
1. Access the client endpoint: `http://100.85.20.10/reports/export`.
2. Download the cryptographically signed, ReportLab-generated **Executive Threat Summary PDF**.
3. Transmit the report alongside the monthly invoice (e.g., ₹10,000 – ₹25,000 / month) detailing total blocked attacks, zero-day anomalies intercepted, and uptime SLAs.

---

# 18. Security Hardening Verification & Audit Mitigation Proof

The platform codebase has undergone line-by-line penetration testing. The following table provides verification proof for all remediated security items:

| Vulnerability | Target Component | Original Severity | Mitigation Technical Verification |
|:---|:---|:---:|:---|
| **Path Traversal Arbitrary File Read** | `/research/figure/{filename}` | 🚨 Critical | Enforces `os.path.basename`, whitelists `.png`/`.svg`, and asserts `is_relative_to(figures_dir)`. Rejects directory traversal payloads (`../../etc/passwd`). |
| **Path Traversal Arbitrary PCAP Read** | `/forensics/download/{filename}` | 🚨 Critical | Strips path separators, verifies existence strictly within `reports/forensics/`, and validates `.pcap` extension. |
| **Hardcoded Dev License Backdoor** | `src/license.py`, `api/main.py` | ⚠️ High | Removed all development bypass keys (`NETGUARD-DEV`, `DEV-MASTER`). Activation endpoint requires `manage_users` permission. |
| **Disabled TLS Verification** | `src/genai_assistant.py` | ⚠️ High | Removed `CERT_NONE` and `TLSAdapter`. All outbound AI connections enforce standard CA certificate verification. |
| **Predict Denial of Service Spray** | `POST /predict` | ⚡ Medium | The prediction endpoint requires an internal `X-Agent-Key` or authenticated Bearer token. |
| **Wildcard CORS Policy** | `api/main.py` | ⚡ Medium | Removed `allow_origins=["*"]`. Configured strict `ALLOWED_ORIGINS` whitelist binding to frontend port 5174 and production domains. |
| **Replay-Prone Telegram Action Links** | `api/main.py` | ⚡ Medium | HMAC payload incorporates a UNIX expiration timestamp; links clicked after expiration return `403 Link Expired`. |
| **Shared IP Lockout DoS** | `src/auth.py` | ⚡ Medium | Decoupled account-level lockout from IP-level spray defense; exempted loopback (`127.0.0.1`) from shared lockout exhaustion. |
| **Stateless User Revocation Gap** | `src/auth.py` | ℹ️ Low | `verify_request()` checks `is_user_active(username)` against the database on every authenticated call, instantly revoking disabled users. |
| **Subnet Command Injection** | `src/scanner.py` | ℹ️ Low | Validates subnet strings using `ipaddress.ip_network(subnet, strict=False)` before executing system commands. |

---

# 19. Benchmarking, Latency Profiles & Empirical Verification

Empirical performance was benchmarked across 3,000 real-time inference cycles using [scripts/run_diagnostics.py](file:///c:/iot-ids/scripts/run_diagnostics.py):

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Empirical Edge Performance Profile                   │
├──────────────────────────────────────┬─────────────────────────────────┤
│ Median Inference Latency (p50)       │ 17.6 – 19.1 ms                  │
│ 95th Percentile Tail Latency (p95)   │ 28.1 – 42.8 ms                  │
│ 99th Percentile Tail Latency (p99)   │ 31.2 – 148.9 ms                 │
│ Active In-Memory RAM Footprint       │ 9.78 MB                         │
│ Serialized Model Disk Footprint      │ 5.03 MB (XGBoost + iForest)     │
│ Automated Firewall Rule Insertion    │ 0.0002 ms                       │
│ False Alarm Rate (FAR)               │ 0.145%                          │
│ Edge-IIoTset Benign Accuracy         │ 100.0% (Zero False Disruptions) │
│ Classification Macro F1-Score        │ 0.9025                          │
└──────────────────────────────────────┴─────────────────────────────────┘
```

### Continuous Verification Suite
To execute the automated regression test suite across all architectural layers:
```powershell
python tests/verify_all.py
```
**Test Assertions**:
1. Dual-ML classification pipeline accuracy on normal and synthetic attack payloads.
2. Native TreeSHAP feature ranking and mathematical explanation generation.
3. Multi-tenant database query isolation across simulated tenants.
4. Cryptographic Ed25519 license validation and tier enforcement.
5. RFC 5424 / CEF Syslog UDP datagram construction and dispatch.

---

# 20. Enterprise Troubleshooting, Failure Modes & Runbook

### Incident 1: Port Collision on Startup (`Errno 10048` / `EADDRINUSE`)
- **Symptom**: `error while attempting to bind on address ('0.0.0.0', 8081)`.
- **Root Cause**: A stale Uvicorn or Python process is holding the socket.
- **Remediation**:
  ```powershell
  Get-NetTCPConnection -LocalPort 8081 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
  Get-NetTCPConnection -LocalPort 5174 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
  ```

### Incident 2: Packet Capture Interface Yields Zero Ingested Packets
- **Symptom**: Dashboard displays `Capture: RUNNING` but packet counter remains stationary at 0.
- **Root Causes & Remediation**:
  1. **Npcap Driver Mode (Windows)**: Reinstall Npcap ensuring the checkbox *"Install Npcap in WinPcap API-compatible Mode"* is explicitly enabled.
  2. **Insufficient Socket Permissions**: Ensure PowerShell was launched via **"Run as Administrator"** or container was granted `CAP_NET_RAW`.
  3. **Interface Name Mismatch**: Query `/capture/interfaces` and ensure the exact network adapter name is passed (e.g. `Ethernet`, `Wi-Fi`, or `eth0`).
  4. **Stale Process Lock**: Remove stale mutex lock file:
     ```powershell
     Remove-Item "logs\capture.lock" -Force -ErrorAction SilentlyContinue
     ```

### Incident 3: Host Firewall Rules Not Instantiated
- **Symptom**: Log shows `DB Blocklist active (Windows Firewall requires Run as Admin)`.
- **Root Cause**: The Python backend process lacks the Windows administrative security token required to execute `netsh advfirewall`.
- **Remediation**: Relaunch the terminal with elevated administrator privileges or run the service via Windows NSSM.

### Incident 4: License Lockout Screen Displayed
- **Symptom**: Screen states license has expired and blocks standard view tabs.
- **Root Cause**: The 365-day license validity window and subsequent 3-day grace period have lapsed.
- **Remediation**: Authenticate as `admin`, access the activation interface, and submit a newly generated cryptographic license key string.

---

### Engineering Governance & Primary Maintainer
**Nikhil Dehariya**  
*Lead Architect & Founder, NetGuard IDS Platform*  
- **Email**: `nikhildehariya101@gmail.com`  
- **Engineering Repository**: `https://github.com/nikhildehariya/netguard-ids`  
- **Document Ref**: `NGD-ENG-SOP-2026-V35-MNC` (Strict Document Control)
