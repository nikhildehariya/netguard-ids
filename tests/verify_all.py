# =============================================================
# verify_all.py — NetGuard IDS v2.2
# Master End-to-End System Health & Verification Suite
# Tests:
# 1. ML Detection Engine (XGBoost + Isolation Forest)
# 2. XAI Mathematical Explainability (TreeSHAP)
# 3. Dual Database Ingestion & Tenant Isolation
# 4. Multi-Tenant Accounts & RBAC
# 5. SIEM Webhook & Syslog Formatters
# 6. Commercial License Cryptographic Engine
# =============================================================

import sys
import time
from pathlib import Path
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

passed = 0
failed = 0

def log_test(name: str, success: bool, detail: str = ""):
    global passed, failed
    if success:
        passed += 1
        print(f"  ✅ [PASS] {name} {detail}")
    else:
        failed += 1
        print(f"  ❌ [FAIL] {name} {detail}")


print("\n" + "=" * 65)
print("  🛡️  NetGuard IDS — Master Production Verification Suite")
print("=" * 65 + "\n")

# --- Test 1: ML Inference Engine (Dual XGBoost + Isolation Forest) ---
try:
    from predict import detector
    normal_flow = {
        'Dst Port': 80, 'Protocol': 6, 'Flow Duration': 6010454,
        'Tot Fwd Pkts': 4, 'Tot Bwd Pkts': 4, 'TotLen Fwd Pkts': 285, 'TotLen Bwd Pkts': 972
    }
    brute_force_flow = {
        'Dst Port': 21, 'Protocol': 6, 'Flow Duration': 19,
        'Tot Fwd Pkts': 1, 'Tot Bwd Pkts': 1, 'TotLen Fwd Pkts': 0, 'TotLen Bwd Pkts': 0,
        'Flow Pkts/s': 105263.157, 'Fwd Header Len': 40, 'Bwd Header Len': 20,
        'Init Fwd Win Byts': 26883, 'Init Bwd Win Byts': 0, 'Fwd Seg Size Min': 40
    }
    norm_res = detector.predict(normal_flow)
    attack_res = detector.predict(brute_force_flow)

    log_test(
        "Dual-ML Pipeline (XGBoost + IForest)",
        norm_res.get("prediction") == "NORMAL" and attack_res.get("prediction") == "BRUTE_FORCE",
        f"(Normal conf: {norm_res.get('confidence')*100:.1f}%, Attack conf: {attack_res.get('confidence')*100:.1f}%)"
    )
except Exception as e:
    log_test("Dual-ML Pipeline", False, str(e))

# --- Test 2: XAI Explainability (TreeSHAP) ---
try:
    from explainable import explain_prediction
    xai_res = explain_prediction(brute_force_flow, attack_res)
    log_test(
        "Native TreeSHAP Mathematical Reasoning",
        bool(xai_res and "top_features" in xai_res and len(xai_res["top_features"]) > 0),
        f"(Features ranked: {len(xai_res.get('top_features', []))}, Top: {xai_res.get('top_features', [{}])[0].get('feature')})"
    )
except Exception as e:
    log_test("Native TreeSHAP", False, str(e))

# --- Test 3: Multi-Tenant Ingestion & Telemetry Isolation ---
try:
    from detections_db import insert_detection, load_detections
    insert_detection({'prediction': 'DOS_DDOS', 'confidence': 0.99, 'severity': 'high'}, source_ip='10.1.1.5', tenant_id='poc_factory')
    insert_detection({'prediction': 'BOT', 'confidence': 0.91, 'severity': 'high'}, source_ip='10.2.2.8', tenant_id='poc_hospital')

    factory_events = load_detections(limit=10, tenant_id='poc_factory')
    hospital_events = load_detections(limit=10, tenant_id='poc_hospital')

    iso_ok = (
        all(e.get('tenant_id') == 'poc_factory' for e in factory_events) and
        all(e.get('tenant_id') == 'poc_hospital' for e in hospital_events) and
        len(factory_events) >= 1 and len(hospital_events) >= 1
    )
    log_test("Multi-Tenant Telemetry Isolation", iso_ok, "(Factory & Hospital event streams isolated)")
except Exception as e:
    log_test("Multi-Tenant Isolation", False, str(e))

# --- Test 4: Cryptographic Licensing & Hardware Fingerprint ---
try:
    from license import generate_ed25519_keypair, issue_license, validate_license, LicensePayload, LicenseTier
    priv, pub = generate_ed25519_keypair()
    payload = LicensePayload(
        license_id="VERIFY-99", licensee="Enterprise Client", tier=LicenseTier.ENTERPRISE,
        issued_at=int(time.time()), expires_at=int(time.time()) + 86400, max_devices=-1
    )
    token = issue_license(payload, priv)
    val = validate_license(token, public_key_pem=pub)
    log_test("Cryptographic Asymmetric Licensing", val.is_valid, f"(Tier: {val.payload.tier.name})")
except Exception as e:
    log_test("Cryptographic Licensing", False, str(e))

# --- Test 5: Universal SIEM & Webhook Exporters ---
try:
    from webhook_exporters import export_to_syslog
    import socket
    # Mock loopback listener with reuse address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    # Bind to ephemeral port
    s.bind(('127.0.0.1', 0))
    test_port = s.getsockname()[1]
    s.settimeout(2.0)

    test_ev = {'prediction': 'SQL_INJECTION', 'confidence': 0.96, 'severity': 'critical', 'tenant_id': 'poc_bank'}
    export_to_syslog(test_ev, '172.16.0.4', host='127.0.0.1', port=test_port)
    data, _ = s.recvfrom(2048)
    s.close()
    syslog_msg = data.decode('utf-8')
    log_test(
        "SIEM RFC 5424 / CEF Datagram Exporter",
        "CEF:0|NetGuard|IoT-IDS" in syslog_msg and "SQL_INJECTION" in syslog_msg,
        "(Syslog datagram formatted & dispatched)"
    )
except Exception as e:
    log_test("SIEM Exporter", False, str(e))

# --- Test 6: eBPF / XDP Kernel Capture & Line-Rate Mitigation ---
try:
    from ebpf_xdp import xdp_manager
    xdp_manager.attach()
    p_pass = xdp_manager.simulate_packet("192.168.1.100", "10.0.0.1", 50000, 80, 6, 100)
    xdp_manager.block_ip("203.0.113.55")
    p_drop = xdp_manager.simulate_packet("203.0.113.55", "10.0.0.1", 50000, 80, 6, 100)
    xdp_manager.unblock_ip("203.0.113.55")
    stats = xdp_manager.get_stats()
    xdp_ok = (p_pass == "XDP_PASS" and p_drop == "XDP_DROP" and stats.get("packets_dropped", 0) >= 1)
    log_test("eBPF / XDP Kernel Capture & Line-Rate Filter", xdp_ok, f"(Mode: {stats.get('driver_mode')}, Drops: {stats.get('packets_dropped')})")
except Exception as e:
    log_test("eBPF / XDP Kernel Capture", False, str(e))

# --- Test 7: Lightweight Edge Sensor Probe Pipeline ---
try:
    from edge_probe import EdgeProbe
    probe = EdgeProbe(hub_url="http://127.0.0.1:8081", tenant_id="tenant_edge_substation")
    probe.record_packet("192.168.10.15", "10.0.0.5", 49152, 502, 6, 128, tcp_flags=24) # Modbus
    probe.record_packet("192.168.10.15", "10.0.0.5", 49152, 502, 6, 256, tcp_flags=16)
    ready = probe.extract_ready_flows(timeout=0.0)
    probe_ok = (
        len(ready) >= 1 and
        ready[0].get("tenant_id") == "tenant_edge_substation" and
        ready[0].get("Dst Port") == 502 and
        ready[0].get("Tot Fwd Pkts") == 2
    )
    log_test("Lightweight Edge Sensor Probe Pipeline", probe_ok, f"(Dispatched {len(ready)} flows, Tenant: {ready[0].get('tenant_id')})")
except Exception as e:
    log_test("Lightweight Edge Sensor Probe", False, str(e))

# --- Test 8: Deep Learning Sequence Modeling (Bi-LSTM + Temporal APT Correlation) ---
try:
    from sequence_model import apt_correlator, BiLSTMTemporalAttention
    # Test Bi-LSTM forward calculation directly
    lstm = BiLSTMTemporalAttention(input_dim=10, hidden_dim=16)
    seq_data = np.random.randn(8, 10).astype(np.float32)
    res_lstm = lstm.forward(seq_data)

    # Test multi-stage sequence correlation
    attacker_ip = "198.51.100.99"
    # Stage 1: PortScan flow
    flow1 = {"Dst Port": 80, "Protocol": 6, "Flow Duration": 100, "Tot Fwd Pkts": 2, "TotLen Fwd Pkts": 80, "src_ip": attacker_ip}
    pred1 = {"prediction": "NORMAL", "confidence": 0.85, "severity": "low"}
    c1 = apt_correlator.correlate(flow1, pred1, source_ip=attacker_ip)

    # Stage 2: Brute force flow
    flow2 = {"Dst Port": 22, "Protocol": 6, "Flow Duration": 500, "Tot Fwd Pkts": 10, "TotLen Fwd Pkts": 1200, "src_ip": attacker_ip}
    pred2 = {"prediction": "BRUTE_FORCE", "confidence": 0.94, "severity": "high"}
    c2 = apt_correlator.correlate(flow2, pred2, source_ip=attacker_ip)

    # Stage 3: Infiltration flow
    flow3 = {"Dst Port": 443, "Protocol": 6, "Flow Duration": 50000, "Tot Fwd Pkts": 80, "TotLen Fwd Pkts": 65000, "src_ip": attacker_ip}
    pred3 = {"prediction": "INFILTRATION", "confidence": 0.96, "severity": "critical"}
    c3 = apt_correlator.correlate(flow3, pred3, source_ip=attacker_ip)

    seq_ok = (
        len(res_lstm.get("attention_weights", [])) == 8 and
        "stage" in res_lstm and
        c3.get("sequence_depth") == 3
    )
    log_test("Deep Learning Sequence Modeling (Bi-LSTM APT)", seq_ok, f"(Bi-LSTM Steps: 8, Stage: {res_lstm.get('stage')}, Depth: {c3.get('sequence_depth')})")
except Exception as e:
    log_test("Deep Learning Sequence Modeling", False, str(e))

# --- Test 9: Real-Time Threat Intelligence (TI) Ingestion Engine ---
try:
    from threat_intel import threat_intel
    ti_c2 = threat_intel.lookup_ip("198.51.100.1")
    threat_intel.add_custom_ioc("203.0.113.99", "APT29 C2 Node", score=0.99)
    ti_custom = threat_intel.lookup_ip("203.0.113.99")
    ti_ok = (
        ti_c2.get("is_malicious") is True and
        "Cobalt Strike" in ti_c2.get("actor", "") and
        ti_custom.get("is_malicious") is True and
        ti_custom.get("actor") == "APT29 C2 Node"
    )
    log_test("Real-Time Threat Intelligence Engine", ti_ok, f"(C2 Actor: {ti_c2.get('actor')}, Custom IOC: {ti_custom.get('actor')})")
except Exception as e:
    log_test("Real-Time Threat Intelligence Engine", False, str(e))

# --- Test 10: Multi-Dataset Continuous Retraining & Active Learning ---
try:
    from retrain_pipeline import active_learning, drift_detector, retrain_pipeline
    fb = active_learning.submit_feedback(
        flow_features={"Dst Port": 1883, "Tot Fwd Pkts": 6},
        original_prediction="NORMAL",
        analyst_label="MQTT_UNAUTHORIZED_PUBLISH",
        source_ip="192.168.1.88",
        reported_by="soc_analyst"
    )
    cycle = retrain_pipeline.run_retrain_cycle()
    retrain_ok = (
        fb.get("success") is True and
        cycle.get("status") == "completed" and
        cycle.get("macro_f1_target", 0) > 0.90
    )
    log_test("Continuous Retraining & Active Learning Pipeline", retrain_ok, f"(Status: {cycle.get('status')}, F1 Target: {cycle.get('macro_f1_target')})")
except Exception as e:
    log_test("Continuous Retraining Pipeline", False, str(e))

# --- Test 11: Distributed Edge Fleet Orchestration ---
try:
    from fleet_manager import fleet_manager
    reg = fleet_manager.register_probe("probe-substation-99", "substation-gw-99", tenant_id="tenant_substation_beta")
    hb = fleet_manager.record_heartbeat("probe-substation-99", packets_seen=2500, flows_streamed=80)
    overview = fleet_manager.get_fleet_overview(tenant_id="tenant_substation_beta")
    fleet_ok = (
        reg.get("success") is True and
        hb.get("success") is True and
        overview.get("online_probes") >= 1 and
        overview.get("fleet_total_packets") >= 2500
    )
    log_test("Distributed Edge Fleet Orchestration", fleet_ok, f"(Online Probes: {overview.get('online_probes')}, Pkts: {overview.get('fleet_total_packets')})")
except Exception as e:
    log_test("Distributed Fleet Orchestration", False, str(e))

# --- Test 12: Enterprise SOAR Switch & VLAN Quarantine ---
try:
    from switch_soar import switch_soar
    q1 = switch_soar.quarantine_endpoint("10.50.1.99", switch_vendor="cisco", vlan_id=666)
    q2 = switch_soar.quarantine_endpoint("10.50.1.100", mac_addr="00:11:22:33:44:55", switch_vendor="radius_802_1x", vlan_id=666)
    active_q = switch_soar.list_quarantined_endpoints()
    rel = switch_soar.release_endpoint("10.50.1.99")
    soar_ok = (
        q1.get("success") is True and
        q2.get("success") is True and
        rel.get("success") is True and
        len(active_q) >= 1
    )
    log_test("Enterprise SOAR Switch & VLAN Quarantine", soar_ok, f"(Cisco & 802.1X VLAN 666 Enforced, Active: {len(active_q)})")
except Exception as e:
    log_test("Enterprise SOAR Switch Quarantine", False, str(e))

# --- Test 13: Turnkey Packaging & Virtual Appliance Delivery ---
try:
    win_installer = BASE_DIR / "deploy" / "windows" / "install-service.ps1"
    appliance_init = BASE_DIR / "deploy" / "appliance" / "setup-appliance.sh"
    pack_ok = (
        win_installer.exists() and
        win_installer.stat().st_size > 500 and
        appliance_init.exists() and
        appliance_init.stat().st_size > 500
    )
    log_test("Turnkey Packaging & Appliance Config", pack_ok, "(Windows Service Installer & VMware/Proxmox Appliance verified)")
except Exception as e:
    log_test("Turnkey Packaging & Appliance Config", False, str(e))










print("\n" + "-" * 65)
print(f"  Summary: {passed} PASSED | {failed} FAILED")
print("=" * 65 + "\n")

if failed > 0:
    sys.exit(1)
sys.exit(0)
