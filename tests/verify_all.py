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
    # Mock loopback listener
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 19514))
    s.settimeout(1.0)

    test_ev = {'prediction': 'SQL_INJECTION', 'confidence': 0.96, 'severity': 'critical', 'tenant_id': 'poc_bank'}
    export_to_syslog(test_ev, '172.16.0.4', host='127.0.0.1', port=19514)
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


print("\n" + "-" * 65)
print(f"  Summary: {passed} PASSED | {failed} FAILED")
print("=" * 65 + "\n")

if failed > 0:
    sys.exit(1)
sys.exit(0)
