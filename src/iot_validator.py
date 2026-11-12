# ==============================================================================
# src/iot_validator.py — NetGuard IDS Real IoT Testbed Validation Engine
# Ingests & validates real Edge-IIoTset (MQTT, Modbus, CoAP) network streams
# ==============================================================================

import sys
from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))

import numpy as np
import pandas as pd
from config import DATA_DIR, LABEL_NAMES, FEATURE_COLS
from predict import detector

EDGE_IIOT_DATASET = DATA_DIR / "ML-EdgeIIoT-dataset.csv"

EDGE_LABEL_MAP = {
    "Normal":                "NORMAL",
    "DDoS_HTTP":             "DOS_DDOS",
    "DDoS_TCP":              "DOS_DDOS",
    "DDoS_UDP":              "DOS_DDOS",
    "DDoS_ICMP":             "DOS_DDOS",
    "Password":              "BRUTE_FORCE",
    "SQL_injection":         "WEB_ATTACK",
    "XSS":                   "WEB_ATTACK",
    "Backdoor":              "INFILTRATION",
    "Port_Scanning":         "INFILTRATION",
    "Vulnerability_scanner": "INFILTRATION",
    "Ransomware":            "INFILTRATION",
    "Fingerprinting":        "INFILTRATION",
    "MITM":                  "INFILTRATION",
    "Uploading":             "WEB_ATTACK",
}


def load_iot_dataset_sample(n_samples: int = 500) -> pd.DataFrame:
    """Load stratified sample of real IoT/IIoT flows across all classes from local dataset."""
    if not EDGE_IIOT_DATASET.exists():
        raise FileNotFoundError(f"IoT Dataset not found at {EDGE_IIOT_DATASET}")
    
    # Read balanced sample from the entire CSV
    df = pd.read_csv(EDGE_IIOT_DATASET, low_memory=False)
    df['Attack_type'] = df['Attack_type'].astype(str).str.strip()
    df['target_category'] = df['Attack_type'].map(EDGE_LABEL_MAP).fillna("INFILTRATION")
    
    n_per_class = max(10, n_samples // df['target_category'].nunique())
    sampled_dfs = []
    for cat, group in df.groupby('target_category'):
        sampled_dfs.append(group.sample(min(len(group), n_per_class), random_state=42))
    
    return pd.concat(sampled_dfs, ignore_index=True)


def validate_iot_stream(n_samples: int = 500) -> dict:
    """
    Run NetGuard Dual-Engine on real Edge-IIoTset flows.
    Returns real empirical accuracy, detection rate, and category breakdowns.
    """
    detector.load()
    df = load_iot_dataset_sample(n_samples=n_samples)
    y_true = df['target_category'].tolist()

    flows_df = pd.DataFrame(index=df.index)
    dst_port = pd.to_numeric(df['tcp.dstport'], errors='coerce').fillna(0)
    udp_port = pd.to_numeric(df['udp.port'], errors='coerce').fillna(0)
    flows_df['Dst Port'] = np.where(dst_port > 0, dst_port, np.where(udp_port > 0, udp_port, 80.0))
    flows_df['Protocol'] = np.where(udp_port > 0, 17.0, 6.0)
    
    time_delta = pd.to_numeric(df['udp.time_delta'], errors='coerce').fillna(0.01)
    flows_df['Flow Duration'] = np.maximum(time_delta * 1e6, 1000.0)
    
    tcp_seq = pd.to_numeric(df['tcp.seq'], errors='coerce').fillna(1.0)
    flows_df['Tot Fwd Pkts'] = (tcp_seq % 500).clip(lower=1.0)
    
    tcp_ack = pd.to_numeric(df['tcp.ack'], errors='coerce').fillna(1.0)
    flows_df['Tot Bwd Pkts'] = (tcp_ack % 500).clip(lower=1.0)
    
    pkt_len = pd.to_numeric(df['tcp.len'], errors='coerce').fillna(64.0)
    flows_df['TotLen Fwd Pkts'] = pkt_len * flows_df['Tot Fwd Pkts']
    flows_df['TotLen Bwd Pkts'] = pkt_len * flows_df['Tot Bwd Pkts']
    flows_df['Fwd Pkt Len Max'] = pkt_len
    flows_df['Flow Byts/s'] = pkt_len * 100.0
    flows_df['Flow Pkts/s'] = 50.0
    flows_df['SYN Flag Cnt'] = pd.to_numeric(df['tcp.connection.syn'], errors='coerce').fillna(0.0)
    flows_df['RST Flag Cnt'] = pd.to_numeric(df['tcp.connection.rst'], errors='coerce').fillna(0.0)
    flows_df['ACK Flag Cnt'] = pd.to_numeric(df['tcp.flags.ack'], errors='coerce').fillna(1.0)
    flows_df['Fwd Header Len'] = 32.0
    flows_df['Bwd Header Len'] = 32.0
    flows_df['Init Fwd Win Byts'] = 64240.0
    flows_df['Init Bwd Win Byts'] = 64240.0

    for col in FEATURE_COLS:
        if col not in flows_df.columns:
            flows_df[col] = 0.0
    flows_df = flows_df[FEATURE_COLS]

    X_scaled = detector.scaler.transform(flows_df)
    xgb_preds_raw = detector.model.predict(X_scaled)
    y_pred = [LABEL_NAMES[p] for p in xgb_preds_raw]

    if detector.iforest is not None:
        iforest_preds = detector.iforest.predict(X_scaled)
        dec_scores = detector.iforest.decision_function(X_scaled)
        anomaly_scores = [float(np.clip(0.5 - s, 0.0, 1.0)) for s in dec_scores]
    else:
        iforest_preds = np.ones(len(X_scaled))
        anomaly_scores = [0.0] * len(X_scaled)

    y_cascade = []
    for i in range(len(y_pred)):
        if y_pred[i] == "NORMAL" and (iforest_preds[i] == -1 or anomaly_scores[i] > 0.55):
            y_cascade.append("ZERO_DAY_ANOMALY")
        else:
            y_cascade.append(y_pred[i])

    normal_idx = [i for i, t in enumerate(y_true) if t == "NORMAL"]
    attack_idx = [i for i, t in enumerate(y_true) if t != "NORMAL"]

    benign_preserved = sum(1 for i in normal_idx if y_cascade[i] == "NORMAL")
    threats_detected = sum(1 for i in attack_idx if y_cascade[i] != "NORMAL")

    return {
        "status": "success",
        "dataset": "Edge-IIoTset (IEEE Dataport Real Testbed)",
        "total_flows": len(df),
        "benign_flows": len(normal_idx),
        "attack_flows": len(attack_idx),
        "benign_accuracy": round((benign_preserved / max(1, len(normal_idx))) * 100, 2),
        "attack_detection_rate": round((threats_detected / max(1, len(attack_idx))) * 100, 2),
        "threat_class_distribution": pd.Series(y_cascade).value_counts().to_dict(),
        "mean_anomaly_score": round(float(np.mean(anomaly_scores)), 4)
    }


if __name__ == "__main__":
    print("[iot_validator] Running validation test on real Edge-IIoTset...")
    res = validate_iot_stream(n_samples=200)
    print(res)
