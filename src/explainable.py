# =============================================================
# explainable.py — NetGuard IDS v2.1
# Explainable AI (XAI) / "Why Detected" Feature Attribution Engine
# =============================================================

import numpy as np
from typing import Optional

# Feature descriptions and standard baseline statistics for CIC-IDS-2018
FEATURE_DESCRIPTIONS = {
    "Dst Port":          "Destination network port targeted by the flow",
    "Protocol":          "IP Protocol number (6=TCP, 17=UDP, 1=ICMP)",
    "Flow Duration":     "Total duration of the network flow (microseconds)",
    "Tot Fwd Pkts":      "Total packets sent in forward direction (client to server)",
    "Tot Bwd Pkts":      "Total packets sent in backward direction (server to client)",
    "TotLen Fwd Pkts":   "Total bytes sent in forward direction",
    "TotLen Bwd Pkts":   "Total bytes sent in backward direction",
    "Fwd Pkt Len Max":   "Maximum packet length in forward direction",
    "Fwd Pkt Len Mean":  "Average packet length in forward direction",
    "Bwd Pkt Len Max":   "Maximum packet length in backward direction",
    "Bwd Pkt Len Mean":  "Average packet length in backward direction",
    "Flow Byts/s":       "Flow transmission rate (bytes per second)",
    "Flow Pkts/s":       "Flow packet rate (packets per second)",
    "Flow IAT Mean":     "Average Inter-Arrival Time between packets",
    "Flow IAT Max":      "Maximum Inter-Arrival Time between packets",
    "SYN Flag Cnt":      "Count of TCP SYN (Synchronize) connection flags",
    "RST Flag Cnt":      "Count of TCP RST (Reset) flags",
    "PSH Flag Cnt":      "Count of TCP PSH (Push) flags",
    "ACK Flag Cnt":      "Count of TCP ACK (Acknowledge) flags",
    "Fwd Header Len":    "Total header bytes in forward packets",
    "Bwd Header Len":    "Total header bytes in backward packets",
}

# Normal baseline thresholds for detecting anomalous feature spikes
BASELINE_THRESHOLDS = {
    "Flow Byts/s":       500000.0,    # > 500 KB/s
    "Flow Pkts/s":       5000.0,      # > 5,000 pkts/s
    "Flow Duration":     10000000.0,  # > 10 seconds
    "Tot Fwd Pkts":      100.0,
    "Tot Bwd Pkts":      100.0,
    "SYN Flag Cnt":      5.0,
    "RST Flag Cnt":      3.0,
    "PSH Flag Cnt":      10.0,
    "Fwd Pkt Len Max":   1400.0,
    "Bwd Pkt Len Max":   1400.0,
}


def explain_prediction(traffic_record: dict, prediction_result: dict) -> dict:
    """
    Generate Explainable AI (XAI) feature attribution breakdown for a traffic record.
    Returns:
      - top_contributing_features: list of dicts with feature name, value, impact score, and description.
      - threat_summary: human-readable explanation of why the flow was flagged.
      - recommendations: action items for security analysts.
    """
    prediction = prediction_result.get("prediction", "NORMAL")
    confidence = prediction_result.get("confidence", 0.0)
    severity   = prediction_result.get("severity", "none")

    contributions = []
    reasons = []

    # 1. Analyze Destination Port & Protocol
    dst_port = float(traffic_record.get("Dst Port", 0))
    protocol = float(traffic_record.get("Protocol", 6))
    
    known_ports = {
        21: "FTP (File Transfer Protocol)",
        22: "SSH (Secure Shell)",
        23: "Telnet (Unencrypted Remote Shell)",
        80: "HTTP (Web Server)",
        443: "HTTPS (Secure Web Server)",
        445: "SMB (Windows File Sharing)",
        3389: "RDP (Remote Desktop Protocol)",
        8080: "HTTP Proxy / Alternative Web Server",
    }
    
    if dst_port in known_ports:
        port_desc = known_ports[dst_port]
    else:
        port_desc = f"Port {int(dst_port)}"

    if prediction in ["BRUTE_FORCE"]:
        if dst_port in [21, 22, 23, 3389]:
            contributions.append({
                "feature": "Dst Port",
                "value": int(dst_port),
                "contribution": 0.35,
                "label": f"Sensitive Service Port ({port_desc}) Targeted",
                "severity": "high"
            })
            reasons.append(f"Targeted authentication port {int(dst_port)} ({port_desc}) with high-frequency login patterns.")

    if prediction in ["DOS_DDOS"]:
        flow_bytes_s = float(traffic_record.get("Flow Byts/s", 0))
        flow_pkts_s = float(traffic_record.get("Flow Pkts/s", 0))
        flow_duration = float(traffic_record.get("Flow Duration", 0))

        if flow_bytes_s > BASELINE_THRESHOLDS["Flow Byts/s"] or flow_pkts_s > 1000:
            contributions.append({
                "feature": "Flow Byts/s",
                "value": f"{flow_bytes_s:,.0f} B/s",
                "contribution": 0.42,
                "label": "Extreme Traffic Bandwidth Spike",
                "severity": "critical"
            })
            reasons.append(f"Abnormally high data flow rate of {flow_bytes_s:,.0f} Bytes/sec overwhelming network bandwidth.")

        if flow_pkts_s > BASELINE_THRESHOLDS["Flow Pkts/s"]:
            contributions.append({
                "feature": "Flow Pkts/s",
                "value": f"{flow_pkts_s:,.0f} Pkts/s",
                "contribution": 0.38,
                "label": "High Packet Burst Rate",
                "severity": "critical"
            })
            reasons.append(f"Massive packet transmission frequency ({flow_pkts_s:,.0f} packets/sec) indicative of DoS flooding.")

        syn_flags = float(traffic_record.get("SYN Flag Cnt", 0))
        if syn_flags > BASELINE_THRESHOLDS["SYN Flag Cnt"]:
            contributions.append({
                "feature": "SYN Flag Cnt",
                "value": int(syn_flags),
                "contribution": 0.30,
                "label": "Anomalous SYN Flood Pattern",
                "severity": "high"
            })
            reasons.append(f"High volume of unacknowledged SYN connection flags ({int(syn_flags)}) detected.")

    if prediction in ["WEB_ATTACK"]:
        tot_fwd_len = float(traffic_record.get("TotLen Fwd Pkts", 0))
        fwd_len_max = float(traffic_record.get("Fwd Pkt Len Max", 0))
        if fwd_len_max > 500 or tot_fwd_len > 1000:
            contributions.append({
                "feature": "Fwd Pkt Len Max",
                "value": f"{fwd_len_max:.0f} bytes",
                "contribution": 0.40,
                "label": "Over-sized HTTP Payload Length",
                "severity": "high"
            })
            reasons.append(f"HTTP payload size ({fwd_len_max:.0f} bytes) contains unusually large header or body structures typical of SQLi/XSS injection attempts.")

    if prediction in ["INFILTRATION"]:
        tot_bwd_bytes = float(traffic_record.get("TotLen Bwd Pkts", 0))
        flow_duration = float(traffic_record.get("Flow Duration", 0))
        if tot_bwd_bytes > 5000 or flow_duration > 5000000:
            contributions.append({
                "feature": "TotLen Bwd Pkts",
                "value": f"{tot_bwd_bytes:,.0f} bytes",
                "contribution": 0.38,
                "label": "Anomalous Data Exfiltration",
                "severity": "critical"
            })
            reasons.append(f"Sustained connection with large response payload ({tot_bwd_bytes:,.0f} bytes) indicating potential data exfiltration.")

    if prediction in ["ZERO_DAY_ANOMALY"]:
        anom_score = prediction_result.get("anomaly_score", confidence)
        contributions.append({
            "feature": "Isolation Forest Outlier",
            "value": f"Anomaly Score: {anom_score * 100:.1f}%",
            "contribution": 0.50,
            "label": "Unsupervised Zero-Day Anomaly",
            "severity": "critical"
        })
        reasons.append(f"Unsupervised Isolation Forest model detected a high-dimensional statistical anomaly (score: {anom_score * 100:.1f}%) deviating from normal network behavior baseline.")

    # Generic feature checks if specific rules didn't trigger
    if not contributions:
        for feat, threshold in BASELINE_THRESHOLDS.items():
            val = float(traffic_record.get(feat, 0))
            if val > threshold:
                contributions.append({
                    "feature": feat,
                    "value": f"{val:,.1f}",
                    "contribution": 0.25,
                    "label": f"High Deviation in {feat}",
                    "severity": "medium"
                })
                reasons.append(f"Feature '{feat}' value ({val:,.1f}) significantly exceeded normal network baseline threshold ({threshold:,.1f}).")

    # Fallback for NORMAL or minor anomalies
    if not contributions:
        contributions.append({
            "feature": "Flow Baseline",
            "value": "Normal",
            "contribution": 0.95,
            "label": "Standard Network Protocol Compliance",
            "severity": "low"
        })
        reasons.append("Traffic characteristics align with standard benign network communication patterns.")

    # Build recommendations based on severity and prediction
    recommendations = []
    if prediction != "NORMAL":
        recommendations.append(f"Isolate or block source IP if confidence exceeds 80%.")
        if prediction == "BRUTE_FORCE":
            recommendations.append("Enforce multi-factor authentication (MFA) and rate limiting on target port.")
        elif prediction == "DOS_DDOS":
            recommendations.append("Apply rate-limiting or null-route traffic from attacking IP range.")
        elif prediction == "WEB_ATTACK":
            recommendations.append("Inspect Web Application Firewall (WAF) logs for SQLi or command injection signatures.")
        elif prediction == "INFILTRATION":
            recommendations.append("Audit internal endpoint for compromise and check outbound socket connections.")
        elif prediction == "ZERO_DAY_ANOMALY":
            recommendations.append("Quarantine flow for deep packet inspection (DPI) and capture raw payload for signature synthesis.")
    else:
        recommendations.append("No immediate action required. Traffic is within safe network limits.")

    return {
        "prediction": prediction,
        "confidence": confidence,
        "confidence_pct": f"{confidence * 100:.1f}%",
        "severity": severity,
        "summary": " ".join(reasons) if reasons else "Traffic evaluated as standard network packet flow.",
        "reasons": reasons,
        "top_features": contributions[:5],
        "recommendations": recommendations,
        "explained_at": np.datetime64("now").astype(str)
    }
