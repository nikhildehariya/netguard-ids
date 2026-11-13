import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import joblib
import numpy as np
from datetime import datetime, timezone

from config import (
    MODEL_PATH, IFOREST_MODEL_PATH, SCALER_PATH,
    LABEL_NAMES, SEVERITY_MAP
)
from preprocess import preprocess_inference


class IntrusionDetector:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
            cls._instance.iforest = None
        return cls._instance

    def load(self):
        if self._loaded:
            return
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}.\n"
                "Run: python src/train.py"
            )
        self.model  = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        if IFOREST_MODEL_PATH.exists():
            try:
                self.iforest = joblib.load(IFOREST_MODEL_PATH)
                print(f"[detector] Isolation Forest loaded from {IFOREST_MODEL_PATH}")
            except Exception as e:
                print(f"[detector] Warning loading Isolation Forest: {e}")
                self.iforest = None
        else:
            self.iforest = None
            print(f"[detector] Notice: iForest model not found at {IFOREST_MODEL_PATH}, running in fallback XGBoost-only mode.")
        self._loaded = True
        print(f"[detector] XGBoost Model loaded from {MODEL_PATH}")

    def predict(self, traffic_record: dict) -> dict:
        if not self._loaded:
            self.load()
        X = preprocess_inference(traffic_record)
        class_idx  = int(self.model.predict(X)[0])
        proba      = self.model.predict_proba(X)[0]
        confidence = float(np.max(proba))
        xgb_label  = LABEL_NAMES[class_idx]

        # ── Isolation Forest Zero-Day Anomaly Detection ──
        is_anomaly = False
        anomaly_score = 0.0
        if self.iforest is not None:
            try:
                iforest_pred = int(self.iforest.predict(X)[0]) # 1 = normal, -1 = anomaly
                raw_score    = float(self.iforest.decision_function(X)[0]) # lower/negative = more anomalous
                # Convert raw_score (typical range -0.5 to 0.5) to normalized score in [0.0, 1.0]
                anomaly_score = float(np.clip(0.5 - raw_score, 0.0, 1.0))
                
                # Domain-Adaptive Thresholding:
                # IoT specific ports (MQTT:1883, Modbus:502, CoAP:5683) or extreme packet bursts
                dst_port = float(traffic_record.get("Dst Port", 0))
                flow_pkts_s = float(traffic_record.get("Flow Pkts/s", 0))
                is_iot_port = dst_port in [1883, 502, 5683, 8883, 4840]
                
                # Adaptive threshold: 0.55 on IoT vectors / high burst, 0.65 on standard traffic
                threshold = 0.55 if (is_iot_port or flow_pkts_s > 1000) else 0.65
                if iforest_pred == -1 or anomaly_score > threshold:
                    is_anomaly = True
            except Exception as e:
                print(f"[detector] Isolation Forest prediction error: {e}")

        # ── Dual-Engine Decision Logic ──
        # If XGBoost predicts NORMAL (or low confidence) but Isolation Forest isolates an anomaly,
        # flag as ZERO_DAY_ANOMALY.
        if xgb_label == "NORMAL" and is_anomaly:
            final_label      = "ZERO_DAY_ANOMALY"
            final_confidence = round(max(anomaly_score, 0.75), 4)
            severity         = SEVERITY_MAP["ZERO_DAY_ANOMALY"]
        else:
            final_label      = xgb_label
            final_confidence = round(confidence, 4)
            severity         = SEVERITY_MAP[xgb_label]

        res = {
            "prediction":     final_label,
            "confidence":     final_confidence,
            "severity":       severity,
            "is_anomaly":     is_anomaly,
            "anomaly_score":  round(anomaly_score, 4),
            "xgb_prediction": xgb_label,
            "all_scores":     {
                LABEL_NAMES[i]: round(float(p), 4)
                for i, p in enumerate(proba)
            },
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }

        # ── Bi-LSTM Deep Sequence Correlation for Multi-Stage APTs ──
        try:
            from sequence_model import apt_correlator
            src_ip = traffic_record.get("src_ip", "127.0.0.1")
            apt_info = apt_correlator.correlate(traffic_record, res, source_ip=src_ip)
            if apt_info.get("is_apt_campaign"):
                res["is_apt"] = True
                res["campaign_id"] = apt_info.get("campaign_id")
                res["apt_stage"] = apt_info.get("apt_stage")
                res["apt_score"] = apt_info.get("apt_score")
                res["temporal_attention"] = apt_info.get("temporal_attention")
                res["severity"] = "critical"
            else:
                res["is_apt"] = False
                res["apt_score"] = apt_info.get("apt_score", 0.0)
        except Exception as e:
            res["is_apt"] = False
            res["apt_error"] = str(e)

        # ── Threat Intelligence (TI) Reputation Correlation ──
        try:
            from threat_intel import threat_intel
            check_ip = traffic_record.get("dst_ip") or traffic_record.get("Dst IP") or traffic_record.get("src_ip")
            if check_ip:
                ti_info = threat_intel.lookup_ip(str(check_ip))
                if ti_info.get("is_malicious"):
                    res["threat_intel"] = ti_info
                    if res["prediction"] == "NORMAL":
                        res["prediction"] = "C2_COMMUNICATION"
                        res["confidence"] = max(res["confidence"], ti_info.get("reputation_score", 0.95))
                        res["severity"] = "critical"
                    else:
                        res["confidence"] = max(res["confidence"], 0.95)
                        res["severity"] = "critical"
        except Exception as e:
            res["threat_intel_error"] = str(e)

        return res

    def predict_batch(self, records: list[dict]) -> list[dict]:
        return [self.predict(r) for r in records]


detector = IntrusionDetector()