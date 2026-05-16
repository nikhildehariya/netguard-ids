import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import joblib
import numpy as np
from datetime import datetime

from config import (
    MODEL_PATH, SCALER_PATH,
    LABEL_NAMES, SEVERITY_MAP
)
from preprocess import preprocess_inference


class IntrusionDetector:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
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
        self._loaded = True
        print(f"[detector] Model loaded from {MODEL_PATH}")

    def predict(self, traffic_record: dict) -> dict:
        if not self._loaded:
            self.load()
        X = preprocess_inference(traffic_record)
        class_idx  = int(self.model.predict(X)[0])
        proba      = self.model.predict_proba(X)[0]
        confidence = float(np.max(proba))
        label      = LABEL_NAMES[class_idx]
        severity   = SEVERITY_MAP[label]
        return {
            "prediction":  label,
            "confidence":  round(confidence, 4),
            "severity":    severity,
            "all_scores":  {
                LABEL_NAMES[i]: round(float(p), 4)
                for i, p in enumerate(proba)
            },
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }

    def predict_batch(self, records: list[dict]) -> list[dict]:
        return [self.predict(r) for r in records]


detector = IntrusionDetector()