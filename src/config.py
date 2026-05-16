import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data"
MODELS_DIR  = BASE_DIR / "models"
LOG_PATH    = BASE_DIR / "logs" / "detections.csv"
REPORTS_DIR = BASE_DIR / "reports"
BLOCKLIST_PATH = BASE_DIR / "logs" / "blocked_ips.csv"

MODEL_PATH    = MODELS_DIR / "xgb_model.pkl"
# ENCODERS_PATH = MODELS_DIR / "encoders.pkl"
SCALER_PATH   = MODELS_DIR / "scaler.pkl"

# ── CIC-IDS2018 Labels ────────────────────────────────────────
LABEL_MAP = {
    "Benign":                  0,
    "FTP-BruteForce":          1,
    "SSH-Bruteforce":          1,
    "DoS attacks-GoldenEye":   2,
    "DoS attacks-Slowloris":   2,
    "DoS attacks-SlowHTTPTest":2,
    "DoS attacks-Hulk":        2,
    "DDOS attack-LOIC-UDP":    2,
    "DDOS attack-HOIC":        2,
    "Brute Force -Web":        3,
    "Brute Force -XSS":        3,
    "SQL Injection":           3,
    "Infilteration":           4,
    "Bot":                     4,
}

# 5 main categories
CLASS_NAMES = {
    0: "NORMAL",
    1: "BRUTE_FORCE",
    2: "DOS_DDOS",
    3: "WEB_ATTACK",
    4: "INFILTRATION"
}

LABEL_NAMES  = CLASS_NAMES
NUM_CLASSES  = len(CLASS_NAMES)

SEVERITY_MAP = {
    "NORMAL":       "none",
    "BRUTE_FORCE":  "high",
    "DOS_DDOS":     "critical",
    "WEB_ATTACK":   "high",
    "INFILTRATION": "critical",
}

SEVERITY_COLOR = {
    "none":     "green",
    "high":     "orange",
    "critical": "red",
}

# ── CIC-IDS2018 Features ──────────────────────────────────────
FEATURE_COLS = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts',
    'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
    'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean',
    'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s',
    'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std',
    'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
    'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s',
    'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std',
    'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt',
    'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count',
    'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg',
    'Bwd Seg Size Avg', 'Subflow Fwd Pkts', 'Subflow Fwd Byts',
    'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Init Fwd Win Byts',
    'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

CATEGORICAL_COLS   = []
ENGINEERED_COLS    = []
ALL_FEATURE_COLS   = FEATURE_COLS

# ── API ───────────────────────────────────────────────────────
API_HOST = "0.0.0.0"
API_PORT = 8080
API_URL  = f"http://localhost:{API_PORT}"

ALERT_CONFIDENCE_THRESHOLD = 0.85

# ── Per-class confidence thresholds (industry grade) ─────────
CONFIDENCE_THRESHOLDS = {
    "NORMAL":      1.00,
    "BRUTE_FORCE": 0.80,
    "DOS_DDOS":    0.85,
    "WEB_ATTACK":  0.80,
    "INFILTRATION":0.45,  # Subtle by nature — lower threshold valid
}

# ── XGBoost ───────────────────────────────────────────────────
XGB_PARAMS = {
    "n_estimators":     300,
    "max_depth":        6,
    "learning_rate":    0.1,
    "subsample":        0.8,
    "colsample_bytree": 0.8,
    "eval_metric":      "mlogloss",
    "random_state":     42,
    "n_jobs":           -1,
}

# ── Alerts ────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()
ALERT_FROM = os.getenv("ALERT_FROM_EMAIL", "")
ALERT_TO   = os.getenv("ALERT_TO_EMAIL", "")
ALERT_PASS = os.getenv("ALERT_PASSWORD", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# ── Dashboard Auth ────────────────────────────────────────────
# FIX: single definition only; loaded from .env with secure default
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "netguard123")

# ── JWT Secret — persists across restarts via .env ───────────
import secrets as _secrets
SECRET_KEY = os.getenv("SECRET_KEY", _secrets.token_hex(32))

# ── Automated Response ────────────────────────────────────────
AUTO_BLOCK_ENABLED = os.getenv("AUTO_BLOCK_ENABLED", "false").lower() == "true"
AUTO_BLOCK_THRESHOLD = int(os.getenv("AUTO_BLOCK_THRESHOLD", "3"))
AUTO_BLOCK_CONFIDENCE = float(os.getenv("AUTO_BLOCK_CONFIDENCE", "0.95"))
AUTO_BLOCK_SEVERITIES = {
    item.strip()
    for item in os.getenv("AUTO_BLOCK_SEVERITIES", "critical").split(",")
    if item.strip()
}

# ── Skip corrupt files ────────────────────────────────────────
SKIP_FILES = ["02-20-2018.csv"]