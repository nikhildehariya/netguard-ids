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
IFOREST_MODEL_PATH = MODELS_DIR / "iforest_model.pkl"
# ENCODERS_PATH = MODELS_DIR / "encoders.pkl"
SCALER_PATH   = MODELS_DIR / "scaler.pkl"

KEYS_DIR         = BASE_DIR / "keys"
PUBLIC_KEY_PATH  = KEYS_DIR / "license_public_key.pem"
PRIVATE_KEY_PATH = KEYS_DIR / "license_private_key.pem"
LICENSE_KEY_PATH = BASE_DIR / "license.key"
GRACE_PERIOD_DAYS = 3

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
    "NORMAL":           "none",
    "BRUTE_FORCE":      "high",
    "DOS_DDOS":         "critical",
    "WEB_ATTACK":       "high",
    "INFILTRATION":     "critical",
    "ZERO_DAY_ANOMALY": "critical",
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
API_PORT = int(os.getenv("API_PORT", "8081"))
API_URL  = f"http://127.0.0.1:{API_PORT}"

# ── Redis Stream Flow Buffer ─────────────────────────────────
REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
REDIS_STREAM_KEY = os.getenv("REDIS_STREAM_KEY", "netguard:flow_stream")
REDIS_CONSUMER_GROUP = os.getenv("REDIS_CONSUMER_GROUP", "netguard_inference_group")
USE_REDIS_BUFFER = os.getenv("USE_REDIS_BUFFER", "true").lower() == "true"

ALERT_CONFIDENCE_THRESHOLD = 0.85

# ── Per-class confidence thresholds (industry grade) ─────────
CONFIDENCE_THRESHOLDS = {
    "NORMAL":           1.00,
    "BRUTE_FORCE":      0.80,
    "DOS_DDOS":         0.85,
    "WEB_ATTACK":       0.80,
    "INFILTRATION":     0.45,  # Subtle by nature — lower threshold valid
    "ZERO_DAY_ANOMALY": 0.70,
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

# ── Isolation Forest (Zero-Day Anomaly Detection) ─────────────
IFOREST_PARAMS = {
    "n_estimators":     100,
    "max_samples":      "auto",
    "contamination":    0.03,  # 3% baseline anomaly expectation
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

# ── PostgreSQL Database Config ───────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://neondb_owner:npg_qmrcY0I9NEgF@ep-lively-glitter-b5u7jwdv-pooler.c-7.us-east-2.aws.neon.tech/neondb?sslmode=require")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "ep-lively-glitter-b5u7jwdv-pooler.c-7.us-east-2.aws.neon.tech")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.getenv("POSTGRES_DB", "neondb")
POSTGRES_USER = os.getenv("POSTGRES_USER", "neondb_owner")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "npg_qmrcY0I9NEgF")
POSTGRES_SSLMODE = os.getenv("POSTGRES_SSLMODE", "require")

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
AUTO_BLOCK_CONFIDENCE = float(os.getenv("AUTO_BLOCK_CONFIDENCE", "0.98"))
AUTO_BLOCK_TTL = int(os.getenv("AUTO_BLOCK_TTL", "3600")) # Default 1 hour
AUTO_BLOCK_SEVERITIES = {
    item.strip()
    for item in os.getenv("AUTO_BLOCK_SEVERITIES", "critical").split(",")
    if item.strip()
}

WHITELISTED_IPS = {
    ip.strip()
    for ip in os.getenv("WHITELISTED_IPS", "8.8.8.8,8.8.4.4,1.1.1.1").split(",")
    if ip.strip()
}

# ── Agent Security — internal packet prediction key ───────────
AGENT_SECRET_KEY = os.getenv("AGENT_SECRET_KEY", "netguard-agent-secret-key-default")

# ── Skip corrupt files ────────────────────────────────────────
SKIP_FILES = ["02-20-2018.csv"]