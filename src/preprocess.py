import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import glob
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE

from config import (
    DATA_DIR, FEATURE_COLS, LABEL_MAP,
    SCALER_PATH, MODELS_DIR,
    SKIP_FILES
)

MODELS_DIR.mkdir(parents=True, exist_ok=True)


def load_all_data() -> pd.DataFrame:
    """Load all CIC-IDS2018 CSV files — skip corrupt ones."""
    all_files = glob.glob(str(DATA_DIR / "*.csv"))
    dfs = []

    for f in all_files:
        fname = Path(f).name
        if fname in SKIP_FILES:
            print(f"[preprocess] Skipping corrupt file: {fname}")
            continue
        try:
            df = pd.read_csv(f, low_memory=False)
            # Drop bad header rows inside data
            df = df[df['Label'] != 'Label']
            dfs.append(df)
            print(f"[preprocess] Loaded {fname} — {len(df):,} rows")
        except Exception as e:
            print(f"[preprocess] Error in {fname}: {e}")

    combined = pd.concat(dfs, ignore_index=True)
    print(f"\n[preprocess] Total rows: {len(combined):,}")
    return combined


def _map_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Map CIC attack labels to 5 main categories."""
    df = df.copy()
    df['label'] = df['Label'].map(LABEL_MAP)
    df = df[df['label'].notna()]
    df['label'] = df['label'].astype(int)
    return df


def _clean_features(df: pd.DataFrame) -> pd.DataFrame:
    """Clean infinite and NaN values."""
    df = df.copy()
    available = [c for c in FEATURE_COLS if c in df.columns]
    df = df[available + ['label']]
    
    # Replace inf values — pehle numeric columns convert karo
    for col in available:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    
    # Ab infinity replace karo
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # NaN fill karo 0 se — drop mat karo (data loss hoga)
    df.fillna(0, inplace=True)
    
    return df


def preprocess_train(df: pd.DataFrame):
    df = _map_labels(df)
    df = _clean_features(df)

    y = df['label'].values
    X = df.drop(columns=['label'])

    print("\n[preprocess] Class distribution:")
    unique, counts = np.unique(y, return_counts=True)
    for u, c in zip(unique, counts):
        print(f"  Class {u}: {c:,}")

    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, SCALER_PATH)
    print(f"[preprocess] Scaler saved → {SCALER_PATH}")

    # No SMOTE — 82 lakh rows enough hai
    return train_test_split(
        X_scaled, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )


def preprocess_inference(record: dict) -> np.ndarray:
    """Preprocess a single record for inference."""
    scaler = joblib.load(SCALER_PATH)
    df = pd.DataFrame([record])

    # Keep only trained feature cols
    available = [c for c in FEATURE_COLS if c in df.columns]
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0

    df = df[FEATURE_COLS]
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    return scaler.transform(df)
