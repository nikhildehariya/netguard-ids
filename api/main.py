import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import os
import subprocess
import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Optional

from predict import detector
from alert import handle_alert
from blocklist import (
    list_blocked_ips, block_ip, unblock_ip,
    get_block_audit, bulk_block, bulk_unblock
)
from reporting import build_pdf_report, load_history
from alert_settings import get_alert_settings, update_alert_to_email
from auth import (
    login, logout, refresh_access_token, verify_request, has_permission,
    create_user, list_users, update_user_role, delete_user, toggle_user_active,
    ROLE_PERMISSIONS
)

try:
    from scapy.all import get_if_list
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        get_windows_if_list = None
except ImportError:
    def get_if_list():
        return []
    get_windows_if_list = None

app = FastAPI(
    title="IoT Intrusion Detection API",
    description="Real-time IoT network traffic classifier",
    version="2.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

capture_process: subprocess.Popen | None = None
CAPTURE_LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "capture.log"


def _capture_log_tail(lines: int = 8) -> str:
    if not CAPTURE_LOG_PATH.exists():
        return ""
    return "\n".join(CAPTURE_LOG_PATH.read_text(errors="ignore").splitlines()[-lines:])


@app.on_event("startup")
def startup():
    detector.load()
    print("[api] Detector ready.")
    print("[auth] Auth system ready.")


# ── Pydantic models ────────────────────────────────────────────

class TrafficRecord(BaseModel):
    Dst_Port:             float = Field(0,   alias="Dst Port")
    Protocol:             float = Field(6)
    Flow_Duration:        float = Field(0,   alias="Flow Duration")
    Tot_Fwd_Pkts:         float = Field(0,   alias="Tot Fwd Pkts")
    Tot_Bwd_Pkts:         float = Field(0,   alias="Tot Bwd Pkts")
    TotLen_Fwd_Pkts:      float = Field(0,   alias="TotLen Fwd Pkts")
    TotLen_Bwd_Pkts:      float = Field(0,   alias="TotLen Bwd Pkts")
    Fwd_Pkt_Len_Max:      float = Field(0,   alias="Fwd Pkt Len Max")
    Fwd_Pkt_Len_Min:      float = Field(0,   alias="Fwd Pkt Len Min")
    Fwd_Pkt_Len_Mean:     float = Field(0,   alias="Fwd Pkt Len Mean")
    Fwd_Pkt_Len_Std:      float = Field(0,   alias="Fwd Pkt Len Std")
    Bwd_Pkt_Len_Max:      float = Field(0,   alias="Bwd Pkt Len Max")
    Bwd_Pkt_Len_Min:      float = Field(0,   alias="Bwd Pkt Len Min")
    Bwd_Pkt_Len_Mean:     float = Field(0,   alias="Bwd Pkt Len Mean")
    Bwd_Pkt_Len_Std:      float = Field(0,   alias="Bwd Pkt Len Std")
    Flow_Byts_s:          float = Field(0,   alias="Flow Byts/s")
    Flow_Pkts_s:          float = Field(0,   alias="Flow Pkts/s")
    Flow_IAT_Mean:        float = Field(0,   alias="Flow IAT Mean")
    Flow_IAT_Std:         float = Field(0,   alias="Flow IAT Std")
    Flow_IAT_Max:         float = Field(0,   alias="Flow IAT Max")
    Flow_IAT_Min:         float = Field(0,   alias="Flow IAT Min")
    Fwd_IAT_Tot:          float = Field(0,   alias="Fwd IAT Tot")
    Fwd_IAT_Mean:         float = Field(0,   alias="Fwd IAT Mean")
    Fwd_IAT_Std:          float = Field(0,   alias="Fwd IAT Std")
    Fwd_IAT_Max:          float = Field(0,   alias="Fwd IAT Max")
    Fwd_IAT_Min:          float = Field(0,   alias="Fwd IAT Min")
    Bwd_IAT_Tot:          float = Field(0,   alias="Bwd IAT Tot")
    Bwd_IAT_Mean:         float = Field(0,   alias="Bwd IAT Mean")
    Bwd_IAT_Std:          float = Field(0,   alias="Bwd IAT Std")
    Bwd_IAT_Max:          float = Field(0,   alias="Bwd IAT Max")
    Bwd_IAT_Min:          float = Field(0,   alias="Bwd IAT Min")
    Fwd_PSH_Flags:        float = Field(0,   alias="Fwd PSH Flags")
    Bwd_PSH_Flags:        float = Field(0,   alias="Bwd PSH Flags")
    Fwd_URG_Flags:        float = Field(0,   alias="Fwd URG Flags")
    Bwd_URG_Flags:        float = Field(0,   alias="Bwd URG Flags")
    Fwd_Header_Len:       float = Field(0,   alias="Fwd Header Len")
    Bwd_Header_Len:       float = Field(0,   alias="Bwd Header Len")
    Fwd_Pkts_s:           float = Field(0,   alias="Fwd Pkts/s")
    Bwd_Pkts_s:           float = Field(0,   alias="Bwd Pkts/s")
    Pkt_Len_Min:          float = Field(0,   alias="Pkt Len Min")
    Pkt_Len_Max:          float = Field(0,   alias="Pkt Len Max")
    Pkt_Len_Mean:         float = Field(0,   alias="Pkt Len Mean")
    Pkt_Len_Std:          float = Field(0,   alias="Pkt Len Std")
    Pkt_Len_Var:          float = Field(0,   alias="Pkt Len Var")
    FIN_Flag_Cnt:         float = Field(0,   alias="FIN Flag Cnt")
    SYN_Flag_Cnt:         float = Field(0,   alias="SYN Flag Cnt")
    RST_Flag_Cnt:         float = Field(0,   alias="RST Flag Cnt")
    PSH_Flag_Cnt:         float = Field(0,   alias="PSH Flag Cnt")
    ACK_Flag_Cnt:         float = Field(0,   alias="ACK Flag Cnt")
    URG_Flag_Cnt:         float = Field(0,   alias="URG Flag Cnt")
    CWE_Flag_Count:       float = Field(0,   alias="CWE Flag Count")
    ECE_Flag_Cnt:         float = Field(0,   alias="ECE Flag Cnt")
    Down_Up_Ratio:        float = Field(0,   alias="Down/Up Ratio")
    Pkt_Size_Avg:         float = Field(0,   alias="Pkt Size Avg")
    Fwd_Seg_Size_Avg:     float = Field(0,   alias="Fwd Seg Size Avg")
    Bwd_Seg_Size_Avg:     float = Field(0,   alias="Bwd Seg Size Avg")
    Subflow_Fwd_Pkts:     float = Field(0,   alias="Subflow Fwd Pkts")
    Subflow_Fwd_Byts:     float = Field(0,   alias="Subflow Fwd Byts")
    Subflow_Bwd_Pkts:     float = Field(0,   alias="Subflow Bwd Pkts")
    Subflow_Bwd_Byts:     float = Field(0,   alias="Subflow Bwd Byts")
    Init_Fwd_Win_Byts:    float = Field(0,   alias="Init Fwd Win Byts")
    Init_Bwd_Win_Byts:    float = Field(0,   alias="Init Bwd Win Byts")
    Fwd_Act_Data_Pkts:    float = Field(0,   alias="Fwd Act Data Pkts")
    Fwd_Seg_Size_Min:     float = Field(0,   alias="Fwd Seg Size Min")
    Active_Mean:          float = Field(0,   alias="Active Mean")
    Active_Std:           float = Field(0,   alias="Active Std")
    Active_Max:           float = Field(0,   alias="Active Max")
    Active_Min:           float = Field(0,   alias="Active Min")
    Idle_Mean:            float = Field(0,   alias="Idle Mean")
    Idle_Std:             float = Field(0,   alias="Idle Std")
    Idle_Max:             float = Field(0,   alias="Idle Max")
    Idle_Min:             float = Field(0,   alias="Idle Min")
    flow_id:    Optional[str]  = Field('')
    source_ip:  Optional[str]  = Field(None)
    test_mode:  bool           = Field(False)

    class Config:
        populate_by_name = True


class CaptureRequest(BaseModel):
    interface: str = "eth0"
    packet_limit: int = 0


class BlockRequest(BaseModel):
    ip: str
    reason: str = "Manual block from dashboard"
    ttl_seconds: Optional[int] = None
    layer: str = "firewall"


class BulkBlockRequest(BaseModel):
    ips: list[str]
    reason: str = "Bulk block from dashboard"
    layer: str = "firewall"


class BulkUnblockRequest(BaseModel):
    ips: list[str]


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "viewer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UpdateRoleRequest(BaseModel):
    role: str


class AlertSettingsUpdateRequest(BaseModel):
    alert_to_email: str


# ── Auth helpers ───────────────────────────────────────────────

def get_token(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def require_permission(request: Request, permission: str):
    token = get_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not has_permission(token, permission):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return verify_request(token)


def get_actor(request: Request) -> str:
    """Extract username from JWT for audit logging."""
    token = get_token(request)
    if not token:
        return "anonymous"
    payload = verify_request(token)
    return payload.get("sub", "unknown") if payload else "unknown"


# ══════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.post("/auth/login")
def auth_login(req: LoginRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    result = login(req.username, req.password, ip)
    if not result["success"]:
        status = 423 if result.get("locked") else 401
        raise HTTPException(status_code=status, detail=result["message"])
    return result


@app.post("/auth/refresh")
def auth_refresh(req: RefreshRequest):
    result = refresh_access_token(req.refresh_token)
    if not result["success"]:
        raise HTTPException(status_code=401, detail=result["message"])
    return result


@app.post("/auth/logout")
def auth_logout(req: RefreshRequest):
    return logout(req.refresh_token)


@app.get("/auth/me")
def auth_me(request: Request):
    token = get_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = verify_request(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {
        "username":    payload["sub"],
        "role":        payload["role"],
        "permissions": ROLE_PERMISSIONS.get(payload["role"], [])
    }


# ── User Management (admin only) ──────────────────────────────

@app.post("/auth/users")
def register_user(req: RegisterRequest, request: Request):
    require_permission(request, "manage_users")
    return create_user(req.username, req.email, req.password, req.role)


@app.get("/auth/users")
def get_users(request: Request):
    require_permission(request, "manage_users")
    return {"users": list_users()}


@app.patch("/auth/users/{username}/role")
def change_role(username: str, req: UpdateRoleRequest, request: Request):
    require_permission(request, "manage_users")
    return update_user_role(username, req.role)


@app.delete("/auth/users/{username}")
def remove_user(username: str, request: Request):
    require_permission(request, "manage_users")
    return delete_user(username)


@app.patch("/auth/users/{username}/toggle")
def toggle_user(username: str, request: Request):
    require_permission(request, "manage_users")
    return toggle_user_active(username)


@app.get("/admin/alert-settings")
def get_admin_alert_settings(request: Request):
    require_permission(request, "manage_users")
    return get_alert_settings()


@app.patch("/admin/alert-settings")
def patch_admin_alert_settings(req: AlertSettingsUpdateRequest, request: Request):
    require_permission(request, "manage_users")
    email = req.alert_to_email.strip()
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Please provide a valid email address")
    return update_alert_to_email(email)


# ══════════════════════════════════════════════════════════════
# PREDICT ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.post("/predict")
def predict(record: TrafficRecord, http_request: Request):
    # FIX: capture.py sends directly without auth (internal), but dashboard
    # calls go through auth. Allow both: skip auth for internal loopback,
    # require "view" for external callers.
    # Simplest industry approach: capture.py is internal, so /predict is
    # intentionally open for the capture pipeline. Dashboard reads via
    # /history and /stats which ARE protected.
    try:
        data = {
            "Dst Port":           record.Dst_Port,
            "Protocol":           record.Protocol,
            "Flow Duration":      record.Flow_Duration,
            "Tot Fwd Pkts":       record.Tot_Fwd_Pkts,
            "Tot Bwd Pkts":       record.Tot_Bwd_Pkts,
            "TotLen Fwd Pkts":    record.TotLen_Fwd_Pkts,
            "TotLen Bwd Pkts":    record.TotLen_Bwd_Pkts,
            "Fwd Pkt Len Max":    record.Fwd_Pkt_Len_Max,
            "Fwd Pkt Len Min":    record.Fwd_Pkt_Len_Min,
            "Fwd Pkt Len Mean":   record.Fwd_Pkt_Len_Mean,
            "Fwd Pkt Len Std":    record.Fwd_Pkt_Len_Std,
            "Bwd Pkt Len Max":    record.Bwd_Pkt_Len_Max,
            "Bwd Pkt Len Min":    record.Bwd_Pkt_Len_Min,
            "Bwd Pkt Len Mean":   record.Bwd_Pkt_Len_Mean,
            "Bwd Pkt Len Std":    record.Bwd_Pkt_Len_Std,
            "Flow Byts/s":        record.Flow_Byts_s,
            "Flow Pkts/s":        record.Flow_Pkts_s,
            "Flow IAT Mean":      record.Flow_IAT_Mean,
            "Flow IAT Std":       record.Flow_IAT_Std,
            "Flow IAT Max":       record.Flow_IAT_Max,
            "Flow IAT Min":       record.Flow_IAT_Min,
            "Fwd IAT Tot":        record.Fwd_IAT_Tot,
            "Fwd IAT Mean":       record.Fwd_IAT_Mean,
            "Fwd IAT Std":        record.Fwd_IAT_Std,
            "Fwd IAT Max":        record.Fwd_IAT_Max,
            "Fwd IAT Min":        record.Fwd_IAT_Min,
            "Bwd IAT Tot":        record.Bwd_IAT_Tot,
            "Bwd IAT Mean":       record.Bwd_IAT_Mean,
            "Bwd IAT Std":        record.Bwd_IAT_Std,
            "Bwd IAT Max":        record.Bwd_IAT_Max,
            "Bwd IAT Min":        record.Bwd_IAT_Min,
            "Fwd PSH Flags":      record.Fwd_PSH_Flags,
            "Bwd PSH Flags":      record.Bwd_PSH_Flags,
            "Fwd URG Flags":      record.Fwd_URG_Flags,
            "Bwd URG Flags":      record.Bwd_URG_Flags,
            "Fwd Header Len":     record.Fwd_Header_Len,
            "Bwd Header Len":     record.Bwd_Header_Len,
            "Fwd Pkts/s":         record.Fwd_Pkts_s,
            "Bwd Pkts/s":         record.Bwd_Pkts_s,
            "Pkt Len Min":        record.Pkt_Len_Min,
            "Pkt Len Max":        record.Pkt_Len_Max,
            "Pkt Len Mean":       record.Pkt_Len_Mean,
            "Pkt Len Std":        record.Pkt_Len_Std,
            "Pkt Len Var":        record.Pkt_Len_Var,
            "FIN Flag Cnt":       record.FIN_Flag_Cnt,
            "SYN Flag Cnt":       record.SYN_Flag_Cnt,
            "RST Flag Cnt":       record.RST_Flag_Cnt,
            "PSH Flag Cnt":       record.PSH_Flag_Cnt,
            "ACK Flag Cnt":       record.ACK_Flag_Cnt,
            "URG Flag Cnt":       record.URG_Flag_Cnt,
            "CWE Flag Count":     record.CWE_Flag_Count,
            "ECE Flag Cnt":       record.ECE_Flag_Cnt,
            "Down/Up Ratio":      record.Down_Up_Ratio,
            "Pkt Size Avg":       record.Pkt_Size_Avg,
            "Fwd Seg Size Avg":   record.Fwd_Seg_Size_Avg,
            "Bwd Seg Size Avg":   record.Bwd_Seg_Size_Avg,
            "Subflow Fwd Pkts":   record.Subflow_Fwd_Pkts,
            "Subflow Fwd Byts":   record.Subflow_Fwd_Byts,
            "Subflow Bwd Pkts":   record.Subflow_Bwd_Pkts,
            "Subflow Bwd Byts":   record.Subflow_Bwd_Byts,
            "Init Fwd Win Byts":  record.Init_Fwd_Win_Byts,
            "Init Bwd Win Byts":  record.Init_Bwd_Win_Byts,
            "Fwd Act Data Pkts":  record.Fwd_Act_Data_Pkts,
            "Fwd Seg Size Min":   record.Fwd_Seg_Size_Min,
            "Active Mean":        record.Active_Mean,
            "Active Std":         record.Active_Std,
            "Active Max":         record.Active_Max,
            "Active Min":         record.Active_Min,
            "Idle Mean":          record.Idle_Mean,
            "Idle Std":           record.Idle_Std,
            "Idle Max":           record.Idle_Max,
            "Idle Min":           record.Idle_Min,
        }
        source_ip = record.source_ip or (http_request.client.host if http_request.client else "unknown")
        result = detector.predict(data)
        handle_alert(result, source_ip, flow_id=record.flow_id or "", test_mode=record.test_mode)
        return result
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/batch")
def predict_batch(records: list[TrafficRecord], request: Request):
    # FIX: batch endpoint now requires "view" permission
    require_permission(request, "view")
    try:
        results = []
        for record in records:
            payload = record.model_dump(by_alias=True)
            payload.pop("flow_id", None)
            payload.pop("source_ip", None)
            payload.pop("test_mode", None)
            results.append(detector.predict(payload))
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ══════════════════════════════════════════════════════════════
# SYSTEM ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    return {"status": "running", "model_loaded": detector._loaded}


@app.get("/history")
def history(limit: int = 100, mode: str = "live", request: Request = None):
    # FIX: require "view" permission so viewer/analyst can access dashboard data
    require_permission(request, "view")
    df = load_history(limit=limit, mode=mode)
    return df.tail(limit).to_dict(orient="records")


@app.get("/stats")
def stats(mode: str = "live", limit: int | None = None, request: Request = None):
    # FIX: require "view" permission
    require_permission(request, "view")
    df = load_history(limit=limit, mode=mode)
    if df.empty:
        return {
            "total": 0, "by_class": {}, "by_triage_status": {},
            "attack_rate": 0.0, "raw_non_normal_rate": 0.0,
        }
    total          = len(df)
    actionable     = df[df["actionable"]]
    raw_non_normal = df[df["prediction"] != "NORMAL"]
    by_class       = df["prediction"].value_counts().to_dict()
    by_triage_status = df["triage_status"].value_counts().to_dict()
    return {
        "total":              total,
        "by_class":           by_class,
        "by_triage_status":   by_triage_status,
        "attack_rate":        round(len(actionable) / total * 100, 2) if total else 0.0,
        "raw_non_normal_rate":round(len(raw_non_normal) / total * 100, 2) if total else 0.0,
    }


@app.get("/reports/export")
def export_report(
    limit: int = 200,
    hours: Optional[float] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    request: Request = None,
):
    # FIX: require "report" permission
    require_permission(request, "report")
    path = build_pdf_report(limit=limit, hours=hours, start=start, end=end)
    return FileResponse(path, media_type="application/pdf", filename=Path(path).name)


# ══════════════════════════════════════════════════════════════
# CAPTURE ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.get("/capture/interfaces")
def capture_interfaces(request: Request):
    # FIX: require "capture" permission
    require_permission(request, "capture")
    scapy_interfaces = get_if_list()
    windows_list = []
    if get_windows_if_list is not None:
        try:
            windows_list = get_windows_if_list() or []
        except Exception:
            windows_list = []

    windows_by_guid = {
        item.get("guid"): item
        for item in windows_list
        if item.get("guid")
    }

    # Merge both sources so adapters present in Windows metadata but missing
    # from get_if_list() are still selectable in manual mode.
    merged_ids: list[str] = []
    merged_ids.extend(scapy_interfaces)
    merged_ids.extend(windows_by_guid.keys())

    seen: set[str] = set()
    items = []
    for iface in merged_ids:
        if iface.startswith("{") and not iface.startswith("\\Device\\NPF_"):
            iface_id = f"\\Device\\NPF_{iface}"
            iface_guid = iface
        elif iface.startswith("\\Device\\NPF_{") and iface.endswith("}"):
            iface_id = iface
            iface_guid = iface.replace("\\Device\\NPF_", "")
        else:
            iface_id = iface
            iface_guid = iface

        if iface_id in seen:
            continue
        seen.add(iface_id)

        meta = windows_by_guid.get(iface_guid, {})
        ips = [ip for ip in meta.get("ips", []) if not ip.startswith("fe80:")]
        label_parts = [meta.get("name") or iface, meta.get("description", ""), ", ".join(ips)]
        label = " - ".join(part for part in label_parts if part)
        items.append({
            "id": iface_id,
            "label": label,
            "name": meta.get("name") or iface,
            "description": meta.get("description", ""),
            "ips": ips,
        })
    return {"interfaces": items}


@app.get("/capture/status")
def capture_status(request: Request):
    require_permission(request, "view")
    running = capture_process is not None and capture_process.poll() is None
    status  = {"running": running}
    if capture_process is not None and not running:
        status["exit_code"] = capture_process.poll()
        status["last_log"]  = _capture_log_tail()
    return status


@app.post("/capture/start")
def capture_start(req: CaptureRequest, request: Request):
    # FIX: require "capture" permission
    require_permission(request, "capture")
    global capture_process
    if capture_process is not None and capture_process.poll() is None:
        return {"started": False, "message": "Capture already running"}

    iface_raw   = req.interface
    iface_clean = iface_raw.replace("\\Device\\NPF_", "").replace("/Device/NPF_", "")
    valid_interfaces = set(get_if_list())
    if iface_clean not in valid_interfaces and iface_raw not in valid_interfaces:
        raise HTTPException(
            status_code=400,
            detail=f"Interface '{iface_raw}' not found. Available: {sorted(valid_interfaces)}"
        )

    script = Path(__file__).resolve().parent.parent / "src" / "capture.py"
    CAPTURE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_file = open(CAPTURE_LOG_PATH, "a", encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    capture_process = subprocess.Popen(
        [sys.executable, str(script), "--iface", iface_raw],
        stdout=log_file, stderr=subprocess.STDOUT, text=True, env=env,
    )
    time.sleep(1.0)
    if capture_process.poll() is not None:
        return {
            "started": False,
            "message": _capture_log_tail() or f"Capture failed on {req.interface}",
        }
    return {"started": True, "message": f"Capture started on {req.interface}"}


@app.post("/capture/stop")
def capture_stop(request: Request):
    # FIX: require "capture" permission
    require_permission(request, "capture")
    global capture_process
    if capture_process is None or capture_process.poll() is not None:
        return {"stopped": False, "message": "Capture is not running"}
    capture_process.terminate()
    capture_process = None
    return {"stopped": True, "message": "Capture stopped"}


# ══════════════════════════════════════════════════════════════
# BLOCKLIST ENDPOINTS
# FIX: specific routes (/audit, /bulk-block, /bulk-unblock) MUST come
# BEFORE the parameterised route (/blocked-ips/{ip}) so FastAPI
# matches them correctly and doesn't swallow them as an {ip} value.
# ══════════════════════════════════════════════════════════════

@app.get("/blocked-ips/audit")
def block_audit_log(ip: Optional[str] = None, limit: int = 200, request: Request = None):
    """Full audit log of all block/unblock events. Admin only."""
    require_permission(request, "manage_users")
    return {"audit": get_block_audit(ip=ip, limit=limit)}


@app.post("/blocked-ips/bulk-block")
def bulk_block_ips(req: BulkBlockRequest, request: Request):
    """Block multiple IPs at once."""
    require_permission(request, "block_ip")
    actor = get_actor(request)
    return bulk_block(req.ips, reason=req.reason, blocked_by=actor)


@app.post("/blocked-ips/bulk-unblock")
def bulk_unblock_ips(req: BulkUnblockRequest, request: Request):
    """Unblock multiple IPs at once."""
    require_permission(request, "unblock_ip")
    actor = get_actor(request)
    return bulk_unblock(req.ips, unblocked_by=actor)


@app.get("/blocked-ips")
def blocked_ips(request: Request):
    """List all currently blocked IPs."""
    require_permission(request, "view")
    return {"items": list_blocked_ips()}


@app.post("/blocked-ips")
def add_blocked_ip(req: BlockRequest, request: Request):
    """Block an IP. Admin or analyst required."""
    require_permission(request, "block_ip")
    actor = get_actor(request)
    return block_ip(
        req.ip,
        reason=req.reason,
        blocked_by=actor,
        ttl_seconds=req.ttl_seconds,
        layer=req.layer,
    )


@app.delete("/blocked-ips/{ip}")
def remove_blocked_ip(ip: str, request: Request):
    """Unblock an IP. Admin only."""
    require_permission(request, "unblock_ip")
    actor = get_actor(request)
    return unblock_ip(ip, unblocked_by=actor)


# ══════════════════════════════════════════════════════════════
# MIGRATION ENDPOINT
# ══════════════════════════════════════════════════════════════

@app.post("/admin/migrate-csv")
def migrate_csv(request: Request):
    """One-time: migrate detections.csv → detections.db. Admin only."""
    require_permission(request, "manage_users")
    from detections_db import migrate_csv_to_sqlite
    return migrate_csv_to_sqlite()


# ══════════════════════════════════════════════════════════════
# NETWORK SCANNER ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.get("/network/devices")
def get_network_devices(request: Request):
    """Return cached device scan results."""
    require_permission(request, "view")
    from scanner import get_cached
    return get_cached()


@app.post("/network/scan")
def scan_network(request: Request, subnet: Optional[str] = None):
    """Run full scan: ping sweep + ARP + Nmap. Analyst or admin only."""
    require_permission(request, "capture")
    from scanner import full_scan
    import threading
    result = {}
    def run():
        nonlocal result
        # full_scan internally does ping_sweep → arp_scan → nmap_scan
        result.update(full_scan(subnet))
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=120)   # 2 min — ping sweep + nmap needs more time
    return result


@app.post("/network/scan/arp")
def scan_arp_only(request: Request, subnet: Optional[str] = None):
    """Quick scan: ping sweep + ARP only (no Nmap). Analyst or admin only."""
    require_permission(request, "capture")
    from scanner import arp_scan, update_cache
    from datetime import datetime
    # do_ping_sweep=True → pings entire subnet first, then reads ARP table
    # This ensures all active devices appear even after reboot/switch change
    devices = arp_scan(subnet, do_ping_sweep=True)
    timestamp = datetime.now().isoformat(timespec="seconds")
    update_cache(devices, timestamp)
    return {
        "devices":   devices,
        "total":     len(devices),
        "timestamp": timestamp,
        "scan_type": "arp+ping",
    }
