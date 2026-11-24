import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import os
import subprocess
import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import hmac
import hashlib
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

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
    create_user, list_users, list_tenants, update_user_role, delete_user, toggle_user_active,
    ROLE_PERMISSIONS
)
from explainable import explain_prediction
from genai_assistant import generate_threat_briefing, process_copilot_query
from license import (
    validate_license, get_active_license_status,
    require_tier, require_feature, LicenseTier,
    LICENSE_KEY_PATH
)
from config import AGENT_SECRET_KEY, SECRET_KEY
from stream_consumer import consumer_worker


try:
    from scapy.all import get_if_list, conf
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        get_windows_if_list = None
except ImportError:
    def get_if_list():
        return []
    conf = None
    get_windows_if_list = None

app = FastAPI(
    title="IoT Intrusion Detection API",
    description="Real-time IoT network traffic classifier",
    version="4.0.0"
)

ALLOWED_ORIGINS = [
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "http://localhost:8081",
    "http://127.0.0.1:8081",
]
custom_origins = os.getenv("CORS_ORIGINS", "")
if custom_origins:
    ALLOWED_ORIGINS.extend([o.strip() for o in custom_origins.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

capture_process: subprocess.Popen | None = None
CAPTURE_LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "capture.log"


def _capture_log_tail(lines: int = 8) -> str:
    if not CAPTURE_LOG_PATH.exists():
        return ""
    return "\n".join(CAPTURE_LOG_PATH.read_text(errors="ignore").splitlines()[-lines:])


def is_capture_running_systemwide() -> bool:
    lock_path = Path(__file__).resolve().parent.parent / "logs" / "capture.lock"
    if not lock_path.exists():
        return False
    f = None
    try:
        f = open(lock_path, "a+")
        if sys.platform == "win32":
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return False
    except (IOError, OSError):
        return True
    finally:
        if f is not None:
            try:
                f.close()
            except Exception:
                pass


def auto_start_live_capture():
    global capture_process
    if capture_process is not None and capture_process.poll() is None:
        return
    if is_capture_running_systemwide():
        print("[api] Live capture is already active system-wide (NSSM service or standalone). Skipping auto-start.")
        return
    iface = "auto"
    if conf is not None and hasattr(conf, "iface") and conf.iface:
        iface = str(getattr(conf.iface, "name", conf.iface))
    
    cmd = [sys.executable, str(Path(__file__).resolve().parent.parent / "src" / "capture.py"), "--iface", iface]
    CAPTURE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_file = open(CAPTURE_LOG_PATH, "a", encoding="utf-8", errors="ignore")
    capture_process = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT)
    print(f"[api] Auto-started live packet capture on '{iface}' (PID: {capture_process.pid})")


@app.on_event("startup")
def startup():
    detector.load()
    print("[api] Detector ready.")
    print("[auth] Auth system ready.")
    
    # Run DB table init in background thread so FastAPI startup completes in <1ms
    def _bg_init():
        try:
            from auth import init_db
            init_db()
        except Exception as e:
            print(f"[api] Background DB init notice: {e}")
    
    import threading
    threading.Thread(target=_bg_init, daemon=True).start()

    try:
        consumer_worker.start(run_in_background=True)
    except Exception as e:
        print(f"[api] Redis Stream consumer startup warning: {e}")

    # Auto-start live packet capture on primary active network interface on boot
    def _auto_start():
        time.sleep(1)
        auto_start_live_capture()
        
    threading.Thread(target=_auto_start, daemon=True).start()

    # Automatic Background Cloud Sync to Neon PostgreSQL (Zero manual scripts required)
    def _auto_cloud_sync():
        time.sleep(10)
        while True:
            try:
                sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
                from migrate_sqlite_to_pg import migrate_all
                success = migrate_all()
                time.sleep(30 if success else 120)
            except Exception:
                time.sleep(120)

    threading.Thread(target=_auto_cloud_sync, daemon=True).start()


@app.on_event("shutdown")
def shutdown():
    global capture_process
    if capture_process is not None and capture_process.poll() is None:
        capture_process.terminate()
    try:
        consumer_worker.stop()
    except Exception:
        pass


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
    tenant_id:  Optional[str]  = Field('default')

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
    full_name: Optional[str] = ""
    phone: Optional[str] = ""
    designation: Optional[str] = ""
    tenant_id: Optional[str] = None


class RefreshRequest(BaseModel):
    refresh_token: str


class UpdateRoleRequest(BaseModel):
    role: str


class AlertSettingsUpdateRequest(BaseModel):
    alert_to_email: str


class ExplainRequest(BaseModel):
    record: dict
    prediction: Optional[dict] = None


class AssistantQueryRequest(BaseModel):
    query: str


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
        "tenant_id":   payload.get("tenant_id") or "default",
        "permissions": ROLE_PERMISSIONS.get(payload["role"], [])
    }


# ── User Management (admin only) ──────────────────────────────

@app.post("/auth/users")
def register_user(req: RegisterRequest, request: Request):
    payload = require_permission(request, "manage_users")
    caller_tenant = (payload.get("tenant_id") if payload else None) or "default"
    
    # If caller is not SuperAdmin, lock assigned tenant to their own tenant
    if caller_tenant not in ("default", "*"):
        assigned_tenant = caller_tenant
    else:
        assigned_tenant = req.tenant_id or "default"

    return create_user(
        req.username, req.email, req.password, req.role,
        req.full_name, req.phone, req.designation,
        tenant_id=assigned_tenant
    )


@app.get("/auth/users")
def get_users(request: Request, tenant_id: Optional[str] = None):
    payload = require_permission(request, "manage_users")
    caller_tenant = (payload.get("tenant_id") if payload else None) or "default"
    
    # If caller is tenant admin (e.g. sharma_fabrics), they ONLY see their own users!
    if caller_tenant not in ("default", "*"):
        return {
            "users": list_users(tenant_id=caller_tenant),
            "caller_tenant": caller_tenant,
            "is_superadmin": False
        }
    
    # Caller is SuperAdmin: can view all or filter by tenant_id
    filter_tenant = None if (not tenant_id or tenant_id in ("*", "all")) else tenant_id
    return {
        "users": list_users(tenant_id=filter_tenant),
        "caller_tenant": caller_tenant,
        "is_superadmin": True,
        "selected_tenant": filter_tenant or "all"
    }


@app.get("/auth/tenants")
def get_tenants(request: Request):
    payload = require_permission(request, "view")
    caller_tenant = (payload.get("tenant_id") if payload else None) or "default"
    is_super = caller_tenant in ("default", "*")
    
    if not is_super:
        return {"tenants": [caller_tenant], "is_superadmin": False}
    
    all_tenants = list_tenants()
    return {"tenants": all_tenants, "is_superadmin": True}


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
    payload = require_permission(request, "manage_users")
    caller_tenant = (payload.get("tenant_id") if payload else None) or "default"
    if caller_tenant not in ("default", "*"):
        raise HTTPException(status_code=403, detail="Notification settings are reserved for SuperAdmin only")
    return get_alert_settings()


@app.patch("/admin/alert-settings")
def patch_admin_alert_settings(req: AlertSettingsUpdateRequest, request: Request):
    payload = require_permission(request, "manage_users")
    caller_tenant = (payload.get("tenant_id") if payload else None) or "default"
    if caller_tenant not in ("default", "*"):
        raise HTTPException(status_code=403, detail="Only SuperAdmin can configure global alert settings")
    email = req.alert_to_email.strip()
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Please provide a valid email address")
    return update_alert_to_email(email)


# ══════════════════════════════════════════════════════════════
# PREDICT ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.post("/predict")
def predict(record: TrafficRecord, http_request: Request):
    # Secure prediction endpoint: require agent key or client user token
    agent_key = http_request.headers.get("X-Agent-Key")
    if not (agent_key and hmac.compare_digest(agent_key, AGENT_SECRET_KEY)):
        require_permission(http_request, "view")
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
        tenant_id = getattr(record, "tenant_id", "default") or "default"
        result = detector.predict(data)
        handle_alert(result, source_ip, flow_id=record.flow_id or "", test_mode=record.test_mode, tenant_id=tenant_id)
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
    redis_active = bool(consumer_worker.client and consumer_worker.running)
    return {
        "status": "running",
        "model_loaded": detector._loaded,
        "redis_stream_buffer": {
            "active": redis_active,
            "worker_name": consumer_worker.consumer_name if redis_active else "inactive (fallback to direct HTTP)"
        }
    }


@app.get("/history")
@app.get("/detections")
def history(limit: int = 100, mode: str = "live", tenant_id: Optional[str] = None, request: Request = None):
    # Require "view" permission so viewer/analyst can access dashboard data
    payload = require_permission(request, "view")
    caller_tenant = (payload.get("tenant_id") if payload else None) or "default"
    
    if caller_tenant not in ("default", "*"):
        tenant = caller_tenant
    else:
        tenant = None if (tenant_id in ("all", "*")) else (tenant_id or caller_tenant)

    df = load_history(limit=limit, mode=mode, tenant_id=tenant)
    if df.empty and mode == "live":
        df = load_history(limit=limit, mode="all", tenant_id=tenant)
    return df.tail(limit).to_dict(orient="records")


@app.get("/stats")
def stats(mode: str = "live", limit: int | None = None, tenant_id: Optional[str] = None, request: Request = None):
    # Require "view" permission
    payload = require_permission(request, "view")
    caller_tenant = (payload.get("tenant_id") if payload else None) or "default"
    
    if caller_tenant not in ("default", "*"):
        tenant = caller_tenant
    else:
        tenant = None if (tenant_id in ("all", "*")) else (tenant_id or caller_tenant)

    df = load_history(limit=limit, mode=mode, tenant_id=tenant)
    if df.empty and mode == "live":
        df = load_history(limit=limit, mode="all", tenant_id=tenant)
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
    if get_windows_if_list is not None:
        try:
            for w_iface in (get_windows_if_list() or []):
                guid = w_iface.get("guid")
                if guid:
                    valid_interfaces.add(guid)
                    valid_interfaces.add(f"\\Device\\NPF_{guid}")
        except Exception:
            pass

    if iface_raw in ("eth0", "auto", "", "default") or (iface_clean not in valid_interfaces and iface_raw not in valid_interfaces):
        # Auto-fallback to active default interface if requested interface is eth0/auto or missing from valid list
        fallback = None
        if conf is not None and hasattr(conf, "iface") and conf.iface:
            fallback = str(getattr(conf.iface, "name", conf.iface))
        elif valid_interfaces:
            fallback = next(iter(valid_interfaces))

        if fallback:
            iface_raw = fallback
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Interface '{req.interface}' not found. Available: {sorted(valid_interfaces)}"
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
            "message": _capture_log_tail() or f"Capture failed on {iface_raw}",
        }
    return {"started": True, "message": f"Capture started on {iface_raw}"}


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

@app.get("/api/telegram/block", response_class=HTMLResponse)
def telegram_quick_block(ip: str, sig: str, expires: int = 0):
    """Secure, signed, time-limited block from Telegram alert."""
    current_ts = int(time.time())
    
    # 1. Expiration validation
    if expires and current_ts > expires:
        return HTMLResponse(
            status_code=403,
            content="""
            <html>
            <head>
                <style>
                    body { background-color: #0f172a; color: #f87171; font-family: sans-serif; text-align: center; padding-top: 100px; }
                    .card { background-color: #1e293b; border: 1px solid #ef4444; border-radius: 12px; display: inline-block; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                </style>
            </head>
            <body>
                <div class="card">
                    <h1>❌ Link Expired</h1>
                    <p>This quick-block link has expired. Please manage security blocks directly via the NetGuard Dashboard.</p>
                </div>
            </body>
            </html>
            """
        )

    # 2. Signature verification
    payload_with_exp = f"{ip}:{expires}".encode()
    expected_with_exp = hmac.new(SECRET_KEY.encode(), payload_with_exp, hashlib.sha256).hexdigest()[:16]
    expected_legacy = hmac.new(SECRET_KEY.encode(), ip.encode(), hashlib.sha256).hexdigest()[:16] if not expires else ""

    if not (hmac.compare_digest(sig, expected_with_exp) or (expected_legacy and hmac.compare_digest(sig, expected_legacy))):
         return HTMLResponse(
             status_code=403,
             content="""
             <html>
             <head>
                 <style>
                     body { background-color: #0f172a; color: #f87171; font-family: sans-serif; text-align: center; padding-top: 100px; }
                     .card { background-color: #1e293b; border: 1px solid #ef4444; border-radius: 12px; display: inline-block; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                 </style>
             </head>
             <body>
                 <div class="card">
                     <h1>❌ Signature Verification Failed</h1>
                     <p>The quick-block signature is invalid or tampered.</p>
                 </div>
             </body>
             </html>
             """
         )

    res = block_ip(ip, reason="Telegram Triage Action", blocked_by="telegram_admin", ttl_seconds=3600)
    
    if res["blocked"]:
        message_html = f"""
        <h1 style="color: #22d3a0;">✅ IP Successfully Blocked</h1>
        <p style="color: #94a3b8;">IP address <strong>{ip}</strong> has been temporarily blocked for 1 hour.</p>
        """
    else:
        message_html = f"""
        <h1 style="color: #f97316;">⚠️ Block Refused</h1>
        <p style="color: #94a3b8;">Reason: {res['message']}</p>
        """

    return HTMLResponse(
        content=f"""
        <html>
        <head>
            <style>
                body {{ background-color: #0f172a; color: #f1f5f9; font-family: sans-serif; text-align: center; padding-top: 100px; }}
                .card {{ background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; display: inline-block; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                strong {{ color: #38bdf8; }}
            </style>
        </head>
        <body>
            <div class="card">
                {message_html}
            </div>
        </body>
        </html>
        """
    )


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
@app.get("/blocklist")
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
    from scanner import full_scan, get_cached, validate_subnet
    if subnet:
        try:
            subnet = validate_subnet(subnet)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err))

    import threading
    result = {}
    error = {}
    def run():
        nonlocal result, error
        try:
            # full_scan internally does ping_sweep → arp_scan → nmap_scan
            result.update(full_scan(subnet))
        except Exception as exc:
            error["detail"] = str(exc)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=120)   # 2 min — ping sweep + nmap needs more time
    if error:
        raise HTTPException(status_code=500, detail=error["detail"])
    if t.is_alive():
        cached = get_cached()
        return {
            **cached,
            "partial": True,
            "scan_type": "full-timeout-cache",
            "message": "Full scan is still running; showing the latest cached devices.",
        }
    return result


@app.post("/network/scan/arp")
def scan_arp_only(request: Request, subnet: Optional[str] = None):
    """Quick scan: ping sweep + ARP only (no Nmap). Analyst or admin only."""
    require_permission(request, "capture")
    from scanner import arp_scan, update_cache, validate_subnet
    from datetime import datetime
    if subnet:
        try:
            subnet = validate_subnet(subnet)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err))
    devices = arp_scan(subnet, do_ping_sweep=False)
    timestamp = datetime.now().isoformat(timespec="seconds")
    update_cache(devices, timestamp)
    return {
        "devices":   devices,
        "total":     len(devices),
        "timestamp": timestamp,
        "scan_type": "arp+ping",
    }


# ══════════════════════════════════════════════════════════════
# LICENSING ENDPOINTS (COMMERCIAL MONETIZATION)
# ══════════════════════════════════════════════════════════════

class LicenseActivationRequest(BaseModel):
    key: str

@app.get("/api/license/status")
def get_license_status():
    val = get_active_license_status(force_refresh=True)
    return val.to_dict()

@app.post("/api/license/activate")
def activate_license(req: LicenseActivationRequest, request: Request):
    require_permission(request, "manage_users")
    val = validate_license(req.key.strip())
    if not val.is_valid:
        raise HTTPException(status_code=400, detail=val.message)

    try:
        LICENSE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LICENSE_KEY_PATH, "w", encoding="utf-8") as f:
            f.write(req.key.strip())
        os.environ["NETGUARD_LICENSE_KEY"] = req.key.strip()
        os.environ["LICENSE_KEY"] = req.key.strip()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save license key: {e}")

    return {
        "message": "License successfully activated!",
        "status": val.status.value,
        "tier": val.payload.tier.value if val.payload else None,
        "licensee": val.payload.licensee if val.payload else None,
        "max_devices": val.payload.max_devices if val.payload else None,
        "days_remaining": val.days_remaining
    }


# ══════════════════════════════════════════════════════════════
# EXPLAINABLE AI (XAI) & GENAI ASSISTANT ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.post("/explain")
def explain_traffic(req: ExplainRequest, request: Request):
    require_permission(request, "view")
    if not require_tier(LicenseTier.PRO):
        raise HTTPException(
            status_code=402,
            detail="Explainable AI diagnostics require Pro or Enterprise License Tier."
        )
    try:
        traffic_data = req.record
        if req.prediction:
            pred_res = req.prediction
        else:
            pred_res = detector.predict(traffic_data)
        explanation = explain_prediction(traffic_data, pred_res)
        return explanation
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/assistant/insights")
def assistant_insights(request: Request):
    require_permission(request, "view")
    if not require_tier(LicenseTier.ENTERPRISE):
        raise HTTPException(
            status_code=402,
            detail="GenAI Threat Assistant requires Enterprise License Tier."
        )
    try:
        return generate_threat_briefing()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/assistant/chat")
def assistant_chat(req: AssistantQueryRequest, request: Request):
    require_permission(request, "view")
    if not require_tier(LicenseTier.ENTERPRISE):
        raise HTTPException(
            status_code=402,
            detail="GenAI Assistant Chat requires Enterprise License Tier."
        )
    try:
        if not req.query.strip():
            raise HTTPException(status_code=400, detail="Query prompt cannot be empty")
        return process_copilot_query(req.query)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ══════════════════════════════════════════════════════════════
# RESEARCH & IEEE BENCHMARK METRICS ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.get("/research/metrics")
def get_research_metrics(request: Request):
    """Serve all pre-computed IEEE benchmarks, latencies, and real Edge-IIoTset results."""
    require_permission(request, "view")
    root_dir = Path(__file__).resolve().parent.parent
    results_search_dirs = [
        root_dir / "logs" / "benchmarks",
        root_dir / "logs" / "diagnostics",
    ]
    
    def load_json(name):
        import json
        for sdir in results_search_dirs:
            p = sdir / name
            if p.exists():
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    continue
        return {}

    return {
        "status": "ready",
        "baselines": load_json("baseline_comparison.json"),
        "edge_hardware": load_json("edge_hardware_profile.json"),
        "iot_protocols": load_json("iot_protocol_evaluation.json"),
        "edge_iiot_benchmark": load_json("edge_iiot_real_benchmark.json"),
        "figures": [
            "confusion_matrix_cascade.png",
            "roc_curves_multiclass.png",
            "pr_curves_multiclass.png",
            "shap_global_bar_importance.png",
            "shap_summary_beeswarm.png",
            "shap_waterfall_attack.png"
        ]
    }


@app.get("/research/figure/{filename}")
def get_research_figure(filename: str, request: Request, token: Optional[str] = None):
    """Serve high-resolution research plots for UI rendering safely with authentication and path confinement."""
    auth_token = get_token(request) or token
    if not auth_token:
        raise HTTPException(status_code=401, detail="Authentication required to view research figures")
    if not has_permission(auth_token, "view"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Sanitize and strictly confine to static/figures
    safe_name = os.path.basename(filename)
    if safe_name != filename or ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid figure filename")
    
    allowed_extensions = {".png", ".jpg", ".jpeg", ".svg"}
    if not any(safe_name.lower().endswith(ext) for ext in allowed_extensions):
        raise HTTPException(status_code=400, detail="Unsupported figure format")

    root_dir = Path(__file__).resolve().parent.parent
    figures_dir = (root_dir / "static" / "figures").resolve()
    target = (figures_dir / safe_name).resolve()

    if not target.is_relative_to(figures_dir):
        raise HTTPException(status_code=403, detail="Access denied")

    if target.exists() and target.is_file():
        media = "image/svg+xml" if safe_name.lower().endswith(".svg") else "image/png"
        return FileResponse(target, media_type=media)
    raise HTTPException(status_code=404, detail="Figure not found")


# ══════════════════════════════════════════════════════════════
# AUTOMATED PCAP FORENSICS & INDUSTRIAL DPI (PHASE 7)
# ══════════════════════════════════════════════════════════════

@app.get("/forensics/pcaps")
def get_forensic_pcaps(request: Request):
    """List all available automated incident PCAP captures for Wireshark analysis."""
    require_permission(request, "view")
    from pcap_forensics import list_forensic_pcaps
    return {"pcaps": list_forensic_pcaps()}


@app.get("/forensics/download/{filename}")
def download_forensic_pcap(filename: str, request: Request, token: Optional[str] = None):
    """Download an automated incident PCAP dump safely with path traversal defense."""
    auth_token = get_token(request) or token
    if not auth_token:
        raise HTTPException(status_code=401, detail="Authentication required")
    if not (has_permission(auth_token, "report") or has_permission(auth_token, "view")):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    safe_name = os.path.basename(filename)
    if safe_name != filename or ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid pcap filename")
    if not safe_name.lower().endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Only .pcap files are downloadable")

    root_dir = Path(__file__).resolve().parent.parent
    forensics_dir = (root_dir / "reports" / "forensics").resolve()
    target = (forensics_dir / safe_name).resolve()

    if not target.is_relative_to(forensics_dir):
        raise HTTPException(status_code=403, detail="Access denied")

    if target.exists() and target.is_file():
        return FileResponse(
            target,
            media_type="application/vnd.tcpdump.pcap",
            filename=safe_name,
            headers={"Content-Disposition": f'attachment; filename="{safe_name}"'}
        )
    raise HTTPException(status_code=404, detail="Forensic PCAP not found")


@app.post("/forensics/trigger-dump")
def manual_pcap_dump(request: Request, source_ip: str = "127.0.0.1", label: str = "MANUAL_INVESTIGATION"):
    """Manually trigger a 60-second forensic PCAP snapshot from the rolling packet buffer."""
    require_permission(request, "capture")
    from pcap_forensics import trigger_alert_pcap
    pcap_path = trigger_alert_pcap(source_ip=source_ip, prediction=label, severity="high")
    if pcap_path:
        return {"success": True, "pcap_path": os.path.basename(pcap_path), "message": "Forensic PCAP successfully captured"}
    return {"success": False, "message": "Packet buffer is currently empty or capture is offline"}


# ══════════════════════════════════════════════════════════════
# eBPF / XDP KERNEL CAPTURE ENDPOINTS (PHASE 7)
# ══════════════════════════════════════════════════════════════

class XdpBlockRequest(BaseModel):
    ip: str

@app.get("/capture/ebpf/status")
def get_ebpf_status(request: Request):
    """Retrieve kernel XDP capture status, 10Gbps line-rate metrics, and drop counts."""
    require_permission(request, "view")
    from ebpf_xdp import xdp_manager
    return xdp_manager.get_stats()


@app.post("/capture/ebpf/block")
def block_ip_ebpf(req: XdpBlockRequest, request: Request):
    """Add IP to line-rate XDP kernel drop table (zero-copy NIC drop)."""
    require_permission(request, "block_ip")
    from ebpf_xdp import xdp_manager
    ok = xdp_manager.block_ip(req.ip)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid IPv4 address")
    return {"success": True, "ip": req.ip, "message": "IP added to kernel XDP drop map"}


@app.post("/capture/ebpf/unblock")
def unblock_ip_ebpf(req: XdpBlockRequest, request: Request):
    """Remove IP from kernel XDP drop map."""
    require_permission(request, "unblock_ip")
    from ebpf_xdp import xdp_manager
    ok = xdp_manager.unblock_ip(req.ip)
    return {"success": True, "ip": req.ip, "message": "IP removed from kernel XDP drop map"}


# ══════════════════════════════════════════════════════════════
# LIGHTWEIGHT EDGE SENSOR PROBE INGESTION (PHASE 7)
# ══════════════════════════════════════════════════════════════

class EdgeStreamPayload(BaseModel):
    tenant_id: Optional[str] = "default"
    interface: Optional[str] = "eth0"
    flows: List[Dict[str, Any]]

@app.post("/sensor/stream")
def ingest_sensor_stream(payload: EdgeStreamPayload, request: Request):
    """
    Ingest real-time micro-flows streamed from C/Rust/Python edge sensor probes.
    Validates agent secret key and performs multi-tenant ML inference.
    """
    secret = request.headers.get("X-Agent-Secret") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if not (secret and hmac.compare_digest(secret, AGENT_SECRET_KEY)):
        raise HTTPException(status_code=401, detail="Unauthorized edge sensor probe")

    tenant = request.headers.get("X-Tenant-ID") or payload.tenant_id or "default"
    from predict import detector
    from detections_db import insert_detection

    processed = 0
    anomalies = 0

    for flow in payload.flows:
        src_ip = flow.get("src_ip", "127.0.0.1")
        pred = detector.predict(flow)
        processed += 1
        if pred.get("prediction") != "NORMAL":
            anomalies += 1
            insert_detection(pred, source_ip=src_ip, tenant_id=tenant)

    return {
        "success": True,
        "processed_flows": processed,
        "anomalies_detected": anomalies,
        "tenant_id": tenant
    }


# ══════════════════════════════════════════════════════════════
# REAL-TIME THREAT INTELLIGENCE (TI) ENDPOINTS (PHASE 8)
# ══════════════════════════════════════════════════════════════

class CustomIocRequest(BaseModel):
    ip: str
    actor: str
    score: Optional[float] = 0.95
    category: Optional[str] = "custom_c2"

@app.get("/threat-intel/lookup/{ip}")
def lookup_threat_intel(ip: str, request: Request):
    """Query real-time threat intelligence reputation for an IP."""
    require_permission(request, "view")
    from threat_intel import threat_intel
    return threat_intel.lookup_ip(ip)

@app.get("/threat-intel/status")
def threat_intel_status(request: Request):
    """Retrieve threat intelligence feed status, cache hit rates, and metrics."""
    require_permission(request, "view")
    from threat_intel import threat_intel
    return threat_intel.get_metrics()

@app.post("/threat-intel/feed/custom")
def add_custom_ioc_entry(req: CustomIocRequest, request: Request):
    """Add a verified IOC / C2 node to the active threat intelligence engine."""
    require_permission(request, "manage_users")
    from threat_intel import threat_intel
    threat_intel.add_custom_ioc(req.ip, req.actor, score=req.score or 0.95, category=req.category or "custom_c2")
    return {"success": True, "ip": req.ip, "actor": req.actor, "message": "Custom IOC registered in threat intelligence feed"}


# ══════════════════════════════════════════════════════════════
# CONTINUOUS RETRAINING & ACTIVE LEARNING ENDPOINTS (PHASE 8)
# ══════════════════════════════════════════════════════════════

class ActiveLearningFeedbackRequest(BaseModel):
    flow_features: Dict[str, Any]
    original_prediction: str
    analyst_label: str
    source_ip: Optional[str] = "unknown"

@app.post("/retrain/feedback")
def submit_active_learning_feedback(req: ActiveLearningFeedbackRequest, request: Request):
    """Submit an analyst correction/false positive for automated retraining."""
    require_permission(request, "report")
    actor = get_actor(request)
    from retrain_pipeline import active_learning
    return active_learning.submit_feedback(
        flow_features=req.flow_features,
        original_prediction=req.original_prediction,
        analyst_label=req.analyst_label,
        source_ip=req.source_ip or "unknown",
        reported_by=actor
    )

@app.get("/retrain/feedback")
def list_active_learning_feedback(request: Request, limit: int = 50):
    """List pending analyst-corrected samples queued for retraining."""
    require_permission(request, "view")
    from retrain_pipeline import active_learning
    return {
        "pending_samples": active_learning.get_pending_samples(limit=limit),
        "counts": active_learning.count_samples()
    }

@app.get("/retrain/drift-check")
def check_concept_drift(request: Request):
    """Run Kolmogorov-Smirnov test comparing live traffic distributions to baseline."""
    require_permission(request, "view")
    from retrain_pipeline import drift_detector
    from reporting import load_history
    recent = load_history(limit=100, mode="live")
    live_features = {}
    if not recent.empty:
        for feat in ["Flow Duration", "Tot Fwd Pkts", "TotLen Fwd Pkts"]:
            if feat in recent.columns:
                live_features[feat] = recent[feat].dropna().tolist()
    return drift_detector.evaluate_drift(live_features)

@app.post("/retrain/trigger")
def trigger_retraining_cycle(request: Request):
    """Trigger incremental continuous retraining cycle merging active learning queue."""
    require_permission(request, "manage_users")
    from retrain_pipeline import retrain_pipeline
    return retrain_pipeline.run_retrain_cycle()


# ══════════════════════════════════════════════════════════════
# DISTRIBUTED FLEET ORCHESTRATION ENDPOINTS (PHASE 8)
# ══════════════════════════════════════════════════════════════

class ProbeRegisterRequest(BaseModel):
    probe_id: str
    hostname: str
    tenant_id: Optional[str] = "default"
    ip_address: Optional[str] = "unknown"
    version: Optional[str] = "3.5.0-edge"
    interface: Optional[str] = "eth0"

class ProbeHeartbeatRequest(BaseModel):
    probe_id: str
    packets_seen: Optional[int] = 0
    flows_streamed: Optional[int] = 0
    cpu_usage_pct: Optional[float] = 0.0
    ram_usage_mb: Optional[float] = 0.0

class FleetRuleRequest(BaseModel):
    tenant_id: str
    rule: Dict[str, Any]

@app.post("/fleet/register")
def register_fleet_probe(req: ProbeRegisterRequest, request: Request):
    """Register an edge sensor probe with central NetGuard hub."""
    require_permission(request, "capture")
    from fleet_manager import fleet_manager
    return fleet_manager.register_probe(
        probe_id=req.probe_id,
        hostname=req.hostname,
        tenant_id=req.tenant_id or "default",
        ip_address=req.ip_address or "unknown",
        version=req.version or "3.5.0-edge",
        interface=req.interface or "eth0"
    )

@app.post("/fleet/heartbeat")
def probe_heartbeat(req: ProbeHeartbeatRequest, request: Request):
    """Receive probe telemetry heartbeat and return active policy rules."""
    from fleet_manager import fleet_manager
    return fleet_manager.record_heartbeat(
        probe_id=req.probe_id,
        packets_seen=req.packets_seen or 0,
        flows_streamed=req.flows_streamed or 0,
        cpu_usage_pct=req.cpu_usage_pct or 0.0,
        ram_usage_mb=req.ram_usage_mb or 0.0
    )

@app.get("/fleet/probes")
def get_fleet_probes(request: Request, tenant_id: Optional[str] = None):
    """List all connected fleet sensor probes, health status, and throughput."""
    payload = require_permission(request, "view")
    tenant = tenant_id or (payload.get("tenant_id") if payload else None)
    if tenant == "default":
        tenant = None
    from fleet_manager import fleet_manager
    return fleet_manager.get_fleet_overview(tenant_id=tenant)

@app.post("/fleet/rules")
def push_fleet_rule(req: FleetRuleRequest, request: Request):
    """Broadcast a dynamic DPI or firewall policy to edge sensor fleet."""
    require_permission(request, "manage_users")
    from fleet_manager import fleet_manager
    return fleet_manager.push_tenant_rule(req.tenant_id, req.rule)


# ══════════════════════════════════════════════════════════════
# ENTERPRISE SOAR SWITCH & VLAN QUARANTINE ENDPOINTS (PHASE 8)
# ══════════════════════════════════════════════════════════════

class SoarQuarantineRequest(BaseModel):
    ip: str
    mac: Optional[str] = ""
    switch_vendor: Optional[str] = "cisco"
    vlan_id: Optional[int] = 666
    reason: Optional[str] = "Automated NetGuard Threat Mitigation"

class SoarReleaseRequest(BaseModel):
    ip: str

@app.post("/soar/quarantine")
def isolate_endpoint_switch(req: SoarQuarantineRequest, request: Request):
    """Isolate an infected endpoint via switch ACL or dynamic 802.1X Quarantine VLAN."""
    require_permission(request, "block_ip")
    actor = get_actor(request)
    from switch_soar import switch_soar
    return switch_soar.quarantine_endpoint(
        ip_str=req.ip,
        mac_addr=req.mac or "",
        switch_vendor=req.switch_vendor or "cisco",
        vlan_id=req.vlan_id or 666,
        reason=req.reason or "Automated NetGuard Threat Mitigation",
        actor=actor
    )

@app.post("/soar/unquarantine")
def release_endpoint_switch(req: SoarReleaseRequest, request: Request):
    """Release an endpoint from switch quarantine and restore default VLAN connectivity."""
    require_permission(request, "unblock_ip")
    actor = get_actor(request)
    from switch_soar import switch_soar
    return switch_soar.release_endpoint(ip_str=req.ip, actor=actor)

@app.get("/soar/quarantined")
def get_quarantined_endpoints(request: Request):
    """List all currently isolated switch ports and quarantine VLAN assignments."""
    require_permission(request, "view")
    from switch_soar import switch_soar
    return {"quarantined_endpoints": switch_soar.list_quarantined_endpoints()}







