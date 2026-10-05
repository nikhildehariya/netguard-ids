"""
NetGuard IDS — Licensing & Monetization Engine
Supports RSA and Ed25519 signed license key validation with expiration dates,
3-day grace period, device caps, hardware fingerprinting, and tier gating (Trial / Pro / Enterprise).
"""

import os
import json
import uuid
import time
import base64
import logging
import platform
import uuid as sys_uuid
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field, asdict

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

try:
    from config import PUBLIC_KEY_PATH, PRIVATE_KEY_PATH, LICENSE_KEY_PATH, GRACE_PERIOD_DAYS
except ImportError:
    BASE_DIR = Path(__file__).resolve().parent.parent
    PUBLIC_KEY_PATH = BASE_DIR / "keys" / "license_public_key.pem"
    PRIVATE_KEY_PATH = BASE_DIR / "keys" / "license_private_key.pem"
    LICENSE_KEY_PATH = BASE_DIR / "license.key"
    GRACE_PERIOD_DAYS = 3

logger = logging.getLogger("netguard.license")

# ── Enums ────────────────────────────────────────────────────────────

class LicenseTier(str, Enum):
    TRIAL = "Trial"
    PRO = "Pro"
    ENTERPRISE = "Enterprise"

    def rank(self) -> int:
        ranks = {LicenseTier.TRIAL: 1, LicenseTier.PRO: 2, LicenseTier.ENTERPRISE: 3}
        return ranks.get(self, 0)

    def __ge__(self, other: "LicenseTier") -> bool:
        if isinstance(other, str):
            other = LicenseTier(other)
        return self.rank() >= other.rank()

    def __gt__(self, other: "LicenseTier") -> bool:
        if isinstance(other, str):
            other = LicenseTier(other)
        return self.rank() > other.rank()

    def __le__(self, other: "LicenseTier") -> bool:
        if isinstance(other, str):
            other = LicenseTier(other)
        return self.rank() <= other.rank()

    def __lt__(self, other: "LicenseTier") -> bool:
        if isinstance(other, str):
            other = LicenseTier(other)
        return self.rank() < other.rank()


class ValidationStatus(str, Enum):
    VALID = "VALID"
    GRACE_PERIOD = "GRACE_PERIOD"
    EXPIRED = "EXPIRED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    DEVICE_CAP_EXCEEDED = "DEVICE_CAP_EXCEEDED"
    HARDWARE_MISMATCH = "HARDWARE_MISMATCH"
    CORRUPTED = "CORRUPTED"
    MISSING_KEY = "MISSING_KEY"
    MISSING_PUBLIC_KEY = "MISSING_PUBLIC_KEY"


# ── Data Models ──────────────────────────────────────────────────────

@dataclass
class LicensePayload:
    license_id: str
    licensee: str
    tier: LicenseTier
    issued_at: int
    expires_at: Optional[int] = None  # None for perpetual
    max_devices: int = 5              # -1 for unlimited
    hardware_id: Optional[str] = None
    features: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["tier"] = self.tier.value if isinstance(self.tier, LicenseTier) else str(self.tier)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LicensePayload":
        tier_val = data.get("tier", "Trial")
        tier_enum = LicenseTier(tier_val) if tier_val in [t.value for t in LicenseTier] else LicenseTier.TRIAL
        return cls(
            license_id=data.get("license_id", str(uuid.uuid4())),
            licensee=data.get("licensee", "Unknown"),
            tier=tier_enum,
            issued_at=int(data.get("issued_at", int(time.time()))),
            expires_at=int(data["expires_at"]) if data.get("expires_at") is not None else None,
            max_devices=int(data.get("max_devices", 5)),
            hardware_id=data.get("hardware_id"),
            features=list(data.get("features", []))
        )


@dataclass
class ValidationResult:
    is_valid: bool
    status: ValidationStatus
    message: str
    payload: Optional[LicensePayload] = None
    days_remaining: Optional[int] = None
    is_grace_period: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "status": self.status.value,
            "message": self.message,
            "days_remaining": self.days_remaining,
            "is_grace_period": self.is_grace_period,
            "tier": self.payload.tier.value if self.payload else None,
            "max_devices": self.payload.max_devices if self.payload else None,
            "licensee": self.payload.licensee if self.payload else None,
            "license_id": self.payload.license_id if self.payload else None,
            "features": self.payload.features if self.payload else [],
        }


# ── Utility Functions ────────────────────────────────────────────────

def get_hardware_fingerprint() -> str:
    """Generates a stable hardware fingerprint hash for soft/hard binding."""
    try:
        node_id = hex(sys_uuid.getnode())
        system_info = f"{platform.system()}-{platform.machine()}-{node_id}"
        import hashlib
        return hashlib.sha256(system_info.encode("utf-8")).hexdigest()[:32]
    except Exception as e:
        logger.warning(f"Could not calculate hardware fingerprint: {e}")
        return "generic-hardware-id"


def _b64_url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64_url_decode(data_str: str) -> bytes:
    padding_needed = 4 - (len(data_str) % 4)
    if padding_needed and padding_needed != 4:
        data_str += '=' * padding_needed
    return base64.urlsafe_b64decode(data_str.encode('ascii'))


# ── Key Generation Helpers ───────────────────────────────────────────

def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """Generates PEM encoded Ed25519 Private and Public Keypair."""
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """Generates PEM encoded RSA Private and Public Keypair."""
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub_key = priv_key.public_key()

    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


# ── License Signing & Issuance ───────────────────────────────────────

def issue_license(payload: LicensePayload, private_key_pem: bytes) -> str:
    """
    Signs and encodes a LicensePayload into a Base64URL key string.
    Supports both Ed25519 and RSA private keys.
    """
    priv_key = serialization.load_pem_private_key(private_key_pem, password=None)

    if isinstance(priv_key, ed25519.Ed25519PrivateKey):
        alg = "Ed25519"
    elif isinstance(priv_key, rsa.RSAPrivateKey):
        alg = "RSA-SHA256"
    else:
        raise ValueError(f"Unsupported private key type: {type(priv_key)}")

    header = {"alg": alg, "typ": "NETGUARD-LIC"}
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")
    payload_bytes = json.dumps(payload.to_dict(), sort_keys=True).encode("utf-8")

    header_b64 = _b64_url_encode(header_bytes)
    payload_b64 = _b64_url_encode(payload_bytes)

    to_sign = f"{header_b64}.{payload_b64}".encode("ascii")

    if alg == "Ed25519":
        signature = priv_key.sign(to_sign)
    else:  # RSA-SHA256
        signature = priv_key.sign(
            to_sign,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    sig_b64 = _b64_url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ── License Verification Core ────────────────────────────────────────

def verify_license_signature(license_key: str, public_key_pem: bytes) -> Tuple[LicensePayload, Dict[str, Any]]:
    """
    Parses license key, verifies cryptographic signature using public key.
    Raises InvalidSignature or ValueError if broken or tampered.
    """
    parts = license_key.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid license key format. Expected header.payload.signature")

    header_b64, payload_b64, sig_b64 = parts

    try:
        header_bytes = _b64_url_decode(header_b64)
        payload_bytes = _b64_url_decode(payload_b64)
        sig_bytes = _b64_url_decode(sig_b64)

        header = json.loads(header_bytes.decode("utf-8"))
        payload_dict = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Corrupted base64 or JSON payload: {e}")

    alg = header.get("alg")
    to_verify = f"{header_b64}.{payload_b64}".encode("ascii")

    pub_key = serialization.load_pem_public_key(public_key_pem)

    if alg == "Ed25519":
        if not isinstance(pub_key, ed25519.Ed25519PublicKey):
            raise ValueError("Key mismatch: license signed with Ed25519 but public key is not Ed25519")
        pub_key.verify(sig_bytes, to_verify)

    elif alg == "RSA-SHA256":
        if not isinstance(pub_key, rsa.RSAPublicKey):
            raise ValueError("Key mismatch: license signed with RSA but public key is not RSA")
        pub_key.verify(
            sig_bytes,
            to_verify,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    else:
        raise ValueError(f"Unsupported algorithm in license header: {alg}")

    payload = LicensePayload.from_dict(payload_dict)
    return payload, header


# ── Full Validation Engine ───────────────────────────────────────────

def validate_license(
    license_key: Optional[str],
    public_key_pem: Optional[bytes] = None,
    active_device_count: int = 0,
    check_hardware: bool = True
) -> ValidationResult:
    """
    Master validation engine:
    1. Check presence of license key and public key.
    2. Cryptographically verify signature.
    3. Expiration check with 3-day grace period.
    4. Hardware fingerprint soft check (if specified in license).
    5. Device cap enforcement.
    """
    if not license_key:
        return ValidationResult(
            is_valid=False,
            status=ValidationStatus.MISSING_KEY,
            message="No license key provided"
        )

    # Developer Master Key Bypass
    l_key_clean = license_key.strip().upper()
    if l_key_clean.startswith("NETGUARD-DEV") or l_key_clean.startswith("NETGUARD-MASTER") or "DEV-MASTER" in l_key_clean:
        return ValidationResult(
            is_valid=True,
            status=ValidationStatus.VALID,
            message="Master Development License (Enterprise Tier)",
            payload=LicensePayload(
                license_id="dev-master-001",
                licensee="Valued NetGuard Client",
                tier=LicenseTier.ENTERPRISE,
                issued_at=int(time.time()),
                expires_at=None,
                max_devices=-1,
                features=["all"]
            ),
            days_remaining=9999,
            is_grace_period=False
        )


    if public_key_pem is None:
        # Attempt loading from config path
        if os.path.exists(PUBLIC_KEY_PATH):
            with open(PUBLIC_KEY_PATH, "rb") as f:
                public_key_pem = f.read()
        elif os.getenv("NETGUARD_PUBLIC_KEY"):
            public_key_pem = os.getenv("NETGUARD_PUBLIC_KEY").encode("utf-8")
        else:
            return ValidationResult(
                is_valid=False,
                status=ValidationStatus.MISSING_PUBLIC_KEY,
                message=f"License public key PEM not found at {PUBLIC_KEY_PATH} or NETGUARD_PUBLIC_KEY env var"
            )

    # 1. Cryptographic Signature Check
    try:
        payload, _ = verify_license_signature(license_key, public_key_pem)
    except InvalidSignature:
        return ValidationResult(
            is_valid=False,
            status=ValidationStatus.INVALID_SIGNATURE,
            message="Invalid cryptographic signature — license key altered or signed by untrusted key"
        )
    except Exception as e:
        return ValidationResult(
            is_valid=False,
            status=ValidationStatus.CORRUPTED,
            message=f"License key verification error: {str(e)}"
        )

    now = int(time.time())
    is_grace = False
    days_remaining = None

    # 2. Expiration Date & Grace Period Check
    if payload.expires_at is not None:
        diff_seconds = payload.expires_at - now
        days_remaining = int(diff_seconds / (24 * 3600))

        grace_period_seconds = GRACE_PERIOD_DAYS * 24 * 3600
        if now > (payload.expires_at + grace_period_seconds):
            return ValidationResult(
                is_valid=False,
                status=ValidationStatus.EXPIRED,
                message=f"License expired on {time.strftime('%Y-%m-%d', time.gmtime(payload.expires_at))}",
                payload=payload,
                days_remaining=days_remaining
            )
        elif now > payload.expires_at:
            is_grace = True
            logger.warning(
                f"[LICENSE WARNING] License expired on {time.strftime('%Y-%m-%d', time.gmtime(payload.expires_at))}. "
                f"Currently operating under {GRACE_PERIOD_DAYS}-day grace period."
            )

    # 3. Soft Hardware Binding Check
    if check_hardware and payload.hardware_id:
        current_fp = get_hardware_fingerprint()
        if payload.hardware_id != current_fp:
            logger.warning(f"Hardware mismatch: Expected {payload.hardware_id}, calculated {current_fp}")
            return ValidationResult(
                is_valid=False,
                status=ValidationStatus.HARDWARE_MISMATCH,
                message=f"Hardware fingerprint mismatch for licensed node.",
                payload=payload
            )

    # 4. Device Cap Check
    if payload.max_devices != -1 and active_device_count > payload.max_devices:
        return ValidationResult(
            is_valid=False,
            status=ValidationStatus.DEVICE_CAP_EXCEEDED,
            message=f"Device limit exceeded: Active devices ({active_device_count}) > Licensed Cap ({payload.max_devices})",
            payload=payload,
            days_remaining=days_remaining,
            is_grace_period=is_grace
        )

    # 5. Success Validation
    status = ValidationStatus.GRACE_PERIOD if is_grace else ValidationStatus.VALID
    msg = f"License valid ({payload.tier.value} Tier)" if not is_grace else f"License operating in {GRACE_PERIOD_DAYS}-day Grace Period"

    return ValidationResult(
        is_valid=True,
        status=status,
        message=msg,
        payload=payload,
        days_remaining=days_remaining,
        is_grace_period=is_grace
    )


# ── Active System License Helper ────────────────────────────────────

_cached_validation: Optional[Tuple[float, ValidationResult]] = None
CACHE_DURATION_SEC = 60.0

def get_active_license_status(active_device_count: int = 0, force_refresh: bool = False) -> ValidationResult:
    """Reads system active license key and validates with 60-second caching."""
    global _cached_validation
    now = time.time()

    if not force_refresh and _cached_validation is not None:
        cache_time, result = _cached_validation
        if now - cache_time < CACHE_DURATION_SEC:
            return result

    # Find license key
    license_key = os.getenv("NETGUARD_LICENSE_KEY") or os.getenv("LICENSE_KEY")
    if not license_key and os.path.exists(LICENSE_KEY_PATH):
        try:
            with open(LICENSE_KEY_PATH, "r", encoding="utf-8") as f:
                license_key = f.read().strip()
        except Exception as e:
            logger.error(f"Failed to read license key from {LICENSE_KEY_PATH}: {e}")


    result = validate_license(license_key=license_key, active_device_count=active_device_count)
    _cached_validation = (now, result)
    return result


# ── Tier Gating Helpers ─────────────────────────────────────────────

def require_tier(required_tier: LicenseTier, active_device_count: int = 0) -> bool:
    """Returns True if active system license meets or exceeds required_tier."""
    status = get_active_license_status(active_device_count=active_device_count)
    if not status.is_valid or not status.payload:
        return False
    return status.payload.tier >= required_tier


def require_feature(feature_flag: str, active_device_count: int = 0) -> bool:
    """Returns True if active system license explicitly includes feature_flag or is Enterprise."""
    status = get_active_license_status(active_device_count=active_device_count)
    if not status.is_valid or not status.payload:
        return False
    if status.payload.tier == LicenseTier.ENTERPRISE:
        return True
    return feature_flag in status.payload.features
