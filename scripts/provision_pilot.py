# =============================================================
# provision_pilot.py — NetGuard IDS v2.2
# Automated Commercial Pilot Onboarding & License Provisioner
# =============================================================

import sys
import os
import argparse
import time
from pathlib import Path

# Add src to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

from license import issue_license, LicensePayload, LicenseTier, generate_ed25519_keypair, generate_rsa_keypair
from auth import create_user, list_users
from database import get_db_connection, release_db_connection


def provision_pilot_customer(company_name: str, admin_email: str, admin_password: str,
                             tier_name: str = "PRO", duration_days: int = 30,
                             max_devices: int = 50, output_dir: str = "pilot_deployments"):
    """
    Provisions a complete enterprise pilot deployment package:
    1. Dedicated Organization Tenant ID
    2. Tenant Administrator Account
    3. Asymmetrically Signed 30-Day Commercial License Key
    4. Client-Ready Deployment Config (.env.pilot)
    """
    tenant_id = company_name.lower().replace(" ", "_").replace("-", "_")
    tier_enum = getattr(LicenseTier, tier_name.upper(), LicenseTier.PRO)

    print(f"\n=======================================================")
    print(f"  🛡️ Provisioning NetGuard Pilot for: {company_name}")
    print(f"  🏢 Tenant ID: {tenant_id}")
    print(f"  🏷️ Tier: {tier_name.upper()} ({duration_days} days)")
    print(f"=======================================================\n")

    # 1. Create Tenant Admin User
    admin_username = f"admin_{tenant_id}"
    user_res = create_user(
        username=admin_username,
        email=admin_email,
        password=admin_password,
        role="admin",
        full_name=f"{company_name} Security Admin",
        designation="SOC Manager",
        tenant_id=tenant_id
    )
    if user_res.get("success"):
        print(f"✅ Created Tenant Administrator: {admin_username} ({admin_email})")
    else:
        print(f"ℹ️ Admin user status: {user_res.get('message')}")

    # 2. Key Generation & Commercial License Issuance
    priv_key, pub_key = generate_ed25519_keypair()
    now = int(time.time())
    expires = now + (duration_days * 86400)

    features = ["explainable_ai", "export_pdf", "threat_copilot", "auto_containment"]
    if tier_name.upper() == "ENTERPRISE":
        features.extend(["unlimited_devices", "custom_siem", "all"])

    payload = LicensePayload(
        license_id=f"PILOT-{tenant_id.upper()}-{int(time.time())}",
        licensee=company_name,
        tier=tier_enum,
        issued_at=now,
        expires_at=expires,
        max_devices=max_devices,
        features=features
    )

    license_key = issue_license(payload, priv_key)
    print(f"✅ Generated Cryptographic License Token (Valid until: {time.ctime(expires)})")

    # 3. Export Pilot Customer Deliverables
    out_path = BASE_DIR / output_dir / tenant_id
    out_path.mkdir(parents=True, exist_ok=True)

    with open(out_path / "license.key", "w", encoding="utf-8") as f:
        f.write(license_key if isinstance(license_key, str) else license_key.decode("utf-8"))

    with open(out_path / "license_public_key.pem", "wb") as f:
        f.write(pub_key if isinstance(pub_key, bytes) else pub_key.encode("utf-8"))

    pilot_env = f"""# NetGuard Pilot Environment Config: {company_name}
TENANT_ID={tenant_id}
COMPANY_NAME="{company_name}"
API_PORT=8081
LICENSE_KEY_PATH=./license.key
PUBLIC_KEY_PATH=./license_public_key.pem
AUTO_BLOCK_ENABLED=True
AUTO_BLOCK_CONFIDENCE=0.90
"""
    with open(out_path / ".env.pilot", "w", encoding="utf-8") as f:
        f.write(pilot_env)

    print(f"📁 Exported Pilot Assets to: {out_path.resolve()}")
    print(f"   ├── license.key")
    print(f"   ├── license_public_key.pem")
    print(f"   └── .env.pilot\n")

    return {
        "tenant_id": tenant_id,
        "admin_username": admin_username,
        "license_key": license_key,
        "out_dir": str(out_path)
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetGuard Commercial Pilot Provisioner")
    parser.add_argument("--company", required=True, help="Customer Company Name")
    parser.add_argument("--email", required=True, help="SOC Admin Email")
    parser.add_argument("--password", required=True, help="Initial Temporary Password")
    parser.add_argument("--tier", default="PRO", choices=["PRO", "ENTERPRISE", "TRIAL"])
    parser.add_argument("--days", type=int, default=30, help="Trial duration in days")
    parser.add_argument("--devices", type=int, default=50, help="Max monitored devices")

    args = parser.parse_args()
    provision_pilot_customer(
        company_name=args.company,
        admin_email=args.email,
        admin_password=args.password,
        tier_name=args.tier,
        duration_days=args.days,
        max_devices=args.devices
    )
