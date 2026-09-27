import sys
import os
import hashlib
from pathlib import Path

# Load SECRET_KEY from .env
env_path = Path(__file__).resolve().parent.parent / ".env"
secret_key = "DEFAULT_SECRET_KEY_FOR_NETGUARD_IDS_PROJECT"

if env_path.exists():
    with open(env_path, "r") as f:
        for line in f:
            if line.strip().startswith("SECRET_KEY="):
                secret_key = line.split("SECRET_KEY=")[1].strip().replace("\"", "").replace("'", "")
                break

print("=======================================================")
print("  NetGuard IDS - Commercial License Key Generator      ")
print("=======================================================")

client_name = input("Enter Client/Institute Name: ").strip()
if not client_name:
    print("Client name cannot be empty.")
    sys.exit(1)

exp_date_str = input("Enter Expiration Date (Format: YYYYMMDD, e.g., 20261231): ").strip()
if len(exp_date_str) != 8 or not exp_date_str.isdigit():
    print("Invalid date format. Must be YYYYMMDD.")
    sys.exit(1)

# Generate checksum based on expiration date and SECRET_KEY
checksum = hashlib.sha256(f"{exp_date_str}-{secret_key}".encode()).hexdigest()[:6].upper()
license_key = f"NETGUARD-{exp_date_str}-{checksum}"

print("\n-------------------------------------------------------")
print(f"License Key generated successfully for: {client_name}")
print(f"Expiration Date: {exp_date_str[:4]}-{exp_date_str[4:6]}-{exp_date_str[6:]}")
print("-------------------------------------------------------")
print(f"LICENSE KEY:  {license_key}")
print("-------------------------------------------------------")
print("Provide this key to your client. When they enter it, the")
print("dashboard will unlock and link their software to this date.")
print("=======================================================")
