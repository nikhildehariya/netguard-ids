#!/usr/bin/env python3
"""
NetGuard IDS — License Generator & Keypair Management Utility CLI
Usage:
  1. Generate Keypair:
     python scripts/generate_license.py --gen-keys [--key-type Ed25519|RSA]

  2. Issue License Key:
     python scripts/generate_license.py --issue --tier Pro --licensee "Acme Corp" --days 365 --devices 20 --output license.key
"""

import sys
import os
import time
import argparse
from pathlib import Path

# Add src to python path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

from license import (
    generate_ed25519_keypair,
    generate_rsa_keypair,
    issue_license,
    LicensePayload,
    LicenseTier,
    get_hardware_fingerprint
)
from config import KEYS_DIR, PUBLIC_KEY_PATH, PRIVATE_KEY_PATH, LICENSE_KEY_PATH


def main():
    parser = argparse.ArgumentParser(description="NetGuard IDS License Manager CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Command: gen-keys
    gen_keys_p = subparsers.add_parser("gen-keys", help="Generate Private & Public Keypair for signing licenses")
    gen_keys_p.add_argument("--key-type", choices=["Ed25519", "RSA"], default="Ed25519", help="Asymmetric algorithm type")

    # Command: issue
    issue_p = subparsers.add_parser("issue", help="Issue a signed license key")
    issue_p.add_argument("--tier", choices=["Trial", "Pro", "Enterprise"], default="Trial", help="License Tier")
    issue_p.add_argument("--licensee", default="Default Licensee", help="Name of client or organization")
    issue_p.add_argument("--days", type=int, default=14, help="License validity duration in days (0 for perpetual)")
    issue_p.add_argument("--devices", type=int, default=5, help="Max allowed devices (-1 for unlimited)")
    issue_p.add_argument("--features", default="", help="Comma-separated feature flags (e.g. genai,explainable)")
    issue_p.add_argument("--bind-hardware", action="store_true", help="Bind license to this machine's hardware ID")
    issue_p.add_argument("--priv-key", help="Path to private key PEM (default: keys/license_private_key.pem)")
    issue_p.add_argument("--out", help="Output file path (default: write to license.key and stdout)")

    # Command: print-hardware-id
    subparsers.add_parser("hardware-id", help="Print local machine hardware fingerprint ID")

    args = parser.parse_args()

    if args.command == "gen-keys":
        KEYS_DIR.mkdir(parents=True, exist_ok=True)
        if args.key_type == "Ed25519":
            priv, pub = generate_ed25519_keypair()
        else:
            priv, pub = generate_rsa_keypair(key_size=2048)

        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(priv)
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(pub)

        print(f" Successfully generated {args.key_type} keypair:")
        print(f"   Private Key: {PRIVATE_KEY_PATH}")
        print(f"   Public Key:  {PUBLIC_KEY_PATH}")

    elif args.command == "issue":
        priv_key_path = Path(args.priv_key) if args.priv_key else PRIVATE_KEY_PATH
        if not priv_key_path.exists():
            print(f"❌ Error: Private key not found at {priv_key_path}. Run 'gen-keys' command first.")
            sys.exit(1)

        with open(priv_key_path, "rb") as f:
            priv_pem = f.read()

        now = int(time.time())
        expires_at = (now + args.days * 24 * 3600) if args.days > 0 else None
        features = [f.strip() for f in args.features.split(",") if f.strip()]
        hardware_id = get_hardware_fingerprint() if args.bind_hardware else None

        payload = LicensePayload(
            license_id=os.urandom(8).hex(),
            licensee=args.licensee,
            tier=LicenseTier(args.tier),
            issued_at=now,
            expires_at=expires_at,
            max_devices=args.devices,
            hardware_id=hardware_id,
            features=features
        )

        license_key = issue_license(payload, priv_pem)

        out_path = Path(args.out) if args.out else LICENSE_KEY_PATH
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(license_key)

        print(" Generated License Key Successfully:")
        print(f"   Licensee:    {args.licensee}")
        print(f"   Tier:        {args.tier}")
        print(f"   Expires:     {time.strftime('%Y-%m-%d', time.gmtime(expires_at)) if expires_at else 'Perpetual'}")
        print(f"   Max Devices: {'Unlimited' if args.devices == -1 else args.devices}")
        print(f"   Saved to:    {out_path}")
        print("\nLicense Key:")
        print(license_key)

    elif args.command == "hardware-id":
        print(f"Hardware Fingerprint ID: {get_hardware_fingerprint()}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
