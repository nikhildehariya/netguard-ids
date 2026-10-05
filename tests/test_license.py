"""
NetGuard IDS — Unit Tests for Licensing & Monetization Engine
"""

import sys
import os
import time
from pathlib import Path

# Add src to python path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

import unittest
from license import (
    generate_ed25519_keypair,
    generate_rsa_keypair,
    issue_license,
    validate_license,
    verify_license_signature,
    get_hardware_fingerprint,
    LicensePayload,
    LicenseTier,
    ValidationStatus,
    require_tier,
    require_feature
)


class TestLicenseEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ed_priv, cls.ed_pub = generate_ed25519_keypair()
        cls.rsa_priv, cls.rsa_pub = generate_rsa_keypair(key_size=2048)

    def test_ed25519_license_issuance_and_validation(self):
        payload = LicensePayload(
            license_id="test-ed-123",
            licensee="Test Organization",
            tier=LicenseTier.PRO,
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 3600,
            max_devices=10,
            features=["explainable_ai", "export_pdf"]
        )
        license_key = issue_license(payload, self.ed_priv)
        res = validate_license(license_key, public_key_pem=self.ed_pub, active_device_count=5)

        self.assertTrue(res.is_valid)
        self.assertEqual(res.status, ValidationStatus.VALID)
        self.assertEqual(res.payload.tier, LicenseTier.PRO)
        self.assertEqual(res.payload.max_devices, 10)
        self.assertIn("explainable_ai", res.payload.features)

    def test_rsa_license_issuance_and_validation(self):
        payload = LicensePayload(
            license_id="test-rsa-456",
            licensee="Enterprise Client",
            tier=LicenseTier.ENTERPRISE,
            issued_at=int(time.time()),
            expires_at=None,  # Perpetual
            max_devices=-1,   # Unlimited
            features=["genai_assistant", "all"]
        )
        license_key = issue_license(payload, self.rsa_priv)
        res = validate_license(license_key, public_key_pem=self.rsa_pub, active_device_count=100)

        self.assertTrue(res.is_valid)
        self.assertEqual(res.status, ValidationStatus.VALID)
        self.assertEqual(res.payload.tier, LicenseTier.ENTERPRISE)
        self.assertEqual(res.payload.max_devices, -1)

    def test_tampered_license_signature_rejection(self):
        payload = LicensePayload(
            license_id="test-tamper",
            licensee="Hacker",
            tier=LicenseTier.TRIAL,
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 3600
        )
        license_key = issue_license(payload, self.ed_priv)

        # Modify payload part of token
        parts = license_key.split(".")
        tampered_key = f"{parts[0]}.eyJaYWNrZXIiOiB0cnVlfQ.{parts[2]}"

        res = validate_license(tampered_key, public_key_pem=self.ed_pub)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.status, ValidationStatus.INVALID_SIGNATURE)

    def test_expired_license_and_grace_period(self):
        now = int(time.time())

        # Case A: Expired 1 day ago (within 3-day grace period)
        grace_payload = LicensePayload(
            license_id="grace-1",
            licensee="Grace Client",
            tier=LicenseTier.PRO,
            issued_at=now - (10 * 86400),
            expires_at=now - (1 * 86400),
            max_devices=10
        )
        grace_key = issue_license(grace_payload, self.ed_priv)
        res_grace = validate_license(grace_key, public_key_pem=self.ed_pub)
        self.assertTrue(res_grace.is_valid)
        self.assertTrue(res_grace.is_grace_period)
        self.assertEqual(res_grace.status, ValidationStatus.GRACE_PERIOD)

        # Case B: Expired 5 days ago (beyond 3-day grace period)
        expired_payload = LicensePayload(
            license_id="expired-1",
            licensee="Expired Client",
            tier=LicenseTier.PRO,
            issued_at=now - (30 * 86400),
            expires_at=now - (5 * 86400),
            max_devices=10
        )
        expired_key = issue_license(expired_payload, self.ed_priv)
        res_exp = validate_license(expired_key, public_key_pem=self.ed_pub)
        self.assertFalse(res_exp.is_valid)
        self.assertEqual(res_exp.status, ValidationStatus.EXPIRED)

    def test_device_cap_exceeded(self):
        payload = LicensePayload(
            license_id="device-cap-test",
            licensee="Small Business",
            tier=LicenseTier.PRO,
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 3600,
            max_devices=5
        )
        key = issue_license(payload, self.ed_priv)

        # 5 devices -> Valid
        res_ok = validate_license(key, public_key_pem=self.ed_pub, active_device_count=5)
        self.assertTrue(res_ok.is_valid)

        # 6 devices -> Exceeded
        res_fail = validate_license(key, public_key_pem=self.ed_pub, active_device_count=6)
        self.assertFalse(res_fail.is_valid)
        self.assertEqual(res_fail.status, ValidationStatus.DEVICE_CAP_EXCEEDED)

    def test_hardware_fingerprint_matching(self):
        fp = get_hardware_fingerprint()
        payload_correct = LicensePayload(
            license_id="hw-1",
            licensee="Node Bound",
            tier=LicenseTier.PRO,
            issued_at=int(time.time()),
            hardware_id=fp
        )
        key_correct = issue_license(payload_correct, self.ed_priv)
        res_ok = validate_license(key_correct, public_key_pem=self.ed_pub, check_hardware=True)
        self.assertTrue(res_ok.is_valid)

        # Mismatched HW ID
        payload_wrong = LicensePayload(
            license_id="hw-2",
            licensee="Wrong Node",
            tier=LicenseTier.PRO,
            issued_at=int(time.time()),
            hardware_id="invalid-hardware-fingerprint-12345"
        )
        key_wrong = issue_license(payload_wrong, self.ed_priv)
        res_wrong = validate_license(key_wrong, public_key_pem=self.ed_pub, check_hardware=True)
        self.assertFalse(res_wrong.is_valid)
        self.assertEqual(res_wrong.status, ValidationStatus.HARDWARE_MISMATCH)

    def test_tier_ordering_and_access(self):
        self.assertTrue(LicenseTier.PRO >= LicenseTier.TRIAL)
        self.assertTrue(LicenseTier.ENTERPRISE >= LicenseTier.PRO)
        self.assertFalse(LicenseTier.TRIAL >= LicenseTier.PRO)


if __name__ == "__main__":
    unittest.main()
