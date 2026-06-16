"""
totp.py — TOTP helper for Google Authenticator
------------------------------------------------
3 simple functions used everywhere else:
  1. generate_totp_secret()  → creates a new random secret
  2. get_totp_uri(...)       → builds the otpauth:// link (used to make QR code)
  3. verify_totp_code(...)   → checks if the 6-digit code the user typed is valid
"""

import pyotp


def generate_totp_secret() -> str:
    """
    Creates a new random Base32 secret string.
    This gets saved in the database against the user.
    Example output: "JBSWY3DPEHPK3PXP"
    """
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str, issuer: str = "Domain Security Scanner") -> str:
    """
    Builds the otpauth:// URI that encodes into a QR code.
    The frontend library (e.g. qrcode.js) turns this URI into a scannable QR code.

    Example output:
      otpauth://totp/Domain%20Security%20Scanner:user@example.com?secret=JBSWY3...&issuer=Domain%20Security%20Scanner
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Checks whether the 6-digit code the user entered is valid RIGHT NOW.

    valid_window=1 means we also accept the code from 30 seconds
    before/after the current window — handles minor clock drift.

    Returns True if valid, False if not.
    """
    normalized_code = ''.join(ch for ch in str(code).strip() if ch.isdigit())
    totp = pyotp.TOTP(secret)
    return totp.verify(normalized_code, valid_window=2)