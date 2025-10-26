"""
Authentication helpers for passwordless auth:
- Passkeys (WebAuthn/FIDO2)
- Magic links (email)
- Recovery codes
"""

import secrets
import hashlib
import json
from datetime import datetime, timedelta
from typing import List, Optional, Tuple


def generate_recovery_codes(count: int = 10) -> Tuple[List[str], str]:
    """
    Generate recovery codes for emergency access.

    Returns:
        Tuple of (plain_codes, hashed_codes_json)
        - plain_codes: List of codes to show user once
        - hashed_codes_json: JSON string of hashed codes to store in DB
    """
    plain_codes = []
    hashed_codes = []

    for _ in range(count):
        # Generate 8-character alphanumeric code
        code = secrets.token_urlsafe(6)[:8].upper()
        plain_codes.append(code)

        # Hash the code before storing
        hashed = hashlib.sha256(code.encode()).hexdigest()
        hashed_codes.append(hashed)

    return plain_codes, json.dumps(hashed_codes)


def verify_recovery_code(code: str, hashed_codes_json: str) -> Tuple[bool, Optional[str]]:
    """
    Verify a recovery code and return updated list without the used code.

    Args:
        code: The recovery code to verify
        hashed_codes_json: JSON string of hashed codes from DB

    Returns:
        Tuple of (is_valid, updated_hashed_codes_json)
        - is_valid: True if code is valid
        - updated_hashed_codes_json: New JSON with used code removed (or None if invalid)
    """
    if not hashed_codes_json:
        return False, None

    hashed_codes = json.loads(hashed_codes_json)
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    if code_hash in hashed_codes:
        # Remove the used code
        hashed_codes.remove(code_hash)
        return True, json.dumps(hashed_codes)

    return False, None


def generate_magic_link_token() -> str:
    """Generate a secure token for magic link."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Hash a token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def get_magic_link_expiry(minutes: int = 15) -> str:
    """Get expiry timestamp for magic link."""
    expiry = datetime.now() + timedelta(minutes=minutes)
    return expiry.isoformat()


def is_magic_link_expired(expires_at: str) -> bool:
    """Check if magic link has expired."""
    expiry = datetime.fromisoformat(expires_at)
    return datetime.now() > expiry
