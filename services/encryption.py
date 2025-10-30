# services/encryption.py
"""
Encryption utilities for securely storing bank API credentials.

Two modes:
1. Server-side encryption: Uses ENCRYPTION_KEY from .env (DEPRECATED for bank credentials)
2. Zero-knowledge encryption: Derives key from user's password (RECOMMENDED)

The zero-knowledge approach ensures server admins cannot access bank credentials,
as decryption is only possible when the user provides their password.
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import json
import secrets
import base64


def get_encryption_key():
    """
    Get the encryption key from environment variables.

    Returns:
        bytes: The encryption key

    Raises:
        ValueError: If ENCRYPTION_KEY is not set in environment
    """
    key = os.getenv('ENCRYPTION_KEY')
    if not key:
        raise ValueError(
            "ENCRYPTION_KEY not set in .env file. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return key.encode()


def encrypt_credentials(credentials_dict: dict) -> str:
    """
    Encrypt a credentials dictionary for secure storage.

    Args:
        credentials_dict: Dictionary containing credentials (e.g., {'api_key': '...'})

    Returns:
        str: Encrypted string safe for database storage

    Example:
        >>> creds = {'api_key': 'up:yeah:abc123'}
        >>> encrypted = encrypt_credentials(creds)
        >>> encrypted
        'gAAAAABh...'
    """
    f = Fernet(get_encryption_key())
    json_str = json.dumps(credentials_dict)
    encrypted = f.encrypt(json_str.encode())
    return encrypted.decode()


def decrypt_credentials(encrypted_str: str) -> dict:
    """
    Decrypt credentials back to a dictionary.

    Args:
        encrypted_str: Encrypted credentials string from database

    Returns:
        dict: Decrypted credentials dictionary

    Raises:
        cryptography.fernet.InvalidToken: If decryption fails (wrong key or corrupted data)

    Example:
        >>> encrypted = 'gAAAAABh...'
        >>> creds = decrypt_credentials(encrypted)
        >>> creds
        {'api_key': 'up:yeah:abc123'}
    """
    f = Fernet(get_encryption_key())
    decrypted = f.decrypt(encrypted_str.encode())
    return json.loads(decrypted.decode())


# ============================================================================
# Zero-Knowledge Encryption (Password-Based)
# ============================================================================

def generate_encryption_salt() -> str:
    """
    Generate a unique salt for password-based key derivation.

    Returns:
        str: Base64-encoded salt (safe for database storage)

    Example:
        >>> salt = generate_encryption_salt()
        >>> salt
        'rH8F2vP...'  # 32-byte salt, base64-encoded
    """
    salt = secrets.token_bytes(32)  # 256 bits
    return base64.b64encode(salt).decode()


def derive_key_from_password(password: str, salt_b64: str) -> bytes:
    """
    Derive a Fernet encryption key from a password and salt using PBKDF2.

    Args:
        password: User's password (plain text)
        salt_b64: Base64-encoded salt (from database)

    Returns:
        bytes: Derived Fernet-compatible encryption key

    Notes:
        - Uses PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP recommendation 2023)
        - Same password + salt always produces same key (deterministic)
        - Different salts produce different keys even with same password

    Example:
        >>> salt = generate_encryption_salt()
        >>> key = derive_key_from_password("mypassword123", salt)
        >>> len(key)
        44  # Fernet keys are 32 bytes + base64 encoding
    """
    salt = base64.b64decode(salt_b64.encode())

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet requires 32-byte keys
        salt=salt,
        iterations=600000,  # OWASP 2023 recommendation
    )

    key_bytes = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key_bytes)


def encrypt_credentials_with_password(credentials_dict: dict, password: str, salt_b64: str) -> str:
    """
    Encrypt credentials using a password-derived key (zero-knowledge encryption).

    Args:
        credentials_dict: Dictionary containing credentials (e.g., {'api_key': '...'})
        password: User's password (plain text)
        salt_b64: Base64-encoded salt from users.encryption_salt

    Returns:
        str: Encrypted string safe for database storage

    Example:
        >>> creds = {'api_key': 'up:yeah:abc123'}
        >>> salt = 'rH8F2vP...'  # from users.encryption_salt
        >>> encrypted = encrypt_credentials_with_password(creds, "mypass", salt)
        >>> encrypted
        'gAAAAABh...'
    """
    key = derive_key_from_password(password, salt_b64)
    f = Fernet(key)
    json_str = json.dumps(credentials_dict)
    encrypted = f.encrypt(json_str.encode())
    return encrypted.decode()


def decrypt_credentials_with_password(encrypted_str: str, password: str, salt_b64: str) -> dict:
    """
    Decrypt credentials using a password-derived key (zero-knowledge encryption).

    Args:
        encrypted_str: Encrypted credentials string from database
        password: User's password (plain text)
        salt_b64: Base64-encoded salt from users.encryption_salt

    Returns:
        dict: Decrypted credentials dictionary

    Raises:
        cryptography.fernet.InvalidToken: If decryption fails (wrong password or corrupted data)

    Example:
        >>> encrypted = 'gAAAAABh...'
        >>> salt = 'rH8F2vP...'  # from users.encryption_salt
        >>> creds = decrypt_credentials_with_password(encrypted, "mypass", salt)
        >>> creds
        {'api_key': 'up:yeah:abc123'}
    """
    key = derive_key_from_password(password, salt_b64)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_str.encode())
    return json.loads(decrypted.decode())
