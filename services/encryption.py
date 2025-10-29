# services/encryption.py
"""
Encryption utilities for securely storing bank API credentials.

Uses Fernet (symmetric encryption) from the cryptography library.
ENCRYPTION_KEY must be set in .env file.

Generate a key with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

from cryptography.fernet import Fernet
import os
import json


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
