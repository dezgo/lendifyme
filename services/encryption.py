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


# ============================================================================
# Envelope Encryption (for loan data)
# ============================================================================

def generate_dek() -> bytes:
    """
    Generate a Data Encryption Key (DEK) for envelope encryption.

    This key is used to encrypt individual loan records. The DEK itself is then:
    - Encrypted with the lender's password (for lender access)
    - Embedded in the borrower access token (for borrower access)

    Returns:
        bytes: A 32-byte Fernet-compatible encryption key

    Example:
        >>> dek = generate_dek()
        >>> len(dek)
        44  # 32 bytes base64-encoded
    """
    return Fernet.generate_key()


def create_token_from_dek(dek: bytes) -> str:
    """
    Create a borrower access token from a DEK.

    The token is simply the DEK encoded as a URL-safe string. This allows
    borrowers to decrypt their loan data using just the unguessable URL.

    Args:
        dek: The data encryption key (32 bytes)

    Returns:
        str: URL-safe token containing the DEK

    Example:
        >>> dek = generate_dek()
        >>> token = create_token_from_dek(dek)
        >>> len(token)
        44  # Similar to old token length
    """
    return dek.decode('utf-8')  # DEK is already base64-urlsafe encoded


def extract_dek_from_token(token: str) -> bytes:
    """
    Extract the DEK from a borrower access token.

    Args:
        token: The borrower access token from the URL

    Returns:
        bytes: The data encryption key

    Raises:
        ValueError: If token is invalid

    Example:
        >>> dek = generate_dek()
        >>> token = create_token_from_dek(dek)
        >>> extracted_dek = extract_dek_from_token(token)
        >>> extracted_dek == dek
        True
    """
    try:
        return token.encode('utf-8')
    except Exception as e:
        raise ValueError(f"Invalid borrower access token: {e}")


def encrypt_dek_with_password(dek: bytes, password: str, salt_b64: str) -> str:
    """
    Encrypt a DEK with the user's password for lender access.

    This allows the lender to decrypt their loan data using their password,
    while the borrower can decrypt using just the token.

    Args:
        dek: The data encryption key to encrypt
        password: User's password
        salt_b64: User's encryption salt from database

    Returns:
        str: Encrypted DEK safe for database storage

    Example:
        >>> dek = generate_dek()
        >>> salt = generate_encryption_salt()
        >>> encrypted = encrypt_dek_with_password(dek, "mypass", salt)
    """
    user_key = derive_key_from_password(password, salt_b64)
    f = Fernet(user_key)
    return f.encrypt(dek).decode()


def decrypt_dek_with_password(encrypted_dek: str, password: str, salt_b64: str) -> bytes:
    """
    Decrypt a DEK using the user's password.

    Args:
        encrypted_dek: The encrypted DEK from database
        password: User's password
        salt_b64: User's encryption salt from database

    Returns:
        bytes: The decrypted data encryption key

    Raises:
        cryptography.fernet.InvalidToken: If password is wrong

    Example:
        >>> dek = generate_dek()
        >>> salt = generate_encryption_salt()
        >>> encrypted = encrypt_dek_with_password(dek, "mypass", salt)
        >>> decrypted = decrypt_dek_with_password(encrypted, "mypass", salt)
        >>> decrypted == dek
        True
    """
    user_key = derive_key_from_password(password, salt_b64)
    f = Fernet(user_key)
    return f.decrypt(encrypted_dek.encode())


def encrypt_field(value: str, dek: bytes) -> str:
    """
    Encrypt a single field value using a DEK.

    Args:
        value: The plaintext value to encrypt (will be converted to string)
        dek: The data encryption key

    Returns:
        str: Encrypted value safe for database storage

    Example:
        >>> dek = generate_dek()
        >>> encrypted = encrypt_field("Alice", dek)
        >>> encrypted
        'gAAAAABh...'
    """
    if value is None:
        return None
    f = Fernet(dek)
    return f.encrypt(str(value).encode()).decode()


def decrypt_field(encrypted_value: str, dek: bytes) -> str:
    """
    Decrypt a single field value using a DEK.

    Args:
        encrypted_value: The encrypted value from database
        dek: The data encryption key

    Returns:
        str: The decrypted plaintext value

    Raises:
        cryptography.fernet.InvalidToken: If decryption fails

    Example:
        >>> dek = generate_dek()
        >>> encrypted = encrypt_field("Alice", dek)
        >>> decrypted = decrypt_field(encrypted, dek)
        >>> decrypted
        'Alice'
    """
    if encrypted_value is None:
        return None
    f = Fernet(dek)
    return f.decrypt(encrypted_value.encode()).decode()


# ============================================================================
# Master Recovery Key (for password recovery without data loss)
# ============================================================================

def generate_master_recovery_key() -> str:
    """
    Generate a strong master recovery key for password recovery.

    The master recovery key is a 32-character alphanumeric key that's shown
    to the user ONCE during registration. It allows password reset without
    data loss by providing an alternative way to decrypt DEKs.

    Returns:
        str: A 32-character recovery key (e.g., "a3f7d9e2b8c1...")

    Example:
        >>> key = generate_master_recovery_key()
        >>> len(key)
        32
    """
    # Generate 32 random bytes and convert to hex (64 chars), then take first 32
    # This gives us a strong 128-bit key that's easy to type
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


def encrypt_dek_with_recovery_key(dek: bytes, recovery_key: str, salt_b64: str) -> str:
    """
    Encrypt a DEK with the master recovery key.

    This creates a second encrypted copy of the DEK that can be used to
    reset the user's password without losing access to their data.

    Args:
        dek: The data encryption key to encrypt
        recovery_key: The master recovery key (32-character hex string)
        salt_b64: User's encryption salt from database

    Returns:
        str: Encrypted DEK safe for database storage in encrypted_dek_recovery

    Example:
        >>> dek = generate_dek()
        >>> recovery_key = generate_master_recovery_key()
        >>> salt = generate_encryption_salt()
        >>> encrypted = encrypt_dek_with_recovery_key(dek, recovery_key, salt)
    """
    # Derive a key from the recovery key using the same KDF as passwords
    # This ensures consistent encryption strength
    recovery_encryption_key = derive_key_from_password(recovery_key, salt_b64)
    f = Fernet(recovery_encryption_key)
    return f.encrypt(dek).decode()


def decrypt_dek_with_recovery_key(encrypted_dek_recovery: str, recovery_key: str, salt_b64: str) -> bytes:
    """
    Decrypt a DEK using the master recovery key.

    Used during password reset to decrypt all DEKs and re-encrypt them
    with the new password.

    Args:
        encrypted_dek_recovery: The encrypted DEK from loans.encrypted_dek_recovery
        recovery_key: The master recovery key (provided by user)
        salt_b64: User's encryption salt from database

    Returns:
        bytes: The decrypted data encryption key

    Raises:
        cryptography.fernet.InvalidToken: If recovery key is wrong

    Example:
        >>> dek = generate_dek()
        >>> recovery_key = generate_master_recovery_key()
        >>> salt = generate_encryption_salt()
        >>> encrypted = encrypt_dek_with_recovery_key(dek, recovery_key, salt)
        >>> decrypted = decrypt_dek_with_recovery_key(encrypted, recovery_key, salt)
        >>> decrypted == dek
        True
    """
    # Derive key from recovery key using same KDF
    recovery_encryption_key = derive_key_from_password(recovery_key, salt_b64)
    f = Fernet(recovery_encryption_key)
    return f.decrypt(encrypted_dek_recovery.encode())
