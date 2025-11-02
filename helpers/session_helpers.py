"""
Session and user-related helper functions.
"""
from flask import session
import sqlite3


def get_db_path():
    """Get database path (imported from app for now)."""
    import os
    ENV = os.getenv('FLASK_ENV', 'production')
    if ENV == 'test':
        return os.getenv('TEST_DB_PATH', 'test_lendifyme.db')
    return 'lendifyme.db'


def get_current_user_id():
    """Get the current logged-in user's ID from session."""
    return session.get('user_id')


def is_email_verified():
    """Check if current user has verified their email."""
    user_id = get_current_user_id()
    if not user_id:
        return False

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT email_verified FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    return result and result[0] == 1


def get_unverified_loan_count():
    """Get the number of loans an unverified user has created."""
    user_id = get_current_user_id()
    if not user_id:
        return 0

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM loans WHERE user_id = ?", (user_id,))
    count = c.fetchone()[0]
    conn.close()

    return count


def get_user_encryption_salt():
    """Get the current user's encryption salt from database."""
    user_id = get_current_user_id()
    if not user_id:
        return None

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT encryption_salt FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    return result[0] if result else None


def get_user_password_from_session():
    """Get the user's password from session (needed for decryption)."""
    return session.get('user_password')
