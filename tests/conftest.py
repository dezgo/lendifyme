# conftest.py
import os
import sys
import sqlite3
import pytest


# --- Ensure we're in test mode before importing the app ---
os.environ.setdefault("FLASK_ENV", "test")

# Make project root importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture
def app(tmp_path, monkeypatch):
    """
    Create a test app configured to use an isolated temp DB file.
    Import AFTER env/test mode is set to avoid prod-side effects.
    """
    # Valid Fernet key for tests
    monkeypatch.setenv("ENCRYPTION_KEY", "ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY=")

    # Import the Flask app only now (after env is set)
    from app import app as flask_app

    db_path = tmp_path / "test.db"
    flask_app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret-key",
        DATABASE=str(db_path),  # single source of truth
    )

    # Initialize schema on the temp DB
    from services.migrations import run_migrations
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        run_migrations(conn)
    finally:
        conn.close()

    yield flask_app

    # Cleanup env var
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)


@pytest.fixture
def client(app):
    """Flask test client bound to the temp DB configured in `app`."""
    return app.test_client()


@pytest.fixture
def logged_in_client(app, client):
    from services.encryption import generate_encryption_salt
    from werkzeug.security import generate_password_hash

    db_path = app.config["DATABASE"]
    conn = sqlite3.connect(db_path)
    try:
        c = conn.cursor()

        # Generate encryption salt for password-based credential encryption
        encryption_salt = generate_encryption_salt()

        # Hash password for password-based authentication
        test_password = 'testpassword123'
        password_hash = generate_password_hash(test_password)

        # Insert user with basic fields first
        c.execute("""
            INSERT INTO users (email, name, recovery_codes, created_at, encryption_salt, password_hash)
            VALUES (?, ?, ?, datetime('now'), ?, ?)
        """, ('test@example.com', 'Test User', '[]', encryption_salt, password_hash))
        user_id = c.lastrowid

        # Explicitly set all verification and subscription fields to ensure they're set correctly
        c.execute("""
            UPDATE users
            SET email_verified = 1,
                onboarding_completed = 1,
                role = 'user',
                subscription_tier = 'pro'
            WHERE id = ?
        """, (user_id,))

        conn.commit()

        # Verify the email_verified flag was actually set
        c.execute("SELECT email_verified FROM users WHERE id = ?", (user_id,))
        result = c.fetchone()
        if not result or result[0] != 1:
            raise Exception(f"Failed to set email_verified for test user. Got: {result}")

    finally:
        conn.close()

    with client.session_transaction() as sess:
        sess['user_id'] = user_id
        sess['user_email'] = 'test@example.com'
        sess['user_name'] = 'Test User'
        sess['user_password'] = test_password  # Required for bank connection decryption

    return client
