# conftest.py
import re
from flask.testing import FlaskClient
import os
import sys
import sqlite3
# --- make CSRF a no-op in tests (global) ---
import pytest
import flask_wtf.csrf as csrf_mod


_token_re = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')

# --- Ensure we're in test mode before importing the app ---
os.environ.setdefault("FLASK_ENV", "test")

# Make project root importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture(autouse=True)
def _disable_csrf(app, monkeypatch):
    # If CSRFProtect is registered on the app, disable its request hook
    ext = getattr(app, "extensions", {}).get("csrf")
    if ext:
        monkeypatch.setattr(ext, "protect", lambda: None, raising=False)

    # Also short-circuit direct validators some forms call
    monkeypatch.setattr(csrf_mod, "validate_csrf", lambda *a, **k: None, raising=False)


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("ENCRYPTION_KEY", "ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY=")

    from app import app as flask_app

    db_path = tmp_path / "test.db"
    flask_app.config.update(
        TESTING=True,
        PROPAGATE_EXCEPTIONS=True,
        SECRET_KEY="test-secret-key",
        DATABASE=str(db_path),
    )

    # Initialize schema on the temp DB (inside app context so get_db_connection sees app.config)
    from services.migrations import run_migrations
    from helpers.db import get_db_connection

    with flask_app.app_context():
        conn = get_db_connection()
        try:
            run_migrations(conn)
        finally:
            conn.close()

    yield flask_app

    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)


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


def _extract_csrf(html: str) -> str | None:
    m = _token_re.search(html or "")
    return m.group(1) if m else None


class CSRFClient(FlaskClient):
    _cached_csrf = None

    def _ensure_csrf(self, path_hint="/"):
        if self._cached_csrf:
            return self._cached_csrf
        for path in (path_hint, "/register", "/login", "/"):  # add common form pages
            resp = self.get(path)
            if resp.status_code == 200:
                token = _extract_csrf(resp.data.decode("utf-8", "ignore"))
                if token:
                    self._cached_csrf = token
                    return token
        # No token found — return empty string so posts still go through
        # (useful for API routes or if CSRF is off/exempt).
        return ""

    def _with_csrf(self, path, kwargs):
        # If the test already provided a token, leave it alone
        if "json" in kwargs:
            headers = kwargs.setdefault("headers", {})
            if "X-CSRFToken" not in headers and "X-CSRF-Token" not in headers:
                token = self._ensure_csrf(path)
                headers.setdefault("X-CSRFToken", token)
        else:
            data = kwargs.setdefault("data", {})
            if "csrf_token" not in data:
                token = self._ensure_csrf(path)
                data["csrf_token"] = token
        return kwargs

    def post(self, path, *args, **kwargs):
        kwargs = self._with_csrf(path, kwargs)
        return super().post(path, *args, **kwargs)

    def put(self, path, *args, **kwargs):
        kwargs = self._with_csrf(path, kwargs)
        return super().put(path, *args, **kwargs)

    def patch(self, path, *args, **kwargs):
        kwargs = self._with_csrf(path, kwargs)
        return super().patch(path, *args, **kwargs)

    def delete(self, path, *args, **kwargs):
        kwargs = self._with_csrf(path, kwargs)
        return super().delete(path, *args, **kwargs)


@pytest.fixture
def client(app):
    app.test_client_class = CSRFClient
    with app.test_client() as c:
        yield c
