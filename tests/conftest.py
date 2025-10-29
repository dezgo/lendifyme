import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from app import app as flask_app
import sqlite3


@pytest.fixture
def app():
    """Create test app with secret key and encryption key."""
    flask_app.config['TESTING'] = True
    flask_app.config['SECRET_KEY'] = 'test-secret-key'

    # Set encryption key for tests (valid Fernet key)
    os.environ['ENCRYPTION_KEY'] = 'ISO-GA14bRMefte-maLgDXga80SEn-M_Lz-MSLP5fhY='

    yield flask_app

    # Clean up
    if 'ENCRYPTION_KEY' in os.environ:
        del os.environ['ENCRYPTION_KEY']


@pytest.fixture
def client(app, tmpdir):
    """Create test client with temporary database."""
    db_path = str(tmpdir.join('test.db'))
    app.config['DATABASE'] = db_path

    with app.test_client() as client:
        # Initialize database with migrations
        conn = sqlite3.connect(db_path)
        from services.migrations import run_migrations
        run_migrations(conn)
        conn.close()

        yield client


@pytest.fixture
def logged_in_client(client, tmpdir):
    """Create logged-in client with user session."""
    db_path = tmpdir.join('test.db')
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()

    # Create user
    c.execute("""
        INSERT INTO users (email, name, recovery_codes, created_at)
        VALUES (?, ?, ?, datetime('now'))
    """, ('test@example.com', 'Test User', '[]'))
    user_id = c.lastrowid
    conn.commit()
    conn.close()

    # Set session
    with client.session_transaction() as sess:
        sess['user_id'] = user_id
        sess['user_email'] = 'test@example.com'
        sess['user_name'] = 'Test User'

    return client
