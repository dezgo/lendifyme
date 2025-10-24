import os
import tempfile
import pytest
from app import app as flask_app
import sqlite3

@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp()
    flask_app.config['TESTING'] = True
    flask_app.config['DATABASE'] = db_path

    with flask_app.test_client() as client:
        with flask_app.app_context():
            conn = sqlite3.connect(db_path)
            from services.migrations import run_migrations
            run_migrations(conn)
            conn.close()
        yield client

    os.close(db_fd)
    os.unlink(db_path)

def test_form_submission(client):
    response = client.post('/', data={
        'borrower': 'Alice',
        'amount': '120.50',
        'note': 'For groceries',
        'date_borrowed': '2025-10-25'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Alice' in response.data
    assert b'120.5' in response.data
    assert b'For groceries' in response.data
    assert b'2025-10-25' in response.data
