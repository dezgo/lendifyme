"""
Tests for the async support request form (GET/POST /support).

These cover the async front door only — the Socket.IO/WebRTC live path is
exercised elsewhere and is no longer auto-triggered by this page.
"""
import sqlite3

import pytest

import services.email_sender as email_sender


@pytest.fixture(autouse=True)
def _stub_support_email(monkeypatch):
    """Never hit the network in tests; capture the call instead."""
    calls = []

    def _fake_send(**kwargs):
        calls.append(kwargs)
        return True, "stubbed"

    # Ensure the route attempts to notify the admin (it no-ops without this).
    monkeypatch.setenv("ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setattr(email_sender, "send_support_request_email", _fake_send)
    return calls


def _rows(app):
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM support_requests ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


def test_get_support_renders_form(logged_in_client):
    resp = logged_in_client.get("/support")
    assert resp.status_code == 200
    body = resp.data.decode("utf-8", "ignore")
    assert 'name="message"' in body
    # Async promise is on the page, not a live spinner.
    assert "email" in body.lower()
    assert "Waiting for an agent" not in body


def test_get_support_requires_login(client):
    resp = client.get("/support")
    assert resp.status_code in (301, 302)
    assert "/login" in resp.headers["Location"]


def test_post_stores_request_and_redirects(app, logged_in_client, _stub_support_email):
    resp = logged_in_client.post(
        "/support",
        data={"subject": "Help with matching", "message": "I can't match a transaction."},
    )
    # Redirect to dashboard on success.
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")

    rows = _rows(app)
    assert len(rows) == 1
    row = rows[0]
    assert row["subject"] == "Help with matching"
    assert row["message"] == "I can't match a transaction."
    assert row["user_email"] == "test@example.com"
    assert row["status"] == "new"

    # Admin was notified with reply-to context.
    assert len(_stub_support_email) == 1
    assert _stub_support_email[0]["user_email"] == "test@example.com"
    assert _stub_support_email[0]["message"] == "I can't match a transaction."


def test_post_success_flash_shown_after_redirect(logged_in_client):
    resp = logged_in_client.post(
        "/support",
        data={"message": "Just a quick question."},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"your request has been sent" in resp.data.lower()


def test_post_empty_message_rejected(app, logged_in_client):
    resp = logged_in_client.post("/support", data={"message": "  "}, follow_redirects=True)
    assert resp.status_code == 200
    # Nothing stored.
    assert _rows(app) == []
    # Error surfaced to the user.
    assert b"describe your issue" in resp.data.lower()


def test_post_requires_login(client):
    resp = client.post("/support", data={"message": "hello there"})
    assert resp.status_code in (301, 302)
    assert "/login" in resp.headers["Location"]
