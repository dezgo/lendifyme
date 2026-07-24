"""
Tests for Phase 2 opportunistic live support:
  - live-session token issue/resolve (offline email-link path)
  - admin "start live" route (online banner vs offline email)
  - the user-facing /support/live page (token + ownership checks)
"""
import sqlite3

import pytest

import services.email_sender as email_sender
from services.support_service import (
    issue_live_token,
    resolve_live_token,
    list_support_requests,
    get_support_request,
)


# ---- helpers ---------------------------------------------------------------
def _cf(app):
    """A conn_factory bound to the test DB (Row rows), for service-layer calls."""
    def factory():
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.row_factory = sqlite3.Row
        return conn
    return factory


def _insert_request(app, user_id=4242, email="borrower@example.com",
                    subject="Help", message="I'm stuck", status="new"):
    conn = sqlite3.connect(app.config["DATABASE"])
    try:
        cur = conn.execute(
            "INSERT INTO support_requests "
            "(user_id, user_email, subject, message, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, datetime('now'))",
            (user_id, email, subject, message, status),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def _user_id(app, email="test@example.com"):
    conn = sqlite3.connect(app.config["DATABASE"])
    try:
        return conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()[0]
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def _clean_state():
    """Keep module-level presence/session dicts from leaking between tests."""
    from routes import support
    support.online_users.clear()
    support.live_sessions.clear()
    yield
    support.online_users.clear()
    support.live_sessions.clear()


@pytest.fixture
def admin_client(app, client):
    from services.encryption import generate_encryption_salt
    conn = sqlite3.connect(app.config["DATABASE"])
    try:
        cur = conn.execute(
            "INSERT INTO users (email, name, recovery_codes, created_at, "
            "encryption_salt, role, email_verified, onboarding_completed) "
            "VALUES (?, ?, ?, datetime('now'), ?, 'admin', 1, 1)",
            ("admin@example.com", "Admin", "[]", generate_encryption_salt()),
        )
        conn.commit()
        admin_id = cur.lastrowid
    finally:
        conn.close()
    with client.session_transaction() as sess:
        sess["user_id"] = admin_id
        sess["user_email"] = "admin@example.com"
        sess["is_admin"] = True
    return client


# ---- service: tokens -------------------------------------------------------
def test_issue_and_resolve_live_token(app):
    with app.app_context():
        rid = _insert_request(app)
        cf = _cf(app)
        token, _ = issue_live_token(rid, ttl_minutes=30, conn_factory=cf)
        assert token

        row = resolve_live_token(token, conn_factory=cf)
        assert row is not None
        assert row["id"] == rid


def test_resolve_unknown_token_returns_none(app):
    with app.app_context():
        assert resolve_live_token("nope", conn_factory=_cf(app)) is None
        assert resolve_live_token("", conn_factory=_cf(app)) is None


def test_resolve_expired_token_returns_none(app):
    with app.app_context():
        rid = _insert_request(app)
        cf = _cf(app)
        token, _ = issue_live_token(rid, ttl_minutes=-1, conn_factory=cf)  # already expired
        assert resolve_live_token(token, conn_factory=cf) is None


def test_list_and_get_support_request(app):
    with app.app_context():
        cf = _cf(app)
        rid = _insert_request(app, subject="Findable")
        _insert_request(app, subject="Closed one", status="closed")

        open_rows = list_support_requests(conn_factory=cf)
        subjects = {r["subject"] for r in open_rows}
        assert "Findable" in subjects
        assert "Closed one" not in subjects  # closed hidden by default

        all_rows = list_support_requests(include_closed=True, conn_factory=cf)
        assert "Closed one" in {r["subject"] for r in all_rows}

        one = get_support_request(rid, conn_factory=cf)
        assert one["subject"] == "Findable"


# ---- route: admin start-live ----------------------------------------------
def test_start_live_offline_sends_email(app, admin_client, monkeypatch):
    sent = []

    def _fake_invite(**kwargs):
        sent.append(kwargs)
        return True, "stubbed"

    monkeypatch.setattr(email_sender, "send_live_support_invite_email", _fake_invite)

    rid = _insert_request(app, email="offliner@example.com")
    resp = admin_client.post(f"/admin/support/{rid}/start-live")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert body["mode"] == "email"

    # Email actually attempted with a join link.
    assert len(sent) == 1
    assert "join_link" in sent[0] and "token=" in sent[0]["join_link"]

    # A token was persisted.
    row = get_support_request(rid, conn_factory=_cf(app))
    assert row["live_token"]


def test_start_live_online_pushes_banner(app, admin_client, monkeypatch):
    from routes import support

    rid = _insert_request(app, user_id=777, email="online@example.com")
    # Mark the user online.
    support.online_users[777] = {"sid-1"}

    captured = {}
    socketio = app.extensions["socketio"]
    monkeypatch.setattr(
        socketio, "emit",
        lambda event, data, **kw: captured.update(event=event, data=data, room=kw.get("room")),
    )

    resp = admin_client.post(f"/admin/support/{rid}/start-live")
    assert resp.status_code == 200
    assert resp.get_json()["mode"] == "banner"
    assert captured["event"] == "live_invite"
    assert captured["room"] == "user_777"
    assert captured["data"]["request_id"] == rid


def test_start_live_not_found(app, admin_client):
    resp = admin_client.post("/admin/support/999999/start-live")
    assert resp.status_code == 404


def test_start_live_offline_no_email_is_rejected(app, admin_client):
    rid = _insert_request(app, email=None)
    resp = admin_client.post(f"/admin/support/{rid}/start-live")
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False


def test_start_live_requires_admin(app, logged_in_client):
    rid = _insert_request(app)
    resp = logged_in_client.post(f"/admin/support/{rid}/start-live")
    # Non-admin is redirected away by @admin_required.
    assert resp.status_code in (301, 302)


# ---- route: user /support/live --------------------------------------------
def test_support_live_valid_token_renders(app, logged_in_client):
    uid = _user_id(app)
    rid = _insert_request(app, user_id=uid)
    token, _ = issue_live_token(rid, conn_factory=_cf(app))

    resp = logged_in_client.get(f"/support/live?token={token}")
    assert resp.status_code == 200
    assert b"Live chat" in resp.data


def test_support_live_expired_token_redirects(app, logged_in_client):
    uid = _user_id(app)
    rid = _insert_request(app, user_id=uid)
    token, _ = issue_live_token(rid, ttl_minutes=-1, conn_factory=_cf(app))

    resp = logged_in_client.get(f"/support/live?token={token}")
    assert resp.status_code == 302


def test_support_live_wrong_owner_redirects(app, logged_in_client):
    # Request owned by a different user than the logged-in one.
    rid = _insert_request(app, user_id=999999)
    resp = logged_in_client.get(f"/support/live?r={rid}")
    assert resp.status_code == 302


def test_support_live_requires_login(app, client):
    resp = client.get("/support/live?r=1")
    assert resp.status_code in (301, 302)
    assert "/login" in resp.headers["Location"]


def test_admin_support_lists_requests(app, admin_client):
    _insert_request(app, subject="ListMeOnDashboard")
    resp = admin_client.get("/admin/support")
    assert resp.status_code == 200
    assert b"ListMeOnDashboard" in resp.data
