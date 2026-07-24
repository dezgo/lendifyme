# services/support_service.py
from __future__ import annotations

import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional, Tuple

from helpers.db import get_db_connection
from schemas.support import SupportRequestInput
# Reuse the generic throttle table/logic that backs the feedback form.
from services.feedback_service import throttle_or_raise

VALID_SUPPORT_STATUSES = {"new", "replied", "resolved", "closed"}

# How long an emailed live-session link stays valid.
LIVE_TOKEN_TTL_MINUTES = 30

# ---- Connection factory (dependency injection) ------------------------------
ConnFactory = Callable[[], sqlite3.Connection]


def default_conn_factory() -> sqlite3.Connection:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    return conn


# ---- Public service API -----------------------------------------------------
def submit_support_request(
    data: SupportRequestInput,
    conn_factory: ConnFactory = default_conn_factory,
) -> Tuple[int, str]:
    """
    Throttle, then persist a support request.

    Returns (support_request_id, "created"). Raises ValidationError(429) if the
    per-window submission limit is exceeded.
    """
    conn = conn_factory()
    try:
        throttle_key = f"support:{data.user_id}" if data.user_id else f"support-ip:{data.ip_addr}"
        throttle_or_raise(conn, throttle_key)

        cur = conn.execute(
            """
            INSERT INTO support_requests (
              subject, message, user_id, user_email, ip_address, user_agent,
              page_url, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'new', CURRENT_TIMESTAMP)
            """,
            (
                data.subject,
                data.message,
                data.user_id,
                data.user_email,
                data.ip_addr,
                data.user_agent,
                data.page_url,
            ),
        )
        conn.commit()
        return cur.lastrowid, "created"
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---- Admin dashboard queries ------------------------------------------------
def list_support_requests(
    include_closed: bool = False,
    limit: int = 100,
    conn_factory: ConnFactory = default_conn_factory,
) -> list[sqlite3.Row]:
    """Return stored support requests, newest first, for the admin dashboard."""
    conn = conn_factory()
    try:
        if include_closed:
            rows = conn.execute(
                "SELECT * FROM support_requests ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM support_requests WHERE status != 'closed' "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return list(rows)
    finally:
        conn.close()


def get_support_request(
    request_id: int,
    conn_factory: ConnFactory = default_conn_factory,
) -> Optional[sqlite3.Row]:
    """Fetch a single support request by id, or None."""
    conn = conn_factory()
    try:
        return conn.execute(
            "SELECT * FROM support_requests WHERE id = ?", (request_id,)
        ).fetchone()
    finally:
        conn.close()


# ---- Live-session tokens (offline email-link path) --------------------------
def issue_live_token(
    request_id: int,
    ttl_minutes: int = LIVE_TOKEN_TTL_MINUTES,
    conn_factory: ConnFactory = default_conn_factory,
) -> Tuple[str, datetime]:
    """
    Mint a fresh, time-boxed live-session token for a support request and store
    it. Returns (token, expires_at_utc). Overwrites any previous token so an
    older emailed link stops working once a new one is issued.
    """
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
    conn = conn_factory()
    try:
        conn.execute(
            "UPDATE support_requests SET live_token = ?, live_token_expires_at = ? "
            "WHERE id = ?",
            (token, expires_at.isoformat(), request_id),
        )
        conn.commit()
        return token, expires_at
    finally:
        conn.close()


def resolve_live_token(
    token: str,
    conn_factory: ConnFactory = default_conn_factory,
) -> Optional[sqlite3.Row]:
    """
    Return the support_requests row for a valid, unexpired token, else None.
    """
    if not token:
        return None
    conn = conn_factory()
    try:
        row = conn.execute(
            "SELECT * FROM support_requests WHERE live_token = ?", (token,)
        ).fetchone()
        if not row:
            return None

        expires_raw = row["live_token_expires_at"]
        if not expires_raw:
            return None
        try:
            expires_at = datetime.fromisoformat(expires_raw)
        except (TypeError, ValueError):
            return None
        # Stored value is timezone-aware UTC ISO; guard naive just in case.
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) >= expires_at:
            return None
        return row
    finally:
        conn.close()
