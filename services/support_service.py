# services/support_service.py
from __future__ import annotations

import sqlite3
from typing import Callable, Tuple

from helpers.db import get_db_connection
from schemas.support import SupportRequestInput
# Reuse the generic throttle table/logic that backs the feedback form.
from services.feedback_service import throttle_or_raise

VALID_SUPPORT_STATUSES = {"new", "replied", "resolved", "closed"}

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
