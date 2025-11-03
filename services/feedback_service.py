# services/feedback_service.py
from __future__ import annotations

import sqlite3
import time
from typing import Callable, Dict, List, Optional, Tuple

from helpers.utils import get_db_path
from schemas.feedback import FeedbackInput, ValidationError, ALLOWED_FEEDBACK_TYPES

# Throttle settings
THROTTLE_MAX = 5
THROTTLE_WINDOW_SECONDS = 600  # 10 minutes

# Admin status whitelist
VALID_FEEDBACK_STATUSES = {"new", "reviewed", "resolved", "closed"}

# ---- Connection factory (dependency injection) ------------------------------
ConnFactory = Callable[[], sqlite3.Connection]


def default_conn_factory() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


# ---- Throttle helpers -------------------------------------------------------
def ensure_throttle_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS feedback_throttle (
          key TEXT PRIMARY KEY,
          window_start INTEGER NOT NULL,
          count INTEGER NOT NULL
        )
        """
    )


def throttle_or_raise(conn: sqlite3.Connection, key: str, now: Optional[int] = None) -> None:
    """Raises ValidationError(429) if the per-window limit is exceeded."""
    ensure_throttle_table(conn)
    now = now or int(time.time())
    window = now // THROTTLE_WINDOW_SECONDS

    cur = conn.execute("SELECT window_start, count FROM feedback_throttle WHERE key = ?", (key,))
    row = cur.fetchone()
    if row is None or row["window_start"] != window:
        conn.execute(
            "REPLACE INTO feedback_throttle (key, window_start, count) VALUES (?, ?, ?)",
            (key, window, 1),
        )
    else:
        if row["count"] >= THROTTLE_MAX:
            raise ValidationError("Too many submissions. Please try again later.", status_code=429)
        conn.execute("UPDATE feedback_throttle SET count = count + 1 WHERE key = ?", (key,))


# ---- Public service API -----------------------------------------------------
def submit_feedback(
    data: FeedbackInput,
    conn_factory: ConnFactory = default_conn_factory,
) -> Tuple[int, str]:
    """
    Business logic: validate (already done by schema), throttle, insert.
    Returns (feedback_id, "created").
    """
    conn = conn_factory()
    try:
        throttle_key = f"user:{data.user_id}" if data.user_id else f"ip:{data.ip_addr}"
        throttle_or_raise(conn, throttle_key)

        cur = conn.execute(
            """
            INSERT INTO feedback (
              feedback_type, message, user_id, user_email, ip_address, user_agent,
              page_url, page_title, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', CURRENT_TIMESTAMP)
            """,
            (
                data.feedback_type,
                data.message,
                data.user_id,
                data.user_email,
                data.ip_addr,
                data.user_agent,
                data.page_url,
                data.page_title,
            ),
        )
        conn.commit()
        return cur.lastrowid, "created"
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def admin_feedback(
    status_filter: str = "all",
    page: int = 1,
    page_size: int = 50,
    conn_factory: ConnFactory = default_conn_factory,
) -> Tuple[List[dict], Dict[str, int], int]:
    """
    Returns (feedback_rows, status_counts, total_rows_for_filter)
    - status_filter: 'all' or a valid status
    - simple pagination with page/page_size
    """
    if status_filter != "all" and status_filter not in VALID_FEEDBACK_STATUSES:
        raise ValidationError("Invalid status filter.")

    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    offset = (page - 1) * page_size

    conn = conn_factory()
    try:
        # Counts by status (ensure zeros for missing)
        counts = {s: 0 for s in VALID_FEEDBACK_STATUSES}
        cur = conn.execute("SELECT status, COUNT(*) AS c FROM feedback GROUP BY status")
        for r in cur.fetchall():
            if r["status"] in counts:
                counts[r["status"]] = r["c"]

        # Total rows for current filter
        if status_filter == "all":
            total = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
            rows = conn.execute(
                """
                SELECT id, user_id, user_email, page_url, page_title,
                       feedback_type, message, status, created_at, admin_notes
                FROM feedback
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (page_size, offset),
            ).fetchall()
        else:
            total = conn.execute(
                "SELECT COUNT(*) FROM feedback WHERE status = ?", (status_filter,)
            ).fetchone()[0]
            rows = conn.execute(
                """
                SELECT id, user_id, user_email, page_url, page_title,
                       feedback_type, message, status, created_at, admin_notes
                FROM feedback
                WHERE status = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (status_filter, page_size, offset),
            ).fetchall()

        # Convert to plain dicts
        feedback_list = [
            {
                "id": r["id"],
                "user_id": r["user_id"],
                "user_email": r["user_email"],
                "page_url": r["page_url"],
                "page_title": r["page_title"],
                "feedback_type": r["feedback_type"],
                "message": r["message"],
                "status": r["status"],
                "created_at": r["created_at"],
                "admin_notes": r["admin_notes"],
            }
            for r in rows
        ]

        return feedback_list, counts, total
    finally:
        conn.close()


def admin_feedback_update(
    feedback_id: int,
    new_status: str,
    admin_notes: Optional[str],
    conn_factory: ConnFactory = default_conn_factory,
) -> int:
    """
    Update status and notes. Returns number of affected rows.
    """
    new_status = (new_status or "").strip().lower()
    if new_status not in VALID_FEEDBACK_STATUSES:
        raise ValidationError("Invalid status.")

    notes = (admin_notes or "").strip()
    if len(notes) > 4000:
        raise ValidationError("admin_notes too long.")

    conn = conn_factory()
    try:
        cur = conn.execute(
            """
            UPDATE feedback
            SET status = ?, admin_notes = ?
            WHERE id = ?
            """,
            (new_status, notes, feedback_id),
        )
        conn.commit()
        return cur.rowcount or 0
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
