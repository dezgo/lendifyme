"""
Analytics event logging.
"""
import json
from flask import session, current_app
from helpers.db import get_db_connection


def log_event(event_name, event_data=None, user_id=None):
    """
    Log an analytics event to the events table.

    Args:
        event_name: Name of the event (e.g., 'user_signed_up', 'loan_created')
        event_data: Optional dict with additional context (stored as JSON)
        user_id: Optional user ID (defaults to current user if logged in)
    """
    try:
        if user_id is None:
            user_id = session.get('user_id')

        session_id = session.get('_id', None)
        event_data_json = json.dumps(event_data) if event_data else None

        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO events (event_name, user_id, session_id, event_data)
            VALUES (?, ?, ?, ?)
            """,
            (event_name, user_id, session_id, event_data_json),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        # Don't let analytics failures break the app
        try:
            current_app.logger.error(f"Failed to log event {event_name}: {e}")
        except Exception:
            pass
