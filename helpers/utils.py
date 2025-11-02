"""
Shared utility functions used across the application.
"""
import sqlite3
import json
from flask import session, current_app


def get_db_path():
    """Get database path from config (allows tests to override)."""
    return current_app.config.get('DATABASE', 'lendifyme.db')


def get_current_user_id():
    """Get the current logged-in user's ID from session."""
    return session.get('user_id')


def log_event(event_name, user_id=None, event_data=None):
    """
    Log an analytics event to the database.

    Args:
        event_name: Name of the event (e.g., 'user_signed_up', 'loan_created')
        user_id: Optional user ID (defaults to current user if logged in)
        event_data: Optional dict with additional context (stored as JSON)
    """
    try:
        # Use current user if not specified
        if user_id is None:
            user_id = get_current_user_id()

        # Get session ID if available
        session_id = session.get('_id', None)

        # Convert event_data to JSON if provided
        event_data_json = json.dumps(event_data) if event_data else None

        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute("""
            INSERT INTO events (event_name, user_id, session_id, event_data)
            VALUES (?, ?, ?, ?)
        """, (event_name, user_id, session_id, event_data_json))
        conn.commit()
        conn.close()
    except Exception as e:
        # Don't let analytics failures break the app
        current_app.logger.error(f"Failed to log event {event_name}: {e}")
