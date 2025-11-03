"""
Decorators for route protection and access control.
"""
from functools import wraps
from flask import session, flash, redirect, url_for, request
import sqlite3
from helpers.utils import get_db_path


def get_current_user_id():
    """Get the current logged-in user's ID from session."""
    return session.get('user_id')


def is_user_admin():
    """Check if current user has admin role."""
    user_id = get_current_user_id()
    if not user_id:
        return False

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    return result and result[0] == 'admin'


def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "error")
            # Try to use auth.login, fallback to login for backward compatibility
            try:
                return redirect(url_for('auth.login', next=request.url))
            except:
                return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "error")
            # Try to use auth.login, fallback to login for backward compatibility
            try:
                return redirect(url_for('auth.login', next=request.url))
            except:
                return redirect(url_for('auth.login', next=request.url))

        # Check if user is admin
        if not is_user_admin():
            flash("Access denied. Admin privileges required.", "error")
            # Try index, fallback to main index for backward compatibility
            try:
                return redirect(url_for('index'))
            except:
                return redirect('/')

        return f(*args, **kwargs)
    return decorated_function
