"""
Decorators for route protection and access control.
"""
from functools import wraps
from flask import session, flash, redirect, url_for, request
from helpers.session_helpers import get_current_user_id, is_user_admin

# Re-exported so callers can do `from helpers.decorators import get_current_user_id`
# without churn during the cleanup.
__all__ = ['login_required', 'admin_required', 'get_current_user_id', 'is_user_admin']


def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('auth.login', next=request.url))

        if not is_user_admin():
            flash("Access denied. Admin privileges required.", "error")
            try:
                return redirect(url_for('dashboard.index'))
            except Exception:
                return redirect('/')

        return f(*args, **kwargs)
    return decorated_function
