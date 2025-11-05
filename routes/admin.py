"""
Admin routes - user management, feedback, analytics, cleanup.
"""
from flask import Blueprint, render_template, request, session, redirect, url_for, flash, current_app
from helpers.decorators import admin_required, get_current_user_id
from helpers.db import get_db_connection
from schemas.feedback import ValidationError
from services.feedback_service import admin_feedback, admin_feedback_update
import json


# Helper function to log events
def log_event(event_name, event_data=None, user_id=None):
    """Log an event to the events table."""
    if user_id is None:
        user_id = get_current_user_id()

    conn = get_db_connection()
    c = conn.cursor()

    event_data_json = json.dumps(event_data) if event_data else '{}'

    c.execute("""
        INSERT INTO events (user_id, event_name, event_data, created_at)
        VALUES (?, ?, ?, datetime('now'))
    """, (user_id, event_name, event_data_json))

    conn.commit()
    conn.close()


# Create blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route("/users")
@admin_required
def admin_users():
    """Admin page to manage all users and their subscriptions."""
    conn = get_db_connection()
    c = conn.cursor()

    # Get all users with their subscription info and usage stats
    c.execute("""
        SELECT u.id, u.email, u.name, u.subscription_tier, u.manual_override,
               u.created_at, u.email_verified,
               us.status, us.current_period_end,
               COUNT(DISTINCT l.id) as loan_count
        FROM users u
        LEFT JOIN user_subscriptions us ON u.id = us.user_id AND us.status IN ('active', 'trialing', 'past_due')
        LEFT JOIN loans l ON u.id = l.user_id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    """)
    user_rows = c.fetchall()

    users = []
    for row in user_rows:
        users.append({
            'id': row[0],
            'email': row[1],
            'name': row[2],
            'tier': row[3],
            'manual_override': row[4],
            'created_at': row[5],
            'email_verified': row[6],
            'subscription_status': row[7],
            'period_end': row[8],
            'loan_count': row[9]
        })

    conn.close()

    return render_template("admin_users.html", users=users)


@admin_bp.route("/user/<int:user_id>/upgrade", methods=["POST"])
@admin_required
def admin_upgrade_user(user_id):
    """Manually upgrade a user's subscription tier."""
    new_tier = request.form.get("tier")

    if new_tier not in ['free', 'basic', 'pro']:
        flash("Invalid tier", "error")
        return redirect("/admin/users")

    conn = get_db_connection()
    c = conn.cursor()

    # Update user's tier and set manual override
    c.execute("""
        UPDATE users
        SET subscription_tier = ?,
            manual_override = 1,
            trial_ends_at = NULL
        WHERE id = ?
    """, (new_tier, user_id))

    # Get user email for flash message
    c.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    user_email = result[0] if result else f"User {user_id}"

    conn.commit()
    conn.close()

    log_event('admin_user_upgrade', event_data={'target_user_id': user_id, 'new_tier': new_tier})
    flash(f"Successfully updated {user_email} to {new_tier.title()} (manual override)", "success")

    return redirect("/admin/users")


@admin_bp.route("/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    """Delete a user account and all associated data."""
    current_user_id = get_current_user_id()

    # Safety check: Can't delete yourself
    if user_id == current_user_id:
        flash("You cannot delete your own account.", "error")
        return redirect("/admin/users")

    conn = get_db_connection()
    c = conn.cursor()

    # Check if user exists and get their info
    c.execute("SELECT email, role FROM users WHERE id = ?", (user_id,))
    user_result = c.fetchone()

    if not user_result:
        flash("User not found.", "error")
        conn.close()
        return redirect("/admin/users")

    user_email, user_role = user_result

    # Safety check: Don't delete the last admin
    if user_role == 'admin':
        c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = c.fetchone()[0]

        if admin_count <= 1:
            flash("Cannot delete the last admin user.", "error")
            conn.close()
            return redirect("/admin/users")

    # Manually delete related records (in case CASCADE isn't set up everywhere)
    # Delete loans and their related data
    c.execute("""
        DELETE FROM applied_transactions
        WHERE loan_id IN (SELECT id FROM loans WHERE user_id = ?)
    """, (user_id,))

    c.execute("""
        DELETE FROM rejected_matches
        WHERE loan_id IN (SELECT id FROM loans WHERE user_id = ?)
    """, (user_id,))

    c.execute("DELETE FROM loans WHERE user_id = ?", (user_id,))

    # Delete other user-related data
    c.execute("DELETE FROM bank_connections WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM pending_matches_data WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM passkeys WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM magic_links WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM user_subscriptions WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM events WHERE user_id = ?", (user_id,))

    # Finally delete the user
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))

    conn.commit()
    conn.close()

    log_event('admin_user_delete', event_data={'target_user_id': user_id, 'target_email': user_email})
    flash(f"Successfully deleted user {user_email} and all associated data.", "success")

    return redirect("/admin/users")


@admin_bp.route("/cleanup-inactive", methods=["POST"])
@admin_required
def admin_cleanup_inactive():
    """
    Clean up inactive user accounts to prevent spam buildup.

    Deletion criteria:
    - Unverified accounts: inactive for 7+ days
    - Verified accounts with no loans: inactive for 90+ days
    - Accounts with loans are never auto-deleted (manual deletion only)
    """
    days_unverified = int(request.form.get("days_unverified", 7))
    days_verified = int(request.form.get("days_verified", 90))
    dry_run = request.form.get("dry_run") == "1"

    conn = get_db_connection()
    c = conn.cursor()

    deleted_users = []

    # Find unverified accounts that haven't logged in for X days and have no loans
    c.execute("""
        SELECT u.id, u.email, u.created_at, u.last_login_at, u.email_verified
        FROM users u
        LEFT JOIN loans l ON l.user_id = u.id
        WHERE u.email_verified = 0
        AND (u.last_login_at IS NULL OR u.last_login_at < datetime('now', '-' || ? || ' days'))
        AND u.role != 'admin'
        GROUP BY u.id
        HAVING COUNT(l.id) = 0
    """, (days_unverified,))

    unverified_users = c.fetchall()

    # Find verified accounts that haven't logged in for X days and have no loans
    c.execute("""
        SELECT u.id, u.email, u.created_at, u.last_login_at, u.email_verified
        FROM users u
        LEFT JOIN loans l ON l.user_id = u.id
        WHERE u.email_verified = 1
        AND (u.last_login_at IS NULL OR u.last_login_at < datetime('now', '-' || ? || ' days'))
        AND u.role != 'admin'
        GROUP BY u.id
        HAVING COUNT(l.id) = 0
    """, (days_verified,))

    verified_users = c.fetchall()

    candidates = unverified_users + verified_users

    if not dry_run:
        for user_id, email, created_at, last_login_at, email_verified in candidates:
            # Delete all user-related data
            c.execute("DELETE FROM bank_connections WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM pending_matches_data WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM passkeys WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM magic_links WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM user_subscriptions WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM events WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM users WHERE id = ?", (user_id,))

            deleted_users.append({
                'email': email,
                'verified': email_verified,
                'created_at': created_at,
                'last_login_at': last_login_at
            })

        conn.commit()

        log_event('admin_cleanup_inactive', event_data={
            'deleted_count': len(deleted_users),
            'days_unverified': days_unverified,
            'days_verified': days_verified
        })

        flash(f"Successfully deleted {len(deleted_users)} inactive accounts.", "success")
    else:
        # Dry run - just show what would be deleted
        for user_id, email, created_at, last_login_at, email_verified in candidates:
            deleted_users.append({
                'email': email,
                'verified': email_verified,
                'created_at': created_at,
                'last_login_at': last_login_at
            })

        flash(f"Dry run: Found {len(deleted_users)} accounts that would be deleted.", "success")

    conn.close()

    # Store results in session to display on admin page
    session['cleanup_results'] = {
        'deleted_users': deleted_users,
        'dry_run': dry_run,
        'days_unverified': days_unverified,
        'days_verified': days_verified
    }

    return redirect("/admin/users")


@admin_bp.route("/feedback")
@admin_required
def admin_feedback_view():
    """Admin page to list and manage feedback submissions."""
    status_filter = (request.args.get("status") or "all").lower().strip()

    # simple, safe int parsing
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        page = 1
    try:
        page_size = int(request.args.get("page_size", 50))
    except ValueError:
        page_size = 50

    try:
        feedback_list, status_counts, total = admin_feedback(
            status_filter=status_filter,
            page=page,
            page_size=page_size,
        )
    except ValidationError as e:
        flash(str(e), "error")
        # fall back to "all"
        feedback_list, status_counts, total = admin_feedback(
            status_filter="all", page=1, page_size=page_size
        )
        status_filter = "all"
        page = 1

    # For template pager
    total_pages = max(1, (total + page_size - 1) // page_size)

    return render_template(
        "admin_feedback.html",
        feedback=feedback_list,
        status_filter=status_filter,
        status_counts=status_counts,
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@admin_bp.route("/feedback/<int:feedback_id>/update", methods=["POST"])
@admin_required
def admin_feedback_update_route(feedback_id: int):
    """Update feedback status and admin notes."""
    new_status = request.form.get("status", "")
    admin_notes = request.form.get("admin_notes", "")

    try:
        updated = admin_feedback_update(
            feedback_id=feedback_id,
            new_status=new_status,
            admin_notes=admin_notes,
        )
    except ValidationError as e:
        flash(str(e), "error")
        # preserve current filter/page in the redirect if present
        return redirect(url_for("admin.admin_feedback_view", **request.args))

    if updated:
        flash("Feedback updated successfully", "success")
    else:
        flash("No changes made (record not found?)", "warning")

    return redirect(url_for("admin.admin_feedback_view", **request.args))


# Analytics route - registered separately in app.py at /analytics (not /admin/analytics)
def analytics_view():
    """Analytics dashboard showing usage metrics. Admin only."""
    from datetime import datetime, timedelta

    conn = get_db_connection()
    c = conn.cursor()

    # Date calculations
    today = datetime.now().date()
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)

    metrics = {}

    # Total users
    c.execute("SELECT COUNT(*) FROM users")
    metrics['total_users'] = c.fetchone()[0]

    # New signups (last 7 days, last 30 days) (excluding admin)
    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'user_signed_up' AND created_at >= date('now', '-7 days') AND user_id != 1")
    metrics['new_users_7d'] = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'user_signed_up' AND created_at >= date('now', '-30 days') AND user_id != 1")
    metrics['new_users_30d'] = c.fetchone()[0]

    # DAU (Daily Active Users) - users with any event today (excluding admin)
    c.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM events
        WHERE date(created_at) = date('now')
          AND user_id != 1
    """)
    metrics['dau'] = c.fetchone()[0]

    # WAU (Weekly Active Users) (excluding admin)
    c.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM events
        WHERE created_at >= date('now', '-7 days')
          AND user_id != 1
    """)
    metrics['wau'] = c.fetchone()[0]

    # MAU (Monthly Active Users) (excluding admin)
    c.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM events
        WHERE created_at >= date('now', '-30 days')
          AND user_id != 1
    """)
    metrics['mau'] = c.fetchone()[0]

    # Total loans created
    c.execute("SELECT COUNT(*) FROM loans")
    metrics['total_loans'] = c.fetchone()[0]

    # Loans created (last 7 days, last 30 days) (excluding admin)
    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'loan_created' AND created_at >= date('now', '-7 days') AND user_id != 1")
    metrics['loans_7d'] = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'loan_created' AND created_at >= date('now', '-30 days') AND user_id != 1")
    metrics['loans_30d'] = c.fetchone()[0]

    # Bank link funnel (excluding admin)
    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'bank_link_started' AND created_at >= date('now', '-30 days') AND user_id != 1")
    bank_started = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE event_name = 'bank_link_success' AND created_at >= date('now', '-30 days') AND user_id != 1")
    bank_success = c.fetchone()[0]

    metrics['bank_link_started'] = bank_started
    metrics['bank_link_success'] = bank_success
    metrics['bank_link_conversion'] = (bank_success / bank_started * 100) if bank_started > 0 else 0

    # Retention: users active this week who were also active last week (excluding admin)
    c.execute("""
        SELECT COUNT(DISTINCT e1.user_id)
        FROM events e1
        WHERE e1.created_at >= date('now', '-7 days')
          AND e1.user_id != 1
          AND e1.user_id IN (
              SELECT DISTINCT user_id
              FROM events
              WHERE created_at >= date('now', '-14 days')
                AND created_at < date('now', '-7 days')
                AND user_id != 1
          )
    """)
    retained_users = c.fetchone()[0]

    c.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM events
        WHERE created_at >= date('now', '-14 days')
          AND created_at < date('now', '-7 days')
          AND user_id != 1
    """)
    previous_week_users = c.fetchone()[0]

    metrics['retention_rate'] = (retained_users / previous_week_users * 100) if previous_week_users > 0 else 0

    # Recent events (last 20) (excluding admin)
    c.execute("""
        SELECT e.event_name, e.created_at, u.email, e.event_data
        FROM events e
        LEFT JOIN users u ON e.user_id = u.id
        WHERE e.user_id != 1
        ORDER BY e.created_at DESC
        LIMIT 20
    """)
    recent_events = []
    for row in c.fetchall():
        event_name, created_at, email, event_data = row
        recent_events.append({
            'event_name': event_name,
            'created_at': created_at,
            'user_email': email if email else 'Anonymous',
            'event_data': json.loads(event_data) if event_data else {}
        })

    # Event counts by type (last 30 days) (excluding admin)
    c.execute("""
        SELECT event_name, COUNT(*) as count
        FROM events
        WHERE created_at >= date('now', '-30 days')
          AND user_id != 1
        GROUP BY event_name
        ORDER BY count DESC
    """)
    event_counts = c.fetchall()

    conn.close()

    return render_template("analytics.html",
                         metrics=metrics,
                         recent_events=recent_events,
                         event_counts=event_counts)
