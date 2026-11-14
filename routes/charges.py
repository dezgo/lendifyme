"""
Itemised charges — sync a loan's charges from tagged Up transactions.
"""
import sqlite3
from flask import Blueprint, render_template, request, redirect, flash, session
from helpers.decorators import login_required
from helpers.session_helpers import get_current_user_id
from helpers.db import get_db_path
from helpers.events import log_event
from services.loans import get_loan_dek, decrypt_loan_row
from services import charges as charge_service
from services.up_bank import UpError

charges_bp = Blueprint('charges', __name__)

MAX_TAG_ROWS = 4


def _load_owned_loan(c, loan_id):
    c.execute(
        "SELECT id, borrower_encrypted FROM loans WHERE id = ? AND user_id = ?",
        (loan_id, get_current_user_id()),
    )
    return c.fetchone()


def _parse_rules(form):
    """Read tag/share rows from the form. Returns (rules, error)."""
    rules, seen = [], set()
    for i in range(MAX_TAG_ROWS):
        tag = (form.get(f"tag_{i}") or "").strip()
        share = (form.get(f"share_{i}") or "").strip().rstrip('%')
        if not tag:
            continue
        try:
            pct = float(share)
        except ValueError:
            return None, f"Share for '{tag}' must be a number between 1 and 100."
        if not 0 < pct <= 100:
            return None, f"Share for '{tag}' must be between 1 and 100."
        if tag in seen:
            return None, f"'{tag}' is listed twice."
        seen.add(tag)
        rules.append({"tag": tag, "share_percent": pct})
    if not rules:
        return None, "Add at least one tag."
    return rules, None


@charges_bp.route("/loan/<int:loan_id>/charges/sync", methods=["GET", "POST"])
@login_required
def sync_charges(loan_id):
    user_password = session.get('user_password')
    if not user_password:
        flash("Please log in with your password first.", "error")
        return redirect("/login")

    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    loan_row = _load_owned_loan(c, loan_id)
    if not loan_row:
        conn.close()
        flash("Loan not found", "error")
        return redirect("/")

    dek = get_loan_dek(loan_id, user_password=user_password)
    borrower = decrypt_loan_row(loan_row, dek)['borrower']
    saved_rules = charge_service.get_charge_tags(conn, loan_id)

    if request.method == "GET":
        conn.close()
        return render_template("charges_sync.html", loan_id=loan_id, borrower=borrower,
                               rules=saved_rules, max_rows=MAX_TAG_ROWS)

    rules, error = _parse_rules(request.form)
    token = (request.form.get("up_token") or "").strip()
    if not error and not token:
        error = "Paste your Up access token."
    if not error and not dek:
        error = "Couldn't unlock this loan. Log out and back in, then try again."
    if error:
        conn.close()
        flash(error, "error")
        return render_template("charges_sync.html", loan_id=loan_id, borrower=borrower,
                               rules=rules or saved_rules, max_rows=MAX_TAG_ROWS), 400

    try:
        result = charge_service.sync_from_up(conn, loan_id, token, rules, dek)
    except UpError as e:
        conn.close()
        flash(str(e), "error")
        return render_template("charges_sync.html", loan_id=loan_id, borrower=borrower,
                               rules=rules, max_rows=MAX_TAG_ROWS), 400
    conn.close()

    log_event("charges_synced", event_data={"loan_id": loan_id, **result})
    flash(
        f"Synced from Up: {result['added']} added, {result['updated']} changed, "
        f"{result['removed']} removed. Total charged is now ${result['total']:.2f}.",
        "success",
    )
    return redirect(f"/loan/{loan_id}/transactions")
