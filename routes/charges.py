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
            return None, f"Share for '{tag}' must be a number between 0 and 100."
        if not 0 <= pct <= 100:
            return None, f"Share for '{tag}' must be between 0 and 100."
        if tag in seen:
            return None, f"'{tag}' is listed twice."
        seen.add(tag)
        rules.append({"tag": tag, "share_percent": pct})
    if not rules:
        return None, "Add at least one tag."
    return rules, None


def _form_context(conn, loan_id, dek, borrower, rules):
    from services import up_bank
    payer_name, _ = charge_service.payment_settings(conn, loan_id, dek)
    row = conn.execute("SELECT u.up_token_encrypted FROM loans l JOIN users u ON u.id = l.user_id "
                       "WHERE l.id = ?", (loan_id,)).fetchone()
    return dict(loan_id=loan_id, borrower=borrower, rules=rules, max_rows=MAX_TAG_ROWS,
                payer_name=payer_name or "", has_saved_token=bool(row and row[0]),
                can_save_token=up_bank.can_store_tokens())


@charges_bp.route("/loan/<int:loan_id>/charges/sync", methods=["GET", "POST"])
@login_required
def sync_charges(loan_id):
    from services import up_bank
    from services.encryption import encrypt_field

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
        ctx = _form_context(conn, loan_id, dek, borrower, saved_rules)
        conn.close()
        return render_template("charges_sync.html", **ctx)

    rules, error = _parse_rules(request.form)
    ctx = _form_context(conn, loan_id, dek, borrower, rules or saved_rules)
    user_id = get_current_user_id()

    token = (request.form.get("up_token") or "").strip()
    if not token and ctx["has_saved_token"]:
        token = up_bank.decrypt_token(conn.execute(
            "SELECT up_token_encrypted FROM users WHERE id = ?", (user_id,)).fetchone()[0]) or ""
    if not error and not token:
        error = "Paste your Up access token."
    if not error and not dek:
        error = "Couldn't unlock this loan. Log out and back in, then try again."
    if error:
        conn.close()
        flash(error, "error")
        return render_template("charges_sync.html", **ctx), 400

    payer_name = (request.form.get("payer_name") or "").strip()[:100]
    conn.execute("UPDATE loans SET bank_name_encrypted = ? WHERE id = ?",
                 (encrypt_field(payer_name, dek) if payer_name else None, loan_id))
    since = conn.execute("SELECT date_borrowed FROM loans WHERE id = ?", (loan_id,)).fetchone()[0]

    try:
        result = charge_service.sync_from_up(conn, loan_id, token, rules, dek,
                                             payer_name or None, (since or "")[:10] or None)
    except UpError as e:
        conn.close()
        flash(str(e), "error")
        return render_template("charges_sync.html", **ctx), 400

    keep = request.form.get("keep_token") == "on"
    if keep and request.form.get("up_token") and up_bank.can_store_tokens():
        conn.execute("UPDATE users SET up_token_encrypted = ? WHERE id = ?",
                     (up_bank.encrypt_token(token), user_id))
    elif not keep:
        conn.execute("UPDATE users SET up_token_encrypted = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    log_event("charges_synced", event_data={"loan_id": loan_id, **result})
    msg = (f"Synced from Up: {result['added']} added, {result['updated']} changed, "
           f"{result['removed']} removed")
    if payer_name:
        msg += f", {result['payments']} new payment{'s' if result['payments'] != 1 else ''}"
    msg += f". Total charged is now ${result['total']:.2f}."
    if keep:
        msg += " It'll keep itself up to date from now on."
    flash(msg, "success")
    return redirect(f"/loan/{loan_id}/transactions")


def _manual_context(loan_id):
    """Open the DB and unlock an owned loan for a manual-charge change.
    Returns (conn, dek) or (None, None) after flashing why."""
    user_password = session.get('user_password')
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    if not _load_owned_loan(conn.cursor(), loan_id):
        conn.close()
        flash("Loan not found", "error")
        return None, None
    dek = get_loan_dek(loan_id, user_password=user_password) if user_password else None
    if not dek:
        conn.close()
        flash("Couldn't unlock this loan. Log out and back in, then try again.", "error")
        return None, None
    return conn, dek


@charges_bp.route("/loan/<int:loan_id>/charges/add", methods=["POST"])
@login_required
def add_charge(loan_id):
    from datetime import date as _date
    conn, dek = _manual_context(loan_id)
    if not conn:
        return redirect("/")
    back = redirect(f"/loan/{loan_id}/transactions")

    description = (request.form.get("description") or "").strip()[:200]
    when = (request.form.get("date") or "").strip() or _date.today().isoformat()
    try:
        amount = float((request.form.get("amount") or "").replace("$", "").replace(",", "").strip())
        share = float((request.form.get("share") or "").rstrip("%").strip())
        _date.fromisoformat(when)
    except ValueError:
        conn.close()
        flash("Enter a date, an amount and a share.", "error")
        return back
    if not description or not 0 < amount < 1_000_000 or not 0 <= share <= 100:
        conn.close()
        flash("Enter what it was, an amount above $0, and a share between 0 and 100%.", "error")
        return back
    if not charge_service.has_charges_setup(conn, loan_id):
        conn.close()
        flash("Hand-entered charges are only for loans that list charges.", "error")
        return back

    total = charge_service.add_manual_charge(conn, loan_id, when, description, amount, share, dek)
    conn.close()
    flash(f"Added '{description}'. Total charged is now ${total:.2f}.", "success")
    return back


@charges_bp.route("/loan/<int:loan_id>/charges/<int:charge_id>/remove", methods=["POST"])
@login_required
def remove_charge(loan_id, charge_id):
    conn, dek = _manual_context(loan_id)
    if not conn:
        return redirect("/")
    removed = charge_service.remove_manual_charge(conn, loan_id, charge_id, dek)
    conn.close()
    flash("Charge removed." if removed else "Only charges you typed in can be removed here — untag bank ones in Up.",
          "success" if removed else "error")
    return redirect(f"/loan/{loan_id}/transactions")
