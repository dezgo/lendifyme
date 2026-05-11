"""
Loan-related helper functions.

Contains encryption, decryption, and subscription limit checking for loans.
"""
import json
import secrets
from flask import current_app
from helpers.db import get_db_connection
from helpers.session_helpers import (
    get_current_user_id,
    get_user_encryption_salt,
    get_user_password_from_session,
)


def encrypt_loan_data(loan_data, dek):
    """
    Encrypt sensitive loan fields using envelope encryption.

    Args:
        loan_data: Dict with loan fields
        dek: Data encryption key (bytes)

    Returns:
        Dict with encrypted fields
    """
    from services.encryption import encrypt_field

    return {
        'borrower_encrypted': encrypt_field(loan_data.get('borrower'), dek) if loan_data.get('borrower') else None,
        'amount_encrypted': encrypt_field(str(loan_data.get('amount')), dek) if loan_data.get('amount') is not None else None,
        'note_encrypted': encrypt_field(loan_data.get('note'), dek) if loan_data.get('note') else None,
        'bank_name_encrypted': encrypt_field(loan_data.get('bank_name'), dek) if loan_data.get('bank_name') else None,
        'borrower_email_encrypted': encrypt_field(loan_data.get('borrower_email'), dek) if loan_data.get('borrower_email') else None,
        'repayment_amount_encrypted': encrypt_field(str(loan_data.get('repayment_amount')), dek) if loan_data.get('repayment_amount') is not None else None,
        'repayment_frequency_encrypted': encrypt_field(loan_data.get('repayment_frequency'), dek) if loan_data.get('repayment_frequency') else None,
    }


def decrypt_loan_row(row, dek):
    """
    Decrypt a loan row that may contain plaintext and/or encrypted columns.

    Works with sqlite3.Row, dict, or anything supporting `key in row.keys()` and
    `row[key]`. Encrypted columns take precedence; falls back to plaintext if
    the encrypted variant is missing/empty or no DEK is available.

    Args:
        row: Loan row from a SELECT that includes any subset of the columns:
             borrower, borrower_encrypted, amount, amount_encrypted, note,
             note_encrypted, bank_name, bank_name_encrypted, borrower_email,
             borrower_email_encrypted, repayment_amount,
             repayment_amount_encrypted, repayment_frequency,
             repayment_frequency_encrypted.
        dek: Data encryption key (bytes) or None.

    Returns:
        Dict with keys: borrower, amount (float|None), note, bank_name,
        borrower_email, repayment_amount (float|None), repayment_frequency.
        Missing columns surface as None.
    """
    from services.encryption import decrypt_field

    keys = set(row.keys())

    def pick(plain_col, encrypted_col):
        if encrypted_col in keys:
            encrypted = row[encrypted_col]
            if encrypted and dek:
                return decrypt_field(encrypted, dek)
        if plain_col in keys:
            return row[plain_col]
        return None

    def to_float(val):
        if val is None or val == '':
            return None
        try:
            return float(val)
        except (TypeError, ValueError):
            return None

    return {
        'borrower': pick('borrower', 'borrower_encrypted'),
        'amount': to_float(pick('amount', 'amount_encrypted')),
        'note': pick('note', 'note_encrypted'),
        'bank_name': pick('bank_name', 'bank_name_encrypted'),
        'borrower_email': pick('borrower_email', 'borrower_email_encrypted'),
        'repayment_amount': to_float(pick('repayment_amount', 'repayment_amount_encrypted')),
        'repayment_frequency': pick('repayment_frequency', 'repayment_frequency_encrypted'),
    }


def get_user_subscription_tier(user_id=None):
    """
    Get user's current subscription tier (free/basic/pro).

    Checks users.subscription_tier first.  If it's NULL or missing,
    falls back to the most-recent active/trialing user_subscriptions row
    (defence-in-depth against webhooks that set the column to NULL).

    Args:
        user_id: User ID (defaults to current user)

    Returns:
        str: 'free', 'basic', or 'pro'
    """
    if user_id is None:
        user_id = get_current_user_id()

    if not user_id:
        return 'free'

    conn = get_db_connection()
    c = conn.cursor()

    c.execute(
        "SELECT subscription_tier, manual_override FROM users WHERE id = ?",
        (user_id,),
    )
    result = c.fetchone()
    if not result:
        conn.close()
        return 'free'

    tier, manual_override = result

    # Admin-granted access — trust the column as-is
    if manual_override and tier:
        conn.close()
        return tier

    # If tier is properly set and non-NULL, use it
    if tier and tier != 'free':
        conn.close()
        return tier

    # Defence-in-depth: if tier is NULL or 'free', cross-check
    # user_subscriptions for an active/trialing record that may have been
    # missed by a failed webhook.
    c.execute("""
        SELECT tier FROM user_subscriptions
        WHERE user_id = ? AND status IN ('active', 'trialing')
        ORDER BY updated_at DESC
        LIMIT 1
    """, (user_id,))
    sub_row = c.fetchone()

    if sub_row and sub_row[0]:
        # Repair: sync users.subscription_tier so future lookups are fast
        c.execute(
            "UPDATE users SET subscription_tier = ? WHERE id = ?",
            (sub_row[0], user_id),
        )
        conn.commit()
        current_app.logger.warning(
            "Auto-repaired subscription_tier for user %s: NULL/free -> %s",
            user_id, sub_row[0],
        )
        conn.close()
        return sub_row[0]

    conn.close()
    return tier if tier else 'free'


def get_subscription_limits(tier):
    """
    Get subscription limits and features for a tier.

    Args:
        tier: 'free', 'basic', or 'pro'

    Returns:
        dict: Features and limits for the tier
    """
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT max_loans, features_json
        FROM subscription_plans
        WHERE tier = ? AND active = 1
    """, (tier,))
    result = c.fetchone()
    conn.close()

    if not result:
        # Fallback defaults
        return {
            'max_loans': 1,
            'manual_repayment': True,
            'csv_import': True,
            'borrower_portal': True,
            'email_notifications': False,
            'transaction_export': False,
            'analytics': False
        }

    max_loans, features_json = result
    features = json.loads(features_json)
    features['max_loans'] = max_loans  # Ensure max_loans is in the dict

    return features


def check_loan_limit(user_id=None):
    """
    Check if user can create more loans.

    Args:
        user_id: User ID (defaults to current user)

    Returns:
        tuple: (current_count, max_allowed, can_create)
    """
    if user_id is None:
        user_id = get_current_user_id()

    if not user_id:
        return (0, 1, False)

    # Get user's tier
    tier = get_user_subscription_tier(user_id)
    limits = get_subscription_limits(tier)
    max_loans = limits.get('max_loans')

    # Count current active loans
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM loans WHERE user_id = ?", (user_id,))
    current_count = c.fetchone()[0]
    conn.close()

    # None means unlimited
    if max_loans is None:
        return (current_count, None, True)

    can_create = current_count < max_loans
    return (current_count, max_loans, can_create)


def has_feature(user_id, feature_name):
    """
    Check if user has access to a specific feature.

    Args:
        user_id: User ID
        feature_name: Feature key (e.g., 'bank_api', 'email_notifications', 'transaction_export')

    Returns:
        bool: True if user has access to the feature
    """
    if not user_id:
        return False

    tier = get_user_subscription_tier(user_id)
    limits = get_subscription_limits(tier)

    return limits.get(feature_name, False)


def is_trial_active(user_id=None):
    """
    Check if user is currently in a trial period.

    Args:
        user_id: User ID (defaults to current user)

    Returns:
        bool: True if trial is active
    """
    from datetime import datetime

    if user_id is None:
        user_id = get_current_user_id()

    if not user_id:
        return False

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT trial_ends_at FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    if not result or not result[0]:
        return False

    trial_ends_at = datetime.fromisoformat(result[0])
    return datetime.now() < trial_ends_at


def generate_borrower_access_token():
    """Generate a secure random token for borrower access."""
    return secrets.token_urlsafe(32)


def decrypt_dek_for_loan(encrypted_dek, encryption_salt, user_password):
    """
    Pure function: decrypt a loan's DEK given its encrypted blob, the user's
    encryption_salt, and their password. No DB access.

    Handles the MIGRATION_PENDING placeholder format by stripping the prefix.
    (Auto-finalization into the real encrypted form still happens lazily in
    get_loan_dek for single-loan callers.)

    Returns:
        bytes: The DEK, or None if any input is missing or decryption fails.
    """
    from services.encryption import decrypt_dek_with_password

    if not encrypted_dek or not encryption_salt or not user_password:
        return None

    if encrypted_dek.startswith("MIGRATION_PENDING:"):
        return encrypted_dek.replace("MIGRATION_PENDING:", "").encode('utf-8')

    try:
        return decrypt_dek_with_password(encrypted_dek, user_password, encryption_salt)
    except Exception as e:
        current_app.logger.error(f"Failed to decrypt DEK: {e}")
        return None


def get_loan_dek(loan_id, user_password=None, borrower_token=None):
    """
    Get the DEK for a specific loan.

    Can decrypt using either:
    - User's password (for lender access)
    - Borrower access token (for borrower portal)

    Args:
        loan_id: The loan ID
        user_password: User's password (optional if using token)
        borrower_token: Borrower access token (optional if using password)

    Returns:
        bytes: The decrypted DEK, or None if unable to decrypt
    """
    from services.encryption import (
        decrypt_dek_with_password,
        extract_dek_from_token,
        encrypt_dek_with_password
    )

    conn = get_db_connection()
    c = conn.cursor()

    if borrower_token:
        # Borrower access: extract DEK directly from token
        try:
            dek = extract_dek_from_token(borrower_token)
            conn.close()
            return dek
        except Exception as e:
            current_app.logger.error(f"Failed to extract DEK from token: {e}")
            conn.close()
            return None

    elif user_password:
        # Lender access: decrypt DEK with password
        c.execute("""
            SELECT encrypted_dek, user_id
            FROM loans
            WHERE id = ?
        """, (loan_id,))

        result = c.fetchone()
        if not result:
            conn.close()
            return None

        encrypted_dek, user_id = result

        # Check for migration placeholder
        if encrypted_dek and encrypted_dek.startswith("MIGRATION_PENDING:"):
            # Extract DEK from placeholder and re-encrypt it properly
            dek_str = encrypted_dek.replace("MIGRATION_PENDING:", "")
            dek = dek_str.encode('utf-8')

            # Get user's encryption salt
            c.execute("SELECT encryption_salt FROM users WHERE id = ?", (user_id,))
            salt_result = c.fetchone()

            if salt_result and salt_result[0]:
                # Re-encrypt DEK with user's password
                new_encrypted_dek = encrypt_dek_with_password(dek, user_password, salt_result[0])

                # Update database
                c.execute("UPDATE loans SET encrypted_dek = ? WHERE id = ?",
                          (new_encrypted_dek, loan_id))
                conn.commit()

                current_app.logger.info(f"Finalized DEK encryption for loan {loan_id}")

            conn.close()
            return dek

        # Normal case: decrypt DEK
        c.execute("SELECT encryption_salt FROM users WHERE id = ?", (user_id,))
        salt_result = c.fetchone()
        conn.close()

        if not salt_result or not salt_result[0]:
            return None

        try:
            return decrypt_dek_with_password(encrypted_dek, user_password, salt_result[0])
        except Exception as e:
            current_app.logger.error(f"Failed to decrypt DEK for loan {loan_id}: {e}")
            return None

    conn.close()
    return None


def decrypt_loans(cursor, rows, user_password):
    """Return a list of decrypted loan tuples matching the original render shape.

    Performs the salt lookup once and the amount_repaid SUMs in a single query
    instead of one-per-loan, so the dashboard scales with O(1) queries
    regardless of how many loans the user has.
    """
    if not rows:
        return []

    user_id = get_current_user_id()

    # Fetch encryption_salt once
    cursor.execute("SELECT encryption_salt FROM users WHERE id = ?", (user_id,))
    salt_row = cursor.fetchone()
    encryption_salt = salt_row[0] if salt_row else None

    # Batch-fetch amount_repaid for all loans in one query
    loan_ids = [row["id"] for row in rows]
    placeholders = ",".join("?" for _ in loan_ids)
    cursor.execute(
        f"SELECT loan_id, COALESCE(SUM(amount), 0) "
        f"FROM applied_transactions WHERE loan_id IN ({placeholders}) "
        f"GROUP BY loan_id",
        loan_ids,
    )
    repaid_by_loan = {lid: total for lid, total in cursor.fetchall()}

    loans = []
    for row in rows:
        loan_id = row["id"]
        dek = decrypt_dek_for_loan(row["encrypted_dek"], encryption_salt, user_password)
        if not dek:
            current_app.logger.error("Failed to decrypt DEK for loan %s", loan_id)
            continue

        fields = decrypt_loan_row(row, dek)
        amount_repaid = repaid_by_loan.get(loan_id, 0)

        loans.append(
            (
                loan_id,
                fields['borrower'],
                fields['amount'],
                fields['note'],
                row["date_borrowed"],
                amount_repaid,
                fields['repayment_amount'],
                fields['repayment_frequency'],
                fields['bank_name'],
                row["created_at"],
                row["borrower_access_token"],
                fields['borrower_email'],
                row["loan_type"],
            )
        )

    return loans

