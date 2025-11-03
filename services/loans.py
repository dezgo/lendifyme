"""
Loan-related helper functions.

Contains encryption, decryption, and subscription limit checking for loans.
"""
import sqlite3
import json
import secrets
from flask import current_app, session


def get_db_path():
    """Get the database path from Flask config."""
    return current_app.config['DATABASE']


def get_current_user_id():
    """Get current user ID from session."""
    return session.get('user_id')


def get_user_encryption_salt():
    """Get the encryption salt for the current user."""
    user_id = get_current_user_id()
    if not user_id:
        return None

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT encryption_salt FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    return result[0] if result else None


def get_user_password_from_session():
    """Get user's password from session (set at login for encryption/decryption)."""
    return session.get('user_password')


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


def decrypt_loan_data(loan_row, dek):
    """
    Decrypt loan data from database row.

    Args:
        loan_row: Database row (dict or tuple)
        dek: Data encryption key (bytes)

    Returns:
        Dict with decrypted loan data
    """
    from services.encryption import decrypt_field

    # Handle both dict and tuple row formats
    if isinstance(loan_row, dict):
        get_field = lambda key: loan_row.get(key)
    else:
        # Assume it's a row from c.fetchone() - need column names
        # This will be handled by the calling code
        return None

    try:
        return {
            'borrower': decrypt_field(get_field('borrower_encrypted'), dek) if get_field('borrower_encrypted') else get_field('borrower'),
            'amount': float(decrypt_field(get_field('amount_encrypted'), dek)) if get_field('amount_encrypted') else get_field('amount'),
            'note': decrypt_field(get_field('note_encrypted'), dek) if get_field('note_encrypted') else get_field('note'),
            'bank_name': decrypt_field(get_field('bank_name_encrypted'), dek) if get_field('bank_name_encrypted') else get_field('bank_name'),
            'borrower_email': decrypt_field(get_field('borrower_email_encrypted'), dek) if get_field('borrower_email_encrypted') else get_field('borrower_email'),
            'repayment_amount': float(decrypt_field(get_field('repayment_amount_encrypted'), dek)) if get_field('repayment_amount_encrypted') else get_field('repayment_amount'),
            'repayment_frequency': decrypt_field(get_field('repayment_frequency_encrypted'), dek) if get_field('repayment_frequency_encrypted') else get_field('repayment_frequency'),
        }
    except Exception as e:
        current_app.logger.error(f"Failed to decrypt loan data: {e}")
        return None


def get_user_subscription_tier(user_id=None):
    """
    Get user's current subscription tier (free/basic/pro).

    Args:
        user_id: User ID (defaults to current user)

    Returns:
        str: 'free', 'basic', or 'pro'
    """
    if user_id is None:
        user_id = get_current_user_id()

    if not user_id:
        return 'free'

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT subscription_tier FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    return result[0] if result else 'free'


def get_subscription_limits(tier):
    """
    Get subscription limits and features for a tier.

    Args:
        tier: 'free', 'basic', or 'pro'

    Returns:
        dict: Features and limits for the tier
    """
    conn = sqlite3.connect(get_db_path())
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
            'max_loans': 3,
            'manual_repayment': True,
            'csv_import': True,
            'borrower_portal': True,
            'email_notifications': False,
            'transaction_export': False,
            'bank_api': False,
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
        return (0, 3, False)

    # Get user's tier
    tier = get_user_subscription_tier(user_id)
    limits = get_subscription_limits(tier)
    max_loans = limits.get('max_loans')

    # Count current active loans
    conn = sqlite3.connect(get_db_path())
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

    conn = sqlite3.connect(get_db_path())
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

    conn = sqlite3.connect(get_db_path())
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
    """Return a list of decrypted loan tuples matching the original render shape."""
    from services.encryption import decrypt_field

    loans = []
    for row in rows:
        loan_id = row["id"]
        dek = get_loan_dek(loan_id, user_password=user_password)
        if not dek:
            current_app.logger.error("Failed to decrypt DEK for loan %s", loan_id)
            continue

        borrower = decrypt_field(row["borrower_encrypted"], dek) if row["borrower_encrypted"] else row["borrower"]
        amount = (
            float(decrypt_field(row["amount_encrypted"], dek))
            if row["amount_encrypted"]
            else row["amount"]
        )
        note = decrypt_field(row["note_encrypted"], dek) if row["note_encrypted"] else row["note"]
        bank_name = (
            decrypt_field(row["bank_name_encrypted"], dek)
            if row["bank_name_encrypted"]
            else row["bank_name"]
        )
        borrower_email = (
            decrypt_field(row["borrower_email_encrypted"], dek)
            if row["borrower_email_encrypted"]
            else row["borrower_email"]
        )

        if row["repayment_amount_encrypted"]:
            repayment_amount = float(decrypt_field(row["repayment_amount_encrypted"], dek))
        else:
            repayment_amount = row["repayment_amount"]

        repayment_frequency = (
            decrypt_field(row["repayment_frequency_encrypted"], dek)
            if row["repayment_frequency_encrypted"]
            else row["repayment_frequency"]
        )

        # amount_repaid from applied_transactions
        cursor.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM applied_transactions WHERE loan_id = ?",
            (loan_id,),
        )
        amount_repaid = cursor.fetchone()[0]

        loans.append(
            (
                loan_id,
                borrower,
                amount,
                note,
                row["date_borrowed"],
                amount_repaid,
                repayment_amount,
                repayment_frequency,
                bank_name,
                row["created_at"],
                row["borrower_access_token"],
                borrower_email,
                row["loan_type"],
            )
        )

    return loans

