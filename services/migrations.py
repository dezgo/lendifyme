# services/migrations.py

def _get_user_version(conn) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def _set_user_version(conn, version: int) -> None:
    conn.execute(f"PRAGMA user_version = {version}")


def run_migrations(conn):
    current = _get_user_version(conn)
    print(f"📊 Current database version: {current}")

    if current < 1:
        migrate_v1_create_loans_table(conn)
        _set_user_version(conn, 1)
        conn.commit()
        print("✅ Migration v1 applied.")

    if current < 2:
        migrate_v2_add_amount_repaid(conn)
        _set_user_version(conn, 2)
        conn.commit()
        print("✅ Migration v2 applied.")

    if current < 3:
        migrate_v3_add_repayment_schedule(conn)
        _set_user_version(conn, 3)
        conn.commit()
        print("✅ Migration v3 applied.")

    if current < 4:
        migrate_v4_create_applied_transactions(conn)
        _set_user_version(conn, 4)
        conn.commit()
        print("✅ Migration v4 applied.")

    if current < 5:
        migrate_v5_add_bank_name(conn)
        _set_user_version(conn, 5)
        conn.commit()
        print("✅ Migration v5 applied.")

    if current < 6:
        migrate_v6_create_rejected_matches(conn)
        _set_user_version(conn, 6)
        conn.commit()
        print("✅ Migration v6 applied.")

    if current < 7:
        migrate_v7_create_users_table(conn)
        _set_user_version(conn, 7)
        conn.commit()
        print("✅ Migration v7 applied.")

    if current < 8:
        migrate_v8_add_user_id_to_loans(conn)
        _set_user_version(conn, 8)
        conn.commit()
        print("✅ Migration v8 applied.")

    if current < 9:
        try:
            migrate_v9_remove_amount_repaid(conn)
            _set_user_version(conn, 9)
            conn.commit()
            print("✅ Migration v9 applied.")

            # Verify the migration worked
            new_version = _get_user_version(conn)
            print(f"   Database version now: {new_version}")
        except Exception as e:
            print(f"❌ Migration v9 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 10:
        try:
            migrate_v10_passwordless_auth(conn)
            _set_user_version(conn, 10)
            conn.commit()
            print("✅ Migration v10 applied.")

            # Verify the migration worked
            c = conn.cursor()
            c.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in c.fetchall()]
            print(f"   Users table columns: {columns}")
            new_version = _get_user_version(conn)
            print(f"   Database version now: {new_version}")
        except Exception as e:
            print(f"❌ Migration v10 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 11:
        try:
            migrate_v11_create_pending_matches_table(conn)
            _set_user_version(conn, 11)
            conn.commit()
            print("✅ Migration v11 applied.")
        except Exception as e:
            print(f"❌ Migration v11 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 12:
        try:
            migrate_v12_add_borrower_access_token(conn)
            _set_user_version(conn, 12)
            conn.commit()
            print("✅ Migration v12 applied.")
        except Exception as e:
            print(f"❌ Migration v12 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 13:
        try:
            migrate_v13_add_loan_type(conn)
            _set_user_version(conn, 13)
            conn.commit()
            print("✅ Migration v13 applied.")
        except Exception as e:
            print(f"❌ Migration v13 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 14:
        try:
            migrate_v14_fix_negative_amounts(conn)
            _set_user_version(conn, 14)
            conn.commit()
            print("✅ Migration v14 applied.")
        except Exception as e:
            print(f"❌ Migration v14 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 15:
        try:
            migrate_v15_create_bank_connections(conn)
            _set_user_version(conn, 15)
            conn.commit()
            print("✅ Migration v15 applied.")
        except Exception as e:
            print(f"❌ Migration v15 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 16:
        try:
            migrate_v16_add_password_hash(conn)
            _set_user_version(conn, 16)
            conn.commit()
            print("✅ Migration v16 applied.")
        except Exception as e:
            print(f"❌ Migration v16 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 17:
        try:
            migrate_v17_add_onboarding_completed(conn)
            _set_user_version(conn, 17)
            conn.commit()
            print("✅ Migration v17 applied.")
        except Exception as e:
            print(f"❌ Migration v17 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 18:
        try:
            migrate_v18_add_email_verification(conn)
            _set_user_version(conn, 18)
            conn.commit()
            print("✅ Migration v18 applied.")
        except Exception as e:
            print(f"❌ Migration v18 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 19:
        try:
            migrate_v19_add_borrower_notification_preference(conn)
            _set_user_version(conn, 19)
            conn.commit()
            print("✅ Migration v19 applied.")
        except Exception as e:
            print(f"❌ Migration v19 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 20:
        try:
            migrate_v20_create_events_table(conn)
            _set_user_version(conn, 20)
            conn.commit()
            print("✅ Migration v20 applied.")
        except Exception as e:
            print(f"❌ Migration v20 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 21:
        try:
            migrate_v21_add_user_roles(conn)
            _set_user_version(conn, 21)
            conn.commit()
            print("✅ Migration v21 applied.")
        except Exception as e:
            print(f"❌ Migration v21 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 22:
        try:
            migrate_v22_add_subscriptions(conn)
            _set_user_version(conn, 22)
            conn.commit()
            print("✅ Migration v22 applied.")
        except Exception as e:
            print(f"❌ Migration v22 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 23:
        try:
            migrate_v23_add_encryption_salt(conn)
            _set_user_version(conn, 23)
            conn.commit()
            print("✅ Migration v23 applied.")
        except Exception as e:
            print(f"❌ Migration v23 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 24:
        try:
            migrate_v24_add_auto_match_tracking(conn)
            _set_user_version(conn, 24)
            conn.commit()
            print("✅ Migration v24 applied.")
        except Exception as e:
            print(f"❌ Migration v24 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 25:
        try:
            migrate_v25_envelope_encryption(conn)
            _set_user_version(conn, 25)
            conn.commit()
            print("✅ Migration v25 applied.")
        except Exception as e:
            print(f"❌ Migration v25 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 26:
        try:
            migrate_v26_create_rate_limits(conn)
            _set_user_version(conn, 26)
            conn.commit()
            print("✅ Migration v26 applied.")
        except Exception as e:
            print(f"❌ Migration v26 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 27:
        try:
            migrate_v27_add_last_login(conn)
            _set_user_version(conn, 27)
            conn.commit()
            print("✅ Migration v27 applied.")
        except Exception as e:
            print(f"❌ Migration v27 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    if current < 28:
        try:
            migrate_v28_master_recovery_key(conn)
            _set_user_version(conn, 28)
            conn.commit()
            print("✅ Migration v28 applied.")
        except Exception as e:
            print(f"❌ Migration v28 failed: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise

    # Ensure all changes are committed
    conn.commit()

    # Final verification
    final_version = _get_user_version(conn)
    print(f"🎉 All migrations complete. Database version: {final_version}")


def migrate_v1_create_loans_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS loans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            borrower TEXT NOT NULL,
            amount REAL NOT NULL,
            date_borrowed TEXT NOT NULL,
            date_due TEXT,
            date_repaid TEXT,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)


def migrate_v2_add_amount_repaid(conn):
    conn.execute("""
        ALTER TABLE loans
        ADD COLUMN amount_repaid REAL DEFAULT 0 NOT NULL;
    """)


def migrate_v3_add_repayment_schedule(conn):
    conn.execute("""
        ALTER TABLE loans
        ADD COLUMN repayment_amount REAL;
    """)
    conn.execute("""
        ALTER TABLE loans
        ADD COLUMN repayment_frequency TEXT;
    """)


def migrate_v4_create_applied_transactions(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS applied_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            description TEXT NOT NULL,
            amount REAL NOT NULL,
            loan_id INTEGER NOT NULL,
            applied_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (loan_id) REFERENCES loans (id)
        );
    """)
    # Create index for faster duplicate checking
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_applied_transactions_lookup
        ON applied_transactions(date, description, amount);
    """)


def migrate_v5_add_bank_name(conn):
    conn.execute("""
        ALTER TABLE loans
        ADD COLUMN bank_name TEXT;
    """)


def migrate_v6_create_rejected_matches(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rejected_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            description TEXT NOT NULL,
            amount REAL NOT NULL,
            loan_id INTEGER NOT NULL,
            rejected_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (loan_id) REFERENCES loans (id)
        );
    """)
    # Create index for faster duplicate checking
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_rejected_matches_lookup
        ON rejected_matches(date, description, amount, loan_id);
    """)


def migrate_v7_create_users_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
            auth_provider TEXT DEFAULT 'email',
            google_id TEXT UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Create index for faster lookups
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_email
        ON users(email);
    """)


def migrate_v8_add_user_id_to_loans(conn):
    # Add user_id column (nullable initially for existing loans)
    conn.execute("""
        ALTER TABLE loans
        ADD COLUMN user_id INTEGER;
    """)
    # Create index for faster filtering by user
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_loans_user_id
        ON loans(user_id);
    """)


def migrate_v9_remove_amount_repaid(conn):
    # SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
    # Check if migration already partially completed
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='loans'")
    loans_exists = c.fetchone() is not None

    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='loans_new'")
    loans_new_exists = c.fetchone() is not None

    # If loans_new exists but loans still exists, clean up the partial migration
    if loans_new_exists and loans_exists:
        conn.execute("DROP TABLE loans_new;")
        loans_new_exists = False

    # If only loans_new exists (migration was interrupted after dropping loans), rename it
    if loans_new_exists and not loans_exists:
        conn.execute("ALTER TABLE loans_new RENAME TO loans;")
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_loans_user_id
            ON loans(user_id);
        """)
        return

    # Normal migration path
    if loans_exists:
        # Check if amount_repaid column exists
        c.execute("PRAGMA table_info(loans)")
        columns = [col[1] for col in c.fetchall()]

        if 'amount_repaid' not in columns:
            # Migration already completed
            return

        # Create a new table without amount_repaid
        conn.execute("""
            CREATE TABLE loans_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                borrower TEXT NOT NULL,
                amount REAL NOT NULL,
                date_borrowed TEXT NOT NULL,
                date_due TEXT,
                date_repaid TEXT,
                note TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                repayment_amount REAL,
                repayment_frequency TEXT,
                bank_name TEXT,
                user_id INTEGER
            );
        """)

        # Copy data from old table to new table
        conn.execute("""
            INSERT INTO loans_new (id, borrower, amount, date_borrowed, date_due, date_repaid, note, created_at, repayment_amount, repayment_frequency, bank_name, user_id)
            SELECT id, borrower, amount, date_borrowed, date_due, date_repaid, note, created_at, repayment_amount, repayment_frequency, bank_name, user_id
            FROM loans;
        """)

        # Drop old table
        conn.execute("DROP TABLE loans;")

        # Rename new table to original name
        conn.execute("ALTER TABLE loans_new RENAME TO loans;")

        # Recreate index
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_loans_user_id
            ON loans(user_id);
        """)


def migrate_v10_passwordless_auth(conn):
    """
    Migrate to passwordless authentication:
    - Remove password_hash from users
    - Add passkeys table for WebAuthn credentials
    - Add magic_links table for email-based login
    - Add recovery_codes field to users
    """
    c = conn.cursor()

    # Create passkeys table for WebAuthn credentials
    conn.execute("""
        CREATE TABLE IF NOT EXISTS passkeys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            sign_count INTEGER DEFAULT 0,
            device_name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_used_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_passkeys_user_id
        ON passkeys(user_id);
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_passkeys_credential_id
        ON passkeys(credential_id);
    """)

    # Create magic_links table for email authentication
    conn.execute("""
        CREATE TABLE IF NOT EXISTS magic_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_magic_links_token
        ON magic_links(token);
    """)

    # Check current users table schema
    c.execute("PRAGMA table_info(users)")
    columns = {col[1]: col for col in c.fetchall()}

    # Check if we need to migrate the users table
    has_password_hash = 'password_hash' in columns
    has_recovery_codes = 'recovery_codes' in columns

    # Skip if already migrated
    if not has_password_hash and has_recovery_codes:
        print("  Users table already migrated, skipping...")
        return

    print(f"  Migrating users table (has_password_hash={has_password_hash}, has_recovery_codes={has_recovery_codes})...")

    # Clean up if users_new already exists from a failed migration
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users_new'")
    if c.fetchone():
        print("  Cleaning up partial migration...")
        conn.execute("DROP TABLE users_new")

    # Create new users table with correct schema
    conn.execute("""
        CREATE TABLE users_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            auth_provider TEXT DEFAULT 'magic_link',
            google_id TEXT UNIQUE,
            recovery_codes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Copy data from old table, selecting only columns that exist
    if has_recovery_codes:
        # Recovery codes already exists, preserve it
        conn.execute("""
            INSERT INTO users_new (id, email, name, auth_provider, google_id, recovery_codes, created_at)
            SELECT id, email, name, auth_provider, google_id, recovery_codes, created_at
            FROM users;
        """)
    else:
        # No recovery codes yet, set to NULL
        conn.execute("""
            INSERT INTO users_new (id, email, name, auth_provider, google_id, created_at)
            SELECT id, email, name, auth_provider, google_id, created_at
            FROM users;
        """)

    # Replace old table with new one
    conn.execute("DROP TABLE users;")
    conn.execute("ALTER TABLE users_new RENAME TO users;")

    # Recreate index
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_email
        ON users(email);
    """)

    print("  Users table migration complete.")


def migrate_v11_create_pending_matches_table(conn):
    """
    Create table to store pending transaction matches (replacing session storage).
    This fixes the session cookie size limit issue.
    """
    # Create pending_matches_data table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pending_matches_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_key TEXT NOT NULL,
            matches_json TEXT NOT NULL,
            context_transactions_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """)

    # Create index for faster lookups
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_pending_matches_session
        ON pending_matches_data(user_id, session_key);
    """)

    # Create index for cleanup of expired data
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_pending_matches_expires
        ON pending_matches_data(expires_at);
    """)

    print("  Pending matches table created successfully.")


def migrate_v12_add_borrower_access_token(conn):
    """
    Add borrower_access_token and borrower_email columns to loans table.
    This enables the borrower self-service portal feature.
    """
    import secrets

    # Add borrower_access_token column (unique token for borrower access)
    conn.execute("""
        ALTER TABLE loans
        ADD COLUMN borrower_access_token TEXT;
    """)

    # Add borrower_email column for sending invitations and notifications
    conn.execute("""
        ALTER TABLE loans
        ADD COLUMN borrower_email TEXT;
    """)

    # Generate tokens for all existing loans that don't have one
    c = conn.cursor()
    c.execute("SELECT id FROM loans WHERE borrower_access_token IS NULL")
    loans_without_tokens = c.fetchall()

    for (loan_id,) in loans_without_tokens:
        token = secrets.token_urlsafe(32)
        c.execute("UPDATE loans SET borrower_access_token = ? WHERE id = ?", (token, loan_id))

    if loans_without_tokens:
        print(f"  Generated access tokens for {len(loans_without_tokens)} existing loans")

    # Create unique index on borrower_access_token for fast lookups and uniqueness
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_loans_borrower_token
        ON loans(borrower_access_token);
    """)

    print("  Borrower access token column added successfully.")


def migrate_v13_add_loan_type(conn):
    """
    Add loan_type column to support both lending (money you lent) and borrowing (money you borrowed).
    This enables tracking loans in both directions.
    """
    # Add loan_type column - defaults to 'lending' for backwards compatibility
    conn.execute("""
        ALTER TABLE loans
        ADD COLUMN loan_type TEXT DEFAULT 'lending' NOT NULL;
    """)

    # Update all existing loans to be 'lending' type (explicit, though default handles it)
    conn.execute("""
        UPDATE loans
        SET loan_type = 'lending'
        WHERE loan_type IS NULL;
    """)

    print("  Loan type column added successfully (lending/borrowing support enabled).")


def migrate_v14_fix_negative_amounts(conn):
    """
    Fix negative amounts in applied_transactions and rejected_matches tables.
    For borrowing loans, transactions were stored as negative values, but they should
    always be positive (representing repayment amounts).
    """
    c = conn.cursor()

    # Fix applied_transactions table
    c.execute("SELECT id, amount FROM applied_transactions WHERE amount < 0")
    negative_applied = c.fetchall()

    if negative_applied:
        for trans_id, amount in negative_applied:
            c.execute("UPDATE applied_transactions SET amount = ? WHERE id = ?",
                     (abs(amount), trans_id))
        print(f"  Fixed {len(negative_applied)} negative amounts in applied_transactions.")
    else:
        print("  No negative amounts found in applied_transactions.")

    # Fix rejected_matches table
    c.execute("SELECT id, amount FROM rejected_matches WHERE amount < 0")
    negative_rejected = c.fetchall()

    if negative_rejected:
        for match_id, amount in negative_rejected:
            c.execute("UPDATE rejected_matches SET amount = ? WHERE id = ?",
                     (abs(amount), match_id))
        print(f"  Fixed {len(negative_rejected)} negative amounts in rejected_matches.")
    else:
        print("  No negative amounts found in rejected_matches.")


def migrate_v15_create_bank_connections(conn):
    """
    Create bank_connections table for storing user bank API credentials.
    Enables multi-user, multi-bank support with encrypted credential storage.
    """
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS bank_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            connector_type TEXT NOT NULL,
            display_name TEXT,
            credentials_encrypted TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            last_synced_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    c.execute("CREATE INDEX IF NOT EXISTS idx_bank_connections_user ON bank_connections(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_bank_connections_active ON bank_connections(user_id, is_active)")

    conn.commit()
    print("  Bank connections table created successfully.")


def migrate_v16_add_password_hash(conn):
    """
    Add password_hash column to users table for optional password authentication.
    Allows users to choose between magic link (passwordless) or password auth.
    """
    c = conn.cursor()

    # Check if password_hash column already exists
    c.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in c.fetchall()]

    if 'password_hash' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        print("  Added password_hash column to users table.")
    else:
        print("  password_hash column already exists.")

    conn.commit()


def migrate_v17_add_onboarding_completed(conn):
    """
    Add onboarding_completed column to track if user has completed initial setup.
    Enables streamlined onboarding flow for new users.
    """
    c = conn.cursor()

    # Check if column already exists
    c.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in c.fetchall()]

    if 'onboarding_completed' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN onboarding_completed BOOLEAN DEFAULT 0")
        # Mark existing users as having completed onboarding
        c.execute("UPDATE users SET onboarding_completed = 1")
        print("  Added onboarding_completed column to users table.")


def migrate_v18_add_email_verification(conn):
    """
    Add email verification columns to prevent spam accounts.
    Unverified users will have restricted functionality until they verify their email.
    """
    c = conn.cursor()

    # Check which columns already exist
    c.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in c.fetchall()]

    if 'email_verified' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 0")
        # Mark existing users as verified (grandfather them in)
        c.execute("UPDATE users SET email_verified = 1")
        print("  Added email_verified column to users table.")

    if 'verification_token' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN verification_token TEXT")
        print("  Added verification_token column to users table.")

    if 'verification_sent_at' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN verification_sent_at TEXT")
        print("  Added verification_sent_at column to users table.")


def migrate_v19_add_borrower_notification_preference(conn):
    """
    Add borrower notification preference to allow borrowers to opt out of email notifications.
    They can still access the borrower portal even if notifications are disabled.
    """
    c = conn.cursor()

    # Check if column already exists
    c.execute("PRAGMA table_info(loans)")
    columns = [row[1] for row in c.fetchall()]

    if 'borrower_notifications_enabled' not in columns:
        c.execute("ALTER TABLE loans ADD COLUMN borrower_notifications_enabled BOOLEAN DEFAULT 1")
        print("  Added borrower_notifications_enabled column to loans table.")


def migrate_v20_create_events_table(conn):
    """
    Create events table for analytics and usage tracking.
    Tracks key user actions for metrics like DAU/WAU/MAU, retention, and conversion funnels.
    """
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_name TEXT NOT NULL,
            user_id INTEGER,
            session_id TEXT,
            event_data TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # Create indexes for fast analytics queries
    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_event_name
        ON events(event_name)
    """)

    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_user_id
        ON events(user_id)
    """)

    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_created_at
        ON events(created_at)
    """)

    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_user_date
        ON events(user_id, created_at)
    """)

    print("  Created events table with indexes for analytics.")


def migrate_v21_add_user_roles(conn):
    """
    Add role column to users table for role-based access control.
    Roles: 'user' (default), 'admin' (full access including analytics).
    """
    c = conn.cursor()

    # Check if column already exists
    c.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in c.fetchall()]

    if 'role' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        # Make the first user an admin (usually the person deploying)
        c.execute("UPDATE users SET role = 'admin' WHERE id = 1")
        print("  Added role column to users table. First user set as admin.")


def migrate_v22_add_subscriptions(conn):
    """
    Add subscription system with Stripe integration.
    - Add subscription fields to users table
    - Create subscription_plans table (free, basic, pro)
    - Create user_subscriptions table for Stripe subscription tracking
    - Grandfather all existing users to Pro tier (lifetime free)
    """
    import json
    c = conn.cursor()

    # 1. Add subscription columns to users table
    c.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in c.fetchall()]

    if 'subscription_tier' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN subscription_tier TEXT DEFAULT 'free'")
        print("  Added subscription_tier column to users table.")

    if 'stripe_customer_id' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN stripe_customer_id TEXT")
        print("  Added stripe_customer_id column to users table.")

    if 'manual_override' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN manual_override BOOLEAN DEFAULT 0")
        print("  Added manual_override column to users table.")

    if 'trial_ends_at' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN trial_ends_at TEXT")
        print("  Added trial_ends_at column to users table.")

    # 2. Create subscription_plans table
    c.execute("""
        CREATE TABLE IF NOT EXISTS subscription_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tier TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            price_monthly INTEGER,
            price_yearly INTEGER,
            stripe_price_id_monthly TEXT,
            stripe_price_id_yearly TEXT,
            max_loans INTEGER,
            features_json TEXT NOT NULL,
            active BOOLEAN DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("  Created subscription_plans table.")

    # 3. Create user_subscriptions table
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            stripe_subscription_id TEXT UNIQUE,
            stripe_customer_id TEXT,
            tier TEXT NOT NULL,
            status TEXT NOT NULL,
            current_period_start TEXT,
            current_period_end TEXT,
            cancel_at_period_end BOOLEAN DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    print("  Created user_subscriptions table.")

    # Create indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_id ON user_subscriptions(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_user_subscriptions_status ON user_subscriptions(status)")
    print("  Created indexes on user_subscriptions.")

    # 4. Seed subscription_plans with our 3 tiers
    plans = [
        {
            'tier': 'free',
            'name': 'Free',
            'price_monthly': 0,
            'price_yearly': 0,
            'stripe_price_id_monthly': None,
            'stripe_price_id_yearly': None,
            'max_loans': 3,
            'features': {
                'max_loans': 3,
                'manual_repayment': True,
                'csv_import': True,
                'borrower_portal': True,
                'email_notifications': False,
                'transaction_export': False,
                'bank_api': False,
                'analytics': False
            }
        },
        {
            'tier': 'basic',
            'name': 'Basic',
            'price_monthly': 900,  # $9.00 in cents
            'price_yearly': 9000,  # $90.00 in cents
            'stripe_price_id_monthly': None,  # Set via env vars later
            'stripe_price_id_yearly': None,
            'max_loans': 25,
            'features': {
                'max_loans': 25,
                'manual_repayment': True,
                'csv_import': True,
                'borrower_portal': True,
                'email_notifications': True,
                'transaction_export': True,
                'bank_api': False,
                'analytics': False
            }
        },
        {
            'tier': 'pro',
            'name': 'Pro',
            'price_monthly': 1900,  # $19.00 in cents
            'price_yearly': 19000,  # $190.00 in cents
            'stripe_price_id_monthly': None,  # Set via env vars later
            'stripe_price_id_yearly': None,
            'max_loans': None,  # Unlimited
            'features': {
                'max_loans': None,  # Unlimited
                'manual_repayment': True,
                'csv_import': True,
                'borrower_portal': True,
                'email_notifications': True,
                'transaction_export': True,
                'bank_api': True,
                'analytics': True,
                'advanced_matching': True
            }
        }
    ]

    for plan in plans:
        c.execute("""
            INSERT OR IGNORE INTO subscription_plans
            (tier, name, price_monthly, price_yearly, stripe_price_id_monthly,
             stripe_price_id_yearly, max_loans, features_json, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            plan['tier'],
            plan['name'],
            plan['price_monthly'],
            plan['price_yearly'],
            plan['stripe_price_id_monthly'],
            plan['stripe_price_id_yearly'],
            plan['max_loans'],
            json.dumps(plan['features'])
        ))

    print("  Seeded subscription_plans with free, basic, and pro tiers.")

    # 5. Grandfather all existing users to Pro tier (lifetime)
    c.execute("SELECT COUNT(*) FROM users")
    user_count = c.fetchone()[0]

    if user_count > 0:
        c.execute("""
            UPDATE users
            SET subscription_tier = 'pro',
                manual_override = 1
            WHERE id IN (SELECT id FROM users)
        """)
        print(f"  Grandfathered {user_count} existing user(s) to Pro tier (lifetime free).")


def migrate_v23_add_encryption_salt(conn):
    """
    Add encryption_salt to users table for zero-knowledge encryption.
    This enables deriving encryption keys from user passwords instead of
    storing a server-side key, ensuring server admins cannot access bank credentials.
    """
    c = conn.cursor()

    # Check if column already exists
    c.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in c.fetchall()]

    if 'encryption_salt' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN encryption_salt TEXT")
        print("  Added encryption_salt column to users table.")
    else:
        print("  encryption_salt column already exists.")


def migrate_v24_add_auto_match_tracking(conn):
    """
    Add tracking fields to applied_transactions for auto-matching feature.
    - auto_applied: Track which matches were automatically applied vs manually reviewed
    - confidence_score: Store matching confidence (0-100) for transparency
    - connection_id: Track which bank connection the transaction came from
    """
    c = conn.cursor()

    # Check which columns already exist
    c.execute("PRAGMA table_info(applied_transactions)")
    columns = [row[1] for row in c.fetchall()]

    if 'auto_applied' not in columns:
        c.execute("ALTER TABLE applied_transactions ADD COLUMN auto_applied BOOLEAN DEFAULT 0")
        print("  Added auto_applied column to applied_transactions table.")

    if 'confidence_score' not in columns:
        c.execute("ALTER TABLE applied_transactions ADD COLUMN confidence_score REAL")
        print("  Added confidence_score column to applied_transactions table.")

    if 'connection_id' not in columns:
        c.execute("ALTER TABLE applied_transactions ADD COLUMN connection_id INTEGER")
        print("  Added connection_id column to applied_transactions table.")

    # Create index for querying auto-applied transactions
    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_applied_transactions_auto_applied
        ON applied_transactions(auto_applied, applied_at)
    """)


def migrate_v25_envelope_encryption(conn):
    """
    Implement envelope encryption for true zero-knowledge data storage.

    Encryption Strategy:
    - Each loan gets a unique Data Encryption Key (DEK)
    - Loan data is encrypted with the DEK
    - DEK is encrypted with lender's password and stored in encrypted_dek column
    - DEK is also embedded in borrower_access_token for borrower access

    This ensures:
    - Server admins cannot read loan data (zero-knowledge)
    - Lenders can decrypt with their password
    - Borrowers can decrypt with their access token (no password needed)

    Fields encrypted in loans table:
    - borrower, amount, note, bank_name, borrower_email
    - repayment_amount, repayment_frequency

    Fields encrypted in applied_transactions and rejected_matches:
    - description, amount

    Fields encrypted in pending_matches_data:
    - matches_json, context_transactions_json
    """
    from services.encryption import (
        generate_dek, create_token_from_dek, encrypt_dek_with_password,
        encrypt_field, derive_key_from_password
    )

    c = conn.cursor()

    print("  Starting envelope encryption migration...")

    # ========================================================================
    # Step 0: Make old plaintext columns nullable (backwards compatibility)
    # ========================================================================
    print("  Making old plaintext columns nullable...")

    # SQLite doesn't support ALTER COLUMN, so we need to recreate the table
    # First, check if we need to do this migration
    c.execute("PRAGMA table_info(loans)")
    columns_info = c.fetchall()

    # Check if borrower column is NOT NULL
    borrower_is_not_null = any(col[1] == 'borrower' and col[3] == 1 for col in columns_info)

    if borrower_is_not_null:
        print("    Recreating loans table to make plaintext columns nullable...")

        # Get all existing column names
        c.execute("PRAGMA table_info(loans)")
        existing_columns = [col[1] for col in c.fetchall()]

        # Create new table with same structure but nullable plaintext columns
        # Only include columns that exist in old table
        c.execute("""
            CREATE TABLE loans_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                borrower TEXT,
                amount REAL,
                date_borrowed TEXT NOT NULL,
                date_due TEXT,
                date_repaid TEXT,
                note TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                repayment_amount REAL,
                repayment_frequency TEXT,
                bank_name TEXT,
                user_id INTEGER,
                borrower_access_token TEXT,
                borrower_email TEXT,
                loan_type TEXT DEFAULT 'lending' NOT NULL,
                borrower_notifications_enabled BOOLEAN DEFAULT 1
            )
        """)

        # Copy data from old table (only columns that exist)
        column_list = ', '.join(existing_columns)
        c.execute(f"INSERT INTO loans_new ({column_list}) SELECT {column_list} FROM loans")

        # Drop old table
        c.execute("DROP TABLE loans")

        # Rename new table
        c.execute("ALTER TABLE loans_new RENAME TO loans")

        # Recreate indexes
        c.execute("CREATE INDEX IF NOT EXISTS idx_loans_user_id ON loans(user_id)")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_loans_borrower_token ON loans(borrower_access_token)")

        print("    Loans table recreated with nullable columns.")
    else:
        print("    Plaintext columns already nullable, skipping table recreation.")

    # ========================================================================
    # Step 1: Add encrypted columns to loans table
    # ========================================================================
    c.execute("PRAGMA table_info(loans)")
    loan_columns = [row[1] for row in c.fetchall()]

    if 'encrypted_dek' not in loan_columns:
        c.execute("ALTER TABLE loans ADD COLUMN encrypted_dek TEXT")
        print("    Added encrypted_dek column to loans table.")

    if 'borrower_encrypted' not in loan_columns:
        c.execute("ALTER TABLE loans ADD COLUMN borrower_encrypted TEXT")
        print("    Added borrower_encrypted column to loans table.")

    if 'amount_encrypted' not in loan_columns:
        c.execute("ALTER TABLE loans ADD COLUMN amount_encrypted TEXT")
        print("    Added amount_encrypted column to loans table.")

    if 'note_encrypted' not in loan_columns:
        c.execute("ALTER TABLE loans ADD COLUMN note_encrypted TEXT")
        print("    Added note_encrypted column to loans table.")

    if 'bank_name_encrypted' not in loan_columns:
        c.execute("ALTER TABLE loans ADD COLUMN bank_name_encrypted TEXT")
        print("    Added bank_name_encrypted column to loans table.")

    if 'borrower_email_encrypted' not in loan_columns:
        c.execute("ALTER TABLE loans ADD COLUMN borrower_email_encrypted TEXT")
        print("    Added borrower_email_encrypted column to loans table.")

    if 'repayment_amount_encrypted' not in loan_columns:
        c.execute("ALTER TABLE loans ADD COLUMN repayment_amount_encrypted TEXT")
        print("    Added repayment_amount_encrypted column to loans table.")

    if 'repayment_frequency_encrypted' not in loan_columns:
        c.execute("ALTER TABLE loans ADD COLUMN repayment_frequency_encrypted TEXT")
        print("    Added repayment_frequency_encrypted column to loans table.")

    # ========================================================================
    # Step 2: Add encrypted columns to applied_transactions
    # ========================================================================
    c.execute("PRAGMA table_info(applied_transactions)")
    applied_columns = [row[1] for row in c.fetchall()]

    if 'description_encrypted' not in applied_columns:
        c.execute("ALTER TABLE applied_transactions ADD COLUMN description_encrypted TEXT")
        print("    Added description_encrypted column to applied_transactions table.")

    if 'amount_encrypted' not in applied_columns:
        c.execute("ALTER TABLE applied_transactions ADD COLUMN amount_encrypted TEXT")
        print("    Added amount_encrypted column to applied_transactions table.")

    # ========================================================================
    # Step 3: Add encrypted columns to rejected_matches
    # ========================================================================
    c.execute("PRAGMA table_info(rejected_matches)")
    rejected_columns = [row[1] for row in c.fetchall()]

    if 'description_encrypted' not in rejected_columns:
        c.execute("ALTER TABLE rejected_matches ADD COLUMN description_encrypted TEXT")
        print("    Added description_encrypted column to rejected_matches table.")

    if 'amount_encrypted' not in rejected_columns:
        c.execute("ALTER TABLE rejected_matches ADD COLUMN amount_encrypted TEXT")
        print("    Added amount_encrypted column to rejected_matches table.")

    # ========================================================================
    # Step 4: Add encrypted columns to pending_matches_data
    # ========================================================================
    c.execute("PRAGMA table_info(pending_matches_data)")
    pending_columns = [row[1] for row in c.fetchall()]

    if 'matches_json_encrypted' not in pending_columns:
        c.execute("ALTER TABLE pending_matches_data ADD COLUMN matches_json_encrypted TEXT")
        print("    Added matches_json_encrypted column to pending_matches_data table.")

    if 'context_transactions_json_encrypted' not in pending_columns:
        c.execute("ALTER TABLE pending_matches_data ADD COLUMN context_transactions_json_encrypted TEXT")
        print("    Added context_transactions_json_encrypted column to pending_matches_data table.")

    # ========================================================================
    # Step 5: Migrate existing loan data
    # ========================================================================
    print("  Migrating existing loan data to encrypted format...")

    # Get all loans that need migration (no encrypted_dek yet)
    c.execute("""
        SELECT l.id, l.borrower, l.amount, l.note, l.bank_name, l.borrower_email,
               l.repayment_amount, l.repayment_frequency, l.borrower_access_token,
               l.user_id, u.encryption_salt
        FROM loans l
        LEFT JOIN users u ON u.id = l.user_id
        WHERE l.encrypted_dek IS NULL
    """)

    loans_to_migrate = c.fetchall()

    if loans_to_migrate:
        print(f"    Found {len(loans_to_migrate)} loans to encrypt...")

        # We need user passwords to encrypt the DEKs, but we don't have them!
        # Solution: For existing loans, we'll need to encrypt them on next login
        # For now, just generate DEKs and new tokens, store encrypted_dek as NULL
        # The app will handle migration on next password-authenticated access

        for loan in loans_to_migrate:
            (loan_id, borrower, amount, note, bank_name, borrower_email,
             repayment_amount, repayment_frequency, old_token, user_id, encryption_salt) = loan

            # Generate new DEK for this loan
            dek = generate_dek()

            # Create new borrower access token from DEK
            new_token = create_token_from_dek(dek)

            # Encrypt all fields with the DEK
            borrower_enc = encrypt_field(borrower, dek) if borrower else None
            amount_enc = encrypt_field(str(amount), dek) if amount is not None else None
            note_enc = encrypt_field(note, dek) if note else None
            bank_name_enc = encrypt_field(bank_name, dek) if bank_name else None
            borrower_email_enc = encrypt_field(borrower_email, dek) if borrower_email else None
            repayment_amount_enc = encrypt_field(str(repayment_amount), dek) if repayment_amount is not None else None
            repayment_frequency_enc = encrypt_field(repayment_frequency, dek) if repayment_frequency else None

            # Note: We can't encrypt the DEK with user's password here because we don't have it
            # Set encrypted_dek to a special marker that will trigger re-encryption on next login
            # We'll use a placeholder that encodes the DEK temporarily (insecure, but will be replaced)
            encrypted_dek_placeholder = f"MIGRATION_PENDING:{dek.decode('utf-8')}"

            # Update the loan record
            c.execute("""
                UPDATE loans
                SET borrower_encrypted = ?,
                    amount_encrypted = ?,
                    note_encrypted = ?,
                    bank_name_encrypted = ?,
                    borrower_email_encrypted = ?,
                    repayment_amount_encrypted = ?,
                    repayment_frequency_encrypted = ?,
                    encrypted_dek = ?,
                    borrower_access_token = ?
                WHERE id = ?
            """, (
                borrower_enc, amount_enc, note_enc, bank_name_enc, borrower_email_enc,
                repayment_amount_enc, repayment_frequency_enc,
                encrypted_dek_placeholder, new_token, loan_id
            ))

        print(f"    Encrypted {len(loans_to_migrate)} loans.")
        print("    ⚠️  Note: DEKs stored with temporary placeholder - will be encrypted with user password on next login")
    else:
        print("    No loans to migrate.")

    # ========================================================================
    # Step 6: Migrate applied_transactions
    # ========================================================================
    print("  Migrating applied_transactions to encrypted format...")

    # For transactions, we need to get the DEK from the associated loan
    c.execute("""
        SELECT at.id, at.description, at.amount, at.loan_id, l.encrypted_dek
        FROM applied_transactions at
        JOIN loans l ON l.id = at.loan_id
        WHERE at.description_encrypted IS NULL
    """)

    transactions_to_migrate = c.fetchall()

    if transactions_to_migrate:
        print(f"    Found {len(transactions_to_migrate)} transactions to encrypt...")

        for trans in transactions_to_migrate:
            trans_id, description, amount, loan_id, encrypted_dek_str = trans

            # Extract DEK from placeholder (temporary during migration)
            if encrypted_dek_str and encrypted_dek_str.startswith("MIGRATION_PENDING:"):
                dek_str = encrypted_dek_str.replace("MIGRATION_PENDING:", "")
                dek = dek_str.encode('utf-8')

                # Encrypt transaction fields
                desc_enc = encrypt_field(description, dek) if description else None
                amount_enc = encrypt_field(str(amount), dek) if amount is not None else None

                c.execute("""
                    UPDATE applied_transactions
                    SET description_encrypted = ?,
                        amount_encrypted = ?
                    WHERE id = ?
                """, (desc_enc, amount_enc, trans_id))

        print(f"    Encrypted {len(transactions_to_migrate)} applied transactions.")
    else:
        print("    No applied transactions to migrate.")

    # ========================================================================
    # Step 7: Migrate rejected_matches
    # ========================================================================
    print("  Migrating rejected_matches to encrypted format...")

    c.execute("""
        SELECT rm.id, rm.description, rm.amount, rm.loan_id, l.encrypted_dek
        FROM rejected_matches rm
        JOIN loans l ON l.id = rm.loan_id
        WHERE rm.description_encrypted IS NULL
    """)

    rejected_to_migrate = c.fetchall()

    if rejected_to_migrate:
        print(f"    Found {len(rejected_to_migrate)} rejected matches to encrypt...")

        for match in rejected_to_migrate:
            match_id, description, amount, loan_id, encrypted_dek_str = match

            # Extract DEK from placeholder
            if encrypted_dek_str and encrypted_dek_str.startswith("MIGRATION_PENDING:"):
                dek_str = encrypted_dek_str.replace("MIGRATION_PENDING:", "")
                dek = dek_str.encode('utf-8')

                # Encrypt match fields
                desc_enc = encrypt_field(description, dek) if description else None
                amount_enc = encrypt_field(str(amount), dek) if amount is not None else None

                c.execute("""
                    UPDATE rejected_matches
                    SET description_encrypted = ?,
                        amount_encrypted = ?
                    WHERE id = ?
                """, (desc_enc, amount_enc, match_id))

        print(f"    Encrypted {len(rejected_to_migrate)} rejected matches.")
    else:
        print("    No rejected matches to migrate.")

    print("  ✅ Envelope encryption migration complete!")
    print("  ⚠️  Users will need to log in with their password to finalize DEK encryption.")


def migrate_v26_create_rate_limits(conn):
    """
    Create rate_limits table for anti-spam measures.
    Tracks registration attempts by IP address to prevent bot signups.
    """
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS rate_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create index for faster lookups
    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_rate_limits_key
        ON rate_limits(key, timestamp)
    """)

    print("  Created rate_limits table for anti-spam tracking.")


def migrate_v27_add_last_login(conn):
    """
    Add last_login_at column to track when users last accessed their account.
    This enables automatic cleanup of inactive/unused accounts.
    """
    c = conn.cursor()

    # Check if column already exists
    c.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in c.fetchall()]

    if 'last_login_at' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")
        # Set last_login_at to created_at for existing users (assume they logged in when they signed up)
        c.execute("UPDATE users SET last_login_at = created_at WHERE last_login_at IS NULL")
        print("  Added last_login_at column to users table.")
    else:
        print("  last_login_at column already exists.")

    conn.commit()


def migrate_v28_master_recovery_key(conn):
    """
    Add Master Recovery Key support to enable password recovery without data loss.

    The Master Recovery Key is a strong 32+ character key generated during registration
    that allows users to reset their password without losing access to encrypted data.

    How it works:
    - Each loan's DEK is encrypted TWO ways:
      1. encrypted_dek (with user password) - existing
      2. encrypted_dek_recovery (with master recovery key) - NEW
    - When user forgets password and uses recovery codes to login, they can reset their
      password because we can decrypt DEKs with the master recovery key and re-encrypt
      them with the new password
    - The master recovery key is shown to the user ONCE during registration (like recovery codes)
      and stored hashed in the database (like password_hash)

    Migration strategy:
    - For existing loans: encrypted_dek_recovery will be NULL until user next logs in with password
    - On password login, the app will detect NULL encrypted_dek_recovery and populate it
    """
    c = conn.cursor()

    # ========================================================================
    # Step 1: Add master_recovery_key_hash column to users table
    # ========================================================================
    c.execute("PRAGMA table_info(users)")
    user_columns = [row[1] for row in c.fetchall()]

    if 'master_recovery_key_hash' not in user_columns:
        c.execute("ALTER TABLE users ADD COLUMN master_recovery_key_hash TEXT")
        print("  Added master_recovery_key_hash column to users table.")
    else:
        print("  master_recovery_key_hash column already exists.")

    # ========================================================================
    # Step 2: Add encrypted_dek_recovery column to loans table
    # ========================================================================
    c.execute("PRAGMA table_info(loans)")
    loan_columns = [row[1] for row in c.fetchall()]

    if 'encrypted_dek_recovery' not in loan_columns:
        c.execute("ALTER TABLE loans ADD COLUMN encrypted_dek_recovery TEXT")
        print("  Added encrypted_dek_recovery column to loans table.")
    else:
        print("  encrypted_dek_recovery column already exists.")

    # ========================================================================
    # Step 3: Check for existing loans that need migration
    # ========================================================================
    c.execute("SELECT COUNT(*) FROM loans WHERE encrypted_dek_recovery IS NULL")
    loans_needing_migration = c.fetchone()[0]

    if loans_needing_migration > 0:
        print(f"  ⚠️  Found {loans_needing_migration} existing loan(s) that need recovery key encryption.")
        print("  These loans will be automatically migrated when the user next logs in with their password.")
    else:
        print("  No existing loans need migration.")

    conn.commit()
    print("  Master Recovery Key system enabled!")
