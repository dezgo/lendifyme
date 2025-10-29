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
