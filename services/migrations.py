# services/migrations.py

def _get_user_version(conn) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def _set_user_version(conn, version: int) -> None:
    conn.execute(f"PRAGMA user_version = {version}")


def run_migrations(conn):
    current = _get_user_version(conn)

    if current < 1:
        migrate_v1_create_loans_table(conn)
        _set_user_version(conn, 1)
        print("✅ Migration v1 applied.")

    if current < 2:
        migrate_v2_add_amount_repaid(conn)
        _set_user_version(conn, 2)
        print("✅ Migration v2 applied.")

    if current < 3:
        migrate_v3_add_repayment_schedule(conn)
        _set_user_version(conn, 3)
        print("✅ Migration v3 applied.")

    if current < 4:
        migrate_v4_create_applied_transactions(conn)
        _set_user_version(conn, 4)
        print("✅ Migration v4 applied.")

    if current < 5:
        migrate_v5_add_bank_name(conn)
        _set_user_version(conn, 5)
        print("✅ Migration v5 applied.")

    if current < 6:
        migrate_v6_create_rejected_matches(conn)
        _set_user_version(conn, 6)
        print("✅ Migration v6 applied.")


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
