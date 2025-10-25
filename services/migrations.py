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
