# helpers/db.py
from flask import current_app, has_app_context
import os
import os.path as p
import sqlite3

DEFAULT_DB = "lendifyme.db"


def get_db_path() -> str:
    """
    Resolve a single source of truth for the SQLite DB path.

    Priority:
      1) Flask app config: app.config["DATABASE"]
      2) TEST_DB_PATH env (useful in tests/CLI)
      3) DATABASE env
      4) instance_path/lendifyme.db (when in app context)
      5) ./lendifyme.db (repo root)
    """
    # 1) Inside app context? Let app config win.
    if has_app_context():
        db_from_cfg = current_app.config.get("DATABASE")
        if db_from_cfg:
            return db_from_cfg

    # 2) Explicit test override via env
    test_env = os.environ.get("TEST_DB_PATH")
    if test_env:
        return test_env

    # 3) Generic env override
    env_db = os.environ.get("DATABASE")
    if env_db:
        return env_db

    # 4) If we have an app context, prefer instance folder
    if has_app_context():
        inst = getattr(current_app, "instance_path", None)
        if inst:
            return p.join(inst, DEFAULT_DB)

    # 5) Fallback: project root
    return p.abspath(DEFAULT_DB)


def get_db_connection():
    """Open a connection to the resolved DB path with sensible defaults."""
    conn = sqlite3.connect(get_db_path())
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
