"""SQLite connection and schema initialization helpers."""

from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA_PATH = Path(__file__).with_name("schema.sql")

_PRAGMAS_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
"""


def resolve_db_path(db_path: str | Path | None) -> str:
    """Normalize a database path, defaulting to in-memory SQLite."""
    if db_path is None:
        return ":memory:"
    raw = str(db_path).strip()
    return raw if raw else ":memory:"


def load_schema_sql() -> str:
    """Read the bundled SQLite schema definition."""
    return _SCHEMA_PATH.read_text(encoding="utf-8")


def open_database(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Open a WAL-enabled SQLite connection and initialize the schema."""
    resolved = resolve_db_path(db_path)
    if resolved != ":memory:":
        Path(resolved).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(resolved, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_PRAGMAS_SQL)
    conn.executescript(load_schema_sql())
    return conn
