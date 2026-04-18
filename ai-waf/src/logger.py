"""
logger.py
---------
SQLite-backed event logger.  Every HTTP request the WAF sees gets a row:
  - timestamp, method, url, label (0/1), score (probability), action (ALLOW/BLOCK)

The dashboard (Week 5) reads from this database to show live stats.
"""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from src.config import LOG_DB_PATH

# Thread-local storage so each thread gets its own connection
_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Return a per-thread SQLite connection, creating the DB + table if needed."""
    db_path = Path(LOG_DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _create_table(_local.conn)

    return _local.conn


def _create_table(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            method    TEXT    NOT NULL,
            url       TEXT    NOT NULL,
            path      TEXT,
            score     REAL    NOT NULL,
            label     INTEGER NOT NULL,
            action    TEXT    NOT NULL,
            client_ip TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_action ON events(action)
    """)
    conn.commit()


def log_event(
    method: str,
    url: str,
    path: str,
    score: float,
    label: int,
    action: str,
    client_ip: str = "",
):
    """Insert one WAF decision into the database."""
    conn = _get_conn()
    conn.execute(
        """
        INSERT INTO events (timestamp, method, url, path, score, label, action, client_ip)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            method,
            url,
            path,
            round(float(score), 4),
            int(label),
            action,
            client_ip,
        ),
    )
    conn.commit()


def get_recent(limit: int = 100) -> list[dict]:
    """Return the most recent `limit` events as a list of dicts."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    """Return aggregate stats for the dashboard."""
    conn = _get_conn()

    total  = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    blocked = conn.execute("SELECT COUNT(*) FROM events WHERE action='BLOCK'").fetchone()[0]
    allowed = conn.execute("SELECT COUNT(*) FROM events WHERE action='ALLOW'").fetchone()[0]

    # Last 10 minutes block rate
    ten_min_ago = datetime.now(timezone.utc).replace(microsecond=0).isoformat(timespec="seconds")
    recent_total = conn.execute(
        "SELECT COUNT(*) FROM events WHERE timestamp >= datetime(?, '-10 minutes')",
        (ten_min_ago,)
    ).fetchone()[0]
    recent_blocked = conn.execute(
        "SELECT COUNT(*) FROM events WHERE action='BLOCK' AND timestamp >= datetime(?, '-10 minutes')",
        (ten_min_ago,)
    ).fetchone()[0]

    return {
        "total":          total,
        "blocked":        blocked,
        "allowed":        allowed,
        "block_rate_pct": round(blocked / total * 100, 2) if total > 0 else 0.0,
        "recent_total":   recent_total,
        "recent_blocked": recent_blocked,
    }


def clear_all():
    """Wipe all events — useful for testing."""
    conn = _get_conn()
    conn.execute("DELETE FROM events")
    conn.commit()


if __name__ == "__main__":
    # Quick smoke-test
    clear_all()
    log_event("GET",  "http://localhost/page",           "/page",           0.12, 0, "ALLOW", "127.0.0.1")
    log_event("POST", "http://localhost/login",          "/login",          0.73, 1, "BLOCK", "192.168.1.5")
    log_event("GET",  "http://localhost/img/logo.png",   "/img/logo.png",   0.03, 0, "ALLOW", "127.0.0.1")
    log_event("GET",  "http://localhost/admin?id=1 OR 1=1", "/admin",       0.95, 1, "BLOCK", "10.0.0.2")

    print("Logged 4 events.")
    print("\nStats:", get_stats())
    print("\nRecent events:")
    for e in get_recent():
        print(f"  [{e['action']}] {e['method']} {e['url'][:60]}  score={e['score']}")
