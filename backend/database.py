"""
DATABASE LAYER
====================================================
Plain SQLite (a single local file, no server to install) holding two
tables: every packet we've ever ingested, and every alert we've ever
raised. This is what makes the backend a real, persistent system rather
than a script — state survives restarts, and can be queried directly
with normal SQL if you ever want to (`sqlite3 data.db`).
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "data.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row  # lets us access columns by name, e.g. row["src_ip"]
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT,
            dst_port INTEGER,
            protocol TEXT,
            packet_size INTEGER,
            dns_query TEXT DEFAULT '',
            ja3 TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_traffic_src ON traffic(src_ip);
        CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic(timestamp);

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            layer TEXT NOT NULL,
            category TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            confidence_percent REAL NOT NULL,
            explanation TEXT NOT NULL,
            detection_latency_sec REAL DEFAULT 0,
            decoded_bits TEXT DEFAULT '',
            ja3 TEXT DEFAULT '',
            matched_threat TEXT DEFAULT '',
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);
        CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);

        CREATE TABLE IF NOT EXISTS ja3_feed (
            ja3 TEXT PRIMARY KEY,
            threat TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


def clear_all():
    """Wipes traffic + alerts (keeps the JA3 feed). Used by seed.py so
    re-seeding doesn't just keep appending duplicates."""
    conn = get_conn()
    conn.execute("DELETE FROM traffic")
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
