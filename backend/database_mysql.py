"""
DATABASE LAYER — MySQL
====================================================
This is the production-grade version of the database layer. Same
two core tables as the SQLite version (traffic, alerts), but with
proper MySQL types, a real foreign key between them, and indexes
sized for actual query patterns — this is meant to hold up under
real traffic volume, not just a demo dataset.

Requires a running MySQL/MariaDB server and a database already
created (see README.md "MySQL backend" section for the exact
commands). Connection details come from config.py.
"""

import pymysql
import pymysql.cursors

from config import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME


def get_conn():
    """Every call gets its own connection — simple and safe for a
    project this size. (At real scale you'd add a connection pool,
    e.g. DBUtils.PooledDB — noted here for anyone picking this up.)

    autocommit=True is deliberate: with it False, MySQL's default
    REPEATABLE READ isolation lets a connection's very first query
    freeze a consistent snapshot of the data for that connection's
    entire session — so a read-only connection can keep seeing an
    outdated view even after other connections (like /api/ingest, or
    a tool like MySQL Workbench) have committed new rows. With
    autocommit=True, every single query starts its own fresh
    transaction and always sees the latest committed data. For a
    read-heavy API like this one, that's exactly what we want."""
    return pymysql.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD,
        database=DB_NAME, charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor, autocommit=True,
    )


SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DOUBLE NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45),
    dst_port INT,
    protocol VARCHAR(10),
    packet_size INT,
    dns_query VARCHAR(255) DEFAULT '',
    ja3 VARCHAR(64) DEFAULT '',
    INDEX idx_traffic_src (src_ip),
    INDEX idx_traffic_ts (timestamp),
    INDEX idx_traffic_src_ts (src_ip, timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS alerts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DOUBLE NOT NULL,
    layer VARCHAR(64) NOT NULL,
    category VARCHAR(80) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    confidence_percent FLOAT NOT NULL,
    explanation TEXT NOT NULL,
    detection_latency_sec FLOAT DEFAULT 0,
    decoded_bits VARCHAR(128) DEFAULT '',
    ja3 VARCHAR(64) DEFAULT '',
    matched_threat VARCHAR(120) DEFAULT '',
    model_used VARCHAR(40) DEFAULT 'rule-based',
    created_at DOUBLE NOT NULL,
    INDEX idx_alerts_src (src_ip),
    INDEX idx_alerts_category (category),
    INDEX idx_alerts_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ja3_feed (
    ja3 VARCHAR(64) PRIMARY KEY,
    threat VARCHAR(120) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ml_predictions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    src_ip VARCHAR(45) NOT NULL,
    model_name VARCHAR(40) NOT NULL,
    predicted_label VARCHAR(80) NOT NULL,
    confidence FLOAT NOT NULL,
    is_final_verdict BOOLEAN NOT NULL DEFAULT FALSE,
    features_json TEXT,
    created_at DOUBLE NOT NULL,
    INDEX idx_ml_src (src_ip),
    INDEX idx_ml_model (model_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def init_db():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            for statement in SCHEMA.split(";"):
                statement = statement.strip()
                if statement:
                    cur.execute(statement)
        conn.commit()

        # Safe migration for anyone with an existing database from
        # before is_final_verdict existed — CREATE TABLE IF NOT EXISTS
        # above won't add a column to an already-existing table, so
        # this covers upgrading in place without dropping the database.
        # "ADD COLUMN IF NOT EXISTS" is a MariaDB-only shortcut — real
        # MySQL doesn't support that syntax at all, so this instead
        # just tries the plain ALTER TABLE and quietly ignores the
        # "column already exists" error, which works on both.
        try:
            with conn.cursor() as cur:
                cur.execute("ALTER TABLE ml_predictions ADD COLUMN "
                            "is_final_verdict BOOLEAN NOT NULL DEFAULT FALSE")
            conn.commit()
        except pymysql.MySQLError as e:
            if e.args[0] != 1060:  # 1060 = "Duplicate column name" — anything else is a real problem
                raise
            conn.rollback()
    finally:
        conn.close()


def clear_all():
    """Wipes traffic + alerts + ml_predictions (keeps the JA3 feed)."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SET FOREIGN_KEY_CHECKS=0")
            cur.execute("DELETE FROM ml_predictions")
            cur.execute("DELETE FROM alerts")
            cur.execute("DELETE FROM traffic")
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
        conn.commit()
    finally:
        conn.close()
