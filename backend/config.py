"""
DATABASE CONFIGURATION
====================================================
All MySQL connection settings live here, read from environment
variables so real credentials never get hard-coded into the code
(and never end up committed anywhere). Sensible local defaults are
provided so the project still runs out-of-the-box on your machine
after you've created the database once (see README.md).

To use different credentials (e.g. a real server, not local), set
these environment variables before running seed_mysql.py or
uvicorn, instead of editing this file:
    DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
"""

import os

DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("DB_PORT", "3306"))
DB_USER = os.environ.get("DB_USER", "sih_app")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "changeme")
DB_NAME = os.environ.get("DB_NAME", "sih26145")
