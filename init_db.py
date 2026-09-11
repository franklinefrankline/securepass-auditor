"""Database initialization utility.

Executes schema.sql against PostgreSQL using credentials in .env.
Usage:
    python init_db.py
"""

import sys
from db import init_db, check_db_connection

if __name__ == "__main__":
    print("[*] Testing connection to PostgreSQL...")
    ok, msg = check_db_connection()
    if not ok:
        print(f"[!] Connection failed: {msg}")
        print("[!] Please ensure PostgreSQL is running and DATABASE_URL in .env is correct.")
        sys.exit(1)

    print("[*] Connection verified. Initializing schema.sql...")
    if init_db():
        print("[+] Database initialized successfully! Table 'audit_log' is ready.")
    else:
        print("[!] Database schema initialization failed.")
        sys.exit(1)
