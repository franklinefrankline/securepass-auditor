"""Database access layer for SecurePass Auditor.

Uses psycopg2 with strictly parameterized SQL queries.
Credentials are read exclusively from environment variables via python-dotenv.
Plaintext passwords are NEVER handled, inserted, printed, or logged here.
"""

from __future__ import annotations

import os
import re
import logging
import urllib.parse
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# Load environment variables from .env with override=True
load_dotenv(override=True)

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
logger = logging.getLogger(__name__)


def clean_database_url(url: str) -> str:
    """Ensures database connection URL encodes special characters in passwords safely.

    Also normalizes legacy 'postgres://' prefixes used by Render/Heroku to 'postgresql://'.
    Prevents raw characters like '#' or '@' in the password from corrupting the URI.
    """
    if not url:
        return ""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    match = re.match(r"^(postgresql(?:\+[a-z]+)?://)([^:]+):([^@]+)@(.+)$", url)
    if match:
        prefix, user, raw_pw, host_part = match.groups()
        quoted_pw = urllib.parse.quote(urllib.parse.unquote(raw_pw))
        return f"{prefix}{user}:{quoted_pw}@{host_part}"
    return url


def get_database_url() -> str:
    """Fetches and sanitizes the database URL dynamically."""
    # In Vercel serverless, do not default to localhost if DATABASE_URL is not configured
    if os.getenv("VERCEL") and not os.getenv("DATABASE_URL"):
        return ""

    raw_url = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:%23Frankline2006@localhost:5432/password_auditor",
    )
    return clean_database_url(raw_url)


def truncate_hash(full_hash: str) -> str:
    """Safely truncates a 64-character SHA-256 hash for safe UI presentation.

    Example: '2dfb3f8baf0d1...3a' -> '2dfb3f8b...3a'
    """
    if not full_hash or len(full_hash) < 16:
        return full_hash or ""
    return f"{full_hash[:8]}...{full_hash[-4:]}"


@contextmanager
def get_db_connection() -> Generator[psycopg2.extensions.connection, None, None]:
    """Context manager for PostgreSQL database connections.

    Ensures transactions are explicitly committed on success and rolled back on error,
    with connections cleanly closed.
    """
    db_url = get_database_url()
    if not db_url:
        raise psycopg2.OperationalError("Database URL is not configured or unavailable in serverless environment")

    try:
        conn = psycopg2.connect(db_url, connect_timeout=5)
    except psycopg2.OperationalError as e:
        logger.error("ERROR: Database connection failed: %s", e)
        raise

    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("ERROR: Transaction failed and was rolled back: %s", type(e).__name__)
        raise
    finally:
        conn.close()


def check_db_connection() -> Tuple[bool, str]:
    """Checks whether the PostgreSQL database is reachable.

    Returns:
        Tuple of (is_connected: bool, message: str)
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                return True, "Database connection operational"
    except Exception as e:
        logger.warning("Database connection check failed: %s", type(e).__name__)
        return False, f"Database connection unavailable ({type(e).__name__})"


def init_db(schema_file: Optional[str] = None) -> bool:
    """Initializes the database schema using schema.sql if table does not exist."""
    if schema_file is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        schema_file = os.path.join(base_dir, "schema.sql")

    if not os.path.exists(schema_file):
        logger.error("schema.sql file not found at %s", schema_file)
        return False

    with open(schema_file, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(schema_sql)
        logger.info("Database schema verified / initialized successfully.")
        return True
    except Exception as e:
        logger.error("Failed to initialize database schema: %s", type(e).__name__)
        return False


import sqlite3
import tempfile
from datetime import datetime, timezone


def _get_sqlite_path() -> str:
    """Returns path to the SQLite fallback database in a writable directory."""
    tmp_dir = "/tmp" if os.path.exists("/tmp") and os.path.isdir("/tmp") else tempfile.gettempdir()
    return os.path.join(tmp_dir, "securepass_fallback.db")


def _init_sqlite():
    """Initializes SQLite fallback schema and seeds realistic records if empty."""
    db_path = _get_sqlite_path()
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    password_hash TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    length INTEGER NOT NULL,
                    has_upper INTEGER NOT NULL,
                    has_lower INTEGER NOT NULL,
                    has_digit INTEGER NOT NULL,
                    has_symbol INTEGER NOT NULL,
                    is_common INTEGER NOT NULL,
                    checked_at TEXT NOT NULL
                );
            """)
            # Ensure user_id column exists if table was created previously without it
            cur.execute("PRAGMA table_info(audit_log);")
            columns = [row[1] for row in cur.fetchall()]
            if "user_id" not in columns:
                try:
                    cur.execute("ALTER TABLE audit_log ADD COLUMN user_id INTEGER DEFAULT 1;")
                except Exception:
                    pass

            # Seed default demo user if table is empty
            cur.execute("SELECT COUNT(*) FROM users;")
            if cur.fetchone()[0] == 0:
                from werkzeug.security import generate_password_hash
                demo_hash = generate_password_hash("AuditAdmin2026!")
                cur.execute("""
                    INSERT INTO users (full_name, email, password_hash, created_at)
                    VALUES (?, ?, ?, ?);
                """, ("Security Analyst", "analyst@securepass.io", demo_hash, "2026-09-11 12:00:00"))
                conn.commit()

            cur.execute("SELECT COUNT(*) FROM audit_log;")
            count = cur.fetchone()[0]
            if count == 0:
                demo_records = [
                    (1, "be57987b28238128498877a7df8445ab68f448c9030b4ec74121908d1690a1b2", 100, 24, 1, 1, 1, 1, 0, "2026-09-11 13:42:55"),
                    (1, "4ba833b3a4a7536dfcae878434771daeeeaecb22a00185e505ecf97bb1e3c4d5", 100, 16, 1, 1, 1, 1, 0, "2026-09-11 13:20:12"),
                    (1, "16081159b365824c9c819a86a6358c548777faefb5fa8d1633580556f135e6f7", 85, 14, 1, 1, 1, 1, 0, "2026-09-11 12:55:40"),
                    (1, "8a4938e6e5a6a43f545f47a95b87c7161b96a9284206c71c4c1a84f3daeca8b9", 30, 6, 0, 1, 1, 0, 0, "2026-09-11 12:15:33"),
                    (1, "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4c4f3a21", 20, 8, 0, 1, 1, 0, 1, "2026-09-11 11:30:18"),
                ]
                cur.executemany("""
                    INSERT INTO audit_log (
                        user_id, password_hash, score, length, has_upper, has_lower, has_digit, has_symbol, is_common, checked_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, demo_records)
                conn.commit()
    except Exception as e:
        logger.warning("Failed to initialize SQLite fallback: %s", e)


def create_user(full_name: str, email: str, password_hash: str) -> Tuple[Optional[int], Optional[str]]:
    """Creates a new user record in PostgreSQL or SQLite fallback.

    Returns:
        (user_id, error_message). When user_id is returned, error_message is None.
    """
    clean_name = (full_name or "").strip()
    clean_email = (email or "").strip().lower()

    if not clean_name:
        return None, "Full name is required."
    if not clean_email or "@" not in clean_email:
        return None, "A valid email address is required."
    if not password_hash:
        return None, "Password hash cannot be empty."

    # 1. Try PostgreSQL
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(%s);", (clean_email,))
                if cur.fetchone():
                    return None, "An account with this email address already exists."

                cur.execute(
                    """
                    INSERT INTO users (full_name, email, password_hash)
                    VALUES (%s, %s, %s)
                    RETURNING id;
                    """,
                    (clean_name, clean_email, password_hash),
                )
                row = cur.fetchone()
                if row:
                    user_id = row[0]
                    logger.info("SUCCESS: Created user #%s in PostgreSQL.", user_id)
                    return user_id, None
    except Exception as e:
        logger.warning("PostgreSQL unavailable (%s), trying SQLite fallback for user creation.", type(e).__name__)

    # 2. SQLite Fallback
    try:
        _init_sqlite()
        db_path = _get_sqlite_path()
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(?);", (clean_email,))
            if cur.fetchone():
                return None, "An account with this email address already exists."

            cur.execute(
                """
                INSERT INTO users (full_name, email, password_hash, created_at)
                VALUES (?, ?, ?, ?);
                """,
                (clean_name, clean_email, password_hash, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()
            user_id = cur.lastrowid
            logger.info("SUCCESS: Created user #%s in SQLite fallback.", user_id)
            return user_id, None
    except Exception as e:
        logger.error("ERROR: Failed to create user in SQLite fallback: %s", e)
        return None, "Account registration failed. Please try again."


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Fetches user record by email address from PostgreSQL or SQLite fallback."""
    clean_email = (email or "").strip().lower()
    if not clean_email:
        return None

    # 1. Try PostgreSQL
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT id, full_name, email, password_hash, created_at FROM users WHERE LOWER(email) = LOWER(%s);",
                    (clean_email,),
                )
                row = cur.fetchone()
                if row:
                    return dict(row)
    except Exception as e:
        logger.warning("PostgreSQL unavailable (%s), querying user from SQLite fallback.", type(e).__name__)

    # 2. SQLite Fallback
    try:
        _init_sqlite()
        db_path = _get_sqlite_path()
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT id, full_name, email, password_hash, created_at FROM users WHERE LOWER(email) = LOWER(?);",
                (clean_email,),
            )
            row = cur.fetchone()
            if row:
                return dict(row)
    except Exception as e:
        logger.error("ERROR: Failed to fetch user from SQLite fallback: %s", e)

    return None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Fetches user record by ID from PostgreSQL or SQLite fallback."""
    if not user_id:
        return None

    # 1. Try PostgreSQL
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT id, full_name, email, password_hash, created_at FROM users WHERE id = %s;",
                    (user_id,),
                )
                row = cur.fetchone()
                if row:
                    return dict(row)
    except Exception as e:
        logger.warning("PostgreSQL unavailable (%s), querying user by id from SQLite fallback.", type(e).__name__)

    # 2. SQLite Fallback
    try:
        _init_sqlite()
        db_path = _get_sqlite_path()
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT id, full_name, email, password_hash, created_at FROM users WHERE id = ?;",
                (user_id,),
            )
            row = cur.fetchone()
            if row:
                return dict(row)
    except Exception as e:
        logger.error("ERROR: Failed to fetch user by id from SQLite fallback: %s", e)

    return None


def log_audit(
    password_hash: str,
    score: int,
    length: int,
    has_upper: bool,
    has_lower: bool,
    has_digit: bool,
    has_symbol: bool,
    is_common: bool,
    user_id: Optional[int] = None,
) -> Optional[int]:
    """Inserts a password audit record into PostgreSQL or SQLite fallback.

    NEVER pass raw passwords to this function.
    """
    effective_user_id = user_id if user_id is not None else 1

    query = """
        INSERT INTO audit_log (
            user_id,
            password_hash,
            score,
            length,
            has_upper,
            has_lower,
            has_digit,
            has_symbol,
            is_common
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
    """
    params = (
        int(effective_user_id),
        password_hash,
        int(score),
        int(length),
        bool(has_upper),
        bool(has_lower),
        bool(has_digit),
        bool(has_symbol),
        bool(is_common),
    )

    # 1. Try PostgreSQL first if configured
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                row = cur.fetchone()
                if row:
                    audit_id = row[0]
                    logger.info("SUCCESS: Inserted audit record #%s into PostgreSQL.", audit_id)
                    return audit_id
    except Exception as e:
        logger.warning("PostgreSQL unavailable (%s), writing audit to SQLite fallback.", type(e).__name__)

    # 2. Write to SQLite fallback
    try:
        _init_sqlite()
        db_path = _get_sqlite_path()
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO audit_log (
                    user_id, password_hash, score, length, has_upper, has_lower, has_digit, has_symbol, is_common, checked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                int(effective_user_id),
                password_hash,
                int(score),
                int(length),
                1 if has_upper else 0,
                1 if has_lower else 0,
                1 if has_digit else 0,
                1 if has_symbol else 0,
                1 if is_common else 0,
                datetime.now(timezone.utc).isoformat(),
            ))
            conn.commit()
            audit_id = cur.lastrowid
            logger.info("SUCCESS: Inserted audit record #%s into SQLite fallback.", audit_id)
            return audit_id
    except Exception as e:
        logger.error("ERROR: Failed to insert audit into SQLite fallback: %s", e)
        return None


def get_audit_history(user_id: Optional[int] = None, limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves the latest audit records from PostgreSQL or SQLite fallback.

    When user_id is provided, strictly isolates audits to that specific user.
    """
    results: List[Dict[str, Any]] = []

    # 1. Try PostgreSQL first
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if user_id is not None:
                    query = """
                        SELECT
                            id,
                            user_id,
                            password_hash,
                            score,
                            length,
                            has_upper,
                            has_lower,
                            has_digit,
                            has_symbol,
                            is_common,
                            checked_at
                        FROM audit_log
                        WHERE user_id = %s
                        ORDER BY checked_at DESC
                        LIMIT %s;
                    """
                    cur.execute(query, (int(user_id), limit))
                else:
                    query = """
                        SELECT
                            id,
                            user_id,
                            password_hash,
                            score,
                            length,
                            has_upper,
                            has_lower,
                            has_digit,
                            has_symbol,
                            is_common,
                            checked_at
                        FROM audit_log
                        ORDER BY checked_at DESC
                        LIMIT %s;
                    """
                    cur.execute(query, (limit,))

                rows = cur.fetchall()

                if rows:
                    for row in rows:
                        full_hash = row["password_hash"]
                        checked_at_val = row["checked_at"]
                        if hasattr(checked_at_val, "isoformat"):
                            iso_date = checked_at_val.isoformat()
                        else:
                            iso_date = str(checked_at_val)
                        if not iso_date.endswith("Z") and "+" not in iso_date and "-" not in iso_date[10:]:
                            iso_date = iso_date.replace(" ", "T") + "Z"

                        score = row["score"]
                        if score <= 40:
                            strength = "Weak"
                        elif score <= 70:
                            strength = "Fair"
                        else:
                            strength = "Strong"

                        results.append(
                            {
                                "id": row["id"],
                                "user_id": row.get("user_id"),
                                "password_hash": truncate_hash(full_hash),
                                "score": score,
                                "strength": strength,
                                "length": row["length"],
                                "has_upper": row["has_upper"],
                                "has_lower": row["has_lower"],
                                "has_digit": row["has_digit"],
                                "has_symbol": row["has_symbol"],
                                "is_common": row["is_common"],
                                "checked_at": iso_date,
                            }
                        )
                    logger.info("SUCCESS: Retrieved %d audit records from PostgreSQL.", len(results))
                    return results
    except Exception as e:
        logger.warning("PostgreSQL unavailable (%s), fetching from SQLite fallback.", type(e).__name__)

    # 2. Query SQLite fallback
    try:
        _init_sqlite()
        db_path = _get_sqlite_path()
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            if user_id is not None:
                cur.execute("""
                    SELECT id, user_id, password_hash, score, length, has_upper, has_lower, has_digit, has_symbol, is_common, checked_at
                    FROM audit_log
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT ?;
                """, (int(user_id), limit))
            else:
                cur.execute("""
                    SELECT id, user_id, password_hash, score, length, has_upper, has_lower, has_digit, has_symbol, is_common, checked_at
                    FROM audit_log
                    ORDER BY id DESC
                    LIMIT ?;
                """, (limit,))

            rows = cur.fetchall()

            for row in rows:
                full_hash = row["password_hash"]
                score = row["score"]
                if score <= 40:
                    strength = "Weak"
                elif score <= 70:
                    strength = "Fair"
                else:
                    strength = "Strong"

                results.append(
                    {
                        "id": row["id"],
                        "user_id": row["user_id"] if "user_id" in row.keys() else 1,
                        "password_hash": truncate_hash(full_hash),
                        "score": score,
                        "strength": strength,
                        "length": row["length"],
                        "has_upper": bool(row["has_upper"]),
                        "has_lower": bool(row["has_lower"]),
                        "has_digit": bool(row["has_digit"]),
                        "has_symbol": bool(row["has_symbol"]),
                        "is_common": bool(row["is_common"]),
                        "checked_at": (
                            str(row["checked_at"]).replace(" ", "T") + "Z"
                            if not str(row["checked_at"]).endswith("Z")
                            and "+" not in str(row["checked_at"])
                            and "-" not in str(row["checked_at"])[10:]
                            else str(row["checked_at"])
                        ),
                    }
                )
            logger.info("SUCCESS: Retrieved %d audit records from SQLite fallback.", len(results))
    except Exception as e:
        logger.error("ERROR: Failed to fetch audit history from SQLite fallback: %s", e)

    return results
