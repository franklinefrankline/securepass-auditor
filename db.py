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


def log_audit(
    password_hash: str,
    score: int,
    length: int,
    has_upper: bool,
    has_lower: bool,
    has_digit: bool,
    has_symbol: bool,
    is_common: bool,
) -> Optional[int]:
    """Inserts a password audit record into PostgreSQL using parameterized SQL.

    NEVER pass raw passwords to this function.

    Returns:
        Inserted record ID or None if an error occurred.
    """
    query = """
        INSERT INTO audit_log (
            password_hash,
            score,
            length,
            has_upper,
            has_lower,
            has_digit,
            has_symbol,
            is_common
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
    """
    params = (
        password_hash,
        int(score),
        int(length),
        bool(has_upper),
        bool(has_lower),
        bool(has_digit),
        bool(has_symbol),
        bool(is_common),
    )

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                row = cur.fetchone()
                if row:
                    audit_id = row[0]
                    logger.info("SUCCESS: Inserted audit record #%s into PostgreSQL audit_log.", audit_id)
                    return audit_id
                return None
    except Exception as e:
        logger.error("ERROR: Failed to insert password audit into database: %s", type(e).__name__)
        return None


def get_audit_history(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves the latest audit records from the audit_log table.

    Returns:
        List of audit dictionaries with truncated hashes for safe UI presentation.
    """
    query = """
        SELECT
            id,
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
    results: List[Dict[str, Any]] = []

    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, (limit,))
                rows = cur.fetchall()

                for row in rows:
                    full_hash = row["password_hash"]
                    checked_at_val = row["checked_at"]
                    # Format timestamp as ISO string
                    iso_date = (
                        checked_at_val.isoformat()
                        if hasattr(checked_at_val, "isoformat")
                        else str(checked_at_val)
                    )

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
                logger.info("SUCCESS: Retrieved %d audit records from database.", len(results))
    except Exception as e:
        logger.error("ERROR: Failed to fetch audit history from database: %s", type(e).__name__)
        return []

    return results
