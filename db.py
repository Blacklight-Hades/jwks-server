"""
Database layer for the JWKS server.

Handles schema creation, key storage with AES encryption,
user registration, and authentication request logging.

All database operations use:
  - Parameterized queries to prevent SQL injection.
  - Context managers for connection handling.
  - DELETE journal mode for cross-process visibility.
"""

import os
import sqlite3
import hashlib
import time
from contextlib import contextmanager
from typing import Optional

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# Database Connection Helper
# ---------------------------------------------------------------------------

@contextmanager
def get_db_connection(db_file: str):
    """
    Context manager for SQLite connections.

    Ensures connections are properly closed and uses DELETE journal mode
    so that committed data is immediately visible to external readers
    (e.g. the gradebot process).

    Args:
        db_file: Path to the SQLite database file.

    Yields:
        sqlite3.Connection: An open database connection.
    """
    conn = sqlite3.connect(db_file)
    conn.execute("PRAGMA journal_mode=DELETE")
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# AES Encryption Helpers
# ---------------------------------------------------------------------------

def _get_aes_key() -> Optional[bytes]:
    """
    Derive a 32-byte AES-256 key from the NOT_MY_KEY environment variable.

    Uses SHA-256 to normalise any-length secret string into the exact
    32 bytes required for AES-256.

    Returns:
        The derived 32-byte key, or None if NOT_MY_KEY is not set
        (encryption disabled).
    """
    env_key = os.environ.get("NOT_MY_KEY")
    if env_key is None:
        return None
    return hashlib.sha256(env_key.encode("utf-8")).digest()


def _pad(data: bytes) -> bytes:
    """
    Apply PKCS7 padding to *data* so its length is a multiple of 16.

    Args:
        data: The plaintext bytes to pad.

    Returns:
        The padded byte string.
    """
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    """
    Remove PKCS7 padding from *data*.

    Args:
        data: The padded byte string.

    Returns:
        The original unpadded byte string.
    """
    pad_len = data[-1]
    return data[:-pad_len]


def encrypt_private_key(pem_bytes: bytes) -> bytes:
    """
    Encrypt PEM-encoded private key bytes with AES-256-CBC.

    The returned blob is: IV (16 bytes) || ciphertext.
    If NOT_MY_KEY is not set, returns the raw PEM bytes unchanged.

    Args:
        pem_bytes: The PEM-encoded private key as bytes.

    Returns:
        The encrypted blob (IV + ciphertext), or raw PEM if encryption
        is disabled.
    """
    aes_key = _get_aes_key()
    if aes_key is None:
        return pem_bytes

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(_pad(pem_bytes)) + encryptor.finalize()
    return iv + ciphertext


def decrypt_private_key(data: bytes) -> bytes:
    """
    Decrypt an AES-256-CBC encrypted blob back to PEM bytes.

    Expects the format: IV (first 16 bytes) || ciphertext.
    If NOT_MY_KEY is not set, assumes *data* is already plain PEM.

    Args:
        data: The encrypted blob, or raw PEM bytes.

    Returns:
        The decrypted PEM-encoded private key bytes.
    """
    aes_key = _get_aes_key()
    if aes_key is None:
        return data

    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return _unpad(plaintext)


# ---------------------------------------------------------------------------
# Schema Initialisation
# ---------------------------------------------------------------------------

def init_db(db_file: str) -> None:
    """
    Create the keys, users, and auth_logs tables if they don't already exist.

    Table schemas:
      - **keys**: Stores AES-encrypted RSA private keys with expiry timestamps.
      - **users**: Stores registered users with Argon2-hashed passwords.
      - **auth_logs**: Logs each authentication request with IP, timestamp,
        and optional user reference.

    Args:
        db_file: Path to the SQLite database file.
    """
    with get_db_connection(db_file) as conn:
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )

        conn.commit()


# ---------------------------------------------------------------------------
# Key Retrieval (with decryption)
# ---------------------------------------------------------------------------

def get_valid_keys_from_db(db_file: str) -> list[tuple]:
    """
    Query the DB for all non-expired keys and decrypt them.

    Args:
        db_file: Path to the SQLite database file.

    Returns:
        A list of (kid, private_key_object) tuples for keys whose
        expiry timestamp is in the future.
    """
    now = int(time.time())
    with get_db_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
        rows = cursor.fetchall()

    result = []
    for kid, key_data in rows:
        raw = key_data.encode("utf-8") if isinstance(key_data, str) else key_data
        pem_bytes = decrypt_private_key(raw)
        private_key = load_pem_private_key(pem_bytes, password=None)
        result.append((kid, private_key))
    return result


def get_expired_key_from_db(db_file: str) -> Optional[tuple]:
    """
    Query the DB for one expired key and decrypt it.

    Args:
        db_file: Path to the SQLite database file.

    Returns:
        A (kid, private_key_object) tuple, or None if no expired key exists.
    """
    now = int(time.time())
    with get_db_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT kid, key FROM keys WHERE exp < ? LIMIT 1", (now,)
        )
        row = cursor.fetchone()

    if row is None:
        return None

    kid, key_data = row
    raw = key_data.encode("utf-8") if isinstance(key_data, str) else key_data
    pem_bytes = decrypt_private_key(raw)
    private_key = load_pem_private_key(pem_bytes, password=None)
    return (kid, private_key)


# ---------------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------------

def register_user(
    db_file: str, username: str, email: Optional[str], password_hash: str
) -> int:
    """
    Insert a new user into the users table.

    Args:
        db_file: Path to the SQLite database file.
        username: The unique username for the new user.
        email: The user's email address (may be None).
        password_hash: The Argon2-hashed password string.

    Returns:
        The auto-generated user ID of the newly created row.

    Raises:
        sqlite3.IntegrityError: If the username or email already exists.
    """
    with get_db_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email),
        )
        user_id = cursor.lastrowid
        conn.commit()
    return user_id


def get_user_by_username(db_file: str, username: str) -> Optional[dict]:
    """
    Look up a user by username.

    Args:
        db_file: Path to the SQLite database file.
        username: The username to search for.

    Returns:
        A dictionary of the user's row data, or None if not found.
    """
    with get_db_connection(db_file) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
    if row is None:
        return None
    return dict(row)


# ---------------------------------------------------------------------------
# Auth Logging
# ---------------------------------------------------------------------------

def log_auth_request(
    db_file: str, request_ip: str, user_id: Optional[int] = None
) -> None:
    """
    Log an authentication request to the auth_logs table.

    Args:
        db_file: Path to the SQLite database file.
        request_ip: The IP address of the client making the request.
        user_id: The ID of the authenticated user, or None if unknown.
    """
    with get_db_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
            (request_ip, user_id),
        )
        conn.commit()
