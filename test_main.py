"""
Comprehensive test suite for the JWKS server.

Covers:
  - Database schema (keys, users, auth_logs tables)
  - AES encryption of private keys
  - JWKS endpoint
  - Auth endpoint (token issuance, logging, rate limiting)
  - User registration endpoint
"""

import os
import re
import time
import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient

# ── Test configuration ────────────────────────────────────────────────────────
TEST_DB = "test_keys.db"

# Set a known AES key for testing BEFORE importing modules that read it
os.environ["NOT_MY_KEY"] = "test-aes-key-for-jwks-server!!"

import db    # noqa: E402
import main  # noqa: E402

main.DB_FILE = TEST_DB


@pytest.fixture(autouse=True)
def setup_test_db():
    """Create a fresh test DB before each test and remove it after."""
    # Remove any leftover DB from a previous run
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

    # Initialize schema and seed keys using the test DB
    db.init_db(TEST_DB)
    main.DB_FILE = TEST_DB
    main.generate_and_store_keys()

    # Clear the rate-limiter state between tests
    main._request_log.clear()

    yield

    # Teardown: remove test DB
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


client = TestClient(main.app)


# ══════════════════════════════════════════════════════════════════════════════
# DB Schema Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_init_db_creates_keys_table():
    """init_db should create the keys table."""
    conn = sqlite3.connect(TEST_DB)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
    )
    assert cursor.fetchone() is not None
    conn.close()


def test_init_db_creates_users_table():
    """init_db should create the users table."""
    conn = sqlite3.connect(TEST_DB)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
    )
    assert cursor.fetchone() is not None
    conn.close()


def test_init_db_creates_auth_logs_table():
    """init_db should create the auth_logs table."""
    conn = sqlite3.connect(TEST_DB)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='auth_logs'"
    )
    assert cursor.fetchone() is not None
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# Key Storage & Encryption Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_generate_and_store_keys_inserts_rows():
    """generate_and_store_keys should insert at least 2 rows (1 valid, 1 expired)."""
    conn = sqlite3.connect(TEST_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]
    conn.close()
    assert count >= 2


def test_private_keys_are_encrypted_in_db():
    """
    Raw bytes in the key column should NOT start with '-----BEGIN'
    (i.e., they should be AES-encrypted, not plain PEM).
    """
    conn = sqlite3.connect(TEST_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT key FROM keys LIMIT 1")
    raw = cursor.fetchone()[0]
    conn.close()

    # Encrypted blobs are bytes and should not look like PEM text
    if isinstance(raw, str):
        assert not raw.startswith("-----BEGIN"), "Key is stored as plaintext PEM!"
    else:
        assert not raw.startswith(b"-----BEGIN"), "Key is stored as plaintext PEM!"


def test_encrypted_keys_still_work_for_jwks():
    """JWKS endpoint should still return keys even though they're encrypted in the DB."""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1


def test_encrypted_keys_still_work_for_auth():
    """POST /auth should still return a valid JWT despite AES encryption."""
    response = client.post("/auth")
    assert response.status_code == 200
    assert "token" in response.json()


def test_get_valid_keys_returns_only_unexpired():
    """get_valid_keys_from_db should only return keys where exp > now."""
    keys = db.get_valid_keys_from_db(TEST_DB)
    now = int(time.time())
    assert len(keys) >= 1
    for kid, _ in keys:
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT exp FROM keys WHERE kid = ?", (kid,))
        exp = cursor.fetchone()[0]
        conn.close()
        assert exp > now


def test_get_expired_key_returns_expired():
    """get_expired_key_from_db should return a key where exp < now."""
    result = db.get_expired_key_from_db(TEST_DB)
    assert result is not None
    kid, _ = result
    conn = sqlite3.connect(TEST_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT exp FROM keys WHERE kid = ?", (kid,))
    exp = cursor.fetchone()[0]
    conn.close()
    assert exp < int(time.time())


def test_get_expired_key_returns_none_when_no_expired_keys():
    """get_expired_key_from_db should return None if no expired keys exist."""
    conn = sqlite3.connect(TEST_DB)
    conn.execute("DELETE FROM keys WHERE exp < ?", (int(time.time()),))
    conn.commit()
    conn.close()
    result = db.get_expired_key_from_db(TEST_DB)
    assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# JWKS Endpoint Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_jwks_endpoint_returns_keys():
    """GET /.well-known/jwks.json should return a list with at least one key."""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1


def test_jwks_key_has_required_fields():
    """Each JWK should contain the required RSA fields."""
    response = client.get("/.well-known/jwks.json")
    key = response.json()["keys"][0]
    for field in ("kty", "kid", "use", "alg", "n", "e"):
        assert field in key


def test_jwks_only_returns_valid_keys():
    """JWKS endpoint should never return expired keys."""
    conn = sqlite3.connect(TEST_DB)
    conn.execute("DELETE FROM keys WHERE exp > ?", (int(time.time()),))
    conn.commit()
    conn.close()

    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert response.json()["keys"] == []


# ══════════════════════════════════════════════════════════════════════════════
# Auth Endpoint Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_auth_returns_token():
    """POST /auth should return a JWT token."""
    response = client.post("/auth")
    assert response.status_code == 200
    assert "token" in response.json()


def test_auth_expired_returns_token():
    """POST /auth?expired=true should return a JWT signed with an expired key."""
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    assert "token" in response.json()


def test_auth_token_is_string():
    """The token returned by POST /auth should be a non-empty string."""
    response = client.post("/auth")
    token = response.json()["token"]
    assert isinstance(token, str)
    assert len(token) > 0


def test_auth_and_jwks_kid_match():
    """The kid in the JWT header should match one of the kids in the JWKS."""
    import base64
    import json

    auth_response = client.post("/auth")
    token = auth_response.json()["token"]

    header_b64 = token.split(".")[0]
    padding = 4 - len(header_b64) % 4
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * padding))
    token_kid = header["kid"]

    jwks_response = client.get("/.well-known/jwks.json")
    jwks_kids = [k["kid"] for k in jwks_response.json()["keys"]]

    assert token_kid in jwks_kids


# ══════════════════════════════════════════════════════════════════════════════
# Auth Logging Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_auth_logs_request():
    """POST /auth should create a row in auth_logs."""
    conn = sqlite3.connect(TEST_DB)
    before = conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]
    conn.close()

    client.post("/auth")

    conn = sqlite3.connect(TEST_DB)
    after = conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]
    conn.close()

    assert after == before + 1


def test_auth_log_has_ip():
    """The auth_logs row should have a non-empty request_ip."""
    client.post("/auth")

    conn = sqlite3.connect(TEST_DB)
    row = conn.execute(
        "SELECT request_ip FROM auth_logs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    assert row is not None
    assert row[0] is not None and len(row[0]) > 0


def test_auth_log_has_timestamp():
    """The auth_logs row should have a non-null request_timestamp."""
    client.post("/auth")

    conn = sqlite3.connect(TEST_DB)
    row = conn.execute(
        "SELECT request_timestamp FROM auth_logs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    assert row is not None
    assert row[0] is not None


# ══════════════════════════════════════════════════════════════════════════════
# Registration Endpoint Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_register_returns_password():
    """POST /register should return a password in the response body."""
    response = client.post(
        "/register",
        json={"username": "testuser1", "email": "test1@example.com"},
    )
    assert response.status_code == 201
    data = response.json()
    assert "password" in data
    assert len(data["password"]) > 0


def test_register_password_is_uuid():
    """The returned password should be a valid UUIDv4 string."""
    response = client.post(
        "/register",
        json={"username": "testuser_uuid", "email": "uuid@example.com"},
    )
    password = response.json()["password"]
    # uuid.UUID will raise if the string is not a valid UUID
    parsed = uuid.UUID(password, version=4)
    assert str(parsed) == password


def test_register_stores_user_in_db():
    """After registration, the user should appear in the users table."""
    client.post(
        "/register",
        json={"username": "db_check_user", "email": "db@example.com"},
    )

    conn = sqlite3.connect(TEST_DB)
    row = conn.execute(
        "SELECT username, email FROM users WHERE username = ?", ("db_check_user",)
    ).fetchone()
    conn.close()

    assert row is not None
    assert row[0] == "db_check_user"
    assert row[1] == "db@example.com"


def test_register_password_is_hashed():
    """The stored password_hash must NOT equal the plaintext password."""
    response = client.post(
        "/register",
        json={"username": "hash_check", "email": "hash@example.com"},
    )
    password = response.json()["password"]

    conn = sqlite3.connect(TEST_DB)
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", ("hash_check",)
    ).fetchone()
    conn.close()

    assert row is not None
    assert row[0] != password  # Hash should differ from plaintext


def test_register_duplicate_username():
    """Registering the same username twice should fail."""
    client.post(
        "/register",
        json={"username": "dupe_user", "email": "dupe1@example.com"},
    )
    response = client.post(
        "/register",
        json={"username": "dupe_user", "email": "dupe2@example.com"},
    )
    assert response.status_code == 409


# ══════════════════════════════════════════════════════════════════════════════
# Rate Limiter Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_rate_limiter_allows_normal_traffic():
    """10 rapid requests should all succeed."""
    for _ in range(10):
        response = client.post("/auth")
        assert response.status_code == 200


def test_rate_limiter_blocks_excess_traffic():
    """The 11th rapid request should receive 429 Too Many Requests."""
    for _ in range(10):
        client.post("/auth")

    response = client.post("/auth")
    assert response.status_code == 429


def test_rate_limited_requests_not_logged():
    """Rate-limited (429) requests should NOT appear in auth_logs."""
    # Fill the rate limit
    for _ in range(10):
        client.post("/auth")

    conn = sqlite3.connect(TEST_DB)
    count_before = conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]
    conn.close()

    # This should be rate-limited
    response = client.post("/auth")
    assert response.status_code == 429

    conn = sqlite3.connect(TEST_DB)
    count_after = conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]
    conn.close()

    assert count_after == count_before  # No new log entry
