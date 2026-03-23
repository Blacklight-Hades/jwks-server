import os
import time
import sqlite3
import pytest
from fastapi.testclient import TestClient

# Use a separate test DB so tests don't pollute the real one
TEST_DB = "test_keys.db"
os.environ["DB_FILE"] = TEST_DB  # Optional: if you wire this up later

# Patch DB_FILE before importing app
import db
import main

main.DB_FILE = TEST_DB
db_original_init = db.init_db


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

    yield

    # Teardown: remove test DB
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


client = TestClient(main.app)


# ── DB layer tests ────────────────────────────────────────────────────────────

def test_init_db_creates_table():
    """init_db should create the keys table."""
    conn = sqlite3.connect(TEST_DB)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
    )
    assert cursor.fetchone() is not None
    conn.close()


def test_generate_and_store_keys_inserts_rows():
    """generate_and_store_keys should insert at least 2 rows (1 valid, 1 expired)."""
    conn = sqlite3.connect(TEST_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]
    conn.close()
    assert count >= 2


def test_get_valid_keys_returns_only_unexpired():
    """get_valid_keys_from_db should only return keys where exp > now."""
    keys = db.get_valid_keys_from_db(TEST_DB)
    now = int(time.time())
    assert len(keys) >= 1
    for kid, _ in keys:
        # Verify expiry directly in the DB
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
    # Delete all expired keys
    conn = sqlite3.connect(TEST_DB)
    conn.execute("DELETE FROM keys WHERE exp < ?", (int(time.time()),))
    conn.commit()
    conn.close()

    result = db.get_expired_key_from_db(TEST_DB)
    assert result is None


# ── Endpoint tests ─────────────────────────────────────────────────────────────

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
    # Remove all valid keys so only expired ones remain
    conn = sqlite3.connect(TEST_DB)
    conn.execute("DELETE FROM keys WHERE exp > ?", (int(time.time()),))
    conn.commit()
    conn.close()

    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert response.json()["keys"] == []


def test_auth_returns_token():
    """POST /auth should return a JWT token."""
    response = client.post("/auth")
    assert response.status_code == 200
    assert "token" in response.json()


def test_auth_expired_returns_token():
    """POST /auth?expired=true should return a JWT token signed with an expired key."""
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
    import base64, json

    auth_response = client.post("/auth")
    token = auth_response.json()["token"]

    # Decode JWT header (no verification needed here)
    header_b64 = token.split(".")[0]
    # Pad base64 if needed
    padding = 4 - len(header_b64) % 4
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * padding))
    token_kid = header["kid"]

    jwks_response = client.get("/.well-known/jwks.json")
    jwks_kids = [k["kid"] for k in jwks_response.json()["keys"]]

    assert token_kid in jwks_kids
