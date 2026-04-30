"""
JWKS Server — main application module.

Exposes three endpoints:
  GET  /.well-known/jwks.json   — JWKS endpoint (public keys)
  POST /auth                    — JWT issuance (rate-limited & logged)
  POST /register                — User registration (Argon2-hashed)

Security features:
  - RSA private keys are AES-256-CBC encrypted at rest.
  - Passwords are hashed with Argon2 before storage.
  - Authentication requests are logged to auth_logs.
  - POST /auth is rate-limited to 10 requests/sec per IP.
"""

import os
import uuid
import time
import sqlite3
import base64
from collections import defaultdict, deque

from fastapi import FastAPI, Query, Header, Request
from fastapi.responses import JSONResponse
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from db import (
    init_db,
    get_db_connection,
    get_valid_keys_from_db,
    get_expired_key_from_db,
    encrypt_private_key,
    register_user,
    get_user_by_username,
    log_auth_request,
)
from jwt_utils import public_key_to_jwk, issue_jwt


DB_FILE = "totally_not_my_privateKeys.db"

app = FastAPI()
ph = PasswordHasher()


# ---------------------------------------------------------------------------
# In-memory sliding-window rate limiter  (10 req/s per IP on POST /auth)
# ---------------------------------------------------------------------------

RATE_LIMIT = 10          # max requests …
RATE_WINDOW = 1.0        # … per this many seconds
_request_log: dict[str, deque] = defaultdict(deque)


def _is_rate_limited(ip: str) -> bool:
    """
    Check whether *ip* has exceeded the rate limit.

    Uses a sliding-window algorithm: timestamps older than RATE_WINDOW
    seconds are evicted, then the current count is compared to RATE_LIMIT.

    Args:
        ip: The client IP address to check.

    Returns:
        True if the IP has reached or exceeded the limit, False otherwise.
    """
    now = time.time()
    window = _request_log[ip]

    # Evict timestamps outside the current window
    while window and window[0] <= now - RATE_WINDOW:
        window.popleft()

    if len(window) >= RATE_LIMIT:
        return True

    window.append(now)
    return False


# ---------------------------------------------------------------------------
# Startup: initialise DB and seed RSA keys
# ---------------------------------------------------------------------------

def generate_and_store_keys() -> None:
    """
    Generate one valid and one expired RSA 2048-bit key pair.

    Each private key is:
      1. Serialised to PEM format.
      2. AES-encrypted (if NOT_MY_KEY is set).
      3. Inserted into the ``keys`` table with an appropriate expiry.
    """
    with get_db_connection(DB_FILE) as conn:
        cursor = conn.cursor()

        # Clear any existing keys to avoid decryption errors if
        # NOT_MY_KEY has changed between server restarts.
        cursor.execute("DELETE FROM keys")

        for expired in (False, True):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Encrypt the PEM before storing
            encrypted_pem = encrypt_private_key(pem)

            # Past expiry for the "expired" key, 1 hour ahead for the valid key
            exp = int(time.time()) - 3600 if expired else int(time.time()) + 3600

            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (encrypted_pem, exp),
            )

        conn.commit()


# Initialize DB and seed keys on startup
init_db(DB_FILE)
generate_and_store_keys()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/.well-known/jwks.json")
def jwks():
    """Return all valid (non-expired) public keys as a JWKS JSON response."""
    keys = []
    for kid, private_key in get_valid_keys_from_db(DB_FILE):
        jwk = public_key_to_jwk(private_key.public_key(), str(kid))
        keys.append(jwk)
    return {"keys": keys}


@app.post("/auth")
async def auth(
    request: Request,
    expired: bool = Query(False),
    authorization: str = Header(default=None),
):
    """
    Issue a signed JWT.

    Flow:
      1. Rate-limit check (429 if exceeded — request is NOT logged).
      2. Select an appropriate RSA key (expired or valid).
      3. Sign and return a JWT.
      4. Resolve the user from credentials (Basic header or JSON body).
      5. Log the request to auth_logs.

    Args:
        request: The incoming FastAPI request object.
        expired: If True, sign with an expired key.
        authorization: Optional HTTP Basic auth header.

    Returns:
        JSON ``{"token": "<JWT>"}`` on success, or an error response.
    """
    client_ip = request.client.host if request.client else "unknown"

    # ── Rate-limit check ──────────────────────────────────────────────────
    if _is_rate_limited(client_ip):
        return JSONResponse(
            status_code=429,
            content={"error": "Too Many Requests"},
        )

    # ── Key selection ─────────────────────────────────────────────────────
    if expired:
        result = get_expired_key_from_db(DB_FILE)
    else:
        results = get_valid_keys_from_db(DB_FILE)
        result = results[0] if results else None

    if result is None:
        return JSONResponse(
            status_code=404,
            content={"error": "No suitable key found"},
        )

    kid, private_key = result

    # ── Issue the JWT ─────────────────────────────────────────────────────
    token = issue_jwt(private_key, str(kid), expired=expired)

    # ── Resolve user_id from credentials ──────────────────────────────────
    user_id = None

    # Try HTTP Basic auth header first
    if authorization and authorization.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(
                authorization.split(" ", 1)[1]
            ).decode("utf-8")
            username = decoded.split(":", 1)[0]
            user = get_user_by_username(DB_FILE, username)
            if user:
                user_id = user["id"]
        except Exception:
            pass  # Malformed header — still log, just without user_id

    # Fall back to JSON body if no user was resolved from the header
    if user_id is None:
        try:
            body = await request.json()
            username = body.get("username")
            if username:
                user = get_user_by_username(DB_FILE, username)
                if user:
                    user_id = user["id"]
        except Exception:
            pass  # No JSON body or missing username — log without user_id

    # ── Log the request ───────────────────────────────────────────────────
    log_auth_request(DB_FILE, client_ip, user_id)

    return {"token": token}


@app.post("/register")
def register(body: dict):
    """
    Register a new user.

    Accepts JSON ``{"username": "...", "email": "..."}``.
    Generates a UUIDv4 password, hashes it with Argon2, stores the user,
    and returns the plaintext password to the caller.

    Args:
        body: The JSON request body with ``username`` (required) and
              ``email`` (optional).

    Returns:
        JSON ``{"password": "<UUIDv4>"}`` with HTTP 201 Created on success.
        HTTP 400 if username is missing, HTTP 409 on duplicate username/email.
    """
    username = body.get("username")
    email = body.get("email")

    if not username:
        return JSONResponse(
            status_code=400,
            content={"error": "username is required"},
        )

    # Generate a secure password using UUIDv4
    password = str(uuid.uuid4())

    # Hash with Argon2 (configurable time, memory, parallelism)
    password_hash = ph.hash(password)

    # Persist to the users table
    try:
        register_user(DB_FILE, username, email, password_hash)
    except sqlite3.IntegrityError:
        return JSONResponse(
            status_code=409,
            content={"error": "Username or email already exists"},
        )

    return JSONResponse(
        status_code=201,
        content={"password": password},
    )
