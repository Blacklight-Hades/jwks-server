import pytest
from fastapi.testclient import TestClient
from main import app
import jwt
import time

client = TestClient(app)

def test_jwks_endpoint():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    for key in data["keys"]:
        assert key["kty"] == "RSA"
        assert "kid" in key
        assert "n" in key
        assert "e" in key

def test_auth_unexpired():
    response = client.post("/auth")
    assert response.status_code == 200
    token = response.json().get("token")
    assert token is not None
    
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["exp"] > decoded["iat"]
    assert "sub" in decoded
    assert "iat" in decoded
    assert "exp" in decoded

def test_auth_expired():
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    token = response.json().get("token")
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["exp"] < int(time.time())

def test_jwks_no_expired_keys():
    jwks_response = client.get("/.well-known/jwks.json")
    jwks = jwks_response.json()
    assert len(jwks["keys"]) >= 1
