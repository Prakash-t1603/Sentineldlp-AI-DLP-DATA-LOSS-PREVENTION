import pytest
from backend.utils.security import verify_password, get_password_hash, create_access_token, decode_access_token

def test_password_hashing():
    raw = "SuperSecretPassword123!"
    hashed = get_password_hash(raw)
    assert hashed != raw
    assert verify_password(raw, hashed) is True
    assert verify_password("WrongPassword", hashed) is False

def test_jwt_token_flow():
    payload = {"sub": "analyst_test", "role": "security_analyst", "id": 42}
    token = create_access_token(payload)
    assert isinstance(token, str)
    assert len(token) > 20

    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == "analyst_test"
    assert decoded["role"] == "security_analyst"

def test_invalid_jwt():
    assert decode_access_token("invalid.token.structure") is None
