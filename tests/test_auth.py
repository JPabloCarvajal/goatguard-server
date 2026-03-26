"""Unit tests for JWT authentication and bcrypt hashing."""
import sys
sys.path.insert(0, ".")

import time
from src.api.auth import (
    init_auth, hash_password, verify_password,
    create_token, verify_token,
)

# Initialize auth for all tests
init_auth(
    jwt_secret="test-secret-key-for-goatguard-unit-tests",
    jwt_algorithm="HS256",
    jwt_expiration_hours=24,
)


class TestPasswordHashing:
    """Tests for bcrypt password hashing."""

    def test_same_password_different_hashes(self):
        """bcrypt uses random salt — same input, different output."""
        hash1 = hash_password("mypassword")
        hash2 = hash_password("mypassword")

        assert hash1 != hash2, "Each hash should have unique salt"

    def test_verify_correct_password(self):
        """Correct password should verify against its own hash."""
        hashed = hash_password("goatguard123")

        assert verify_password("goatguard123", hashed) is True

    def test_verify_wrong_password(self):
        """Wrong password should not verify."""
        hashed = hash_password("goatguard123")

        assert verify_password("wrongpassword", hashed) is False


class TestJWT:
    """Tests for JWT token creation and verification."""

    def test_create_and_verify_token(self):
        """Token should be created and verified successfully."""
        token = create_token(user_id=1, username="admin")
        payload = verify_token(token)

        assert payload is not None
        assert payload["sub"] == "1"
        assert payload["username"] == "admin"

    def test_reject_token_with_wrong_secret(self):
        """Token signed with different secret should fail verification."""
        token = create_token(user_id=1, username="admin")

        # Re-initialize with DIFFERENT secret
        init_auth(jwt_secret="completely-different-secret-for-testing!")
        payload = verify_token(token)

        assert payload is None, "Token from different secret should be rejected"

        # Restore original secret for other tests
        init_auth(jwt_secret="test-secret-key-for-goatguard-unit-tests")

    def test_token_contains_required_fields(self):
        """Token payload should have sub, username, exp, iat."""
        token = create_token(user_id=42, username="testuser")
        payload = verify_token(token)

        assert "sub" in payload
        assert "username" in payload
        assert "exp" in payload
        assert "iat" in payload
        assert payload["sub"] == "42"
        assert payload["username"] == "testuser"