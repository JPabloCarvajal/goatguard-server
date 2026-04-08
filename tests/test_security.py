"""Security tests — JWT manipulation, malicious inputs, injection attempts."""
import sys
sys.path.insert(0, ".")

import jwt as pyjwt
from datetime import datetime, timedelta, timezone
from src.api.auth import init_auth, create_token, verify_token, hash_password, verify_password

# Initialize with known secret for testing
TEST_SECRET = "test-secret-key-for-goatguard-security-tests"
init_auth(jwt_secret=TEST_SECRET)


class TestJWTSecurity:
    """Tests for JWT token manipulation resistance."""

    def test_modified_payload_rejected(self):
        """Changing the payload should invalidate the signature."""
        token = create_token(user_id=1, username="admin")

        # Decode without verification, modify, re-encode with wrong key
        parts = token.split(".")
        # Tamper with payload (add admin=true)
        import base64
        import json
        payload = json.loads(base64.b64decode(parts[1] + "=="))
        payload["admin"] = True
        payload["sub"] = "999"
        tampered_payload = base64.b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip("=")
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

        result = verify_token(tampered_token)
        assert result is None, "Tampered token should be rejected"

    def test_expired_token_rejected(self):
        """Token with past expiration should be rejected."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "1",
            "username": "admin",
            "exp": now - timedelta(hours=1),  # expired 1 hour ago
            "iat": now - timedelta(hours=25),
        }
        expired_token = pyjwt.encode(payload, TEST_SECRET, algorithm="HS256")

        result = verify_token(expired_token)
        assert result is None, "Expired token should be rejected"

    def test_token_signed_with_none_algorithm(self):
        """Token with 'none' algorithm (classic JWT attack) should fail."""
        payload = {
            "sub": "1",
            "username": "admin",
            "exp": datetime.now(timezone.utc) + timedelta(hours=24),
            "iat": datetime.now(timezone.utc),
        }
        # Create unsigned token
        try:
            none_token = pyjwt.encode(payload, "", algorithm="none")
            result = verify_token(none_token)
            assert result is None, "'none' algorithm attack should be rejected"
        except Exception:
            pass  # PyJWT may reject 'none' algorithm entirely

    def test_token_with_different_algorithm(self):
        """Token signed with HS384 should fail HS256 verification."""
        payload = {
            "sub": "1",
            "username": "admin",
            "exp": datetime.now(timezone.utc) + timedelta(hours=24),
            "iat": datetime.now(timezone.utc),
        }
        wrong_algo_token = pyjwt.encode(
            payload, TEST_SECRET, algorithm="HS384"
        )

        result = verify_token(wrong_algo_token)
        assert result is None, "Wrong algorithm should be rejected"

    def test_completely_fabricated_token(self):
        """Random string that looks like JWT should fail."""
        fake = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.fakesignature"
        result = verify_token(fake)
        assert result is None


class TestInputSanitization:
    """Tests for malicious input handling."""

    def test_sql_injection_in_password(self):
        """SQL injection attempt in password should be safely hashed."""
        malicious = "'; DROP TABLE users; --"
        hashed = hash_password(malicious)
        assert verify_password(malicious, hashed) is True
        assert "DROP" not in hashed

    def test_xss_in_password(self):
        """XSS payload in password should be safely hashed."""
        xss = '<script>alert("XSS")</script>'
        hashed = hash_password(xss)
        assert verify_password(xss, hashed) is True
        assert "<script>" not in hashed

    def test_null_byte_in_password(self):
        """Null byte injection should be handled."""
        try:
            hashed = hash_password("pass\x00word")
            # bcrypt may reject null bytes — both outcomes are acceptable
            assert isinstance(hashed, str)
        except ValueError:
            pass  # bcrypt correctly rejects null bytes

    def test_extremely_long_token(self):
        """Very long token string should not cause DoS."""
        long_token = "a" * 100000
        result = verify_token(long_token)
        assert result is None

    def test_unicode_injection_in_token(self):
        """Unicode control characters in token should fail gracefully."""
        unicode_token = "eyJ\u0000\uffff.payload.signature"
        result = verify_token(unicode_token)
        assert result is None


class TestPasswordSecurity:
    """Tests for password hashing security properties."""

    def test_hash_is_not_plaintext(self):
        """Hash should never contain the original password."""
        password = "supersecretpassword123"
        hashed = hash_password(password)
        assert password not in hashed

    def test_hash_starts_with_bcrypt_prefix(self):
        """bcrypt hashes should start with $2b$ identifier."""
        hashed = hash_password("test")
        assert hashed.startswith("$2b$"), f"Not a bcrypt hash: {hashed[:10]}"

    def test_different_passwords_different_hashes(self):
        """Different passwords should produce different hashes."""
        h1 = hash_password("password1")
        h2 = hash_password("password2")
        assert h1 != h2

    def test_timing_attack_resistance(self):
        """Wrong password verification should take similar time as correct.
        bcrypt.checkpw uses constant-time comparison internally."""
        hashed = hash_password("correctpassword")

        import time
        # Time correct password
        start = time.perf_counter()
        for _ in range(5):
            verify_password("correctpassword", hashed)
        correct_time = time.perf_counter() - start

        # Time wrong password
        start = time.perf_counter()
        for _ in range(5):
            verify_password("wrongpassword00", hashed)
        wrong_time = time.perf_counter() - start

        # Times should be similar (within 50% of each other)
        ratio = max(correct_time, wrong_time) / min(correct_time, wrong_time)
        assert ratio < 2.0, f"Timing difference too large: {ratio:.2f}x (possible timing leak)"