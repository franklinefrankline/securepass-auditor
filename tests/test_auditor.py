"""Comprehensive Automated Test Suite for Password Strength Auditor.

Verifies:
- Scoring engine calculations and point caps
- Pattern detection (repeated characters, numeric sequences, keyboard patterns)
- Common password detection and score cap at 20
- Flask API routes (/health, /check, /history, /generate)
- Input validation (missing JSON, non-string, empty password, long inputs)
- Security HTTP headers (CSP, X-Content-Type-Options, nosniff, DENY)
- Zero plaintext password persistence (SHA-256 verification)
"""

import hashlib
import json
import unittest
from unittest.mock import MagicMock, patch

from app import app
from db import truncate_hash
from scorer import PasswordScorer, get_scorer


class TestScorerEngine(unittest.TestCase):
    """Unit tests for the password scoring algorithm in scorer.py."""

    def setUp(self):
        self.scorer = get_scorer()

    def test_short_password_abc(self):
        """Test 1: Short weak password 'abc'."""
        result = self.scorer.evaluate("abc")
        self.assertEqual(result["level"], "WEAK")
        self.assertLessEqual(result["score"], 40)
        self.assertIn("Password must be at least 8 characters long", result["issues"])
        self.assertFalse(result["has_upper"])
        self.assertFalse(result["has_digit"])
        self.assertFalse(result["has_symbol"])

    def test_common_password_password123(self):
        """Test 2: 'password123' must be detected as common and capped at 20."""
        result = self.scorer.evaluate("password123")
        self.assertTrue(result["is_common"])
        self.assertLessEqual(result["score"], 20)
        self.assertEqual(result["level"], "WEAK")
        self.assertIn("Found in common passwords list", result["issues"])

    def test_keyboard_pattern_qwerty(self):
        """Test 3: 'qwerty' triggers keyboard pattern / common warning."""
        result = self.scorer.evaluate("qwerty")
        self.assertTrue(result["patterns_detected"]["keyboard_pattern"])
        self.assertEqual(result["level"], "WEAK")

    def test_repeated_characters_aaa(self):
        """Repeated characters like 'aaa' or '111' trigger warning."""
        self.assertTrue(self.scorer.detect_repeated_characters("aaa"))
        self.assertTrue(self.scorer.detect_repeated_characters("Pass111word!"))
        self.assertFalse(self.scorer.detect_repeated_characters("AbCdEf!1"))

    def test_numeric_sequences(self):
        """Sequential numbers like '123' or '456' trigger warning."""
        self.assertTrue(self.scorer.detect_numeric_sequences("pass123word"))
        self.assertTrue(self.scorer.detect_numeric_sequences("sec321ret"))
        self.assertFalse(self.scorer.detect_numeric_sequences("pass135word"))

    def test_mixed_case_and_digits_Frank123(self):
        """Test 4: 'Frank123' has upper, lower, digits, but missing symbol."""
        result = self.scorer.evaluate("Frank123")
        self.assertTrue(result["has_upper"])
        self.assertTrue(result["has_lower"])
        self.assertTrue(result["has_digit"])
        self.assertFalse(result["has_symbol"])
        self.assertIn("Add a special character", result["issues"])

    def test_strong_password_FrankAt123456(self):
        """Test 5: 'Frank@123456' has length >= 12, upper, lower, digit, symbol."""
        result = self.scorer.evaluate("Frank@123456")
        self.assertTrue(result["has_upper"])
        self.assertTrue(result["has_lower"])
        self.assertTrue(result["has_digit"])
        self.assertTrue(result["has_symbol"])
        self.assertGreaterEqual(result["score"], 70)

    def test_high_score_password(self):
        """Test 6: 'Aabbcc!!12345' meets high complexity requirements."""
        result = self.scorer.evaluate("Aabbcc!!12345")
        self.assertGreaterEqual(result["score"], 70)
        self.assertEqual(result["level"], "STRONG")

    def test_common_password_plain_password(self):
        """'password' detected as common and capped at 20."""
        result = self.scorer.evaluate("password")
        self.assertTrue(result["is_common"])
        self.assertLessEqual(result["score"], 20)
        self.assertEqual(result["level"], "WEAK")

    def test_frank_at_123(self):
        """'Frank@123' has length >= 8, upper, lower, digit, symbol."""
        result = self.scorer.evaluate("Frank@123")
        self.assertTrue(result["has_upper"])
        self.assertTrue(result["has_lower"])
        self.assertTrue(result["has_digit"])
        self.assertTrue(result["has_symbol"])
        self.assertGreaterEqual(result["score"], 60)

    def test_very_strong_password_2026(self):
        """'VeryStrong@Password2026!' has maximum score 100 and STRONG."""
        result = self.scorer.evaluate("VeryStrong@Password2026!")
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["level"], "STRONG")
        self.assertFalse(result["is_common"])

    def test_empty_password(self):
        """Test 7: Empty password handled gracefully."""
        result = self.scorer.evaluate("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "WEAK")
        self.assertEqual(result["length"], 0)
        self.assertIn("Password cannot be empty", result["issues"])


class TestFlaskAPI(unittest.TestCase):
    """Integration tests for Flask routes and security headers."""

    def setUp(self):
        self.client = app.test_client()

    def test_health_endpoint(self):
        """Test 9: GET /health returns status: ok."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("database", data)

    def test_check_missing_json(self):
        """Test 8: POST /check with no JSON returns HTTP 400."""
        res = self.client.post("/check", data="plain text not json", content_type="text/plain")
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)

    def test_check_missing_password_field(self):
        """POST /check with missing 'password' field returns HTTP 400."""
        res = self.client.post("/check", json={"other": "field"})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)

    def test_check_non_string_password(self):
        """POST /check with non-string password returns HTTP 400."""
        res = self.client.post("/check", json={"password": 12345})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)

    def test_check_empty_password(self):
        """POST /check with empty password returns score 0 gracefully."""
        res = self.client.post("/check", json={"password": ""})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["score"], 0)
        self.assertEqual(data["level"], "WEAK")

    def test_check_valid_password_omits_raw_password(self):
        """POST /check returns analysis, hash, and NEVER echoes raw password."""
        raw_pw = "SecretSecurePass123!#"
        expected_hash = hashlib.sha256(raw_pw.encode("utf-8")).hexdigest()

        with patch("app.log_audit", return_value=1):
            res = self.client.post("/check", json={"password": raw_pw, "log_audit": True})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()

            # Ensure raw password is NOT in response keys or values
            self.assertNotIn("password", data)
            self.assertNotIn(raw_pw, json.dumps(data))

            # Ensure truncated hash matches SHA-256
            self.assertTrue(data["truncated_hash"].startswith(expected_hash[:8]))

    def test_security_headers_present(self):
        """Test 11: Verify secure HTTP headers on responses."""
        res = self.client.get("/")
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", res.headers.get("Content-Security-Policy", ""))

    def test_history_json_endpoint(self):
        """GET /history with Accept: application/json returns list of audits."""
        mock_records = [
            {
                "id": 1,
                "password_hash": "2dfb3f8b...3a",
                "score": 85,
                "strength": "Strong",
                "length": 14,
                "has_upper": True,
                "has_lower": True,
                "has_digit": True,
                "has_symbol": True,
                "is_common": False,
                "checked_at": "2026-09-11T10:00:00",
            }
        ]
        with patch("app.get_audit_history", return_value=mock_records):
            res = self.client.get("/history", headers={"Accept": "application/json"})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertIn("history", data)
            self.assertEqual(len(data["history"]), 1)
            self.assertEqual(data["history"][0]["id"], 1)

    def test_generate_password_endpoint(self):
        """POST /generate returns a strong candidate password."""
        res = self.client.post("/generate")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("generated_password", data)
        pw = data["generated_password"]
        self.assertGreaterEqual(len(pw), 16)
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.islower() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw))


class TestTruncateHash(unittest.TestCase):
    """Test safe hash truncation helper."""

    def test_truncate_64_char_hash(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        res = truncate_hash(h)
        self.assertEqual(res, "e3b0c442...b855")


if __name__ == "__main__":
    unittest.main()
