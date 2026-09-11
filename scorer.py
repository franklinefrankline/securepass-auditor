"""Password Strength Scoring and Pattern Detection Engine.

Evaluates password complexity, detects weaknesses, detects common passwords,
and flags predictable patterns (repeated characters, numeric sequences, keyboard walks).
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Set, Tuple

# Common keyboard rows (QWERTY layout)
KEYBOARD_ROWS = [
    "1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

KEYBOARD_PATTERNS = [
    "qwerty",
    "qwertz",
    "azerty",
    "asdf",
    "zxcv",
    "1234",
    "2345",
    "3456",
    "4567",
    "5678",
    "6789",
    "7890",
]


class PasswordScorer:
    """Evaluates password strength, weaknesses, and patterns."""

    def __init__(self, common_passwords_file: Optional[str] = None):
        self.common_passwords: Set[str] = set()
        if common_passwords_file is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            common_passwords_file = os.path.join(base_dir, "common_passwords.txt")

        self.load_common_passwords(common_passwords_file)

    def load_common_passwords(self, file_path: str) -> None:
        """Loads common passwords from a text file into an in-memory set."""
        if not os.path.exists(file_path):
            self.common_passwords = set()
            return

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            self.common_passwords = {
                line.strip().lower() for line in f if line.strip()
            }

    @staticmethod
    def detect_repeated_characters(password: str) -> bool:
        """Detects 3 or more consecutive identical characters (e.g. aaa, 111, !!!)."""
        return bool(re.search(r"(.)\1{2,}", password, re.IGNORECASE))

    @staticmethod
    def detect_numeric_sequences(password: str) -> bool:
        """Detects 3 or more sequential ascending or descending digits (e.g. 123, 4567, 321)."""
        for i in range(len(password) - 2):
            chunk = password[i : i + 3]
            if chunk.isdigit():
                d1, d2, d3 = int(chunk[0]), int(chunk[1]), int(chunk[2])
                if (d2 == d1 + 1 and d3 == d2 + 1) or (d2 == d1 - 1 and d3 == d2 - 1):
                    return True
        return False

    @staticmethod
    def detect_keyboard_patterns(password: str) -> bool:
        """Detects common keyboard walk sequences like qwerty, asdf, zxcv."""
        lowered = password.lower()
        for pattern in KEYBOARD_PATTERNS:
            if pattern in lowered:
                return True
        return False

    def is_common_password(self, password: str) -> bool:
        """Checks if the password exists in the local common passwords list."""
        return password.strip().lower() in self.common_passwords

    def evaluate(self, password: str) -> Dict:
        """Evaluates a password and returns a comprehensive audit dictionary.

        Returns:
            dict containing:
                score (0-100),
                level ('WEAK' | 'FAIR' | 'STRONG'),
                length,
                has_upper,
                has_lower,
                has_digit,
                has_symbol,
                is_common,
                issues (weaknesses),
                suggestions,
                patterns_detected (dict)
        """
        if not password:
            return {
                "score": 0,
                "level": "WEAK",
                "length": 0,
                "has_upper": False,
                "has_lower": False,
                "has_digit": False,
                "has_symbol": False,
                "is_common": False,
                "issues": ["Password cannot be empty"],
                "suggestions": ["Enter a secure password of at least 12 characters"],
                "patterns_detected": {
                    "repeated_chars": False,
                    "numeric_sequence": False,
                    "keyboard_pattern": False,
                },
            }

        length = len(password)
        has_upper = bool(re.search(r"[A-Z]", password))
        has_lower = bool(re.search(r"[a-z]", password))
        has_digit = bool(re.search(r"[0-9]", password))
        # Symbols include any ASCII or Unicode punctuation/special characters
        has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))

        # 1. Base Score calculation
        score = 0
        if length >= 8:
            score += 20
        if length >= 12:
            score += 10
        if has_upper:
            score += 15
        if has_lower:
            score += 15
        if has_digit:
            score += 15
        if has_symbol:
            score += 25

        # 2. Pattern detection
        has_repeated = self.detect_repeated_characters(password)
        has_num_seq = self.detect_numeric_sequences(password)
        has_kbd_pat = self.detect_keyboard_patterns(password)
        is_common = self.is_common_password(password)

        # 3. Weakness analysis and suggestions
        issues: List[str] = []
        suggestions: List[str] = []

        if length < 8:
            issues.append("Password must be at least 8 characters long")
            suggestions.append("Make your password at least 8 characters long")
        elif length < 12:
            issues.append("Password should be at least 12 characters long")
            suggestions.append("Increase length to 12 or more characters for extra strength")

        if not has_upper:
            issues.append("Add an uppercase letter")
            suggestions.append("Include at least one uppercase letter (A-Z)")

        if not has_lower:
            issues.append("Add a lowercase letter")
            suggestions.append("Include at least one lowercase letter (a-z)")

        if not has_digit:
            issues.append("Add a number")
            suggestions.append("Include at least one numeric digit (0-9)")

        if not has_symbol:
            issues.append("Add a special character")
            suggestions.append("Include at least one special character (!@#$%^&*...)")

        if has_repeated:
            issues.append("Avoid repeated characters")
            suggestions.append("Avoid repeating the same character consecutive times")
            score = max(0, score - 10)

        if has_num_seq:
            issues.append("Avoid sequential numbers")
            suggestions.append("Avoid consecutive numeric sequences like 123 or 987")
            score = max(0, score - 5)

        if has_kbd_pat:
            issues.append("Avoid predictable keyboard patterns")
            suggestions.append("Avoid predictable keyboard patterns like qwerty or asdf")
            score = max(0, score - 10)

        if is_common:
            issues.append("Found in common passwords list")
            suggestions.append("This is a widely breached common password. Choose a unique passphrase")
            # Common password score is capped at 20
            score = min(score, 20)

        # Cap score strictly between 0 and 100
        score = max(0, min(score, 100))

        # Strength level categories
        if score <= 40:
            level = "WEAK"
        elif score <= 70:
            level = "FAIR"
        else:
            level = "STRONG"

        return {
            "score": score,
            "level": level,
            "length": length,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_symbol": has_symbol,
            "is_common": is_common,
            "issues": issues,
            "suggestions": suggestions,
            "patterns_detected": {
                "repeated_chars": has_repeated,
                "numeric_sequence": has_num_seq,
                "keyboard_pattern": has_kbd_pat,
            },
        }


# Global singleton instance for easy import and fast startup
_scorer_instance: Optional[PasswordScorer] = None


def get_scorer() -> PasswordScorer:
    """Returns the shared PasswordScorer instance."""
    global _scorer_instance
    if _scorer_instance is None:
        _scorer_instance = PasswordScorer()
    return _scorer_instance
