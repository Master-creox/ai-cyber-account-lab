"""Password strength assessment.

Defensive and privacy-first: the password is assessed in memory only and is
never stored, logged, or transmitted.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

COMMON_PATTERNS = [
    "password", "123456", "qwerty", "admin", "letmein", "welcome",
]


@dataclass
class PasswordAssessment:
    score: int  # 0 (weakest) to 4 (strongest)
    label: str
    feedback: list[str] = field(default_factory=list)


_LABELS = {0: "very weak", 1: "weak", 2: "fair", 3: "strong", 4: "very strong"}


def assess_password(password: str) -> PasswordAssessment:
    feedback: list[str] = []
    score = 0

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters; 14+ is better.")
    if len(password) >= 14:
        score += 1
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Mix lowercase and uppercase letters.")
    if re.search(r"\d", password) and re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        feedback.append("Add numbers and a symbol.")

    lowered = password.lower()
    if any(pattern in lowered for pattern in COMMON_PATTERNS):
        score = max(0, score - 1)
        feedback.append("Avoid common words and patterns like 'password' or '123456'.")
    if len(set(password)) <= 3 and password:
        score = max(0, score - 1)
        feedback.append("Avoid repeating the same few characters.")

    score = min(score, 4)
    if not feedback:
        feedback.append("Good passphrase. Keep it unique to this account.")
    return PasswordAssessment(score=score, label=_LABELS[score], feedback=feedback)


if __name__ == "__main__":
    demo = assess_password("Correct horse battery staple 42!")
    print(demo)
