"""Privacy-preserving common-password check (demo).

The input password is hashed with SHA-256 in memory and only the hash is
compared against hashes of a tiny built-in list of very common passwords.
The password itself is never stored or transmitted.

A production system would use a much larger hashed dataset or a
k-anonymity breach-lookup design — this module demonstrates the technique.
"""
from __future__ import annotations

import hashlib

_COMMON_PASSWORD_SHA256 = {
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
    "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225",
    "65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5",
    "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
    "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9",
    "1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032",
    "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f",
    "bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a",
    "e4ad93ca07acb8d908a3aa41e920ea4f4ef4f26e7f86cf8291c5db289780a5ae"
}


def is_common_password(password: str) -> bool:
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return digest in _COMMON_PASSWORD_SHA256
