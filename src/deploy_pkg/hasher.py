"""SHA-256 hashing utilities."""

from __future__ import annotations

import hashlib
from pathlib import Path


CHUNK_SIZE = 65_536  # 64 KB


def sha256_file(path: Path) -> str:
    """Return the hex-encoded SHA-256 digest of a file.

    Reads in chunks so large files don't blow memory.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def verify_file(path: Path, expected_hash: str) -> bool:
    """Return True if the file's SHA-256 matches *expected_hash*."""
    return sha256_file(path) == expected_hash
