"""Tests for SHA-256 hashing."""

import hashlib
from pathlib import Path

import pytest

from deploy_pkg.hasher import sha256_file, verify_file


def test_sha256_file_matches_hashlib(tmp_path):
    f = tmp_path / "test.txt"
    f.write_bytes(b"hello warehouse")
    expected = hashlib.sha256(b"hello warehouse").hexdigest()
    assert sha256_file(f) == expected


def test_sha256_file_large_file(tmp_path):
    f = tmp_path / "large.bin"
    data = b"x" * 200_000  # larger than chunk size
    f.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert sha256_file(f) == expected


def test_verify_file_passes(tmp_path):
    f = tmp_path / "ok.txt"
    f.write_bytes(b"good content")
    digest = hashlib.sha256(b"good content").hexdigest()
    assert verify_file(f, digest) is True


def test_verify_file_fails_on_tamper(tmp_path):
    f = tmp_path / "bad.txt"
    f.write_bytes(b"original")
    digest = hashlib.sha256(b"original").hexdigest()
    f.write_bytes(b"tampered")
    assert verify_file(f, digest) is False
