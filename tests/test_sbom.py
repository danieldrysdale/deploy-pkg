"""Tests for CycloneDX SBOM generation and parsing."""

import json
import hashlib
from pathlib import Path

import pytest

from deploy_pkg.sbom import generate_sbom, parse_sbom, get_sbom_version


@pytest.fixture
def sbom_files(tmp_path):
    files = []
    for name, content in [("app.py", b"print('hi')"), ("config.ini", b"[server]")]:
        p = tmp_path / name
        p.write_bytes(content)
        files.append((p, name))
    return files


def test_generate_sbom_is_valid_json(sbom_files):
    sbom = generate_sbom("v1.0.0", sbom_files)
    data = json.loads(sbom)
    assert "bomFormat" in data
    assert data["bomFormat"] == "CycloneDX"


def test_generate_sbom_version(sbom_files):
    sbom = generate_sbom("v1.2.3", sbom_files)
    assert get_sbom_version(sbom) == "v1.2.3"


def test_generate_sbom_contains_all_files(sbom_files):
    sbom = generate_sbom("v1.0.0", sbom_files)
    records = parse_sbom(sbom)
    names = {r["relative_path"] for r in records}
    assert "app.py" in names
    assert "config.ini" in names


def test_generate_sbom_hashes_are_correct(sbom_files):
    sbom = generate_sbom("v1.0.0", sbom_files)
    records = parse_sbom(sbom)
    for record in records:
        abs_path = next(p for p, name in sbom_files if name == record["relative_path"])
        expected = hashlib.sha256(abs_path.read_bytes()).hexdigest()
        assert record["sha256"] == expected


def test_generate_sbom_includes_size(sbom_files):
    sbom = generate_sbom("v1.0.0", sbom_files)
    records = parse_sbom(sbom)
    for record in records:
        assert record["size_bytes"] is not None
        assert record["size_bytes"] > 0


def test_parse_sbom_empty_components():
    sbom = json.dumps({"components": [], "metadata": {"component": {"version": "v0"}}})
    assert parse_sbom(sbom) == []
