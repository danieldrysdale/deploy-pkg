"""Deployer — pulls a release from S3, verifies it, deploys it, supports rollback."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

import boto3

from deploy_pkg.hasher import verify_file
from deploy_pkg.sbom import parse_sbom, get_sbom_version
from deploy_pkg.packager import S3_PREFIX


# State file tracks the currently deployed version
STATE_FILE = Path("/var/lib/deploy-pkg/state.json")
BACKUP_DIR = Path("/var/lib/deploy-pkg/backup")


def _state_file() -> Path:
    """Return the state file path, respecting DEPLOY_PKG_STATE_DIR override (for tests)."""
    state_dir = os.environ.get("DEPLOY_PKG_STATE_DIR")
    if state_dir:
        return Path(state_dir) / "state.json"
    return STATE_FILE


def _backup_dir() -> Path:
    """Return the backup directory, respecting DEPLOY_PKG_STATE_DIR override (for tests)."""
    state_dir = os.environ.get("DEPLOY_PKG_STATE_DIR")
    if state_dir:
        return Path(state_dir) / "backup"
    return BACKUP_DIR


def _read_state() -> dict:
    sf = _state_file()
    if sf.exists():
        return json.loads(sf.read_text())
    return {}


def _write_state(state: dict) -> None:
    sf = _state_file()
    sf.parent.mkdir(parents=True, exist_ok=True)
    sf.write_text(json.dumps(state, indent=2))


def get_current_version() -> Optional[str]:
    """Return the currently deployed version, or None."""
    return _read_state().get("version")


def fetch_release(
    version: str,
    bucket: str,
    s3_client=None,
) -> tuple[Path, str]:
    """Download the package and SBOM for *version* from S3.

    Returns ``(local_package_path, sbom_json)``.
    """
    client = s3_client or boto3.client("s3")
    tmp = Path(tempfile.mkdtemp())

    package_key = f"{S3_PREFIX}/{version}/package.tar.gz"
    sbom_key = f"{S3_PREFIX}/{version}/sbom.json"

    package_path = tmp / "package.tar.gz"
    client.download_file(bucket, package_key, str(package_path))

    sbom_response = client.get_object(Bucket=bucket, Key=sbom_key)
    sbom_json = sbom_response["Body"].read().decode()

    return package_path, sbom_json


def verify_package(package_path: Path, sbom_json: str) -> list[str]:
    """Extract the package to a temp dir and verify every file against the SBOM.

    Returns a list of error messages. Empty list means all files verified OK.
    """
    records = parse_sbom(sbom_json)
    errors = []

    with tempfile.TemporaryDirectory() as tmp:
        extract_dir = Path(tmp)
        with tarfile.open(package_path, "r:gz") as tar:
            tar.extractall(extract_dir)

        for record in records:
            file_path = extract_dir / record["relative_path"]
            if not file_path.exists():
                errors.append(f"MISSING: {record['relative_path']}")
            elif not verify_file(file_path, record["sha256"]):
                errors.append(f"HASH MISMATCH: {record['relative_path']}")

    return errors


def _backup_current(deploy_root: Path, records: list[dict]) -> None:
    """Back up files that are about to be overwritten."""
    backup = _backup_dir()
    if backup.exists():
        shutil.rmtree(backup)
    backup.mkdir(parents=True, exist_ok=True)

    for record in records:
        target = deploy_root / record["relative_path"]
        if target.exists():
            dest = backup / record["relative_path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, dest)


def deploy(
    version: str,
    bucket: str,
    deploy_root: Path,
    s3_client=None,
    run_deploy_script: bool = True,
) -> list[str]:
    """Full deploy workflow: fetch → verify → backup → copy files → run script.

    Returns a list of verification errors. If non-empty, deploy is aborted.
    """
    package_path, sbom_json = fetch_release(version, bucket, s3_client)

    # Verify before touching anything on disk
    errors = verify_package(package_path, sbom_json)
    if errors:
        return errors

    records = parse_sbom(sbom_json)
    previous_version = get_current_version()

    # Back up existing files
    _backup_current(deploy_root, records)

    # Extract and copy files into place
    with tempfile.TemporaryDirectory() as tmp:
        extract_dir = Path(tmp)
        with tarfile.open(package_path, "r:gz") as tar:
            tar.extractall(extract_dir)

        for record in records:
            src = extract_dir / record["relative_path"]
            dst = deploy_root / record["relative_path"]
            if src.name == "deploy.sh":
                # Run the deploy script rather than copying it
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

        # Run the bundled deploy script if present
        deploy_script = extract_dir / "deploy.sh"
        if run_deploy_script and deploy_script.exists():
            os.chmod(deploy_script, 0o755)
            subprocess.run(
                [str(deploy_script)],
                cwd=str(deploy_root),
                check=True,
            )

    _write_state(
        {
            "version": version,
            "previous_version": previous_version,
            "sbom": json.loads(sbom_json),
        }
    )

    return []


def rollback(deploy_root: Path) -> Optional[str]:
    """Restore the previous backup.

    Returns the version rolled back to, or None if no backup exists.
    """
    backup = _backup_dir()
    state = _read_state()
    previous_version = state.get("previous_version")

    if not backup.exists() or not any(backup.iterdir()):
        return None

    for src in backup.rglob("*"):
        if src.is_file():
            rel = src.relative_to(backup)
            dst = deploy_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    _write_state(
        {
            "version": previous_version,
            "previous_version": None,
        }
    )

    return previous_version


def verify_deployed(deploy_root: Path) -> list[str]:
    """Re-verify deployed files against the SBOM stored in state.

    Returns a list of error messages. Empty list means everything checks out.
    """
    state = _read_state()
    sbom_data = state.get("sbom")
    if not sbom_data:
        return ["No deployment state found — nothing to verify."]

    import json
    sbom_json = json.dumps(sbom_data)
    records = parse_sbom(sbom_json)
    errors = []

    for record in records:
        if record["relative_path"] == "deploy.sh":
            continue
        file_path = deploy_root / record["relative_path"]
        if not file_path.exists():
            errors.append(f"MISSING: {record['relative_path']}")
        elif not verify_file(file_path, record["sha256"]):
            errors.append(f"HASH MISMATCH: {record['relative_path']}")

    return errors
