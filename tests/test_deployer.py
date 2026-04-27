"""Tests for fetch, verify, deploy, rollback, and status."""

import json
import pytest

from deploy_pkg.packager import build_package, upload_release
from deploy_pkg import deployer
from tests.conftest import BUCKET


def _upload(s3, version, sample_files, deploy_script=None):
    package_path, sbom_json = build_package(version, sample_files, deploy_script)
    upload_release(version, package_path, sbom_json, BUCKET, s3_client=s3)
    return sbom_json


class TestFetchAndVerify:
    def test_fetch_returns_package_and_sbom(self, s3, sample_files, state_dir):
        _upload(s3, "v1.0.0", sample_files)
        package_path, sbom_json = deployer.fetch_release("v1.0.0", BUCKET, s3_client=s3)
        assert package_path.exists()
        assert "CycloneDX" in sbom_json

    def test_verify_package_passes_on_good_package(self, s3, sample_files, state_dir):
        sbom_json = _upload(s3, "v1.0.0", sample_files)
        package_path, sbom_json = deployer.fetch_release("v1.0.0", BUCKET, s3_client=s3)
        errors = deployer.verify_package(package_path, sbom_json)
        assert errors == []

    def test_verify_package_detects_tampered_file(self, s3, sample_files, tmp_path, state_dir):
        sbom_json = _upload(s3, "v1.0.0", sample_files)
        package_path, sbom_json = deployer.fetch_release("v1.0.0", BUCKET, s3_client=s3)

        # Tamper: inject a bad hash into the SBOM
        data = json.loads(sbom_json)
        for c in data["components"]:
            for h in c.get("hashes", []):
                h["content"] = "0" * 64  # wrong hash
        bad_sbom = json.dumps(data)

        errors = deployer.verify_package(package_path, bad_sbom)
        assert len(errors) > 0
        assert all("HASH MISMATCH" in e for e in errors)


class TestDeploy:
    def test_deploy_copies_files_to_deploy_root(self, s3, sample_files, deploy_root, state_dir):
        _upload(s3, "v1.0.0", sample_files)
        errors = deployer.deploy("v1.0.0", BUCKET, deploy_root, s3_client=s3, run_deploy_script=False)
        assert errors == []
        for _, rel_path in sample_files:
            assert (deploy_root / rel_path).exists()

    def test_deploy_updates_state(self, s3, sample_files, deploy_root, state_dir):
        _upload(s3, "v1.0.0", sample_files)
        deployer.deploy("v1.0.0", BUCKET, deploy_root, s3_client=s3, run_deploy_script=False)
        assert deployer.get_current_version() == "v1.0.0"

    def test_deploy_aborts_on_verification_failure(self, s3, sample_files, deploy_root, state_dir, monkeypatch):
        _upload(s3, "v1.0.0", sample_files)

        # Patch verify_package to simulate failure
        monkeypatch.setattr(
            deployer,
            "verify_package",
            lambda *a, **kw: ["HASH MISMATCH: app.py"],
        )

        errors = deployer.deploy("v1.0.0", BUCKET, deploy_root, s3_client=s3, run_deploy_script=False)
        assert errors == ["HASH MISMATCH: app.py"]
        # No files should have been written
        assert not any(deploy_root.iterdir())

    def test_deploy_second_version_tracks_previous(self, s3, sample_files, deploy_root, state_dir):
        _upload(s3, "v1.0.0", sample_files)
        _upload(s3, "v1.1.0", sample_files)
        deployer.deploy("v1.0.0", BUCKET, deploy_root, s3_client=s3, run_deploy_script=False)
        deployer.deploy("v1.1.0", BUCKET, deploy_root, s3_client=s3, run_deploy_script=False)
        state = json.loads((state_dir / "state.json").read_text())
        assert state["version"] == "v1.1.0"
        assert state["previous_version"] == "v1.0.0"


class TestRollback:
    def test_rollback_restores_previous_files(self, s3, tmp_path, deploy_root, state_dir):
        # v1.0.0 has one content, v1.1.0 has different content
        files_v1 = []
        files_v2 = []
        for name in ["app.py", "config.ini"]:
            p1 = tmp_path / f"v1_{name}"
            p1.write_text(f"v1 content of {name}")
            files_v1.append((p1, name))
            p2 = tmp_path / f"v2_{name}"
            p2.write_text(f"v2 content of {name}")
            files_v2.append((p2, name))

        _upload(s3, "v1.0.0", files_v1)
        _upload(s3, "v1.1.0", files_v2)

        deployer.deploy("v1.0.0", BUCKET, deploy_root, s3_client=s3, run_deploy_script=False)
        deployer.deploy("v1.1.0", BUCKET, deploy_root, s3_client=s3, run_deploy_script=False)

        # Confirm v2 content is in place
        assert "v2 content" in (deploy_root / "app.py").read_text()

        version, errors = deployer.rollback(deploy_root, BUCKET, s3_client=s3, run_deploy_script=False)
        assert errors == []
        assert version == "v1.0.0"
        assert "v1 content" in (deploy_root / "app.py").read_text()

    def test_rollback_via_s3_verifies_package(self, s3, tmp_path, deploy_root, state_dir, monkeypatch):
        files_v1 = [(tmp_path / "app.py", "app.py")]
        files_v1[0][0].write_text("v1")
        files_v2 = [(tmp_path / "app2.py", "app.py")]
        files_v2[0][0].write_text("v2")

        _upload(s3, "v1.0.0", files_v1)
        _upload(s3, "v1.1.0", files_v2)

        deployer.deploy("v1.0.0", BUCKET, deploy_root, s3_client=s3, run_deploy_script=False)
        deployer.deploy("v1.1.0", BUCKET, deploy_root, s3_client=s3, run_deploy_script=False)

        # Patch verify to simulate a corrupted v1.0.0 in S3
        original_verify = deployer.verify_package
        call_count = [0]
        def patched_verify(package_path, sbom_json):
            call_count[0] += 1
            return ["HASH MISMATCH: app.py"]
        monkeypatch.setattr(deployer, "verify_package", patched_verify)

        version, errors = deployer.rollback(deploy_root, BUCKET, s3_client=s3, run_deploy_script=False)
        assert errors != []  # rollback aborted due to verification failure
        assert call_count[0] > 0

    def test_rollback_returns_none_with_no_previous_version(self, deploy_root, state_dir, s3):
        version, errors = deployer.rollback(deploy_root, BUCKET, s3_client=s3)
        assert version is None
        assert errors == []


class TestVerifyDeployed:
    def test_verify_deployed_passes_after_clean_deploy(self, s3, sample_files, deploy_root, state_dir):
        _upload(s3, "v1.0.0", sample_files)
        deployer.deploy("v1.0.0", BUCKET, deploy_root, s3_client=s3, run_deploy_script=False)
        errors = deployer.verify_deployed(deploy_root)
        assert errors == []

    def test_verify_deployed_detects_tampered_file(self, s3, sample_files, deploy_root, state_dir):
        _upload(s3, "v1.0.0", sample_files)
        deployer.deploy("v1.0.0", BUCKET, deploy_root, s3_client=s3, run_deploy_script=False)

        # Tamper with a deployed file
        (deploy_root / "app.py").write_text("I have been tampered with")

        errors = deployer.verify_deployed(deploy_root)
        assert any("app.py" in e for e in errors)

    def test_verify_deployed_detects_missing_file(self, s3, sample_files, deploy_root, state_dir):
        _upload(s3, "v1.0.0", sample_files)
        deployer.deploy("v1.0.0", BUCKET, deploy_root, s3_client=s3, run_deploy_script=False)

        (deploy_root / "app.py").unlink()

        errors = deployer.verify_deployed(deploy_root)
        assert any("app.py" in e for e in errors)

    def test_verify_deployed_no_state(self, deploy_root, state_dir):
        errors = deployer.verify_deployed(deploy_root)
        assert errors == ["No deployment state found -- nothing to verify."]
