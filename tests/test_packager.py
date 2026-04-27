"""Tests for package building and S3 upload."""

import json
import tarfile

import pytest

from deploy_pkg.packager import build_package, upload_release, list_releases
from tests.conftest import BUCKET


def test_build_package_creates_tarball(sample_files, tmp_path):
    package_path, sbom_json = build_package("v1.0.0", sample_files)
    assert package_path.exists()
    assert tarfile.is_tarfile(package_path)


def test_build_package_tarball_contains_all_files(sample_files):
    package_path, _ = build_package("v1.0.0", sample_files)
    with tarfile.open(package_path, "r:gz") as tar:
        names = tar.getnames()
    for _, rel_path in sample_files:
        assert rel_path in names


def test_build_package_sbom_is_cyclonedx(sample_files):
    _, sbom_json = build_package("v1.0.0", sample_files)
    data = json.loads(sbom_json)
    assert data["bomFormat"] == "CycloneDX"


def test_build_package_with_deploy_script(sample_files, deploy_script):
    package_path, sbom_json = build_package("v1.0.0", sample_files, deploy_script)
    with tarfile.open(package_path, "r:gz") as tar:
        assert "deploy.sh" in tar.getnames()


def test_upload_release_puts_objects_in_s3(s3, sample_files, tmp_path):
    package_path, sbom_json = build_package("v1.0.0", sample_files)
    urls = upload_release("v1.0.0", package_path, sbom_json, BUCKET, s3_client=s3)

    assert "v1.0.0" in urls["package_url"]
    assert "v1.0.0" in urls["sbom_url"]

    # Verify objects exist in S3
    s3.head_object(Bucket=BUCKET, Key="releases/v1.0.0/package.tar.gz")
    s3.head_object(Bucket=BUCKET, Key="releases/v1.0.0/sbom.json")


def test_list_releases_returns_versions(s3, sample_files):
    for version in ["v1.0.0", "v1.1.0", "v2.0.0"]:
        package_path, sbom_json = build_package(version, sample_files)
        upload_release(version, package_path, sbom_json, BUCKET, s3_client=s3)

    releases = list_releases(BUCKET, s3_client=s3)
    assert releases == ["v1.0.0", "v1.1.0", "v2.0.0"]


def test_list_releases_empty_bucket(s3):
    assert list_releases(BUCKET, s3_client=s3) == []
