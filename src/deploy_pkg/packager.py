"""Package builder — bundles files into a .tar.gz and uploads to S3."""

from __future__ import annotations

import tarfile
import tempfile
from pathlib import Path

import boto3

from deploy_pkg.sbom import generate_sbom


S3_PREFIX = "releases"


def build_package(
    version: str,
    files: list[tuple[Path, str]],  # (absolute_path, relative_path_in_archive)
    deploy_script: Path | None = None,
) -> tuple[Path, str]:
    """Bundle *files* into a .tar.gz and generate a CycloneDX SBOM.

    Parameters
    ----------
    version:
        Release version string (e.g. ``"v1.2.0"``).
    files:
        List of ``(absolute_path, relative_path)`` tuples.
    deploy_script:
        Optional path to a deploy script. If provided, it is added to the
        archive as ``deploy.sh`` and included in the SBOM.

    Returns
    -------
    tuple[Path, str]
        ``(path_to_tar_gz, sbom_json_string)``
    """
    all_files = list(files)
    if deploy_script:
        all_files.append((deploy_script, "deploy.sh"))

    sbom_json = generate_sbom(version, all_files)

    tmp = tempfile.mkdtemp()
    package_path = Path(tmp) / f"{version}.tar.gz"

    with tarfile.open(package_path, "w:gz") as tar:
        for abs_path, rel_path in all_files:
            tar.add(abs_path, arcname=rel_path)

    return package_path, sbom_json


def upload_release(
    version: str,
    package_path: Path,
    sbom_json: str,
    bucket: str,
    s3_client=None,
) -> dict[str, str]:
    """Upload the package and SBOM to S3.

    Returns a dict with ``package_url`` and ``sbom_url``.
    """
    client = s3_client or boto3.client("s3")

    package_key = f"{S3_PREFIX}/{version}/package.tar.gz"
    sbom_key = f"{S3_PREFIX}/{version}/sbom.json"

    client.upload_file(str(package_path), bucket, package_key)
    client.put_object(
        Bucket=bucket,
        Key=sbom_key,
        Body=sbom_json.encode(),
        ContentType="application/json",
    )

    return {
        "package_url": f"s3://{bucket}/{package_key}",
        "sbom_url": f"s3://{bucket}/{sbom_key}",
    }


def list_releases(bucket: str, s3_client=None) -> list[str]:
    """Return a sorted list of all release versions in the S3 bucket."""
    client = s3_client or boto3.client("s3")
    paginator = client.get_paginator("list_objects_v2")
    versions = set()

    for page in paginator.paginate(Bucket=bucket, Prefix=f"{S3_PREFIX}/", Delimiter="/"):
        for prefix in page.get("CommonPrefixes", []):
            # prefix looks like "releases/v1.0.0/"
            version = prefix["Prefix"].rstrip("/").split("/")[-1]
            versions.add(version)

    return sorted(versions)
