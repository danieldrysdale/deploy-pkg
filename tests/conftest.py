"""Shared pytest fixtures."""

from __future__ import annotations

import os
import pytest
import boto3
from moto import mock_aws
from pathlib import Path


BUCKET = "test-deploy-bucket"


@pytest.fixture
def aws_credentials():
    """Mocked AWS credentials so moto intercepts all boto3 calls."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "ap-southeast-2"


@pytest.fixture
def s3(aws_credentials):
    """A moto-mocked S3 client with the test bucket pre-created."""
    with mock_aws():
        client = boto3.client("s3", region_name="ap-southeast-2")
        client.create_bucket(
            Bucket=BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
        )
        yield client


@pytest.fixture
def sample_files(tmp_path) -> list[tuple[Path, str]]:
    """Three sample files to bundle into a package."""
    files = []
    for name, content in [
        ("app.py", "print('hello warehouse')"),
        ("config.ini", "[server]\nhost=localhost"),
        ("README.txt", "Deployment package v1.0.0"),
    ]:
        p = tmp_path / name
        p.write_text(content)
        files.append((p, name))
    return files


@pytest.fixture
def deploy_script(tmp_path) -> Path:
    """A minimal deploy.sh script."""
    script = tmp_path / "deploy.sh"
    script.write_text("#!/bin/bash\necho 'deploy script ran'\n")
    return script


@pytest.fixture
def state_dir(tmp_path, monkeypatch) -> Path:
    """Redirect state and backup dirs to tmp_path for tests."""
    d = tmp_path / "state"
    d.mkdir()
    monkeypatch.setenv("DEPLOY_PKG_STATE_DIR", str(d))
    return d


@pytest.fixture
def deploy_root(tmp_path) -> Path:
    """A temp directory to deploy files into."""
    d = tmp_path / "deploy_root"
    d.mkdir()
    return d
