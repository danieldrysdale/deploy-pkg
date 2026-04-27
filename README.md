# deploy-pkg

A versioned deployment packager with S3 storage, CycloneDX SBOM generation, SHA-256 file verification, and rollback support.

Built for environments where you need to know exactly what is deployed, prove it hasn't been tampered with, and recover quickly when something goes wrong.

## Features

- **Build** — bundle any set of files into a versioned `.tar.gz` with an optional `deploy.sh` script
- **SBOM** — CycloneDX v1.6 JSON SBOM generated for every package, listing every file with its SHA-256 hash and size
- **Upload** — package and SBOM pushed to S3 under `releases/{version}/`
- **Verify** — every file checked against the SBOM before deployment touches the disk
- **Deploy** — files copied into place, deploy script executed, state recorded
- **Rollback** — one command restores the previous deployment from backup
- **Post-deploy verify** — re-check deployed files against the SBOM at any time
- 30 pytest tests using moto to mock S3 — no real AWS account needed for testing

## Project structure

```
deploy-pkg/
├── src/deploy_pkg/
│   ├── __init__.py
│   ├── cli.py          # argparse CLI entry point
│   ├── hasher.py       # SHA-256 file hashing
│   ├── sbom.py         # CycloneDX SBOM generation and parsing
│   ├── packager.py     # Package builder and S3 uploader
│   └── deployer.py     # Fetch, verify, deploy, rollback, state management
├── tests/
│   ├── conftest.py
│   ├── test_hasher.py
│   ├── test_sbom.py
│   ├── test_packager.py
│   └── test_deployer.py
└── pyproject.toml
```

## Installation

```bash
git clone https://github.com/danieldrysdale/deploy-pkg
cd deploy-pkg
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## AWS credentials

Configure credentials on the build/deploy machine:

```bash
aws configure
# or set environment variables:
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=ap-southeast-2
```

## Usage

### Build and upload a release

```bash
deploy-pkg build \
  --version v1.2.0 \
  --bucket my-deploy-bucket \
  --files src/app.py src/config.ini \
  --deploy-script scripts/deploy.sh
```

### List available releases

```bash
deploy-pkg releases --bucket my-deploy-bucket
```

### Deploy a release to a server

```bash
deploy-pkg deploy \
  --version v1.2.0 \
  --bucket my-deploy-bucket \
  --deploy-root /opt/myapp
```

Deploy will:
1. Pull `package.tar.gz` and `sbom.json` from S3
2. Verify every file's SHA-256 against the SBOM — abort if anything fails
3. Back up existing files
4. Copy new files into place
5. Run `deploy.sh` if bundled

### Verify deployed files

```bash
deploy-pkg verify --deploy-root /opt/myapp
```

Re-checks every deployed file against the SBOM stored in state. Run this any time to confirm the deployment hasn't been tampered with.

### Roll back

```bash
deploy-pkg rollback --deploy-root /opt/myapp
```

Restores the previous backup. One level of rollback is maintained.

### Check current status

```bash
deploy-pkg status
```

## S3 structure

```
s3://my-deploy-bucket/
└── releases/
    ├── v1.0.0/
    │   ├── package.tar.gz
    │   └── sbom.json
    └── v1.2.0/
        ├── package.tar.gz
        └── sbom.json
```

## SBOM format

Packages produce a [CycloneDX](https://cyclonedx.org/) v1.6 JSON SBOM. Each bundled file appears as a `file` component with its SHA-256 hash and size:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "name": "deploy-pkg",
      "version": "v1.2.0"
    }
  },
  "components": [
    {
      "type": "file",
      "name": "app.py",
      "hashes": [{ "alg": "SHA-256", "content": "abc123..." }],
      "properties": [
        { "name": "deploy-pkg:size_bytes", "value": "1024" },
        { "name": "deploy-pkg:relative_path", "value": "app.py" }
      ]
    }
  ]
}
```

## Running tests

Tests use [moto](https://github.com/getmoto/moto) to mock S3 — no real AWS account required:

```bash
pytest -v
```
