"""Command-line interface for deploy-pkg."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from deploy_pkg import packager, deployer


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------

def cmd_build(args: argparse.Namespace) -> int:
    """Build a deployment package and upload to S3."""
    files: list[tuple[Path, str]] = []
    for f in args.files:
        abs_path = Path(f).resolve()
        if not abs_path.exists():
            print(f"ERROR: file not found: {f}", file=sys.stderr)
            return 1
        rel_path = abs_path.name if not args.strip_prefix else str(abs_path).replace(args.strip_prefix, "").lstrip("/")
        files.append((abs_path, rel_path))

    deploy_script = Path(args.deploy_script).resolve() if args.deploy_script else None
    if deploy_script and not deploy_script.exists():
        print(f"ERROR: deploy script not found: {args.deploy_script}", file=sys.stderr)
        return 1

    print(f"Building package {args.version} with {len(files)} file(s)...")
    package_path, sbom_json = packager.build_package(args.version, files, deploy_script)

    print(f"Package:  {package_path}")
    print(f"Uploading to s3://{args.bucket}...")

    urls = packager.upload_release(args.version, package_path, sbom_json, args.bucket)
    print(f"Package:  {urls['package_url']}")
    print(f"SBOM:     {urls['sbom_url']}")
    print("Done.")
    return 0


def cmd_deploy(args: argparse.Namespace) -> int:
    """Pull a release from S3 and deploy it."""
    deploy_root = Path(args.deploy_root).resolve()
    deploy_root.mkdir(parents=True, exist_ok=True)

    print(f"Deploying {args.version} from s3://{args.bucket}...")
    errors = deployer.deploy(
        args.version,
        args.bucket,
        deploy_root,
        run_deploy_script=not args.no_script,
    )

    if errors:
        print("VERIFICATION FAILED — deploy aborted:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    print(f"Successfully deployed {args.version} to {deploy_root}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify deployed files against the SBOM."""
    deploy_root = Path(args.deploy_root).resolve()
    print(f"Verifying deployment at {deploy_root}...")
    errors = deployer.verify_deployed(deploy_root)

    if errors:
        print("VERIFICATION FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    version = deployer.get_current_version()
    print(f"All files verified OK (version: {version})")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    """Roll back to the previous deployment via S3."""
    deploy_root = Path(args.deploy_root).resolve()
    current = deployer.get_current_version()
    print(f"Rolling back from {current} using s3://{args.bucket}...")

    version, errors = deployer.rollback(
        deploy_root,
        args.bucket,
        run_deploy_script=not args.no_script,
    )

    if version is None:
        print("ERROR: no previous version recorded — cannot roll back.", file=sys.stderr)
        return 1

    if errors:
        print("ROLLBACK VERIFICATION FAILED — aborted:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    print(f"Rolled back to: {version}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show current deployment status."""
    version = deployer.get_current_version()
    if version is None:
        print("Status: no deployment found")
    else:
        print(f"Status: deployed version → {version}")
    return 0


def cmd_releases(args: argparse.Namespace) -> int:
    """List available releases in S3."""
    releases = packager.list_releases(args.bucket)
    if not releases:
        print("No releases found.")
        return 0
    current = deployer.get_current_version()
    print(f"{'Version':<20}  Status")
    print("-" * 35)
    for r in releases:
        marker = "* current" if r == current else ""
        print(f"{r:<20}  {marker}")
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deploy-pkg",
        description="Versioned deployment packager with CycloneDX SBOM, SHA-256 verification, and rollback.",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # build
    b = sub.add_parser("build", help="Build and upload a deployment package")
    b.add_argument("--version", required=True, help="Release version (e.g. v1.2.0)")
    b.add_argument("--bucket", required=True, help="S3 bucket name")
    b.add_argument("--files", nargs="+", required=True, help="Files to bundle")
    b.add_argument("--deploy-script", help="Optional deploy.sh to bundle and run on deploy")
    b.add_argument("--strip-prefix", help="Path prefix to strip from file names in the archive")

    # deploy
    d = sub.add_parser("deploy", help="Deploy a release from S3")
    d.add_argument("--version", required=True, help="Release version to deploy")
    d.add_argument("--bucket", required=True, help="S3 bucket name")
    d.add_argument("--deploy-root", required=True, help="Directory to deploy files into")
    d.add_argument("--no-script", action="store_true", help="Skip running the bundled deploy script")

    # verify
    v = sub.add_parser("verify", help="Verify deployed files against the SBOM")
    v.add_argument("--deploy-root", required=True, help="Deployment directory to verify")

    # rollback
    r = sub.add_parser("rollback", help="Roll back to the previous deployment via S3")
    r.add_argument("--deploy-root", required=True, help="Deployment directory to roll back")
    r.add_argument("--bucket", required=True, help="S3 bucket name")
    r.add_argument("--no-script", action="store_true", help="Skip running the bundled deploy script")

    # status
    sub.add_parser("status", help="Show currently deployed version")

    # releases
    rel = sub.add_parser("releases", help="List available releases in S3")
    rel.add_argument("--bucket", required=True, help="S3 bucket name")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    handlers = {
        "build": cmd_build,
        "deploy": cmd_deploy,
        "verify": cmd_verify,
        "rollback": cmd_rollback,
        "status": cmd_status,
        "releases": cmd_releases,
    }

    sys.exit(handlers[args.command](args))


if __name__ == "__main__":
    main()
