"""CycloneDX SBOM generation and parsing for deployment packages."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from cyclonedx.model import HashAlgorithm, HashType, Property
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot6

from deploy_pkg.hasher import sha256_file


def generate_sbom(
    version: str,
    files: list[tuple[Path, str]],  # (absolute_path, relative_path_in_package)
) -> str:
    """Generate a CycloneDX v1.6 JSON SBOM for a deployment package.

    Parameters
    ----------
    version:
        The release version string (e.g. ``"v1.2.0"``).
    files:
        List of ``(absolute_path, relative_path)`` tuples for every file
        being bundled into the package.

    Returns
    -------
    str
        The CycloneDX SBOM as a JSON string.
    """
    # Top-level component representing the deployment package itself
    package_component = Component(
        type=ComponentType.APPLICATION,
        name="deploy-pkg",
        version=version,
        description=f"Deployment package {version}",
    )

    # One component per bundled file
    file_components: list[Component] = []
    for abs_path, rel_path in files:
        digest = sha256_file(abs_path)
        size = abs_path.stat().st_size
        component = Component(
            type=ComponentType.FILE,
            name=rel_path,
            version=version,
            hashes=[
                HashType(
                    alg=HashAlgorithm.SHA_256,
                    content=digest,
                )
            ],
            properties=[
                Property(name="deploy-pkg:size_bytes", value=str(size)),
                Property(name="deploy-pkg:relative_path", value=rel_path),
            ],
        )
        file_components.append(component)

    bom = Bom(
        metadata=BomMetaData(
            timestamp=datetime.now(tz=timezone.utc),
            component=package_component,
        ),
        components=file_components,
    )

    output = JsonV1Dot6(bom)
    return output.output_as_string(indent=2)


def parse_sbom(sbom_json: str) -> list[dict]:
    """Parse a CycloneDX JSON SBOM and return a list of file records.

    Each record has keys: ``relative_path``, ``sha256``, ``size_bytes``.
    """
    data = json.loads(sbom_json)
    records = []
    for component in data.get("components", []):
        rel_path = None
        size_bytes = None

        for prop in component.get("properties", []):
            if prop["name"] == "deploy-pkg:relative_path":
                rel_path = prop["value"]
            elif prop["name"] == "deploy-pkg:size_bytes":
                size_bytes = int(prop["value"])

        sha256 = None
        for h in component.get("hashes", []):
            if h.get("alg") == "SHA-256":
                sha256 = h["content"]

        if rel_path and sha256:
            records.append(
                {
                    "relative_path": rel_path,
                    "sha256": sha256,
                    "size_bytes": size_bytes,
                }
            )

    return records


def get_sbom_version(sbom_json: str) -> str:
    """Extract the package version from a CycloneDX SBOM."""
    data = json.loads(sbom_json)
    return data.get("metadata", {}).get("component", {}).get("version", "unknown")
