"""SBOM generator — CycloneDX 1.4/1.5 and SPDX 2.3 JSON from manifest dependencies."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .manifest import Dependency


def _hash_value(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dep_to_cdx_component(dep: Dependency, idx: int) -> dict:
    return {
        "bom-ref": f"supplysec-{idx}-{dep.name}",
        "type": "library",
        "name": dep.name,
        "version": dep.version,
        "purl": dep.purl,
        "hashes": [
            {"alg": "SHA-256", "content": _hash_value(f"{dep.name}@{dep.version}")}
        ],
        "licenses": dep.extra.get("licenses", []),
        "properties": [
            {"name": "supplysec:ecosystem", "value": dep.ecosystem},
            {"name": "supplysec:source", "value": dep.source_file},
        ],
    }


def to_cyclonedx(deps: list[Dependency], version: str = "1.5") -> dict[str, Any]:
    """Generate CycloneDX JSON BOM."""
    spec_version = "1.5" if version == "1.5" else "1.4"
    components = [_dep_to_cdx_component(d, i) for i, d in enumerate(deps)]
    metadata = {
        "timestamp": _now_iso(),
        "tools": [{"vendor": "supplysec", "name": "supplysec", "version": "1.0.0"}],
    }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
        "metadata": metadata,
        "components": components,
    }


def to_spdx(deps: list[Dependency], version: str = "2.3") -> dict[str, Any]:
    """Generate SPDX 2.3 JSON."""
    doc_namespace = f"urn:uuid:supplysec-{_hash_value(_now_iso())[:16]}"
    packages = []
    relationships = []
    for i, dep in enumerate(deps):
        pkg_id = f"SPDXRef-pkg-{i}"
        packages.append({
            "SPDXID": pkg_id,
            "name": dep.name,
            "versionInfo": dep.version,
            "downloadLocation": "NOASSERTION",
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": _hash_value(f"{dep.name}@{dep.version}"),
                }
            ],
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": dep.purl,
                }
            ],
            "primaryPackagePurpose": "LIBRARY",
        })
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": pkg_id,
            "relationshipType": "CONTAINS",
        })
    return {
        "spdxVersion": f"SPDX-{version}",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "supplysec-sbom",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": _now_iso(),
            "creators": ["Tool: supplysec-1.0.0"],
            "licenseListVersion": version,
        },
        "packages": packages,
        "relationships": relationships,
    }


def write_sbom(deps: list[Dependency], output_dir: str | Path,
               cyclonedx_version: str = "1.5", spdx_version: str = "2.3") -> dict[str, Path]:
    """Write CycloneDX + SPDX JSON to output_dir, return paths."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    cdx_path = out / "bom-cyclonedx.json"
    spdx_path = out / "sbom-spdx.json"

    cdx = to_cyclonedx(deps, cyclonedx_version)
    cdx_path.write_text(json.dumps(cdx, indent=2))

    spdx = to_spdx(deps, spdx_version)
    spdx_path.write_text(json.dumps(spdx, indent=2))

    return {"cyclonedx": cdx_path, "spdx": spdx_path}
