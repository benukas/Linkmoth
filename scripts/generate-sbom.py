#!/usr/bin/env python3
"""Create a deterministic SPDX 2.3 file inventory for a Linkmoth release."""
import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(args.root).resolve()
    files = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        files.append({
            "SPDXID": "SPDXRef-File-" + hashlib.sha256(relative.encode()).hexdigest()[:16],
            "fileName": "./" + relative,
            "checksums": [{"algorithm": "SHA256", "checksumValue": digest(path)}],
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        })
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Linkmoth " + args.version,
        "documentNamespace": "https://github.com/benukas/linkmoth/releases/" + args.version + "/sbom",
        "creationInfo": {"creators": ["Tool: Linkmoth release builder"], "created": "1970-01-01T00:00:00Z"},
        "files": files,
    }
    Path(args.output).write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
