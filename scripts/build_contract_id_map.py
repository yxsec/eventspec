#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build contract_id (sha256(contract.tac)) -> addresses mapping.",
    )
    parser.add_argument(
        "--base",
        type=Path,
        required=True,
        help="Root directory to scan recursively for folders containing contract.tac.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("contract_id_to_addresses.json"),
        help="Output JSON path (default: contract_id_to_addresses.json).",
    )
    args = parser.parse_args()

    mapping: dict[str, list[str]] = {}
    count = 0

    for root, _, files in os.walk(args.base):
        if "contract.tac" not in files:
            continue
        tac_path = Path(root) / "contract.tac"
        addr = tac_path.parent.name
        if len(addr) != 40:
            continue

        try:
            digest = sha256_file(tac_path)
        except Exception:
            continue

        addrs = mapping.setdefault(digest, [])
        if addr not in addrs:
            addrs.append(addr)

        count += 1
        if count % 50000 == 0:
            print(f"processed {count} files...")

    for k in list(mapping.keys()):
        mapping[k] = sorted(mapping[k])

    args.out.write_text(json.dumps(mapping, indent=2, sort_keys=True))
    print(f"mapped {count} contract.tac files -> {len(mapping)} unique hashes")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
