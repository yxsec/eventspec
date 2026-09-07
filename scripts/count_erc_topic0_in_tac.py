#!/usr/bin/env python3
"""Count contract.tac files containing ERC event topic0 values."""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None


TOPIC0_RE = re.compile(r"0x[0-9a-f]{64}", re.IGNORECASE)


def _load_erc_rows(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return [row for row in reader]


def _collect_topic0(rows: Iterable[Dict[str, str]]) -> Set[str]:
    topic0s: Set[str] = set()
    for row in rows:
        topic0 = (row.get("topic0") or "").strip().lower()
        if topic0:
            topic0s.add(topic0)
    return topic0s


def _maybe_print_progress(index: int, total: int) -> None:
    if total <= 1:
        return
    progress_every = max(1, total // 100)
    if index == 1 or index == total or index % progress_every == 0:
        percent = (index / total) * 100
        print(f"[count] progress {index}/{total} ({percent:.1f}%)")


def _iter_tac_paths(tac_root: Path) -> List[Path]:
    return sorted(tac_root.rglob("contract.tac"))


def _scan_contracts(
    tac_paths: List[Path], target_topic0: Set[str]
) -> Tuple[Dict[str, int], int]:
    counts = {topic0: 0 for topic0 in target_topic0}
    total = len(tac_paths)
    iterator: Iterable[Path] = tac_paths
    if tqdm is not None:
        iterator = tqdm(tac_paths, desc="scan-tac", unit="contract")
    for index, tac_path in enumerate(iterator, start=1):
        try:
            text = tac_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        matched: Set[str] = set()
        for match in TOPIC0_RE.finditer(text):
            topic0 = match.group(0).lower()
            if topic0 in target_topic0:
                matched.add(topic0)
        if matched:
            for topic0 in matched:
                counts[topic0] += 1
        if tqdm is None:
            _maybe_print_progress(index, total)
    return counts, total


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Count contract.tac files containing ERC event topic0 values."
    )
    parser.add_argument(
        "--erc",
        type=Path,
        default=Path("artifacts/erc_events.csv"),
        help="Path to erc_events.csv",
    )
    parser.add_argument(
        "--tac-root",
        type=Path,
        required=True,
        help="Root directory containing contract.tac files.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("artifacts/out/erc_topic0_file_counts.csv"),
        help="Output CSV path",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    erc_rows = _load_erc_rows(args.erc)
    target_topic0 = _collect_topic0(erc_rows)
    tac_paths = _iter_tac_paths(args.tac_root)

    counts, total_files = _scan_contracts(tac_paths, target_topic0)

    with args.out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "erc_id",
                "erc_title",
                "event_name",
                "event_signature",
                "topic0",
                "file_count",
                "total_files",
            ],
        )
        writer.writeheader()
        for row in erc_rows:
            topic0 = (row.get("topic0") or "").strip().lower()
            writer.writerow(
                {
                    "erc_id": row.get("erc_id"),
                    "erc_title": row.get("erc_title"),
                    "event_name": row.get("event_name"),
                    "event_signature": row.get("event_signature"),
                    "topic0": row.get("topic0"),
                    "file_count": counts.get(topic0, 0),
                    "total_files": total_files,
                }
            )

    print(f"[count] scanned {total_files} files")
    print(f"[count] wrote {args.out}")


if __name__ == "__main__":
    main()
