#!/usr/bin/env python3
"""Build experiment design and result tables for ERC comparisons."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


TOPK_RE = re.compile(r"topk_(\d+)")


def _dominant_count(profile: Dict[str, float]) -> Optional[str]:
    if not profile:
        return None
    return max(profile.items(), key=lambda kv: kv[1])[0]


def _infer_state_change_expected(conditions: Optional[str]) -> Optional[bool]:
    if not conditions:
        return None
    lowered = conditions.lower()
    storage_keywords = (
        "balance[",
        "allowance[",
        "totalsupply",
        "supply",
        "owner",
        "stake",
        "mint",
        "burn",
    )
    if any(keyword in lowered for keyword in storage_keywords):
        return True
    if "+=" in conditions or "-=" in conditions:
        return True
    if " = " in conditions:
        if not any(op in conditions for op in ("==", ">=", "<=", "!=")):
            return True
    return False


def _parse_state_change_flag(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"", "-", "?", "na", "n/a"}:
        return None
    if lowered in {"1", "true", "t", "yes", "y"}:
        return True
    if lowered in {"0", "false", "f", "no", "n"}:
        return False
    return None


def _expected_state_change(row: Dict[str, str]) -> Optional[bool]:
    explicit = _parse_state_change_flag(row.get("state_change_flag"))
    if explicit is not None:
        return explicit
    return _infer_state_change_expected(row.get("Conditions"))


def _infer_state_change_observed(pattern: Dict[str, object]) -> bool:
    sstore = pattern.get("sstore_profile") or {}
    for value in sstore.values():
        try:
            if float(value) > 0:
                return True
        except (TypeError, ValueError):
            continue
    value_bind = pattern.get("value_bind_profile") or {}
    for value in value_bind.values():
        try:
            if float(value) > 0:
                return True
        except (TypeError, ValueError):
            continue
    slot_bind = pattern.get("slot_bind_profile") or {}
    for value in slot_bind.values():
        try:
            if float(value) > 0:
                return True
        except (TypeError, ValueError):
            continue
    return False


def _load_erc_rows(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _load_topic0_counts(path: Path) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    with path.open(encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            topic0 = (row.get("topic0") or "").strip().lower()
            if not topic0:
                continue
            try:
                counts[topic0] = int(row.get("file_count") or 0)
            except (TypeError, ValueError):
                counts[topic0] = 0
    return counts


def _load_patterns(path: Path) -> Tuple[Dict[str, List[dict]], Dict[str, List[dict]]]:
    by_sig: Dict[str, List[dict]] = {}
    by_topic0: Dict[str, List[dict]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            sig = str(row.get("event_signature") or "").lower()
            if sig:
                by_sig.setdefault(sig, []).append(row)
            topic0 = str(row.get("topic0") or "").lower()
            if topic0:
                by_topic0.setdefault(topic0, []).append(row)
    return by_sig, by_topic0


def _parse_support_min(db_dir: Path) -> int:
    name = db_dir.name
    if "support10" in name:
        return 10
    return 20


def _parse_top_k(db_dir: Path) -> int:
    match = TOPK_RE.search(db_dir.name)
    if match:
        return int(match.group(1))
    return 3


def _iter_db_dirs(root: Path) -> List[Path]:
    return sorted(
        d for d in root.iterdir() if d.is_dir() and d.name.startswith("db")
    )


def _compute_metrics(
    erc_rows: List[Dict[str, str]],
    topic0_counts: Dict[str, int],
    by_sig: Dict[str, List[dict]],
    by_topic0: Dict[str, List[dict]],
    file_count_threshold: int,
) -> Dict[str, object]:
    filtered_rows = []
    for row in erc_rows:
        topic0 = (row.get("topic0") or "").strip().lower()
        if not topic0:
            continue
        if topic0_counts.get(topic0, 0) < file_count_threshold:
            continue
        filtered_rows.append(row)

    erc_total = len(filtered_rows)
    found = 0
    indexed_match_hits = 0
    data_match_hits = 0
    indexed_data_match_hits = 0
    state_match_hits = 0
    state_match_total = 0

    for row in filtered_rows:
        sig = (row.get("event_signature") or "").lower()
        topic0 = (row.get("topic0") or "").lower()
        candidates = by_sig.get(sig) or by_topic0.get(topic0) or []
        if candidates:
            found += 1

        try:
            expected_topics = int(row.get("indexed_count")) + 1
        except (TypeError, ValueError):
            expected_topics = None
        try:
            expected_data = int(row.get("data_count"))
        except (TypeError, ValueError):
            expected_data = None

        indexed_match = False
        data_match = False
        indexed_data_match = False

        for cand in candidates:
            profile = cand.get("param_count_profile") or {}
            topics = _dominant_count(profile.get("topics") or {})
            data = _dominant_count(profile.get("data") or {})
            try:
                topics_val = int(topics) if topics is not None else None
            except ValueError:
                topics_val = None
            try:
                data_val = int(data) if data is not None else None
            except ValueError:
                data_val = None

            if expected_topics is not None and topics_val == expected_topics:
                indexed_match = True
            if expected_data is not None and data_val == expected_data:
                data_match = True
            if (
                expected_topics is not None
                and expected_data is not None
                and topics_val == expected_topics
                and data_val == expected_data
            ):
                indexed_data_match = True

        if indexed_match:
            indexed_match_hits += 1
        if data_match:
            data_match_hits += 1
        if indexed_data_match:
            indexed_data_match_hits += 1

        expected_state = _expected_state_change(row)
        if expected_state is not None:
            state_match_total += 1
            observed_states = {
                _infer_state_change_observed(cand) for cand in candidates
            }
            if expected_state in observed_states:
                state_match_hits += 1

    def rate(hits: int, total: int) -> float:
        if total <= 0:
            return 0.0
        return hits / total * 100

    return {
        "erc_total": erc_total,
        "found": found,
        "found_rate": rate(found, erc_total),
        "indexed_match_hits": indexed_match_hits,
        "indexed_match_total": erc_total,
        "indexed_match_rate": rate(indexed_match_hits, erc_total),
        "data_match_hits": data_match_hits,
        "data_match_total": erc_total,
        "data_match_rate": rate(data_match_hits, erc_total),
        "indexed_data_match_hits": indexed_data_match_hits,
        "indexed_data_match_total": erc_total,
        "indexed_data_match_rate": rate(indexed_data_match_hits, erc_total),
        "state_match_hits": state_match_hits,
        "state_match_total": state_match_total,
        "state_match_rate": rate(state_match_hits, state_match_total),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build experiment design/results tables."
    )
    parser.add_argument(
        "--erc",
        type=Path,
        default=Path("artifacts/erc_events.csv"),
        help="Path to erc_events.csv",
    )
    parser.add_argument(
        "--counts",
        type=Path,
        default=Path("artifacts/out/erc_topic0_file_counts.csv"),
        help="Path to erc_topic0_file_counts.csv",
    )
    parser.add_argument(
        "--out-design",
        type=Path,
        default=Path("artifacts/experiment_design.csv"),
        help="Output path for experiment design CSV",
    )
    parser.add_argument(
        "--out-results",
        type=Path,
        default=Path("artifacts/experiment_results.csv"),
        help="Output path for experiment results CSV",
    )
    parser.add_argument(
        "--out-root",
        type=Path,
        default=Path("artifacts/out"),
        help="Root directory containing db outputs",
    )
    parser.add_argument(
        "--thresholds",
        type=str,
        default="10,20,50",
        help="Comma-separated file_count thresholds",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    thresholds = [int(x.strip()) for x in args.thresholds.split(",") if x.strip()]

    erc_rows = _load_erc_rows(args.erc)
    topic0_counts = _load_topic0_counts(args.counts)
    db_dirs = _iter_db_dirs(args.out_root)

    # Experiment design table
    design_rows = [
        {
            "experiment_id": "primary",
            "support_min": 20,
            "core_support_min": 10,
            "top_k": 3,
            "file_count_threshold": 20,
            "state_rule": "strict",
            "notes": "Main setting for paper results.",
        },
        {
            "experiment_id": "support_sensitivity_low",
            "support_min": 10,
            "core_support_min": 10,
            "top_k": 3,
            "file_count_threshold": 10,
            "state_rule": "strict",
            "notes": "Lower support for coverage sensitivity.",
        },
        {
            "experiment_id": "support_sensitivity_high",
            "support_min": 50,
            "core_support_min": 25,
            "top_k": 3,
            "file_count_threshold": 50,
            "state_rule": "strict",
            "notes": "Higher support for robustness sensitivity.",
        },
        {
            "experiment_id": "topk_sensitivity_low",
            "support_min": 20,
            "core_support_min": 10,
            "top_k": 1,
            "file_count_threshold": 20,
            "state_rule": "strict",
            "notes": "Top-K sensitivity (lower bound).",
        },
        {
            "experiment_id": "topk_sensitivity_high",
            "support_min": 20,
            "core_support_min": 10,
            "top_k": 5,
            "file_count_threshold": 20,
            "state_rule": "strict",
            "notes": "Top-K sensitivity (upper bound).",
        },
    ]

    # Map available db dirs by (support_min, top_k)
    available_map: Dict[Tuple[int, int], str] = {}
    for db_dir in db_dirs:
        support_min = _parse_support_min(db_dir)
        top_k = _parse_top_k(db_dir)
        available_map[(support_min, top_k)] = db_dir.name

    for row in design_rows:
        key = (row["support_min"], row["top_k"])
        row["db_dir"] = available_map.get(key, "")
        row["available"] = "yes" if row["db_dir"] else "no"

    with args.out_design.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "experiment_id",
                "support_min",
                "core_support_min",
                "top_k",
                "file_count_threshold",
                "state_rule",
                "available",
                "db_dir",
                "notes",
            ],
        )
        writer.writeheader()
        writer.writerows(design_rows)

    # Experiment results table
    with args.out_results.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "db_dir",
                "support_min",
                "top_k",
                "file_count_threshold",
                "erc_total",
                "found",
                "found_rate",
                "indexed_match_hits",
                "indexed_match_total",
                "indexed_match_rate",
                "data_match_hits",
                "data_match_total",
                "data_match_rate",
                "indexed_data_match_hits",
                "indexed_data_match_total",
                "indexed_data_match_rate",
                "state_match_hits",
                "state_match_total",
                "state_match_rate",
            ],
        )
        writer.writeheader()

        for db_dir in db_dirs:
            patterns_path = db_dir / "event_patterns.jsonl"
            if not patterns_path.exists():
                continue
            by_sig, by_topic0 = _load_patterns(patterns_path)
            support_min = _parse_support_min(db_dir)
            top_k = _parse_top_k(db_dir)

            for threshold in thresholds:
                metrics = _compute_metrics(
                    erc_rows,
                    topic0_counts,
                    by_sig,
                    by_topic0,
                    threshold,
                )
                writer.writerow(
                    {
                        "db_dir": db_dir.name,
                        "support_min": support_min,
                        "top_k": top_k,
                        "file_count_threshold": threshold,
                        **{
                            key: (
                                f"{value:.1f}%"
                                if key.endswith("_rate")
                                else value
                            )
                            for key, value in metrics.items()
                        },
                    }
                )

    print(f"wrote {args.out_design}")
    print(f"wrote {args.out_results}")


if __name__ == "__main__":
    main()
