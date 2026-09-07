#!/usr/bin/env python3
"""Compare ERC event specs against inferred event patterns."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

_SEGMENT_SPLIT_RE = re.compile(
    r"(?:\u21d4|\u21d2|<->|<=>|=>|&&|\|\||\bAND\b|\bOR\b)", re.IGNORECASE
)


def _load_jsonl(path: Path) -> Iterable[Dict[str, object]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _load_erc_events(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return [row for row in reader]


def _parse_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _best_pattern(patterns: List[Dict[str, object]]) -> Optional[Dict[str, object]]:
    if not patterns:
        return None

    def score(row: Dict[str, object]) -> int:
        tier = row.get("pattern_tier") or "open"
        support = row.get("support") or {}
        return int(support.get(tier, 0))

    return max(patterns, key=score)


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


def _explicit_state_change_flag(row: Dict[str, str]) -> Optional[bool]:
    raw = row.get("state_change_flag")
    if raw is None:
        return None
    return _parse_bool_flag(raw)


def _split_param_names(text: Optional[str]) -> List[str]:
    if not text:
        return []
    parts = [part.strip() for part in text.split(",")]
    return [part for part in parts if part and part != "-"]

def _split_flag_values(text: Optional[str]) -> List[str]:
    if text is None:
        return []
    return [part.strip() for part in text.split(",")]


def _parse_bool_flag(text: str) -> Optional[bool]:
    lowered = text.strip().lower()
    if lowered in {"", "-", "?", "na", "n/a"}:
        return None
    if lowered in {"1", "true", "t", "yes", "y"}:
        return True
    if lowered in {"0", "false", "f", "no", "n"}:
        return False
    return None


def _param_label_map(param_names: List[str], indexed_count: Optional[int]) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    indexed = max(indexed_count or 0, 0)
    for idx, name in enumerate(param_names):
        if not name:
            continue
        if idx < indexed:
            labels[name] = f"topic{idx + 1}"
        else:
            labels[name] = f"data{idx - indexed}"
    return labels


def _contains_param(text: str, name: str) -> bool:
    if not name:
        return False
    pattern = rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])"
    return re.search(pattern, text) is not None


def _assignment_sides(segment: str) -> Optional[Tuple[str, str]]:
    for idx, char in enumerate(segment):
        if char != "=":
            continue
        prev_char = segment[idx - 1] if idx > 0 else ""
        next_char = segment[idx + 1] if idx + 1 < len(segment) else ""
        if prev_char in {"<", ">", "!", "="} or next_char == "=":
            continue
        lhs = segment[:idx].strip()
        rhs = segment[idx + 1 :].strip()
        return (lhs, rhs)
    return None


def _assignment_side_segments(conditions: Optional[str]) -> List[Tuple[str, str]]:
    if not conditions:
        return []
    segments: List[Tuple[str, str]] = []
    for line in conditions.splitlines():
        line = line.strip()
        if not line:
            continue
        for part in _SEGMENT_SPLIT_RE.split(line):
            part = part.strip()
            if not part:
                continue
            sides = _assignment_sides(part)
            if sides:
                segments.append(sides)
    return segments


def _expected_state_bind_sets(
    row: Dict[str, str],
) -> Tuple[Optional[Set[str]], Optional[Set[str]]]:
    explicit_labels = _split_param_names(row.get("state_bind_labels"))
    if explicit_labels:
        return set(explicit_labels), set()

    param_names = _split_param_names(row.get("param_names"))
    if not param_names:
        return None, None

    label_map = _param_label_map(param_names, _parse_int(row.get("indexed_count")))

    flags_raw = _split_flag_values(row.get("state_bind_flags"))
    if flags_raw and not any(flag.strip() for flag in flags_raw):
        flags_raw = []
    if flags_raw:
        parsed_flags: List[Optional[bool]] = []
        invalid = False
        allowed = {
            "",
            "-",
            "?",
            "na",
            "n/a",
            "1",
            "true",
            "t",
            "yes",
            "y",
            "0",
            "false",
            "f",
            "no",
            "n",
        }
        for flag in flags_raw:
            if flag.strip().lower() not in allowed:
                invalid = True
                break
            parsed_flags.append(_parse_bool_flag(flag))
        if invalid or len(parsed_flags) != len(param_names):
            return None, None
        expected = {
            label_map.get(param_names[idx])
            for idx, flag in enumerate(parsed_flags)
            if flag is True and label_map.get(param_names[idx])
        }
        forbidden = {
            label_map.get(param_names[idx])
            for idx, flag in enumerate(parsed_flags)
            if flag is False and label_map.get(param_names[idx])
        }
        return expected or set(), forbidden or set()

    explicit_params = _split_param_names(row.get("state_bind_params"))
    if explicit_params:
        labels = {label_map.get(name) for name in explicit_params if label_map.get(name)}
        return labels or None, set()

    side_segments = _assignment_side_segments(row.get("Conditions"))
    if not side_segments:
        return None, None

    lowered_map = {name.lower(): name for name in param_names}
    expected: Set[str] = set()
    for lhs, rhs in side_segments:
        lhs_lower = lhs.lower()
        rhs_lower = rhs.lower()
        for name_lower, original in lowered_map.items():
            if _contains_param(lhs_lower, name_lower) or _contains_param(rhs_lower, name_lower):
                label = label_map.get(original)
                if label:
                    expected.add(label)
    return expected or None, set()


def _pattern_state_bind_labels(pattern: Dict[str, object], min_prob: float) -> Set[str]:
    labels: Set[str] = set()
    for profile in (
        pattern.get("value_bind_profile") or {},
        pattern.get("slot_bind_profile") or {},
        pattern.get("sload_bind_profile") or {},
    ):
        for label, prob in profile.items():
            label_text = str(label)
            if label_text in {"bind_any_topic", "bind_any_data"}:
                continue
            if not (label_text.startswith("topic") or label_text.startswith("data")):
                continue
            try:
                value = float(prob)
            except (TypeError, ValueError):
                continue
            if value >= min_prob:
                labels.add(label_text)
    return labels


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


def _infer_state_change_observed_function(pattern: Optional[Dict[str, object]]) -> Optional[bool]:
    if not pattern:
        return None
    sstore = pattern.get("sstore_profile") or {}
    for value in sstore.values():
        try:
            if float(value) > 0:
                return True
        except (TypeError, ValueError):
            continue
    return False


def _candidate_param_counts(patterns: Iterable[Dict[str, object]]) -> List[Tuple[Optional[str], Optional[str]]]:
    counts: List[Tuple[Optional[str], Optional[str]]] = []
    for pattern in patterns:
        param_profile = pattern.get("param_count_profile") or {}
        topics = _dominant_count(param_profile.get("topics") or {})
        data = _dominant_count(param_profile.get("data") or {})
        counts.append((topics, data))
    return counts


def _split_trigger_functions(text: Optional[str]) -> List[str]:
    if not text:
        return []
    parts = [part.strip() for part in text.split(",") if part.strip()]
    return [part.lower() for part in parts]


def _contract_id_for_tac(tac_path: Path) -> str:
    return hashlib.sha256(tac_path.read_bytes()).hexdigest()


def _find_contract_dirs(tac_root: Path, needed_ids: Set[str]) -> Dict[str, Path]:
    found: Dict[str, Path] = {}
    remaining = set(needed_ids)
    for tac_path in tac_root.rglob("contract.tac"):
        if not remaining:
            break
        contract_id = _contract_id_for_tac(tac_path)
        if contract_id in remaining:
            found[contract_id] = tac_path.parent
            remaining.remove(contract_id)
    return found


def _read_tab_rows(path: Path) -> List[Tuple[str, str]]:
    if not path.exists():
        return []
    rows: List[Tuple[str, str]] = []
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle, delimiter="\t")
        for row in reader:
            if len(row) < 2:
                continue
            rows.append((row[0].strip(), row[1].strip()))
    return rows


def _load_function_names(facts_dir: Path) -> Dict[str, str]:
    names: Dict[str, str] = {}
    name_path = facts_dir / "HighLevelFunctionName.csv"
    selector_path = facts_dir / "PublicFunction.csv"
    for func_id, name in _read_tab_rows(name_path):
        if name:
            names[func_id] = name
    for func_id, selector in _read_tab_rows(selector_path):
        if func_id not in names and selector:
            names[func_id] = selector
    return names


def _base_function_name(name: str) -> str:
    if not name:
        return ""
    return name.split("(", 1)[0].strip().lower()


def _resolve_function_calls(
    examples: List[Dict[str, str]],
    contract_dirs: Dict[str, Path],
    name_cache: Dict[Path, Dict[str, str]],
) -> List[str]:
    observed: List[str] = []
    for example in examples:
        contract_id = example.get("contract_id")
        function_id = example.get("function_id")
        if not contract_id or not function_id:
            continue
        facts_dir = contract_dirs.get(contract_id)
        if not facts_dir:
            continue
        if facts_dir not in name_cache:
            name_cache[facts_dir] = _load_function_names(facts_dir)
        fn_name = name_cache[facts_dir].get(function_id, "")
        base = _base_function_name(fn_name)
        if base and base not in observed:
            observed.append(base)
    return observed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare ERC event specs against inferred event patterns."
    )
    parser.add_argument(
        "--patterns",
        type=Path,
        default=Path("artifacts/out/db/event_patterns.jsonl"),
        help="Path to event_patterns.jsonl",
    )
    parser.add_argument(
        "--erc",
        type=Path,
        default=Path("artifacts/erc_events.csv"),
        help="Path to erc_events.csv",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("artifacts/out/db/erc_compare.csv"),
        help="Output CSV path",
    )
    parser.add_argument(
        "--tac-root",
        type=Path,
        default=None,
        help="TAC root for resolving function names (optional, can be slow).",
    )
    parser.add_argument(
        "--state-param-min",
        type=float,
        default=0.7,
        help="Minimum probability to treat a parameter as state-bound.",
    )
    parser.add_argument(
        "--state-param-ignore",
        action="store_true",
        help="Skip parameter-level state binding comparisons.",
    )
    parser.add_argument(
        "--state-change-unknown",
        choices=("presence", "function", "skip"),
        default="presence",
        help=(
            "How to handle unknown state-change expectations: "
            "presence=match if any candidate exists; "
            "function=use function-level SSTORE; "
            "skip=leave match empty."
        ),
    )
    parser.add_argument(
        "--functions",
        type=Path,
        default=None,
        help="Path to function_patterns.jsonl (used for function-level fallback).",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    erc_rows = _load_erc_events(args.erc)
    patterns = list(_load_jsonl(args.patterns))

    patterns_by_sig: Dict[str, List[Dict[str, object]]] = {}
    patterns_by_topic0: Dict[str, List[Dict[str, object]]] = {}
    for row in patterns:
        sig = str(row.get("event_signature") or "").lower()
        if sig:
            patterns_by_sig.setdefault(sig, []).append(row)
        topic0 = str(row.get("topic0") or "").lower()
        if topic0:
            patterns_by_topic0.setdefault(topic0, []).append(row)

    function_patterns_by_cluster: Dict[str, Dict[str, object]] = {}
    if args.state_change_unknown == "function":
        functions_path = args.functions or args.patterns.with_name("function_patterns.jsonl")
        if not functions_path.exists():
            raise SystemExit(
                f"function_patterns.jsonl not found at {functions_path} (set --functions)"
            )
        for row in _load_jsonl(functions_path):
            cluster_id = row.get("cluster_id")
            if cluster_id:
                function_patterns_by_cluster[str(cluster_id)] = row

    contract_dirs: Dict[str, Path] = {}
    name_cache: Dict[Path, Dict[str, str]] = {}
    if args.tac_root:
        needed_ids: Set[str] = set()
        for row in patterns:
            for example in row.get("examples") or []:
                contract_id = example.get("contract_id")
                if contract_id:
                    needed_ids.add(contract_id)
        contract_dirs = _find_contract_dirs(args.tac_root, needed_ids)

    fieldnames = [
        "erc_id",
        "erc_title",
        "event_name",
        "event_signature",
        "topic0",
        "expected_indexed",
        "expected_data",
        "pattern_topics",
        "pattern_data",
        "indexed_match",
        "data_match",
        "state_change_expected",
        "state_change_observed",
        "state_change_observed_fn",
        "state_change_match",
        "state_param_expected",
        "state_param_forbidden",
        "state_param_observed",
        "state_param_missing",
        "state_param_violations",
        "state_param_match",
        "function_call_expected",
        "function_call_observed",
        "function_call_match",
        "pattern_tier",
        "pattern_support",
        "cluster_id",
        "pattern_count",
        "found",
    ]

    with args.out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()

        for row in erc_rows:
            event_sig = (row.get("event_signature") or "").lower()
            topic0 = (row.get("topic0") or "").lower()
            candidates = patterns_by_sig.get(event_sig) or patterns_by_topic0.get(topic0) or []
            pattern = _best_pattern(candidates)

            expected_indexed = _parse_int(row.get("indexed_count"))
            expected_data = _parse_int(row.get("data_count"))
            expected_topics = expected_indexed + 1 if expected_indexed is not None else None

            pattern_topics = None
            pattern_data = None
            pattern_tier = None
            pattern_support = None
            cluster_id = None
            state_change_observed = None
            state_change_observed_fn = None
            function_calls_observed: List[str] = []
            state_param_observed: Set[str] = set()

            if pattern:
                param_profile = pattern.get("param_count_profile") or {}
                pattern_topics = _dominant_count(param_profile.get("topics") or {})
                pattern_data = _dominant_count(param_profile.get("data") or {})
                pattern_tier = pattern.get("pattern_tier")
                support = pattern.get("support") or {}
                pattern_support = support.get(pattern_tier) if pattern_tier else None
                cluster_id = pattern.get("cluster_id")
                state_change_observed = _infer_state_change_observed(pattern)
                state_param_observed = _pattern_state_bind_labels(
                    pattern, args.state_param_min
                )
                if contract_dirs:
                    function_calls_observed = _resolve_function_calls(
                        pattern.get("examples") or [],
                        contract_dirs,
                        name_cache,
                    )
            if function_patterns_by_cluster:
                observed_states_fn: Set[bool] = set()
                for candidate in candidates:
                    cluster = candidate.get("cluster_id")
                    fn_pattern = (
                        function_patterns_by_cluster.get(str(cluster)) if cluster else None
                    )
                    observed = _infer_state_change_observed_function(fn_pattern)
                    if observed is not None:
                        observed_states_fn.add(observed)
                if observed_states_fn:
                    state_change_observed_fn = True in observed_states_fn

            candidate_counts = _candidate_param_counts(candidates)
            indexed_match = None
            if expected_topics is not None:
                indexed_match = any(
                    expected_topics == _parse_int(topics)
                    for topics, _ in candidate_counts
                    if topics is not None
                )

            data_match = None
            if expected_data is not None:
                data_match = any(
                    expected_data == _parse_int(data)
                    for _, data in candidate_counts
                    if data is not None
                )

            explicit_state = _explicit_state_change_flag(row)
            state_change_expected = (
                explicit_state
                if explicit_state is not None
                else _infer_state_change_expected(row.get("Conditions"))
            )
            state_change_match = None
            if state_change_expected is None:
                if args.state_change_unknown == "function":
                    state_change_match = state_change_observed_fn
                elif args.state_change_unknown == "skip":
                    state_change_match = None
                else:
                    state_change_match = bool(candidates)
            elif candidates:
                observed_states = {
                    _infer_state_change_observed(candidate) for candidate in candidates
                }
                state_change_match = state_change_expected in observed_states
            else:
                state_change_match = False

            state_param_expected, state_param_forbidden = _expected_state_bind_sets(row)
            state_param_match = None
            state_param_missing: List[str] = []
            state_param_violations: List[str] = []
            if args.state_param_ignore:
                state_param_expected = None
                state_param_forbidden = None
            else:
                if state_param_expected is None and not state_param_forbidden:
                    state_param_match = None
                elif candidates:
                    state_param_match = any(
                        (state_param_expected or set())
                        <= _pattern_state_bind_labels(candidate, args.state_param_min)
                        and not (
                            state_param_forbidden
                            and state_param_forbidden
                            & _pattern_state_bind_labels(candidate, args.state_param_min)
                        )
                        for candidate in candidates
                    )
                else:
                    state_param_match = False

                observed_set = state_param_observed if pattern else set()
                if state_param_expected:
                    state_param_missing = sorted(state_param_expected - observed_set)
                if state_param_forbidden:
                    state_param_violations = sorted(state_param_forbidden & observed_set)

            expected_calls = _split_trigger_functions(row.get("trigger_functions"))
            function_call_match = None
            if expected_calls:
                observed_calls: List[str] = []
                if contract_dirs and candidates:
                    for candidate in candidates:
                        observed_calls.extend(
                            _resolve_function_calls(
                                candidate.get("examples") or [],
                                contract_dirs,
                                name_cache,
                            )
                        )
                else:
                    observed_calls = function_calls_observed
                if observed_calls:
                    function_call_match = bool(set(expected_calls) & set(observed_calls))

            writer.writerow(
                {
                    "erc_id": row.get("erc_id"),
                    "erc_title": row.get("erc_title"),
                    "event_name": row.get("event_name"),
                    "event_signature": row.get("event_signature"),
                    "topic0": row.get("topic0"),
                    "expected_indexed": expected_indexed,
                    "expected_data": expected_data,
                    "pattern_topics": pattern_topics,
                    "pattern_data": pattern_data,
                    "indexed_match": indexed_match,
                    "data_match": data_match,
                    "state_change_expected": state_change_expected,
                    "state_change_observed": state_change_observed,
                    "state_change_observed_fn": state_change_observed_fn,
                    "state_change_match": state_change_match,
                    "state_param_expected": ";".join(sorted(state_param_expected or [])),
                    "state_param_forbidden": ";".join(sorted(state_param_forbidden or [])),
                    "state_param_observed": ";".join(sorted(state_param_observed or [])),
                    "state_param_missing": ";".join(state_param_missing),
                    "state_param_violations": ";".join(state_param_violations),
                    "state_param_match": state_param_match,
                    "function_call_expected": ";".join(expected_calls),
                    "function_call_observed": ";".join(function_calls_observed),
                    "function_call_match": function_call_match,
                    "pattern_tier": pattern_tier,
                    "pattern_support": pattern_support,
                    "cluster_id": cluster_id,
                    "pattern_count": len(candidates),
                    "found": bool(pattern),
                }
            )


if __name__ == "__main__":
    main()
