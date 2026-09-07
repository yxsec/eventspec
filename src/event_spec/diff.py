"""Differential checks using the empirical event spec database."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

from .extract import extract_contract
from .signature import build_function_signature
from .utils import (
    clamp_prob,
    ensure_dir,
    jaccard,
    js_similarity,
    load_config,
    normalize_dist,
    read_jsonl,
    wilson_width,
)

CATEGORY_MAP = {
    "missing_event": "event_emission_mismatch",
    "no_event_emission": "event_emission_mismatch",
    "over_emit_event": "event_emission_mismatch",
    "over_emit_total": "event_emission_mismatch",
    "unexpected_event": "event_emission_mismatch",
    "unexpected_shape": "event_parameter_mismatch",
    "unindexed_param": "event_parameter_mismatch",
    "param_source_mismatch": "event_parameter_mismatch",
    "param_literal_mismatch": "event_parameter_mismatch",
    "param_arg_mismatch": "event_parameter_mismatch",
    "guard_gap": "unauthorized_event_emission",
    "guard_gap_warning": "unauthorized_event_emission_warning",
    "sstore_mismatch": "state_event_mismatch",
    "sstore_param_mismatch": "state_event_mismatch",
    "arg_param_state_gap": "state_event_mismatch",
    "equality_anomaly": "event_collision",
}

_NON_VIEW_OPS = {
    "CALL",
    "CALLCODE",
    "CREATE",
    "CREATE2",
    "DELEGATECALL",
    "LOG0",
    "LOG1",
    "LOG2",
    "LOG3",
    "LOG4",
    "SELFDESTRUCT",
    "SSTORE",
}

_SKIP_FUNCTION_IDS = {"__function_selector__"}
_APPROVAL_TOPIC0 = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"


def _filter_findings(findings: List[Dict[str, object]]) -> List[Dict[str, object]]:
    if not findings:
        return findings
    return [
        item for item in findings if item.get("function_id") not in _SKIP_FUNCTION_IDS
    ]


def _guard_gap_function_id(
    obs: Dict[str, object]
) -> Tuple[object, Dict[str, object]]:
    entrypoint_ids = [str(item) for item in (obs.get("entrypoint_ids") or []) if item]
    if not entrypoint_ids:
        return obs.get("function_id"), {}
    entrypoint_ids = sorted(dict.fromkeys(entrypoint_ids))
    candidate_ids = [item for item in entrypoint_ids if item not in _SKIP_FUNCTION_IDS]
    function_id = candidate_ids[0] if candidate_ids else entrypoint_ids[0]
    evidence = {
        "entrypoint_ids": entrypoint_ids,
        "callee_function_id": obs.get("function_id"),
    }
    return function_id, evidence


def _with_category(payload: Dict[str, object]) -> Dict[str, object]:
    category = CATEGORY_MAP.get(payload.get("type"), "other")
    payload["category"] = category
    payload["subcategory"] = payload.get("type")
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run differential event checks for a target contract."
    )
    parser.add_argument("--tac", required=True, type=Path, help="Path to contract.tac")
    parser.add_argument("--db", required=False, type=Path, help="Event spec database")
    parser.add_argument("--out", required=True, type=Path, help="Output findings JSON")
    parser.add_argument("--config", required=False, help="Path to config JSON")
    parser.add_argument("--symbolic", action="store_true", help="Enable Greed equality checks")
    parser.add_argument(
        "--symbolic-eq-constant-only",
        action="store_true",
        help="Only compare equalities where at least one operand is provably constant (symbolic mode only).",
    )
    parser.add_argument(
        "--symbolic-log-limit",
        type=int,
        default=2,
        help=(
            "Max repeated logs per topic0/signature to slice (symbolic mode only). "
            "0 means no limit."
        ),
    )
    parser.add_argument(
        "--target-only",
        action="store_true",
        help="Only run target-only equality collision checks (skip pattern comparisons).",
    )
    parser.add_argument("--timeout", type=int, default=15, help="Greed solver timeout (seconds)")
    return parser


def _pattern_support(pattern: Dict[str, object]) -> int:
    tier = pattern.get("pattern_tier", "open")
    support = pattern.get("support", {}) or {}
    return int(support.get(tier, 0))


def _non_view_ops(function_row: Dict[str, object]) -> List[str]:
    opcode_bow = function_row.get("opcode_bow", {}) or {}
    matches = {
        str(op).upper()
        for op, count in opcode_bow.items()
        if int(count or 0) > 0 and str(op).upper() in _NON_VIEW_OPS
    }
    return sorted(matches)


def _direct_no_event_findings(function_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    for function_row in function_rows:
        observed_total = int(function_row.get("log_count_total", 0) or 0)
        if observed_total != 0:
            continue
        has_state_change = bool(function_row.get("has_state_change"))
        non_view_ops = _non_view_ops(function_row)
        if not has_state_change and not non_view_ops:
            continue
        severity = "medium" if has_state_change else "low"
        findings.append(
            _with_category(
                {
                    "type": "no_event_emission",
                    "topic0": None,
                    "function_id": function_row.get("function_id"),
                    "severity": severity,
                    "score": 0.0,
                    "evidence": {
                        "observed_count": observed_total,
                        "has_state_change": has_state_change,
                        "non_view_ops": non_view_ops,
                    },
                }
            )
        )
    return findings


def _target_only_collision_findings(
    equalities: List[Dict[str, object]],
    *,
    constant_only: bool,
) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    if not equalities:
        return findings
    if constant_only:
        collisions: Dict[Tuple[str, str, str], set[str]] = defaultdict(set)
        for row in equalities:
            topic0 = row.get("topic0")
            label = row.get("label")
            status = row.get("status")
            if not topic0 or not label or status != "possible":
                continue
            if not label.startswith("data"):
                continue
            if not row.get("const_a") or not row.get("const_b"):
                continue
            value_a = row.get("value_a")
            value_b = row.get("value_b")
            if not value_a or not value_b or value_a != value_b:
                continue
            fn_a = row.get("function_a")
            fn_b = row.get("function_b")
            if not fn_a or not fn_b or fn_a == fn_b:
                continue
            collisions[(topic0, label, value_a)].update({fn_a, fn_b})
        for (topic0, label, value), functions in collisions.items():
            if len(functions) < 2:
                continue
            fn_list = sorted(functions)
            findings.append(
                _with_category(
                    {
                        "type": "equality_anomaly",
                        "topic0": topic0,
                        "function_id": fn_list[0],
                        "severity": "medium",
                        "score": 1.0,
                        "evidence": {
                            "mode": "target_only_constant",
                            "label": label,
                            "constant_value": value,
                            "functions": fn_list,
                            "function_count": len(fn_list),
                        },
                    }
                )
            )
    else:
        collisions: Dict[Tuple[str, str], set[str]] = defaultdict(set)
        for row in equalities:
            topic0 = row.get("topic0")
            label = row.get("label")
            status = row.get("status")
            if not topic0 or not label or status != "possible":
                continue
            if not label.startswith("data"):
                continue
            fn_a = row.get("function_a")
            fn_b = row.get("function_b")
            if not fn_a or not fn_b or fn_a == fn_b:
                continue
            collisions[(topic0, label)].update({fn_a, fn_b})
        for (topic0, label), functions in collisions.items():
            if len(functions) < 2:
                continue
            fn_list = sorted(functions)
            findings.append(
                _with_category(
                    {
                        "type": "equality_anomaly",
                        "topic0": topic0,
                        "function_id": fn_list[0],
                        "severity": "medium",
                        "score": 1.0,
                        "evidence": {
                            "mode": "target_only_possible",
                            "label": label,
                            "functions": fn_list,
                            "function_count": len(fn_list),
                        },
                    }
                )
            )
    return findings


def _build_function_features(
    function_rows: List[Dict[str, object]],
    obs_rows: List[Dict[str, object]],
) -> Dict[str, Dict[str, Counter]]:
    features: Dict[str, Dict[str, Counter]] = {}
    for row in function_rows:
        fn_id = row.get("function_id")
        if not fn_id:
            continue
        features[fn_id] = {
            "dep_counts": Counter(),
            "source_counts": Counter(),
            "topic_counts": Counter(),
            "data_counts": Counter(),
        }
    for obs in obs_rows:
        fn_id = obs.get("function_id")
        if not fn_id:
            continue
        entry = features.setdefault(
            fn_id,
            {
                "dep_counts": Counter(),
                "source_counts": Counter(),
                "topic_counts": Counter(),
                "data_counts": Counter(),
            },
        )
        for operand in obs.get("operands", []) or []:
            for dep in operand.get("dep_kinds", []) or []:
                entry["dep_counts"][dep] += 1
            for src in operand.get("source_kinds", []) or []:
                entry["source_counts"][src] += 1
        counts = obs.get("param_counts", {}) or {}
        entry["topic_counts"][counts.get("topics", 0)] += 1
        entry["data_counts"][counts.get("data", 0)] += 1
    return features


def _cluster_ids_by_function(
    function_rows: List[Dict[str, object]],
    obs_rows: List[Dict[str, object]],
) -> Dict[str, str]:
    features = _build_function_features(function_rows, obs_rows)
    cluster_ids: Dict[str, str] = {}
    for row in function_rows:
        fn_id = row.get("function_id")
        if not fn_id:
            continue
        cluster_ids[fn_id] = build_function_signature(row, features.get(fn_id, {}))
    return cluster_ids


def _sim_indexed(obs_labels: set[str], pattern: Dict[str, object], support: int, alpha: float) -> float:
    profile = pattern.get("indexed_profile", {}) or {}
    if not profile:
        return 0.0
    loglik = 0.0
    count = 0
    for label, p in profile.items():
        prob = clamp_prob(float(p), support, alpha)
        present = label in obs_labels
        loglik += math.log(prob if present else (1.0 - prob))
        count += 1
    if count == 0:
        return 0.0
    avg_log = loglik / count
    return max(0.0, min(1.0, math.exp(avg_log)))


def _prob_from_profile(profile: Dict[str, float], count: int, support: int, alpha: float) -> float:
    key = str(count)
    p = float(profile.get(key, 0.0))
    return clamp_prob(p, support, alpha)


def _sim_param_count(obs_counts: Dict[str, int], pattern: Dict[str, object], support: int, alpha: float) -> float:
    profile = pattern.get("param_count_profile", {}) or {}
    topics_profile = profile.get("topics", {}) or {}
    data_profile = profile.get("data", {}) or {}
    topics_prob = _prob_from_profile(topics_profile, obs_counts.get("topics", 0), support, alpha)
    data_prob = _prob_from_profile(data_profile, obs_counts.get("data", 0), support, alpha)
    return max(0.0, min(1.0, 0.5 * (topics_prob + data_prob)))


def _label_distributions(operands: List[Dict[str, object]]) -> tuple[Dict[str, Dict[str, float]], Dict[str, Dict[str, float]]]:
    source_counts: Dict[str, Counter[str]] = defaultdict(Counter)
    dep_counts: Dict[str, Counter[str]] = defaultdict(Counter)
    for operand in operands:
        label = operand.get("label")
        if not label:
            continue
        for src in operand.get("source_kinds", []) or []:
            source_counts[label][src] += 1
        for dep in operand.get("dep_kinds", []) or []:
            dep_counts[label][dep] += 1
    source_dist = {label: normalize_dist(counts) for label, counts in source_counts.items()}
    dep_dist = {label: normalize_dist(counts) for label, counts in dep_counts.items()}
    return source_dist, dep_dist


def _avg_label_similarity(
    obs_dist: Dict[str, Dict[str, float]],
    pattern_profiles: Dict[str, Dict[str, object]],
    key: str,
    *,
    alpha: float,
) -> float:
    sims: List[float] = []
    for label, dist in obs_dist.items():
        pattern = pattern_profiles.get(label, {})
        profile = pattern.get(key)
        if not profile:
            continue
        sims.append(js_similarity(dist, profile, alpha=alpha))
    if not sims:
        return 0.0
    return sum(sims) / len(sims)


def _sim_sstore(function_row: Dict[str, object], pattern: Dict[str, object]) -> float:
    sstore_kinds = set(function_row.get("sstore_kinds", []) or [])
    profile = pattern.get("sstore_profile", {}) or {}
    pattern_kinds = {kind for kind, prob in profile.items() if prob > 0}
    return jaccard(sstore_kinds, pattern_kinds)


def _sim_guard(function_row: Dict[str, object], pattern: Dict[str, object]) -> float:
    guards = set(function_row.get("guard_categories", []) or [])
    profile = pattern.get("guard_profile", {}) or {}
    pattern_guards = {cat for cat, prob in profile.items() if prob > 0}
    return jaccard(guards, pattern_guards)


def _sim_ops(function_row: Dict[str, object], pattern: Dict[str, object]) -> float:
    opcode_bow = function_row.get("opcode_bow", {}) or {}
    function_ops = {op for op, count in opcode_bow.items() if count >= 3}
    profile = pattern.get("opcode_profile", {}) or {}
    pattern_ops = {op for op, prob in profile.items() if prob > 0}
    return jaccard(function_ops, pattern_ops)


def _event_similarity(
    obs: Dict[str, object],
    function_row: Dict[str, object],
    pattern: Dict[str, object],
    support: int,
    alpha: float,
) -> float:
    obs_labels = {op.get("label") for op in obs.get("operands", []) or [] if op.get("label")}
    sim_indexed = _sim_indexed(obs_labels, pattern, support, alpha)
    sim_param = _sim_param_count(obs.get("param_counts", {}) or {}, pattern, support, alpha)
    src_dist, dep_dist = _label_distributions(obs.get("operands", []) or [])
    sim_sources = _avg_label_similarity(
        src_dist,
        pattern.get("operand_profiles", {}) or {},
        "source",
        alpha=alpha,
    )
    sim_deps = _avg_label_similarity(
        dep_dist,
        pattern.get("operand_profiles", {}) or {},
        "deps",
        alpha=alpha,
    )
    sim_sstore = _sim_sstore(function_row, pattern)
    sim_guard = _sim_guard(function_row, pattern)

    weight_sum = 1.10
    score = (
        0.30 * sim_indexed
        + 0.10 * sim_param
        + 0.25 * sim_sources
        + 0.20 * sim_deps
        + 0.15 * sim_sstore
        + 0.10 * sim_guard
    ) / weight_sum
    return max(0.0, min(1.0, score))


def _function_similarity(function_row: Dict[str, object], pattern: Dict[str, object]) -> float:
    sim_sstore = _sim_sstore(function_row, pattern)
    sim_guard = _sim_guard(function_row, pattern)
    sim_ops = _sim_ops(function_row, pattern)
    score = 0.45 * sim_sstore + 0.35 * sim_guard + 0.20 * sim_ops
    return max(0.0, min(1.0, score))


def run(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    function_patterns: List[Dict[str, object]] = []
    event_patterns: List[Dict[str, object]] = []
    event_patterns_by_topic: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    if not args.target_only:
        if not args.db:
            raise SystemExit("--db is required unless --target-only is set")
        db_dir: Path = args.db 
        function_patterns_path = db_dir / "function_patterns.jsonl"
        event_patterns_path = db_dir / "event_patterns.jsonl"
        if not function_patterns_path.exists() or not event_patterns_path.exists():
            raise SystemExit(
                "function_patterns.jsonl or event_patterns.jsonl not found in db directory"
            ) # load jsonl

        function_patterns = list(read_jsonl(function_patterns_path))
        event_patterns = list(read_jsonl(event_patterns_path))
        for pattern in event_patterns:
            topic0 = pattern.get("topic0")
            if topic0:
                event_patterns_by_topic[topic0].append(pattern) #event_patterns_by_topic （max tpoc k）

    observations, functions, equalities = extract_contract(
        args.tac,
        "open",
        symbolic=args.symbolic,
        symbolic_eq_constant_only=args.symbolic_eq_constant_only,
        symbolic_log_limit=args.symbolic_log_limit,
        timeout=args.timeout,
    )# extract single smart contract
    obs_rows = [obs.to_dict() for obs in observations]
    function_rows = [fn.to_dict() for fn in functions]
    direct_findings = _direct_no_event_findings(function_rows)
    if args.target_only:
        findings = direct_findings + _target_only_collision_findings(
            equalities, constant_only=args.symbolic_eq_constant_only
        )
        findings = _filter_findings(findings)
        ensure_dir(args.out.parent)
        args.out.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        return
    function_by_id = {row.get("function_id"): row for row in function_rows}
    function_cluster_id = _cluster_ids_by_function(function_rows, obs_rows)

    findings: List[Dict[str, object]] = []
    findings.extend(direct_findings)
    similarity_min = float(config.get("similarity_min", 0.65))
    support_min = int(config.get("support_min", 20))
    indexed_min = float(config.get("indexed_min", 0.8))
    guard_min = float(config.get("guard_min", 0.8))
    sstore_min = float(config.get("sstore_min", 0.7))
    missing_event_min = float(config.get("missing_event_min", 0.9))
    over_emit_min = float(config.get("over_emit_min", 0.9))
    over_emit_total_min = float(config.get("over_emit_total_min", 0.9))
    unexpected_event_max = float(config.get("unexpected_event_max", 0.1))
    shape_min = float(config.get("shape_min", 0.8))
    param_source_min = float(config.get("param_source_min", 0.8))
    param_arg_min = float(config.get("param_arg_min", 0.8))
    literal_min = float(config.get("literal_min", 0.8))
    max_conf_width = float(config.get("max_conf_width", 0.2))
    alpha = float(config.get("alpha", 1.0))
    arg_state_bind_required = config.get("arg_state_bind_required", True)

    for obs in obs_rows:
        topic0 = obs.get("topic0")
        if not topic0:
            continue
        patterns = event_patterns_by_topic.get(topic0, [])
        if not patterns:
            continue
        function_row = function_by_id.get(obs.get("function_id"))
        if not function_row:
            continue
        best_pattern = None
        best_score = 0.0
        for pattern in patterns:
            support = _pattern_support(pattern)
            score = _event_similarity(obs, function_row, pattern, support, alpha)
            if score > best_score:
                best_score = score
                best_pattern = pattern
        if not best_pattern or best_score < similarity_min:
            continue

        support = _pattern_support(best_pattern)
        indexed_profile = best_pattern.get("indexed_profile", {}) or {}
        obs_labels = {op.get("label") for op in obs.get("operands", []) or [] if op.get("label")}
        operand_profiles = best_pattern.get("operand_profiles", {}) or {}
        for label, prob in indexed_profile.items():
            if not label.startswith("topic") or label == "topic0":
                continue
            p = float(prob)
            if p < indexed_min:
                continue
            if label in obs_labels:
                continue
            if support < support_min:
                continue
            if wilson_width(p, support) > max_conf_width:
                continue
            findings.append(
                _with_category(
                    {
                    "type": "unindexed_param",
                    "topic0": topic0,
                    "function_id": obs.get("function_id"),
                    "severity": "medium" if best_pattern.get("pattern_tier") == "core" else "low",
                    "score": best_score,
                    "evidence": {
                        "pattern_id": best_pattern.get("cluster_id"),
                        "support": best_pattern.get("support"),
                        "pattern_tier": best_pattern.get("pattern_tier"),
                        "label": label,
                        "indexed_prob": p,
                    },
                    }
                )
            )

        guard_summary = obs.get("guard_summary")
        if guard_summary is None:
            guard_summary = function_row.get("guard_categories", []) or []
        check_sources = obs.get("check_sources") or []
        has_any_checks = bool(guard_summary) or bool(check_sources)
        guard_gap_emitted = False
        guard_severity = "medium" if best_pattern.get("pattern_tier") == "core" else "low"
        guard_profile = best_pattern.get("guard_profile", {}) or {}
        guard_function_id, guard_evidence = _guard_gap_function_id(obs)
        expected_guards: List[str] = []
        for category, prob in guard_profile.items():
            if category == "interprocedural":
                continue
            p = float(prob)
            if p < guard_min:
                continue
            if support < support_min:
                continue
            if wilson_width(p, support) > max_conf_width:
                continue
            expected_guards.append(category)
        observed_guards = [
            cat
            for cat in (guard_summary or [])
            if cat and cat != "interprocedural"
        ]
        expected_set = set(expected_guards)
        observed_set = set(observed_guards)
        if expected_guards:
            if has_any_checks:
                if not expected_set.issubset(observed_set):
                    evidence = {
                        "pattern_id": best_pattern.get("cluster_id"),
                        "support": best_pattern.get("support"),
                        "pattern_tier": best_pattern.get("pattern_tier"),
                        "guard_expected": expected_guards,
                        "guard_observed": observed_guards,
                        "check_sources": list(check_sources),
                        "mode": "guard_mismatch",
                    }
                    if guard_evidence:
                        evidence.update(guard_evidence)
                    findings.append(
                        _with_category(
                            {
                                "type": "guard_gap_warning",
                                "topic0": topic0,
                                "function_id": guard_function_id,
                                "severity": "warning",
                                "score": best_score,
                                "evidence": evidence,
                            }
                        )
                    )
            else:
                evidence = {
                    "pattern_id": best_pattern.get("cluster_id"),
                    "support": best_pattern.get("support"),
                    "pattern_tier": best_pattern.get("pattern_tier"),
                    "guard_expected": expected_guards,
                    "guard_observed": observed_guards,
                    "mode": "no_require",
                }
                if guard_evidence:
                    evidence.update(guard_evidence)
                findings.append(
                    _with_category(
                        {
                            "type": "guard_gap",
                            "topic0": topic0,
                            "function_id": guard_function_id,
                            "severity": guard_severity,
                            "score": best_score,
                            "evidence": evidence,
                        }
                    )
                )
                guard_gap_emitted = True

        if not has_any_checks and not guard_gap_emitted:
            evidence = {
                "mode": "no_checks",
                "guard_summary": list(guard_summary),
                "check_sources": list(check_sources),
            }
            if guard_evidence:
                evidence.update(guard_evidence)
            findings.append(
                _with_category(
                    {
                        "type": "guard_gap",
                        "topic0": topic0,
                        "function_id": guard_function_id,
                        "severity": guard_severity,
                        "score": best_score,
                        "evidence": evidence,
                    }
                )
            )

        value_profile = best_pattern.get("value_bind_profile", {}) or {}
        slot_profile = best_pattern.get("slot_bind_profile", {}) or {}
        value_bindings = obs.get("value_bindings", {}) or {}
        bind_labels_value = value_bindings.get("bind_labels") or {}
        bind_labels_slot = value_bindings.get("bind_labels_slot") or {}
        bind_labels_sload = value_bindings.get("bind_labels_sload") or {}
        bind_any_data_value = bool(value_bindings.get("bind_any_data"))
        bind_any_data_slot = bool(value_bindings.get("bind_any_data_slot"))
        bind_any_data = bind_any_data_value or bind_any_data_slot
        bind_prob_value = float(value_profile.get("bind_any_data", 0.0))
        bind_prob_slot = float(slot_profile.get("bind_any_data", 0.0))
        sstore_profile = best_pattern.get("sstore_profile", {}) or {}
        sstore_dom = any(float(p) >= sstore_min for p in sstore_profile.values())
        bind_expected = bind_prob_value >= sstore_min or bind_prob_slot >= sstore_min
        if bind_expected and not bind_any_data and sstore_dom:
            if support < support_min:
                continue
            if wilson_width(max(bind_prob_value, bind_prob_slot), support) > max_conf_width:
                continue
            findings.append(
                _with_category(
                    {
                    "type": "sstore_mismatch",
                    "topic0": topic0,
                    "function_id": obs.get("function_id"),
                    "severity": "medium" if best_pattern.get("pattern_tier") == "core" else "low",
                    "score": best_score,
                    "evidence": {
                        "pattern_id": best_pattern.get("cluster_id"),
                        "support": best_pattern.get("support"),
                        "pattern_tier": best_pattern.get("pattern_tier"),
                        "bind_any_data": max(bind_prob_value, bind_prob_slot),
                        "bind_any_data_value": bind_prob_value,
                        "bind_any_data_slot": bind_prob_slot,
                    },
                    }
                )
            )
        expected_param_bind: set[str] = set()
        for profile in (value_profile, slot_profile):
            for label, prob in profile.items():
                label_text = str(label)
                if label_text == "topic0":
                    continue
                if not (label_text.startswith("data") or label_text.startswith("topic")):
                    continue
                p = float(prob)
                if p < sstore_min:
                    continue
                if support < support_min:
                    continue
                if wilson_width(p, support) > max_conf_width:
                    continue
                expected_param_bind.add(label_text)
        if expected_param_bind and sstore_dom:
            observed_bound = {
                label
                for label in set(bind_labels_value) | set(bind_labels_slot)
                if str(label).startswith("data") or str(label).startswith("topic")
            }
            observed_labels = {
                op.get("label")
                for op in obs.get("operands", []) or []
                if str(op.get("label", "")).startswith(("data", "topic"))
            }
            missing_params = sorted(expected_param_bind - observed_bound)
            missing_data = [label for label in missing_params if label.startswith("data")]
            missing_topics = [label for label in missing_params if label.startswith("topic")]
            if missing_params:
                findings.append(
                    _with_category(
                        {
                            "type": "sstore_param_mismatch",
                            "topic0": topic0,
                            "function_id": obs.get("function_id"),
                            "severity": "medium"
                            if best_pattern.get("pattern_tier") == "core"
                            else "low",
                            "score": best_score,
                            "evidence": {
                                "pattern_id": best_pattern.get("cluster_id"),
                                "support": best_pattern.get("support"),
                                "pattern_tier": best_pattern.get("pattern_tier"),
                                "expected_param_labels": sorted(expected_param_bind),
                                "observed_param_labels": sorted(observed_labels),
                                "observed_param_bindings": sorted(observed_bound),
                                "observed_value_bindings": sorted(
                                    label
                                    for label in bind_labels_value
                                    if str(label).startswith(("data", "topic"))
                                ),
                                "observed_slot_bindings": sorted(
                                    label
                                    for label in bind_labels_slot
                                    if str(label).startswith(("data", "topic"))
                                ),
                                "observed_sload_bindings": sorted(
                                    label
                                    for label in bind_labels_sload
                                    if str(label).startswith(("data", "topic"))
                                ),
                                "missing_param_bindings": missing_params,
                                "missing_data_bindings": missing_data,
                                "missing_topic_bindings": missing_topics,
                            },
                        }
                    )
                )
        if arg_state_bind_required:
            observed_state_bound = {
                label
                for label in set(bind_labels_value) | set(bind_labels_slot) | set(bind_labels_sload)
                if str(label).startswith(("data", "topic"))
            }
            arg_labels: List[str] = []
            missing_arg_labels: List[str] = []
            for operand in obs.get("operands", []) or []:
                label = str(operand.get("label") or "")
                if not label or label == "topic0":
                    continue
                if not label.startswith(("data", "topic")):
                    continue
                sources = set(operand.get("source_kinds") or [])
                if "ARG" not in sources and "CALLDATA" not in sources:
                    continue
                arg_labels.append(label)
                if label not in observed_state_bound:
                    missing_arg_labels.append(label)
            if missing_arg_labels:
                findings.append(
                    _with_category(
                        {
                            "type": "arg_param_state_gap",
                            "topic0": topic0,
                            "function_id": obs.get("function_id"),
                            "severity": "medium"
                            if best_pattern.get("pattern_tier") == "core"
                            else "low",
                            "score": best_score,
                            "evidence": {
                                "pattern_id": best_pattern.get("cluster_id"),
                                "support": best_pattern.get("support"),
                                "pattern_tier": best_pattern.get("pattern_tier"),
                                "arg_param_labels": sorted(set(arg_labels)),
                                "missing_arg_param_labels": sorted(set(missing_arg_labels)),
                                "observed_state_bindings": sorted(observed_state_bound),
                                "observed_value_bindings": sorted(
                                    label
                                    for label in bind_labels_value
                                    if str(label).startswith(("data", "topic"))
                                ),
                                "observed_slot_bindings": sorted(
                                    label
                                    for label in bind_labels_slot
                                    if str(label).startswith(("data", "topic"))
                                ),
                                "observed_sload_bindings": sorted(
                                    label
                                    for label in bind_labels_sload
                                    if str(label).startswith(("data", "topic"))
                                ),
                            },
                        }
                    )
                )

        for operand in obs.get("operands", []) or []:
            label = operand.get("label")
            if not label or label == "topic0":
                continue
            profile = operand_profiles.get(label)
            if not profile:
                continue
            label_support = int(profile.get("support", support))
            source_profile = profile.get("source", {}) or {}
            # Argument-index evidence is explicitly tested even for a small
            # synthetic profile; source/literal evidence still requires the
            # configured support threshold below.
            profile_has_support = label_support >= support_min
            if not profile_has_support:
                source_profile = {}
            if source_profile:
                try:
                    expected_src, expected_prob = max(
                        source_profile.items(), key=lambda item: float(item[1])
                    )
                except (TypeError, ValueError):
                    expected_src = None
                    expected_prob = 0.0
                expected_prob = float(expected_prob)
                if expected_src == "OTHER":
                    continue
                if (
                    expected_src
                    and expected_prob >= param_source_min
                    and wilson_width(expected_prob, label_support) <= max_conf_width
                ):
                    observed_sources = set(operand.get("source_kinds", []) or [])
                    if expected_src not in observed_sources:
                        findings.append(
                            _with_category(
                                {
                                    "type": "param_source_mismatch",
                                    "topic0": topic0,
                                    "function_id": obs.get("function_id"),
                                    "severity": "medium"
                                    if best_pattern.get("pattern_tier") == "core"
                                    else "low",
                                    "score": best_score,
                                    "evidence": {
                                        "pattern_id": best_pattern.get("cluster_id"),
                                        "support": best_pattern.get("support"),
                                        "pattern_tier": best_pattern.get("pattern_tier"),
                                        "label": label,
                                        "expected_source": expected_src,
                                        "expected_prob": expected_prob,
                                        "label_support": label_support,
                                    },
                                }
                            )
                        )
            literal_profile = profile.get("literal", {}) or {}
            if not profile_has_support:
                literal_profile = {}
            if literal_profile:
                try:
                    expected_literal, expected_prob = max(
                        literal_profile.items(), key=lambda item: float(item[1])
                    )
                except (TypeError, ValueError):
                    expected_literal = None
                    expected_prob = 0.0
                expected_prob = float(expected_prob)
                if (
                    expected_literal
                    and expected_prob >= literal_min
                    and wilson_width(expected_prob, label_support) <= max_conf_width
                ):
                    observed_literal = operand.get("literal_class")
                    observed_sources = set(operand.get("source_kinds", []) or [])
                    if observed_literal != expected_literal:
                        if observed_literal is None and "CONST" in observed_sources:
                            continue
                        findings.append(
                            _with_category(
                                {
                                    "type": "param_literal_mismatch",
                                    "topic0": topic0,
                                    "function_id": obs.get("function_id"),
                                    "severity": "medium"
                                    if best_pattern.get("pattern_tier") == "core"
                                    else "low",
                                    "score": best_score,
                                    "evidence": {
                                        "pattern_id": best_pattern.get("cluster_id"),
                                        "support": best_pattern.get("support"),
                                        "pattern_tier": best_pattern.get("pattern_tier"),
                                        "label": label,
                                        "expected_literal": expected_literal,
                                        "expected_prob": expected_prob,
                                        "observed_literal": observed_literal,
                                        "label_support": label_support,
                                    },
                                }
                            )
                        )
            arg_index_profile = profile.get("arg_index", {}) or {}
            if arg_index_profile:
                try:
                    expected_arg, expected_prob = max(
                        arg_index_profile.items(), key=lambda item: float(item[1])
                    )
                except (TypeError, ValueError):
                    expected_arg = None
                    expected_prob = 0.0
                expected_prob = float(expected_prob)
                expected_arg_str = str(expected_arg) if expected_arg is not None else None
                if (
                    expected_arg_str
                    and expected_arg_str != "unknown"
                    and expected_prob >= param_arg_min
                    and wilson_width(expected_prob, label_support) <= max_conf_width
                ):
                    observed_arg = operand.get("arg_index")
                    if observed_arg is not None and str(observed_arg) != expected_arg_str:
                        observed_sources = set(operand.get("source_kinds", []) or [])
                        if (
                            str(topic0 or "").lower() == _APPROVAL_TOPIC0
                            and label == "data0"
                            and "ARG" in observed_sources
                        ):
                            continue
                        findings.append(
                            _with_category(
                                {
                                    "type": "param_arg_mismatch",
                                    "topic0": topic0,
                                    "function_id": obs.get("function_id"),
                                    "severity": "medium"
                                    if best_pattern.get("pattern_tier") == "core"
                                    else "low",
                                    "score": best_score,
                                    "evidence": {
                                        "pattern_id": best_pattern.get("cluster_id"),
                                        "support": best_pattern.get("support"),
                                        "pattern_tier": best_pattern.get("pattern_tier"),
                                        "label": label,
                                        "expected_arg": expected_arg_str,
                                        "expected_prob": expected_prob,
                                        "observed_arg": observed_arg,
                                        "label_support": label_support,
                                    },
                                }
                            )
                        )

    eq_min = float(config.get("eq_min", 0.6))
    target_eq_counts: Dict[Tuple[str, str, str], Counter[str]] = defaultdict(Counter)
    target_eq_example_fn: Dict[Tuple[str, str, str], str] = {}
    if equalities:
        for row in equalities:
            topic0 = row.get("topic0")
            label = row.get("label")
            status = row.get("status")
            if not topic0 or not label or status not in {"possible", "unsat"}:
                continue
            fn_a = row.get("function_a")
            fn_b = row.get("function_b")
            if not fn_a or not fn_b:
                continue
            cluster_a = function_cluster_id.get(fn_a)
            cluster_b = function_cluster_id.get(fn_b)
            if not cluster_a or cluster_a != cluster_b:
                continue
            key = (topic0, cluster_a, label)
            target_eq_counts[key][status] += 1
            if key not in target_eq_example_fn:
                target_eq_example_fn[key] = fn_a or fn_b or "<global>"
        findings.extend(
            _target_only_collision_findings(
                equalities, constant_only=args.symbolic_eq_constant_only
            )
        )

    for function_row in function_rows:
        best_pattern = None
        best_score = 0.0
        for pattern in function_patterns:
            score = _function_similarity(function_row, pattern)
            if score > best_score:
                best_score = score
                best_pattern = pattern
        if not best_pattern or best_score < similarity_min:
            continue
        support = _pattern_support(best_pattern)
        if support < support_min:
            continue
        expected_events = best_pattern.get("expected_events", {}) or {}
        has_state_change = bool(function_row.get("has_state_change"))
        sstore_profile = best_pattern.get("sstore_profile", {}) or {}
        sstore_dom = any(float(p) >= sstore_min for p in sstore_profile.values())
        if not has_state_change and not sstore_dom:
            continue
        if expected_events:
            for topic0, prob in expected_events.items():
                p = float(prob)
                if p < missing_event_min:
                    continue
                if wilson_width(p, support) > max_conf_width:
                    continue
                if topic0 in (function_row.get("reachable_logs", []) or []):
                    continue
                tier = best_pattern.get("pattern_tier", "open")
                severity = "low" if tier != "core" else ("high" if p >= 0.95 else "medium")
                findings.append(
                    _with_category(
                        {
                        "type": "missing_event",
                        "topic0": topic0,
                        "function_id": function_row.get("function_id"),
                        "severity": severity,
                        "score": best_score,
                        "evidence": {
                            "pattern_id": best_pattern.get("cluster_id"),
                            "support": best_pattern.get("support"),
                            "pattern_tier": tier,
                            "expected_prob": p,
                        },
                        }
                    )
                )

        log_count_profile = best_pattern.get("log_count_profile", {}) or {}
        if log_count_profile:
            try:
                expected_count_str, expected_prob = max(
                    log_count_profile.items(), key=lambda item: float(item[1])
                )
                expected_count = int(expected_count_str)
            except (TypeError, ValueError):
                expected_count = None
                expected_prob = 0.0
            if expected_count is not None:
                observed_total = int(function_row.get("log_count_total", 0) or 0)
                p = float(expected_prob)
                if (
                    observed_total > expected_count
                    and p >= over_emit_total_min
                    and wilson_width(p, support) <= max_conf_width
                ):
                    tier = best_pattern.get("pattern_tier", "open")
                    findings.append(
                        _with_category(
                            {
                            "type": "over_emit_total",
                            "topic0": None,
                            "function_id": function_row.get("function_id"),
                            "severity": "medium" if tier == "core" else "low",
                            "score": best_score,
                            "evidence": {
                                "pattern_id": best_pattern.get("cluster_id"),
                                "support": best_pattern.get("support"),
                                "pattern_tier": tier,
                                "observed_total": observed_total,
                                "expected_total": expected_count,
                                "expected_prob": p,
                            },
                            }
                        )
                    )

        for topic0 in (function_row.get("reachable_logs", []) or []):
            p = float(expected_events.get(topic0, 0.0))
            if p > unexpected_event_max:
                continue
            if wilson_width(p, support) > max_conf_width:
                continue
            tier = best_pattern.get("pattern_tier", "open")
            findings.append(
                _with_category(
                    {
                    "type": "unexpected_event",
                    "topic0": topic0,
                    "function_id": function_row.get("function_id"),
                    "severity": "medium" if tier == "core" else "low",
                    "score": best_score,
                    "evidence": {
                        "pattern_id": best_pattern.get("cluster_id"),
                        "support": best_pattern.get("support"),
                        "pattern_tier": tier,
                        "expected_prob": p,
                    },
                    }
                )
            )

        event_count_profile = best_pattern.get("event_count_profile", {}) or {}
        event_count_support = best_pattern.get("event_count_support", {}) or {}
        log_counts = function_row.get("reachable_log_counts", {}) or {}
        for topic0, observed_count in log_counts.items():
            profile = event_count_profile.get(topic0)
            if not profile:
                continue
            try:
                expected_count_str, expected_prob = max(
                    profile.items(), key=lambda item: float(item[1])
                )
                expected_count = int(expected_count_str)
            except (TypeError, ValueError):
                continue
            p = float(expected_prob)
            if observed_count <= expected_count:
                continue
            support_topic = int(event_count_support.get(topic0, support))
            if support_topic < support_min:
                continue
            if p < over_emit_min:
                continue
            if wilson_width(p, support_topic) > max_conf_width:
                continue
            tier = best_pattern.get("pattern_tier", "open")
            findings.append(
                _with_category(
                    {
                    "type": "over_emit_event",
                    "topic0": topic0,
                    "function_id": function_row.get("function_id"),
                    "severity": "medium" if tier == "core" else "low",
                    "score": best_score,
                    "evidence": {
                        "pattern_id": best_pattern.get("cluster_id"),
                        "support": best_pattern.get("support"),
                        "pattern_tier": tier,
                        "observed_count": observed_count,
                        "expected_count": expected_count,
                        "expected_prob": p,
                        "count_support": support_topic,
                    },
                    }
                )
            )

        log_shape_profile = best_pattern.get("log_shape_profile", {}) or {}
        log_shape_support = best_pattern.get("log_shape_support", {}) or {}
        shape_counts = function_row.get("log_shape_counts", {}) or {}
        for topic0, shapes in shape_counts.items():
            if not isinstance(shapes, dict):
                continue
            profile = log_shape_profile.get(topic0)
            if not profile:
                continue
            try:
                expected_shape, expected_prob = max(
                    profile.items(), key=lambda item: float(item[1])
                )
            except (TypeError, ValueError):
                continue
            expected_prob = float(expected_prob)
            if expected_prob < shape_min:
                continue
            support_topic = int(log_shape_support.get(topic0, 0))
            if support_topic < support_min:
                continue
            for shape, count in shapes.items():
                if shape == expected_shape:
                    continue
                shape_prob = float(profile.get(shape, 0.0))
                if shape_prob > (1.0 - shape_min):
                    continue
                if wilson_width(shape_prob, support_topic) > max_conf_width:
                    continue
                tier = best_pattern.get("pattern_tier", "open")
                findings.append(
                    _with_category(
                        {
                        "type": "unexpected_shape",
                        "topic0": topic0,
                        "function_id": function_row.get("function_id"),
                        "severity": "medium" if tier == "core" else "low",
                        "score": best_score,
                        "evidence": {
                            "pattern_id": best_pattern.get("cluster_id"),
                            "support": best_pattern.get("support"),
                            "pattern_tier": tier,
                            "expected_shape": expected_shape,
                            "expected_prob": expected_prob,
                            "observed_shape": shape,
                            "observed_count": count,
                            "shape_prob": shape_prob,
                            "shape_support": support_topic,
                        },
                        }
                    )
                )

    if equalities:
        for pattern in event_patterns:
            tier = pattern.get("pattern_tier", "open")
            if tier != "core":
                continue
            support = _pattern_support(pattern)
            if support < support_min:
                continue
            topic0 = pattern.get("topic0")
            if not topic0:
                continue
            eq_profile = pattern.get("equality_profile", {}) or {}
            eq_support = pattern.get("equality_support", {}) or {}
            if not eq_profile:
                continue
            for label, prob in eq_profile.items():
                p = float(prob)
                if p < eq_min:
                    if p > (1.0 - eq_min):
                        continue
                key = (topic0, pattern.get("cluster_id"), label)
                counts = target_eq_counts.get(key)
                if not counts:
                    continue
                total = counts.get("possible", 0) + counts.get("unsat", 0)
                if total < 2:
                    continue
                support_label = int(eq_support.get(label, 0))
                if support_label < support_min:
                    continue
                if wilson_width(p, support_label) > max_conf_width:
                    continue
                target_prob = counts.get("possible", 0) / total
                direction = None
                if p >= eq_min and target_prob <= (1.0 - eq_min):
                    direction = "pattern_high_target_low"
                elif p <= (1.0 - eq_min) and target_prob >= eq_min:
                    direction = "pattern_low_target_high"
                if not direction:
                    continue
                fn_id = target_eq_example_fn.get(key, "<global>")
                findings.append(
                    _with_category(
                        {
                        "type": "equality_anomaly",
                        "topic0": topic0,
                        "function_id": fn_id,
                        "severity": "medium",
                        "score": max(p, target_prob),
                        "evidence": {
                            "pattern_id": pattern.get("cluster_id"),
                            "support": pattern.get("support"),
                            "pattern_tier": tier,
                            "label": label,
                            "pattern_prob": p,
                            "pattern_support": support_label,
                            "target_prob": target_prob,
                            "target_counts": dict(counts),
                            "direction": direction,
                        },
                        }
                    )
                )

    findings = _filter_findings(findings)
    ensure_dir(args.out.parent)
    args.out.write_text(json.dumps(findings, indent=2), encoding="utf-8")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
