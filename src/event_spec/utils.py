"""Shared helpers for the event spec pipeline."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List


DEFAULT_CONFIG: Dict[str, Any] = {
    "support_min": 20,
    "core_support_min": 10,
    "similarity_min": 0.65,
    "missing_event_min": 0.9,
    "over_emit_min": 0.9,
    "over_emit_total_min": 0.9,
    "unexpected_event_max": 0.1,
    "shape_min": 0.8,
    "param_source_min": 0.8,
    "param_arg_min": 0.8,
    "literal_min": 0.8,
    "indexed_min": 0.8,
    "guard_min": 0.8,
    "sstore_min": 0.7,
    "eq_min": 0.6,
    "max_conf_width": 0.2,
    "alpha": 1.0,
    "top_k": 3,
}


def load_config(path: str | None) -> Dict[str, Any]:
    if not path:
        return dict(DEFAULT_CONFIG)
    config_path = Path(path)
    if not config_path.exists():
        raise SystemExit(f"Config not found: {config_path}")
    return json.loads(config_path.read_text(encoding="utf-8"))


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            yield json.loads(stripped)


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")


def sha1_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def unique_preserve(items: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def normalize_dist(counts: Dict[str, float]) -> Dict[str, float]:
    total = sum(counts.values())
    if total <= 0:
        return {}
    return {key: value / total for key, value in counts.items()}


def jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    set_a = set(a)
    set_b = set(b)
    if not set_a and not set_b:
        return 1.0
    union = set_a | set_b
    if not union:
        return 0.0
    return len(set_a & set_b) / len(union)


def js_similarity(p: Dict[str, float], q: Dict[str, float], alpha: float = 0.0) -> float:
    if not p and not q:
        return 1.0
    keys = set(p) | set(q)
    if not keys:
        return 0.0
    if alpha > 0:
        p_counts = {key: p.get(key, 0.0) + alpha for key in keys}
        q_counts = {key: q.get(key, 0.0) + alpha for key in keys}
    else:
        p_counts = {key: p.get(key, 0.0) for key in keys}
        q_counts = {key: q.get(key, 0.0) for key in keys}
    p_norm = normalize_dist(p_counts)
    q_norm = normalize_dist(q_counts)
    m = {key: 0.5 * (p_norm.get(key, 0.0) + q_norm.get(key, 0.0)) for key in keys}
    divergence = 0.0
    for key in keys:
        p_val = p_norm.get(key, 0.0)
        q_val = q_norm.get(key, 0.0)
        m_val = m.get(key, 0.0)
        if p_val > 0 and m_val > 0:
            divergence += 0.5 * p_val * math.log(p_val / m_val, 2)
        if q_val > 0 and m_val > 0:
            divergence += 0.5 * q_val * math.log(q_val / m_val, 2)
    divergence = max(divergence, 0.0)
    similarity = 1.0 - math.sqrt(divergence)
    return max(0.0, min(1.0, similarity))


def clamp_prob(p: float, support: int, alpha: float) -> float:
    denom = support + 2 * alpha
    eps = alpha / denom if denom > 0 else 1e-6
    return min(max(p, eps), 1.0 - eps)


def wilson_interval(p: float, n: int, z: float = 1.96) -> tuple[float, float]:
    if n <= 0:
        return (0.0, 1.0)
    z2 = z * z
    denom = 1.0 + z2 / n
    center = p + z2 / (2 * n)
    margin = z * math.sqrt((p * (1 - p) + z2 / (4 * n)) / n)
    lower = (center - margin) / denom
    upper = (center + margin) / denom
    return (max(0.0, lower), min(1.0, upper))


def wilson_width(p: float, n: int, z: float = 1.96) -> float:
    lower, upper = wilson_interval(p, n, z=z)
    return max(0.0, upper - lower)
