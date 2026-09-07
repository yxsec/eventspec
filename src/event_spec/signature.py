"""Shared function signature helpers."""

from __future__ import annotations

from collections import Counter
from typing import Mapping, Optional

from .utils import sha1_text


def _get_value(obj: object, key: str, default: Optional[object] = None) -> Optional[object]:
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def build_function_signature(
    function_row: object,
    features: Mapping[str, object],
) -> str:
    tokens: list[str] = []
    guard_categories = _get_value(function_row, "guard_categories", []) or []
    for category in guard_categories:
        tokens.append(f"guard:{category}")

    sstore_kinds = _get_value(function_row, "sstore_kinds", []) or []
    for kind in sstore_kinds:
        tokens.append(f"sstore:{kind}")

    dep_counts: Counter[str] = features.get("dep_counts", Counter())  # type: ignore[assignment]
    source_counts: Counter[str] = features.get("source_counts", Counter())  # type: ignore[assignment]
    dep_total = sum(dep_counts.values())
    source_total = sum(source_counts.values())
    for dep, count in dep_counts.items():
        if dep_total > 0 and count / dep_total >= 0.15:
            tokens.append(f"dep:{dep}")
    for src, count in source_counts.items():
        if source_total > 0 and count / source_total >= 0.15:
            tokens.append(f"source:{src}")

    topic_mode = _mode(features.get("topic_counts", Counter()))
    data_mode = _mode(features.get("data_counts", Counter()))
    tokens.append(f"topics:{topic_mode}")
    tokens.append(f"data:{data_mode}")

    opcode_bow = _get_value(function_row, "opcode_bow", {}) or {}
    for opcode, count in opcode_bow.items():
        if count >= 3:
            tokens.append(f"op:{opcode}")

    if not tokens:
        tokens.append("empty")
    return sha1_text("|".join(sorted(tokens)))


def _mode(counter: Counter[int]) -> str:
    if not counter:
        return "0"
    return str(counter.most_common(1)[0][0])
