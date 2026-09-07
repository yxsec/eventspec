"""SQLite-backed aggregate counts for event spec inference."""

from __future__ import annotations

import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Mapping, Sequence, Tuple, Union

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

from .schema import EventSpecPattern, FunctionSpecPattern
from .signature import build_function_signature
from .utils import normalize_dist


MAX_EXAMPLES = 3


def _maybe_print_progress(index: int, total: int, progress_every: int, label: str) -> None:
    if total <= 1:
        return
    if index == 1 or index == total or index % progress_every == 0:
        percent = (index / total) * 100
        print(f"[infer] {label} {index}/{total} ({percent:.1f}%)")


class AggregateStore:
    def __init__(self, path: Path, *, reset: bool = False) -> None:
        if reset and path.exists():
            path.unlink()
        self.path = path
        self.conn = sqlite3.connect(str(path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_db()
        self._func_example_counts: Dict[Tuple[str, str], int] = {}
        self._event_example_counts: Dict[Tuple[str, str, str], int] = {}

    def close(self) -> None:
        self.conn.close()

    def has_contract(self, contract_id: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM processed_contracts WHERE contract_id = ?",
            (contract_id,),
        ).fetchone()
        return bool(row)

    def mark_contract(self, contract_id: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO processed_contracts (contract_id) VALUES (?)",
            (contract_id,),
        )
        self.conn.commit()

    def update_contract(
        self,
        observations: Sequence,
        functions: Sequence,
        equalities: Sequence[Mapping[str, object]],
    ) -> None:
        feature_map = _build_function_features(functions, observations)
        cluster_by_function: Dict[str, str] = {}

        func_support: Dict[Tuple[str, str], int] = defaultdict(int)
        func_guard: Dict[Tuple[str, str, str], int] = defaultdict(int)
        func_sstore: Dict[Tuple[str, str, str], int] = defaultdict(int)
        func_opcode: Dict[Tuple[str, str, str], int] = defaultdict(int)
        func_log_count: Dict[Tuple[str, str, str], int] = defaultdict(int)
        func_expected_event: Dict[Tuple[str, str, str], int] = defaultdict(int)
        func_event_count: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
        func_log_shape: Dict[Tuple[str, str, str, str], int] = defaultdict(int)

        for fn in functions:
            fn_id = getattr(fn, "function_id", None)
            if not fn_id:
                continue
            tier = getattr(fn, "corpus_tier", "open") or "open"
            cluster_id = build_function_signature(fn, feature_map.get(fn_id, {}))
            cluster_by_function[fn_id] = cluster_id
            func_support[(cluster_id, tier)] += 1

            for category in set(getattr(fn, "guard_categories", []) or []):
                func_guard[(cluster_id, tier, category)] += 1
            for kind in set(getattr(fn, "sstore_kinds", []) or []):
                func_sstore[(cluster_id, tier, kind)] += 1
            for opcode, count in (getattr(fn, "opcode_bow", {}) or {}).items():
                if count > 0:
                    func_opcode[(cluster_id, tier, opcode)] += 1

            log_count_total = int(getattr(fn, "log_count_total", 0) or 0)
            func_log_count[(cluster_id, tier, str(log_count_total))] += 1

            for topic0 in set(getattr(fn, "reachable_logs", []) or []):
                func_expected_event[(cluster_id, tier, topic0)] += 1

            for topic0, count in (getattr(fn, "reachable_log_counts", {}) or {}).items():
                func_event_count[(cluster_id, tier, topic0, str(int(count)))] += 1

            shape_counts = getattr(fn, "log_shape_counts", {}) or {}
            for topic0, shapes in shape_counts.items():
                if not isinstance(shapes, dict):
                    continue
                for shape, count in shapes.items():
                    try:
                        count_int = int(count)
                    except (TypeError, ValueError):
                        continue
                    if count_int <= 0:
                        continue
                    func_log_shape[(cluster_id, tier, topic0, shape)] += count_int

            self._maybe_add_function_example(cluster_id, tier, fn)

        event_support: Dict[Tuple[str, str, str], int] = defaultdict(int)
        event_indexed: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
        event_param_count: Dict[Tuple[str, str, str, str, str], int] = defaultdict(int)
        event_label_support: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
        event_operand_source: Dict[Tuple[str, str, str, str, str], int] = defaultdict(int)
        event_operand_dep: Dict[Tuple[str, str, str, str, str], int] = defaultdict(int)
        event_operand_op: Dict[Tuple[str, str, str, str, str], int] = defaultdict(int)
        event_operand_literal: Dict[Tuple[str, str, str, str, str], int] = defaultdict(int)
        event_operand_arg_index: Dict[Tuple[str, str, str, str, str], int] = defaultdict(int)
        event_unaligned_offset: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
        event_sstore: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
        event_value_bind_label: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
        event_value_bind_flag: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
        event_slot_bind_label: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
        event_slot_bind_flag: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
        event_sload_bind_label: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
        event_sload_bind_flag: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
        event_guard: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
        event_equality: Dict[Tuple[str, str, str, str, str], int] = defaultdict(int)

        for obs in observations:
            fn_id = getattr(obs, "function_id", None)
            topic0 = getattr(obs, "topic0", None)
            if not fn_id or not topic0:
                continue
            cluster_id = cluster_by_function.get(fn_id)
            if not cluster_id:
                continue
            tier = getattr(obs, "corpus_tier", "open") or "open"
            event_support[(cluster_id, topic0, tier)] += 1

            labels = {op.label for op in getattr(obs, "operands", []) or [] if op.label}
            for label in labels:
                event_indexed[(cluster_id, topic0, tier, label)] += 1

            counts = getattr(obs, "param_counts", {}) or {}
            event_param_count[(cluster_id, topic0, tier, "topics", str(int(counts.get("topics", 0))))] += 1
            event_param_count[(cluster_id, topic0, tier, "data", str(int(counts.get("data", 0))))] += 1

            for operand in getattr(obs, "operands", []) or []:
                label = operand.label
                if not label:
                    continue
                event_label_support[(cluster_id, topic0, tier, label)] += 1
                for src in operand.source_kinds or []:
                    event_operand_source[(cluster_id, topic0, tier, label, src)] += 1
                for dep in operand.dep_kinds or []:
                    event_operand_dep[(cluster_id, topic0, tier, label, dep)] += 1
                for op in operand.def_use_ops or []:
                    event_operand_op[(cluster_id, topic0, tier, label, op)] += 1
                if operand.literal_class:
                    event_operand_literal[(cluster_id, topic0, tier, label, operand.literal_class)] += 1
                arg_index = getattr(operand, "arg_index", None)
                if arg_index is not None:
                    event_operand_arg_index[(cluster_id, topic0, tier, label, str(arg_index))] += 1
                if label == "data_unaligned" and operand.memory_slice:
                    offset = operand.memory_slice.offset
                    if offset is not None:
                        event_unaligned_offset[
                            (cluster_id, topic0, tier, f"0x{offset:x}")
                        ] += 1

            for entry in getattr(obs, "sstore_summary", []) or []:
                kind = entry.slot_kind
                if kind:
                    event_sstore[(cluster_id, topic0, tier, kind)] += 1

            bindings = getattr(obs, "value_bindings", {}) or {}
            if bindings.get("bind_any_topic"):
                event_value_bind_flag[(cluster_id, topic0, tier, "bind_any_topic")] += 1
            if bindings.get("bind_any_data"):
                event_value_bind_flag[(cluster_id, topic0, tier, "bind_any_data")] += 1
            for label in (bindings.get("bind_labels") or {}).keys():
                event_value_bind_label[(cluster_id, topic0, tier, label)] += 1
            if bindings.get("bind_any_topic_slot"):
                event_slot_bind_flag[(cluster_id, topic0, tier, "bind_any_topic")] += 1
            if bindings.get("bind_any_data_slot"):
                event_slot_bind_flag[(cluster_id, topic0, tier, "bind_any_data")] += 1
            for label in (bindings.get("bind_labels_slot") or {}).keys():
                event_slot_bind_label[(cluster_id, topic0, tier, label)] += 1
            if bindings.get("bind_any_topic_sload"):
                event_sload_bind_flag[(cluster_id, topic0, tier, "bind_any_topic")] += 1
            if bindings.get("bind_any_data_sload"):
                event_sload_bind_flag[(cluster_id, topic0, tier, "bind_any_data")] += 1
            for label in (bindings.get("bind_labels_sload") or {}).keys():
                event_sload_bind_label[(cluster_id, topic0, tier, label)] += 1

            for category in set(getattr(obs, "guard_summary", []) or []):
                event_guard[(cluster_id, topic0, tier, category)] += 1

            self._maybe_add_event_example(cluster_id, topic0, tier, obs)

        for row in equalities:
            status = row.get("status")
            if status not in {"possible", "unsat"}:
                continue
            topic0 = row.get("topic0")
            label = row.get("label")
            tier = row.get("corpus_tier", "open") or "open"
            fn_a = row.get("function_a")
            fn_b = row.get("function_b")
            if not topic0 or not label or not fn_a or not fn_b:
                continue
            cluster_a = cluster_by_function.get(fn_a)
            cluster_b = cluster_by_function.get(fn_b)
            if not cluster_a or cluster_a != cluster_b:
                continue
            event_equality[(cluster_a, topic0, str(tier), label, str(status))] += 1

        self._flush_counts(func_support, "func_support", ("cluster_id", "tier"))
        self._flush_counts(func_guard, "func_guard", ("cluster_id", "tier", "guard"))
        self._flush_counts(func_sstore, "func_sstore", ("cluster_id", "tier", "kind"))
        self._flush_counts(func_opcode, "func_opcode", ("cluster_id", "tier", "opcode"))
        self._flush_counts(func_log_count, "func_log_count", ("cluster_id", "tier", "count_value"))
        self._flush_counts(
            func_expected_event, "func_expected_event", ("cluster_id", "tier", "topic0")
        )
        self._flush_counts(
            func_event_count,
            "func_event_count",
            ("cluster_id", "tier", "topic0", "count_value"),
        )
        self._flush_counts(
            func_log_shape,
            "func_log_shape",
            ("cluster_id", "tier", "topic0", "shape"),
        )

        self._flush_counts(
            event_support, "event_support", ("cluster_id", "topic0", "tier")
        )
        self._flush_counts(
            event_indexed,
            "event_indexed",
            ("cluster_id", "topic0", "tier", "label"),
        )
        self._flush_counts(
            event_param_count,
            "event_param_count",
            ("cluster_id", "topic0", "tier", "kind", "count_value"),
        )
        self._flush_counts(
            event_label_support,
            "event_label_support",
            ("cluster_id", "topic0", "tier", "label"),
        )
        self._flush_counts(
            event_operand_source,
            "event_operand_source",
            ("cluster_id", "topic0", "tier", "label", "source"),
        )
        self._flush_counts(
            event_operand_dep,
            "event_operand_dep",
            ("cluster_id", "topic0", "tier", "label", "dep"),
        )
        self._flush_counts(
            event_operand_op,
            "event_operand_op",
            ("cluster_id", "topic0", "tier", "label", "op"),
        )
        self._flush_counts(
            event_operand_literal,
            "event_operand_literal",
            ("cluster_id", "topic0", "tier", "label", "literal"),
        )
        self._flush_counts(
            event_operand_arg_index,
            "event_operand_arg_index",
            ("cluster_id", "topic0", "tier", "label", "arg_index"),
        )
        self._flush_counts(
            event_unaligned_offset,
            "event_unaligned_offset",
            ("cluster_id", "topic0", "tier", "offset"),
        )
        self._flush_counts(
            event_sstore,
            "event_sstore",
            ("cluster_id", "topic0", "tier", "kind"),
        )
        self._flush_counts(
            event_value_bind_label,
            "event_value_bind_label",
            ("cluster_id", "topic0", "tier", "label"),
        )
        self._flush_counts(
            event_value_bind_flag,
            "event_value_bind_flag",
            ("cluster_id", "topic0", "tier", "flag"),
        )
        self._flush_counts(
            event_slot_bind_label,
            "event_slot_bind_label",
            ("cluster_id", "topic0", "tier", "label"),
        )
        self._flush_counts(
            event_slot_bind_flag,
            "event_slot_bind_flag",
            ("cluster_id", "topic0", "tier", "flag"),
        )
        self._flush_counts(
            event_sload_bind_label,
            "event_sload_bind_label",
            ("cluster_id", "topic0", "tier", "label"),
        )
        self._flush_counts(
            event_sload_bind_flag,
            "event_sload_bind_flag",
            ("cluster_id", "topic0", "tier", "flag"),
        )
        self._flush_counts(
            event_guard,
            "event_guard",
            ("cluster_id", "topic0", "tier", "guard"),
        )
        self._flush_counts(
            event_equality,
            "event_equality",
            ("cluster_id", "topic0", "tier", "label", "status"),
        )

        self.conn.commit()

    def load_function_patterns(self, config: Mapping[str, object]) -> List[FunctionSpecPattern]:
        support_map: Dict[str, Dict[str, int]] = defaultdict(lambda: {"core": 0, "open": 0})
        for cluster_id, tier, count in self.conn.execute(
            "SELECT cluster_id, tier, count FROM func_support"
        ):
            support_map[cluster_id][tier] = int(count)

        func_guard = _load_counts(
            self.conn, "func_guard", ("cluster_id", "tier", "guard"), prefix_len=2
        )
        func_sstore = _load_counts(
            self.conn, "func_sstore", ("cluster_id", "tier", "kind"), prefix_len=2
        )
        func_opcode = _load_counts(
            self.conn, "func_opcode", ("cluster_id", "tier", "opcode"), prefix_len=2
        )
        func_log_count = _load_counts(
            self.conn, "func_log_count", ("cluster_id", "tier", "count_value"), prefix_len=2
        )
        func_expected_event = _load_counts(
            self.conn, "func_expected_event", ("cluster_id", "tier", "topic0"), prefix_len=2
        )
        func_event_count = _load_counts(
            self.conn,
            "func_event_count",
            ("cluster_id", "tier", "topic0", "count_value"),
            prefix_len=2,
        )
        func_log_shape = _load_counts(
            self.conn,
            "func_log_shape",
            ("cluster_id", "tier", "topic0", "shape"),
            prefix_len=2,
        )
        func_examples = _load_examples(
            self.conn,
            "func_examples",
            ("cluster_id", "tier"),
        )

        patterns: List[FunctionSpecPattern] = []
        core_min = int(config.get("core_support_min", 10))
        progress_total = len(support_map)
        progress_every = max(1, progress_total // 100) if progress_total else 1
        iterator = support_map.items()
        if tqdm is not None:
            iterator = tqdm(iterator, total=progress_total, desc="infer-functions", unit="pattern")
        for index, (cluster_id, support) in enumerate(iterator, start=1):
            tier = "core" if support.get("core", 0) >= core_min else "open"
            support_total = support.get(tier, 0)
            if support_total <= 0:
                continue

            expected_counts = func_expected_event.get((cluster_id, tier), {})
            expected_events = {
                topic0: count / support_total for topic0, count in expected_counts.items()
            }

            log_count_counts = func_log_count.get((cluster_id, tier), {})
            log_count_profile = {
                key: count / support_total for key, count in log_count_counts.items()
            }

            event_count_profile: Dict[str, Dict[str, float]] = {}
            event_count_support: Dict[str, int] = {}
            for topic0, counts in _group_by_topic(func_event_count, cluster_id, tier).items():
                total_topic = sum(counts.values())
                if total_topic <= 0:
                    continue
                event_count_profile[topic0] = {
                    count_value: count / total_topic for count_value, count in counts.items()
                }
                event_count_support[topic0] = total_topic

            log_shape_profile: Dict[str, Dict[str, float]] = {}
            log_shape_support: Dict[str, int] = {}
            for topic0, counts in _group_by_topic(func_log_shape, cluster_id, tier).items():
                total_shape = sum(counts.values())
                if total_shape <= 0:
                    continue
                log_shape_profile[topic0] = {
                    shape: count / total_shape for shape, count in counts.items()
                }
                log_shape_support[topic0] = total_shape

            guard_profile = _profile_from_counts(
                func_guard.get((cluster_id, tier), {}), support_total
            )
            sstore_profile = _profile_from_counts(
                func_sstore.get((cluster_id, tier), {}), support_total
            )
            opcode_profile = _profile_from_counts(
                func_opcode.get((cluster_id, tier), {}), support_total
            )
            examples = func_examples.get((cluster_id, tier))
            if not examples and tier != "open":
                examples = func_examples.get((cluster_id, "open"), [])
            examples = list(examples or [])[:MAX_EXAMPLES]

            pattern = FunctionSpecPattern(
                cluster_id=cluster_id,
                support=dict(support),
                pattern_tier=tier,
                expected_events=expected_events,
                event_count_profile=event_count_profile,
                event_count_support=event_count_support,
                log_count_profile=log_count_profile,
                log_shape_profile=log_shape_profile,
                log_shape_support=log_shape_support,
                guard_profile=guard_profile,
                sstore_profile=sstore_profile,
                opcode_profile=opcode_profile,
                examples=examples,
            )
            patterns.append(pattern)
            if tqdm is None:
                _maybe_print_progress(index, progress_total, progress_every, "functions")
        return patterns

    def load_event_patterns(self, config: Mapping[str, object]) -> List[EventSpecPattern]:
        support_map: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(
            lambda: {"core": 0, "open": 0}
        )
        for cluster_id, topic0, tier, count in self.conn.execute(
            "SELECT cluster_id, topic0, tier, count FROM event_support"
        ):
            support_map[(topic0, cluster_id)][tier] = int(count)

        indexed_counts = _load_counts(
            self.conn, "event_indexed", ("cluster_id", "topic0", "tier", "label"), prefix_len=3
        )
        param_counts = _load_counts(
            self.conn,
            "event_param_count",
            ("cluster_id", "topic0", "tier", "kind", "count_value"),
            prefix_len=3,
        )
        label_support = _load_counts(
            self.conn, "event_label_support", ("cluster_id", "topic0", "tier", "label"), prefix_len=3
        )
        operand_source = _load_counts(
            self.conn,
            "event_operand_source",
            ("cluster_id", "topic0", "tier", "label", "source"),
            prefix_len=4,
        )
        operand_dep = _load_counts(
            self.conn,
            "event_operand_dep",
            ("cluster_id", "topic0", "tier", "label", "dep"),
            prefix_len=4,
        )
        operand_op = _load_counts(
            self.conn,
            "event_operand_op",
            ("cluster_id", "topic0", "tier", "label", "op"),
            prefix_len=4,
        )
        operand_literal = _load_counts(
            self.conn,
            "event_operand_literal",
            ("cluster_id", "topic0", "tier", "label", "literal"),
            prefix_len=4,
        )
        operand_arg_index = _load_counts(
            self.conn,
            "event_operand_arg_index",
            ("cluster_id", "topic0", "tier", "label", "arg_index"),
            prefix_len=4,
        )
        unaligned_offsets = _load_counts(
            self.conn, "event_unaligned_offset", ("cluster_id", "topic0", "tier", "offset"), prefix_len=3
        )
        sstore_counts = _load_counts(
            self.conn, "event_sstore", ("cluster_id", "topic0", "tier", "kind"), prefix_len=3
        )
        value_bind_label = _load_counts(
            self.conn, "event_value_bind_label", ("cluster_id", "topic0", "tier", "label"), prefix_len=3
        )
        value_bind_flag = _load_counts(
            self.conn, "event_value_bind_flag", ("cluster_id", "topic0", "tier", "flag"), prefix_len=3
        )
        slot_bind_label = _load_counts_optional(
            self.conn, "event_slot_bind_label", ("cluster_id", "topic0", "tier", "label"), prefix_len=3
        )
        slot_bind_flag = _load_counts_optional(
            self.conn, "event_slot_bind_flag", ("cluster_id", "topic0", "tier", "flag"), prefix_len=3
        )
        sload_bind_label = _load_counts_optional(
            self.conn, "event_sload_bind_label", ("cluster_id", "topic0", "tier", "label"), prefix_len=3
        )
        sload_bind_flag = _load_counts_optional(
            self.conn, "event_sload_bind_flag", ("cluster_id", "topic0", "tier", "flag"), prefix_len=3
        )
        guard_counts = _load_counts(
            self.conn, "event_guard", ("cluster_id", "topic0", "tier", "guard"), prefix_len=3
        )
        equality_counts = _load_counts(
            self.conn,
            "event_equality",
            ("cluster_id", "topic0", "tier", "label", "status"),
            prefix_len=3,
        )
        event_examples = _load_examples(
            self.conn,
            "event_examples",
            ("cluster_id", "topic0", "tier"),
        )

        core_min = int(config.get("core_support_min", 10))
        support_min = int(config.get("support_min", 20))
        top_k = int(config.get("top_k", 3))

        patterns: List[EventSpecPattern] = []
        progress_total = len(support_map)
        progress_every = max(1, progress_total // 100) if progress_total else 1
        iterator = support_map.items()
        if tqdm is not None:
            iterator = tqdm(iterator, total=progress_total, desc="infer-events", unit="pattern")
        for index, ((topic0, cluster_id), support) in enumerate(iterator, start=1):
            tier = "core" if support.get("core", 0) >= core_min else "open"
            support_total = support.get(tier, 0)
            if support_total <= 0:
                continue

            indexed = indexed_counts.get((cluster_id, topic0, tier), {})
            indexed_profile = {
                label: count / support_total for label, count in indexed.items()
            }

            param = param_counts.get((cluster_id, topic0, tier), {})
            topics_profile = {
                key: count / support_total
                for (kind, key), count in param.items()
                if kind == "topics"
            }
            data_profile = {
                key: count / support_total
                for (kind, key), count in param.items()
                if kind == "data"
            }
            param_count_profile = {"topics": topics_profile, "data": data_profile}

            label_support_counts = label_support.get((cluster_id, topic0, tier), {})
            operand_profiles: Dict[str, Dict[str, object]] = {}
            for label, support_count in label_support_counts.items():
                source_profile = normalize_dist(
                    operand_source.get((cluster_id, topic0, tier, label), {})
                )
                dep_profile = normalize_dist(
                    operand_dep.get((cluster_id, topic0, tier, label), {})
                )
                op_counts = operand_op.get((cluster_id, topic0, tier, label), {})
                top_ops = [op for op, _ in sorted(op_counts.items(), key=lambda item: item[1], reverse=True)[:8]]
                literal_profile = normalize_dist(
                    operand_literal.get((cluster_id, topic0, tier, label), {})
                )
                arg_index_counts = operand_arg_index.get((cluster_id, topic0, tier, label), {})
                known_total = sum(int(value) for value in arg_index_counts.values())
                unknown = support_count - known_total
                if unknown > 0:
                    arg_index_counts = dict(arg_index_counts)
                    arg_index_counts["unknown"] = unknown
                arg_index_profile = normalize_dist(arg_index_counts)
                operand_profiles[label] = {
                    "source": source_profile,
                    "deps": dep_profile,
                    "ops": top_ops,
                    "literal": literal_profile,
                    "arg_index": arg_index_profile,
                    "support": support_count,
                }

            unaligned_profile = normalize_dist(
                unaligned_offsets.get((cluster_id, topic0, tier), {})
            )
            sstore_profile = normalize_dist(
                sstore_counts.get((cluster_id, topic0, tier), {})
            )
            value_bind_counts = value_bind_label.get((cluster_id, topic0, tier), {})
            value_bind_profile = (
                {label: count / support_total for label, count in value_bind_counts.items()}
                if support_total > 0
                else {}
            )
            flag_counts = value_bind_flag.get((cluster_id, topic0, tier), {})
            if support_total > 0:
                value_bind_profile["bind_any_topic"] = (
                    flag_counts.get("bind_any_topic", 0) / support_total
                )
                value_bind_profile["bind_any_data"] = (
                    flag_counts.get("bind_any_data", 0) / support_total
                )
            slot_bind_counts = slot_bind_label.get((cluster_id, topic0, tier), {})
            slot_bind_profile = (
                {label: count / support_total for label, count in slot_bind_counts.items()}
                if support_total > 0
                else {}
            )
            slot_flag_counts = slot_bind_flag.get((cluster_id, topic0, tier), {})
            if support_total > 0:
                slot_bind_profile["bind_any_topic"] = (
                    slot_flag_counts.get("bind_any_topic", 0) / support_total
                )
                slot_bind_profile["bind_any_data"] = (
                    slot_flag_counts.get("bind_any_data", 0) / support_total
                )
            sload_bind_counts = sload_bind_label.get((cluster_id, topic0, tier), {})
            sload_bind_profile = (
                {label: count / support_total for label, count in sload_bind_counts.items()}
                if support_total > 0
                else {}
            )
            sload_flag_counts = sload_bind_flag.get((cluster_id, topic0, tier), {})
            if support_total > 0:
                sload_bind_profile["bind_any_topic"] = (
                    sload_flag_counts.get("bind_any_topic", 0) / support_total
                )
                sload_bind_profile["bind_any_data"] = (
                    sload_flag_counts.get("bind_any_data", 0) / support_total
                )

            guard_count_map = guard_counts.get((cluster_id, topic0, tier), {})
            guard_profile = (
                {cat: count / support_total for cat, count in guard_count_map.items()}
                if support_total > 0
                else {}
            )

            eq_profile, eq_support = _build_equality_profile(
                equality_counts, cluster_id, topic0, tier
            )

            examples = event_examples.get((cluster_id, topic0, tier))
            if not examples and tier != "open":
                examples = event_examples.get((cluster_id, topic0, "open"), [])
            examples = list(examples or [])[:MAX_EXAMPLES]

            pattern = EventSpecPattern(
                topic0=topic0,
                cluster_id=cluster_id,
                support=dict(support),
                pattern_tier=tier,
                indexed_profile=indexed_profile,
                param_count_profile=param_count_profile,
                operand_profiles=operand_profiles,
                unaligned_offset_profile=unaligned_profile,
                sstore_profile=sstore_profile,
                value_bind_profile=value_bind_profile,
                slot_bind_profile=slot_bind_profile,
                sload_bind_profile=sload_bind_profile,
                guard_profile=guard_profile,
                equality_profile=eq_profile,
                equality_support=eq_support,
                examples=examples,
            )
            patterns.append(pattern)
            if tqdm is None:
                _maybe_print_progress(index, progress_total, progress_every, "events")

        filtered: List[EventSpecPattern] = []
        by_topic: Dict[str, List[EventSpecPattern]] = defaultdict(list)
        for pattern in patterns:
            support = pattern.support.get(pattern.pattern_tier, 0)
            if support < support_min:
                continue
            by_topic[pattern.topic0].append(pattern)
        for topic0, items in by_topic.items():
            items.sort(key=lambda item: item.support.get(item.pattern_tier, 0), reverse=True)
            filtered.extend(items[:top_k])
        return filtered

    def _init_db(self) -> None:
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS processed_contracts (contract_id TEXT PRIMARY KEY)"
        )

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS func_support (cluster_id TEXT, tier TEXT, count INTEGER, PRIMARY KEY (cluster_id, tier))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS func_guard (cluster_id TEXT, tier TEXT, guard TEXT, count INTEGER, PRIMARY KEY (cluster_id, tier, guard))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS func_sstore (cluster_id TEXT, tier TEXT, kind TEXT, count INTEGER, PRIMARY KEY (cluster_id, tier, kind))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS func_opcode (cluster_id TEXT, tier TEXT, opcode TEXT, count INTEGER, PRIMARY KEY (cluster_id, tier, opcode))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS func_log_count (cluster_id TEXT, tier TEXT, count_value TEXT, count INTEGER, PRIMARY KEY (cluster_id, tier, count_value))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS func_expected_event (cluster_id TEXT, tier TEXT, topic0 TEXT, count INTEGER, PRIMARY KEY (cluster_id, tier, topic0))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS func_event_count (cluster_id TEXT, tier TEXT, topic0 TEXT, count_value TEXT, count INTEGER, PRIMARY KEY (cluster_id, tier, topic0, count_value))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS func_log_shape (cluster_id TEXT, tier TEXT, topic0 TEXT, shape TEXT, count INTEGER, PRIMARY KEY (cluster_id, tier, topic0, shape))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS func_examples (cluster_id TEXT, tier TEXT, contract_id TEXT, function_id TEXT, PRIMARY KEY (cluster_id, tier, contract_id, function_id))"
        )

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_support (cluster_id TEXT, topic0 TEXT, tier TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_indexed (cluster_id TEXT, topic0 TEXT, tier TEXT, label TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, label))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_param_count (cluster_id TEXT, topic0 TEXT, tier TEXT, kind TEXT, count_value TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, kind, count_value))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_label_support (cluster_id TEXT, topic0 TEXT, tier TEXT, label TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, label))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_operand_source (cluster_id TEXT, topic0 TEXT, tier TEXT, label TEXT, source TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, label, source))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_operand_dep (cluster_id TEXT, topic0 TEXT, tier TEXT, label TEXT, dep TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, label, dep))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_operand_op (cluster_id TEXT, topic0 TEXT, tier TEXT, label TEXT, op TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, label, op))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_operand_literal (cluster_id TEXT, topic0 TEXT, tier TEXT, label TEXT, literal TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, label, literal))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_operand_arg_index (cluster_id TEXT, topic0 TEXT, tier TEXT, label TEXT, arg_index TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, label, arg_index))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_unaligned_offset (cluster_id TEXT, topic0 TEXT, tier TEXT, offset TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, offset))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_sstore (cluster_id TEXT, topic0 TEXT, tier TEXT, kind TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, kind))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_value_bind_label (cluster_id TEXT, topic0 TEXT, tier TEXT, label TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, label))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_value_bind_flag (cluster_id TEXT, topic0 TEXT, tier TEXT, flag TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, flag))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_slot_bind_label (cluster_id TEXT, topic0 TEXT, tier TEXT, label TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, label))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_slot_bind_flag (cluster_id TEXT, topic0 TEXT, tier TEXT, flag TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, flag))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_sload_bind_label (cluster_id TEXT, topic0 TEXT, tier TEXT, label TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, label))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_sload_bind_flag (cluster_id TEXT, topic0 TEXT, tier TEXT, flag TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, flag))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_guard (cluster_id TEXT, topic0 TEXT, tier TEXT, guard TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, guard))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_equality (cluster_id TEXT, topic0 TEXT, tier TEXT, label TEXT, status TEXT, count INTEGER, PRIMARY KEY (cluster_id, topic0, tier, label, status))"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS event_examples (cluster_id TEXT, topic0 TEXT, tier TEXT, contract_id TEXT, function_id TEXT, PRIMARY KEY (cluster_id, topic0, tier, contract_id, function_id))"
        )

        self.conn.commit()

    def _flush_counts(
        self,
        counter: Mapping[Tuple[str, ...], int],
        table: str,
        columns: Sequence[str],
    ) -> None:
        if not counter:
            return
        cols = ", ".join(columns)
        placeholders = ", ".join(["?"] * (len(columns) + 1))
        conflict = ", ".join(columns)
        sql = (
            f"INSERT INTO {table} ({cols}, count) VALUES ({placeholders}) "
            f"ON CONFLICT({conflict}) DO UPDATE SET count = count + excluded.count"
        )
        values = [tuple(key) + (count,) for key, count in counter.items()]
        self.conn.executemany(sql, values)

    def _maybe_add_function_example(self, cluster_id: str, tier: str, fn: object) -> None:
        key = (cluster_id, tier)
        current = self._func_example_counts.get(key)
        if current is None:
            current = self._count_examples("func_examples", ("cluster_id", "tier"), key)
            self._func_example_counts[key] = current
        if current >= MAX_EXAMPLES:
            return
        contract_id = getattr(fn, "contract_id", "")
        function_id = getattr(fn, "function_id", "")
        cursor = self.conn.execute(
            "INSERT OR IGNORE INTO func_examples (cluster_id, tier, contract_id, function_id) VALUES (?, ?, ?, ?)",
            (cluster_id, tier, contract_id, function_id),
        )
        if cursor.rowcount:
            self._func_example_counts[key] = current + 1

    def _maybe_add_event_example(
        self, cluster_id: str, topic0: str, tier: str, obs: object
    ) -> None:
        key = (cluster_id, topic0, tier)
        current = self._event_example_counts.get(key)
        if current is None:
            current = self._count_examples(
                "event_examples", ("cluster_id", "topic0", "tier"), key
            )
            self._event_example_counts[key] = current
        if current >= MAX_EXAMPLES:
            return
        contract_id = getattr(obs, "contract_id", "")
        function_id = getattr(obs, "function_id", "")
        cursor = self.conn.execute(
            "INSERT OR IGNORE INTO event_examples (cluster_id, topic0, tier, contract_id, function_id) VALUES (?, ?, ?, ?, ?)",
            (cluster_id, topic0, tier, contract_id, function_id),
        )
        if cursor.rowcount:
            self._event_example_counts[key] = current + 1

    def _count_examples(self, table: str, columns: Sequence[str], key: Tuple[str, ...]) -> int:
        where = " AND ".join([f"{col} = ?" for col in columns])
        row = self.conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE {where}",
            tuple(key),
        ).fetchone()
        return int(row[0]) if row else 0


def _build_function_features(functions: Sequence, observations: Sequence) -> Dict[str, Dict[str, Counter]]:
    features: Dict[str, Dict[str, Counter]] = {}
    for fn in functions:
        fn_id = getattr(fn, "function_id", None)
        if not fn_id:
            continue
        features[fn_id] = {
            "dep_counts": Counter(),
            "source_counts": Counter(),
            "topic_counts": Counter(),
            "data_counts": Counter(),
        }
    for obs in observations:
        fn_id = getattr(obs, "function_id", None)
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
        for operand in getattr(obs, "operands", []) or []:
            for dep in operand.dep_kinds or []:
                entry["dep_counts"][dep] += 1
            for src in operand.source_kinds or []:
                entry["source_counts"][src] += 1
        counts = getattr(obs, "param_counts", {}) or {}
        entry["topic_counts"][counts.get("topics", 0)] += 1
        entry["data_counts"][counts.get("data", 0)] += 1
    return features


def _load_counts(
    conn: sqlite3.Connection,
    table: str,
    columns: Sequence[str],
    *,
    prefix_len: int,
) -> Dict[Tuple[str, ...], Dict[Union[Tuple[str, ...], str], int]]:
    results: Dict[Tuple[str, ...], Dict[Union[Tuple[str, ...], str], int]] = defaultdict(dict)
    cols = ", ".join(columns)
    for row in conn.execute(f"SELECT {cols}, count FROM {table}"):
        prefix = tuple(str(item) for item in row[:prefix_len])
        suffix = tuple(str(item) for item in row[prefix_len:-1])
        count = int(row[-1])
        key: Union[Tuple[str, ...], str]
        if len(suffix) == 1:
            key = suffix[0]
        else:
            key = suffix
        results[prefix][key] = count
    return results


def _load_counts_optional(
    conn: sqlite3.Connection,
    table: str,
    columns: Sequence[str],
    *,
    prefix_len: int,
) -> Dict[Tuple[str, ...], Dict[Union[Tuple[str, ...], str], int]]:
    try:
        return _load_counts(conn, table, columns, prefix_len=prefix_len)
    except sqlite3.OperationalError:
        return defaultdict(dict)


def _load_examples(
    conn: sqlite3.Connection,
    table: str,
    columns: Sequence[str],
) -> Dict[Tuple[str, ...], List[Dict[str, str]]]:
    results: Dict[Tuple[str, ...], List[Dict[str, str]]] = defaultdict(list)
    cols = ", ".join(columns)
    for row in conn.execute(
        f"SELECT {cols}, contract_id, function_id FROM {table}"
    ):
        *prefix, contract_id, function_id = row
        results[tuple(prefix)].append(
            {"contract_id": str(contract_id), "function_id": str(function_id)}
        )
    return results


def _profile_from_counts(counts: Mapping[str, int], total: int) -> Dict[str, float]:
    if total <= 0:
        return {}
    return {key: value / total for key, value in counts.items()}


def _group_by_topic(
    data: Dict[Tuple[str, str], Dict[Union[Tuple[str, ...], str], int]],
    cluster_id: str,
    tier: str,
) -> Dict[str, Dict[str, int]]:
    results: Dict[str, Dict[str, int]] = defaultdict(dict)
    for (cid, t), counts in data.items():
        if cid != cluster_id or t != tier:
            continue
        for key, count in counts.items():
            if isinstance(key, tuple):
                topic0, value = key
                results[topic0][str(value)] = results[topic0].get(str(value), 0) + count
    return results


def _build_equality_profile(
    equality_counts: Dict[Tuple[str, str, str], Dict[Union[Tuple[str, ...], str], int]],
    cluster_id: str,
    topic0: str,
    tier: str,
) -> Tuple[Dict[str, float], Dict[str, int]]:
    def collect(tier_value: str) -> Dict[str, Dict[str, int]]:
        results: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        counts = equality_counts.get((cluster_id, topic0, tier_value), {})
        for key, count in counts.items():
            if isinstance(key, tuple):
                label, status = key
            else:
                continue
            results[label][status] += count
        return results

    tier_counts = collect(tier)
    if not tier_counts and tier != "open":
        tier_counts = collect("open")
    profile: Dict[str, float] = {}
    support: Dict[str, int] = {}
    for label, counts in tier_counts.items():
        possible = counts.get("possible", 0)
        unsat = counts.get("unsat", 0)
        total = possible + unsat
        if total <= 0:
            continue
        profile[label] = possible / total
        support[label] = total
    return profile, support
