"""Data schema for empirical event spec inference."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class MemorySlice:
    offset: Optional[int] = None
    size: Optional[int] = None

    def to_dict(self) -> Dict[str, Optional[int]]:
        return {"offset": self.offset, "size": self.size}


@dataclass
class OperandObservation:
    label: str
    is_topic: bool
    source_kinds: List[str] = field(default_factory=list)
    dep_kinds: List[str] = field(default_factory=list)
    def_use_ops: List[str] = field(default_factory=list)
    memory_slice: Optional[MemorySlice] = None
    arg_index: Optional[int] = None
    constraint_candidates: List[str] = field(default_factory=list)
    literal_class: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "label": self.label,
            "is_topic": self.is_topic,
            "source_kinds": list(self.source_kinds),
            "dep_kinds": list(self.dep_kinds),
            "def_use_ops": list(self.def_use_ops),
            "memory_slice": self.memory_slice.to_dict() if self.memory_slice else None,
            "arg_index": self.arg_index,
            "constraint_candidates": list(self.constraint_candidates),
            "literal_class": self.literal_class,
        }


@dataclass
class SstoreSummary:
    slot_kind: str
    slot_deps: List[str] = field(default_factory=list)
    value_deps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "slot_kind": self.slot_kind,
            "slot_deps": list(self.slot_deps),
            "value_deps": list(self.value_deps),
        }


@dataclass
class EventObservation:
    contract_id: str
    corpus_tier: str
    function_id: str
    function_name: Optional[str]
    function_selector: Optional[str]
    entrypoint_ids: List[str] = field(default_factory=list)
    topic0: str = ""
    event_signature: Optional[str] = None
    log_site: Dict[str, str] = field(default_factory=dict)
    param_counts: Dict[str, int] = field(default_factory=dict)
    operands: List[OperandObservation] = field(default_factory=list)
    opcode_footprint: Dict[str, int] = field(default_factory=dict)
    sstore_scope: str = "reachable_to_log"
    sstore_summary: List[SstoreSummary] = field(default_factory=list)
    value_bindings: Dict[str, object] = field(default_factory=dict)
    guard_summary: List[str] = field(default_factory=list)
    check_sources: List[str] = field(default_factory=list)
    context: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "contract_id": self.contract_id,
            "corpus_tier": self.corpus_tier,
            "function_id": self.function_id,
            "function_name": self.function_name,
            "function_selector": self.function_selector,
            "entrypoint_ids": list(self.entrypoint_ids),
            "topic0": self.topic0,
            "event_signature": self.event_signature,
            "log_site": dict(self.log_site),
            "param_counts": dict(self.param_counts),
            "operands": [operand.to_dict() for operand in self.operands],
            "opcode_footprint": dict(self.opcode_footprint),
            "sstore_scope": self.sstore_scope,
            "sstore_summary": [summary.to_dict() for summary in self.sstore_summary],
            "value_bindings": dict(self.value_bindings),
            "guard_summary": list(self.guard_summary),
            "check_sources": list(self.check_sources),
            "context": dict(self.context),
        }


@dataclass
class FunctionSummary:
    contract_id: str
    corpus_tier: str
    function_id: str
    function_name: Optional[str]
    function_selector: Optional[str]
    opcode_bow: Dict[str, int] = field(default_factory=dict)
    guard_categories: List[str] = field(default_factory=list)
    sstore_kinds: List[str] = field(default_factory=list)
    has_state_change: bool = False
    reachable_logs: List[str] = field(default_factory=list)
    log_count_total: int = 0
    reachable_log_counts: Dict[str, int] = field(default_factory=dict)
    log_shape_counts: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "contract_id": self.contract_id,
            "corpus_tier": self.corpus_tier,
            "function_id": self.function_id,
            "function_name": self.function_name,
            "function_selector": self.function_selector,
            "opcode_bow": dict(self.opcode_bow),
            "guard_categories": list(self.guard_categories),
            "sstore_kinds": list(self.sstore_kinds),
            "has_state_change": self.has_state_change,
            "reachable_logs": list(self.reachable_logs),
            "log_count_total": self.log_count_total,
            "reachable_log_counts": dict(self.reachable_log_counts),
            "log_shape_counts": {
                topic0: dict(counts) for topic0, counts in self.log_shape_counts.items()
            },
        }


@dataclass
class FunctionSpecPattern:
    cluster_id: str
    support: Dict[str, int] = field(default_factory=dict)
    pattern_tier: str = "open"
    expected_events: Dict[str, float] = field(default_factory=dict)
    event_count_profile: Dict[str, Dict[str, float]] = field(default_factory=dict)
    event_count_support: Dict[str, int] = field(default_factory=dict)
    log_count_profile: Dict[str, float] = field(default_factory=dict)
    log_shape_profile: Dict[str, Dict[str, float]] = field(default_factory=dict)
    log_shape_support: Dict[str, int] = field(default_factory=dict)
    guard_profile: Dict[str, float] = field(default_factory=dict)
    sstore_profile: Dict[str, float] = field(default_factory=dict)
    opcode_profile: Dict[str, float] = field(default_factory=dict)
    examples: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "cluster_id": self.cluster_id,
            "support": dict(self.support),
            "pattern_tier": self.pattern_tier,
            "expected_events": dict(self.expected_events),
            "event_count_profile": dict(self.event_count_profile),
            "event_count_support": dict(self.event_count_support),
            "log_count_profile": dict(self.log_count_profile),
            "log_shape_profile": {
                topic0: dict(counts) for topic0, counts in self.log_shape_profile.items()
            },
            "log_shape_support": dict(self.log_shape_support),
            "guard_profile": dict(self.guard_profile),
            "sstore_profile": dict(self.sstore_profile),
            "opcode_profile": dict(self.opcode_profile),
            "examples": list(self.examples),
        }


@dataclass
class EventSpecPattern:
    topic0: str
    cluster_id: str
    support: Dict[str, int] = field(default_factory=dict)
    pattern_tier: str = "open"
    indexed_profile: Dict[str, float] = field(default_factory=dict)
    param_count_profile: Dict[str, Dict[str, float]] = field(default_factory=dict)
    operand_profiles: Dict[str, Dict[str, object]] = field(default_factory=dict)
    unaligned_offset_profile: Dict[str, float] = field(default_factory=dict)
    sstore_profile: Dict[str, float] = field(default_factory=dict)
    value_bind_profile: Dict[str, float] = field(default_factory=dict)
    slot_bind_profile: Dict[str, float] = field(default_factory=dict)
    sload_bind_profile: Dict[str, float] = field(default_factory=dict)
    guard_profile: Dict[str, float] = field(default_factory=dict)
    equality_profile: Dict[str, float] = field(default_factory=dict)
    equality_support: Dict[str, int] = field(default_factory=dict)
    examples: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "topic0": self.topic0,
            "cluster_id": self.cluster_id,
            "support": dict(self.support),
            "pattern_tier": self.pattern_tier,
            "indexed_profile": dict(self.indexed_profile),
            "param_count_profile": dict(self.param_count_profile),
            "operand_profiles": dict(self.operand_profiles),
            "unaligned_offset_profile": dict(self.unaligned_offset_profile),
            "sstore_profile": dict(self.sstore_profile),
            "value_bind_profile": dict(self.value_bind_profile),
            "slot_bind_profile": dict(self.slot_bind_profile),
            "sload_bind_profile": dict(self.sload_bind_profile),
            "guard_profile": dict(self.guard_profile),
            "equality_profile": dict(self.equality_profile),
            "equality_support": dict(self.equality_support),
            "examples": list(self.examples),
        }


@dataclass
class Finding:
    type: str
    topic0: Optional[str]
    function_id: str
    severity: str
    score: float
    category: Optional[str] = None
    subcategory: Optional[str] = None
    evidence: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "type": self.type,
            "topic0": self.topic0,
            "function_id": self.function_id,
            "severity": self.severity,
            "score": self.score,
            "category": self.category,
            "subcategory": self.subcategory,
            "evidence": dict(self.evidence),
        }
