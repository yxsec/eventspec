"""Data structures shared across the TAC taint tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class TacStatement:
    offset: str
    opcode: str
    defs: Tuple[str, ...]
    def_literals: Tuple[Optional[str], ...]
    uses: Tuple[str, ...]
    raw: str
    function: Optional[str] = None
    block: Optional[str] = None
    block_predecessors: Tuple[str, ...] = field(default_factory=tuple)
    block_successors: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def uid(self) -> str:
        func = self.function or "<global>"
        return f"{func}@{self.offset}"


@dataclass
class TraceStep:
    var: str
    statement: TacStatement
    origin: Optional[str] = None


@dataclass
class LogOperandReport:
    label: str
    token: str
    var: Optional[str]
    tainted: bool
    literal: Optional[str] = None
    signature: Optional[str] = None
    origin: Optional[str] = None
    path: List[TraceStep] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "label": self.label,
            "token": self.token,
            "var": self.var,
            "tainted": self.tainted,
            "literal": self.literal,
            "signature": self.signature,
            "origin": self.origin,
            "path": [trace_step_to_dict(step) for step in self.path],
        }


@dataclass
class MemoryOperandReport:
    label: str
    offset: int
    token: str
    var: Optional[str]
    tainted: bool
    literal: Optional[str] = None
    origin: Optional[str] = None
    path: List[TraceStep] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "label": self.label,
            "offset": self.offset,
            "token": self.token,
            "var": self.var,
            "tainted": self.tainted,
            "literal": self.literal,
            "origin": self.origin,
            "path": [trace_step_to_dict(step) for step in self.path],
        }


@dataclass
class LogReport:
    statement: TacStatement
    operands: List[LogOperandReport]
    event_topic0: Optional[str] = None
    event_signature: Optional[str] = None
    entry_points: List[str] = field(default_factory=list)
    memory_operands: List[MemoryOperandReport] = field(default_factory=list)
    guard_categories: List[str] = field(default_factory=list)
    greed_results: List["GreedSliceResult"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "function": self.statement.function,
            "block": self.statement.block,
            "offset": self.statement.offset,
            "opcode": self.statement.opcode,
            "event_topic0": self.event_topic0,
            "event_signature": self.event_signature,
            "entry_points": self.entry_points,
            "operands": [operand.to_dict() for operand in self.operands],
            "memory_operands": [operand.to_dict() for operand in self.memory_operands],
            "guards": self.guard_categories,
            "greed_results": [result.to_dict() for result in self.greed_results],
        }


@dataclass
class GreedSliceResult:
    operand: str
    var: str
    status: str
    value: Optional[str] = None
    calldata: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "operand": self.operand,
            "var": self.var,
            "status": self.status,
            "value": self.value,
            "calldata": self.calldata,
            "details": self.details,
        }


@dataclass
class TaintProvenance:
    parent_var: Optional[str]
    statement: TacStatement


@dataclass
class EntryPointIndex:
    block_to_function: Dict[str, str]
    function_reachability: Dict[str, List[str]]
    function_names: Dict[str, str]
    function_reachability_ids: Dict[str, List[str]]
    callsites_by_callee: Dict[str, List[str]] = field(default_factory=dict)
    public_selectors: Dict[str, str] = field(default_factory=dict)

    def entry_points_for_block(self, block_id: Optional[str]) -> List[str]:
        if not block_id:
            return []
        func_id = self.block_to_function.get(block_id)
        if not func_id:
            return []
        return self.function_reachability.get(func_id, [])

    def entry_point_ids_for_block(self, block_id: Optional[str]) -> List[str]:
        if not block_id:
            return []
        func_id = self.block_to_function.get(block_id)
        if not func_id:
            return []
        return self.function_reachability_ids.get(func_id, [])

    def function_display_name(self, func_id: str) -> str:
        return self.function_names.get(func_id, func_id)

    def callsites_for_function(self, func_id: str) -> List[str]:
        return self.callsites_by_callee.get(func_id, [])

    def entry_point_display(self, func_id: str) -> str:
        name = (self.function_names.get(func_id) or "").strip()
        if name and name != func_id and name != "__function_selector__":
            return name
        selector = self.public_selectors.get(func_id)
        return selector or func_id


def trace_step_to_dict(step: TraceStep) -> Dict[str, object]:
    stmt = step.statement
    return {
        "var": step.var,
        "statement": format_statement(stmt),
        "opcode": stmt.opcode,
        "function": stmt.function,
        "block": stmt.block,
        "offset": stmt.offset,
        "origin": step.origin,
    }


def format_statement(stmt: TacStatement) -> str:
    func = stmt.function or "<global>"
    block = f" block {stmt.block}" if stmt.block else ""
    defs = ", ".join(stmt.defs)
    uses = ", ".join(stmt.uses)
    if defs:
        expr = f"{defs} = {stmt.opcode}"
    else:
        expr = stmt.opcode
    if uses:
        expr = f"{expr} {uses}"
    return f"{func}@{stmt.offset}{block}: {expr}"
