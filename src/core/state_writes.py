"""State write collection helpers."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .models import TacStatement
from .parser import normalize_var


def _parse_int_literal(expr: Optional[str]) -> Optional[int]:
    if not expr:
        return None
    cleaned = expr.strip().lower()
    if cleaned.startswith("(") and cleaned.endswith(")"):
        cleaned = cleaned[1:-1].strip()
    if cleaned.startswith("0x"):
        try:
            return int(cleaned, 16)
        except ValueError:
            return None
    if cleaned.isdigit():
        try:
            return int(cleaned, 10)
        except ValueError:
            return None
    return None


def _merge_trace_steps(existing: List[Any], incoming: List[Any]) -> List[Any]:
    seen: Set[Tuple[str, str]] = set()
    merged: List[Any] = []
    for step in existing + incoming:
        var = step.var or ""
        uid = getattr(step.statement, "uid", "")
        key = (var, uid)
        if key in seen:
            continue
        seen.add(key)
        merged.append(step)
    return merged


def _collect_sha3_slot_steps(stmt: Any, analyzer: Any, taint_info: Dict[str, Any]) -> List[Any]:
    if not stmt.block:
        return []
    block = analyzer.blocks.get(stmt.block)
    if not block:
        return []
    stmt_pos = analyzer.statement_positions.get(id(stmt), -1)
    if stmt_pos < 0:
        return []
    mem_start = None
    mem_len = None
    if stmt.uses:
        mem_start = _parse_int_literal(analyzer.resolve_operand_expression(stmt.uses[0]))
        if len(stmt.uses) > 1:
            mem_len = _parse_int_literal(
                analyzer.resolve_operand_expression(stmt.uses[1])
            )
    steps: List[Any] = []
    for block_stmt in block.statements:
        pos = analyzer.statement_positions.get(id(block_stmt), -1)
        if pos < 0 or pos >= stmt_pos:
            break
        if block_stmt.opcode.upper() != "MSTORE" or len(block_stmt.uses) < 2:
            continue
        ptr_expr = analyzer.resolve_operand_expression(block_stmt.uses[0])
        ptr_val = _parse_int_literal(ptr_expr)
        if ptr_val is None:
            continue
        if mem_start is not None and mem_len is not None:
            if ptr_val < mem_start or ptr_val >= mem_start + mem_len:
                continue
        elif ptr_val > 0x80:
            continue
        value_var = normalize_var(block_stmt.uses[1])
        if not value_var:
            continue
        steps.extend(analyzer._trace_to_input(value_var, taint_info))
    return steps


def _mapping_slot_steps(
    *,
    slot_var: Optional[str],
    analyzer: Any,
    taint_info: Dict[str, Any],
) -> List[Any]:
    if not slot_var:
        return []
    stmt = analyzer.var_def_stmt.get(slot_var)
    if not stmt:
        return []
    sha_steps: List[Any] = []
    if stmt.opcode.upper() in {"SHA3", "KECCAK256"}:
        sha_steps.extend(_collect_sha3_slot_steps(stmt, analyzer, taint_info))
        return sha_steps
    for token in stmt.uses:
        upstream_var = normalize_var(token)
        if not upstream_var:
            continue
        upstream_stmt = analyzer.var_def_stmt.get(upstream_var)
        if not upstream_stmt:
            continue
        if upstream_stmt.opcode.upper() in {"SHA3", "KECCAK256"}:
            sha_steps.extend(
                _collect_sha3_slot_steps(upstream_stmt, analyzer, taint_info)
            )
    return sha_steps


def collect_function_state_writes(
    statements: Sequence[TacStatement],
    analyzer: Any,
    taint_info: Dict[str, Any],
) -> Dict[str, List[Dict[str, Any]]]:
    """Return function -> list of observed SSTORE writes."""
    writes: Dict[str, List[Dict[str, Any]]] = {}
    for stmt in statements:
        if (stmt.opcode or "").upper() != "SSTORE":
            continue
        if len(stmt.uses) < 2:
            continue
        fn = stmt.function or "<global>"
        slot_token = stmt.uses[0]
        slot_expr = analyzer.resolve_operand_expression(slot_token)
        slot_var = normalize_var(slot_token)
        slot_origin = analyzer.describe_value_origin(slot_var) if slot_var else None
        slot_tainted = bool(slot_var and slot_var in taint_info)
        slot_path = analyzer._trace_to_input(slot_var, taint_info) if slot_var else []
        mapping_steps = _mapping_slot_steps(
            slot_var=slot_var, analyzer=analyzer, taint_info=taint_info
        )
        if mapping_steps:
            slot_path = _merge_trace_steps(slot_path, mapping_steps)
        mapping_steps = _mapping_slot_steps(
            slot_var=slot_var, analyzer=analyzer, taint_info=taint_info
        )
        if mapping_steps:
            slot_path = _merge_trace_steps(slot_path, mapping_steps)
        value_token = stmt.uses[1]
        value_var = normalize_var(value_token)
        value_origin = analyzer.describe_value_origin(value_var) if value_var else None
        value_tainted = bool(value_var and value_var in taint_info)
        value_path = analyzer._trace_to_input(value_var, taint_info) if value_var else []
        writes.setdefault(fn, []).append(
            {
                "statement_uid": stmt.uid,
                "slot": slot_expr,
                "slot_token": slot_token,
                "slot_var": slot_var,
                "slot_origin": slot_origin,
                "slot_tainted": slot_tainted,
                "slot_path": [
                    {
                        "var": step.var,
                        "opcode": step.statement.opcode,
                        "origin": step.origin,
                    }
                    for step in slot_path
                ],
                "value_token": value_token,
                "value_var": value_var,
                "value_origin": value_origin,
                "value_tainted": value_tainted,
                "value_path": [
                    {
                        "var": step.var,
                        "opcode": step.statement.opcode,
                        "origin": step.origin,
                    }
                    for step in value_path
                ],
            }
        )
    return writes


def collect_function_state_reads(
    statements: Sequence[TacStatement],
    analyzer: Any,
    taint_info: Dict[str, Any],
) -> Dict[str, List[Dict[str, Any]]]:
    """Return function -> list of observed SLOAD reads."""
    reads: Dict[str, List[Dict[str, Any]]] = {}
    for stmt in statements:
        if (stmt.opcode or "").upper() != "SLOAD":
            continue
        if not stmt.uses:
            continue
        fn = stmt.function or "<global>"
        slot_token = stmt.uses[0]
        slot_expr = analyzer.resolve_operand_expression(slot_token)
        slot_var = normalize_var(slot_token)
        slot_origin = analyzer.describe_value_origin(slot_var) if slot_var else None
        slot_tainted = bool(slot_var and slot_var in taint_info)
        slot_path = analyzer._trace_to_input(slot_var, taint_info) if slot_var else []
        reads.setdefault(fn, []).append(
            {
                "statement_uid": stmt.uid,
                "slot": slot_expr,
                "slot_token": slot_token,
                "slot_var": slot_var,
                "slot_origin": slot_origin,
                "slot_tainted": slot_tainted,
                "slot_path": [
                    {
                        "var": step.var,
                        "opcode": step.statement.opcode,
                        "origin": step.origin,
                    }
                    for step in slot_path
                ],
            }
        )
    return reads
