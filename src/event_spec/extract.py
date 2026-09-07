"""Extract event observations for the empirical spec database."""

from __future__ import annotations

import argparse
import hashlib
import re
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

from src.core.access_control import (
    annotate_access_control,
    classify_access_control,
    traces_to_opcode,
)
from src.core.analysis import TaintAnalyzer
from src.core.cfg import compute_dominators
from src.core.constants import DEFAULT_EVENT_SIGNATURE_PATH, DEFAULT_SOURCE_OPCODES
from src.core.facts import load_entrypoint_index, load_event_signatures
from src.core.models import GreedSliceResult, LogReport, TacStatement, TraceStep
from src.core.parser import extract_literal, normalize_var, parse_tac_file
from src.core.state_writes import collect_function_state_reads, collect_function_state_writes

from .schema import (
    EventObservation,
    FunctionSummary,
    MemorySlice,
    OperandObservation,
    SstoreSummary,
)
from .agg_store import AggregateStore
from .utils import ensure_dir, unique_preserve


_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_INT_RE = re.compile(r"^[0-9]+$")
_ARG_ORIGIN_RE = re.compile(r"^arg\s*arg(\d+)$", re.IGNORECASE)
_CHECK_EXIT_OPS = {"REVERT", "THROW", "INVALID"}
_CHECK_SOURCE_OPS = {"CALLER", "ORIGIN", "CALLDATALOAD", "CALLDATACOPY", "SLOAD"}
_COMPILER_CHECK_OPS = {"CALLVALUE", "CALLDATASIZE"}
_TRACE_THROUGH_OPS = {
    "PHI",
    "MOV",
    "ISZERO",
    "EQ",
    "LT",
    "GT",
    "SLT",
    "SGT",
    "ADD",
    "SUB",
    "MUL",
    "DIV",
    "SDIV",
    "MOD",
    "SMOD",
    "AND",
    "OR",
    "XOR",
    "SHL",
    "SHR",
    "SAR",
    "NOT",
}


def _is_literal(text: str) -> bool:
    stripped = text.strip()
    return bool(_HEX_RE.match(stripped) or _INT_RE.match(stripped))


def _parse_int_literal(text: str) -> Optional[int]:
    stripped = text.strip()
    if _HEX_RE.match(stripped):
        return int(stripped, 16)
    if _INT_RE.match(stripped):
        return int(stripped, 10)
    return None


def _parse_int_expr(text: str) -> Optional[int]:
    stripped = text.strip()
    value = _parse_int_literal(stripped)
    if value is not None:
        return value
    if "+" in stripped:
        parts = [part.strip() for part in stripped.split("+") if part.strip()]
        if len(parts) == 2:
            left = _parse_int_literal(parts[0])
            right = _parse_int_literal(parts[1])
            if left is not None and right is not None:
                return left + right
    if "-" in stripped:
        parts = [part.strip() for part in stripped.split("-") if part.strip()]
        if len(parts) == 2:
            left = _parse_int_literal(parts[0])
            right = _parse_int_literal(parts[1])
            if left is not None and right is not None:
                return left - right
    return None


def _slot_kind(slot_expr: str) -> str:
    expr = slot_expr.strip().lower()
    if "sha3(" in expr:
        return "mapping_like"
    if _is_literal(expr):
        return "const"
    if expr.startswith("(") and expr.endswith(")") and " + " in expr:
        inner = expr[1:-1]
        parts = [part.strip() for part in inner.split("+", 1)]
        if len(parts) == 2 and (_is_literal(parts[0]) or _is_literal(parts[1])):
            return "linear"
    return "unknown"


def _deps_from_expr(expr: str) -> List[str]:
    lowered = (expr or "").lower()
    deps: List[str] = []
    if "calldataload(" in lowered:
        deps.append("CALLDATA")
    if "sload(" in lowered:
        deps.append("SLOAD")
    if "sha3(" in lowered:
        deps.append("SHA3")
    if _is_literal(lowered):
        deps.append("CONST")
    if not deps:
        deps.append("OTHER")
    return deps


def _deps_from_origin(origin: Optional[str]) -> List[str]:
    if not origin:
        return ["OTHER"]
    lowered = origin.lower()
    deps: List[str] = []
    if "calldataload" in lowered:
        deps.append("CALLDATA")
    if "sload" in lowered:
        deps.append("SLOAD")
    if "sha3" in lowered:
        deps.append("SHA3")
    if _is_literal(lowered):
        deps.append("CONST")
    if not deps:
        deps.append("OTHER")
    return deps


def _origin_key(origin: Optional[str]) -> Optional[str]:
    if not origin:
        return None
    lowered = origin.lower()
    if lowered.startswith("calldataload offset"):
        return lowered
    if lowered.startswith("sload slot"):
        return lowered
    return None


def _arg_index_from_origin(origin: Optional[str]) -> Optional[int]:
    if not origin:
        return None
    lowered = origin.strip().lower()
    match = _ARG_ORIGIN_RE.match(lowered)
    if match:
        return int(match.group(1))
    if lowered.startswith("calldataload offset"):
        expr = lowered[len("calldataload offset"):].strip()
        expr = expr.strip("() ")
        offset = _parse_int_expr(expr)
        if offset is None:
            return None
        if offset < 4:
            return None
        if (offset - 4) % 32 != 0:
            return None
        return (offset - 4) // 32
    return None


def _collect_path_ops(path: Iterable[TraceStep]) -> List[str]:
    return unique_preserve(step.statement.opcode for step in path if step.statement.opcode)


def _source_kinds(origin: Optional[str], path: Iterable[TraceStep], literal: Optional[str]) -> List[str]:
    kinds: List[str] = []
    if origin:
        lowered = origin.lower()
        if lowered.startswith("calldataload"):
            kinds.append("CALLDATA")
        if lowered.startswith("sload"):
            kinds.append("SLOAD")
        if lowered.startswith("mload"):
            kinds.append("MLOAD")
        if lowered.startswith("arg"):
            kinds.append("ARG")
        if _arg_index_from_origin(origin) is not None:
            kinds.append("ARG")
    if literal:
        kinds.append("CONST")
    for step in path:
        opcode = step.statement.opcode.upper()
        if opcode == "CALLER":
            kinds.append("CALLER")
        elif opcode == "CALLVALUE":
            kinds.append("CALLVALUE")
        elif opcode == "ORIGIN":
            kinds.append("ORIGIN")
        elif opcode == "SHA3":
            kinds.append("SHA3")
        elif opcode == "CONST":
            kinds.append("CONST")
    if not kinds:
        kinds.append("OTHER")
    return unique_preserve(kinds)


def _dep_kinds(path: Iterable[TraceStep]) -> List[str]:
    categories: List[str] = []
    for step in path:
        opcode = step.statement.opcode.upper()
        if opcode in {"ADD", "SUB", "MUL", "DIV", "MOD", "EXP", "SDIV", "SMOD"}:
            categories.append("arith")
        elif opcode in {"AND", "OR", "XOR", "SHL", "SHR", "SAR", "NOT"}:
            categories.append("bitwise")
        elif opcode in {"EQ", "LT", "GT", "SLT", "SGT", "ISZERO"}:
            categories.append("compare")
        elif opcode == "SHA3":
            categories.append("hash")
        elif opcode in {"MLOAD", "MSTORE", "MSTORE8"}:
            categories.append("mem")
        elif opcode in {"SLOAD", "SSTORE"}:
            categories.append("storage")
        elif opcode in {"CALLDATALOAD", "CALLDATACOPY", "CALLDATASIZE"}:
            categories.append("data")
        elif opcode in {
            "CALLER",
            "CALLVALUE",
            "ORIGIN",
            "ADDRESS",
            "TIMESTAMP",
            "NUMBER",
            "GASPRICE",
            "CHAINID",
            "COINBASE",
        }:
            categories.append("env")
        elif opcode in {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"}:
            categories.append("call")
    return unique_preserve(categories)


def _token_is_literal(token: str, analyzer: TaintAnalyzer) -> bool:
    literal = extract_literal(token)
    if literal:
        return True
    var = normalize_var(token)
    if not var:
        return False
    return bool(analyzer.var_literals.get(var))


def _constraint_candidates(
    path: Iterable[TraceStep],
    analyzer: TaintAnalyzer,
) -> List[str]:
    candidates: List[str] = []
    for step in path:
        stmt = step.statement
        opcode = stmt.opcode.upper()
        if opcode == "EQ" and any(_token_is_literal(token, analyzer) for token in stmt.uses):
            candidates.append("eq_const")
        if opcode in {"LT", "GT", "SLT", "SGT"} and any(
            _token_is_literal(token, analyzer) for token in stmt.uses
        ):
            candidates.append("cmp_const")
        if opcode == "ISZERO":
            candidates.append("nonzero")
        if opcode == "AND" and any(_token_is_literal(token, analyzer) for token in stmt.uses):
            candidates.append("masking")
        if opcode in {"SHL", "SHR", "SAR"}:
            candidates.append("shift")
    return unique_preserve(candidates)


def _literal_class(literal: Optional[str]) -> Optional[str]:
    if not literal:
        return None
    text = literal.strip().lower()
    if not text:
        return None
    try:
        value = int(text, 16) if text.startswith("0x") else int(text, 10)
    except ValueError:
        return None
    return "zero" if value == 0 else "nonzero"


def _normalize_label(label: str) -> str:
    if label.startswith("data@"):
        return "data_unaligned"
    return label


def _build_operand_observation(
    label: str,
    is_topic: bool,
    origin: Optional[str],
    literal: Optional[str],
    path: List[TraceStep],
    memory_slice: Optional[MemorySlice],
    analyzer: TaintAnalyzer,
) -> OperandObservation:
    return OperandObservation(
        label=_normalize_label(label),
        is_topic=is_topic,
        source_kinds=_source_kinds(origin, path, literal),
        dep_kinds=_dep_kinds(path),
        def_use_ops=_collect_path_ops(path),
        memory_slice=memory_slice,
        arg_index=_arg_index_from_origin(origin),
        constraint_candidates=_constraint_candidates(path, analyzer),
        literal_class=_literal_class(literal),
    )


def _opcode_footprint(paths: Dict[str, List[TraceStep]]) -> Dict[str, int]:
    counter: Counter[str] = Counter()
    for path in paths.values():
        for step in path:
            opcode = step.statement.opcode
            if opcode:
                counter[opcode] += 1
    return dict(counter)


def _param_counts(operands: Iterable[OperandObservation]) -> Dict[str, int]:
    topics = 0
    data = 0
    for operand in operands:
        if operand.label.startswith("topic"):
            topics += 1
        elif operand.label.startswith("data"):
            data += 1
    return {"topics": topics, "data": data}


def _log_shape_key(report: LogReport) -> str:
    labels: List[str] = []
    for operand in report.operands:
        if operand.label in {"mem_start", "mem_len"}:
            continue
        labels.append(_normalize_label(operand.label))
    for mem_operand in report.memory_operands:
        labels.append(_normalize_label(mem_operand.label))
    topic_labels = sorted(
        {label for label in labels if label.startswith("topic") and label != "topic0"}
    )
    topics_count = sum(1 for label in labels if label.startswith("topic"))
    data_count = sum(1 for label in labels if label.startswith("data"))
    indexed_key = ",".join(topic_labels) if topic_labels else "-"
    return f"topics:{topics_count}|data:{data_count}|indexed:{indexed_key}"


def _hash_contract(tac_path: Path) -> str:
    digest = hashlib.sha256(tac_path.read_bytes()).hexdigest()
    return digest


def _normalize_guard_categories(categories: Iterable[str]) -> List[str]:
    normalized: List[str] = []
    seen: set[str] = set()
    for category in categories or []:
        label = str(category or "").strip().lower()
        if not label or label in seen:
            continue
        seen.add(label)
        normalized.append(label)
    return normalized


def _block_has_check_exit(block: Optional[object]) -> bool:
    if not block:
        return False
    return any(stmt.opcode.upper() in _CHECK_EXIT_OPS for stmt in block.statements)


def _block_has_reachable_check_exit(
    block_id: Optional[str],
    blocks: Dict[str, object],
    block_reachability: Dict[str, set[str]],
) -> bool:
    if not block_id:
        return False
    if _block_has_check_exit(blocks.get(block_id)):
        return True
    for reachable in block_reachability.get(block_id, set()):
        if _block_has_check_exit(blocks.get(reachable)):
            return True
    return False


def _traces_to_opcode_extended(
    var: Optional[str],
    target_opcodes: Iterable[str],
    def_map: Dict[str, TacStatement],
    depth: int = 0,
) -> bool:
    if not var or depth > 8:
        return False
    stmt = def_map.get(var)
    if not stmt:
        return False
    opcode = stmt.opcode.upper()
    if opcode in target_opcodes:
        return True
    if opcode in _TRACE_THROUGH_OPS:
        return any(
            _traces_to_opcode_extended(
                normalize_var(token),
                target_opcodes,
                def_map,
                depth + 1,
            )
            for token in stmt.uses
        )
    if opcode == "MLOAD":
        if not stmt.uses:
            return False
        return _traces_to_opcode_extended(
            normalize_var(stmt.uses[0]),
            target_opcodes,
            def_map,
            depth + 1,
        )
    if opcode == "SLOAD":
        return "SLOAD" in target_opcodes
    return False


def _check_sources_for_block(
    block_id: Optional[str],
    dominators: Dict[str, set[str]],
    blocks: Dict[str, object],
    def_map: Dict[str, TacStatement],
    block_reachability: Dict[str, set[str]],
) -> List[str]:
    if not block_id:
        return []
    dom_blocks = dominators.get(block_id, {block_id})
    sources: set[str] = set()
    for dom in dom_blocks:
        block = blocks.get(dom)
        if not block or not block.successors:
            continue
        if not any(
            _block_has_reachable_check_exit(succ, blocks, block_reachability)
            for succ in block.successors
        ):
            continue
        for stmt in block.statements:
            if stmt.opcode.upper() != "JUMPI":
                continue
            matched = False
            cond_var = normalize_var(stmt.uses[-1]) if stmt.uses else None
            if not cond_var:
                continue
            for source in _CHECK_SOURCE_OPS:
                if traces_to_opcode(cond_var, {source}, def_map):
                    sources.add(source.lower())
                    matched = True
            if not matched:
                if _traces_to_opcode_extended(
                    cond_var,
                    _COMPILER_CHECK_OPS,
                    def_map,
                ):
                    continue
                sources.add("require")
    return sorted(sources)


def _check_sources_for_log(
    report: LogReport,
    dominators: Dict[str, set[str]],
    blocks: Dict[str, object],
    def_map: Dict[str, object],
    block_reachability: Dict[str, set[str]],
) -> List[str]:
    return _check_sources_for_block(
        report.statement.block,
        dominators,
        blocks,
        def_map,
        block_reachability,
    )


def _resolve_literal_token(
    token: str,
    def_map: Dict[str, TacStatement],
) -> Optional[str]:
    literal = extract_literal(token)
    if literal:
        return literal.lower()
    var = normalize_var(token)
    if not var:
        return None
    stmt = def_map.get(var)
    if not stmt:
        return None
    for literal in stmt.def_literals:
        if literal:
            return literal.lower()
    return None


def _callee_arg_prefix(callee_func: str) -> Optional[str]:
    if not callee_func:
        return None
    func_id = callee_func.strip()
    if func_id.startswith("0x"):
        func_id = func_id[2:]
    if not func_id:
        return None
    return f"v{func_id}arg"


def _callprivate_arg_def_map(
    callee_func: str,
    callsite_block: str,
    blocks: Dict[str, object],
    def_map: Dict[str, TacStatement],
) -> Dict[str, TacStatement]:
    block = blocks.get(callsite_block)
    if not block or not callee_func:
        return {}
    prefix = _callee_arg_prefix(callee_func)
    if not prefix:
        return {}
    for stmt in block.statements:
        if stmt.opcode.upper() != "CALLPRIVATE" or not stmt.uses:
            continue
        callee_literal = _resolve_literal_token(stmt.uses[0], def_map)
        if not callee_literal or callee_literal.lower() != callee_func.lower():
            continue
        arg_defs: Dict[str, TacStatement] = {}
        for idx, token in enumerate(stmt.uses[1:]):
            var = normalize_var(token)
            if not var:
                continue
            arg_var = f"{prefix}{idx}"
            if arg_var in def_map or arg_var in arg_defs:
                continue
            arg_defs[arg_var] = TacStatement(
                offset="arg",
                opcode="MOV",
                defs=(arg_var,),
                def_literals=(None,),
                uses=(var,),
                raw=f"{arg_var} = MOV {var}",
                function=callee_func,
                block=None,
            )
        return arg_defs
    return {}


def _check_sources_interprocedural(
    report: LogReport,
    entry_index: Optional[object],
    entry_ids: List[str],
    dominators: Dict[str, set[str]],
    blocks: Dict[str, object],
    def_map: Dict[str, object],
    block_reachability: Dict[str, set[str]],
) -> List[str]:
    if not entry_index or not entry_ids:
        return []
    callee_func = report.statement.function
    if not callee_func:
        return []
    entry_set = set(entry_ids)
    sources: set[str] = set()
    visited_funcs: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(callee_func, 0)])
    depth_limit = 8
    while queue:
        current_func, depth = queue.popleft()
        if current_func in visited_funcs:
            continue
        visited_funcs.add(current_func)
        if depth > depth_limit:
            continue
        callsites = entry_index.callsites_by_callee.get(current_func, [])
        for callsite in callsites:
            caller_func = entry_index.block_to_function.get(callsite)
            if not caller_func:
                continue
            reachable_entries = set(
                entry_index.function_reachability_ids.get(caller_func, [])
            )
            if not reachable_entries or not (reachable_entries & entry_set):
                continue
            callsite_sources = _check_sources_for_block(
                callsite, dominators, blocks, def_map, block_reachability
            )
            for source in callsite_sources:
                sources.add(f"interprocedural:{source}")
            if current_func == callee_func:
                arg_def_map = _callprivate_arg_def_map(
                    current_func, callsite, blocks, def_map
                )
                if arg_def_map:
                    augmented_def_map = dict(def_map)
                    augmented_def_map.update(arg_def_map)
                    callee_sources = _check_sources_for_block(
                        report.statement.block,
                        dominators,
                        blocks,
                        augmented_def_map,
                        block_reachability,
                    )
                    for source in callee_sources:
                        sources.add(f"interprocedural:{source}")
            queue.append((caller_func, depth + 1))
    return sorted(sources)

def _filter_sstores_for_log(
    *,
    log_report: LogReport,
    sstore_records: List[Dict[str, object]],
    analyzer: TaintAnalyzer,
) -> tuple[List[Dict[str, object]], str]:
    log_block = log_report.statement.block
    log_index = analyzer.statement_positions.get(id(log_report.statement))
    block_reachability = analyzer.block_reachability
    if not log_block or log_block not in analyzer.blocks:
        return list(sstore_records), "same_function_all"
    if log_index is None:
        return list(sstore_records), "same_function_all"
    filtered: List[Dict[str, object]] = []
    for record in sstore_records:
        block = record.get("block")
        if not block:
            continue
        if block == log_block:
            index = record.get("index")
            if index is None:
                return list(sstore_records), "same_function_all"
            if index < log_index:
                filtered.append(record)
            continue
        reachable = block_reachability.get(block, set())
        if log_block in reachable:
            filtered.append(record)
    return filtered, "reachable_to_log"


def _value_bindings(
    *,
    operands: List[OperandObservation],
    operand_paths: Dict[str, List[TraceStep]],
    sstore_records: List[Dict[str, object]],
    sload_records: List[Dict[str, object]],
) -> Dict[str, object]:
    bind_labels: Dict[str, int] = {}
    bind_labels_slot: Dict[str, int] = {}
    bind_labels_sload: Dict[str, int] = {}
    for operand in operands:
        label = operand.label
        op_path = operand_paths.get(label, [])
        op_vars = {step.var for step in op_path if step.var}
        op_origins = {_origin_key(step.origin) for step in op_path if _origin_key(step.origin)}
        if op_path:
            direct_origin = _origin_key(op_path[0].origin)
            if direct_origin:
                op_origins.add(direct_origin)
        bound_count = 0
        bound_slot_count = 0
        bound_sload_count = 0
        for record in sstore_records:
            value_path = record.get("value_path", [])
            value_vars = {entry.get("var") for entry in value_path if entry.get("var")}
            value_origins = {_origin_key(entry.get("origin")) for entry in value_path if _origin_key(entry.get("origin"))}
            value_origin = _origin_key(record.get("value_origin")) if record.get("value_origin") else None
            if value_origin:
                value_origins.add(value_origin)
            if op_vars & value_vars or op_origins & value_origins:
                bound_count += 1
            slot_path = record.get("slot_path", [])
            slot_vars = {entry.get("var") for entry in slot_path if entry.get("var")}
            slot_origins = {_origin_key(entry.get("origin")) for entry in slot_path if _origin_key(entry.get("origin"))}
            slot_origin = _origin_key(record.get("slot_origin")) if record.get("slot_origin") else None
            if slot_origin:
                slot_origins.add(slot_origin)
            if op_vars & slot_vars or op_origins & slot_origins:
                bound_slot_count += 1
        for record in sload_records:
            slot_path = record.get("slot_path", [])
            slot_vars = {entry.get("var") for entry in slot_path if entry.get("var")}
            slot_origins = {_origin_key(entry.get("origin")) for entry in slot_path if _origin_key(entry.get("origin"))}
            slot_origin = _origin_key(record.get("slot_origin")) if record.get("slot_origin") else None
            if slot_origin:
                slot_origins.add(slot_origin)
            if op_vars & slot_vars or op_origins & slot_origins:
                bound_sload_count += 1
        if bound_count > 0:
            bind_labels[label] = bound_count
        if bound_slot_count > 0:
            bind_labels_slot[label] = bound_slot_count
        if bound_sload_count > 0:
            bind_labels_sload[label] = bound_sload_count
    bind_any_topic = any(label.startswith("topic") for label in bind_labels)
    bind_any_data = any(label.startswith("data") for label in bind_labels)
    bind_any_topic_slot = any(label.startswith("topic") for label in bind_labels_slot)
    bind_any_data_slot = any(label.startswith("data") for label in bind_labels_slot)
    bind_any_topic_sload = any(label.startswith("topic") for label in bind_labels_sload)
    bind_any_data_sload = any(label.startswith("data") for label in bind_labels_sload)
    return {
        "bind_any_topic": bind_any_topic,
        "bind_any_data": bind_any_data,
        "bind_labels": bind_labels,
        "bind_any_topic_slot": bind_any_topic_slot,
        "bind_any_data_slot": bind_any_data_slot,
        "bind_labels_slot": bind_labels_slot,
        "bind_any_topic_sload": bind_any_topic_sload,
        "bind_any_data_sload": bind_any_data_sload,
        "bind_labels_sload": bind_labels_sload,
    }


def _merge_paths(existing: List[TraceStep], incoming: List[TraceStep]) -> List[TraceStep]:
    seen: set[tuple[str, str]] = set()
    merged: List[TraceStep] = []
    for step in existing + incoming:
        key = (step.var or "", step.statement.uid)
        if key in seen:
            continue
        seen.add(key)
        merged.append(step)
    return merged


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract event observations from a TAC analysis run."
    )
    parser.add_argument(
        "--tac",
        required=True,
        type=Path,
        help="Path to contract.tac, a directory of *.tac files, or a list file.",
    )
    parser.add_argument("--out", required=True, type=Path, help="Output directory")
    parser.add_argument(
        "--tier",
        choices=("core", "open"),
        default="open",
        help="Corpus tier for these observations",
    )
    parser.add_argument("--symbolic", action="store_true", help="Enable Greed slices")
    parser.add_argument(
        "--symbolic-eq-constant-only",
        action="store_true",
        help="Keep equality records only when one operand is provably constant (symbolic mode only).",
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
        "--symbolic-mstore-concretize",
        action="store_true",
        help="Enable Greed MSTORE offset concretization (symbolic mode only).",
    )
    parser.add_argument("--timeout", type=int, default=15, help="Greed solver timeout (seconds)")
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to existing outputs and skip contracts already present.",
    )
    return parser


def _operand_var_for_label(report: LogReport, label: str) -> Optional[str]:
    for result in report.greed_results:
        if result.operand == label:
            return result.var
    return None


def _collect_equality_records(
    log_reports: List[LogReport],
    *,
    contract_id: str,
    corpus_tier: str,
    executor,
    constant_only: bool = False,
) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    result_lookup: Dict[str, Dict[str, GreedSliceResult]] = {
        report.statement.uid: {
            result.operand: result for result in report.greed_results if result.operand
        }
        for report in log_reports
    }
    constant_cache: Dict[Tuple[str, str], Tuple[bool, Optional[str]]] = {}

    def constant_info(log_uid: str, label: str) -> Tuple[bool, Optional[str]]:
        key = (log_uid, label)
        if key in constant_cache:
            return constant_cache[key]
        result = result_lookup.get(log_uid, {}).get(label)
        if not result or result.status != "sat" or result.value is None or not result.var:
            constant_cache[key] = (False, None)
            return constant_cache[key]
        status = executor.check_var_relation_feasible(
            log_uid,
            result.var,
            "!=",
            result.value,
            rhs_is_var=False,
        )
        is_const = status == "unsat"
        constant_cache[key] = (is_const, result.value if is_const else None)
        return constant_cache[key]

    logs_by_key: Dict[str, List[LogReport]] = defaultdict(list)
    for report in log_reports:
        key = report.event_signature or report.event_topic0
        if key:
            logs_by_key[key].append(report)
    for reports in logs_by_key.values():
        if len(reports) < 2:
            continue
        labels = {
            result.operand
            for report in reports
            for result in report.greed_results
            if result.operand
        }
        for label in labels:
            for i in range(len(reports)):
                for j in range(i + 1, len(reports)):
                    report_a = reports[i]
                    report_b = reports[j]
                    topic0 = report_a.event_topic0
                    if not topic0 or report_b.event_topic0 != topic0:
                        continue
                    var_a = _operand_var_for_label(report_a, label)
                    var_b = _operand_var_for_label(report_b, label)
                    if not var_a or not var_b:
                        continue
                    const_a = False
                    const_b = False
                    value_a = None
                    value_b = None
                    if constant_only:
                        const_a, value_a = constant_info(report_a.statement.uid, label)
                        const_b, value_b = constant_info(report_b.statement.uid, label)
                        if not (const_a or const_b):
                            continue
                    status = executor.check_joint_var_relation_feasible(
                        report_a.statement.uid, var_a, report_b.statement.uid, var_b, "=="
                    )
                    if status not in {"possible", "unsat"}:
                        continue
                    records.append(
                        {
                            "contract_id": contract_id,
                            "corpus_tier": corpus_tier,
                            "topic0": topic0,
                            "label": label,
                            "status": status,
                            "function_a": report_a.statement.function or "<global>",
                            "function_b": report_b.statement.function or "<global>",
                            "log_a": report_a.statement.uid,
                            "log_b": report_b.statement.uid,
                            "const_a": const_a,
                            "const_b": const_b,
                            "value_a": value_a,
                            "value_b": value_b,
                        }
                    )
    return records


def extract_contract(
    tac_path: Path,
    tier: str,
    *,
    symbolic: bool = False,
    symbolic_mstore_concretize: bool = False,
    symbolic_eq_constant_only: bool = False,
    symbolic_log_limit: int = 2,
    timeout: int = 15,
) -> tuple[List[EventObservation], List[FunctionSummary], List[Dict[str, object]]]: # Return EventObservation,FunctionSummary, equality_records
    if not tac_path.exists():
        raise SystemExit(f"TAC file not found: {tac_path}")
    statements = parse_tac_file(tac_path) # parse tac file to TacStatement 
    if not statements:
        raise SystemExit("No TAC statements found.")

    event_sig_path = DEFAULT_EVENT_SIGNATURE_PATH #Signature db
    event_sig_map = load_event_signatures(event_sig_path) if event_sig_path.exists() else {} # mapping signature to name
    entry_index = load_entrypoint_index(tac_path.parent) #Build an entrypoint from TAC(call graph reachability)

    analyzer = TaintAnalyzer(
        statements,
        DEFAULT_SOURCE_OPCODES,
        event_signatures=event_sig_map,
        entrypoint_index=entry_index,
    )
    log_reports, taint_info = analyzer.analyze() # taint data

    dominators = compute_dominators(analyzer.blocks) # Compute CFG dominator sets per function
    block_guard_categories = classify_access_control(statements) # access control for block
    annotate_access_control(
        log_reports,
        entry_index=entry_index,
        dominators=dominators,
        block_guard_categories=block_guard_categories,
    ) # access control block for function

    contract_id = _hash_contract(tac_path) # to dep

    equality_records: List[Dict[str, object]] = []
    if symbolic:
        try:
            from src.integrations.greed_bridge import GreedSliceExecutor
            from src.core.slices import build_log_slices
        except Exception as exc:  # pragma: no cover - optional dependency
            print(f"[greed] {exc}")
        else:
            log_key_counts: Dict[str, int] = defaultdict(int) # event signature count
            for report in log_reports: # record the count(event_signature)>2
                key = report.event_signature or report.event_topic0
                if key:
                    log_key_counts[key] += 1
            repeated_logs = [
                report
                for report in log_reports
                if (report.event_signature or report.event_topic0)
                and log_key_counts.get(report.event_signature or report.event_topic0, 0) > 1
            ]
            grouped_logs: Dict[str, List[LogReport]] = defaultdict(list) # grouped_logs
            for report in repeated_logs:
                key = report.event_signature or report.event_topic0
                if key:
                    grouped_logs[key].append(report)
            limit = symbolic_log_limit
            if limit is None or limit <= 0:
                limited_logs = [
                    report for reports in grouped_logs.values() for report in reports
                ]
            else:
                limited_logs = []
                for reports in grouped_logs.values():
                    limited_logs.extend(reports[:limit])
            slices = build_log_slices(
                limited_logs,
                dominators,
                blocks=analyzer.blocks,
                include_untainted=True,
            ) # program slicing
            if slices:
                try:
                    executor = GreedSliceExecutor(
                        target_dir=tac_path.parent,
                        solver_timeout=timeout,
                        mstore_concretize=symbolic_mstore_concretize,
                    )
                except RuntimeError as exc:
                    print(f"[greed] {exc}")
                else:
                    results = executor.solve_slices(slices)
                    for report in log_reports:
                        report.greed_results = results.get(report.statement.uid, [])
                    equality_records = _collect_equality_records(
                        log_reports,
                        contract_id=contract_id,
                        corpus_tier=tier,
                        executor=executor,
                        constant_only=symbolic_eq_constant_only,
                    ) # add quality records for diff analysis

    function_state_writes = collect_function_state_writes(statements, analyzer, taint_info) # collect sstore inform
    function_state_reads = collect_function_state_reads(statements, analyzer, taint_info) # collect sload inform
    stmt_by_uid = {stmt.uid: stmt for stmt in statements} # stmt uid to block statement

    sstore_records_by_fn: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for fn, writes in function_state_writes.items():
        for write in writes:
            stmt = stmt_by_uid.get(write.get("statement_uid"))
            if not stmt:
                continue
            slot_expr = write.get("slot") or ""
            slot_kind = _slot_kind(slot_expr)
            record = {
                "function": fn,
                "block": stmt.block,
                "index": analyzer.statement_positions.get(id(stmt)),
                "slot": slot_expr,
                "slot_kind": slot_kind,
                "slot_deps": _deps_from_expr(slot_expr),
                "slot_origin": write.get("slot_origin"),
                "slot_path": write.get("slot_path", []),
                "value_origin": write.get("value_origin"),
                "value_deps": _deps_from_origin(write.get("value_origin")),
                "value_path": write.get("value_path", []),
            }
            sstore_records_by_fn[fn].append(record)
    sload_records_by_fn: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for fn, reads in function_state_reads.items():
        for read in reads:
            stmt = stmt_by_uid.get(read.get("statement_uid"))
            if not stmt:
                continue
            slot_expr = read.get("slot") or ""
            record = {
                "function": fn,
                "block": stmt.block,
                "index": analyzer.statement_positions.get(id(stmt)),
                "slot": slot_expr,
                "slot_deps": _deps_from_expr(slot_expr),
                "slot_origin": read.get("slot_origin"),
                "slot_path": read.get("slot_path", []),
            }
            sload_records_by_fn[fn].append(record)

    observations: List[EventObservation] = []

    for report in log_reports:
        if not report.event_topic0:
            continue
        fn = report.statement.function or "<global>"
        fn_name = entry_index.function_names.get(fn) if entry_index else None
        fn_selector = entry_index.public_selectors.get(fn) if entry_index else None
        entry_ids = (
            entry_index.entry_point_ids_for_block(report.statement.block)
            if entry_index
            else []
        )
        operand_observations: List[OperandObservation] = []
        operand_paths: Dict[str, List[TraceStep]] = {}

        for operand in report.operands:
            if operand.label in {"mem_start", "mem_len"}:
                continue
            label = operand.label
            normalized = _normalize_label(label)
            operand_obs = _build_operand_observation(
                label=normalized,
                is_topic=normalized.startswith("topic"),
                origin=operand.origin,
                literal=operand.literal,
                path=operand.path,
                memory_slice=None,
                analyzer=analyzer,
            )
            operand_observations.append(operand_obs)
            operand_paths[normalized] = _merge_paths(
                operand_paths.get(normalized, []), list(operand.path)
            )

        for mem_operand in report.memory_operands:
            label = _normalize_label(mem_operand.label)
            size = 32 if mem_operand.label.startswith("data") and mem_operand.label[4:].isdigit() else None
            memory_slice = MemorySlice(offset=mem_operand.offset, size=size)
            operand_obs = _build_operand_observation(
                label=label,
                is_topic=False,
                origin=mem_operand.origin,
                literal=mem_operand.literal,
                path=mem_operand.path,
                memory_slice=memory_slice,
                analyzer=analyzer,
            )
            operand_observations.append(operand_obs)
            operand_paths[label] = _merge_paths(
                operand_paths.get(label, []), list(mem_operand.path)
            )

        sstore_records = sstore_records_by_fn.get(fn, [])
        filtered_sstores, sstore_scope = _filter_sstores_for_log(
            log_report=report,
            sstore_records=sstore_records,
            analyzer=analyzer,
        )
        sload_records = sload_records_by_fn.get(fn, [])
        filtered_sloads, _ = _filter_sstores_for_log(
            log_report=report,
            sstore_records=sload_records,
            analyzer=analyzer,
        )
        sstore_summary = [
            SstoreSummary(
                slot_kind=record["slot_kind"],
                slot_deps=list(record.get("slot_deps", [])),
                value_deps=list(record.get("value_deps", [])),
            )
            for record in filtered_sstores
        ]
        value_bindings = _value_bindings(
            operands=operand_observations,
            operand_paths=operand_paths,
            sstore_records=filtered_sstores,
            sload_records=filtered_sloads,
        )
        guard_summary = _normalize_guard_categories(report.guard_categories or [])
        check_sources = _check_sources_for_log(
            report,
            dominators=dominators,
            blocks=analyzer.blocks,
            def_map=analyzer.var_def_stmt,
            block_reachability=analyzer.block_reachability,
        )
        if entry_index:
            check_sources = unique_preserve(
                check_sources
                + _check_sources_interprocedural(
                    report,
                    entry_index=entry_index,
                    entry_ids=list(entry_ids),
                    dominators=dominators,
                    blocks=analyzer.blocks,
                    def_map=analyzer.var_def_stmt,
                    block_reachability=analyzer.block_reachability,
                )
            )
        observation = EventObservation(
            contract_id=contract_id,
            corpus_tier=tier,
            function_id=fn,
            function_name=fn_name,
            function_selector=fn_selector,
            entrypoint_ids=list(entry_ids),
            topic0=report.event_topic0,
            event_signature=report.event_signature,
            log_site={
                "block": report.statement.block or "",
                "offset": report.statement.offset,
            },
            param_counts=_param_counts(operand_observations),
            operands=operand_observations,
            opcode_footprint=_opcode_footprint(operand_paths),
            sstore_scope=sstore_scope,
            sstore_summary=sstore_summary,
            value_bindings=value_bindings,
            guard_summary=guard_summary,
            check_sources=check_sources,
            context={"reachable_entrypoints": list(entry_ids)},
        )
        observations.append(observation)

    functions: Dict[str, FunctionSummary] = {}
    for stmt in statements:
        fn = stmt.function or "<global>"
        if fn not in functions:
            fn_name = entry_index.function_names.get(fn) if entry_index else None
            fn_selector = entry_index.public_selectors.get(fn) if entry_index else None
            functions[fn] = FunctionSummary(
                contract_id=contract_id,
                corpus_tier=tier,
                function_id=fn,
                function_name=fn_name,
                function_selector=fn_selector,
            )
        summary = functions[fn]
        summary.opcode_bow[stmt.opcode] = summary.opcode_bow.get(stmt.opcode, 0) + 1

    for report in log_reports:
        fn = report.statement.function or "<global>"
        if fn not in functions:
            continue
        summary = functions[fn]
        for category in _normalize_guard_categories(report.guard_categories or []):
            if category not in summary.guard_categories:
                summary.guard_categories.append(category)
        if report.event_topic0:
            topic0 = report.event_topic0
            summary.log_count_total += 1
            summary.reachable_log_counts[topic0] = summary.reachable_log_counts.get(topic0, 0) + 1
            shape_key = _log_shape_key(report)
            summary.log_shape_counts.setdefault(topic0, {})
            summary.log_shape_counts[topic0][shape_key] = (
                summary.log_shape_counts[topic0].get(shape_key, 0) + 1
            )
            if topic0 not in summary.reachable_logs:
                summary.reachable_logs.append(topic0)

    for fn, records in sstore_records_by_fn.items():
        if fn not in functions:
            continue
        summary = functions[fn]
        summary.has_state_change = bool(records)
        for record in records:
            kind = record.get("slot_kind")
            if kind and kind not in summary.sstore_kinds:
                summary.sstore_kinds.append(kind)

    return observations, list(functions.values()), equality_records


def _resolve_tac_paths(tac: Path) -> List[Path]:
    if tac.is_dir():
        return sorted(tac.rglob("*.tac"))
    if tac.suffix == ".tac":
        return [tac]
    tac_paths: List[Path] = []
    base_dir = tac.parent
    for line in tac.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        path = Path(stripped).expanduser()
        if not path.is_absolute():
            path = (base_dir / path).resolve()
        tac_paths.append(path)
    return tac_paths


def _maybe_print_progress(index: int, total: int, progress_every: int) -> None:
    if total <= 1:
        return
    if index == 1 or index == total or index % progress_every == 0:
        percent = (index / total) * 100
        print(f"[extract] progress {index}/{total} ({percent:.1f}%)")


def _iter_with_progress(paths: List[Path]) -> Iterable[Path]:
    if tqdm is None:
        return paths
    return tqdm(paths, desc="extract", unit="contract")


def run(args: argparse.Namespace) -> None:
    tac_paths = list(dict.fromkeys(_resolve_tac_paths(args.tac))) #Create folder

    out_dir: Path = args.out
    agg_db_path = out_dir / "agg.db"
    ensure_dir(agg_db_path.parent) # Change PWD
    agg_store = AggregateStore(agg_db_path, reset=not args.append) # Sql_db

    if args.append: # append more tac data
        kept: List[Path] = []
        skipped = 0
        for tac_path in tac_paths:
            if tac_path.exists():
                contract_id = _hash_contract(tac_path) # hash(contract.tac)
                if agg_store.has_contract(contract_id):
                    skipped += 1
                    continue
            kept.append(tac_path)
        tac_paths = kept
        if skipped:
            print(f"[extract] append: skipping {skipped} contracts already in output")
        if not tac_paths:
            print("[extract] append: no new contracts to process")
            agg_store.close()
            return
    if tac_paths:
        deduped = 0
        seen_hashes: set[str] = set()
        unique_paths: List[Path] = []
        for tac_path in tac_paths:
            if not tac_path.exists():
                unique_paths.append(tac_path)
                continue
            contract_id = _hash_contract(tac_path)
            if contract_id in seen_hashes:
                deduped += 1
                continue
            seen_hashes.add(contract_id)
            unique_paths.append(tac_path)
        tac_paths = unique_paths
        if deduped:
            print(f"[extract] dedupe: skipping {deduped} duplicate contracts by content hash")
    total = len(tac_paths)
    progress_every = max(1, total // 100) if total else 1
    use_basic_progress = tqdm is None
    try:
        for index, tac_path in enumerate(_iter_with_progress(tac_paths), start=1):
            try:
                if not tac_path.exists():
                    print(f"[extract] {tac_path}: TAC file not found")
                    continue
                tier = args.tier # Set tier
                try:
                    observations, functions, equalities = extract_contract(
                        tac_path,
                        tier,
                        symbolic=args.symbolic,
                        symbolic_mstore_concretize=args.symbolic_mstore_concretize,
                        symbolic_eq_constant_only=args.symbolic_eq_constant_only,
                        symbolic_log_limit=args.symbolic_log_limit,
                        timeout=args.timeout,
                    )
                except SystemExit as exc:
                    print(f"[extract] {tac_path}: {exc}")
                    continue
                agg_store.update_contract(observations, functions, equalities)
                contract_id = None
                if observations:
                    contract_id = observations[0].contract_id
                elif functions:
                    contract_id = functions[0].contract_id
                if contract_id:
                    agg_store.mark_contract(contract_id)
            finally:
                if use_basic_progress:
                    _maybe_print_progress(index, total, progress_every)
    finally:
        agg_store.close()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
