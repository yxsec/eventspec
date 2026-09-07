"""Access-control classification heuristics inspired by Prettysmart."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from .models import EntryPointIndex, LogReport, TacStatement
from .parser import normalize_var, extract_literal

OWNER_GUARD_OPS = {"EQ", "ISZERO"}
DATA_SOURCE_OPS = {"CALLDATALOAD", "CALLDATACOPY"}
COMPARISON_OPS = {"EQ", "ISZERO", "JUMPI", "GT", "LT", "SGT", "SLT"}

GENERIC_GUARD_SOURCES = {"CALLER", "ORIGIN", "CALLVALUE", "CALLDATALOAD", "CALLDATACOPY"}


def classify_access_control(statements: Sequence[TacStatement]) -> Dict[str, Set[str]]:
    """Classify guarding basic blocks into coarse access-control categories."""
    block_map = group_statements_by_block(statements)
    def_map = build_def_map(statements)
    literal_map = build_literal_map(statements)
    classifications: Dict[str, Set[str]] = defaultdict(set)
    detectors = [
        ("owner", detect_owner_guard),
        ("whitelist", detect_whitelist_guard),
        ("Rolebased", detect_rolebased_guard),
        ("datadriven", detect_datadriven_guard),
        ("datadriven2", detect_datadriven2_guard),
    ]
    for block_id, block_stmts in block_map.items():
        if not block_id:
            continue
        for name, detector in detectors:
            if detector(block_stmts, def_map, literal_map):
                classifications[block_id].add(name)
    return classifications


def annotate_access_control(
    reports: Sequence[LogReport],
    *,
    entry_index: Optional[EntryPointIndex],
    dominators: Dict[str, set[str]],
    block_guard_categories: Dict[str, set[str]],
) -> List[str]:
    issues: List[str] = []
    skip_functions = {"__function_selector__"}
    for report in reports:
        fn = report.statement.function
        if not fn:
            continue
        if fn in skip_functions:
            continue
        block_id = report.statement.block
        entry_point_ids: List[str] = []
        if entry_index:
            entry_point_ids = entry_index.entry_point_ids_for_block(block_id)

        intra_categories: set[str] = set()
        if block_id:
            dom_blocks = dominators.get(block_id, {block_id})
            for dom in dom_blocks:
                intra_categories |= block_guard_categories.get(dom, set())

        report.guard_categories = sorted(intra_categories)
        if intra_categories:
            continue

        # Attribute missing-guard issues to entry points (public/external), not to internal callees.
        if not entry_point_ids:
            continue

        for ep_id in entry_point_ids:
            interproc_categories = set(
                find_interprocedural_guard_categories_for_entrypoint(
                    callee_func=fn,
                    entry_func=ep_id,
                    entry_index=entry_index,
                    dominators=dominators,
                    block_guard_categories=block_guard_categories,
                )
            )
            if interproc_categories:
                # Keep the most informative categories on the report for human debugging.
                report.guard_categories = sorted(interproc_categories | {"interprocedural"})
                continue
            ep_display = entry_index.entry_point_display(ep_id) if entry_index else ep_id
            issue = (
                f"[access_control] entry {ep_display} reaches {fn} "
                f"log at {block_id} without dominating guard"
            )
            issues.append(issue)
    return issues


def find_interprocedural_guard_categories_for_entrypoint(
    *,
    callee_func: str,
    entry_func: str,
    entry_index: Optional[EntryPointIndex],
    dominators: Dict[str, set[str]],
    block_guard_categories: Dict[str, set[str]],
    depth_limit: int = 6,
) -> List[str]:
    """Best-effort search for guarding blocks in callers on reachable paths."""
    if not entry_index:
        return []

    visited_funcs: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(callee_func, 0)])
    found: set[str] = set()
    while queue:
        func_id, depth = queue.popleft()
        if func_id in visited_funcs:
            continue
        visited_funcs.add(func_id)
        if depth >= depth_limit:
            continue
        for callsite_block in entry_index.callsites_for_function(func_id):
            caller_func = entry_index.block_to_function.get(callsite_block)
            if not caller_func:
                continue
            reachable_entries = set(entry_index.function_reachability_ids.get(caller_func, []))
            if entry_func not in reachable_entries and caller_func != entry_func:
                continue
            dom_blocks = dominators.get(callsite_block, {callsite_block})
            for dom in dom_blocks:
                found |= block_guard_categories.get(dom, set())
            queue.append((caller_func, depth + 1))
        if found:
            break
    return sorted(found)


def group_statements_by_block(
    statements: Sequence[TacStatement],
) -> Dict[str, List[TacStatement]]:
    groups: Dict[str, List[TacStatement]] = defaultdict(list)
    for stmt in statements:
        if stmt.block:
            groups[stmt.block].append(stmt)
    return groups


def build_def_map(statements: Sequence[TacStatement]) -> Dict[str, TacStatement]:
    mapping: Dict[str, TacStatement] = {}
    for stmt in statements:
        for var in stmt.defs:
            mapping[var] = stmt
    return mapping


def build_literal_map(statements: Sequence[TacStatement]) -> Dict[str, Optional[str]]:
    literals: Dict[str, Optional[str]] = {}
    for stmt in statements:
        for idx, var in enumerate(stmt.defs):
            literal = None
            if idx < len(stmt.def_literals):
                literal = stmt.def_literals[idx]
            literals[var] = literal
    return literals


def detect_owner_guard(
    block_statements: Sequence[TacStatement],
    def_map: Dict[str, TacStatement],
    literal_map: Dict[str, Optional[str]],
) -> bool:
    for stmt in block_statements:
        if stmt.opcode.upper() not in OWNER_GUARD_OPS:
            continue
        operands = [normalize_var(token) for token in stmt.uses if normalize_var(token)]
        if len(operands) < 2:
            continue
        caller_side = any(
            traces_to_opcode(var, {"CALLER", "ORIGIN"}, def_map) for var in operands
        )
        storage_side = any(traces_to_opcode(var, {"SLOAD"}, def_map) for var in operands)
        if caller_side and storage_side:
            return True
    return False


def detect_datadriven_guard(
    block_statements: Sequence[TacStatement],
    def_map: Dict[str, TacStatement],
    literal_map: Dict[str, Optional[str]],
) -> bool:
    for sload_stmt, sha3_stmt in find_sha3_sload_pairs(block_statements, def_map):
        if not sha3_has_caller_operand(sha3_stmt, def_map):
            continue
        sload_var = sload_stmt.defs[0] if sload_stmt.defs else None
        if not sload_var:
            continue
        if comparison_with_data_source(block_statements, sload_var, def_map):
            return True
    return False


def detect_datadriven2_guard(
    block_statements: Sequence[TacStatement],
    def_map: Dict[str, TacStatement],
    literal_map: Dict[str, Optional[str]],
) -> bool:
    for sload_stmt, sha3_stmt in find_sha3_sload_pairs(block_statements, def_map):
        inner_sha3 = sha3_nested_operand(sha3_stmt, def_map)
        if not inner_sha3:
            continue
        if not sha3_has_caller_operand(sha3_stmt, def_map):
            continue
        sload_var = sload_stmt.defs[0] if sload_stmt.defs else None
        if not sload_var:
            continue
        if comparison_with_data_source(block_statements, sload_var, def_map):
            return True
    return False


def detect_whitelist_guard(
    block_statements: Sequence[TacStatement],
    def_map: Dict[str, TacStatement],
    literal_map: Dict[str, Optional[str]],
) -> bool:
    for sload_stmt, sha3_stmt in find_sha3_sload_pairs(block_statements, def_map):
        if not sha3_has_caller_operand(sha3_stmt, def_map):
            continue
        if not sha3_has_literal_operand(sha3_stmt, literal_map):
            continue
        sload_var = sload_stmt.defs[0] if sload_stmt.defs else None
        if not sload_var:
            continue
        if comparison_against_zero(block_statements, sload_var, literal_map):
            return True
    return False


def detect_rolebased_guard(
    block_statements: Sequence[TacStatement],
    def_map: Dict[str, TacStatement],
    literal_map: Dict[str, Optional[str]],
) -> bool:
    for sload_stmt, sha3_stmt in find_sha3_sload_pairs(block_statements, def_map):
        if not sha3_has_caller_operand(sha3_stmt, def_map):
            continue
        inner_sha3 = sha3_nested_operand(sha3_stmt, def_map)
        if not inner_sha3:
            continue
        if not sha3_has_literal_operand(inner_sha3, literal_map):
            continue
        sload_var = sload_stmt.defs[0] if sload_stmt.defs else None
        if not sload_var:
            continue
        if var_guarded_in_block(block_statements, sload_var):
            return True
    return False



def traces_to_opcode(
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
    if opcode in {"PHI", "MOV"}:
        return any(
            traces_to_opcode(normalize_var(token), target_opcodes, def_map, depth + 1)
            for token in stmt.uses
        )
    if opcode in {"AND", "OR", "XOR", "ADD", "SUB", "SHL", "SHR", "SAR"}:
        return any(
            traces_to_opcode(normalize_var(token), target_opcodes, def_map, depth + 1)
            for token in stmt.uses
        )
    if opcode == "MLOAD":
        if not stmt.uses:
            return False
        return traces_to_opcode(
            normalize_var(stmt.uses[0]), target_opcodes, def_map, depth + 1
        )
    if opcode == "SLOAD":
        return "SLOAD" in target_opcodes
    return False


def find_sha3_sload_pairs(
    block_statements: Sequence[TacStatement],
    def_map: Dict[str, TacStatement],
) -> Iterator[Tuple[TacStatement, TacStatement]]:
    for stmt in block_statements:
        if stmt.opcode.upper() != "SLOAD" or not stmt.uses or not stmt.defs:
            continue
        addr_var = normalize_var(stmt.uses[0])
        if not addr_var:
            continue
        sha3_stmt = def_map.get(addr_var)
        if sha3_stmt and sha3_stmt.opcode.upper() == "SHA3":
            yield stmt, sha3_stmt


def sha3_has_caller_operand(
    sha3_stmt: TacStatement,
    def_map: Dict[str, TacStatement],
) -> bool:
    for token in sha3_stmt.uses:
        var = normalize_var(token)
        if traces_to_opcode(var, {"CALLER", "ORIGIN"}, def_map):
            return True
    return False


def sha3_has_literal_operand(
    sha3_stmt: TacStatement,
    literal_map: Dict[str, Optional[str]],
) -> bool:
    for token in sha3_stmt.uses:
        if token_is_literal(token, literal_map):
            return True
    return False


def sha3_nested_operand(
    sha3_stmt: TacStatement,
    def_map: Dict[str, TacStatement],
) -> Optional[TacStatement]:
    for token in sha3_stmt.uses:
        var = normalize_var(token)
        inner = def_map.get(var)
        if inner and inner.opcode.upper() == "SHA3":
            return inner
    return None


def token_is_literal(token: str, literal_map: Dict[str, Optional[str]]) -> bool:
    literal = extract_literal(token)
    if literal:
        return True
    var = normalize_var(token)
    if var:
        literal_value = literal_map.get(var)
        if literal_value is not None:
            return True
    return False


def get_token_literal(
    token: str,
    literal_map: Dict[str, Optional[str]],
) -> Optional[str]:
    literal = extract_literal(token)
    if literal:
        return literal.lower()
    var = normalize_var(token)
    if var:
        literal_value = literal_map.get(var)
        if literal_value:
            return literal_value.lower()
    return None


def comparison_against_zero(
    block_statements: Sequence[TacStatement],
    target_var: str,
    literal_map: Dict[str, Optional[str]],
) -> bool:
    zero_literals = {"0", "0x0", "0x00"}
    for stmt in block_statements:
        op = stmt.opcode.upper()
        if op == "ISZERO":
            operands = [normalize_var(token) for token in stmt.uses]
            if operands and operands[0] == target_var:
                return True
        if op != "EQ":
            continue
        uses = stmt.uses
        normalized = [normalize_var(token) for token in uses]
        if target_var not in normalized:
            continue
        for token in uses:
            literal = get_token_literal(token, literal_map)
            if literal and literal in zero_literals:
                return True
    return False


def comparison_with_data_source(
    block_statements: Sequence[TacStatement],
    target_var: str,
    def_map: Dict[str, TacStatement],
) -> bool:
    comparison_ops = {"EQ", "GT", "LT", "SGT", "SLT"}
    for stmt in block_statements:
        op = stmt.opcode.upper()
        if op not in comparison_ops:
            continue
        operands = [normalize_var(token) for token in stmt.uses]
        if target_var not in operands:
            continue
        for token in stmt.uses:
            var = normalize_var(token)
            if not var or var == target_var:
                continue
            if traces_to_opcode(var, DATA_SOURCE_OPS, def_map):
                return True
    return False


def var_guarded_in_block(
    block_statements: Sequence[TacStatement],
    target_var: str,
) -> bool:
    for stmt in block_statements:
        op = stmt.opcode.upper()
        if op not in COMPARISON_OPS:
            continue
        operands = [normalize_var(token) for token in stmt.uses]
        if target_var in operands:
            return True
    return False
