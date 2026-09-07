"""Taint propagation logic and graph construction."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .cfg import build_cfg, compute_block_reachability
from .constants import LOG_OPCODES
from .models import (
    EntryPointIndex,
    LogOperandReport,
    LogReport,
    MemoryOperandReport,
    TacStatement,
    TaintProvenance,
    TraceStep,
)
from .parser import extract_literal, normalize_var


class TaintAnalyzer:
    def __init__(
        self,
        statements: Sequence[TacStatement],
        source_opcodes: Iterable[str],
        event_signatures: Optional[Dict[str, str]] = None,
        entrypoint_index: Optional[EntryPointIndex] = None,
    ):
        self.statements = list(statements)
        self.source_opcodes = {opcode.upper() for opcode in source_opcodes}
        self.var_def_stmt: Dict[str, TacStatement] = {} # map variable to statement
        self.var_literals: Dict[str, Optional[str]] = {} # map variable to literal eg. v1:"0x10"
        self.statement_positions: Dict[int, int] = {} # map statement to position
        self.event_signatures = (
            {key.lower(): value for key, value in event_signatures.items()}
            if event_signatures
            else {}
        )
        self.entrypoint_index = entrypoint_index
        self.expr_cache: Dict[str, str] = {}
        self.blocks = build_cfg(self.statements)# build cfg
        self.block_reachability = compute_block_reachability(self.blocks) # compute block reachability
        for index, stmt in enumerate(self.statements):
            self.statement_positions[id(stmt)] = index
            for idx, var in enumerate(stmt.defs):
                self.var_def_stmt[var] = stmt
                literal = None
                if idx < len(stmt.def_literals):
                    literal = stmt.def_literals[idx]
                self.var_literals[var] = literal

    def analyze(self) -> Tuple[List[LogReport], Dict[str, TaintProvenance]]:
        var_consumers: Dict[str, List[TacStatement]] = defaultdict(list)# record map variable to statements
        for stmt in self.statements:
            for token in stmt.uses:
                var = normalize_var(token)
                if var:
                    var_consumers[var].append(stmt)

        taint_info: Dict[str, TaintProvenance] = {} # initialize taint source 
        queue: deque[str] = deque()
        for stmt in self.statements:
            if stmt.opcode.upper() in self.source_opcodes:
                for var in stmt.defs:
                    if var not in taint_info:
                        taint_info[var] = TaintProvenance(parent_var=None, statement=stmt)
                        queue.append(var)

        # Heuristic: treat unresolved function argument variables (e.g. v...arg0)
        # as taint sources when inter-procedural argument passing is not modeled.
        for var in var_consumers:
            if var in taint_info:
                continue
            if _ARG_VAR_PATTERN.match(var):
                taint_info[var] = TaintProvenance(parent_var=None, statement=self.var_def_stmt.get(var) or TacStatement(
                    offset="arg",
                    opcode="ARG",
                    defs=(var,),
                    def_literals=(),
                    uses=(),
                    raw=var,
                    function=self.var_def_stmt.get(var).function if self.var_def_stmt.get(var) else None,
                    block=self.var_def_stmt.get(var).block if self.var_def_stmt.get(var) else None,
                ))
                queue.append(var)

        while queue: # propagate taint source to log
            current_var = queue.popleft()
            for consumer in var_consumers.get(current_var, []):
                if not consumer.defs:
                    continue
                source_stmt = taint_info[current_var].statement
                if not self._can_flow(source_stmt, consumer):
                    continue
                for var in consumer.defs:
                    if var in taint_info:
                        continue
                    taint_info[var] = TaintProvenance(
                        parent_var=current_var, statement=consumer
                    )
                    queue.append(var)

        log_reports: List[LogReport] = []
        for stmt in self.statements:
            if stmt.opcode.upper() not in LOG_OPCODES:
                continue
            operands = self._collect_log_operands(stmt, taint_info)
            topic0_literal: Optional[str] = None
            for operand in operands:
                if operand.label == "topic0" and operand.literal:
                    topic0_literal = operand.literal.lower()
                    break
            event_signature = None
            for operand in operands:
                if operand.label == "topic0" and operand.signature:
                    event_signature = operand.signature
                    break
            entry_points: List[str] = []
            if self.entrypoint_index:
                entry_points = self.entrypoint_index.entry_points_for_block(stmt.block)
            memory_operands = self._decode_memory_operands(stmt, operands, taint_info)
            log_reports.append(
                LogReport(
                    statement=stmt,
                    operands=operands,
                    event_topic0=topic0_literal,
                    event_signature=event_signature,
                    entry_points=entry_points,
                    memory_operands=memory_operands,
                )
            )

        self._annotate_log_reports(log_reports, taint_info)
        return log_reports, taint_info

    def _collect_log_operands(
        self, stmt: TacStatement, taint_info: Dict[str, TaintProvenance]
    ) -> List[LogOperandReport]:
        reports: List[LogOperandReport] = []
        for idx, token in enumerate(stmt.uses):
            label = describe_log_operand(stmt.opcode.upper(), idx)  # parse log operands
            var = normalize_var(token)
            tainted = var in taint_info if var else False
            literal = extract_literal(token)
            if literal is None and var:
                literal = self.var_literals.get(var)
            signature = None
            if label.startswith("topic0") and literal:
                signature = self.event_signatures.get(literal.lower())
            reports.append(
                LogOperandReport(
                    label=label,
                    token=token,
                    var=var,
                    tainted=tainted,
                    literal=literal,
                    signature=signature,
                    origin=None,
                    path=[],
                )
            )
        return reports

    def _can_flow(
        self,
        source_stmt: Optional[TacStatement],
        target_stmt: TacStatement,
    ) -> bool: # check statement reachability
        if not source_stmt or not target_stmt:
            return True
        src_block = source_stmt.block
        dst_block = target_stmt.block
        if not src_block or not dst_block:
            return True
        if src_block == dst_block:
            src_index = self.statement_positions.get(id(source_stmt), -1)
            dst_index = self.statement_positions.get(id(target_stmt), -1)
            if src_index <= dst_index:
                return True
            reachable = self.block_reachability.get(src_block)
            return bool(reachable and src_block in reachable)
        reachable = self.block_reachability.get(src_block)
        if not reachable:
            return False
        return dst_block in reachable

    def _decode_memory_operands(
        self,
        stmt: TacStatement,
        operands: List[LogOperandReport],
        taint_info: Dict[str, TaintProvenance],
    ) -> List[MemoryOperandReport]:
        mem_start_var = None
        mem_len_var = None
        mem_start_literal: Optional[int] = None
        mem_len_literal: Optional[int] = None
        for operand in operands:
            if operand.label == "mem_start":
                mem_start_var = operand.var
                mem_start_literal = self._resolve_int_token(operand.token)
            elif operand.label == "mem_len":
                mem_len_var = operand.var
                mem_len_literal = self._resolve_int_token(operand.token)
        if not mem_start_var and mem_start_literal is None:
            return []
        log_index = self.statement_positions.get(id(stmt))
        if log_index is None:
            return []

        base_origin = self.describe_value_origin(mem_start_var) if mem_start_var else None
        mem_len = None
        if mem_len_var and mem_start_var:
            mem_len = self._resolve_memory_length(mem_len_var, mem_start_var, base_origin)
        if mem_len is None and mem_len_var:
            mem_len = self._resolve_int_token(mem_len_var)
        if mem_len is None:
            mem_len = mem_len_literal
        reports: List[MemoryOperandReport] = []
        block_distances = self._compute_predecessor_distances(stmt.block)
        candidate_stmts = self._collect_mstore_candidates(stmt, log_index)
        copy_stmts = self._collect_memcopy_candidates(stmt, log_index)
        candidates: List[Tuple[int, Optional[int], str, int, int, Optional[str]]] = []

        def resolve_relative_offset(token: str) -> Optional[int]:
            if mem_start_literal is not None:
                absolute = self._resolve_int_token(token)
                if absolute is not None:
                    return absolute - mem_start_literal
            if mem_start_var:
                return self._pointer_offset_from_token(
                    token, mem_start_var, base_origin, set()
                )
            return None

        for prev_stmt in candidate_stmts:
            ptr_token = prev_stmt.uses[0]
            offset = resolve_relative_offset(ptr_token)
            if offset is None or offset < 0:
                continue
            if mem_len is not None and offset >= mem_len:
                continue
            value_token = prev_stmt.uses[1]
            slot_index = offset // 0x20 if offset % 0x20 == 0 else None
            distance = block_distances.get(prev_stmt.block or "", 10**9)
            stmt_pos = self.statement_positions.get(id(prev_stmt), -1)
            candidates.append((offset, slot_index, value_token, distance, stmt_pos, None))
        for copy_stmt in copy_stmts:
            if len(copy_stmt.uses) < 3:
                continue
            dest_token, src_token, len_token = copy_stmt.uses[:3]
            dest_offset = resolve_relative_offset(dest_token)
            if dest_offset is None or dest_offset < 0:
                continue
            copy_len = self._resolve_int_token(len_token)
            if copy_len is None and mem_len is not None:
                if dest_offset >= mem_len:
                    continue
                copy_len = max(0, mem_len - dest_offset)
            if copy_len is None or copy_len <= 0:
                continue
            if mem_len is not None:
                copy_len = min(copy_len, mem_len - dest_offset)
                if copy_len <= 0:
                    continue
            src_base_expr = self.resolve_operand_expression(src_token)
            src_base_val = self._resolve_int_token(src_token)
            distance = block_distances.get(copy_stmt.block or "", 10**9)
            stmt_pos = self.statement_positions.get(id(copy_stmt), -1)
            opcode = copy_stmt.opcode.upper()
            if opcode == "CALLDATACOPY":
                origin_prefix = "CALLDATALOAD"
            elif opcode == "RETURNDATACOPY":
                origin_prefix = "RETURNDATALOAD"
            elif opcode == "CODECOPY":
                origin_prefix = "CODECOPY"
            else:
                origin_prefix = "EXTCODECOPY"
            for delta in range(0, copy_len, 0x20):
                offset = dest_offset + delta
                if mem_len is not None and offset >= mem_len:
                    break
                slot_index = offset // 0x20 if offset % 0x20 == 0 else None
                if src_base_val is not None:
                    origin = f"{origin_prefix} offset 0x{src_base_val + delta:x}"
                elif delta:
                    origin = f"{origin_prefix} offset ({src_base_expr} + 0x{delta:x})"
                else:
                    origin = f"{origin_prefix} offset {src_base_expr}"
                token = f"{opcode.lower()}@{src_base_expr}+0x{delta:x}"
                candidates.append(
                    (offset, slot_index, token, distance, stmt_pos, origin)
                )
        if not candidates:
            return []
        # Prefer writes in blocks closer to the LOG block, and later statements within those blocks.
        best_by_slot: Dict[int, Tuple[int, Optional[int], str, int, int, Optional[str]]] = {}
        best_unaligned_by_offset: Dict[
            int, Tuple[int, Optional[int], str, int, int, Optional[str]]
        ] = {}
        for candidate in candidates:
            offset, slot_index, token, distance, stmt_pos, origin = candidate
            if slot_index is None:
                existing = best_unaligned_by_offset.get(offset)
                if existing is None:
                    best_unaligned_by_offset[offset] = candidate
                    continue
                _, _, _, ex_dist, ex_pos, _ = existing
                if distance < ex_dist or (distance == ex_dist and stmt_pos > ex_pos):
                    best_unaligned_by_offset[offset] = candidate
                continue
            existing = best_by_slot.get(slot_index)
            if existing is None:
                best_by_slot[slot_index] = candidate
                continue
            _, _, _, ex_dist, ex_pos, _ = existing
            if distance < ex_dist or (distance == ex_dist and stmt_pos > ex_pos):
                best_by_slot[slot_index] = candidate

        final_candidates: List[Tuple[int, Optional[int], str, Optional[str]]] = [
            (offset, slot_index, token, origin)
            for offset, slot_index, token, _, _, origin in best_by_slot.values()
        ]
        final_candidates.extend(
            (offset, slot_index, token, origin)
            for offset, slot_index, token, _, _, origin in best_unaligned_by_offset.values()
        )
        for offset, slot_index, token, origin in sorted(
            final_candidates, key=lambda item: item[0]
        ):
            label = f"data{slot_index}" if slot_index is not None else f"data@{offset:#x}"
            var = normalize_var(token)
            literal = extract_literal(token)
            if literal is None and var:
                literal = self.var_literals.get(var)
            tainted = var in taint_info if var else False
            path: List[TraceStep] = []
            if var:
                path = self._trace_to_input(var, taint_info)
                if origin is None:
                    origin = self.describe_value_origin(var)
            reports.append(
                MemoryOperandReport(
                    label=label,
                    offset=offset,
                    token=token,
                    var=var,
                    tainted=tainted,
                    literal=literal,
                    origin=origin,
                    path=path,
                )
            )
        return reports

    def _collect_mstore_candidates(
        self, log_stmt: TacStatement, log_index: int
    ) -> List[TacStatement]:
        if not log_stmt.block:
            return []
        candidates: List[TacStatement] = []
        visited: set[str] = set()
        stack: List[Tuple[str, Optional[int]]] = [(log_stmt.block, log_index)]
        while stack:
            block_id, limit_index = stack.pop()
            if block_id in visited:
                continue
            visited.add(block_id)
            block = self.blocks.get(block_id)
            if not block:
                continue
            for block_stmt in block.statements:
                stmt_index = self.statement_positions.get(id(block_stmt), 0)
                if limit_index is not None and stmt_index >= limit_index:
                    break
                if block_stmt.opcode.upper() == "MSTORE" and len(block_stmt.uses) >= 2:
                    candidates.append(block_stmt)
            for predecessor in block.predecessors:
                if predecessor:
                    stack.append((predecessor, None))
        return candidates

    def _collect_memcopy_candidates(
        self, log_stmt: TacStatement, log_index: int
    ) -> List[TacStatement]:
        if not log_stmt.block:
            return []
        copy_ops = {"CALLDATACOPY", "RETURNDATACOPY", "CODECOPY", "EXTCODECOPY"}
        candidates: List[TacStatement] = []
        visited: set[str] = set()
        stack: List[Tuple[str, Optional[int]]] = [(log_stmt.block, log_index)]
        while stack:
            block_id, limit_index = stack.pop()
            if block_id in visited:
                continue
            visited.add(block_id)
            block = self.blocks.get(block_id)
            if not block:
                continue
            for block_stmt in block.statements:
                stmt_index = self.statement_positions.get(id(block_stmt), 0)
                if limit_index is not None and stmt_index >= limit_index:
                    break
                if (
                    block_stmt.opcode.upper() in copy_ops
                    and len(block_stmt.uses) >= 3
                ):
                    candidates.append(block_stmt)
            for predecessor in block.predecessors:
                if predecessor:
                    stack.append((predecessor, None))
        return candidates

    def _compute_predecessor_distances(self, start_block: Optional[str]) -> Dict[str, int]: # find mstore to log distence
        if not start_block:
            return {}
        distances: Dict[str, int] = {start_block: 0}
        queue: deque[str] = deque([start_block])
        while queue:
            block_id = queue.popleft()
            dist = distances.get(block_id, 0)
            block = self.blocks.get(block_id)
            if not block:
                continue
            for pred in block.predecessors:
                if not pred or pred in distances:
                    continue
                distances[pred] = dist + 1
                queue.append(pred)
        return distances

    def _annotate_log_reports(
        self, reports: Sequence[LogReport], taint_info: Dict[str, TaintProvenance]
    ) -> None:
        trace_cache: Dict[str, List[TraceStep]] = {}
        origin_cache: Dict[str, Optional[str]] = {}

        def origin_for(var: str) -> Optional[str]:
            cached = origin_cache.get(var)
            if var not in origin_cache:
                cached = self.describe_value_origin(var)
                origin_cache[var] = cached
            return cached

        def trace_for(var: str) -> List[TraceStep]:
            cached = trace_cache.get(var)
            if var not in trace_cache:
                cached = self._trace_to_input(var, taint_info)
                trace_cache[var] = cached
            return cached

        for report in reports:
            for operand in report.operands:
                if operand.var:
                    operand.origin = origin_for(operand.var)
                    operand.path = trace_for(operand.var)
            for operand in report.memory_operands:
                if operand.var:
                    operand.origin = origin_for(operand.var)
                    operand.path = trace_for(operand.var)

    def _resolve_memory_length(
        self,
        mem_len_var: Optional[str],
        base_var: str,
        base_origin: Optional[str],
    ) -> Optional[int]: # return memory length
        if not mem_len_var:
            return None
        literal = self.var_literals.get(mem_len_var)
        if literal:
            try:
                return int(literal, 16)
            except ValueError:
                return None
        stmt = self.var_def_stmt.get(mem_len_var)
        if not stmt:
            return None
        if stmt.opcode.upper() == "SUB" and len(stmt.uses) >= 2:
            left = self._pointer_offset_from_token(
                stmt.uses[0], base_var, base_origin, set()
            )
            right = self._pointer_offset_from_token(
                stmt.uses[1], base_var, base_origin, set()
            )
            if left is not None and right is not None:
                return left - right
        return None

    def _resolve_int_token(self, token: str) -> Optional[int]:
        var = normalize_var(token)
        if var:
            return self._resolve_int_var(var, set(), 0)
        literal = extract_literal(token)
        if not literal:
            literal = token.strip()
        if literal.startswith("0x"):
            try:
                return int(literal, 16)
            except ValueError:
                return None
        if literal.isdigit():
            try:
                return int(literal, 10)
            except ValueError:
                return None
        return None

    def _resolve_int_var(
        self, var: str, seen: set[str], depth: int
    ) -> Optional[int]:
        if var in seen or depth > 8:
            return None
        seen.add(var)
        literal = self.var_literals.get(var)
        if literal:
            try:
                return int(literal, 16)
            except ValueError:
                return None
        stmt = self.var_def_stmt.get(var)
        if not stmt:
            return None
        opcode = stmt.opcode.upper()
        if opcode == "CONST":
            literal = self.var_literals.get(var)
            if literal:
                try:
                    return int(literal, 16)
                except ValueError:
                    return None
            return None
        if opcode in {"ADD", "SUB", "MUL", "DIV", "MOD"} and len(stmt.uses) >= 2:
            left = self._resolve_int_token(stmt.uses[0])
            right = self._resolve_int_token(stmt.uses[1])
            if left is None or right is None:
                return None
            if opcode == "ADD":
                return left + right
            if opcode == "SUB":
                return left - right
            if opcode == "MUL":
                return left * right
            if opcode == "DIV":
                return left // right if right else None
            if opcode == "MOD":
                return left % right if right else None
        if opcode in {"SHL", "SHR"} and len(stmt.uses) >= 2:
            left = self._resolve_int_token(stmt.uses[0])
            right = self._resolve_int_token(stmt.uses[1])
            if left is None or right is None:
                return None
            if opcode == "SHL":
                return left << right
            return left >> right
        if opcode == "PHI":
            values = set()
            for token in stmt.uses:
                value = self._resolve_int_token(token)
                if value is None:
                    return None
                values.add(value)
            if len(values) == 1:
                return values.pop()
            return None
        if opcode == "MOV" and len(stmt.uses) == 1:
            return self._resolve_int_token(stmt.uses[0])
        return None

    def _pointer_offset_from_token(
        self,
        token: str,
        base_var: str,
        base_origin: Optional[str],
        seen: set[str],
    ) -> Optional[int]:
        var = normalize_var(token)
        if var:
            if var == base_var:
                return 0
            return self._pointer_offset_from_var(var, base_var, base_origin, seen)
        literal = extract_literal(token)
        if literal:
            try:
                return int(literal, 16)
            except ValueError:
                return None
        return None

    def _pointer_offset_from_var(
        self,
        var: str,
        base_var: str,
        base_origin: Optional[str],
        seen: set[str],
    ) -> Optional[int]:
        if var == base_var:
            return 0
        if var in seen:
            return None
        seen.add(var)
        stmt = self.var_def_stmt.get(var)
        if not stmt:
            return None
        opcode = stmt.opcode.upper()
        if opcode == "MLOAD" and stmt.uses and base_origin == "MLOAD ptr 0x40":
            # Free memory pointer heuristics: treat other MLOAD(0x40) as the same pointer
            # only if we see no intervening updates to memory[0x40] along a safe path.
            if _token_is_literal(stmt.uses[0], "0x40", self.var_literals):
                base_stmt = self.var_def_stmt.get(base_var)
                if (
                    base_stmt
                    and base_stmt.opcode.upper() == "MLOAD"
                    and base_stmt.uses
                    and _token_is_literal(base_stmt.uses[0], "0x40", self.var_literals)
                    and (
                        self._free_mem_ptr_unchanged_between_blocks(stmt, base_stmt)
                        or self._free_mem_ptr_unchanged_between_blocks(base_stmt, stmt)
                    )
                ):
                    return 0
            return None
        if opcode in {"SLOAD", "CALLDATALOAD"}:
            return None
        if opcode == "CONST":
            literal = self.var_literals.get(var)
            if literal:
                try:
                    return int(literal, 16)
                except ValueError:
                    return None
            return None
        if opcode in {"ADD", "SUB"} and len(stmt.uses) >= 2:
            left = self._pointer_offset_from_token(
                stmt.uses[0], base_var, base_origin, seen.copy()
            )
            right = self._pointer_offset_from_token(
                stmt.uses[1], base_var, base_origin, seen.copy()
            )
            if left is None or right is None:
                return None
            return left + right if opcode == "ADD" else left - right
        if opcode == "PHI":
            values = set()
            for token in stmt.uses:
                value = self._pointer_offset_from_token(
                    token, base_var, base_origin, seen.copy()
                )
                if value is None:
                    return None
                values.add(value)
            if len(values) == 1:
                return values.pop()
            return None
        if opcode in {"MOV"} and len(stmt.uses) == 1:
            return self._pointer_offset_from_token(
                stmt.uses[0], base_var, base_origin, seen
            )
        return None

    def _free_mem_ptr_unchanged_between(
        self, earlier: TacStatement, later: TacStatement
    ) -> bool:
        if not earlier.block or not later.block or earlier.block != later.block:
            return False
        start = self.statement_positions.get(id(earlier), -1)
        end = self.statement_positions.get(id(later), -1)
        if start == -1 or end == -1:
            return False
        if start > end:
            start, end = end, start
        block = self.blocks.get(earlier.block)
        if not block:
            return False
        for stmt in block.statements:
            pos = self.statement_positions.get(id(stmt), -1)
            if pos <= start or pos >= end:
                continue
            if stmt.opcode.upper() == "MSTORE" and stmt.uses:
                if _token_is_literal(stmt.uses[0], "0x40", self.var_literals):
                    return False
        return True

    def _block_has_mstore_0x40(
        self,
        block,
        *,
        after_pos: Optional[int] = None,
        before_pos: Optional[int] = None,
    ) -> bool:
        for stmt in block.statements:
            pos = self.statement_positions.get(id(stmt), -1)
            if after_pos is not None and pos <= after_pos:
                continue
            if before_pos is not None and pos >= before_pos:
                continue
            if stmt.opcode.upper() != "MSTORE" or not stmt.uses:
                continue
            if _token_is_literal(stmt.uses[0], "0x40", self.var_literals):
                return True
        return False

    def _free_mem_ptr_unchanged_between_blocks(
        self, earlier: TacStatement, later: TacStatement
    ) -> bool:
        if not earlier.block or not later.block:
            return False
        if earlier.block == later.block:
            return self._free_mem_ptr_unchanged_between(earlier, later)
        reachable = self.block_reachability.get(earlier.block)
        if not reachable or later.block not in reachable:
            return False
        earlier_pos = self.statement_positions.get(id(earlier), -1)
        later_pos = self.statement_positions.get(id(later), -1)
        earlier_block = self.blocks.get(earlier.block)
        later_block = self.blocks.get(later.block)
        if not earlier_block or not later_block:
            return False
        if self._block_has_mstore_0x40(earlier_block, after_pos=earlier_pos):
            return False
        if self._block_has_mstore_0x40(later_block, before_pos=later_pos):
            return False
        blocked: set[str] = set()
        for block_id, block in self.blocks.items():
            if block_id in {earlier.block, later.block}:
                continue
            if self._block_has_mstore_0x40(block):
                blocked.add(block_id)
        queue: deque[str] = deque([earlier.block])
        seen: set[str] = {earlier.block}
        while queue:
            block_id = queue.popleft()
            if block_id == later.block:
                return True
            block = self.blocks.get(block_id)
            if not block:
                continue
            for succ in block.successors:
                if not succ or succ in seen or succ in blocked:
                    continue
                seen.add(succ)
                queue.append(succ)
        return False

    def _trace_to_source(
        self, var: str, taint_info: Dict[str, TaintProvenance]
    ) -> List[TraceStep]:
        path: List[TraceStep] = []
        current = var
        seen: set[str] = set()
        while current and current not in seen:
            seen.add(current)
            info = taint_info.get(current)
            if not info:
                break
            path.append(
                TraceStep(
                    var=current,
                    statement=info.statement,
                    origin=self.describe_value_origin(current),
                )
            )
            if info.parent_var is None:
                break
            current = info.parent_var
        return path

    def _trace_to_input(
        self, var: str, taint_info: Dict[str, TaintProvenance]
    ) -> List[TraceStep]:
        if var in taint_info:
            return self._trace_to_source(var, taint_info)

        source_set = self.source_opcodes

        def dfs(current: str, seen: set[str]) -> List[TraceStep]:
            if current in seen:
                return []
            seen.add(current)
            stmt = self.var_def_stmt.get(current)
            if not stmt:
                return []
            step = TraceStep(
                var=current,
                statement=stmt,
                origin=self.describe_value_origin(current),
            )
            if stmt.opcode.upper() in source_set:
                return [step]
            for token in stmt.uses:
                upstream = normalize_var(token)
                if not upstream:
                    continue
                subpath = dfs(upstream, seen)
                if subpath:
                    return [step] + subpath
            return [step]

        return dfs(var, set())

    def describe_value_origin(self, var: Optional[str]) -> Optional[str]: # return variable origin opcode statement
        if not var: 
            return None
        match = _ARG_VAR_PATTERN.match(var)
        if match:
            return f"ARG arg{match.group(1)}"
        stmt = self.var_def_stmt.get(var)
        if not stmt:
            return None
        opcode = stmt.opcode.upper()
        if opcode == "SLOAD" and stmt.uses:
            slot = self.resolve_operand_expression(stmt.uses[0])
            return f"SLOAD slot {slot}"
        if opcode == "MLOAD" and stmt.uses:
            ptr = self.resolve_operand_expression(stmt.uses[0])
            return f"MLOAD ptr {ptr}"
        if opcode == "CALLDATALOAD" and stmt.uses:
            ptr = self.resolve_operand_expression(stmt.uses[0])
            return f"CALLDATALOAD offset {ptr}"
        return None

    def resolve_operand_expression(self, token: str, depth: int = 0) -> str:
        var = normalize_var(token)
        if var:
            return self.resolve_expression(var, depth)
        literal = extract_literal(token)
        if literal:
            return literal
        stripped = token.strip()
        if stripped:
            return stripped
        return token

    def resolve_expression(self, var: str, depth: int = 0) -> str:
        if var in self.expr_cache:
            return self.expr_cache[var]
        expr = self._resolve_expression_inner(var, set(), depth)
        self.expr_cache[var] = expr
        return expr

    def _resolve_expression_inner(
        self,
        var: str,
        seen: set[str],
        depth: int,
    ) -> str:
        if depth > 8 or var in seen:
            return var
        seen.add(var)
        stmt = self.var_def_stmt.get(var)
        if not stmt:
            return var
        opcode = stmt.opcode.upper()
        if opcode == "CONST":
            literal = self.var_literals.get(var)
            return literal or var
        if opcode == "CALLER":
            return "caller()"
        if opcode == "ORIGIN":
            return "origin()"
        uses_expr = [
            self.resolve_operand_expression(token, depth + 1) for token in stmt.uses
        ]
        if opcode == "ADD" and len(uses_expr) >= 2:
            return f"({uses_expr[0]} + {uses_expr[1]})"
        if opcode == "SUB" and len(uses_expr) >= 2:
            return f"({uses_expr[0]} - {uses_expr[1]})"
        if opcode == "MUL" and len(uses_expr) >= 2:
            return f"({uses_expr[0]} * {uses_expr[1]})"
        if opcode == "DIV" and len(uses_expr) >= 2:
            return f"({uses_expr[0]} / {uses_expr[1]})"
        if opcode == "MOD" and len(uses_expr) >= 2:
            return f"({uses_expr[0]} % {uses_expr[1]})"
        if opcode == "EXP" and len(uses_expr) >= 2:
            return f"exp({uses_expr[0]}, {uses_expr[1]})"
        if opcode == "SHA3":
            return f"sha3({', '.join(uses_expr)})"
        if opcode == "AND" and len(uses_expr) >= 2:
            return f"({uses_expr[0]} & {uses_expr[1]})"
        if opcode == "OR" and len(uses_expr) >= 2:
            return f"({uses_expr[0]} | {uses_expr[1]})"
        if opcode == "SHL" and len(uses_expr) >= 2:
            return f"({uses_expr[0]} << {uses_expr[1]})"
        if opcode == "SHR" and len(uses_expr) >= 2:
            return f"({uses_expr[0]} >> {uses_expr[1]})"
        if opcode == "SLOAD" and len(uses_expr) >= 1:
            return f"sload({uses_expr[0]})"
        if opcode == "MLOAD" and len(uses_expr) >= 1:
            return f"mload({uses_expr[0]})"
        if opcode == "CALLDATALOAD" and len(uses_expr) >= 1:
            return f"calldataload({uses_expr[0]})"
        literal = self.var_literals.get(var)
        if literal:
            return literal
        return var


def describe_log_operand(opcode: str, index: int) -> str:
    labels = ["mem_start", "mem_len", "topic0", "topic1", "topic2", "topic3"]
    log_index = int(opcode[-1])
    max_index = 2 + log_index
    if index < len(labels) and index < max_index:
        return labels[index]
    return f"arg{index}"


_ARG_VAR_PATTERN = re.compile(r".*arg(\d+)$", re.IGNORECASE)


def _token_is_literal(token: str, literal: str, var_literals: Dict[str, Optional[str]]) -> bool:
    extracted = extract_literal(token)
    if extracted and extracted.lower() == literal.lower():
        return True
    var = normalize_var(token)
    if var:
        resolved = var_literals.get(var)
        if resolved and resolved.lower() == literal.lower():
            return True
    return False
