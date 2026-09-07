"""Utilities for building taint-guided slices for Greed."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .cfg import BlockInfo
from .models import LogReport, TacStatement


@dataclass
class LogSlice:
    """Subset of blocks/statements relevant to a LOG operand's taint path."""

    log_statement: TacStatement
    block_ids: Set[str] = field(default_factory=set)
    statement_uids: Set[str] = field(default_factory=set)
    targets: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def log_uid(self) -> str:
        return self.log_statement.uid

    @property
    def log_statement_id(self) -> str:
        return self.log_statement.offset


def build_log_slices(
    reports: Sequence[LogReport],
    dominators: Optional[Dict[str, Set[str]]] = None,
    blocks: Optional[Dict[str, BlockInfo]] = None,
    *,
    include_untainted: bool = False,
) -> List[LogSlice]:
    slices: List[LogSlice] = []
    for report in reports:
        statement_uids: Set[str] = {report.statement.uid}
        block_ids: Set[str] = set()
        if report.statement.block:
            block_ids.add(report.statement.block)
        targets: List[Tuple[str, str]] = []

        def add_operand_path(path: Iterable, label: str, var: Optional[str]) -> None:
            if not var:
                return
            targets.append((label, var))
            for step in path:
                statement_uids.add(step.statement.uid)
                if step.statement.block:
                    block_ids.add(step.statement.block)

        for operand in report.operands:
            if operand.label in {"mem_start", "mem_len"}:
                continue
            if not include_untainted and not operand.tainted:
                continue
            add_operand_path(operand.path, operand.label, operand.var)
        for operand in report.memory_operands:
            if not include_untainted and not operand.tainted:
                continue
            add_operand_path(operand.path, operand.label, operand.var)

        if not targets:
            continue

        block_id = report.statement.block
        if dominators and block_id:
            block_ids.update(dominators.get(block_id, set()))
        if blocks and block_id:
            stack = [block_id]
            visited: Set[str] = set()
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                info = blocks.get(current)
                if not info:
                    continue
                for pred in info.predecessors:
                    if pred and pred not in visited:
                        stack.append(pred)
            block_ids.update(visited)

        slices.append(
            LogSlice(
                log_statement=report.statement,
                block_ids=block_ids,
                statement_uids=statement_uids,
                targets=targets,
            )
        )
    return slices
