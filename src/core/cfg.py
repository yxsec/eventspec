"""CFG construction utilities for TAC blocks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from .models import TacStatement


@dataclass
class BlockInfo:
    block_id: str
    function: Optional[str]
    predecessors: List[str] = field(default_factory=list)
    successors: List[str] = field(default_factory=list)
    statements: List[TacStatement] = field(default_factory=list)


def build_cfg(statements: Sequence[TacStatement]) -> Dict[str, BlockInfo]:
    blocks: Dict[str, BlockInfo] = {}
    for stmt in statements:
        block_id = stmt.block
        if not block_id:
            continue
        info = blocks.setdefault(
            block_id,
            BlockInfo(
                block_id=block_id,
                function=stmt.function,
            ),
        )
        if not info.predecessors and stmt.block_predecessors:
            info.predecessors.extend(stmt.block_predecessors)
        if not info.successors and stmt.block_successors:
            info.successors.extend(stmt.block_successors)
        info.statements.append(stmt)
    return blocks


def compute_block_reachability(blocks: Dict[str, BlockInfo]) -> Dict[str, Set[str]]:
    reachability: Dict[str, Set[str]] = {}
    for block_id in blocks:
        visited: Set[str] = set()
        stack: List[str] = list(blocks[block_id].successors)
        while stack:
            succ = stack.pop()
            if not succ or succ in visited:
                continue
            visited.add(succ)
            succ_block = blocks.get(succ)
            if succ_block:
                stack.extend(succ_block.successors)
        reachability[block_id] = visited
    return reachability


def compute_function_entries(blocks: Dict[str, BlockInfo]) -> Dict[str, str]:
    def sort_key(block_id: str) -> tuple[int, int, str]:
        text = (block_id or "").strip().lower()
        try:
            value = int(text, 16) if text.startswith("0x") else int(text, 10)
            return (0, value, text)
        except ValueError:
            return (1, 0, text)

    blocks_by_func: Dict[str, List[str]] = {}
    entry_candidates: Dict[str, List[str]] = {}
    for block_id, block in blocks.items():
        func = block.function or "<global>"
        blocks_by_func.setdefault(func, []).append(block_id)
        if not block.predecessors:
            entry_candidates.setdefault(func, []).append(block_id)

    entries: Dict[str, str] = {}
    for func, block_ids in blocks_by_func.items():
        candidates = entry_candidates.get(func) or []
        chosen = min(candidates or block_ids, key=sort_key)
        entries[func] = chosen
    return entries


def compute_dominators(blocks: Dict[str, BlockInfo]) -> Dict[str, Set[str]]:
    dominators: Dict[str, Set[str]] = {}
    func_entries = compute_function_entries(blocks)
    func_blocks: Dict[str, List[str]] = {}
    for block_id, block in blocks.items():
        func = block.function or "<global>"
        func_blocks.setdefault(func, []).append(block_id)

    for func, block_ids in func_blocks.items():
        entry = func_entries.get(func, block_ids[0])
        dom_map: Dict[str, Set[str]] = {bid: set(block_ids) for bid in block_ids}
        dom_map[entry] = {entry}
        changed = True
        while changed:
            changed = False
            for bid in block_ids:
                if bid == entry:
                    continue
                block = blocks[bid]
                preds = [
                    pred
                    for pred in block.predecessors
                    if pred in block_ids
                ]
                if not preds:
                    new_dom = {bid}
                else:
                    intersection = set(block_ids)
                    for pred in preds:
                        intersection &= dom_map.get(pred, set(block_ids))
                    new_dom = intersection | {bid}
                if dom_map[bid] != new_dom:
                    dom_map[bid] = new_dom
                    changed = True
        dominators.update(dom_map)
    return dominators
