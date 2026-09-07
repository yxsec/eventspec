"""Helpers for loading auxiliary facts (signatures, knowledge, entry points)."""

from __future__ import annotations

import csv
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List, Optional

from .models import EntryPointIndex


def load_event_signatures(path: Path) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    with path.open(encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "\t" in line:
                left, right = line.split("\t", 1)
            else:
                parts = line.split(None, 1)
                if not parts:
                    continue
                if len(parts) == 1:
                    left, right = parts[0], ""
                else:
                    left, right = parts[0], parts[1]
            left = left.strip()
            right = right.strip()
            if not left or not right:
                continue
            mapping[left.lower()] = right
    return mapping


def read_csv_rows(path: Path, expected_columns: int = 2) -> List[List[str]]:
    rows: List[List[str]] = []
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle, delimiter="\t")
        for raw_row in reader:
            if not raw_row:
                continue
            row = [cell.strip() for cell in raw_row if cell is not None]
            if len(row) < expected_columns:
                continue
            rows.append(row[:expected_columns])
    return rows


def load_entrypoint_index(facts_dir: Path) -> Optional[EntryPointIndex]:
    in_function_path = facts_dir / "InFunction.csv"
    public_function_path = facts_dir / "PublicFunction.csv"
    high_level_path = facts_dir / "HighLevelFunctionName.csv"
    call_graph_path = facts_dir / "IRFunctionCall.csv"

    if not in_function_path.exists() or not public_function_path.exists():
        return None

    block_to_function: Dict[str, str] = {}
    function_ids: set[str] = set()
    for block, func in read_csv_rows(in_function_path):
        block_to_function[block] = func
        function_ids.add(func)

    function_names: Dict[str, str] = {}
    if high_level_path.exists():
        function_names = {func: name for func, name in read_csv_rows(high_level_path)}

    public_function_map = {
        func: selector for func, selector in read_csv_rows(public_function_path)
    }
    public_ids = set(public_function_map.keys())
    for func_id, name in function_names.items():
        lowered = name.strip().lower()
        if lowered in {"fallback()"}:
            public_ids.add(func_id)

    call_graph: Dict[str, set[str]] = defaultdict(set)
    callsites_by_callee: Dict[str, List[str]] = defaultdict(list)
    if call_graph_path.exists():
        for caller_block, callee_func in read_csv_rows(call_graph_path):
            caller_func = block_to_function.get(caller_block)
            if not caller_func:
                continue
            call_graph[caller_func].add(callee_func)
            callsites_by_callee[callee_func].append(caller_block)
            function_ids.add(callee_func)

    all_functions = set(function_ids)
    all_functions.update(call_graph.keys())
    for targets in call_graph.values():
        all_functions.update(targets)

    function_reachability: Dict[str, set[str]] = {func: set() for func in all_functions}
    for public_func in public_ids:
        queue: deque[str] = deque([public_func])
        visited: set[str] = set()
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            function_reachability.setdefault(current, set()).add(public_func)
            for successor in call_graph.get(current, ()):
                queue.append(successor)

    reachability_ids: Dict[str, List[str]] = {}
    reachability_named: Dict[str, List[str]] = {}
    for func, publics in function_reachability.items():
        if not publics:
            reachability_ids[func] = []
            reachability_named[func] = []
            continue
        reachability_ids[func] = sorted(publics)
        reachability_named[func] = [
            _entry_point_display_name(public_func, function_names, public_function_map)
            for public_func in sorted(
                publics,
                key=lambda fid: _entry_point_display_name(
                    fid, function_names, public_function_map
                ),
            )
        ]

    return EntryPointIndex(
        block_to_function=block_to_function,
        function_reachability=reachability_named,
        function_reachability_ids=reachability_ids,
        function_names=function_names,
        callsites_by_callee=dict(callsites_by_callee),
        public_selectors=public_function_map,
    )


def _entry_point_display_name(
    func_id: str,
    function_names: Dict[str, str],
    public_selectors: Dict[str, str],
) -> str:
    name = (function_names.get(func_id) or "").strip()
    if name and name != func_id and name != "__function_selector__":
        return name
    selector = public_selectors.get(func_id)
    return selector or func_id
