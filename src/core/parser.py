"""TAC parsing helpers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

from .models import TacStatement


_LITERAL_PATTERN = re.compile(r"\((0x[0-9a-fA-F]+)\)")


def normalize_var(token: str) -> Optional[str]:
    token = token.strip()
    if not token or not token.startswith("v"):
        return None
    paren = token.find("(")
    if paren != -1:
        return token[:paren]
    return token


def extract_literal(token: str) -> Optional[str]:
    match = _LITERAL_PATTERN.search(token)
    if match:
        return match.group(1)
    return None


def parse_tac_file(path: Path) -> List[TacStatement]:
    statements: List[TacStatement] = []
    function_pattern = re.compile(r"^function\s+([^\(]+)\(")
    block_pattern = re.compile(r"^Begin block\s+(\S+)")
    stmt_pattern = re.compile(r"^\s*([0-9a-fA-FxX]+):\s*(.+)$")
    block_meta_pattern = re.compile(r"^prev=\[(.*)\],\s*succ=\[(.*)\]$")

    current_function: Optional[str] = None
    current_block: Optional[str] = None
    current_block_predecessors: Tuple[str, ...] = ()
    current_block_successors: Tuple[str, ...] = ()

    with path.open(encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("function "):
                func_match = function_pattern.match(stripped)
                if func_match:
                    current_function = func_match.group(1).strip()
                continue
            if stripped == "}":
                current_function = None
                current_block = None
                continue
            block_match = block_pattern.match(stripped)
            if block_match:
                current_block = block_match.group(1)
                current_block_predecessors = ()
                current_block_successors = ()
                continue
            meta_match = block_meta_pattern.match(stripped.replace(" ", ""))
            if meta_match:
                current_block_predecessors = _parse_block_list(meta_match.group(1))
                current_block_successors = _parse_block_list(meta_match.group(2))
                continue
            if stripped.startswith("Predecessors:") or stripped.startswith(
                "Successors:"
            ):
                continue
            stmt_match = stmt_pattern.match(line)
            if not stmt_match:
                continue
            offset = stmt_match.group(1)
            rest = stmt_match.group(2).strip()
            def_tokens: List[str] = []
            if "=" in rest:
                left, expr = rest.split("=", 1)
                def_tokens = [token for token in left.split(",") if token.strip()]
            else:
                expr = rest
                def_tokens = []
            defs_list: List[str] = []
            def_literals: List[Optional[str]] = []
            for token in def_tokens:
                var = normalize_var(token)
                if not var:
                    continue
                defs_list.append(var)
                def_literals.append(extract_literal(token))
            defs = tuple(defs_list)
            expr = expr.strip()
            if not expr:
                continue
            parts = expr.split(None, 1)
            opcode = parts[0]
            arg_text = parts[1] if len(parts) > 1 else ""
            uses_tokens = [token.strip() for token in arg_text.split(",") if token.strip()]
            statements.append(
                TacStatement(
                    offset=offset,
                    opcode=opcode,
                    defs=defs,
                    def_literals=tuple(def_literals),
                    uses=tuple(uses_tokens),
                    raw=line.strip(),
                    function=current_function,
                    block=current_block,
                    block_predecessors=current_block_predecessors,
                    block_successors=current_block_successors,
                )
            )
    return statements


def _parse_block_list(text: str) -> Tuple[str, ...]: # Process prev=[0x13e], succ=[0x154, 0x7fe]
    stripped = text.strip()
    if not stripped:
        return ()
    items = [item.strip() for item in stripped.split(",") if item.strip()]
    return tuple(items)
