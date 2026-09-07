#!/usr/bin/env python3
import argparse
import csv
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


CODE_BLOCK_RE = re.compile(r"```[^\n]*\n(.*?)```", re.S)
EVENT_RE = re.compile(r"\bevent\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
FUNC_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
NORMATIVE_RE = re.compile(r"\b(MUST|SHOULD|MAY|OPTIONAL|REQUIRED|SHALL)\b")
EMIT_RE = re.compile(r"\b(emit|emits|emitted|trigger|triggers|fire|fires)\b", re.I)
CAMEL_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+")


def load_signature_map(path: Path) -> Dict[str, str]:
    sig_map: Dict[str, str] = {}
    if not path.exists():
        return sig_map
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line or "\t" not in line:
                continue
            topic0, sig = line.split("\t", 1)
            sig = sig.strip()
            topic0 = topic0.strip()
            sig_map.setdefault(sig, topic0)
    return sig_map


def parse_front_matter(text: str) -> Tuple[Dict[str, str], str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    meta: Dict[str, str] = {}
    i = 1
    while i < len(lines):
        line = lines[i].strip()
        if line == "---":
            break
        if ":" in line:
            key, value = line.split(":", 1)
            meta[key.strip().lower()] = value.strip()
        i += 1
    body = "\n".join(lines[i + 1 :]) if i < len(lines) else text
    return meta, body


def extract_code_blocks(text: str) -> List[str]:
    return [block for block in CODE_BLOCK_RE.findall(text)]


def extract_function_names(code_blocks: Iterable[str]) -> List[str]:
    names: List[str] = []
    seen = set()
    for block in code_blocks:
        for match in FUNC_RE.finditer(block):
            name = match.group(1)
            if name not in seen:
                seen.add(name)
                names.append(name)
    return names


def split_params(param_str: str) -> List[str]:
    params: List[str] = []
    buf: List[str] = []
    depth = 0
    for ch in param_str:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        if ch == "," and depth == 0:
            params.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if buf:
        params.append("".join(buf))
    return params


def normalize_type(type_token: str) -> str:
    cleaned = type_token.strip().strip(",;")
    if cleaned == "uint":
        return "uint256"
    if cleaned == "int":
        return "int256"
    return cleaned


def parse_param_segment(segment: str) -> Optional[Dict[str, object]]:
    seg = segment.strip()
    if not seg:
        return None
    indexed = bool(re.search(r"\bindexed\b", seg))
    seg = re.sub(r"\bindexed\b", " ", seg)
    seg = re.sub(r"\b(memory|calldata|storage|payable)\b", " ", seg)
    seg = re.sub(r"/\*.*?\*/", " ", seg)
    seg = seg.replace("\n", " ")
    tokens = [tok for tok in re.split(r"\s+", seg) if tok]
    if not tokens:
        return None
    type_token = normalize_type(tokens[0])
    name_token = tokens[1].strip(",;") if len(tokens) > 1 else None
    return {"type": type_token, "name": name_token, "indexed": indexed}


def parse_event_params(param_str: str) -> List[Dict[str, object]]:
    params: List[Dict[str, object]] = []
    for seg in split_params(param_str):
        parsed = parse_param_segment(seg)
        if parsed:
            params.append(parsed)
    return params


def extract_paren_content(text: str, start_idx: int) -> Tuple[str, int]:
    depth = 0
    buf: List[str] = []
    i = start_idx
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return "".join(buf), i + 1
        if depth >= 1:
            buf.append(ch)
        i += 1
    return "".join(buf), i


def extract_event_defs(text: str) -> List[Dict[str, object]]:
    events: List[Dict[str, object]] = []
    for match in EVENT_RE.finditer(text):
        name = match.group(1)
        param_str, end_idx = extract_paren_content(text, match.end() - 1)
        params = parse_event_params(param_str)
        tail = text[end_idx : end_idx + 80]
        anonymous = "anonymous" in tail
        types = [p["type"] for p in params]
        signature = f"{name}({','.join(types)})"
        events.append(
            {
                "name": name,
                "params": params,
                "signature": signature,
                "anonymous": anonymous,
            }
        )
    return events


def event_quality(event: Dict[str, object]) -> Tuple[int, int]:
    params = event.get("params") or []
    named = sum(1 for p in params if p.get("name"))
    return (named, len(params))


def build_param_labels(params: List[Dict[str, object]]) -> List[Dict[str, object]]:
    topic_index = 0
    data_index = 0
    labeled: List[Dict[str, object]] = []
    for param_index, param in enumerate(params):
        is_topic = bool(param.get("indexed"))
        if is_topic:
            label = f"topic{topic_index + 1}"
            entry = {
                **param,
                "label": label,
                "param_index": param_index,
                "topic_index": topic_index,
                "data_index": None,
            }
            topic_index += 1
        else:
            label = f"data{data_index}"
            entry = {
                **param,
                "label": label,
                "param_index": param_index,
                "topic_index": None,
                "data_index": data_index,
            }
            data_index += 1
        labeled.append(entry)
    return labeled


def tokenize_identifier(name: str) -> List[str]:
    tokens: List[str] = []
    for chunk in re.split(r"[^A-Za-z0-9]+", name or ""):
        if not chunk:
            continue
        tokens.extend(CAMEL_RE.findall(chunk))
    return [token.lower() for token in tokens if token]


def normalized_tokens(name: str) -> set[str]:
    tokens = tokenize_identifier(name)
    variants: set[str] = set()
    suffixes = ("ments", "ment", "ions", "ion", "ing", "ed", "ers", "er", "al", "s")
    for token in tokens:
        if len(token) < 2:
            continue
        variants.add(token)
        base = token
        for suffix in suffixes:
            if base.endswith(suffix) and len(base) > len(suffix) + 2:
                variants.add(base[: -len(suffix)])
                break
        if base.endswith("e") and len(base) > 4:
            variants.add(base[:-1])
    return variants


def guess_trigger_functions(event_name: str, function_names: List[str]) -> List[str]:
    if not event_name or not function_names:
        return []
    event_tokens = normalized_tokens(event_name)
    if not event_tokens:
        return []
    event_lower = event_name.lower()
    scored: List[Tuple[int, str]] = []
    for fn in function_names:
        if not fn:
            continue
        fn_lower = fn.lower()
        fn_tokens = normalized_tokens(fn)
        score = len(event_tokens & fn_tokens)
        if event_lower in fn_lower or fn_lower in event_lower:
            score += 2
        if score <= 0:
            continue
        scored.append((score, fn))
    if not scored:
        return []
    max_score = max(score for score, _ in scored)
    candidates = sorted(fn for score, fn in scored if score == max_score)
    return candidates[:8]


def extract_event_comments(code_block: str) -> Dict[str, List[str]]:
    comments: Dict[str, List[str]] = {}
    lines = code_block.splitlines()
    buffer: List[str] = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if in_block:
            content = stripped
            if "*/" in stripped:
                content, _ = stripped.split("*/", 1)
                in_block = False
            content = content.lstrip("*").strip()
            if content:
                buffer.append(content)
            if not in_block:
                continue
            continue

        if stripped.startswith("/*"):
            content = stripped[2:]
            if "*/" in content:
                content, _ = content.split("*/", 1)
                content = content.lstrip("*").strip()
                if content:
                    buffer.append(content)
            else:
                content = content.lstrip("*").strip()
                if content:
                    buffer.append(content)
                in_block = True
            continue

        if stripped.startswith("//"):
            content = stripped.lstrip("/").strip()
            if content:
                buffer.append(content)
            continue

        if not stripped:
            if buffer:
                buffer = []
            continue

        match = EVENT_RE.search(stripped)
        if match:
            name = match.group(1)
            if buffer:
                comments.setdefault(name, []).extend(buffer)
            buffer = []
            continue

        buffer = []
    return comments


def is_requirement_line(line: str) -> bool:
    return bool(NORMATIVE_RE.search(line) or EMIT_RE.search(line))


def requirement_level(line: str) -> Optional[str]:
    match = NORMATIVE_RE.search(line)
    if not match:
        return None
    return match.group(1)


def collect_text_requirements(
    text_lines: List[str],
    event_name: str,
    function_names: List[str],
) -> List[Dict[str, object]]:
    reqs: List[Dict[str, object]] = []
    event_pat = re.compile(rf"\b{re.escape(event_name)}\b")
    for line in text_lines:
        if not event_pat.search(line):
            continue
        if not is_requirement_line(line):
            continue
        funcs = [fn for fn in function_names if re.search(rf"\b{re.escape(fn)}\b", line)]
        reqs.append(
            {
                "level": requirement_level(line),
                "text": line.strip(),
                "functions": funcs,
                "source": "text",
            }
        )
    return reqs


def collect_comment_requirements(
    comment_lines: List[str], function_names: List[str]
) -> List[Dict[str, object]]:
    reqs: List[Dict[str, object]] = []
    for line in comment_lines:
        if not is_requirement_line(line):
            continue
        funcs = [fn for fn in function_names if re.search(rf"\b{re.escape(fn)}\b", line)]
        reqs.append(
            {
                "level": requirement_level(line),
                "text": line.strip(),
                "functions": funcs,
                "source": "comment",
            }
        )
    return reqs


def extract_erc_events(md_path: Path, sig_map: Dict[str, str]) -> List[Dict[str, object]]:
    text = md_path.read_text(encoding="utf-8", errors="ignore")
    meta, body = parse_front_matter(text)
    code_blocks = extract_code_blocks(body)
    function_names = extract_function_names(code_blocks)

    events_by_sig: Dict[str, Dict[str, object]] = {}
    event_comments: Dict[str, List[str]] = {}

    for block in code_blocks:
        for event in extract_event_defs(block):
            sig = event["signature"]
            current = events_by_sig.get(sig)
            if not current or event_quality(event) > event_quality(current):
                events_by_sig[sig] = event
        comments = extract_event_comments(block)
        for name, lines in comments.items():
            event_comments.setdefault(name, []).extend(lines)

    text_without_code = CODE_BLOCK_RE.sub("", body)
    for event in extract_event_defs(text_without_code):
        sig = event["signature"]
        current = events_by_sig.get(sig)
        if not current or event_quality(event) > event_quality(current):
            events_by_sig[sig] = event

    text_lines = [line.strip() for line in text_without_code.splitlines()]

    erc_id = meta.get("eip", "")
    try:
        erc_id_num = int(erc_id)
    except (TypeError, ValueError):
        erc_id_num = None

    records: List[Dict[str, object]] = []
    for sig, event in events_by_sig.items():
        params = event.get("params") or []
        labeled_params = build_param_labels(params)
        indexed_count = sum(1 for p in params if p.get("indexed"))
        data_count = len(params) - indexed_count
        reqs = []
        reqs.extend(
            collect_text_requirements(text_lines, event["name"], function_names)
        )
        comment_lines = event_comments.get(event["name"], [])
        reqs.extend(collect_comment_requirements(comment_lines, function_names))
        deduped: List[Dict[str, object]] = []
        seen_text = set()
        for req in reqs:
            key = (req.get("text"), req.get("source"))
            if key in seen_text:
                continue
            seen_text.add(key)
            deduped.append(req)
        trigger_functions = sorted(
            {fn for req in deduped for fn in (req.get("functions") or [])}
        )
        trigger_source = "requirements" if trigger_functions else "none"
        if not trigger_functions:
            guessed = guess_trigger_functions(event["name"], function_names)
            if guessed:
                trigger_functions = guessed
                trigger_source = "heuristic"
        record = {
            "erc_id": erc_id_num,
            "erc_title": meta.get("title"),
            "status": meta.get("status"),
            "category": meta.get("category"),
            "source_path": str(md_path),
            "event_name": event["name"],
            "event_signature": sig,
            "topic0": None if event.get("anonymous") else sig_map.get(sig),
            "anonymous": bool(event.get("anonymous")),
            "params": labeled_params,
            "indexed_count": indexed_count,
            "data_count": data_count,
            "requirements": deduped,
            "trigger_functions": trigger_functions,
            "trigger_functions_source": trigger_source,
        }
        records.append(record)
    records.sort(key=lambda item: (item["erc_id"] or 0, item["event_name"]))
    return records


def flatten_record(record: Dict[str, object]) -> Dict[str, str]:
    reqs = record.get("requirements") or []
    req_texts = [req.get("text", "") for req in reqs if req.get("text")]
    req_levels = sorted({req.get("level") for req in reqs if req.get("level")})
    trigger_functions = record.get("trigger_functions") or []
    trigger_functions_source = record.get("trigger_functions_source") or ""
    params = record.get("params") or []
    param_count = len(params)
    indexed_count = record.get("indexed_count", 0)
    data_count = record.get("data_count", 0)
    param_types = [param.get("type", "") or "" for param in params]
    param_names = [param.get("name", "") or "" for param in params]
    indexed_flags = ["1" if param.get("indexed") else "0" for param in params]
    param_labels = [param.get("label", "") or "" for param in params]
    indexed_positions = [
        str(idx) for idx, param in enumerate(params) if param.get("indexed")
    ]
    data_positions = [
        str(idx) for idx, param in enumerate(params) if not param.get("indexed")
    ]
    topic_labels = sorted(
        label for label in param_labels if label.startswith("topic")
    )
    indexed_key = ",".join(topic_labels) if topic_labels else "-"
    spec_shape = f"topics:{indexed_count}|data:{data_count}|indexed:{indexed_key}"
    return {
        "erc_id": "" if record.get("erc_id") is None else str(record.get("erc_id")),
        "erc_title": record.get("erc_title") or "",
        "status": record.get("status") or "",
        "category": record.get("category") or "",
        "event_name": record.get("event_name") or "",
        "event_signature": record.get("event_signature") or "",
        "topic0": record.get("topic0") or "",
        "anonymous": str(bool(record.get("anonymous"))),
        "param_count": str(param_count),
        "indexed_count": str(indexed_count),
        "data_count": str(data_count),
        "param_types": ";".join(param_types),
        "param_names": ";".join(param_names),
        "indexed_flags": ";".join(indexed_flags),
        "param_labels": ";".join(param_labels),
        "indexed_positions": ";".join(indexed_positions),
        "data_positions": ";".join(data_positions),
        "spec_shape": spec_shape,
        "params_json": json.dumps(params, ensure_ascii=True),
        "requirement_count": str(len(reqs)),
        "requirement_levels": ";".join(req_levels),
        "requirements_text": "\n".join(req_texts),
        "trigger_functions": ";".join(trigger_functions),
        "trigger_functions_source": trigger_functions_source,
        "source_path": record.get("source_path") or "",
    }


def write_csv(records: List[Dict[str, object]], path: Path) -> None:
    rows = [flatten_record(record) for record in records]
    fieldnames = list(rows[0].keys()) if rows else []
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract ERC event specs to JSONL.")
    parser.add_argument(
        "--erc-md",
        type=Path,
        default=Path("erc-md"),
        help="Path to ERC markdown directory (default: ./erc-md).",
    )
    parser.add_argument(
        "--sig-map",
        type=Path,
        default=Path("src/resources/EventSignature.facts"),
        help="Path to EventSignature.facts.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("artifacts/erc_events.jsonl"),
        help="Output JSONL path.",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=None,
        help="Optional CSV output path.",
    )
    args = parser.parse_args()

    sig_map = load_signature_map(args.sig_map)
    md_dir = args.erc_md
    if not md_dir.exists():
        raise SystemExit(f"erc-md directory not found: {md_dir}")
    records: List[Dict[str, object]] = []
    for md_path in sorted(md_dir.glob("erc-*.md")):
        records.extend(extract_erc_events(md_path, sig_map))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for rec in records:
            handle.write(json.dumps(rec, ensure_ascii=True) + "\n")

    if args.out_csv:
        write_csv(records, args.out_csv)

    print(f"Wrote {len(records)} event records to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
