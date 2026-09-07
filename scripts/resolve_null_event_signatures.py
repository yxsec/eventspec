#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

# --- Keccak-256 (Ethereum) ---
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

R = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

MASK64 = (1 << 64) - 1


def rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & MASK64


def keccak_f(state: list[int]) -> None:
    for rc in RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], R[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])
        state[0] ^= rc


def keccak_256(data: bytes) -> bytes:
    rate = 136
    state = [0] * 25
    pad_len = rate - (len(data) % rate)
    if pad_len == 1:
        data += b"\x81"
    else:
        data += b"\x01" + b"\x00" * (pad_len - 2) + b"\x80"
    for off in range(0, len(data), rate):
        block = data[off:off + rate]
        for i in range(0, rate, 8):
            state[i // 8] ^= int.from_bytes(block[i:i + 8], "little")
        keccak_f(state)
    out = bytearray()
    while len(out) < 32:
        for i in range(0, rate, 8):
            out += state[i // 8].to_bytes(8, "little")
            if len(out) >= 32:
                break
        if len(out) < 32:
            keccak_f(state)
    return bytes(out[:32])


def keccak_hex(sig: str) -> str:
    return "0x" + keccak_256(sig.encode("utf-8")).hex()


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//.*", "", src)
    return src


def _extract_params(src: str, start_idx: int) -> tuple[str, int] | None:
    if start_idx >= len(src) or src[start_idx] != "(":
        return None
    depth = 0
    i = start_idx
    while i < len(src):
        ch = src[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return src[start_idx + 1:i], i + 1
        i += 1
    return None


def _split_params(params: str) -> list[str]:
    parts = []
    buf = []
    depth = 0
    for ch in params:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _canonical_type(param: str) -> str:
    # remove param name if present (last token)
    m = re.match(r"^\s*(.+?)\s+([A-Za-z_]\w*)\s*$", param)
    type_part = m.group(1) if m else param
    # drop known modifiers
    type_part = re.sub(r"\b(indexed|memory|calldata|storage|payable)\b", "", type_part)
    type_part = re.sub(r"\btuple\s*\(", "(", type_part)
    type_part = re.sub(r"\s+", " ", type_part).strip()
    # remove spaces to match canonical signature formatting
    type_part = type_part.replace(" ", "")
    return type_part


def extract_events_from_sol(path: Path) -> dict[str, set[str]]:
    src = path.read_text(errors="replace")
    src = strip_comments(src)
    events: dict[str, set[str]] = {}
    i = 0
    while True:
        idx = src.find("event", i)
        if idx == -1:
            break
        # ensure word boundary
        if idx > 0 and (src[idx - 1].isalnum() or src[idx - 1] == "_"):
            i = idx + 5
            continue
        j = idx + 5
        while j < len(src) and src[j].isspace():
            j += 1
        m = re.match(r"[A-Za-z_]\w*", src[j:])
        if not m:
            i = idx + 5
            continue
        name = m.group(0)
        j += len(name)
        while j < len(src) and src[j].isspace():
            j += 1
        if j >= len(src) or src[j] != "(":
            i = j
            continue
        extracted = _extract_params(src, j)
        if not extracted:
            i = j + 1
            continue
        params_str, end_idx = extracted
        params = _split_params(params_str)
        types = [_canonical_type(p) for p in params]
        sig = f"{name}({','.join(types)})"
        topic0 = keccak_hex(sig)
        events.setdefault(topic0, set()).add(sig)
        i = end_idx
    return events


def filename_address(name: str) -> str | None:
    base = name.split("_", 1)[0]
    if base.startswith("0x") and len(base) == 42:
        base = base[2:]
    if len(base) == 40 and all(c in "0123456789abcdefABCDEF" for c in base):
        return base.lower()
    return None


def build_prefix_index(prefix_dir: Path) -> dict[str, list[Path]]:
    idx: dict[str, list[Path]] = {}
    for p in prefix_dir.iterdir():
        if not p.is_file():
            continue
        addr = filename_address(p.name)
        if not addr:
            continue
        idx.setdefault(addr, []).append(p)
    return idx


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve event_signature=null topic0 by source parsing.")
    parser.add_argument(
        "--patterns",
        type=str,
        required=True,
        help="Path to event_patterns.jsonl",
    )
    parser.add_argument(
        "--id-map",
        type=str,
        required=True,
        help="Path to contract_id_to_addresses.json",
    )
    parser.add_argument(
        "--sanctuary",
        type=str,
        required=True,
        help="Path to smart-contract-sanctuary-ethereum/contracts/mainnet",
    )
    parser.add_argument(
        "--out-topics",
        default="null_event_topics.jsonl",
        help="Output JSONL for null topic0 + addresses",
    )
    parser.add_argument(
        "--out-matches",
        default="null_event_matches.jsonl",
        help="Output JSONL for resolved matches",
    )
    args = parser.parse_args()

    patterns_path = Path(args.patterns)
    id_map_path = Path(args.id_map)
    sanctuary = Path(args.sanctuary)

    id_map = json.loads(id_map_path.read_text())

    topics: dict[str, dict[str, object]] = {}
    with patterns_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("event_signature") is not None:
                continue
            topic0 = row.get("topic0")
            if not topic0:
                continue
            topic0 = topic0.lower()
            entry = topics.setdefault(topic0, {"topic0": topic0, "contract_ids": set(), "clusters": set()})
            cluster = row.get("cluster_id")
            if cluster:
                entry["clusters"].add(cluster)
            for ex in row.get("examples", []) or []:
                cid = ex.get("contract_id")
                if cid:
                    entry["contract_ids"].add(cid)

    # Expand contract_ids to addresses
    for entry in topics.values():
        addrs = set()
        for cid in entry["contract_ids"]:
            addrs.update(id_map.get(cid, []))
        entry["addresses"] = sorted(addrs)
        entry["contract_ids"] = sorted(entry["contract_ids"])
        entry["clusters"] = sorted(entry["clusters"])

    # Write topics list
    out_topics = Path(args.out_topics)
    with out_topics.open("w") as f:
        for entry in topics.values():
            f.write(json.dumps(entry) + "\n")

    # Resolve by parsing sources
    null_topics = set(topics.keys())
    out_matches = Path(args.out_matches)
    matched = 0
    seen_addr = 0

    # Group addresses by prefix
    prefix_to_addrs: dict[str, set[str]] = {}
    for entry in topics.values():
        for addr in entry.get("addresses", []):
            if len(addr) != 40:
                continue
            prefix = addr[:2].lower()
            prefix_to_addrs.setdefault(prefix, set()).add(addr.lower())

    with out_matches.open("w") as f_out:
        for prefix, addrs in prefix_to_addrs.items():
            prefix_dir = sanctuary / prefix
            if not prefix_dir.exists():
                continue
            index = build_prefix_index(prefix_dir)
            for addr in sorted(addrs):
                files = index.get(addr, [])
                if not files:
                    continue
                seen_addr += 1
                addr_events: dict[str, set[str]] = {}
                for path in files:
                    if path.suffix.lower() != ".sol":
                        continue
                    try:
                        evs = extract_events_from_sol(path)
                    except Exception:
                        continue
                    for t0, sigs in evs.items():
                        if t0 not in null_topics:
                            continue
                        addr_events.setdefault(t0, set()).update(sigs)
                if not addr_events:
                    continue
                for t0, sigs in addr_events.items():
                    for sig in sorted(sigs):
                        f_out.write(
                            json.dumps(
                                {
                                    "topic0": t0,
                                    "address": addr,
                                    "event_signature": sig,
                                    "source_files": [str(p) for p in files],
                                }
                            )
                            + "\n"
                        )
                        matched += 1

    print(f"null topics: {len(topics)}")
    print(f"addresses scanned: {seen_addr}")
    print(f"matches written: {matched}")
    print(f"topics file: {out_topics}")
    print(f"matches file: {out_matches}")


if __name__ == "__main__":
    main()
