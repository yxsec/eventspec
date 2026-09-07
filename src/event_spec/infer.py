"""Infer event and function patterns from aggregated observations."""

from __future__ import annotations

import argparse
from pathlib import Path

from .agg_store import AggregateStore
from src.core.constants import DEFAULT_EVENT_SIGNATURE_PATH
from src.core.facts import load_event_signatures
from .utils import ensure_dir, load_config, write_jsonl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Infer event/function patterns from aggregate observations."
    )
    parser.add_argument("--obs", required=True, type=Path, help="Observation directory")
    parser.add_argument("--out", required=True, type=Path, help="Output directory")
    parser.add_argument("--config", required=False, help="Path to config JSON")
    return parser


def run(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    obs_dir: Path = args.obs
    agg_db_path = obs_dir / "agg.db"
    if not agg_db_path.exists():
        raise SystemExit("agg.db not found in obs directory")

    store = AggregateStore(agg_db_path)
    try:
        function_patterns = store.load_function_patterns(config)
        event_patterns = store.load_event_patterns(config)
    finally:
        store.close()

    signature_map = (
        load_event_signatures(DEFAULT_EVENT_SIGNATURE_PATH)
        if DEFAULT_EVENT_SIGNATURE_PATH.exists()
        else {}
    )

    out_dir: Path = args.out
    ensure_dir(out_dir)
    write_jsonl(out_dir / "function_patterns.jsonl", (pat.to_dict() for pat in function_patterns))
    def _event_rows():
        for pat in event_patterns:
            row = pat.to_dict()
            topic0 = row.get("topic0")
            if topic0:
                row["event_signature"] = signature_map.get(str(topic0).lower())
            yield row

    write_jsonl(out_dir / "event_patterns.jsonl", _event_rows())


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
