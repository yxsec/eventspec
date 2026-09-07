"""CLI entry point for event spec inference."""

from __future__ import annotations

import argparse
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eventspec",
        description="Empirical event spec inference and differential checks.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract_parser = subparsers.add_parser(
        "extract", help="Extract observations from TAC analysis results."
    )
    extract_parser.add_argument(
        "--tac",
        required=True,
        type=Path,
        help="Path to contract.tac, a directory of *.tac files, or a list file.",
    )
    extract_parser.add_argument("--out", required=True, type=Path)
    extract_parser.add_argument("--tier", choices=("core", "open"), default="open")
    extract_parser.add_argument("--symbolic", action="store_true")
    extract_parser.add_argument("--symbolic-eq-constant-only", action="store_true")
    extract_parser.add_argument(
        "--symbolic-log-limit",
        type=int,
        default=2,
        help=(
            "Max repeated logs per topic0/signature to slice (symbolic mode only). "
            "0 means no limit."
        ),
    )
    extract_parser.add_argument(
        "--symbolic-mstore-concretize",
        action="store_true",
        help="Enable Greed MSTORE offset concretization (symbolic mode only).",
    )
    extract_parser.add_argument("--timeout", type=int, default=15)
    extract_parser.add_argument(
        "--append",
        action="store_true",
        help="Append to existing outputs and skip contracts already present.",
    )

    infer_parser = subparsers.add_parser(
        "infer", help="Infer event/function patterns from observations."
    )
    infer_parser.add_argument("--obs", required=True, type=Path)
    infer_parser.add_argument("--out", required=True, type=Path)
    infer_parser.add_argument("--config", required=False)

    diff_parser = subparsers.add_parser(
        "diff", help="Run differential checks for a target contract."
    )
    diff_parser.add_argument("--tac", required=True, type=Path)
    diff_parser.add_argument(
        "--db",
        required=False,
        type=Path,
        help="Path to inferred pattern DB directory (required unless --target-only is set).",
    )
    diff_parser.add_argument("--out", required=True, type=Path)
    diff_parser.add_argument("--config", required=False)
    diff_parser.add_argument("--symbolic", action="store_true")
    diff_parser.add_argument("--symbolic-eq-constant-only", action="store_true")
    diff_parser.add_argument(
        "--symbolic-log-limit",
        type=int,
        default=2,
        help=(
            "Max repeated logs per topic0/signature to slice (symbolic mode only). "
            "0 means no limit."
        ),
    )
    diff_parser.add_argument(
        "--target-only",
        action="store_true",
        help="Only run target-only equality collision checks (skip pattern comparisons).",
    )
    diff_parser.add_argument("--timeout", type=int, default=15)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "extract":
        from .extract import run

        run(args)
        return
    if args.command == "infer":
        from .infer import run

        run(args)
        return
    if args.command == "diff":
        from .diff import run

        run(args)
        return
    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
