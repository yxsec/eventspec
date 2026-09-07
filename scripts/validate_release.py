#!/usr/bin/env python3
"""Validate the result-free EventSpec artifact before release."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REQUIRED_FILES = {
    "README.md",
    "docs/TECHNICAL.md",
    "CITATION.cff",
    "THIRD_PARTY_NOTICES.md",
    "Dockerfile",
    "requirements.txt",
    "event_spec_config.json",
    "main.py",
}
FORBIDDEN_NAMES = {
    ".DS_Store",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "build",
    "dist",
    "tmp",
    "result",
    "results",
    "eventspec.zip",
}
FORBIDDEN_SUFFIXES = {".pyc", ".log", ".db", ".sqlite", ".sqlite3", ".jsonl"}


def main() -> None:
    missing = [name for name in sorted(REQUIRED_FILES) if not (ROOT / name).is_file()]
    assert not missing, f"missing required files: {missing}"

    json.loads((ROOT / "event_spec_config.json").read_text(encoding="utf-8"))
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        assert not FORBIDDEN_NAMES.intersection(relative.parts), relative
        if path.is_file():
            assert path.suffix not in FORBIDDEN_SUFFIXES, relative

    for path in (ROOT / "README.md", ROOT / "docs" / "TECHNICAL.md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "anonymization.md" not in text, path
        assert "double-blind" not in text, path

    print("EventSpec release validation passed")


if __name__ == "__main__":
    main()
