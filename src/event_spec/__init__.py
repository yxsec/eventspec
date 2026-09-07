"""Event spec inference tools (differential)."""

from .diff import main as diff_main
from .extract import main as extract_main
from .infer import main as infer_main

__all__ = ["extract_main", "infer_main", "diff_main"]
