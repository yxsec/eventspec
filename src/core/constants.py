"""Default configuration constants for the TAC taint tool."""

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_EVENT_SIGNATURE_PATH = PACKAGE_DIR / "resources" / "EventSignature.facts"

DEFAULT_SOURCE_OPCODES = {
    "CALLDATALOAD",
    "CALLDATACOPY",
    "CALLDATASIZE",
    "CALLVALUE",
    "CALLER",
    "ORIGIN",
}

LOG_OPCODES = {"LOG0", "LOG1", "LOG2", "LOG3", "LOG4"}
