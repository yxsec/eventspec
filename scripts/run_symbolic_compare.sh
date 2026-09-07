#!/usr/bin/env bash
set -euo pipefail

contract_dir="${1:-}"
if [ -z "$contract_dir" ]; then
  echo "Usage: $0 <CONTRACT_DIR_WITH_contract.tac>" >&2
  exit 2
fi
timeout="${TIMEOUT:-30}"
tier="${TIER:-open}"
contract_tac="${contract_dir}/contract.tac"

if [ ! -f "$contract_tac" ]; then
  echo "contract.tac not found: $contract_tac" >&2
  exit 1
fi

if ! python3 - <<'PY'
import sys
try:
    import yices  # noqa: F401
except Exception as exc:
    print(f"yices import failed: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
then
  echo "yices module not available. Did you run: workon greed ?" >&2
  exit 1
fi

time_bin="/usr/bin/time"
if [ ! -x "$time_bin" ]; then
  echo "missing /usr/bin/time; please install GNU time." >&2
  exit 1
fi

mkdir -p tmp
run_dir="$(mktemp -d tmp/symbolic_compare_XXXXXX)"
no_dir="$run_dir/no_mstore"
with_dir="$run_dir/with_mstore"
mkdir -p "$no_dir" "$with_dir"

"$time_bin" -p -o "$no_dir/time.txt" \
  python3 main.py extract \
  --tac "$contract_tac" \
  --out "$no_dir" \
  --tier "$tier" \
  --symbolic \
  --timeout "$timeout"

"$time_bin" -p -o "$with_dir/time.txt" \
  python3 main.py extract \
  --tac "$contract_tac" \
  --out "$with_dir" \
  --tier "$tier" \
  --symbolic \
  --symbolic-mstore-concretize \
  --timeout "$timeout"

python3 - <<'PY'
from pathlib import Path
import sqlite3

def load_stats(base: Path):
    db_path = base / "agg.db"
    stats = {
        "equalities_total": 0,
        "status_counts": {},
        "db_size": db_path.stat().st_size if db_path.exists() else 0,
    }
    if db_path.exists():
        conn = sqlite3.connect(db_path)
        try:
            for status, count in conn.execute(
                "SELECT status, count FROM event_equality"
            ):
                stats["status_counts"][status] = stats["status_counts"].get(status, 0) + int(count)
                stats["equalities_total"] += int(count)
        finally:
            conn.close()
    return stats

run_dir = Path(""""$run_dir"""")
for label in ("no_mstore", "with_mstore"):
    stats = load_stats(run_dir / label)
    print(label)
    print("equalities_total", stats["equalities_total"])
    print("agg_db_size", stats["db_size"])
    print("status_counts", stats["status_counts"])
PY

printf "NO_MSTORE_TIME\n"
cat "$no_dir/time.txt"
printf "WITH_MSTORE_TIME\n"
cat "$with_dir/time.txt"
echo "RUN_DIR $run_dir"
