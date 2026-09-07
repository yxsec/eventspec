#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBS_DIR="${ROOT}/result/obs"
OUT_ROOT="${ROOT}/result"
CFG_DIR="${ROOT}/configs/sensitivity"
JOBS="${JOBS:-5}"

if [[ ! -f "${OBS_DIR}/agg.db" ]]; then
  echo "Missing ${OBS_DIR}/agg.db. Run extract first." >&2
  exit 1
fi

if [[ ! -d "${CFG_DIR}" ]]; then
  echo "Missing ${CFG_DIR}. No sensitivity configs found." >&2
  exit 1
fi

run_one() {
  local cfg="$1"
  local name
  name="$(basename "${cfg}" .json)"
  local out_dir="${OUT_ROOT}/db_${name}"
  local func_file="${out_dir}/function_patterns.jsonl"
  local event_file="${out_dir}/event_patterns.jsonl"

  if [[ -s "${func_file}" && -s "${event_file}" ]]; then
    echo "[SKIP] ${name} (already has patterns)"
    return 0
  fi

  echo "[RUN ] ${name}"
  mkdir -p "${out_dir}"
  python3 "${ROOT}/main.py" infer \
    --obs "${OBS_DIR}" \
    --out "${out_dir}" \
    --config "${cfg}"
}

export -f run_one
export ROOT OBS_DIR OUT_ROOT

find "${CFG_DIR}" -maxdepth 1 -name "*.json" -print | sort | \
  xargs -P "${JOBS}" -I {} bash -c 'run_one "$@"' _ {}
