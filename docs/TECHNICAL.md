# EventSpec Technical Guide

This document is the single technical reference for the released code. Inputs
and generated outputs are supplied externally; the release contains no dataset,
labels, or precomputed results.

## Pipeline

```text
TAC inputs -> extract -> agg.db -> infer -> empirical patterns -> diff -> findings
```

```bash
python3 main.py extract --tac <TAC_OR_DIRECTORY_OR_LIST> --out <OBS_DIR> --tier open
python3 main.py infer --obs <OBS_DIR> --out <DB_DIR> --config event_spec_config.json
python3 main.py diff --tac <TARGET_TAC> --db <DB_DIR> --out <FINDINGS_JSON> \
  --config event_spec_config.json
```

`extract` accepts one TAC file, a recursive directory, or a list of paths.
`infer` reads `agg.db` and emits function/event patterns. `diff` compares a
target contract with those patterns and emits structured findings.

## Extraction

The extractor parses TAC into statements and a control-flow graph, propagates
taint from calldata/environment sources, and identifies `LOG*` sites. For each
event it records topic/data shape, operand provenance, opcode footprints,
access-control guards, storage writes, value bindings, and reachable entrypoints.

Optional symbolic mode uses Greed/Yices to compare repeated event operands. It
can be enabled with `--symbolic`; `--symbolic-mstore-concretize` uses loop facts
to bound memory offsets. Symbolic analysis is bounded to the first two logs of
each repeated event type.

## Inference and differential checking

Functions are clustered by guard, storage, source/dependency, shape, and opcode
features. Event and function profiles are normalized empirical distributions
with configurable support thresholds (`support_min`, `core_support_min`, and
`top_k`).

`diff` selects the closest event/function profile and applies confidence and
similarity gates. Findings include event emission/shape mismatches, parameter
source/index/literal mismatches, guard gaps, storage mismatches, equality
anomalies, and event collisions.

## Data schemas

`agg.db` contains aggregate tables keyed by function cluster, event topic, and
corpus tier. Pattern JSONL rows contain:

- common metadata: `cluster_id`, `support`, `pattern_tier`, `examples`;
- function profiles: expected events, log counts/shapes, guards, storage, opcodes;
- event profiles: indexed labels, parameter counts, operand source/dependency,
  literal/argument-index distributions, guards, storage bindings, and optional
  symbolic equality statistics.

The implementation sources of truth are `src/event_spec/schema.py`,
`src/event_spec/extract.py`, `src/event_spec/agg_store.py`, and
`src/event_spec/diff.py`.

## Experiment settings and drivers

- `event_spec_config.json`: baseline detector configuration.
- `configs/sensitivity/`: sensitivity variants for support, alpha, and top-k.
- `scripts/run_sensitivity_infer.sh`: runs inference over sensitivity settings.
- `scripts/run_symbolic_compare.sh`: compares symbolic extraction modes.
- `scripts/build_experiment_tables.py` and related scripts: optional analysis
  utilities that read externally generated outputs.

The artifact does not include those inputs or generated outputs. The release
tree can be checked with `python3 scripts/validate_release.py`; tests are run
with `PYTHONPATH=. python3 -m pytest -q -p no:cacheprovider tests`.

## Scope limitation

Storage writes are propagated within the emitting function; bindings are not
propagated across call boundaries.
