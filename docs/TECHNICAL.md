# EventSpec Technical Guide

This document is the single technical reference for the released code. The
release includes ERC reference declarations and archived default inference
profiles. Contract source/TAC corpora, aggregate databases, evaluation verdicts,
and generated findings are supplied externally.

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

The release includes the default profiles described below; other experiment
inputs and generated findings are external. The release tree can be checked
with `python3 scripts/validate_release.py`; tests are run
with `PYTHONPATH=. python3 -m pytest -q -p no:cacheprovider tests`.

## Published reference materials

`data/erc_reference_declarations.csv` contains 135 source-matched reference
records from 41 ERCs, checked against ethereum/ERCs snapshot `491797b6`
(2026-01-02). Among 136 original records, one ERC-5507
`RefundFrom(address,address,uint256,uint256)` record had no matching declaration
and is excluded pending resolution. Source standards are available from
[ethereum/ERCs](https://github.com/ethereum/ERCs) and the applicable
[ERC pages](https://eips.ethereum.org/).

The CSV has 16 fields: `erc_id`, `erc_title`, `event_name`, `event_signature`,
`topic0`, `indexed_count`, `data_count`, `param_types`, `param_names`, `Conditions`,
`trigger_functions`, `spec_id`, `variant`, `params_json`, `guard_conditions_json`,
and `reference_notes`. `params_json` records each parameter's name, type, and
boolean indexed flag in declaration order. `data_count` counts non-indexed
parameters, not encoded memory words. `variant` distinguishes ERC-5507 interface
variants; it is blank when not applicable.

`Conditions` preserves legacy research conditions and implementation assumptions;
not all are normative ERC requirements. Read them with the event-specific
`reference_notes`. A blank note means no additional qualification was added.
Guard candidates retain their expressions, applicability scope, and review
status. An empty candidate array means no candidate was recovered by this
extraction; it does not establish that no guard is required. Parameter-origin
labels and validated executable guard-policy labels were not supplied. The
reference table therefore does not establish complete semantic ground truth.

`profiles/default/event_patterns.jsonl.gz` contains 1,246 archived event profiles;
`profiles/default/function_patterns.jsonl.gz` contains 211,487 archived function
profiles. These are the default `db_alpha_1` outputs used in the ERC review.
They were inferred from contract observations and were not regenerated from
the ERC reference table. The files retain the original distributions, support,
cluster IDs, and example corpus/function IDs. Record counts count profiles,
not contracts.

The declared default inference settings are `support_min=20`,
`core_support_min=10`, and `top_k=3`, matching the shipped default configuration.
This documents the associated configuration, without claiming a reconstructed
historical generation command. The two archives preserve their source JSONL
contents byte for byte after decompression.

Extract the profiles into a writable directory before using `diff`:

```bash
mkdir -p /tmp/eventspec-profiles
gzip -dc profiles/default/event_patterns.jsonl.gz > /tmp/eventspec-profiles/event_patterns.jsonl
gzip -dc profiles/default/function_patterns.jsonl.gz > /tmp/eventspec-profiles/function_patterns.jsonl
python3 main.py diff --tac <TARGET_TAC> --db /tmp/eventspec-profiles \
  --out <FINDINGS_JSON> --config event_spec_config.json
```

Parse the reference CSV with a CSV reader: condition cells may contain quoted
newlines, and JSON-valued cells require JSON decoding. Experimental frequencies,
undocumented legacy 0/1 flags, historical event-level verdicts, and raw contract
datasets are outside this publication.

## Scope limitation

Storage writes are propagated within the emitting function; bindings are not
propagated across call boundaries.
