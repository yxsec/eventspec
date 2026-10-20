# EventSpec Artifact

This release contains the EventSpec implementation, optional off-chain harness,
tests, experiment configurations, ERC reference declarations, and archived
default inference profiles.

## Layout

- `src/`: EventSpec implementation
- `Harness/`: EOCA/ESDA harness code
- `greed/`: vendored Greed source used by symbolic mode
- `scripts/`: analysis and experiment drivers
- `configs/`: sensitivity configurations
- `data/erc_reference_declarations.csv`: 135 ERC reference records with parameter
  definitions, legacy conditions, scoped guard candidates, and correction notes
- `profiles/default/`: compressed default event and function profiles
- `tests/`: unit tests
- `docs/`: algorithm and schema documentation
- `Dockerfile`: pinned Ubuntu/Soufflé/Gigahorse/Greed environment

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py --help
```

Use `event_spec_config.json` and `configs/sensitivity/` as the experiment
settings. TAC inputs and all output paths are supplied externally by the user.

Run the release-tree check and tests:

```bash
python3 scripts/validate_release.py
PYTHONPATH=. python3 -m pytest -q -p no:cacheprovider tests
```

The Docker image pins Ubuntu 22.04, Soufflé 2.4, the Gigahorse and Greed
commits, Yices, and Python dependencies:

```bash
docker build -t eventspec:latest .
docker run --rm eventspec:latest python3 main.py --help
```

For command, algorithm, schema, and experiment details, see
[docs/TECHNICAL.md](docs/TECHNICAL.md).

## Reference declarations and inferred profiles

The [ERC reference table](data/erc_reference_declarations.csv) contains 135
records from 41 ERCs and 16 specification fields. Conditions are preserved
research annotations; `reference_notes` records event-specific corrections and
applicability limits. `guard_conditions_json` contains scoped candidates, not
validated event-wide guard policies. Missing parameter-origin annotations have
not been synthesized.

The archived default [event profiles](profiles/default/event_patterns.jsonl.gz)
and [function profiles](profiles/default/function_patterns.jsonl.gz) contain
1,246 and 211,487 JSONL records, respectively. They were inferred from contract
observations and serve as empirical comparison inputs. Both files are compressed
losslessly. For schema, provenance, and decompression instructions, see
[the technical guide](docs/TECHNICAL.md#published-reference-materials).

## Citation

```bibtex
@inproceedings{Liu2026EDD,
  author = {Liu, Yixuan and Dong, Yuxin and Liu, Ye and Wu, Yin and Zhang, Chengxuan and Luo, Xiapu and Li, Yi},
  booktitle = {Proceedings of the 35th ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA)},
  month = oct,
  title = {{EventSpec}: Defining and Detecting Event-Semantic Issues in Blockchain Ecosystems},
  year = {2026}
}
```

Machine-readable citation metadata is in `CITATION.cff`; third-party notices
are in `THIRD_PARTY_NOTICES.md`.
