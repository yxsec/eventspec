# EventSpec Artifact

This release contains the EventSpec implementation, optional off-chain harness,
tests, and experiment configurations. It intentionally excludes datasets,
labels, generated findings, logs, and other run outputs.

## Layout

- `src/`: EventSpec implementation
- `Harness/`: EOCA/ESDA harness code
- `greed/`: vendored Greed source used by symbolic mode
- `scripts/`: analysis and experiment drivers
- `configs/`: sensitivity configurations
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
