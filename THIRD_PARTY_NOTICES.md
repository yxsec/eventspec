# Third-party components

EventSpec includes or uses the following third-party components. Their
copyright and license terms remain with their respective authors.

| Component | Use | License / source |
|---|---|---|
| Greed | Optional symbolic execution and equality checking | MIT; source snapshot under `greed/`, license in `greed/LICENSE.md`; <https://github.com/ucsb-seclab/greed> |
| Gigahorse | TAC generation in the reproducibility container | Upstream terms apply; fetched at the pinned commit in `Dockerfile`; <https://github.com/nevillegrech/gigahorse-toolchain> |
| Soufflé | Datalog analysis runtime | BSD-3-Clause; version 2.4 is built by `Dockerfile`; <https://github.com/souffle-lang/souffle> |
| web3.py | Off-chain harness RPC client | MIT; pinned in `requirements.txt` and `Harness/requirements.txt`; <https://github.com/ethereum/web3.py> |
| tqdm | Optional progress display | MIT; installed from `requirements.txt`; <https://github.com/tqdm/tqdm> |

The ERC reference table contains research annotations and event declarations
checked against the ethereum/ERCs source snapshot `491797b6` (2026-01-02).
The referenced standards remain attributed to their authors; see
<https://github.com/ethereum/ERCs> and <https://eips.ethereum.org/>. Archived
default profiles are outputs of EventSpec inference over contract observations.
Raw external contract datasets and archived evaluation verdicts are not
redistributed in this release.
