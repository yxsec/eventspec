# Off-chain Attack Harness (EOCA / ESDA)

This harness implements the two off-chain attack vectors described in the paper:

- **EOCA (Event Origin Confusion Attack)**: forward a call to a target contract and emit a forged
  event from a separate emitter in the same transaction.
- **ESDA (Event-State Desynchronization Attack)**: emit events without corresponding state writes.

The only required inputs are the address to call (EOCA) and the target event to emit. The harness
then generates the corresponding transactions for off-chain testing.

## Contracts

- `contracts/OffchainHarness.sol`: core harness (EOCA + ESDA).
- `contracts/ExampleTarget.sol`: optional demo target for quick testing.

`OffchainHarness` emits arbitrary logs using low-level `LOG1..LOG4`, so you can supply a topic0 and
up to three extra topics plus raw event data.

## Build and Deploy

Compile with your preferred Solidity toolchain (solc/foundry/hardhat) and obtain ABI + bytecode.
Example using solc:

```bash
solc --combined-json abi,bin Harness/contracts/OffchainHarness.sol > Harness/offchain.json
```

Deploy (requires `web3`):

```bash
pip install -r Harness/requirements.txt
python3 Harness/scripts/harness.py deploy \
  --rpc http://127.0.0.1:8545 \
  --private-key 0xYOUR_KEY \
  --bytecode 0xYOUR_BYTECODE
```

## Generate Transactions (EOCA / ESDA)

The script prints a JSON payload (`to`, `data`, `value`) by default. Use `--send` to broadcast.

### EOCA

```bash
python3 Harness/scripts/harness.py eoca \
  --harness 0xHARNESS \
  --target 0xTARGET \
  --call-data 0xCALLDATA \
  --signature "Transfer(address,address,uint256)" \
  --topic 0xTOPIC1 \
  --topic 0xTOPIC2 \
  --data 0xENCODED_DATA
```

### ESDA

```bash
python3 Harness/scripts/harness.py esda \
  --harness 0xHARNESS \
  --signature "Transfer(address,address,uint256)" \
  --topic 0xTOPIC1 \
  --topic 0xTOPIC2 \
  --data 0xENCODED_DATA
```

Notes:
- `--signature` computes `topic0` as `keccak256(signature)`. Use `--topic0` to provide it directly.
- `--topic` corresponds to indexed parameters (up to 3). `--data` is ABI-encoded non-indexed data.
- `--call-data` defaults to `0x` (fallback call) if omitted.
- EOCA uses `target.call(callData)` and then emits the forged event from the harness address.
- ESDA emits the forged event without any state writes.
