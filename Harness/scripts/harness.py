#!/usr/bin/env python3
import argparse
import json
import sys
from typing import List, Optional

from web3 import Web3

DEFAULT_ABI = [
    {
        "type": "function",
        "name": "eoca",
        "stateMutability": "payable",
        "inputs": [
            {"name": "target", "type": "address"},
            {"name": "callData", "type": "bytes"},
            {"name": "topic0", "type": "bytes32"},
            {"name": "extraTopics", "type": "bytes32[]"},
            {"name": "data", "type": "bytes"},
            {"name": "requireSuccess", "type": "bool"},
        ],
        "outputs": [
            {"name": "ok", "type": "bool"},
            {"name": "ret", "type": "bytes"},
        ],
    },
    {
        "type": "function",
        "name": "esda",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "topic0", "type": "bytes32"},
            {"name": "extraTopics", "type": "bytes32[]"},
            {"name": "data", "type": "bytes"},
        ],
        "outputs": [],
    },
]


def _exit(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(2)


def _strip_0x(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def _parse_hex_bytes(value: Optional[str], name: str) -> bytes:
    if value is None:
        return b""
    text = _strip_0x(value.strip())
    if not text:
        return b""
    if len(text) % 2:
        text = "0" + text
    try:
        return bytes.fromhex(text)
    except ValueError:
        _exit(f"Invalid hex for {name}: {value}")
    return b""


def _parse_bytes32(value: str, name: str) -> bytes:
    raw = _parse_hex_bytes(value, name)
    if len(raw) != 32:
        _exit(f"{name} must be 32 bytes (got {len(raw)} bytes)")
    return raw


def _parse_int(value: str, name: str) -> int:
    try:
        return int(value, 16) if value.startswith("0x") else int(value)
    except ValueError:
        _exit(f"Invalid integer for {name}: {value}")
    return 0


def _topic0_from_signature(sig: Optional[str]) -> Optional[bytes]:
    if not sig:
        return None
    return Web3.keccak(text=sig)


def _load_abi(path: Optional[str]) -> List[dict]:
    if not path:
        return DEFAULT_ABI
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        return data
    if "abi" in data:
        return data["abi"]
    _exit("Unsupported ABI file format")
    return DEFAULT_ABI


def _load_bytecode(value: Optional[str]) -> str:
    if not value:
        _exit("--bytecode is required for deploy")
    hex_str = value.strip()
    return hex_str if hex_str.startswith("0x") else "0x" + hex_str


def _build_contract(w3: Web3, address: Optional[str], abi: List[dict]):
    if address:
        return w3.eth.contract(address=w3.to_checksum_address(address), abi=abi)
    return w3.eth.contract(abi=abi)


def _encode_call(contract, fn_name: str, args: list) -> str:
    return contract.encodeABI(fn_name=fn_name, args=args)


def _send_tx(
    w3: Web3,
    contract,
    fn_name: str,
    args: list,
    private_key: str,
    value: int,
    gas: Optional[int],
    gas_price: Optional[int],
    max_fee: Optional[int],
    max_priority: Optional[int],
    nonce: Optional[int],
) -> str:
    account = w3.eth.account.from_key(private_key)
    fn = getattr(contract.functions, fn_name)(*args)
    tx = {
        "from": account.address,
        "value": value,
        "nonce": nonce if nonce is not None else w3.eth.get_transaction_count(account.address),
        "chainId": w3.eth.chain_id,
    }
    tx = fn.build_transaction(tx)
    _apply_gas_fields(w3, tx, gas, gas_price, max_fee, max_priority)
    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    return tx_hash.hex()


def _print_payload(to: str, data: str, value: int) -> None:
    payload = {
        "to": to,
        "data": data,
        "value": hex(value),
    }
    print(json.dumps(payload, indent=2))


def _apply_gas_fields(
    w3: Web3,
    tx: dict,
    gas: Optional[int],
    gas_price: Optional[int],
    max_fee: Optional[int],
    max_priority: Optional[int],
) -> None:
    if gas is None:
        tx["gas"] = w3.eth.estimate_gas(tx)
    else:
        tx["gas"] = gas
    if max_fee is not None or max_priority is not None:
        tx["maxFeePerGas"] = max_fee if max_fee is not None else w3.eth.gas_price
        tx["maxPriorityFeePerGas"] = max_priority if max_priority is not None else 0
    else:
        tx["gasPrice"] = gas_price if gas_price is not None else w3.eth.gas_price


def _parse_topics(values: List[str]) -> List[bytes]:
    return [_parse_bytes32(item, "topic") for item in values]


def _resolve_topic0(args) -> bytes:
    if args.topic0:
        return _parse_bytes32(args.topic0, "topic0")
    topic0 = _topic0_from_signature(args.signature)
    if topic0 is None:
        _exit("Provide --topic0 or --signature")
    return topic0


def _init_web3(rpc: Optional[str]) -> Web3:
    if not rpc:
        return Web3()
    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        _exit(f"Failed to connect to RPC: {rpc}")
    return w3


def cmd_deploy(args) -> None:
    w3 = _init_web3(args.rpc)
    if not args.private_key:
        _exit("--private-key is required for deploy")
    abi = _load_abi(args.abi)
    bytecode = _load_bytecode(args.bytecode)
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    account = w3.eth.account.from_key(args.private_key)
    tx = contract.constructor().build_transaction(
        {
            "from": account.address,
            "nonce": args.nonce if args.nonce is not None else w3.eth.get_transaction_count(account.address),
            "chainId": w3.eth.chain_id,
        }
    )
    _apply_gas_fields(w3, tx, args.gas, args.gas_price, args.max_fee, args.max_priority)
    signed = w3.eth.account.sign_transaction(tx, args.private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    print(tx_hash.hex())


def cmd_eoca(args) -> None:
    w3 = _init_web3(args.rpc)
    abi = _load_abi(args.abi)
    contract = _build_contract(w3, args.harness, abi)
    topic0 = _resolve_topic0(args)
    extra_topics = _parse_topics(args.topic)
    data = _parse_hex_bytes(args.data, "data")
    call_data = _parse_hex_bytes(args.call_data, "call-data")
    args_list = [
        w3.to_checksum_address(args.target),
        call_data,
        topic0,
        extra_topics,
        data,
        args.require_success,
    ]
    data_hex = _encode_call(contract, "eoca", args_list)
    if args.send:
        if not args.private_key or not args.rpc:
            _exit("--send requires --rpc and --private-key")
        tx_hash = _send_tx(
            w3,
            contract,
            "eoca",
            args_list,
            args.private_key,
            args.value,
            args.gas,
            args.gas_price,
            args.max_fee,
            args.max_priority,
            args.nonce,
        )
        print(tx_hash)
        return
    _print_payload(args.harness, data_hex, args.value)


def cmd_esda(args) -> None:
    w3 = _init_web3(args.rpc)
    abi = _load_abi(args.abi)
    contract = _build_contract(w3, args.harness, abi)
    topic0 = _resolve_topic0(args)
    extra_topics = _parse_topics(args.topic)
    data = _parse_hex_bytes(args.data, "data")
    args_list = [topic0, extra_topics, data]
    data_hex = _encode_call(contract, "esda", args_list)
    if args.send:
        if not args.private_key or not args.rpc:
            _exit("--send requires --rpc and --private-key")
        tx_hash = _send_tx(
            w3,
            contract,
            "esda",
            args_list,
            args.private_key,
            args.value,
            args.gas,
            args.gas_price,
            args.max_fee,
            args.max_priority,
            args.nonce,
        )
        print(tx_hash)
        return
    _print_payload(args.harness, data_hex, args.value)


def _add_common_event_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--harness", required=True, help="Harness contract address")
    parser.add_argument("--topic0", help="Event topic0 (32-byte hex)")
    parser.add_argument("--signature", help="Event signature string")
    parser.add_argument("--topic", action="append", default=[], help="Extra topic (repeatable)")
    parser.add_argument("--data", help="Event data (hex)")
    parser.add_argument("--abi", help="Path to ABI JSON (optional)")
    parser.add_argument("--rpc", help="RPC URL (optional, for --send)")
    parser.add_argument("--private-key", help="Private key (hex) for --send")
    parser.add_argument("--send", action="store_true", help="Send the transaction")
    parser.add_argument("--value", default="0", help="Ether value in wei (default 0)")
    parser.add_argument("--gas", type=int, help="Gas limit")
    parser.add_argument("--gas-price", dest="gas_price", type=int, help="Gas price")
    parser.add_argument("--max-fee", type=int, help="EIP-1559 max fee per gas")
    parser.add_argument("--max-priority", type=int, help="EIP-1559 max priority fee")
    parser.add_argument("--nonce", type=int, help="Nonce override")


def _finalize_args(args):
    args.value = _parse_int(str(args.value), "value")
    return args


def main() -> None:
    parser = argparse.ArgumentParser(description="Off-chain attack harness for EOCA/ESDA")
    subparsers = parser.add_subparsers(dest="command", required=True)

    deploy = subparsers.add_parser("deploy", help="Deploy the OffchainHarness contract")
    deploy.add_argument("--rpc", required=True, help="RPC URL")
    deploy.add_argument("--private-key", required=True, help="Private key (hex)")
    deploy.add_argument("--abi", help="Path to ABI JSON (optional)")
    deploy.add_argument("--bytecode", required=True, help="Contract bytecode (hex)")
    deploy.add_argument("--gas", type=int, help="Gas limit")
    deploy.add_argument("--gas-price", dest="gas_price", type=int, help="Gas price")
    deploy.add_argument("--max-fee", type=int, help="EIP-1559 max fee per gas")
    deploy.add_argument("--max-priority", type=int, help="EIP-1559 max priority fee")
    deploy.add_argument("--nonce", type=int, help="Nonce override")

    eoca = subparsers.add_parser("eoca", help="Event Origin Confusion Attack")
    _add_common_event_args(eoca)
    eoca.add_argument("--target", required=True, help="Target contract address")
    eoca.add_argument("--call-data", default="0x", help="Call data hex for target (default 0x)")
    eoca.add_argument("--require-success", action="store_true", help="Revert on failed target call")

    esda = subparsers.add_parser("esda", help="Event-State Desynchronization Attack")
    _add_common_event_args(esda)

    args = parser.parse_args()
    args = _finalize_args(args)

    if args.command == "deploy":
        cmd_deploy(args)
    elif args.command == "eoca":
        cmd_eoca(args)
    elif args.command == "esda":
        cmd_esda(args)


if __name__ == "__main__":
    main()
