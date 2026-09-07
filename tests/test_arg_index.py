import json
from types import SimpleNamespace
from pathlib import Path

from src.event_spec import diff as diff_module
from src.event_spec import extract as extract_module


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row))
            handle.write("\n")


def test_arg_index_from_origin() -> None:
    assert extract_module._arg_index_from_origin("ARG arg0") == 0
    assert extract_module._arg_index_from_origin("CALLDATALOAD offset 0x04") == 0
    assert extract_module._arg_index_from_origin("CALLDATALOAD offset 0x24") == 1
    assert extract_module._arg_index_from_origin("CALLDATALOAD offset v31a7arg0") is None


def test_param_arg_mismatch(tmp_path: Path) -> None:
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    (db_dir / "function_patterns.jsonl").write_text("", encoding="utf-8")

    pattern = {
        "topic0": "0xdeadbeef",
        "cluster_id": "cid1",
        "support": {"open": 1},
        "pattern_tier": "open",
        "indexed_profile": {"topic0": 1.0, "topic1": 1.0},
        "param_count_profile": {"topics": {"2": 1.0}, "data": {"0": 1.0}},
        "operand_profiles": {
            "topic0": {
                "source": {"CONST": 1.0},
                "deps": {},
                "ops": ["CONST"],
                "literal": {"nonzero": 1.0},
                "arg_index": {},
                "support": 1,
            },
            "topic1": {
                "source": {"CALLDATA": 1.0},
                "deps": {"data": 1.0},
                "ops": ["CALLDATALOAD"],
                "literal": {},
                "arg_index": {"0": 1.0},
                "support": 1,
            },
        },
        "unaligned_offset_profile": {},
        "sstore_profile": {},
        "value_bind_profile": {},
        "guard_profile": {},
        "equality_profile": {},
        "equality_support": {},
        "examples": [],
    }
    _write_jsonl(db_dir / "event_patterns.jsonl", [pattern])

    tac_path = tmp_path / "contract.tac"
    tac_path.write_text(
        """
function test(v0arg0, v0arg1) public {
    Begin block 0x0
    prev=[], succ=[]
    =================================
    0x0: v0(0x0) = CONST
    0x1: v1(0x0) = CONST
    0x2: v2(0x24) = CONST
    0x3: v3 = CALLDATALOAD v2(0x24)
    0x4: v4(0xdeadbeef) = CONST
    0x5: LOG2 v0(0x0), v1(0x0), v4(0xdeadbeef), v3
}
""".lstrip(),
        encoding="utf-8",
    )

    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"similarity_min": 0.0, "max_conf_width": 1.0}),
        encoding="utf-8",
    )

    out_path = tmp_path / "findings.json"
    args = SimpleNamespace(
        tac=tac_path,
        db=db_dir,
        out=out_path,
        config=str(config_path),
        symbolic=False,
        symbolic_eq_constant_only=False,
        symbolic_log_limit=2,
        target_only=False,
        timeout=15,
    )
    diff_module.run(args)

    findings = json.loads(out_path.read_text(encoding="utf-8"))
    assert any(item.get("type") == "param_arg_mismatch" for item in findings)
