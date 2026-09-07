import json
from pathlib import Path
from types import SimpleNamespace

from src.event_spec import diff as diff_module


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row))
            handle.write("\n")


def _write_entrypoint_facts(tmp_path: Path) -> None:
    (tmp_path / "InFunction.csv").write_text(
        "0x0\tpublicEntry\n0x1\tinternalFunc\n", encoding="utf-8"
    )
    (tmp_path / "PublicFunction.csv").write_text(
        "publicEntry\t0x12345678\n", encoding="utf-8"
    )
    (tmp_path / "IRFunctionCall.csv").write_text(
        "0x0\tinternalFunc\n", encoding="utf-8"
    )


def test_guard_gap_uses_entrypoint_id(tmp_path: Path) -> None:
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    (db_dir / "function_patterns.jsonl").write_text("", encoding="utf-8")

    pattern = {
        "topic0": "0xdeadbeef",
        "cluster_id": "cid1",
        "support": {"open": 1},
        "pattern_tier": "open",
        "indexed_profile": {"topic0": 1.0},
        "param_count_profile": {"topics": {"1": 1.0}, "data": {"0": 1.0}},
        "operand_profiles": {
            "topic0": {
                "source": {"CONST": 1.0},
                "deps": {},
                "ops": ["CONST"],
                "literal": {"nonzero": 1.0},
                "arg_index": {},
                "support": 1,
            },
        },
        "unaligned_offset_profile": {},
        "sstore_profile": {},
        "value_bind_profile": {},
        "slot_bind_profile": {},
        "sload_bind_profile": {},
        "guard_profile": {"owner": 1.0},
        "equality_profile": {},
        "equality_support": {},
        "examples": [],
    }
    _write_jsonl(db_dir / "event_patterns.jsonl", [pattern])

    tac_path = tmp_path / "contract.tac"
    tac_path.write_text(
        """
function publicEntry() public {
    Begin block 0x0
    prev=[], succ=[]
    =================================
    0x0: v0(0x0) = CONST
    0x1: v1(0x0) = CONST
    0x2: CALL v0(0x0), v0(0x0), v0(0x0), v0(0x0), v0(0x0), v0(0x0), v0(0x0)
}

function internalFunc() private {
    Begin block 0x1
    prev=[], succ=[]
    =================================
    0x0: v0(0x0) = CONST
    0x1: v1(0x0) = CONST
    0x2: v2(0xdeadbeef) = CONST
    0x3: LOG1 v0(0x0), v1(0x0), v2(0xdeadbeef)
}
""".lstrip(),
        encoding="utf-8",
    )

    _write_entrypoint_facts(tmp_path)

    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "similarity_min": 0.0,
                "support_min": 1,
                "guard_min": 0.0,
                "max_conf_width": 1.0,
            }
        ),
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
    guard_findings = [item for item in findings if item.get("type") == "guard_gap"]
    assert guard_findings
    assert all(item.get("function_id") == "publicEntry" for item in guard_findings)
    for item in guard_findings:
        evidence = item.get("evidence") or {}
        assert evidence.get("callee_function_id") == "internalFunc"
        assert "publicEntry" in (evidence.get("entrypoint_ids") or [])


def test_guard_gap_when_no_checks(tmp_path: Path) -> None:
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    (db_dir / "function_patterns.jsonl").write_text("", encoding="utf-8")

    pattern = {
        "topic0": "0xdeadbeef",
        "cluster_id": "cid2",
        "support": {"open": 1},
        "pattern_tier": "open",
        "indexed_profile": {"topic0": 1.0},
        "param_count_profile": {"topics": {"1": 1.0}, "data": {"0": 1.0}},
        "operand_profiles": {
            "topic0": {
                "source": {"CONST": 1.0},
                "deps": {},
                "ops": ["CONST"],
                "literal": {"nonzero": 1.0},
                "arg_index": {},
                "support": 1,
            },
        },
        "unaligned_offset_profile": {},
        "sstore_profile": {},
        "value_bind_profile": {},
        "slot_bind_profile": {},
        "sload_bind_profile": {},
        "guard_profile": {},
        "equality_profile": {},
        "equality_support": {},
        "examples": [],
    }
    _write_jsonl(db_dir / "event_patterns.jsonl", [pattern])

    tac_path = tmp_path / "contract.tac"
    tac_path.write_text(
        """
function test() public {
    Begin block 0x0
    prev=[], succ=[]
    =================================
    0x0: v0(0x0) = CONST
    0x1: v1(0x0) = CONST
    0x2: v2(0xdeadbeef) = CONST
    0x3: LOG1 v0(0x0), v1(0x0), v2(0xdeadbeef)
}
""".lstrip(),
        encoding="utf-8",
    )

    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "similarity_min": 0.0,
                "support_min": 1,
                "max_conf_width": 1.0,
            }
        ),
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
    guard_findings = [item for item in findings if item.get("type") == "guard_gap"]
    assert guard_findings
    assert all(item.get("function_id") == "test" for item in guard_findings)
    assert any(
        (item.get("evidence") or {}).get("mode") == "no_checks" for item in guard_findings
    )


def test_no_checks_suppressed_by_interprocedural_check(tmp_path: Path) -> None:
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    (db_dir / "function_patterns.jsonl").write_text("", encoding="utf-8")

    pattern = {
        "topic0": "0xdeadbeef",
        "cluster_id": "cid3",
        "support": {"open": 1},
        "pattern_tier": "open",
        "indexed_profile": {"topic0": 1.0},
        "param_count_profile": {"topics": {"1": 1.0}, "data": {"0": 1.0}},
        "operand_profiles": {
            "topic0": {
                "source": {"CONST": 1.0},
                "deps": {},
                "ops": ["CONST"],
                "literal": {"nonzero": 1.0},
                "arg_index": {},
                "support": 1,
            },
        },
        "unaligned_offset_profile": {},
        "sstore_profile": {},
        "value_bind_profile": {},
        "slot_bind_profile": {},
        "sload_bind_profile": {},
        "guard_profile": {},
        "equality_profile": {},
        "equality_support": {},
        "examples": [],
    }
    _write_jsonl(db_dir / "event_patterns.jsonl", [pattern])

    tac_path = tmp_path / "contract.tac"
    tac_path.write_text(
        """
function publicEntry() public {
    Begin block 0x0
    prev=[], succ=[0x1, 0x2]
    =================================
    0x0: v0(0x0) = CONST
    0x1: v1 = CALLDATALOAD v0(0x0)
    0x2: v2 = ISZERO v1
    0x3: v3(0x2) = CONST
    0x4: JUMPI v3(0x2), v2

    Begin block 0x1
    prev=[0x0], succ=[0x10]
    =================================
    0x5: v5(0x10) = CONST
    0x6: JUMP v5(0x10)

    Begin block 0x2
    prev=[0x0], succ=[]
    =================================
    0x7: v7(0x0) = CONST
    0x8: REVERT v7(0x0), v7(0x0)
}

function internalFunc() private {
    Begin block 0x10
    prev=[], succ=[]
    =================================
    0x0: v0(0x0) = CONST
    0x1: v1(0x0) = CONST
    0x2: v2(0xdeadbeef) = CONST
    0x3: LOG1 v0(0x0), v1(0x0), v2(0xdeadbeef)
}
""".lstrip(),
        encoding="utf-8",
    )

    (tmp_path / "InFunction.csv").write_text(
        "0x0\tpublicEntry\n0x1\tpublicEntry\n0x2\tpublicEntry\n0x10\tinternalFunc\n",
        encoding="utf-8",
    )
    (tmp_path / "PublicFunction.csv").write_text(
        "publicEntry\t0x12345678\n", encoding="utf-8"
    )
    (tmp_path / "IRFunctionCall.csv").write_text(
        "0x1\tinternalFunc\n", encoding="utf-8"
    )

    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "similarity_min": 0.0,
                "support_min": 1,
                "max_conf_width": 1.0,
            }
        ),
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
    guard_findings = [item for item in findings if item.get("type") == "guard_gap"]
    assert not guard_findings
