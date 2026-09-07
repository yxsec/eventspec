import json
from pathlib import Path
from types import SimpleNamespace

from src.event_spec import diff as diff_module


def test_no_event_emission_state_change(tmp_path: Path) -> None:
    tac_path = tmp_path / "contract.tac"
    tac_path.write_text(
        """
function test() public {
    Begin block 0x0
    prev=[], succ=[]
    =================================
    0x0: v0(0x0) = CONST
    0x1: v1(0x1) = CONST
    0x2: SSTORE v0(0x0), v1(0x1)
}
""".lstrip(),
        encoding="utf-8",
    )

    out_path = tmp_path / "findings.json"
    args = SimpleNamespace(
        tac=tac_path,
        db=None,
        out=out_path,
        config=None,
        symbolic=False,
        symbolic_eq_constant_only=False,
        symbolic_log_limit=2,
        target_only=True,
        timeout=15,
    )
    diff_module.run(args)

    findings = out_path.read_text(encoding="utf-8")
    assert "\"type\": \"no_event_emission\"" in findings
    assert "\"severity\": \"medium\"" in findings


def test_no_event_emission_non_view(tmp_path: Path) -> None:
    tac_path = tmp_path / "contract.tac"
    tac_path.write_text(
        """
function test() public {
    Begin block 0x0
    prev=[], succ=[]
    =================================
    0x0: v0(0x0) = CONST
    0x1: CALL v0(0x0), v0(0x0), v0(0x0), v0(0x0), v0(0x0), v0(0x0), v0(0x0)
}
""".lstrip(),
        encoding="utf-8",
    )

    out_path = tmp_path / "findings.json"
    args = SimpleNamespace(
        tac=tac_path,
        db=None,
        out=out_path,
        config=None,
        symbolic=False,
        symbolic_eq_constant_only=False,
        symbolic_log_limit=2,
        target_only=True,
        timeout=15,
    )
    diff_module.run(args)

    findings = out_path.read_text(encoding="utf-8")
    assert "\"type\": \"no_event_emission\"" in findings
    assert "\"severity\": \"low\"" in findings


def test_filters_function_selector_findings(tmp_path: Path) -> None:
    tac_path = tmp_path / "contract.tac"
    tac_path.write_text(
        """
function __function_selector__() public {
    Begin block 0x0
    prev=[], succ=[]
    =================================
    0x0: v0(0x0) = CONST
    0x1: v1(0x1) = CONST
    0x2: SSTORE v0(0x0), v1(0x1)
}
""".lstrip(),
        encoding="utf-8",
    )

    out_path = tmp_path / "findings.json"
    args = SimpleNamespace(
        tac=tac_path,
        db=None,
        out=out_path,
        config=None,
        symbolic=False,
        symbolic_eq_constant_only=False,
        symbolic_log_limit=2,
        target_only=True,
        timeout=15,
    )
    diff_module.run(args)

    findings = json.loads(out_path.read_text(encoding="utf-8"))
    assert findings == []
