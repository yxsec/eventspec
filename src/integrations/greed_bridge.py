"""Thin integration layer between the taint slices and Greed symbolic execution."""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Sequence

from ..core.models import GreedSliceResult
from ..core.slices import LogSlice

if TYPE_CHECKING:
    from greed.state import SymbolicEVMState

logger = logging.getLogger(__name__)

def _maybe_add_greed_to_syspath() -> None:
    def looks_like_greed_repo(path: Path) -> bool:
        return (path / "greed" / "__init__.py").exists()

    here = Path(__file__).resolve()
    # Prefer a `greed/` sibling of the directory that contains this package.
    for base in [here.parent, *here.parents]:
        candidate = base / "greed"
        if not (candidate.exists() and looks_like_greed_repo(candidate)):
            continue

        candidate_str = str(candidate)
        if candidate_str not in sys.path:
            sys.path.append(candidate_str)

        yices_py = candidate / "yices2_python_bindings"
        if (yices_py / "yices" / "__init__.py").exists():
            yices_py_str = str(yices_py)
            if yices_py_str not in sys.path:
                sys.path.append(yices_py_str)

        yices_lib = candidate / "yices2" / "build" / "x86_64-pc-linux-gnu-release" / "lib"
        if yices_lib.exists():
            yices_lib_str = str(yices_lib)
            if yices_lib_str not in sys.path:
                sys.path.append(yices_lib_str)

        return


_maybe_add_greed_to_syspath()

try:
    from greed import Project, options
    from greed.exploration_techniques import DirectedSearch, ExplorationTechnique
    from greed.exploration_techniques.other import LoopLimiter, MstoreConcretizer
    from greed.solver import Yices2
    from greed.solver.shortcuts import (
        BVV,
        Equal,
        NotEqual,
        And,
        Or,
        Not,
        BV_ULT,
        BV_ULE,
        BV_UGT,
        BV_UGE,
        bv_unsigned_value,
        is_concrete,
    )
    from greed.utils.extra import gen_exec_id
except ImportError as exc:  # pragma: no cover - optional dependency
    _GREED_IMPORT_ERROR = exc
    Project = None  # type: ignore
    DirectedSearch = None  # type: ignore
    ExplorationTechnique = object  # type: ignore
    LoopLimiter = None  # type: ignore
    MstoreConcretizer = None  # type: ignore
    Yices2 = None  # type: ignore
    BVV = None  # type: ignore
    Equal = None  # type: ignore
    NotEqual = None  # type: ignore
    And = None  # type: ignore
    Or = None  # type: ignore
    Not = None  # type: ignore
    BV_ULT = None  # type: ignore
    BV_ULE = None  # type: ignore
    BV_UGT = None  # type: ignore
    BV_UGE = None  # type: ignore
    bv_unsigned_value = None  # type: ignore
    is_concrete = None  # type: ignore
    gen_exec_id = None  # type: ignore
else:
    _GREED_IMPORT_ERROR = None


class SlicePruner(ExplorationTechnique):
    """Exploration technique that prunes states leaving the allowed slice blocks."""

    def __init__(self, allowed_blocks: Iterable[str], pruned_stash: str = "pruned"):
        super().__init__()
        self.allowed_blocks = {block for block in allowed_blocks if block}
        self.pruned_stash = pruned_stash
        self._entered_allowed = False

    def check_successors(self, simgr, successors):
        if not self.allowed_blocks:
            return successors
        kept = []
        for succ in successors:
            block_id = getattr(succ.curr_stmt, "block_id", None)
            if block_id in self.allowed_blocks or block_id is None:
                self._entered_allowed = True
                kept.append(succ)
            elif not self._entered_allowed:
                # Allow early exploration to find the slice before pruning kicks in.
                kept.append(succ)
            else:
                simgr.stashes.setdefault(self.pruned_stash, []).append(succ)
        return kept


@dataclass
class GreedSliceExecutor:
    """Runs Greed on a per-slice basis and captures operand valuations."""

    target_dir: Path
    max_calldata_bytes: Optional[int] = None
    solver_timeout: int = 15
    loop_limit: int = 3
    mstore_concretize: bool = False

    def __post_init__(self) -> None:
        if Project is None:
            extra = f" (import error: {_GREED_IMPORT_ERROR})" if _GREED_IMPORT_ERROR else ""
            raise RuntimeError(
                "The greed package is not available. Please run setup.sh or pip install -e greed."
                + extra
            )
        self.target_dir = self.target_dir.resolve()
        if not self.target_dir.exists():
            raise FileNotFoundError(f"Greed target directory not found: {self.target_dir}")
        options.SOLVER_TIMEOUT = self.solver_timeout
        if self.max_calldata_bytes is not None:
            options.MAX_CALLDATA_SIZE = self.max_calldata_bytes
        self.project = Project(target_dir=str(self.target_dir))
        self.slice_states: Dict[str, Optional["SymbolicEVMState"]] = {}
        self.slice_operand_vars: Dict[str, Dict[str, str]] = {}
        self._mstore_ready = False
        if self.mstore_concretize:
            self._mstore_ready = self._check_mstore_inputs()

    def solve_slices(self, slices: Sequence[LogSlice]) -> Dict[str, List[GreedSliceResult]]:
        results: Dict[str, List[GreedSliceResult]] = {}
        self.slice_states.clear()
        self.slice_operand_vars = {
            slice_info.log_uid: {label: var for label, var in slice_info.targets}
            for slice_info in slices
        }
        for slice_info in slices:
            try:
                slice_results, state = self._solve_single_slice(slice_info)
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception("Greed slice execution failed for %s", slice_info.log_uid)
                slice_results = [
                    GreedSliceResult(
                        operand=label,
                        var=var,
                        status="error",
                        details=str(exc),
                    )
                    for label, var in slice_info.targets
                ]
                state = None
            self.slice_states[slice_info.log_uid] = state
            results[slice_info.log_uid] = slice_results
        return results

    def _check_mstore_inputs(self) -> bool:
        required = [
            "BlockInStructuredLoop.csv",
            "InductionVariable.csv",
            "InductionVariableStartsAtConst.csv",
            "InductionVariableIncreasesByConst.csv",
            "InductionVariableUpperBoundVar.csv",
        ]
        missing = [name for name in required if not (self.target_dir / name).exists()]
        if missing:
            logger.warning(
                "MstoreConcretizer disabled; missing required TAC facts: %s",
                ", ".join(missing),
            )
            return False
        return True

    def _solve_single_slice(
        self, slice_info: LogSlice
    ) -> tuple[List[GreedSliceResult], Optional["SymbolicEVMState"]]:
        target_stmt = self.project.factory.statement(slice_info.log_statement_id)
        if target_stmt is None:
            return [
                GreedSliceResult(
                    operand=label,
                    var=var,
                    status="error",
                    details=f"Statement {slice_info.log_statement_id} not found in Greed project.",
                )
                for label, var in slice_info.targets
            ], None

        def run_search():
            entry_kwargs = {"xid": gen_exec_id()}
            if self.max_calldata_bytes is not None:
                entry_kwargs["max_calldatasize"] = self.max_calldata_bytes
            entry_state = self.project.factory.entry_state(**entry_kwargs)
            simgr = self.project.factory.simgr(entry_state=entry_state)
            if LoopLimiter is not None and self.loop_limit > 0:
                simgr.use_technique(LoopLimiter(self.loop_limit))
            if self._mstore_ready and MstoreConcretizer is not None:
                simgr.use_technique(MstoreConcretizer())
            simgr.run(find=lambda s: s.curr_stmt.id == target_stmt.id)
            return simgr

        simgr = run_search()
        if not simgr.found:
            return [
                GreedSliceResult(
                    operand=label,
                    var=var,
                    status="unreachable",
                    details="Directed search could not reach the log statement within the slice.",
                )
                for label, var in slice_info.targets
            ], None

        state = simgr.found[0]
        calldata_hex = self._extract_calldata(state)
        operand_results: List[GreedSliceResult] = []
        for label, var in slice_info.targets:
            operand_results.append(
                GreedSliceResult(
                    operand=label,
                    var=var,
                    status="sat",
                    value=self._evaluate_var(state, var),
                    calldata=calldata_hex,
                )
            )
        return operand_results, state

    def _extract_calldata(self, state) -> str:
        if is_concrete(state.calldatasize):
            length_bvv = state.calldatasize
        else:
            length_bvv = state.solver.eval(state.calldatasize, raw=True)
        calldata_len = bv_unsigned_value(length_bvv)
        max_len = self.max_calldata_bytes if self.max_calldata_bytes is not None else calldata_len
        length = min(max_len, calldata_len)
        if length <= 0:
            return "0x"
        mem_bvv = state.solver.eval_memory(state.calldata, BVV(length, 256), raw=False)
        return "0x" + mem_bvv

    def _evaluate_var(self, state, var: str) -> Optional[str]:
        value = state.registers.get(var)
        if value is None:
            return None
        if not is_concrete(value):
            value = state.solver.eval(value, raw=True)
        if value is None:
            return None
        return f"0x{bv_unsigned_value(value):064x}"

    def check_joint_var_relation_feasible(
        self,
        log_uid_a: str,
        var_a: str,
        log_uid_b: str,
        var_b: str,
        op: str,
    ) -> str:
        """Strict joint satisfiability check: constraints(A) ∧ constraints(B) ∧ (var_a op var_b)."""
        if Yices2 is None:
            return "unknown"
        state_a = self.slice_states.get(log_uid_a)
        state_b = self.slice_states.get(log_uid_b)
        if state_a is None or state_b is None:
            return "unknown"
        term_a = state_a.registers.get(var_a)
        term_b = state_b.registers.get(var_b)
        if term_a is None or term_b is None:
            return "unknown"

        op = op.strip()
        if op == "==":
            relation = Equal(term_a, term_b)
        elif op == "!=":
            relation = NotEqual(term_a, term_b)
        elif op == "<":
            relation = BV_ULT(term_a, term_b)
        elif op == "<=":
            relation = BV_ULE(term_a, term_b)
        elif op == ">":
            relation = BV_UGT(term_a, term_b)
        elif op == ">=":
            relation = BV_UGE(term_a, term_b)
        else:
            return "unknown"

        joint = Yices2()
        try:
            joint.add_assertions(state_a.solver.constraints)
            joint.add_assertions(state_b.solver.constraints)
            joint.add_assertion(relation)
            satisfiable = joint.is_sat()
        except Exception:  # pragma: no cover
            return "unknown"
        return "possible" if satisfiable else "unsat"

    def check_var_value_feasible(self, log_uid: str, var: str, value_hex: str) -> str:
        state = self.slice_states.get(log_uid)
        if state is None:
            return "unknown"
        term = state.registers.get(var)
        if term is None:
            return "unknown"
        try:
            int_value = int(value_hex, 16)
        except ValueError:
            return "unknown"
        constraint = Equal(term, BVV(int_value, 256))
        try:
            satisfiable = state.solver.are_formulas_sat([constraint])
        except Exception:  # pragma: no cover
            return "unknown"
        return "possible" if satisfiable else "unsat"

    def check_var_eq_var_feasible(self, log_uid: str, var_a: str, var_b: str) -> str:
        state = self.slice_states.get(log_uid)
        if state is None:
            return "unknown"
        term_a = state.registers.get(var_a)
        term_b = state.registers.get(var_b)
        if term_a is None or term_b is None:
            return "unknown"
        constraint = Equal(term_a, term_b)
        try:
            satisfiable = state.solver.are_formulas_sat([constraint])
        except Exception:  # pragma: no cover
            return "unknown"
        return "possible" if satisfiable else "unsat"

    def check_var_relation_feasible(
        self,
        log_uid: str,
        var_a: str,
        op: str,
        rhs: str,
        *,
        rhs_is_var: bool = True,
    ) -> str:
        state = self.slice_states.get(log_uid)
        if state is None:
            return "unknown"
        term_a = state.registers.get(var_a)
        if term_a is None:
            return "unknown"
        if rhs_is_var:
            term_b = state.registers.get(rhs)
            if term_b is None:
                return "unknown"
        else:
            try:
                int_value = int(rhs, 16) if rhs.lower().startswith("0x") else int(rhs, 10)
            except ValueError:
                return "unknown"
            term_b = BVV(int_value, 256)

        op = op.strip()
        if op == "==":
            constraint = Equal(term_a, term_b)
        elif op == "!=":
            constraint = NotEqual(term_a, term_b)
        elif op == "<":
            constraint = BV_ULT(term_a, term_b)
        elif op == "<=":
            constraint = BV_ULE(term_a, term_b)
        elif op == ">":
            constraint = BV_UGT(term_a, term_b)
        elif op == ">=":
            constraint = BV_UGE(term_a, term_b)
        else:
            return "unknown"

        try:
            satisfiable = state.solver.are_formulas_sat([constraint])
        except Exception:  # pragma: no cover
            return "unknown"
        return "possible" if satisfiable else "unsat"

    def is_constraint_feasible(self, log_uid: str, constraint: dict) -> str:
        state = self.slice_states.get(log_uid)
        if state is None:
            return "unknown"
        term = self._constraint_to_term(state, constraint)
        if term is None:
            return "unknown"
        try:
            satisfiable = state.solver.are_formulas_sat([term])
        except Exception:  # pragma: no cover
            return "unknown"
        return "possible" if satisfiable else "unsat"

    def _constraint_to_term(self, state, constraint: dict):
        if not isinstance(constraint, dict):
            return None
        if "and" in constraint:
            raw_parts = constraint.get("and", [])
            if not isinstance(raw_parts, list) or not raw_parts:
                return None
            parts = [self._constraint_to_term(state, item) for item in raw_parts]
            if any(item is None for item in parts):
                return None
            return And(*parts)
        if "or" in constraint:
            raw_parts = constraint.get("or", [])
            if not isinstance(raw_parts, list) or not raw_parts:
                return None
            parts = [self._constraint_to_term(state, item) for item in raw_parts]
            if any(item is None for item in parts):
                return None
            return Or(*parts)
        if "not" in constraint:
            inner = self._constraint_to_term(state, constraint.get("not"))
            return Not(inner) if inner is not None else None

        op = str(constraint.get("op", "==")).strip()
        lhs = self._term_from_ref(state, constraint.get("lhs"))
        rhs = self._term_from_ref(state, constraint.get("rhs"))
        if lhs is None or rhs is None:
            return None
        if op == "==":
            return Equal(lhs, rhs)
        if op == "!=":
            return NotEqual(lhs, rhs)
        if op == "<":
            return BV_ULT(lhs, rhs)
        if op == "<=":
            return BV_ULE(lhs, rhs)
        if op == ">":
            return BV_UGT(lhs, rhs)
        if op == ">=":
            return BV_UGE(lhs, rhs)
        return None

    def _term_from_ref(self, state, ref):
        if not isinstance(ref, dict):
            return None
        kind = ref.get("type")
        if kind == "var":
            name = ref.get("name")
            if not name:
                return None
            return state.registers.get(name)
        if kind == "literal":
            value = ref.get("value")
            if value is None:
                return None
            try:
                if isinstance(value, int):
                    int_value = value
                else:
                    text = str(value).strip().lower()
                    int_value = int(text, 16) if text.startswith("0x") else int(text, 10)
            except ValueError:
                return None
            return BVV(int_value, 256)
        if kind == "arg":
            idx = ref.get("index")
            try:
                arg_index = int(idx)
            except (TypeError, ValueError):
                return None
            offset = 4 + 32 * arg_index
            try:
                return state.calldata.readn(BVV(offset, 256), BVV(32, 256))
            except Exception:
                return None
        return None
