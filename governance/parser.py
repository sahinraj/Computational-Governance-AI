"""M2: parse declarative Law source into Rule objects.

Concrete syntax (a Law denotes a Rule in the model). Example:

    LAW-001
      capability: payment.send
      authority_level: >= 3
      constraint: amount <= 100
      forbidden_classes: intern
      requires_approval: FinanceLead
      on_violation: escalate

Design choice recorded (spec Sec. 12): a small line-based DSL, not YAML,
so the grammar is explicit and errors point at a line. Predicates support
a minimal comparison form over params: `<field> <op> <number>`.
"""

from __future__ import annotations

import operator

from .model import Capability, Disposition
from .rule import Rule


class ParseError(ValueError):
    def __init__(self, line_no: int, message: str):
        super().__init__(f"line {line_no}: {message}")
        self.line_no = line_no


_OPS = {
    "<=": operator.le, ">=": operator.ge,
    "<": operator.lt, ">": operator.gt,
    "==": operator.eq, "!=": operator.ne,
}


def _make_predicate(field_name: str, op_symbol: str, threshold: float):
    op = _OPS[op_symbol]

    def predicate(actor, params, context):
        if field_name not in params:
            # A predicate over a field the action doesn't supply is treated
            # as unsatisfiable: the rule cannot confirm permission, so deny.
            return False
        return op(params[field_name], threshold)

    predicate.__doc__ = f"{field_name} {op_symbol} {threshold}"
    return predicate


def _parse_authority(value: str, line_no: int) -> int:
    v = value.strip()
    if v.startswith(">="):
        v = v[2:].strip()
    try:
        return int(v)
    except ValueError:
        raise ParseError(line_no, f"invalid authority_level: {value!r}")


def _parse_constraint(value: str, line_no: int):
    parts = value.strip().split()
    if len(parts) != 3:
        raise ParseError(line_no, f"constraint must be '<field> <op> <number>', got {value!r}")
    field_name, op_symbol, rhs = parts
    if op_symbol not in _OPS:
        raise ParseError(line_no, f"unknown operator {op_symbol!r}")
    try:
        threshold = float(rhs)
    except ValueError:
        raise ParseError(line_no, f"constraint RHS must be numeric, got {rhs!r}")
    return _make_predicate(field_name, op_symbol, threshold)


def parse_laws(source: str) -> list[Rule]:
    """Parse source containing one or more LAW blocks into Rules."""
    rules: list[Rule] = []
    current: dict = {}
    current_line = 0

    def finalize(block: dict, header_line: int):
        if "capability" not in block:
            raise ParseError(header_line, f"{block['id']} missing 'capability'")
        return Rule(
            id=block["id"],
            capability=Capability(block["capability"]),
            min_authority=block.get("min_authority", 0),
            disposition=block.get("disposition", Disposition.BLOCK),
            requires_approval=block.get("requires_approval"),
            predicate=block.get("predicate"),
            forbidden_classes=frozenset(block.get("forbidden_classes", [])),
        )

    for i, raw in enumerate(source.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.upper().startswith("LAW-"):
            if current:
                rules.append(finalize(current, current_line))
            current = {"id": line}
            current_line = i
            continue

        if not current:
            raise ParseError(i, f"field outside any LAW block: {line!r}")

        if ":" not in line:
            raise ParseError(i, f"expected 'key: value', got {line!r}")
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()

        if key == "capability":
            current["capability"] = value
        elif key == "authority_level":
            current["min_authority"] = _parse_authority(value, i)
        elif key == "constraint":
            current["predicate"] = _parse_constraint(value, i)
        elif key == "forbidden_classes":
            current["forbidden_classes"] = [c.strip() for c in value.split(",") if c.strip()]
        elif key == "requires_approval":
            current["requires_approval"] = value
        elif key == "on_violation":
            v = value.lower()
            if v not in ("block", "escalate"):
                raise ParseError(i, f"on_violation must be block|escalate, got {value!r}")
            current["disposition"] = Disposition(v)
        else:
            raise ParseError(i, f"unknown field {key!r}")

    if current:
        rules.append(finalize(current, current_line))

    if not rules:
        raise ParseError(0, "no LAW blocks found")

    # Duplicate-id check: ids must be unique (needed for auditable matched_rules).
    seen = set()
    for r in rules:
        if r.id in seen:
            raise ParseError(0, f"duplicate law id {r.id!r}")
        seen.add(r.id)

    return rules
