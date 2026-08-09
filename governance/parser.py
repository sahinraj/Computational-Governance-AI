"""M2: parse declarative Law source into Rule objects.

Concrete syntax (a Law denotes a Rule in the model). Example:

    LAW-001
      capability: payment.send
      authority_level: >= 3
      constraint: amount <= 100
      forbidden_classes: intern
      requires_approval: FinanceLead
      approval_policy: quorum 2 of ReleaseManager, SecurityLead, FinanceLead
      on_violation: escalate

Design choice recorded (spec Sec. 12): a small line-based DSL, not YAML,
so the grammar is explicit and errors point at a line. Predicates support
a minimal comparison form over action, actor, and context fields:
`<field> <op> <number|string>`.
"""

from __future__ import annotations

import operator
import re
import shlex

from .model import Capability, Disposition
from .rule import ApprovalRequirement, PredicateSpec, Rule


class ParseError(ValueError):
    def __init__(self, line_no: int, message: str):
        super().__init__(f"line {line_no}: {message}")
        self.line_no = line_no


_OPS = {
    "<=": operator.le, ">=": operator.ge,
    "<": operator.lt, ">": operator.gt,
    "==": operator.eq, "!=": operator.ne,
}


def _field_value(field_name: str, actor, params, context):
    if field_name in params:
        return params[field_name]
    if field_name in ("budget_used", "context.budget_used"):
        return context.budget_used
    if field_name in ("now", "context.now"):
        return context.now
    if field_name in ("prior_approvals_count", "context.prior_approvals_count"):
        return len(context.prior_approvals)
    if field_name in ("actor.class", "actor.cls"):
        return actor.cls
    if field_name == "actor.authority_level":
        return actor.authority_level
    if field_name == "actor.id":
        return actor.id
    return None


def _make_predicate(field_name: str, op_symbol: str, threshold: object):
    op = _OPS[op_symbol]

    def predicate(actor, params, context):
        value = _field_value(field_name, actor, params, context)
        if value is None:
            # A predicate over a field the action/state doesn't supply is
            # unsatisfiable: the rule cannot confirm permission, so deny.
            return False
        try:
            return op(value, threshold)
        except (TypeError, ValueError):
            return False

    predicate.__doc__ = f"{field_name} {op_symbol} {threshold}"
    return predicate, PredicateSpec(field_name, op_symbol, threshold)


def _parse_authority(value: str, line_no: int) -> int:
    v = value.strip()
    if v.startswith(">="):
        v = v[2:].strip()
    try:
        return int(v)
    except ValueError:
        raise ParseError(line_no, f"invalid authority_level: {value!r}")


def _parse_constraint(value: str, line_no: int):
    try:
        parts = shlex.split(value.strip())
    except ValueError as exc:
        raise ParseError(line_no, f"invalid constraint quoting: {exc}") from exc
    if len(parts) != 3:
        raise ParseError(line_no, f"constraint must be '<field> <op> <number|string>', got {value!r}")
    field_name, op_symbol, rhs = parts
    if op_symbol not in _OPS:
        raise ParseError(line_no, f"unknown operator {op_symbol!r}")
    try:
        threshold = float(rhs)
        if threshold.is_integer():
            threshold = int(threshold)
    except ValueError:
        if not rhs:
            raise ParseError(line_no, "constraint RHS cannot be empty")
        threshold = rhs
    return _make_predicate(field_name, op_symbol, threshold)


def _parse_approval_policy(value: str, line_no: int) -> ApprovalRequirement:
    match = re.fullmatch(r"quorum\s+(\d+)\s+of\s+(.+)", value.strip(), re.IGNORECASE)
    if match is None:
        raise ParseError(line_no, "approval_policy must be 'quorum N of RoleA, RoleB, ...'")
    roles = tuple(role.strip() for role in match.group(2).split(",") if role.strip())
    try:
        return ApprovalRequirement(roles=roles, threshold=int(match.group(1)))
    except ValueError as exc:
        raise ParseError(line_no, str(exc)) from exc


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
            approval_requirement=block.get("approval_requirement"),
            predicate=block.get("predicate"),
            predicate_spec=block.get("predicate_spec"),
            forbidden_classes=frozenset(block.get("forbidden_classes", [])),
            parent_id=block.get("parent_id"),
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
            predicate, predicate_spec = _parse_constraint(value, i)
            current["predicate"] = predicate
            current["predicate_spec"] = predicate_spec
        elif key == "forbidden_classes":
            current["forbidden_classes"] = [c.strip() for c in value.split(",") if c.strip()]
        elif key == "requires_approval":
            current["requires_approval"] = value
        elif key == "approval_policy":
            if "requires_approval" in current:
                raise ParseError(i, "requires_approval and approval_policy are mutually exclusive")
            current["approval_requirement"] = _parse_approval_policy(value, i)
        elif key == "on_violation":
            v = value.lower()
            if v not in ("block", "escalate"):
                raise ParseError(i, f"on_violation must be block|escalate, got {value!r}")
            current["disposition"] = Disposition(v)
        elif key in ("parent", "inherits"):
            current["parent_id"] = value
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
