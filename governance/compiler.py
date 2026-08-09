"""M5: compile parsed laws into a validated enforcement artifact."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .composition import evaluate_rules, inherit_rules, validate_inheritance_graph
from .model import Action, Context, Decision, DecisionKind
from .parser import parse_laws
from .rule import Rule


class CompileError(ValueError):
    """A named policy compilation failure."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _validate_rules(rules: tuple[Rule, ...], roles: Optional[set[str]]) -> None:
    seen: dict[tuple, Rule] = {}
    ids: set[str] = set()
    for rule in rules:
        if rule.id in ids:
            raise CompileError("duplicate_rule", f"duplicate rule id {rule.id}")
        ids.add(rule.id)
        if rule.requires_approval and roles is not None and rule.requires_approval not in roles:
            raise CompileError(
                "dangling_role",
                f"rule {rule.id} references unknown role {rule.requires_approval}",
            )
        if rule.approval_requirement and roles is not None:
            unknown = sorted(set(rule.approval_requirement.roles) - roles)
            if unknown:
                raise CompileError(
                    "dangling_role",
                    f"rule {rule.id} references unknown approval roles {unknown}",
                )
        previous = seen.get(rule.semantic_signature())
        if previous is not None and previous.disposition is not rule.disposition:
            raise CompileError(
                "contradictory_rules",
                f"rules {previous.id} and {rule.id} have identical conditions "
                f"but dispositions {previous.disposition.value} and {rule.disposition.value}",
            )
        seen[rule.semantic_signature()] = rule


@dataclass(frozen=True)
class CompiledPolicy:
    """Immutable enforcement artifact emitted by M5."""

    rules: tuple[Rule, ...]
    roles: frozenset[str] = frozenset()
    default_decision: DecisionKind = DecisionKind.ALLOW

    def evaluate(self, action: Action, context: Context, delegation=None) -> Decision:
        decision = evaluate_rules(self.rules, action, context, delegation=delegation)
        if (
            decision.kind is DecisionKind.ALLOW
            and not decision.matched_rules
            and self.default_decision is DecisionKind.BLOCK
        ):
            return Decision(
                DecisionKind.BLOCK,
                reason="no applicable rule; default-deny policy",
            )
        return decision


def compile_policy(
    source_or_rules: str | Iterable[Rule],
    *,
    roles: Optional[Iterable[str]] = None,
    parent_rules: Iterable[Rule] = (),
    default_decision: DecisionKind | str = DecisionKind.ALLOW,
) -> CompiledPolicy:
    """Parse, validate, and compile a policy source or already parsed rules.

    ``roles`` is optional because a runtime may supply its role registry later;
    when supplied, approval references are checked for dangling names.
    """
    rules = tuple(
        parse_laws(source_or_rules)
        if isinstance(source_or_rules, str)
        else source_or_rules
    )
    role_set = None if roles is None else set(roles)
    try:
        default = DecisionKind(default_decision)
    except ValueError as exc:
        raise CompileError(
            "invalid_default_decision",
            f"unknown default decision {default_decision!r}",
        ) from exc
    if default is DecisionKind.ESCALATE:
        raise CompileError("invalid_default_decision", "default decision cannot be Escalate")
    if parent_rules:
        rules = inherit_rules(tuple(parent_rules), rules)
    try:
        validate_inheritance_graph(rules)
    except ValueError as exc:
        message = str(exc)
        code = "inheritance_error"
        if "missing parent" in message:
            code = "dangling_parent"
        raise CompileError(code, message) from exc
    _validate_rules(rules, role_set)
    return CompiledPolicy(
        rules=rules,
        roles=frozenset(role_set or ()),
        default_decision=default,
    )


compile_laws = compile_policy
