"""M4: deterministic rule composition and parent/child inheritance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .model import Action, Context, Decision, DecisionKind, Disposition
from .rule import PredicateSpec, Result, Rule


class InheritanceError(ValueError):
    """Raised when a child rule would loosen its parent."""


_SEVERITY = {
    DecisionKind.ALLOW: 0,
    DecisionKind.ESCALATE: 1,
    DecisionKind.BLOCK: 2,
}


def _predicate_is_at_least_as_restrictive(
    parent: Optional[PredicateSpec], child: Optional[PredicateSpec]
) -> bool:
    if parent is None:
        return True
    if child is None or parent.field_name != child.field_name:
        return False
    if parent.operator == child.operator:
        if parent.operator in ("<=", "<"):
            return child.threshold <= parent.threshold
        if parent.operator in (">=", ">"):
            return child.threshold >= parent.threshold
        if parent.operator == "==":
            return child.threshold == parent.threshold
        if parent.operator == "!=":
            return child.threshold == parent.threshold
    # A general callable relationship cannot be proven safely. M4 therefore
    # rejects it rather than allowing a potentially weaker child policy.
    return False


def validate_inheritance(parent: Rule, child: Rule) -> None:
    """Prove the concrete M4 tightening conditions for one parent/child pair."""
    if child.parent_id != parent.id:
        raise InheritanceError(
            f"child {child.id} does not declare parent {parent.id}"
        )
    if not child.capability.is_descendant_of(parent.capability):
        raise InheritanceError(
            f"child {child.id} capability {child.capability.name!r} "
            f"cannot widen parent {parent.capability.name!r}"
        )
    if child.min_authority < parent.min_authority:
        raise InheritanceError(
            f"child {child.id} lowers authority requirement from "
            f"{parent.min_authority} to {child.min_authority}"
        )
    if not child.forbidden_classes.issuperset(parent.forbidden_classes):
        raise InheritanceError(
            f"child {child.id} removes a parent actor-class restriction"
        )
    if parent.requires_approval and not child.requires_approval:
        raise InheritanceError(
            f"child {child.id} removes parent approval requirement "
            f"{parent.requires_approval}"
        )
    if parent.disposition is Disposition.BLOCK and child.disposition is Disposition.ESCALATE:
        raise InheritanceError(
            f"child {child.id} changes parent block disposition to escalation"
        )
    predicate_proven = _predicate_is_at_least_as_restrictive(
        parent.predicate_spec, child.predicate_spec
    )
    if parent.predicate is not None and parent.predicate_spec is None:
        # Arbitrary callables are opaque. Only the exact same callable is a
        # proof that a child preserved the parent's condition.
        predicate_proven = child.predicate is parent.predicate
    if not predicate_proven:
        raise InheritanceError(
            f"child {child.id} weakens or cannot prove the parent predicate"
        )


def inherit_rules(parent_rules: Iterable[Rule], child_rules: Iterable[Rule]) -> tuple[Rule, ...]:
    """Return a composed set retaining every parent rule and validated child."""
    parents = tuple(parent_rules)
    parent_by_id = {rule.id: rule for rule in parents}
    result = list(parents)
    ids = set(parent_by_id)
    for child in child_rules:
        if child.id in ids:
            raise InheritanceError(f"duplicate rule id {child.id!r} in inheritance")
        if child.parent_id is not None:
            parent = parent_by_id.get(child.parent_id)
            if parent is None:
                raise InheritanceError(
                    f"child {child.id} references missing parent {child.parent_id}"
                )
            validate_inheritance(parent, child)
        result.append(child)
        ids.add(child.id)
    return tuple(result)


def validate_inheritance_graph(rules: Iterable[Rule]) -> None:
    """Validate explicit parent links when all laws share one source."""
    by_id = {rule.id: rule for rule in rules}
    visiting: set[str] = set()
    checked: set[str] = set()

    def visit(rule: Rule) -> None:
        if rule.id in checked:
            return
        if rule.id in visiting:
            raise InheritanceError(f"inheritance cycle includes {rule.id}")
        visiting.add(rule.id)
        if rule.parent_id is not None:
            parent = by_id.get(rule.parent_id)
            if parent is None:
                raise InheritanceError(
                    f"child {rule.id} references missing parent {rule.parent_id}"
                )
            visit(parent)
            validate_inheritance(parent, rule)
        visiting.remove(rule.id)
        checked.add(rule.id)

    for rule in by_id.values():
        visit(rule)


@dataclass(frozen=True)
class Evaluation:
    """Detailed per-rule evaluation used by the compiler and interceptor."""

    decision: Decision
    results: tuple[tuple[str, Result], ...]


def evaluate_rules(
    rules: Iterable[Rule],
    action: Action,
    context: Context,
    delegation=None,
) -> Decision:
    """Evaluate all applicable rules with order-independent resolution.

    The rule IDs are sorted before evaluation and reporting. The final outcome
    is selected by the total order Block > Escalate > Allow.
    """
    ordered = tuple(sorted(rules, key=lambda rule: rule.id))
    applicable = tuple(
        rule for rule in ordered if rule.applies_to(action).value == "applies"
    )
    matched = tuple(rule.id for rule in applicable)

    authority_source = ""
    authority_path: tuple[str, ...] = ()
    if delegation is not None:
        proof = delegation.authority_proof(action.actor, action.capability, context.now)
        authority_source = proof.source
        authority_path = proof.path
    if delegation is not None and not proof.allowed:
        return Decision(
            DecisionKind.BLOCK,
            reason="delegated authority is missing, expired, or revoked",
            matched_rules=matched,
            authority_source=authority_source,
            authority_path=authority_path,
        )

    results = tuple((rule.id, rule.evaluate(action, context)) for rule in applicable)
    violated = tuple(
        rule for rule in applicable if dict(results)[rule.id] is Result.VIOLATED
    )
    if not violated:
        reason = "all applicable rules satisfied" if applicable else "no applicable rules"
        return Decision(
            DecisionKind.ALLOW,
            reason=reason,
            matched_rules=matched,
            authority_source=authority_source,
            authority_path=authority_path,
        )

    blocking = tuple(
        rule for rule in violated if rule.disposition is Disposition.BLOCK
    )
    chosen = min(
        blocking or violated,
        key=lambda rule: (-_SEVERITY[
            DecisionKind.BLOCK if rule in blocking else DecisionKind.ESCALATE
        ], rule.id),
    )
    if blocking:
        return Decision(
            DecisionKind.BLOCK,
            reason=f"blocked by {chosen.id}",
            matched_rules=matched,
            authority_source=authority_source,
            authority_path=authority_path,
        )
    role = chosen.requires_approval or "human-reviewer"
    return Decision(
        DecisionKind.ESCALATE,
        role=role,
        reason=f"escalated by {chosen.id} to {role}",
        matched_rules=matched,
        authority_source=authority_source,
        authority_path=authority_path,
    )
