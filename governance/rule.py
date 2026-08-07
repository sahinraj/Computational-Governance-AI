"""Rule (the model-level object; 'Law' is its concrete-syntax keyword).

M3 semantics core: evaluate a single rule against an action + context.
A rule binds a capability to a predicate over actor, params, and context,
plus a violation disposition (Foundations Sec. 1, 6).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .model import Action, Context, Capability, Disposition


class Applicability(str, Enum):
    APPLIES = "applies"
    NOT_APPLICABLE = "not_applicable"


class Result(str, Enum):
    """Outcome of evaluating one applicable rule."""
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class PredicateSpec:
    """The declarative shape of a parser-created comparison predicate.

    Keeping this small piece of AST metadata beside the callable lets M4/M5
    prove simple inheritance relationships without inspecting function code.
    """

    field_name: str
    operator: str
    threshold: object


@dataclass(frozen=True)
class Rule:
    """One governance rule.

    Fields mirror Foundations Sec. 5 law shape:
      id, capability, min_authority, predicate, requires_approval, disposition.
    predicate is a callable (actor, params, context) -> bool. The parser (M2)
    builds these from declarative source; here we just evaluate them.
    """
    id: str
    capability: Capability
    min_authority: int = 0
    disposition: Disposition = Disposition.BLOCK
    requires_approval: Optional[str] = None
    # predicate returns True when the action is PERMITTED by this rule's condition.
    predicate: Optional[object] = None  # Callable[[Actor, dict, Context], bool]
    # forbidden_classes: actor classes that may never exercise this capability.
    forbidden_classes: frozenset = field(default_factory=frozenset)
    predicate_spec: Optional[PredicateSpec] = None
    parent_id: Optional[str] = None

    def applies_to(self, action: Action) -> Applicability:
        if action.capability.is_descendant_of(self.capability):
            return Applicability.APPLIES
        return Applicability.NOT_APPLICABLE

    def evaluate(self, action: Action, context: Context) -> Result:
        """Single-rule semantics: satisfies / violates / not-applicable.

        Deterministic in (action, context) only. No side effects, no
        dependence on execution outcome (GA5, T6).
        """
        if self.applies_to(action) is Applicability.NOT_APPLICABLE:
            return Result.NOT_APPLICABLE

        # Authority check.
        if action.actor.authority_level < self.min_authority:
            return Result.VIOLATED

        # Class restriction.
        if action.actor.cls in self.forbidden_classes:
            return Result.VIOLATED

        # Predicate over params/context (e.g. amount <= 100).
        if self.predicate is not None:
            if not self.predicate(action.actor, action.params, context):
                return Result.VIOLATED

        # Approval is a rule condition, but the disposition determines whether
        # missing approval blocks immediately or escalates to the named role.
        if self.requires_approval and self.requires_approval not in context.prior_approvals:
            return Result.VIOLATED

        return Result.SATISFIED

    def semantic_signature(self) -> tuple:
        """Return the condition portion of a rule, excluding disposition."""
        predicate = self.predicate_spec
        predicate_key = None if predicate is None else (
            predicate.field_name, predicate.operator, predicate.threshold
        )
        return (
            self.capability.name,
            self.min_authority,
            predicate_key,
            tuple(sorted(self.forbidden_classes)),
            self.requires_approval,
        )
