"""Core entities and decision types.

Maps directly onto Foundations v1:
  Actor, Capability, Rule, Context, Decision (Sections 1-3).
Enforcement logic here is deterministic (GA5/T6): a decision depends only
on state and action, never on execution outcome.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Disposition(str, Enum):
    """What a rule does when its predicate fails."""
    BLOCK = "block"
    ESCALATE = "escalate"


class DecisionKind(str, Enum):
    ALLOW = "Allow"
    BLOCK = "Block"
    ESCALATE = "Escalate"


@dataclass(frozen=True)
class Decision:
    """Output of governance for one intended action (Foundations Sec. 1).

    kind is the decision; role is set only for ESCALATE; reason and
    matched_rules make every decision auditable.
    """
    kind: DecisionKind
    role: Optional[str] = None
    reason: str = ""
    matched_rules: tuple[str, ...] = ()
    authority_source: str = ""
    authority_path: tuple[str, ...] = ()
    approval_roles: tuple[str, ...] = ()
    approval_threshold: int = 0

    def __post_init__(self):
        if self.kind is DecisionKind.ESCALATE and not self.role:
            raise ValueError("Escalate decision requires a role")
        if self.kind is not DecisionKind.ESCALATE and self.role:
            raise ValueError("role is only valid for Escalate decisions")
        if self.kind is not DecisionKind.ESCALATE and (self.approval_roles or self.approval_threshold):
            raise ValueError("approval quorum is only valid for Escalate decisions")
        if self.approval_roles:
            if len(set(self.approval_roles)) != len(self.approval_roles):
                raise ValueError("approval roles must be distinct")
            if self.approval_threshold < 1 or self.approval_threshold > len(self.approval_roles):
                raise ValueError("approval threshold must be within approval role count")
        elif self.approval_threshold:
            raise ValueError("approval threshold requires approval roles")


@dataclass(frozen=True)
class Actor:
    """An autonomous agent that selects actions (Foundations Sec. 1)."""
    id: str
    authority_level: int
    cls: str = "agent"  # 'class' is reserved; cls maps to the model's actor class
    capabilities: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self):
        # Accept a normal set/list at the API boundary while keeping the model
        # immutable and hash-friendly internally.
        object.__setattr__(self, "capabilities", frozenset(self.capabilities))


@dataclass(frozen=True)
class Capability:
    """A namespaced, hierarchical action class, e.g. 'payment.send'.

    'payment' is an ancestor of 'payment.send' (Foundations Sec. 1).
    """
    name: str

    def is_descendant_of(self, other: "Capability") -> bool:
        if self.name == other.name:
            return True
        return self.name.startswith(other.name + ".")


@dataclass(frozen=True)
class Action:
    """An intended action alpha = (actor, capability, params) (Foundations Sec. 3)."""
    actor: Actor
    capability: Capability
    params: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Context:
    """Mutable state a decision is made against (Foundations Sec. 1).

    Held immutable per-decision; the process advances by producing a new
    Context, never mutating one mid-decision (supports GA5).
    """
    budget_used: float = 0.0
    prior_approvals: tuple[str, ...] = ()
    now: float = 0.0

    def with_approval(self, role: str) -> "Context":
        """Return the next immutable context after a human approval."""
        if role in self.prior_approvals:
            return self
        return Context(
            budget_used=self.budget_used,
            prior_approvals=self.prior_approvals + (role,),
            now=self.now,
        )
