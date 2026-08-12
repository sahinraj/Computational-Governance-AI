"""Computational Governance reference implementation.

Realizes 𝒢(S, α) from Foundations v1. This package builds up per the build
spec milestones and exposes the stable reference API, including audit and
replay primitives.
"""

from .model import (
    Actor, Capability, Action, Context, Decision, DecisionKind, Disposition,
)
from .audit import (
    AUDIT_EVENT_VERSION, AuditLog, DecisionEvent, ReplayResult,
    action_fingerprint, context_fingerprint, delegation_snapshot,
    fingerprint, policy_fingerprint, replay_event, state_fingerprint,
)
from .approval import ApprovalError, ApprovalManager, ApprovalRequest, ApprovalState
from .runtime import RuntimeAdapter, RuntimeAdapterError, ToolCall
from .rule import ApprovalRequirement, Rule, Result, Applicability, PredicateSpec
from .parser import parse_laws, ParseError
from .composition import (
    Evaluation, InheritanceError, evaluate_rules, inherit_rules,
    validate_inheritance, validate_inheritance_graph,
)
from .compiler import CompileError, CompiledPolicy, compile_laws, compile_policy
from .delegation import AuthorityProof, DelegationError, DelegationGraph, Grant
from .interceptor import (
    ApprovalStub, InterceptionResult, Interceptor, InterceptorMode,
)
from .storage import AtomicJsonStore, JsonlAuditStore, StoreError
from .versioning import (
    POLICY_BUNDLE_VERSION,
    PolicyBundle,
    PolicyVersionEvent,
    PolicyVersionStore,
    VersioningError,
    policy_semantics,
)

__all__ = [
    "Actor", "Capability", "Action", "Context", "Decision", "DecisionKind",
    "Disposition", "Rule", "Result", "Applicability", "PredicateSpec", "ApprovalRequirement",
    "AUDIT_EVENT_VERSION", "AuditLog", "DecisionEvent", "ReplayResult",
    "action_fingerprint", "context_fingerprint", "delegation_snapshot",
    "fingerprint", "policy_fingerprint", "replay_event", "state_fingerprint",
    "ApprovalError", "ApprovalManager", "ApprovalRequest", "ApprovalState",
    "RuntimeAdapter", "RuntimeAdapterError", "ToolCall",
    "parse_laws", "ParseError", "Evaluation", "InheritanceError",
    "evaluate_rules", "inherit_rules", "validate_inheritance", "validate_inheritance_graph",
    "CompileError",
    "CompiledPolicy", "compile_laws", "compile_policy", "DelegationError",
    "AuthorityProof", "DelegationGraph", "Grant", "ApprovalStub", "InterceptionResult",
    "Interceptor", "InterceptorMode",
    "AtomicJsonStore", "JsonlAuditStore", "StoreError",
    "POLICY_BUNDLE_VERSION", "PolicyBundle", "PolicyVersionEvent",
    "PolicyVersionStore", "VersioningError", "policy_semantics",
]
