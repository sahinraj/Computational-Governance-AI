"""Computational Governance reference implementation.

Realizes 𝒢(S, α) from Foundations v1. This package builds up per the
build spec milestones; M1-M3 are the parser and single-rule semantics.
"""

from .model import (
    Actor, Capability, Action, Context, Decision, DecisionKind, Disposition,
)
from .rule import Rule, Result, Applicability, PredicateSpec
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

__all__ = [
    "Actor", "Capability", "Action", "Context", "Decision", "DecisionKind",
    "Disposition", "Rule", "Result", "Applicability", "PredicateSpec",
    "parse_laws", "ParseError", "Evaluation", "InheritanceError",
    "evaluate_rules", "inherit_rules", "validate_inheritance", "validate_inheritance_graph",
    "CompileError",
    "CompiledPolicy", "compile_laws", "compile_policy", "DelegationError",
    "AuthorityProof", "DelegationGraph", "Grant", "ApprovalStub", "InterceptionResult",
    "Interceptor", "InterceptorMode",
]
