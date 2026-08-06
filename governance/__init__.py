"""Computational Governance reference implementation.

Realizes 𝒢(S, α) from Foundations v1. This package builds up per the
build spec milestones; M1-M3 are the parser and single-rule semantics.
"""

from .model import (
    Actor, Capability, Action, Context, Decision, DecisionKind, Disposition,
)
from .rule import Rule, Result, Applicability
from .parser import parse_laws, ParseError

__all__ = [
    "Actor", "Capability", "Action", "Context", "Decision", "DecisionKind",
    "Disposition", "Rule", "Result", "Applicability", "parse_laws", "ParseError",
]
