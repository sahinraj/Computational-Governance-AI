"""M2 (parser) and M3 (single-rule semantics) acceptance tests.

M2 accept: the example laws parse into structured objects; a malformed
           law raises a clear error.
M3 accept: unit tests cover satisfy, violate, and not-applicable for each
           field type.
"""

import pytest

from governance import (
    Actor, Capability, Action, Context, Disposition, Result, parse_laws, ParseError,
)

EXAMPLE = """
LAW-001
  capability: payment.send
  authority_level: >= 3
  constraint: amount <= 100
  requires_approval: FinanceLead
  on_violation: escalate

LAW-014
  capability: deploy.production
  authority_level: >= 4
  on_violation: block

LAW-022
  capability: github.write
  authority_level: >= 2
  forbidden_classes: intern
  on_violation: block
"""


# ---- M2: parsing ----

def test_example_laws_parse():
    rules = parse_laws(EXAMPLE)
    assert [r.id for r in rules] == ["LAW-001", "LAW-014", "LAW-022"]
    r1 = rules[0]
    assert r1.capability.name == "payment.send"
    assert r1.min_authority == 3
    assert r1.disposition is Disposition.ESCALATE
    assert r1.requires_approval == "FinanceLead"
    assert r1.predicate is not None
    assert "intern" in rules[2].forbidden_classes


def test_malformed_missing_capability_errors():
    with pytest.raises(ParseError) as e:
        parse_laws("LAW-099\n  authority_level: >= 2\n")
    assert "capability" in str(e.value)


def test_malformed_bad_operator_errors():
    with pytest.raises(ParseError) as e:
        parse_laws("LAW-1\n  capability: x\n  constraint: amount =< 5\n")
    assert "operator" in str(e.value)


def test_malformed_unknown_field_errors():
    with pytest.raises(ParseError) as e:
        parse_laws("LAW-1\n  capability: x\n  color: blue\n")
    assert "unknown field" in str(e.value)


def test_duplicate_id_errors():
    src = "LAW-1\n  capability: x\nLAW-1\n  capability: y\n"
    with pytest.raises(ParseError) as e:
        parse_laws(src)
    assert "duplicate" in str(e.value)


def test_field_outside_block_errors():
    with pytest.raises(ParseError):
        parse_laws("capability: x\n")


# ---- M3: single-rule semantics ----

def _rule(src):
    return parse_laws(src)[0]

CTX = Context()


def test_not_applicable_different_capability():
    r = _rule("LAW-1\n  capability: payment.send\n  authority_level: >= 3\n")
    a = Action(Actor("a", 5), Capability("deploy.production"))
    assert r.evaluate(a, CTX) is Result.NOT_APPLICABLE


def test_applies_to_descendant_capability():
    r = _rule("LAW-1\n  capability: payment\n  authority_level: >= 3\n")
    a = Action(Actor("a", 5), Capability("payment.send"))
    assert r.evaluate(a, CTX) is Result.SATISFIED


def test_authority_satisfy_and_violate():
    r = _rule("LAW-1\n  capability: deploy.production\n  authority_level: >= 4\n")
    ok = Action(Actor("a", 4), Capability("deploy.production"))
    bad = Action(Actor("b", 3), Capability("deploy.production"))
    assert r.evaluate(ok, CTX) is Result.SATISFIED
    assert r.evaluate(bad, CTX) is Result.VIOLATED


def test_forbidden_class_violate():
    r = _rule("LAW-1\n  capability: github.write\n  authority_level: >= 1\n  forbidden_classes: intern\n")
    intern = Action(Actor("i", 5, cls="intern"), Capability("github.write"))
    eng = Action(Actor("e", 5, cls="engineer"), Capability("github.write"))
    assert r.evaluate(intern, CTX) is Result.VIOLATED
    assert r.evaluate(eng, CTX) is Result.SATISFIED


def test_constraint_predicate_satisfy_and_violate():
    r = _rule("LAW-1\n  capability: payment.send\n  constraint: amount <= 100\n")
    under = Action(Actor("a", 5), Capability("payment.send"), {"amount": 50})
    over = Action(Actor("a", 5), Capability("payment.send"), {"amount": 150})
    assert r.evaluate(under, CTX) is Result.SATISFIED
    assert r.evaluate(over, CTX) is Result.VIOLATED


def test_constraint_missing_field_denies():
    r = _rule("LAW-1\n  capability: payment.send\n  constraint: amount <= 100\n")
    a = Action(Actor("a", 5), Capability("payment.send"), {})
    assert r.evaluate(a, CTX) is Result.VIOLATED


def test_determinism_repeated_evaluation():
    # T6 sanity at the single-rule level: same inputs, same result, every time.
    r = _rule("LAW-1\n  capability: payment.send\n  constraint: amount <= 100\n")
    a = Action(Actor("a", 5), Capability("payment.send"), {"amount": 99})
    results = {r.evaluate(a, CTX) for _ in range(100)}
    assert results == {Result.SATISFIED}
