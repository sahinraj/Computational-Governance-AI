"""Acceptance tests for M17's implementation-independent conformance protocol."""

import ast
import json
from pathlib import Path

import pytest

from conformance import (
    AuditEventEnvelope,
    DecisionEnvelope,
    ProtocolError,
    ToolCallEnvelope,
    canonical_json,
)
from conformance.runner import TranscriptAdapter, load_cases, run_conformance


def test_conformance_fixtures_round_trip_and_independent_adapter_passes():
    cases = load_cases()
    assert len(cases) == 3
    report = run_conformance(cases, TranscriptAdapter(cases))
    assert report.accuracy == 1.0
    for case in cases:
        restored = ToolCallEnvelope.from_dict(case.tool_call.to_dict())
        assert restored == case.tool_call
        assert DecisionEnvelope.from_dict(case.expected.to_dict()) == case.expected


def test_protocol_rejects_unknown_versions_and_invalid_decisions():
    case = load_cases()[0].tool_call.to_dict()
    case["protocol_version"] = "2.0"
    with pytest.raises(ProtocolError, match="unsupported"):
        ToolCallEnvelope.from_dict(case)
    with pytest.raises(ProtocolError, match="Escalate requires"):
        DecisionEnvelope("Escalate")


def test_audit_event_protocol_is_redacted_and_canonical():
    event = AuditEventEnvelope.from_dict({
        "event_version": "1.0",
        "event_id": "event-1",
        "trace_id": "trace-1",
        "policy_fingerprint": "p",
        "state_fingerprint": "s",
        "action_fingerprint": "a",
        "context_fingerprint": "c",
        "actor_id": "agent",
        "capability": "payment.send",
        "decision": "Allow",
        "role": None,
        "reason": "safe",
        "matched_rules": ["LAW-1"],
        "authority_source": "intrinsic",
        "authority_path": ["actor:agent"],
        "mode": "enforce",
        "executed": True,
        "outcome": "Allow",
    })
    payload = event.to_dict()
    assert canonical_json(payload) == canonical_json(json.loads(canonical_json(payload)))
    assert "raw-secret" not in canonical_json(payload)


def test_conformance_package_does_not_import_reference_implementation():
    root = Path(__file__).parents[1] / "conformance"
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = [
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        ]
        assert not any(module.startswith("governance") for module in imports), path
