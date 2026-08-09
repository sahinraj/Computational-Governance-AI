"""Acceptance tests for M16 runtime adapter and release hardening."""

import pytest

from evaluation.performance import measure
from governance import (
    Action,
    Actor,
    Capability,
    Context,
    DecisionKind,
    Interceptor,
    RuntimeAdapter,
    RuntimeAdapterError,
    ToolCall,
    compile_policy,
)


def _actor():
    return Actor("tool-agent", 5, capabilities={"payment.send"})


def test_enforce_runtime_adapter_has_no_non_allow_execution_path():
    policy = compile_policy(
        "LAW-1\n  capability: payment.send\n  authority_level: >= 6\n"
    )
    adapter = RuntimeAdapter(Interceptor(policy, mode="enforce"))
    calls = []
    result = adapter.invoke(
        ToolCall(_actor(), "payment.send", {"amount": 50}, request_id="req-1"),
        Context(),
        lambda: calls.append("called"),
    )
    assert result.decision.kind is DecisionKind.BLOCK
    assert result.executed is False
    assert calls == []


def test_enforce_runtime_adapter_allows_once_and_rejects_duplicate_request():
    policy = compile_policy("LAW-1\n  capability: payment.send\n")
    adapter = RuntimeAdapter(Interceptor(policy, mode="enforce"))
    calls = []
    call = ToolCall(_actor(), Capability("payment.send"), request_id="req-2")
    result = adapter.invoke(call, Context(), lambda: calls.append("called") or "ok")
    duplicate = adapter.invoke(call, Context(), lambda: calls.append("duplicate"))
    assert result.decision.kind is DecisionKind.ALLOW
    assert duplicate.decision.kind is DecisionKind.BLOCK
    assert duplicate.executed is False
    assert calls == ["called"]


def test_runtime_adapter_fails_closed_on_enforce_errors_and_can_observe_shadow_errors():
    policy = compile_policy("LAW-1\n  capability: payment.send\n")
    enforce_interceptor = Interceptor(policy, mode="enforce")
    enforce_interceptor.execute = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("broken"))
    enforce = RuntimeAdapter(enforce_interceptor).invoke(
        ToolCall(_actor(), "payment.send"), Context(), lambda: pytest.fail("must not execute")
    )
    assert enforce.decision.kind is DecisionKind.BLOCK
    assert enforce.executed is False
    assert "governance error" in enforce.decision.reason

    shadow_interceptor = Interceptor(policy, mode="shadow")
    shadow_interceptor.execute = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("broken"))
    calls = []
    shadow = RuntimeAdapter(shadow_interceptor, shadow_error_mode="allow").invoke(
        ToolCall(_actor(), "payment.send"), Context(), lambda: calls.append("observed") or "ok"
    )
    assert shadow.decision.kind is DecisionKind.BLOCK
    assert shadow.executed is True
    assert calls == ["observed"]


def test_runtime_adapter_does_not_relabel_tool_failures_as_governance_failures():
    policy = compile_policy("LAW-1\n  capability: payment.send\n")
    adapter = RuntimeAdapter(Interceptor(policy, mode="enforce"))
    with pytest.raises(RuntimeError, match="tool failed"):
        adapter.invoke(
            ToolCall(_actor(), "payment.send"),
            Context(),
            lambda: (_ for _ in ()).throw(RuntimeError("tool failed")),
        )


def test_runtime_tool_call_is_typed_and_performance_measurement_is_reproducible_shape():
    call = ToolCall(_actor(), "payment.send", {"amount": 10})
    assert call.to_action() == Action(call.actor, Capability("payment.send"), {"amount": 10})
    report = measure(10)
    assert report["iterations"] == 10
    assert report["mean_ms"] >= 0
    assert report["max_ms"] >= report["min_ms"]


def test_runtime_adapter_rejects_invalid_shadow_error_mode():
    with pytest.raises(RuntimeAdapterError, match="shadow_error_mode"):
        RuntimeAdapter(Interceptor(compile_policy("LAW-1\n  capability: payment.send\n")), shadow_error_mode="block")
