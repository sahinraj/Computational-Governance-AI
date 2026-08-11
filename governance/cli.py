"""Small standard-library CLI for validation, decisions, replay, and reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .audit import AuditLog, replay_event
from .interceptor import Interceptor
from .model import Action, Actor, Capability, Context
from .compiler import compile_policy
from .versioning import PolicyBundle


def _policy(path: Path, roles: list[str]):
    return compile_policy(path.read_text(encoding="utf-8"), roles=set(roles) or None)


def _params(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--params must be a JSON object: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit("--params must be a JSON object")
    return parsed


def _action(args: argparse.Namespace) -> Action:
    return Action(
        Actor(
            args.actor_id,
            args.authority_level,
            cls=args.actor_class,
            capabilities=frozenset(args.actor_capability),
        ),
        Capability(args.capability),
        _params(args.params),
    )


def _decision_dict(decision) -> dict[str, Any]:
    return {
        "decision": decision.kind.value,
        "role": decision.role,
        "reason": decision.reason,
        "matched_rules": list(decision.matched_rules),
        "authority_source": decision.authority_source,
        "authority_path": list(decision.authority_path),
        "approval_roles": list(decision.approval_roles),
        "approval_threshold": decision.approval_threshold,
    }


def _common_action(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--actor-id", required=True)
    parser.add_argument("--authority-level", type=int, default=0)
    parser.add_argument("--actor-class", default="agent")
    parser.add_argument("--actor-capability", action="append", default=[])
    parser.add_argument("--capability", required=True)
    parser.add_argument("--params", default="{}")
    parser.add_argument("--now", type=float, default=0.0)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m governance")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-policy", help="compile a policy and print its rules")
    validate.add_argument("policy", type=Path)
    validate.add_argument("--role", action="append", default=[])

    export = subparsers.add_parser("policy-export", help="create a versioned policy bundle")
    export.add_argument("policy", type=Path)
    export.add_argument("--policy-id", required=True)
    export.add_argument("--policy-version", required=True)
    export.add_argument("--role", action="append", default=[])
    export.add_argument("--output", type=Path)

    imported = subparsers.add_parser("policy-import", help="validate a versioned policy bundle")
    imported.add_argument("bundle", type=Path)

    diff = subparsers.add_parser("policy-diff", help="compare two versioned policy bundles")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)

    tool_call = subparsers.add_parser("tool-call", help="evaluate one pre-execution tool call")
    tool_call.add_argument("--policy", type=Path, required=True)
    tool_call.add_argument("--role", action="append", default=[])
    tool_call.add_argument("--mode", choices=("shadow", "enforce"), default="shadow")
    _common_action(tool_call)

    replay = subparsers.add_parser("audit-replay", help="replay one redacted audit event")
    replay.add_argument("--policy", type=Path, required=True)
    replay.add_argument("--audit", type=Path, required=True)
    replay.add_argument("--role", action="append", default=[])
    replay.add_argument("--event-id")
    _common_action(replay)

    subparsers.add_parser("conformance", help="run the implementation-independent fixtures")
    assurance = subparsers.add_parser("assurance", help="run seeded model-based assurance")
    assurance.add_argument("--seed", type=int, default=20260809)
    assurance.add_argument("--traces", type=int, default=1000)
    assurance.add_argument("--output", type=Path)
    assurance.add_argument("--check", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "validate-policy":
        policy = _policy(args.policy, args.role)
        print(json.dumps({
            "valid": True,
            "rules": [rule.id for rule in policy.rules],
            "roles": sorted(policy.roles),
            "default_decision": policy.default_decision.value,
        }, indent=2, sort_keys=True))
        return 0
    if args.command == "policy-export":
        bundle = PolicyBundle.from_source(
            args.policy.read_text(encoding="utf-8"),
            policy_id=args.policy_id,
            policy_version=args.policy_version,
            roles=args.role,
        )
        payload = json.dumps(bundle.to_dict(), indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(payload, encoding="utf-8")
        print(payload, end="")
        return 0
    if args.command == "policy-import":
        bundle = PolicyBundle.from_json(args.bundle.read_text(encoding="utf-8"))
        print(json.dumps({
            "valid": True,
            "policy_id": bundle.policy_id,
            "policy_version": bundle.policy_version,
            "content_hash": bundle.content_hash,
        }, indent=2, sort_keys=True))
        return 0
    if args.command == "policy-diff":
        before = PolicyBundle.from_json(args.before.read_text(encoding="utf-8"))
        after = PolicyBundle.from_json(args.after.read_text(encoding="utf-8"))
        print(json.dumps(before.diff(after), indent=2, sort_keys=True))
        return 0
    if args.command == "tool-call":
        policy = _policy(args.policy, args.role)
        decision = Interceptor(policy, mode=args.mode).check(
            _action(args), Context(now=args.now)
        )
        print(json.dumps(_decision_dict(decision), indent=2, sort_keys=True))
        return 0
    if args.command == "audit-replay":
        policy = _policy(args.policy, args.role)
        log = AuditLog.from_jsonl(args.audit)
        event = next(
            (item for item in log.events if args.event_id is None or item.event_id == args.event_id),
            None,
        )
        if event is None:
            raise SystemExit("no matching audit event")
        result = replay_event(event, policy, _action(args), Context(now=args.now))
        print(json.dumps({
            "event_id": event.event_id,
            "exact": result.exact,
            "drift": list(result.drift),
            "decision": _decision_dict(result.decision),
        }, indent=2, sort_keys=True))
        return 0 if result.exact else 1
    if args.command == "conformance":
        from conformance.runner import TranscriptAdapter, load_cases, run_conformance
        cases = load_cases()
        report = run_conformance(cases, TranscriptAdapter(cases))
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0 if report.accuracy == 1.0 else 1
    if args.command == "assurance":
        from evaluation.model_assurance import run_assurance
        report = run_assurance(seed=args.seed, traces=args.traces)
        payload = report.to_json()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(payload, encoding="utf-8")
        print(payload, end="")
        return 0 if report.exact else 1
    raise SystemExit(f"unknown command {args.command}")
