"""Acceptance tests for M22 stable policy and protocol versioning."""

import json

import pytest

from governance import (
    PolicyBundle,
    PolicyVersionStore,
    VersioningError,
)


SOURCE = """
LAW-DEPLOY
  capability: deploy.production
  authority_level: >= 4
  constraint: environment == production
  on_violation: block
"""


QUORUM_SOURCE = """
LAW-DEPLOY
  capability: deploy.production
  approval_policy: quorum 2 of ReleaseManager, SecurityLead, FinanceLead
  on_violation: escalate
"""


def test_equivalent_source_formatting_has_stable_semantic_hash_and_round_trips():
    first = PolicyBundle.from_source(
        SOURCE,
        policy_id="deployment",
        policy_version="1.0.0",
        provenance={"commit": "abc", "author": "team"},
    )
    equivalent = PolicyBundle.from_source(
        "\n# formatting only\n" + SOURCE.replace("  ", "    "),
        policy_id="deployment",
        policy_version="1.0.0",
        provenance={"commit": "different", "author": "another"},
    )
    assert first.content_hash == equivalent.content_hash
    restored = PolicyBundle.from_json(first.to_json())
    assert restored.to_dict() == first.to_dict()
    assert restored.compile().rules[0].id == "LAW-DEPLOY"


def test_bundle_rejects_hash_tampering_and_incompatible_versions():
    bundle = PolicyBundle.from_source(
        SOURCE, policy_id="deployment", policy_version="1.0.0"
    )
    payload = bundle.to_dict()
    payload["semantics"]["default_decision"] = "Block"
    with pytest.raises(VersioningError, match="hash mismatch"):
        PolicyBundle.from_dict(payload)
    payload = bundle.to_dict()
    payload["bundle_version"] = "2.0"
    with pytest.raises(VersioningError, match="unsupported policy bundle version"):
        PolicyBundle.from_dict(payload)
    with pytest.raises(VersioningError, match="stable semver"):
        PolicyBundle.from_source(SOURCE, policy_id="deployment", policy_version="1")


def test_semantic_diff_reports_rule_approval_and_default_changes():
    before = PolicyBundle.from_source(
        SOURCE,
        policy_id="deployment",
        policy_version="1.0.0",
    )
    after = PolicyBundle.from_source(
        QUORUM_SOURCE,
        policy_id="deployment",
        policy_version="1.1.0",
        roles={"ReleaseManager", "SecurityLead", "FinanceLead"},
        default_decision="Block",
    )
    diff = before.diff(after)
    paths = {change["path"] for change in diff["changes"]}
    assert diff["changed"] is True
    assert "policy_version" in paths
    assert "rules.LAW-DEPLOY.approval_requirement" in paths
    assert "default_decision" in paths


def test_version_store_requires_explicit_rollback_and_records_events():
    store = PolicyVersionStore()
    v1 = PolicyBundle.from_source(SOURCE, policy_id="deployment", policy_version="1.0.0")
    v2 = PolicyBundle.from_source(SOURCE, policy_id="deployment", policy_version="1.1.0")
    old = PolicyBundle.from_source(SOURCE, policy_id="deployment", policy_version="0.9.0")
    first = store.activate(v1, reason="initial activation")
    second = store.activate(v2, reason="approved feature release")
    assert first.event == "activate"
    assert second.from_version == "1.0.0"
    with pytest.raises(VersioningError, match="explicit override"):
        store.activate(old, reason="accidental downgrade")
    rollback = store.rollback("deployment", "1.0.0", reason="revert unsafe release")
    assert rollback.event == "rollback"
    assert store.current("deployment").policy_version == "1.0.0"
    assert [event.event_id for event in store.history("deployment")] == [
        "policy-version-0001", "policy-version-0002", "policy-version-0003"
    ]


def test_same_policy_version_cannot_change_content():
    store = PolicyVersionStore()
    first = PolicyBundle.from_source(SOURCE, policy_id="deployment", policy_version="1.0.0")
    changed = PolicyBundle.from_source(
        SOURCE.replace(">= 4", ">= 5"),
        policy_id="deployment",
        policy_version="1.0.0",
    )
    store.register(first)
    with pytest.raises(VersioningError, match="different content"):
        store.register(changed)


def test_cli_exports_imports_and_diffs_versioned_bundles(tmp_path, capsys):
    from governance.cli import main

    before_path = tmp_path / "before.law"
    after_path = tmp_path / "after.law"
    before_path.write_text(SOURCE, encoding="utf-8")
    after_path.write_text(QUORUM_SOURCE, encoding="utf-8")
    first_bundle_path = tmp_path / "before.json"
    second_bundle_path = tmp_path / "after.json"

    assert main([
        "policy-export", str(before_path), "--policy-id", "deployment",
        "--policy-version", "1.0.0", "--output", str(first_bundle_path),
    ]) == 0
    capsys.readouterr()
    assert main([
        "policy-export", str(after_path), "--policy-id", "deployment",
        "--policy-version", "1.1.0", "--role", "ReleaseManager",
        "--role", "SecurityLead", "--role", "FinanceLead",
        "--output", str(second_bundle_path),
    ]) == 0
    capsys.readouterr()
    assert main(["policy-import", str(first_bundle_path)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main(["policy-diff", str(first_bundle_path), str(second_bundle_path)]) == 0
    assert json.loads(capsys.readouterr().out)["changed"] is True
