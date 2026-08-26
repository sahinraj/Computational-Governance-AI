# M27 Policy Lifecycle and Controlled Rollout

M27 adds an operational boundary around immutable M22 `PolicyBundle` objects.
Policy semantics remain unchanged; lifecycle state records who owns a version,
which evidence was produced, who approved it, where it is active, and why it
was promoted or rolled back.

## Lifecycle

```text
draft -> validated -> simulated -> approved -> deployed
                                      |          |
                                      |          +--> superseded
                                      +--------------> rolled_back

deployed --expiry monitor--> expired
```

Invalid policies remain in `draft`. Production deployment requires the
configured number of distinct approvals and a matching passing canary when a
previous production policy exists. An initial production activation has no
prior baseline, so it does not require a canary.

## Python API

```python
from governance import PolicyBundle, PolicyLifecycleManager, SimulationCase

manager = PolicyLifecycleManager(
    production_approval_threshold=2,
    approver_roles={"SecurityLead", "ReleaseManager"},
)
candidate = PolicyBundle.from_source(
    source,
    policy_id="deployments",
    policy_version="1.1.0",
)
manager.draft(candidate, owner="platform-governance")
manager.validate("deployments", "1.1.0")
report = manager.simulate("deployments", "1.1.0", historical_cases,
                          baseline=active_bundle)
canary = manager.canary(
    "deployments", "1.1.0", historical_cases,
    baseline=active_bundle, sample_rate=1.0,
    max_changed_decisions=0,
)
manager.approve(
    "deployments", "1.1.0",
    approver_id="security-1", role="SecurityLead",
)
manager.approve(
    "deployments", "1.1.0",
    approver_id="release-1", role="ReleaseManager",
)
manager.deploy("deployments", "1.1.0", canary_report=canary)
```

`SimulationReport` contains redacted action/context fingerprints and the
candidate/baseline decision snapshots. It never copies raw tool parameters.
`PolicyLifecycleManager.record()` returns the owner, state, expiry, approvals,
simulation evidence, and canary evidence for operator/API responses.

## CLI

The reference CLI can execute an auditable initial rollout:

```bash
python -m governance policy-rollout policy.law \
  --policy-id deployments --policy-version 1.0.0 \
  --owner platform-governance \
  --approver security-1:SecurityLead \
  --approver release-1:ReleaseManager \
  --actor-id agent-1 --capability deploy.production \
  --params '{"environment":"production"}'
```

For a change, add `--baseline baseline.law --baseline-version 1.0.0`.
The command emits the simulation, canary report, lifecycle record, and
append-only lifecycle events as JSON.

## Expiry and rollback

Call `monitor()` from the operator scheduler. Expired active policies are
removed from the active set and produce a lifecycle event. `evaluate()` then
returns `Block` by default; `PolicyExpiryMode.ESCALATE` returns an `Escalate`
decision to the `policy-owner` role. Rollback requires an explicit reason and
the target version's configured production approval quorum.

This M27 manager is intentionally process-local. Durable lifecycle state,
pending approvals, idempotency records, and execution claims remain the scope
of GitHub issue #29 and must be integrated with the M25 repository before a
production-kernel gate.
