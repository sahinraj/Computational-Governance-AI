# M26 Decision Observability

M26 adds dependency-free structured telemetry at the M24 service boundary.
Applications can keep the built-in in-memory collector for tests and local
inspection or attach `JsonlTelemetrySink` as a simple collector fixture. An
OpenTelemetry adapter can implement the `TelemetrySink` protocol without
changing governance enforcement.

## Event contract

Every service decision carries:

- `correlation_id`: stable request-flow identifier;
- `decision_id`: stable identifier derived from the normalized request;
- `policy_fingerprint` and optional `policy_version`;
- verified actor identity reference when authentication succeeds;
- approval reference when an approval lifecycle is involved;
- outcome, latency, and stable failure reason;
- redacted structured attributes.

The schema version is `1.0`. Stable event names are:

| Event | Meaning |
| --- | --- |
| `governance.decision.evaluated` | A request reached a governance decision. |
| `governance.decision.replayed` | A cached idempotent response was served. |
| `governance.execution.completed` | The operation was executed or explicitly not executed. |
| `governance.approval.requested` | A decision created a pending approval. |
| `governance.approval.voted` | An authenticated approval vote was recorded. |
| `governance.approval.resumed` | An approved request was resumed. |
| `governance.approval.expired` | A pending or approved request crossed its deadline. |
| `governance.recovery.failure` | An operator recorded a recovery failure. |

## Redaction boundary

Tool parameters are represented by a SHA-256 fingerprint in service telemetry;
raw parameter values are never passed to the collector. Credentials, tokens,
passwords, secrets, authorization values, and private keys are replaced with
`[REDACTED]`. Additional sensitive keys can be configured with
`RedactionPolicy`.

Telemetry exporter failures are counted in `export_failures` and do not change
the service decision or weaken fail-closed enforcement.

## Local collector example

```python
from governance import GovernanceService, JsonlTelemetrySink, TelemetryCollector

telemetry = TelemetryCollector(
    sinks=[JsonlTelemetrySink("var/governance-telemetry.jsonl")],
)
service = GovernanceService(
    runtime,
    actor_registry=trusted_actors,
    handlers=handlers,
    telemetry=telemetry,
    policy_version="1.0.0",
)
```

Query local output with standard tools:

```bash
jq 'select(.event_name == "governance.decision.evaluated")' \
  var/governance-telemetry.jsonl
jq -s 'group_by(.outcome) | map({outcome: .[0].outcome, count: length})' \
  var/governance-telemetry.jsonl
```

This is a local reference exporter, not a hosted dashboard, collector cluster,
or production OpenTelemetry deployment.
