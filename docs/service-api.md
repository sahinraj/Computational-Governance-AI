# M24 Service API

M24 exposes the governance engine through a small versioned HTTP/JSON boundary
and a transport-independent Python client. The reference implementation uses
only the Python standard library and is intended for local or single-process
deployments. Durable state and crash recovery are M25 work.

## Design boundary

The service runs the existing engine in `enforce` mode. It owns request
idempotency and approval continuation; policy semantics remain in the core
library. HTTP is the reference transport because it is broadly interoperable
and keeps the runtime dependency-free. The SDK uses a transport protocol, so a
different transport can be added without changing request schemas.

The service clock is authoritative. Client-provided timestamps are not accepted
in decision requests. A transport timeout does not cancel a running operation;
retry with the same idempotency key. The process-local service serializes
requests while an operation is running, so a retry receives the original
outcome instead of executing the operation again. Crash durability is deferred
to M25.

## Request schema

`POST /v1/decisions` accepts:

```json
{
  "actor": {
    "id": "agent-1",
    "authority_level": 5,
    "class": "agent",
    "capabilities": []
  },
  "capability": "payment.send",
  "params": {"amount": 10},
  "credential": {"provider-specific": "credential"},
  "idempotency_key": "payment-2026-0001",
  "budget_used": 0,
  "prior_approvals": []
}
```

Credentials are passed to the configured `IdentityVerifier` and are never
returned in service responses or audit records. When identity verification is
configured, missing, expired, mismatched, or forged credentials fail closed.

## Endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/v1/decisions` | Evaluate and, only for `Allow`, invoke the registered handler. |
| `GET` | `/v1/approvals/{approval_id}` | Read the current approval state after client reconnect. |
| `POST` | `/v1/approvals/{approval_id}/vote` | Submit an authenticated `approve` or `deny` vote. |
| `POST` | `/v1/approvals/{approval_id}/resume` | Re-authenticate and consume an approved request exactly once. |

Decision responses contain `schema_version`, `request_id`, a structured
`decision`, `executed`, and (when applicable) `approval_request_id` and `value`.
Approval responses contain the JSON-safe approval snapshot, including identity
references for votes and denials.

Vote requests require `decision`, `role`, `actor_id`, `credential`, and a new
`idempotency_key`. Resume requests require `actor_id`, `credential`, and a new
`idempotency_key`. Resume identity must hold one of the configured approval
roles.

## Stable error codes

| Code | Meaning |
| --- | --- |
| `invalid_request` | Malformed JSON or schema violation. |
| `authentication_failed` | Credential is missing, invalid, expired, or unauthorized. |
| `idempotency_key_conflict` | A key was reused for a different request. |
| `handler_not_found` | No local operation is registered for the capability. |
| `approval_not_found` | Approval state is unavailable or not resumable. |
| `approval_conflict` | Vote, expiry, binding, or replay rule rejected the operation. |
| `operation_failed` | The governed operation failed; retry with the same key only. |
| `internal_error` | The service failed closed before execution. |

## Python SDK

```python
from governance import (
    Actor,
    DecisionRequest,
    GovernanceClient,
    InProcessTransport,
)

client = GovernanceClient(InProcessTransport(service))
response = client.decide(DecisionRequest(
    actor=Actor("agent-1", 5),
    capability="payment.send",
    params={"amount": 10},
    credential=credential,
    idempotency_key="payment-2026-0001",
))
```

Use `HTTPTransport("http://127.0.0.1:8000")` for the local HTTP runner started
with `governance.serve_http(service)`. SDK
retries are deliberately caller-controlled: reuse the same key when the result
is uncertain and never generate a new key for a retry of the same side effect.

## Production boundary

This milestone is a narrow service contract, not a hosted control plane. The
reference service keeps approvals and idempotency in memory, does not provide
multi-process coordination, and does not replace TLS termination, credential
issuance, or operational authentication. M25 owns transactional persistence,
backup/restore, concurrent-update handling, and crash recovery.
