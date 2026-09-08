# M30 Threat Model and Red-Team Evidence

M30 defines the first explicit attack matrix for the governance trust
boundary and runs a deterministic, dependency-free red-team suite against the
reference implementation.

## Scope

The protected assets are:

- the decision that precedes tool execution
- authenticated actor and approver identity
- policy version and semantic content
- approval and execution state
- durable audit and recovery evidence

The untrusted boundary includes caller-supplied actor claims, credentials,
policy bundles, approval requests, serialized transport envelopes, and retry
traffic. The trusted boundary begins only after identity verification, trusted
actor lookup, policy validation, and exact-state binding succeed.

## Attack matrix

| Case | Threat | Control | Expected result |
|---|---|---|---|
| M30-REPLAY | Duplicate request or execution replay | Idempotency reservation and completed-request cache | Same response, one execution |
| M30-IDENTITY | Credential subject substitution | Verified credential subject must match the actor | 401 and no execution |
| M30-DOWNGRADE | Unapproved policy rollback or bundle tampering | Monotonic activation and semantic content hash | Rejected before activation |
| M30-STALE-APPROVAL | Approved evidence reused with changed policy | Approval binds policy, action, context, and state fingerprints | Resume rejected |
| M30-COLLUSION | One identity satisfies multiple quorum roles | Secure quorum requires distinct verified identity references | Second vote rejected |
| M30-CONFUSED-DEPUTY | Caller escalates authority or capability claims | Trusted actor registry replaces caller assertions | Policy evaluates trusted actor; execution blocked |
| M30-RECOVERY | Restart after uncertain external operation | Durable execution claim becomes explicit `unknown` | No unsafe retry; reconciliation required |

Run the suite with:

```bash
python -m evaluation.m30_red_team --check \
  --output reports/m30-red-team.json
```

The report is intentionally deterministic and contains case-level evidence,
pass/fail state, and a compact failure taxonomy. CI runs the same bounded
profile.

## Results and limits

The current M30 profile contains seven attack cases and requires every case to
pass. It is evidence of the listed controls, not exhaustive fuzzing, formal
verification, or an independent security review. The identity provider is a
test adapter, the durable backend is a single-region SQLite reference store,
and arbitrary external side effects still require operator reconciliation.

M30 does not add vendor integrations, hosted infrastructure, custom
cryptography, or a general autonomous-agent framework.
