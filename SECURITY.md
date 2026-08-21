# Security policy

This repository is a research reference implementation, not a hosted security
service. The enforce-mode path is designed to fail closed, but integrations
remain responsible for authenticating actors, protecting policy sources,
securing approval channels, and retaining audit output.

## Reporting a vulnerability

Please do not disclose an exploitable governance bypass in a public issue.
Use GitHub's private vulnerability reporting for this repository when
available. Include the affected commit, a minimal reproduction, expected versus
actual decision, and whether the operation executed.

## Security invariants

- Governance is evaluated before the supplied operation is invoked.
- Enforce-mode errors block and emit an audit event.
- Delegated authority is scoped, expiring, revocable, and provenance-aware.
- Approval requests are bound to the action and current policy/state and are
  single-use.
- Audit events fingerprint policy, state, action, and context without storing
  raw action parameters.

The in-memory approval manager and delegation graph remain the default API
mode. Phase 3 also provides local versioned snapshots and append-only audit
recovery, but those files are not encrypted or replicated; production
integrations must add access control, key management, remote retention, and
identity/signature verification where required.

M25's SQLite backend is a single-region reference adapter. Use encrypted
volumes, managed backups, least-privilege access, and TLS for remote database
connections; the repository does not implement custom encryption or key
management. Durable storage failures and schema mismatches must fail closed.
