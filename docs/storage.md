# M25 Durable Storage

M25 adds `SQLiteGovernanceStore`, a dependency-free transactional repository
for the single-region reference deployment. It preserves the existing
`AtomicJsonStore` and `JsonlAuditStore` adapters for compatibility and tests;
those file adapters are not concurrent production backends.

## Guarantees and boundaries

The SQLite backend provides:

- transactional JSON state records for policy, delegation, and approval state;
- optimistic revision checks that reject stale writes;
- WAL mode, full synchronous commits, foreign-key enforcement, and bounded
  busy waits;
- durable idempotency records and execution claims;
- globally monotonic database audit sequences;
- duplicate-event protection and deterministic conflict errors;
- online backup/restore through SQLite's backup API;
- configurable audit retention;
- deterministic pre-commit failpoints for recovery tests.

The backend is a single-region reference adapter. It is not a multi-region,
active-active, or highly available deployment. A pilot must use encrypted
storage, managed backups, least-privilege database access, and TLS where the
database is remote. This project does not implement custom encryption, key
management, or database credentials.

The M24 service remains process-local until a later integration increment wires
its pending-operation and idempotency paths to these repositories. M25 makes
the transactional storage contract and recovery behavior available without
changing existing library APIs.

## Recovery and retention

Restore backups into a new clean path, validate schema and audit sequence
continuity, verify policy hashes and approval relationships, and run the
recovery suite before accepting traffic. A pre-commit failure leaves the
previous committed revision intact. A crash after an external operation has
started remains an explicit execution outcome that requires reconciliation; a
database cannot make an arbitrary external side effect exactly once.

`purge_audit(before=...)` deletes only audit rows older than the supplied
cutoff. Retention policy, backup frequency, and recovery objectives must be
chosen and measured for the actual deployment environment. No fixed RTO/RPO or
automatic encrypted-backup claim is made by this reference implementation.
