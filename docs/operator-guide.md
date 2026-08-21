# Operator Guide

This guide describes the supported reference deployment boundary after M25.

## Deployment modes

| Mode | Use | Durability |
| --- | --- | --- |
| In-memory service | Unit tests and local experiments | Process lifetime only |
| JSON/JSONL adapters | Compatibility, CLI, and recovery fixtures | File-level atomicity/fsync; no concurrent service coordination |
| SQLiteGovernanceStore | Single-region reference or pilot preparation | Transactional state, revisions, audit sequence, backup/restore |

Active-active, multi-region failover, hosted control-plane operation, and
general high-availability claims are outside this project. The service must
fail closed when its configured durable backend is unavailable or its schema is
unknown.

## Installation and startup

1. Use Python 3.10–3.12 and install the project plus development requirements.
2. Place the SQLite database on a durable, access-controlled, encrypted volume.
3. Run schema initialization through `SQLiteGovernanceStore(path)` before
   accepting traffic; schema version `1.0` is validated at startup.
4. Configure a real provider-backed identity verifier. The signed test
   provider is for fixtures only.
5. Register only explicit capability handlers. Missing handlers fail closed.
6. Start the M24 HTTP service in enforce mode and verify a readiness check that
   opens the database and reads its schema version.

Database credentials, remote TLS settings, and encryption keys belong in a
secret manager or deployment environment. They must not be committed.

## Backup, retention, and incidents

Use `SQLiteGovernanceStore.backup()` so the online backup API captures a
consistent database, including WAL state. Protect backup files with the same
access controls and encryption policy as the live database. Restore into a new
clean path, validate schema and audit sequence continuity, verify policy hashes
and approval relationships, and run the recovery suite before switching
traffic.

Retention must be explicit and auditable. Do not delete active policy state,
pending approvals, or unresolved execution claims. On database outage, schema
mismatch, corrupt backup, identity compromise, or policy/audit mismatch, keep
the service fail-closed, preserve the database and logs, and reconcile any
external operation whose outcome is unknown.

Record measured recovery time and data-loss observations for the actual
environment; this project does not promise fixed RTO or RPO values.

## Pre-deployment checklist

- [ ] Enforce mode and a production identity provider are configured.
- [ ] Database volume and backups use established encryption tools.
- [ ] Database access is least-privilege and TLS-protected when remote.
- [ ] Backup and restore have been rehearsed in the deployment environment.
- [ ] Retention and audit-archive policy is approved.
- [ ] Recovery and external-operation reconciliation procedures are documented.
- [ ] No test credentials or unmanaged database credentials are deployed.
