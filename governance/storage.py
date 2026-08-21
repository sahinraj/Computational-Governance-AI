"""Crash-safe persistence primitives for governance state and audit events."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Protocol

from .audit import AuditLog, DecisionEvent


STORE_VERSION = "1.0"


class StoreError(ValueError):
    """Raised when persisted state is missing, corrupt, or incompatible."""


class AtomicJsonStore:
    """Persist one versioned JSON document using same-directory replacement."""

    def __init__(self, path: str | Path, *, version: str = STORE_VERSION):
        self.path = Path(path)
        self.version = str(version)

    def save(self, payload: Any) -> None:
        envelope = {"store_version": self.version, "payload": payload}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(envelope, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            try:
                directory_fd = os.open(self.path.parent, os.O_RDONLY)
            except OSError:
                directory_fd = None
            if directory_fd is not None:
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except (OSError, TypeError, ValueError) as exc:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise StoreError(f"could not persist {self.path}: {exc}") from exc

    def load(self) -> Any:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise StoreError(f"could not read {self.path}: {exc}") from exc
        if not isinstance(value, dict):
            raise StoreError(f"invalid root document in {self.path}")
        if value.get("store_version") != self.version:
            raise StoreError(
                f"unsupported store version {value.get('store_version')!r}; expected {self.version!r}"
            )
        if "payload" not in value:
            raise StoreError(f"missing payload in {self.path}")
        return value["payload"]


class JsonlAuditStore:
    """Append and recover decision events as an fsynced JSONL stream."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append(self, event: DecisionEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(event.to_json() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except (OSError, UnicodeError, TypeError, ValueError) as exc:
            raise StoreError(f"could not append audit event to {self.path}: {exc}") from exc

    def load(self) -> AuditLog:
        if not self.path.exists():
            return AuditLog()
        try:
            return AuditLog.from_jsonl(self.path)
        except (OSError, UnicodeError, ValueError) as exc:
            raise StoreError(f"could not recover audit log {self.path}: {exc}") from exc


M25_SCHEMA_VERSION = "1.0"


class ConcurrencyError(StoreError):
    """Raised when a stale optimistic revision attempts to overwrite state."""


@dataclass(frozen=True)
class DurableRecord:
    """A versioned JSON record returned by the durable repository."""

    kind: str
    key: str
    revision: int
    payload: dict[str, Any]


@dataclass(frozen=True)
class StoredAuditEvent:
    """An audit event with its durable monotonic sequence."""

    sequence: int
    event: DecisionEvent
    created_at: float


@dataclass(frozen=True)
class DurableIdempotencyRecord:
    scope: str
    key: str
    request_hash: str
    status: str
    response_status: Optional[int] = None
    response: Optional[dict[str, Any]] = None


@dataclass(frozen=True)
class ExecutionClaim:
    scope: str
    key: str
    claim_id: str
    status: str
    outcome: Optional[dict[str, Any]] = None


class Repository(Protocol):
    """Minimal optimistic-concurrency repository contract."""

    def save_state(
        self,
        kind: str,
        key: str,
        payload: Mapping[str, Any],
        *,
        expected_revision: Optional[int] = None,
    ) -> DurableRecord:
        """Create or compare-and-swap one JSON state record."""

    def load_state(self, kind: str, key: str) -> DurableRecord:
        """Read one state record or raise StoreError."""


class SQLiteGovernanceStore:
    """Single-region transactional repository backed by SQLite.

    SQLite is used as the dependency-free reference backend and is suitable
    for a single-process or single-region pilot when placed on durable
    encrypted storage. The repository boundary keeps a PostgreSQL adapter
    possible without scattering SQL through governance decisions.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = 5000,
        failpoint: Optional[Callable[[str], None]] = None,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._failpoint = failpoint
        try:
            self._connection = sqlite3.connect(
                self.path,
                timeout=max(0.001, busy_timeout_ms / 1000),
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._migrate()
        except (OSError, sqlite3.Error, ValueError) as exc:
            raise StoreError(f"could not open durable store {self.path}: {exc}") from exc

    def _migrate(self) -> None:
        try:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_meta "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = self._connection.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                self._connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS state_records (
                        kind TEXT NOT NULL,
                        key TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        payload TEXT NOT NULL,
                        updated_at REAL NOT NULL,
                        PRIMARY KEY (kind, key)
                    );
                    CREATE TABLE IF NOT EXISTS audit_events (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        created_at REAL NOT NULL,
                        payload TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS idempotency_records (
                        scope TEXT NOT NULL,
                        key TEXT NOT NULL,
                        request_hash TEXT NOT NULL,
                        status TEXT NOT NULL,
                        response_status INTEGER,
                        response_json TEXT,
                        created_at REAL NOT NULL,
                        completed_at REAL,
                        PRIMARY KEY (scope, key)
                    );
                    CREATE TABLE IF NOT EXISTS execution_claims (
                        scope TEXT NOT NULL,
                        key TEXT NOT NULL,
                        claim_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        outcome_json TEXT,
                        created_at REAL NOT NULL,
                        completed_at REAL,
                        PRIMARY KEY (scope, key),
                        UNIQUE (claim_id)
                    );
                    INSERT INTO schema_meta(key, value)
                    VALUES ('schema_version', '1.0');
                    """
                )
            elif row["value"] != M25_SCHEMA_VERSION:
                raise StoreError(
                    f"unsupported durable schema {row['value']!r}; expected {M25_SCHEMA_VERSION!r}"
                )
        except sqlite3.Error as exc:
            raise StoreError(f"could not migrate durable store {self.path}: {exc}") from exc

    def _point(self, name: str) -> None:
        if self._failpoint is not None:
            self._failpoint(name)

    def _transaction(self, operation: Callable[[sqlite3.Connection], Any]) -> Any:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                result = operation(self._connection)
                self._point("before_commit")
                self._connection.execute("COMMIT")
                return result
            except StoreError:
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            except (sqlite3.Error, OSError, TypeError, ValueError) as exc:
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise StoreError(f"durable transaction failed: {exc}") from exc
            except Exception as exc:
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise StoreError(f"durable transaction failed: {exc}") from exc

    @staticmethod
    def _json_payload(payload: Mapping[str, Any]) -> str:
        if not isinstance(payload, Mapping):
            raise StoreError("durable payload must be an object")
        try:
            return json.dumps(payload, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise StoreError(f"durable payload is not JSON-compatible: {exc}") from exc

    def save_state(
        self,
        kind: str,
        key: str,
        payload: Mapping[str, Any],
        *,
        expected_revision: Optional[int] = None,
    ) -> DurableRecord:
        if not isinstance(kind, str) or not kind or not isinstance(key, str) or not key:
            raise StoreError("durable state kind and key must be non-empty strings")
        if expected_revision is not None and (
            not isinstance(expected_revision, int) or isinstance(expected_revision, bool)
            or expected_revision < 1
        ):
            raise StoreError("expected durable revision must be a positive integer")
        encoded = self._json_payload(payload)

        def operation(connection: sqlite3.Connection) -> DurableRecord:
            row = connection.execute(
                "SELECT revision FROM state_records WHERE kind=? AND key=?",
                (kind, key),
            ).fetchone()
            current = None if row is None else int(row["revision"])
            if expected_revision is None:
                if current is not None:
                    raise ConcurrencyError(f"durable state {kind}/{key} already exists")
                revision = 1
                connection.execute(
                    "INSERT INTO state_records(kind,key,revision,payload,updated_at) "
                    "VALUES (?,?,?,?,strftime('%s','now'))",
                    (kind, key, revision, encoded),
                )
            else:
                if current != expected_revision:
                    raise ConcurrencyError(
                        f"stale durable state {kind}/{key}: expected revision "
                        f"{expected_revision}, current {current}"
                    )
                revision = expected_revision + 1
                changed = connection.execute(
                    "UPDATE state_records SET revision=?, payload=?, "
                    "updated_at=strftime('%s','now') WHERE kind=? AND key=? AND revision=?",
                    (revision, encoded, kind, key, expected_revision),
                ).rowcount
                if changed != 1:
                    raise ConcurrencyError(f"stale durable state {kind}/{key}")
            return DurableRecord(kind, key, revision, dict(payload))

        return self._transaction(operation)

    def load_state(self, kind: str, key: str) -> DurableRecord:
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT revision,payload FROM state_records WHERE kind=? AND key=?",
                    (kind, key),
                ).fetchone()
            except sqlite3.Error as exc:
                raise StoreError(f"could not load durable state {kind}/{key}: {exc}") from exc
        if row is None:
            raise StoreError(f"unknown durable state {kind}/{key}")
        try:
            payload = json.loads(row["payload"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise StoreError(f"corrupt durable state {kind}/{key}") from exc
        if not isinstance(payload, dict):
            raise StoreError(f"durable state {kind}/{key} is not an object")
        return DurableRecord(kind, key, int(row["revision"]), payload)

    def save_policy(
        self,
        policy_id: str,
        policy_version: str,
        bundle: Mapping[str, Any],
        *,
        expected_revision: Optional[int] = None,
    ) -> DurableRecord:
        return self.save_state(
            "policy",
            policy_id,
            {"policy_version": policy_version, "bundle": dict(bundle)},
            expected_revision=expected_revision,
        )

    def load_policy(self, policy_id: str) -> DurableRecord:
        return self.load_state("policy", policy_id)

    def save_grants(
        self,
        scope: str,
        snapshot: Mapping[str, Any],
        *,
        expected_revision: Optional[int] = None,
    ) -> DurableRecord:
        return self.save_state("grants", scope, snapshot, expected_revision=expected_revision)

    def load_grants(self, scope: str) -> DurableRecord:
        return self.load_state("grants", scope)

    def save_approvals(
        self,
        scope: str,
        snapshot: Mapping[str, Any],
        *,
        expected_revision: Optional[int] = None,
    ) -> DurableRecord:
        return self.save_state("approvals", scope, snapshot, expected_revision=expected_revision)

    def load_approvals(self, scope: str) -> DurableRecord:
        return self.load_state("approvals", scope)

    def append_audit(self, event: DecisionEvent, *, created_at: float) -> StoredAuditEvent:
        if not isinstance(event, DecisionEvent):
            raise StoreError("durable audit append requires a DecisionEvent")
        try:
            timestamp = float(created_at)
        except (TypeError, ValueError) as exc:
            raise StoreError("audit created_at must be numeric") from exc

        def operation(connection: sqlite3.Connection) -> StoredAuditEvent:
            existing = connection.execute(
                "SELECT sequence,created_at,payload FROM audit_events WHERE event_id=?",
                (event.event_id,),
            ).fetchone()
            if existing is not None:
                encoded = event.to_json()
                if existing["payload"] != encoded:
                    raise StoreError(f"duplicate audit event conflict {event.event_id}")
                return StoredAuditEvent(
                    int(existing["sequence"]), event, float(existing["created_at"])
                )
            try:
                cursor = connection.execute(
                    "INSERT INTO audit_events(event_id,created_at,payload) VALUES (?,?,?)",
                    (event.event_id, timestamp, event.to_json()),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreError(f"duplicate audit event {event.event_id}") from exc
            return StoredAuditEvent(int(cursor.lastrowid), event, timestamp)

        return self._transaction(operation)

    def latest_audit_sequence(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) AS latest FROM audit_events"
            ).fetchone()
        return int(row["latest"])

    def load_audit(
        self,
        *,
        after_sequence: int = 0,
        limit: int = 1000,
    ) -> tuple[StoredAuditEvent, ...]:
        if after_sequence < 0 or limit < 1:
            raise StoreError("audit sequence and limit must be non-negative and positive")
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT sequence,created_at,payload FROM audit_events "
                    "WHERE sequence>? ORDER BY sequence ASC LIMIT ?",
                    (after_sequence, limit),
                ).fetchall()
            except sqlite3.Error as exc:
                raise StoreError(f"could not load durable audit events: {exc}") from exc
        events = []
        for row in rows:
            try:
                event = DecisionEvent.from_dict(json.loads(row["payload"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise StoreError("corrupt durable audit event") from exc
            events.append(StoredAuditEvent(int(row["sequence"]), event, float(row["created_at"])))
        return tuple(events)

    def purge_audit(self, *, before: float) -> int:
        try:
            cutoff = float(before)
        except (TypeError, ValueError) as exc:
            raise StoreError("audit retention cutoff must be numeric") from exc

        def operation(connection: sqlite3.Connection) -> int:
            return int(
                connection.execute(
                    "DELETE FROM audit_events WHERE created_at < ?", (cutoff,)
                ).rowcount
            )

        return self._transaction(operation)

    def begin_idempotency(
        self,
        scope: str,
        key: str,
        request_hash: str,
    ) -> DurableIdempotencyRecord:
        """Reserve a request key or return its committed result."""
        if not all(isinstance(value, str) and value for value in (scope, key, request_hash)):
            raise StoreError("idempotency scope, key, and request hash are required")

        def operation(connection: sqlite3.Connection) -> DurableIdempotencyRecord:
            row = connection.execute(
                "SELECT request_hash,status,response_status,response_json "
                "FROM idempotency_records WHERE scope=? AND key=?",
                (scope, key),
            ).fetchone()
            if row is not None:
                if row["request_hash"] != request_hash:
                    raise ConcurrencyError(f"idempotency key conflict {scope}/{key}")
                response = None if row["response_json"] is None else json.loads(row["response_json"])
                return DurableIdempotencyRecord(
                    scope, key, request_hash, row["status"], row["response_status"], response
                )
            connection.execute(
                "INSERT INTO idempotency_records "
                "(scope,key,request_hash,status,created_at) VALUES (?,?,?,?,strftime('%s','now'))",
                (scope, key, request_hash, "in_progress"),
            )
            return DurableIdempotencyRecord(scope, key, request_hash, "in_progress")

        return self._transaction(operation)

    def complete_idempotency(
        self,
        scope: str,
        key: str,
        request_hash: str,
        *,
        response_status: int,
        response: Mapping[str, Any],
    ) -> DurableIdempotencyRecord:
        encoded = self._json_payload(response)

        def operation(connection: sqlite3.Connection) -> DurableIdempotencyRecord:
            row = connection.execute(
                "SELECT request_hash,status FROM idempotency_records WHERE scope=? AND key=?",
                (scope, key),
            ).fetchone()
            if row is None:
                raise StoreError(f"unknown idempotency key {scope}/{key}")
            if row["request_hash"] != request_hash:
                raise ConcurrencyError(f"idempotency key conflict {scope}/{key}")
            connection.execute(
                "UPDATE idempotency_records SET status='complete',response_status=?, "
                "response_json=?,completed_at=strftime('%s','now') WHERE scope=? AND key=?",
                (int(response_status), encoded, scope, key),
            )
            return DurableIdempotencyRecord(
                scope, key, request_hash, "complete", int(response_status), dict(response)
            )

        return self._transaction(operation)

    def load_idempotency(self, scope: str, key: str) -> DurableIdempotencyRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT request_hash,status,response_status,response_json "
                "FROM idempotency_records WHERE scope=? AND key=?",
                (scope, key),
            ).fetchone()
        if row is None:
            raise StoreError(f"unknown idempotency key {scope}/{key}")
        response = None if row["response_json"] is None else json.loads(row["response_json"])
        return DurableIdempotencyRecord(
            scope, key, row["request_hash"], row["status"], row["response_status"], response
        )

    def claim_execution(self, scope: str, key: str, claim_id: str) -> ExecutionClaim:
        if not all(isinstance(value, str) and value for value in (scope, key, claim_id)):
            raise StoreError("execution scope, key, and claim id are required")

        def operation(connection: sqlite3.Connection) -> ExecutionClaim:
            row = connection.execute(
                "SELECT claim_id,status,outcome_json FROM execution_claims WHERE scope=? AND key=?",
                (scope, key),
            ).fetchone()
            if row is not None:
                if row["claim_id"] != claim_id:
                    raise ConcurrencyError(f"execution claim already exists {scope}/{key}")
                outcome = None if row["outcome_json"] is None else json.loads(row["outcome_json"])
                return ExecutionClaim(scope, key, claim_id, row["status"], outcome)
            connection.execute(
                "INSERT INTO execution_claims(scope,key,claim_id,status,created_at) "
                "VALUES (?,?,?,?,strftime('%s','now'))",
                (scope, key, claim_id, "claimed"),
            )
            return ExecutionClaim(scope, key, claim_id, "claimed")

        return self._transaction(operation)

    def complete_execution(
        self,
        scope: str,
        key: str,
        claim_id: str,
        *,
        status: str,
        outcome: Optional[Mapping[str, Any]] = None,
    ) -> ExecutionClaim:
        if status not in {"succeeded", "failed", "unknown"}:
            raise StoreError("execution status must be succeeded, failed, or unknown")
        encoded = None if outcome is None else self._json_payload(outcome)

        def operation(connection: sqlite3.Connection) -> ExecutionClaim:
            row = connection.execute(
                "SELECT claim_id,status FROM execution_claims WHERE scope=? AND key=?",
                (scope, key),
            ).fetchone()
            if row is None or row["claim_id"] != claim_id:
                raise ConcurrencyError(f"unknown or stale execution claim {scope}/{key}")
            connection.execute(
                "UPDATE execution_claims SET status=?,outcome_json=?,completed_at="
                "strftime('%s','now') WHERE scope=? AND key=? AND claim_id=?",
                (status, encoded, scope, key, claim_id),
            )
            return ExecutionClaim(
                scope, key, claim_id, status,
                None if outcome is None else dict(outcome),
            )

        return self._transaction(operation)

    def backup(self, destination: str | Path) -> None:
        """Create a consistent SQLite backup; encryption belongs to the host."""
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.tmp")
        try:
            with self._lock:
                target = sqlite3.connect(temporary)
                try:
                    self._connection.backup(target)
                finally:
                    target.close()
            os.replace(temporary, destination)
        except (OSError, sqlite3.Error) as exc:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise StoreError(f"could not create durable backup {destination}: {exc}") from exc

    @classmethod
    def restore(cls, backup: str | Path, destination: str | Path) -> "SQLiteGovernanceStore":
        """Restore a validated backup into a new store path."""
        backup = Path(backup)
        destination = Path(destination)
        if not backup.exists():
            raise StoreError(f"backup does not exist: {backup}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.tmp")
        try:
            source = sqlite3.connect(backup)
            target = sqlite3.connect(temporary)
            try:
                source.backup(target)
            finally:
                target.close()
                source.close()
            os.replace(temporary, destination)
        except (OSError, sqlite3.Error) as exc:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise StoreError(f"could not restore durable backup {backup}: {exc}") from exc
        return cls(destination)

    def close(self) -> None:
        with self._lock:
            try:
                self._connection.close()
            except sqlite3.Error as exc:
                raise StoreError(f"could not close durable store {self.path}: {exc}") from exc

    def __enter__(self) -> "SQLiteGovernanceStore":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
