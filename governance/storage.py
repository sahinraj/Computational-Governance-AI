"""Crash-safe persistence primitives for governance state and audit events."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

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
