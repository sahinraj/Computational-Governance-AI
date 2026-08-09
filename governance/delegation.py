"""M7: bounded, expiring, revocable delegation graph."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .model import Actor, Capability


class DelegationError(ValueError):
    """Raised when a grant would violate the delegation algebra."""


def _actor_id(actor: Actor | str) -> str:
    return actor.id if isinstance(actor, Actor) else actor


def _capability(value: Capability | str) -> Capability:
    return value if isinstance(value, Capability) else Capability(value)


@dataclass(frozen=True)
class Grant:
    id: str
    from_actor: str
    to_actor: str
    capability: Capability
    depth: int
    expires_at: Optional[float] = None
    parent_grant_id: Optional[str] = None
    granting_rule_id: Optional[str] = None


@dataclass(frozen=True)
class AuthorityProof:
    """Deterministic evidence for one actor/capability authority check."""

    allowed: bool
    source: str
    path: tuple[str, ...] = ()
    reason: str = ""


class DelegationGraph:
    """A graph whose validity is recomputed on every authority check."""

    def __init__(self, intrinsic: Optional[dict[str, Iterable[str]]] = None):
        self._intrinsic: dict[str, set[str]] = {
            actor: set(capabilities) for actor, capabilities in (intrinsic or {}).items()
        }
        self._grants: dict[str, Grant] = {}
        self._revoked: set[str] = set()
        self._next_id = 1

    def register_intrinsic(self, actor: Actor | str, capability: Capability | str) -> None:
        self._intrinsic.setdefault(_actor_id(actor), set()).add(_capability(capability).name)

    def _intrinsic_has(self, actor: str, capability: Capability) -> bool:
        return any(
            capability.is_descendant_of(_capability(granted))
            for granted in self._intrinsic.get(actor, ())
        )

    def _valid_grant(self, grant: Grant, now: float) -> bool:
        if grant.id in self._revoked:
            return False
        if grant.expires_at is not None and now >= grant.expires_at:
            return False
        if grant.parent_grant_id is None:
            return self._intrinsic_has(grant.from_actor, grant.capability)
        parent = self._grants.get(grant.parent_grant_id)
        return parent is not None and self._valid_grant(parent, now)

    def _source_grant(self, grantor: str, capability: Capability, now: float) -> Optional[Grant]:
        candidates = [
            grant for grant in self._grants.values()
            if grant.to_actor == grantor
            and grant.depth > 0
            and capability.is_descendant_of(grant.capability)
            and self._valid_grant(grant, now)
        ]
        return min(candidates, key=lambda grant: grant.id) if candidates else None

    def _grant_path(self, grant: Grant) -> tuple[str, ...]:
        """Return a root-to-leaf grant path for a validated grant."""
        path: list[str] = []
        current: Optional[Grant] = grant
        seen: set[str] = set()
        while current is not None:
            if current.id in seen:
                # This should be impossible through grant(), but keeping the
                # proof routine defensive prevents malformed state from
                # becoming an infinite loop.
                return ()
            seen.add(current.id)
            path.append(current.id)
            current = (
                self._grants.get(current.parent_grant_id)
                if current.parent_grant_id is not None
                else None
            )
        return tuple(reversed(path))

    def _actor_reachable(self, start: str, target: str, now: float) -> bool:
        """Return whether an active delegation path reaches ``target``."""
        pending = [start]
        visited: set[str] = set()
        while pending:
            current = pending.pop()
            if current == target:
                return True
            if current in visited:
                continue
            visited.add(current)
            pending.extend(
                grant.to_actor
                for grant in self._grants.values()
                if grant.from_actor == current and self._valid_grant(grant, now)
            )
        return False

    def grant(
        self,
        grantor: Actor | str,
        grantee: Actor | str,
        capability: Capability | str,
        *,
        scope: Capability | str | None = None,
        depth: int = 0,
        expires_at: Optional[float] = None,
        now: float = 0.0,
        granting_rule_id: Optional[str] = None,
    ) -> Grant:
        if depth < 0:
            raise DelegationError("grant depth cannot be negative")
        requested = _capability(capability)
        source = _capability(scope or capability)
        if not source.name:
            raise DelegationError("capability scope cannot be empty")
        if not source.is_descendant_of(requested):
            raise DelegationError(
                f"grant scope {source.name} widens requested capability {requested.name}"
            )
        grantor_id = _actor_id(grantor)
        if isinstance(grantor, Actor):
            self._intrinsic.setdefault(grantor_id, set()).update(grantor.capabilities)
        grantee_id = _actor_id(grantee)
        if self._actor_reachable(grantee_id, grantor_id, now):
            raise DelegationError(
                f"delegation cycle rejected: {grantor_id} -> {grantee_id}"
            )
        parent_id = None
        if not self._intrinsic_has(grantor_id, source):
            parent = self._source_grant(grantor_id, source, now)
            if parent is None:
                raise DelegationError(
                    f"{grantor_id} does not hold valid authority for {source.name}"
                )
            if depth > parent.depth - 1:
                raise DelegationError(
                    f"grant depth {depth} exceeds remaining depth {parent.depth - 1}"
                )
            parent_id = parent.id
        if expires_at is not None and expires_at <= now:
            raise DelegationError("grant expiry must be in the future")
        grant_id = f"G-{self._next_id:04d}"
        self._next_id += 1
        grant = Grant(
            id=grant_id,
            from_actor=grantor_id,
            to_actor=grantee_id,
            capability=source,
            depth=depth,
            expires_at=expires_at,
            parent_grant_id=parent_id,
            granting_rule_id=granting_rule_id,
        )
        self._grants[grant_id] = grant
        return grant

    def revoke(self, grant: Grant | str) -> None:
        grant_id = grant.id if isinstance(grant, Grant) else grant
        if grant_id not in self._grants:
            raise DelegationError(f"unknown grant {grant_id}")
        self._revoked.add(grant_id)

    def expire(self, now: float) -> tuple[str, ...]:
        """Return currently expired grants; expiry is intentionally derived."""
        return tuple(sorted(
            grant.id for grant in self._grants.values()
            if grant.expires_at is not None and now >= grant.expires_at
        ))

    def has_authority(
        self, actor: Actor | str, capability: Capability | str, now: float = 0.0
    ) -> bool:
        return self.authority_proof(actor, capability, now).allowed

    def authority_proof(
        self, actor: Actor | str, capability: Capability | str, now: float = 0.0
    ) -> AuthorityProof:
        """Return deterministic provenance for intrinsic or delegated authority."""
        actor_id = _actor_id(actor)
        requested = _capability(capability)
        intrinsic = (
            isinstance(actor, Actor)
            and any(requested.is_descendant_of(_capability(cap)) for cap in actor.capabilities)
        ) or self._intrinsic_has(actor_id, requested)
        if intrinsic:
            return AuthorityProof(
                allowed=True,
                source="intrinsic",
                path=(f"actor:{actor_id}",),
                reason="intrinsic capability is valid",
            )

        candidates = [
            grant for grant in self._grants.values()
            if grant.to_actor == actor_id
            and requested.is_descendant_of(grant.capability)
            and self._valid_grant(grant, now)
        ]
        proofs = [(self._grant_path(grant), grant) for grant in candidates]
        proofs = [(path, grant) for path, grant in proofs if path]
        if proofs:
            path, _ = min(proofs, key=lambda item: (len(item[0]), item[0]))
            return AuthorityProof(
                allowed=True,
                source="delegated",
                path=path,
                reason="active delegated capability is valid",
            )
        return AuthorityProof(
            allowed=False,
            source="none",
            reason="no intrinsic or active delegated capability",
        )

    def grants(self) -> tuple[Grant, ...]:
        return tuple(sorted(self._grants.values(), key=lambda grant: grant.id))
