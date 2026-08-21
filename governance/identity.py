"""Provider-neutral authenticated workload and actor identity primitives.

The public boundary is intentionally small enough to adapt to SPIFFE/SPIRE or
another attested workload-identity system.  ``SignedTestIdentityProvider`` is
only a deterministic reference provider for fixtures and local tests; it is
not a production certificate authority or identity service.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol


class IdentityError(ValueError):
    """Raised when an identity cannot be authenticated or bound safely."""


_PROVIDER_VERIFIED_TOKEN = object()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _finite_number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise IdentityError(f"identity {field} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise IdentityError(f"identity {field} must be a finite number")
    return result


@dataclass(frozen=True)
class VerifiedIdentity:
    """Authenticated, provider-neutral identity claims.

    ``identity_reference`` deliberately excludes the credential signature and
    credential reference.  A rotated credential with the same subject, trust
    domain, issuer, and mapped roles therefore remains the same auditable
    principal while historical records remain immutable.
    """

    trust_domain: str
    subject: str
    roles: tuple[str, ...]
    expires_at: float
    issuer: str
    credential_reference: str
    issued_at: float = 0.0
    _verification_token: object = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    @classmethod
    def _from_provider(cls, **claims: Any) -> "VerifiedIdentity":
        """Create an identity artifact that passed the verifier boundary.

        The marker is intentionally not serializable or constructor-settable.
        Rehydrated audit data and caller-constructed claim objects therefore
        cannot be submitted as authenticated approval authority.
        """
        identity = cls(**claims)
        object.__setattr__(identity, "_verification_token", _PROVIDER_VERIFIED_TOKEN)
        return identity

    @property
    def is_provider_verified(self) -> bool:
        """Whether this object was produced by the in-process verifier path."""
        return self._verification_token is _PROVIDER_VERIFIED_TOKEN

    @classmethod
    def _is_verified_artifact(cls, value: Any) -> bool:
        """Check provenance without dispatching through a caller override."""
        return (
            type(value) is cls
            and object.__getattribute__(value, "_verification_token")
            is _PROVIDER_VERIFIED_TOKEN
        )

    def __post_init__(self) -> None:
        for field_name in (
            "trust_domain",
            "subject",
            "issuer",
            "credential_reference",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise IdentityError(f"identity {field_name} must be a non-empty string")
        if not isinstance(self.roles, tuple):
            object.__setattr__(self, "roles", tuple(self.roles))
        if any(not isinstance(role, str) or not role for role in self.roles):
            raise IdentityError("identity roles must be non-empty strings")
        if len(set(self.roles)) != len(self.roles):
            raise IdentityError("identity roles must be distinct")
        object.__setattr__(self, "roles", tuple(sorted(self.roles)))
        issued_at = _finite_number(self.issued_at, "issued_at")
        expires_at = _finite_number(self.expires_at, "expires_at")
        if expires_at <= issued_at:
            raise IdentityError("identity expiry must be after issuance")
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)

    @property
    def identity_reference(self) -> str:
        """Stable non-secret reference for audit, delegation, and approvals."""
        claims = {
            "trust_domain": self.trust_domain,
            "subject": self.subject,
            "issuer": self.issuer,
            "roles": list(self.roles),
        }
        return hashlib.sha256(_canonical(claims)).hexdigest()

    def is_valid_at(self, now: float) -> bool:
        current = _finite_number(now, "now")
        return self.issued_at <= current < self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_domain": self.trust_domain,
            "subject": self.subject,
            "roles": list(self.roles),
            "expires_at": self.expires_at,
            "issuer": self.issuer,
            "credential_reference": self.credential_reference,
            "issued_at": self.issued_at,
            "identity_reference": self.identity_reference,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerifiedIdentity":
        if not isinstance(value, Mapping):
            raise IdentityError("verified identity must be an object")
        identity = cls(
            trust_domain=value.get("trust_domain"),
            subject=value.get("subject"),
            roles=tuple(value.get("roles", ())),
            expires_at=value.get("expires_at"),
            issuer=value.get("issuer"),
            credential_reference=value.get("credential_reference"),
            issued_at=value.get("issued_at", 0.0),
        )
        expected = value.get("identity_reference")
        if expected is not None and expected != identity.identity_reference:
            raise IdentityError("verified identity reference mismatch")
        return identity


class IdentityProvider(Protocol):
    """Adapter contract for SPIFFE/SPIRE or another trusted identity source."""

    def verify(self, credential: Mapping[str, Any] | None, *, now: float) -> VerifiedIdentity:
        """Verify a boundary credential and return claims without raw secrets."""


class IdentityVerifier:
    """Bind provider claims to a trust domain, actor subject, and policy roles."""

    def __init__(
        self,
        provider: IdentityProvider,
        *,
        trust_domain: str,
        role_mapping: Mapping[str, str] | None = None,
    ):
        if not isinstance(trust_domain, str) or not trust_domain:
            raise IdentityError("trust domain must be a non-empty string")
        self.provider = provider
        self.trust_domain = trust_domain
        self.role_mapping = dict(role_mapping or {})
        if any(
            not isinstance(source, str)
            or not source
            or not isinstance(target, str)
            or not target
            for source, target in self.role_mapping.items()
        ):
            raise IdentityError("identity role mappings must use non-empty strings")

    def verify(
        self,
        credential: Mapping[str, Any] | None,
        *,
        actor_id: str | None = None,
        now: float,
    ) -> VerifiedIdentity:
        identity = self.provider.verify(credential, now=now)
        if identity.trust_domain != self.trust_domain:
            raise IdentityError(
                f"identity trust domain {identity.trust_domain!r} is not trusted"
            )
        if actor_id is not None and identity.subject != actor_id:
            raise IdentityError("verified identity subject does not match actor")
        if not identity.is_valid_at(now):
            raise IdentityError("identity is not valid at the decision time")

        if self.role_mapping:
            unknown = sorted(set(identity.roles) - set(self.role_mapping))
            if unknown:
                raise IdentityError(f"identity contains unmapped roles {unknown}")
            roles = tuple(sorted({self.role_mapping[role] for role in identity.roles}))
        else:
            roles = identity.roles
        return VerifiedIdentity._from_provider(
            trust_domain=identity.trust_domain,
            subject=identity.subject,
            roles=roles,
            expires_at=identity.expires_at,
            issuer=identity.issuer,
            credential_reference=identity.credential_reference,
            issued_at=identity.issued_at,
        )


class SignedTestIdentityProvider:
    """HMAC-signed test credential provider for deterministic local fixtures.

    This adapter exists to exercise the trust boundary without introducing a
    custom CA. Production integrations should implement ``IdentityProvider``
    with a SPIFFE/SPIRE-compatible attestation or another established provider.
    """

    def __init__(
        self,
        keys: Mapping[str, bytes],
        *,
        trust_domain: str,
        issuer: str = "test-issuer",
    ):
        if not keys or any(
            not isinstance(key_id, str)
            or not key_id
            or not isinstance(secret, (bytes, bytearray))
            or not secret
            for key_id, secret in keys.items()
        ):
            raise IdentityError("test identity provider requires non-empty signing keys")
        if not isinstance(trust_domain, str) or not trust_domain:
            raise IdentityError("trust domain must be a non-empty string")
        if not isinstance(issuer, str) or not issuer:
            raise IdentityError("identity issuer must be a non-empty string")
        self._keys = {key_id: bytes(secret) for key_id, secret in keys.items()}
        self.trust_domain = trust_domain
        self.issuer = issuer

    @staticmethod
    def _signature(payload: Mapping[str, Any], secret: bytes) -> str:
        digest = hmac.new(secret, _canonical(payload), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def issue(
        self,
        subject: str,
        roles: tuple[str, ...] | list[str],
        *,
        now: float,
        ttl: float = 300.0,
        key_id: str,
        trust_domain: str | None = None,
        issuer: str | None = None,
        credential_reference: str | None = None,
    ) -> dict[str, Any]:
        """Issue a signed fixture credential; intended for tests only."""
        if key_id not in self._keys:
            raise IdentityError(f"unknown test signing key {key_id!r}")
        issued_at = _finite_number(now, "issued_at")
        lifetime = _finite_number(ttl, "ttl")
        if lifetime <= 0:
            raise IdentityError("credential ttl must be positive")
        if not isinstance(subject, str) or not subject:
            raise IdentityError("identity subject must be a non-empty string")
        if not isinstance(roles, (tuple, list)):
            raise IdentityError("identity roles must be a list or tuple")
        if len(set(roles)) != len(roles) or any(
            not isinstance(role, str) or not role for role in roles
        ):
            raise IdentityError("identity roles must be distinct non-empty strings")
        payload = {
            "trust_domain": self.trust_domain if trust_domain is None else trust_domain,
            "subject": subject,
            "roles": list(roles),
            "issuer": self.issuer if issuer is None else issuer,
            "credential_reference": credential_reference or f"credential:{subject}:{issued_at}",
            "issued_at": issued_at,
            "expires_at": issued_at + lifetime,
            "key_id": key_id,
        }
        payload["signature"] = self._signature(payload, self._keys[key_id])
        return payload

    def verify(
        self,
        credential: Mapping[str, Any] | None,
        *,
        now: float,
    ) -> VerifiedIdentity:
        if not isinstance(credential, Mapping):
            raise IdentityError("identity credential is required")
        required = {
            "trust_domain",
            "subject",
            "roles",
            "issuer",
            "credential_reference",
            "issued_at",
            "expires_at",
            "key_id",
            "signature",
        }
        if not required.issubset(credential):
            raise IdentityError("identity credential is missing required fields")
        payload = {key: credential[key] for key in required if key != "signature"}
        if any(
            not isinstance(credential[field], str) or not credential[field]
            for field in ("trust_domain", "subject", "issuer", "credential_reference", "key_id", "signature")
        ):
            raise IdentityError("identity credential contains invalid string fields")
        roles = credential["roles"]
        if not isinstance(roles, list) or len(set(roles)) != len(roles) or any(
            not isinstance(role, str) or not role for role in roles
        ):
            raise IdentityError("identity credential roles are invalid")
        issued_at = _finite_number(credential["issued_at"], "issued_at")
        expires_at = _finite_number(credential["expires_at"], "expires_at")
        current = _finite_number(now, "now")
        if expires_at <= issued_at or current < issued_at or current >= expires_at:
            raise IdentityError("identity credential is expired or not yet valid")
        if credential["trust_domain"] != self.trust_domain:
            raise IdentityError("identity credential trust domain is not trusted")
        if credential["issuer"] != self.issuer:
            raise IdentityError("identity credential issuer is not trusted")
        secret = self._keys.get(credential["key_id"])
        if secret is None:
            raise IdentityError("identity credential signing key is not trusted")
        expected = self._signature(payload, secret)
        supplied = credential["signature"]
        if not hmac.compare_digest(expected, supplied):
            raise IdentityError("identity credential signature is invalid")
        return VerifiedIdentity(
            trust_domain=credential["trust_domain"],
            subject=credential["subject"],
            roles=tuple(roles),
            expires_at=expires_at,
            issuer=credential["issuer"],
            credential_reference=credential["credential_reference"],
            issued_at=issued_at,
        )
