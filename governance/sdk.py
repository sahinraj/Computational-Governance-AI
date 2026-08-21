"""Small typed client for the M24 governance service contract."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .service import DecisionRequest, GovernanceService, ServiceResponse


class Transport(Protocol):
    def request(self, method: str, path: str, value: Mapping[str, Any] | None = None) -> ServiceResponse:
        """Send one versioned service request."""


class ServiceClientError(RuntimeError):
    """Raised when a service response has a non-success status."""

    def __init__(self, response: ServiceResponse):
        error = response.body.get("error", {})
        self.status = response.status
        self.code = error.get("code", "unknown_error")
        super().__init__(error.get("message", "service request failed"))


@dataclass(frozen=True)
class InProcessTransport:
    service: GovernanceService

    def request(self, method: str, path: str, value: Mapping[str, Any] | None = None) -> ServiceResponse:
        return self.service.handle(method, path, value)


@dataclass(frozen=True)
class HTTPTransport:
    base_url: str
    timeout: float = 10.0

    def request(self, method: str, path: str, value: Mapping[str, Any] | None = None) -> ServiceResponse:
        payload = None if value is None else json.dumps(value).encode("utf-8")
        request = Request(
            self.base_url.rstrip("/") + path,
            data=payload,
            method=method,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
                return ServiceResponse(status=response.status, body=body)
        except HTTPError as exc:
            body = json.loads(exc.read().decode("utf-8"))
            return ServiceResponse(status=exc.code, body=body)
        except (URLError, TimeoutError) as exc:
            raise ServiceClientError(
                ServiceResponse(
                    status=503,
                    body={"error": {"code": "transport_unavailable", "message": str(exc)}},
                )
            ) from exc


class GovernanceClient:
    """Transport-independent M24 client; retries are caller-controlled."""

    def __init__(self, transport: Transport):
        self.transport = transport

    def _request(self, method: str, path: str, value: Mapping[str, Any] | None = None) -> dict[str, Any]:
        response = self.transport.request(method, path, value)
        if response.status >= 400:
            raise ServiceClientError(response)
        return response.body

    def decide(self, request: DecisionRequest | Mapping[str, Any]) -> dict[str, Any]:
        value = request.to_dict() if isinstance(request, DecisionRequest) else request
        return self._request("POST", "/v1/decisions", value)

    def get_approval(self, request_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/approvals/{request_id}")

    def vote(self, request_id: str, value: Mapping[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/v1/approvals/{request_id}/vote", value)

    def resume(self, request_id: str, value: Mapping[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/v1/approvals/{request_id}/resume", value)


__all__ = [
    "Transport",
    "ServiceClientError",
    "InProcessTransport",
    "HTTPTransport",
    "GovernanceClient",
]
