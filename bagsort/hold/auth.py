"""Authorisation for hold operations.

Placing and releasing a hold must not be the same privilege: an officer who can
freeze records must not unilaterally unfreeze them. Credentials are signed
bearer tokens (HMAC-SHA256 over ``principal|role|signed_at``) so an API or CLI
call proves who acts, and the registry can enforce separation of duties without
a separate identity service in this self contained plant.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from bagsort.errors import AuthorizationError, ValidationError

ROLE_HOLDER = "hold:place"
ROLE_RELEASER = "hold:release"
ROLES = (ROLE_HOLDER, ROLE_RELEASER)

# A token may not be minted far in the future or replayed long after issue.
MAX_SKEW_SECONDS = 300


@dataclass(frozen=True)
class Principal:
    name: str
    role: str

    def require(self, role: str) -> None:
        if self.role != role:
            raise AuthorizationError(
                f"{self.name!r} holds {self.role!r}, which may not perform {role!r}"
            )


def _message(name: str, role: str, signed_at: str) -> bytes:
    return f"{name}|{role}|{signed_at}".encode("utf-8")


def issue_credential(name: str, role: str, signed_at: str, secret: str) -> str:
    """Mint a bearer token for ``name``; used by the CLI ``token`` command."""

    if role not in ROLES:
        raise ValidationError(f"unknown hold role {role!r}")
    signature = hmac.new(
        secret.encode("utf-8"), _message(name, role, signed_at), hashlib.sha256
    ).hexdigest()
    payload = {"name": name, "role": role, "at": signed_at}
    return f"{json.dumps(payload, separators=(',', ':'))}.{signature}"


class Authorizer:
    """Verify bearer tokens against a shared secret and bound their freshness."""

    def __init__(self, secret: str, clock: object) -> None:
        self._secret = secret.encode("utf-8")
        self._clock = clock

    def authenticate(self, credential: str) -> Principal:
        if not credential:
            raise AuthorizationError("a signed credential is required for hold operations")
        credential = credential.removeprefix("Bearer ").strip()
        try:
            raw, signature = credential.rsplit(".", 1)
            payload = json.loads(raw)
            name, role, signed_at = str(payload["name"]), str(payload["role"]), str(payload["at"])
        except (ValueError, KeyError) as exc:
            raise AuthorizationError("malformed hold credential") from exc
        if role not in ROLES:
            raise AuthorizationError(f"unknown role {role!r}")
        expected = hmac.new(
            self._secret, _message(name, role, signed_at), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise AuthorizationError("hold credential signature does not verify")
        if abs(self._age_seconds(signed_at)) > MAX_SKEW_SECONDS:
            raise AuthorizationError("hold credential is outside its validity window")
        return Principal(name=name, role=role)

    def _age_seconds(self, signed_at: str) -> float:
        from bagsort.clock import DEFAULT_EPOCH
        from datetime import datetime

        try:
            issued = datetime.strptime(signed_at, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise AuthorizationError("hold credential timestamp is not UTC ISO-8601") from exc
        issued = issued.replace(tzinfo=DEFAULT_EPOCH.tzinfo)
        return (self._clock.now() - issued).total_seconds()
