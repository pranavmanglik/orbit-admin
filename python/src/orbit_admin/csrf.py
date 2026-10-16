# Copyright 2026-present Orbit Contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Short-lived, identity-bound CSRF tokens for browser-based Admin mutations."""

from __future__ import annotations

import hmac
import re
import secrets
import time
from base64 import urlsafe_b64encode

from orbit_auth import Principal

_TOKEN = re.compile(
    r"v1\.([0-9]{1,12})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})\Z"
)
_MIN_SECRET_BYTES = 32
_MAX_TOKEN_TTL_SECONDS = 3_600
_MAX_TIMESTAMP = 999_999_999_999


class AdminCSRFProtector:
    """Issue signed tokens bound to an authenticated principal and bounded lifetime.

    Keep the secret in a secret manager and use the same secret across workers that serve the
    same Admin application. Rotate it to revoke outstanding tokens. A token is reusable until
    expiration; applications must still authorize each mutation through Core's route policy.
    """

    def __init__(self, secret: bytes, *, token_ttl_seconds: int = 600) -> None:
        """Validate the signing secret and token lifetime before enabling browser writes."""
        if not isinstance(secret, bytes) or len(secret) < _MIN_SECRET_BYTES:
            raise ValueError("Admin CSRF secret must contain at least 32 bytes.")
        if (
            isinstance(token_ttl_seconds, bool)
            or not isinstance(token_ttl_seconds, int)
            or not 1 <= token_ttl_seconds <= _MAX_TOKEN_TTL_SECONDS
        ):
            raise ValueError("Admin CSRF token lifetime must be between 1 and 3600 seconds.")
        self._secret = bytes(secret)
        self._ttl = token_ttl_seconds

    def issue(self, principal: Principal, *, now: int | None = None) -> str:
        """Create a token for one verified identity without including identity data in it."""
        if not isinstance(principal, Principal):
            raise TypeError("Admin CSRF tokens require an authenticated Principal.")
        issued_at = int(time.time()) if now is None else now
        if (
            isinstance(issued_at, bool)
            or not isinstance(issued_at, int)
            or not 0 <= issued_at <= _MAX_TIMESTAMP - self._ttl
        ):
            raise ValueError("Admin CSRF issue time must be a non-negative integer.")
        expires = issued_at + self._ttl
        nonce = _b64(secrets.token_bytes(16))
        identity = _b64(
            hmac.digest(
                self._secret,
                b"orbit-admin-csrf-identity-v1\0"
                + principal.identity.provider.encode("utf-8")
                + b"\0"
                + principal.identity.subject.encode("utf-8"),
                "sha256",
            )
        )
        unsigned = f"v1.{expires}.{nonce}.{identity}"
        signature = _b64(
            hmac.digest(self._secret, b"orbit-admin-csrf-token-v1\0" + unsigned.encode(), "sha256")
        )
        return f"{unsigned}.{signature}"

    def verify(self, principal: Principal | None, token: str, *, now: int | None = None) -> bool:
        """Check token shape, expiry, principal binding, and signature without raising details."""
        if not isinstance(principal, Principal) or not isinstance(token, str) or len(token) > 160:
            return False
        match = _TOKEN.fullmatch(token)
        if match is None:
            return False
        expires_text, nonce, identity_tag, signature = match.groups()
        current_time = int(time.time()) if now is None else now
        if (
            isinstance(current_time, bool)
            or not isinstance(current_time, int)
            or not 0 <= current_time <= _MAX_TIMESTAMP
        ):
            return False
        expires = int(expires_text)
        if not current_time < expires <= current_time + self._ttl:
            return False
        expected_identity = _b64(
            hmac.digest(
                self._secret,
                b"orbit-admin-csrf-identity-v1\0"
                + principal.identity.provider.encode("utf-8")
                + b"\0"
                + principal.identity.subject.encode("utf-8"),
                "sha256",
            )
        )
        unsigned = f"v1.{expires_text}.{nonce}.{identity_tag}"
        expected_signature = _b64(
            hmac.digest(self._secret, b"orbit-admin-csrf-token-v1\0" + unsigned.encode(), "sha256")
        )
        return hmac.compare_digest(identity_tag, expected_identity) and hmac.compare_digest(
            signature, expected_signature
        )


def _b64(value: bytes) -> str:
    """Encode URL-safe token material without padding."""
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


__all__ = ["AdminCSRFProtector"]
