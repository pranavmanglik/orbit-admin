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
"""Unit tests for Admin CSRF token integrity and expiry."""

import pytest
from orbit_auth import Identity, Principal

from orbit_admin.csrf import AdminCSRFProtector


def _principal(subject: str = "operator-1") -> Principal:
    """Create a verified identity for token binding tests."""
    return Principal(
        identity=Identity(subject=subject, provider="internal", claims={}),
        roles=frozenset({"orbit.admin.write"}),
    )


def test_token_is_bound_to_principal_and_expiration() -> None:
    protector = AdminCSRFProtector(b"k" * 32, token_ttl_seconds=600)
    token = protector.issue(_principal(), now=100)

    assert protector.verify(_principal(), token, now=699)
    assert not protector.verify(_principal(), token, now=700)
    assert not protector.verify(_principal("operator-2"), token, now=200)
    assert not protector.verify(None, token, now=200)


@pytest.mark.parametrize("mutation", ["prefix", "nonce", "identity", "signature"])
def test_token_tampering_and_malformed_values_are_rejected(mutation: str) -> None:
    protector = AdminCSRFProtector(b"k" * 32)
    token = protector.issue(_principal(), now=100)
    parts = token.split(".")
    index = {"prefix": 0, "nonce": 2, "identity": 3, "signature": 4}[mutation]
    parts[index] = ("x" if parts[index][0] != "x" else "y") + parts[index][1:]

    assert not protector.verify(_principal(), ".".join(parts), now=200)
    assert not protector.verify(_principal(), "not-a-token", now=200)
    assert not protector.verify(_principal(), token + "x", now=200)


def test_secret_and_ttl_are_bounded() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        AdminCSRFProtector(b"short")
    with pytest.raises(ValueError, match="lifetime"):
        AdminCSRFProtector(b"k" * 32, token_ttl_seconds=3_601)
    with pytest.raises(ValueError, match="lifetime"):
        AdminCSRFProtector(b"k" * 32, token_ttl_seconds=True)
    with pytest.raises(ValueError, match="issue time"):
        AdminCSRFProtector(b"k" * 32).issue(_principal(), now=999_999_999_999)
