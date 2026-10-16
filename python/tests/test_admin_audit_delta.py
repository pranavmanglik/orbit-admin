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
"""Authenticated encryption behavior for Admin delta audit objects."""

from __future__ import annotations

import json
from collections.abc import AsyncIterable

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from orbit_sql_sqlite import SQLiteDatabase
from pydantic import BaseModel

from orbit_admin import AdminMutationSnapshot, sql_resource
from orbit_admin.audit_delta import EncryptedObjectDeltaAuditSink
from orbit_admin.errors import AdminAuditPersistenceError


class Entity(BaseModel):
    """Example state whose contents must not be visible in the stored object."""

    account_id: int
    email: str


class MemoryObjectStore:
    """Small object-store contract fake that consumes upload streams once."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.failure: Exception | None = None

    async def put(
        self,
        key: str,
        body: bytes | AsyncIterable[bytes],
        *,
        content_type: str | None = None,
        metadata: object = None,
    ) -> object:
        """Collect streamed chunks as a provider would while preserving chunked input."""
        del content_type, metadata
        if self.failure is not None:
            raise self.failure
        if isinstance(body, bytes):
            self.objects[key] = body
            return None
        chunks = [chunk async for chunk in body]
        assert all(len(chunk) <= 64 * 1024 + 16 for chunk in chunks)
        self.objects[key] = b"".join(chunks)
        return None

    async def get(self, key: str) -> None:
        del key
        return None

    async def delete(self, key: str) -> bool:
        del key
        return False

    async def list_page(
        self,
        prefix: str = "",
        *,
        limit: int = 100,
        continuation_token: str | None = None,
    ) -> object:
        del prefix, limit, continuation_token
        return None

    async def aclose(self) -> None:
        return None


def _decrypt(key: bytes, encrypted: bytes) -> tuple[dict[str, object], bytes]:
    """Decode the envelope and authenticate ciphertext before returning plaintext."""
    header_size = int.from_bytes(encrypted[:4], "big")
    header = json.loads(encrypted[4 : 4 + header_size])
    aad = bytes.fromhex(header["aad"])
    nonce = bytes.fromhex(header["nonce"])
    ciphertext = encrypted[4 + header_size : -16]
    tag = encrypted[-16:]
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    decryptor.authenticate_additional_data(aad)
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return header, plaintext


@pytest.mark.asyncio
async def test_delta_is_streamed_encrypted_and_bound_to_action_and_resource() -> None:
    """Ensure plaintext stays hidden and a valid object decrypts with authenticated context."""
    store = MemoryObjectStore()
    key = bytes(range(32))
    sink = EncryptedObjectDeltaAuditSink(store, key=key, key_id="audit-2026-01")

    identifier = await sink.record_change(
        "crud.update",
        "accounts",
        Entity(account_id=7, email="before@example.test"),
        Entity(account_id=7, email="after@example.test"),
    )

    assert identifier
    stored = next(iter(store.objects.values()))
    assert b"before@example.test" not in stored
    assert b"after@example.test" not in stored
    header, plaintext = _decrypt(key, stored)
    assert header["key_id"] == "audit-2026-01"
    assert json.loads(bytes.fromhex(header["aad"])) == {
        "action": "crud.update",
        "id": identifier,
        "key_id": "audit-2026-01",
        "target": "accounts",
    }
    assert json.loads(plaintext) == {
        "after": {"account_id": 7, "email": "after@example.test"},
        "before": {"account_id": 7, "email": "before@example.test"},
    }


@pytest.mark.asyncio
async def test_delta_authentication_fails_after_ciphertext_tampering() -> None:
    """Reject ciphertext alteration rather than exposing unauthenticated delta bytes."""
    store = MemoryObjectStore()
    key = bytes(range(32))
    sink = EncryptedObjectDeltaAuditSink(store, key=key, key_id="audit-v1")
    await sink.record_change("crud.delete", "accounts", Entity(account_id=1, email="x"), None)
    object_key = next(iter(store.objects))
    corrupted = bytearray(store.objects[object_key])
    corrupted[-17] ^= 1
    with pytest.raises(InvalidTag):
        _decrypt(key, bytes(corrupted))


def test_sink_requires_explicit_strong_key_and_key_identifier() -> None:
    """Reject weak or ambiguous key configuration before accepting audit data."""
    store = MemoryObjectStore()
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        EncryptedObjectDeltaAuditSink(store, key=b"short", key_id="key-1")
    with pytest.raises(ValueError, match="key_id"):
        EncryptedObjectDeltaAuditSink(store, key=bytes(32), key_id=" ")


@pytest.mark.asyncio
async def test_sink_translates_provider_failures_without_preserving_vendor_text() -> None:
    """Convert object-store failures to the shared Core error hierarchy safely."""
    store = MemoryObjectStore()
    store.failure = RuntimeError("private bucket and credential detail")
    sink = EncryptedObjectDeltaAuditSink(store, key=bytes(range(32)), key_id="audit-v1")

    with pytest.raises(AdminAuditPersistenceError) as captured:
        await sink.record_change(
            "crud.update",
            "accounts",
            Entity(account_id=1, email="before@example.test"),
            Entity(account_id=1, email="after@example.test"),
        )

    assert captured.value.problem.code == "admin.audit-persistence"
    assert "private bucket" not in str(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.asyncio
async def test_sink_rejects_unbounded_identifiers_and_empty_snapshots() -> None:
    """Validate the authenticated context before allocating or uploading audit data."""
    sink = EncryptedObjectDeltaAuditSink(
        MemoryObjectStore(), key=bytes(range(32)), key_id="audit-v1"
    )
    entity = Entity(account_id=1, email="account@example.test")

    with pytest.raises(ValueError, match="identifiers"):
        await sink.record_change("crud.update\n", "accounts", entity, entity)
    with pytest.raises(ValueError, match="identifiers"):
        await sink.record_change("crud.update", "Accounts", entity, entity)
    with pytest.raises(ValueError, match="at least one"):
        await sink.record_change("crud.update", "accounts", None, None)


@pytest.mark.asyncio
async def test_sql_resource_accepts_the_atomic_delta_mutation_handler() -> None:
    """The regular SQL resource factory can opt into transaction-backed delta auditing."""
    database = SQLiteDatabase(":memory:")

    async def mutate(
        action: str,
        key: int | None,
        payload: BaseModel | dict[str, object],
    ) -> AdminMutationSnapshot:
        del action, key, payload
        return AdminMutationSnapshot(before=None, after=Entity(account_id=7, email="new"))

    resource = sql_resource(
        "accounts",
        database,
        Entity,
        table="accounts",
        key_field="account_id",
        read_fields=frozenset({"account_id", "email"}),
        update_fields=frozenset({"email"}),
        delta_mutation_handler=mutate,
    )

    assert resource.delta_mutation_handler is mutate
    assert resource.update_handler is None
    await database.aclose()
