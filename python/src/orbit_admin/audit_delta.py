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
"""Opt-in authenticated encryption for bounded Admin state-diff records."""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import AsyncIterable, AsyncIterator, Mapping
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4

from pydantic import BaseModel

from orbit_admin.errors import AdminAuditPersistenceError

_CHUNK_BYTES = 64 * 1024
_MAX_DELTA_BYTES = 1_048_576
_ACTION_IDENTIFIER = re.compile(r"[a-z][a-z0-9.-]{0,62}\Z")
_TARGET_IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")


@runtime_checkable
class AdminDeltaAuditSink(Protocol):
    """Destination for encrypted before/after snapshots of a successful mutation."""

    async def record_change(
        self,
        action: str,
        target: str,
        before: BaseModel | None,
        after: BaseModel | None,
    ) -> str:
        """Persist a state change and return its opaque audit object identifier."""


class _ObjectStore(Protocol):
    """Small local typing view of the storage capability's lifecycle and upload contract."""

    async def put(
        self,
        key: str,
        body: bytes | AsyncIterable[bytes],
        *,
        content_type: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> Any:
        """Stream one object into the application-owned storage provider."""


class EncryptedObjectDeltaAuditSink:
    """Write bounded state snapshots as AES-256-GCM authenticated object streams.

    The application supplies a 32-byte key and stable key identifier from its secret manager.
    This sink never owns or closes the object store. Each object uses a fresh random 96-bit nonce;
    action and resource name are authenticated as associated data. Readers must verify the final
    GCM tag before using any decrypted bytes. Object storage must be configured with appropriate
    retention, access controls, and versioning; this class does not provide an append-only ledger
    or atomicity with the resource mutation.
    """

    def __init__(self, store: _ObjectStore, *, key: bytes, key_id: str) -> None:
        required_methods = ("put", "get", "delete", "list_page", "aclose")
        if any(not callable(getattr(store, method, None)) for method in required_methods):
            raise TypeError("store must implement the orbit-storage ObjectStore contract.")
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("AES-256-GCM audit keys must contain exactly 32 bytes.")
        if not isinstance(key_id, str) or not 1 <= len(key_id) <= 128:
            raise ValueError("key_id must contain between 1 and 128 characters.")
        if any(ord(char) < 33 or ord(char) > 126 for char in key_id):
            raise ValueError("key_id must contain printable non-space ASCII characters.")
        self._store = store
        self._key = bytes(key)
        self._key_id = key_id

    async def record_change(
        self,
        action: str,
        target: str,
        before: BaseModel | None,
        after: BaseModel | None,
    ) -> str:
        """Encrypt and stream one bounded canonical before/after JSON document."""
        if (
            not isinstance(action, str)
            or _ACTION_IDENTIFIER.fullmatch(action) is None
            or not isinstance(target, str)
            or _TARGET_IDENTIFIER.fullmatch(target) is None
        ):
            raise ValueError("Admin audit action and target must be bounded lowercase identifiers.")
        if any(
            entity is not None and not isinstance(entity, BaseModel) for entity in (before, after)
        ):
            raise TypeError("Admin delta snapshots must be Pydantic model instances or None.")
        if before is None and after is None:
            raise ValueError("An Admin audit delta must contain at least one entity snapshot.")
        operation_id = str(uuid4())
        associated_data = json.dumps(
            {"id": operation_id, "action": action, "target": target, "key_id": self._key_id},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        document = json.dumps(
            {
                "before": before.model_dump(mode="json") if before is not None else None,
                "after": after.model_dump(mode="json") if after is not None else None,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(document) > _MAX_DELTA_BYTES:
            raise ValueError("Admin state diff exceeds the 1 MiB encrypted audit limit.")
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        nonce = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES(self._key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(associated_data)
        key = f"orbit-admin/audit-deltas/{operation_id}.gcm"

        async def encrypted_chunks() -> AsyncIterator[bytes]:
            """Yield a versioned header followed by bounded ciphertext and the GCM tag."""
            header = json.dumps(
                {
                    "version": 1,
                    "key_id": self._key_id,
                    "nonce": nonce.hex(),
                    "aad": associated_data.hex(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            yield len(header).to_bytes(4, "big") + header
            for offset in range(0, len(document), _CHUNK_BYTES):
                encrypted = encryptor.update(document[offset : offset + _CHUNK_BYTES])
                if encrypted:
                    yield encrypted
            final = encryptor.finalize()
            if final:
                yield final
            yield encryptor.tag

        try:
            await self._store.put(
                key,
                encrypted_chunks(),
                content_type="application/vnd.orbit.admin-audit+aesgcm",
                metadata={"key-id": self._key_id, "encryption": "AES-256-GCM"},
            )
        except Exception:
            raise AdminAuditPersistenceError() from None
        return operation_id


__all__ = ["AdminDeltaAuditSink", "EncryptedObjectDeltaAuditSink"]
