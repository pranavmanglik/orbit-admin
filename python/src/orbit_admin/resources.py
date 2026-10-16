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
"""Explicitly allowlisted, typed repository resources for the Orbit Admin CRUD API."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Generic, TypeVar, cast

from orbit_auth_rbac import PermissionAuthorizer, RoleSubject
from orbit_data import Repository
from orbit_sql import SQLDatabase, SQLRepository, SQLValue
from pydantic import BaseModel, TypeAdapter

EntityT = TypeVar("EntityT", bound=BaseModel)
KeyT = TypeVar("KeyT")
UpdateKeyT = TypeVar("UpdateKeyT")
UpdateEntityT = TypeVar("UpdateEntityT", bound=BaseModel)
_RESOURCE_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")
_PERMISSION_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,254}\Z")
AtomicUpdate = Callable[[UpdateKeyT, Mapping[str, Any]], Awaitable[UpdateEntityT | None]]


@dataclass(frozen=True, slots=True)
class AdminMutationSnapshot:
    """Authoritative entity states returned by an application-owned atomic mutation."""

    before: BaseModel | None
    after: BaseModel | None


DeltaMutation = Callable[
    [str, KeyT | None, BaseModel | Mapping[str, Any]], Awaitable[AdminMutationSnapshot]
]


@dataclass(frozen=True, slots=True)
class AdminResource(Generic[EntityT, KeyT]):
    """Bind one Pydantic entity to a repository and explicit field-level permissions.

    ``read_fields`` controls response serialization. Create/update field sets are separate
    allowlists; model fields such as passwords or internal flags are never exposed or writable
    unless the application names them explicitly. Deletion is disabled by default. When encrypted
    delta auditing is configured, ``delta_mutation_handler`` must perform each mutation and return
    authoritative before/after snapshots from that mutation's transaction or compare-and-swap.
    """

    name: str
    model: type[EntityT]
    repository: Repository[EntityT, KeyT]
    key_field: str
    read_fields: frozenset[str]
    create_fields: frozenset[str] = frozenset()
    update_fields: frozenset[str] = frozenset()
    update_handler: AtomicUpdate[KeyT, EntityT] | None = None
    delta_mutation_handler: DeltaMutation[KeyT] | None = None
    allow_delete: bool = False
    field_permissions: Mapping[str, str] | None = None
    field_authorizer: PermissionAuthorizer | None = None
    authorization_context_fields: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        """Validate resource identity, model schema, repository surface, and field allowlists."""
        if not isinstance(self.name, str) or _RESOURCE_NAME.fullmatch(self.name) is None:
            raise ValueError("Admin resource names must be lowercase slugs.")
        if not isinstance(self.model, type) or not issubclass(self.model, BaseModel):
            raise TypeError("Admin resources require a Pydantic model class.")
        if not isinstance(self.repository, Repository):
            raise TypeError("Admin resources require an orbit-data Repository.")
        if self.key_field not in self.model.model_fields:
            raise ValueError("key_field must name a field on the resource model.")
        fields = frozenset(self.model.model_fields)
        for name, values in (
            ("read_fields", self.read_fields),
            ("create_fields", self.create_fields),
            ("update_fields", self.update_fields),
        ):
            if isinstance(values, (str, bytes)) or not isinstance(values, (set, frozenset)):
                raise TypeError(f"{name} must be a set or frozenset of model field names.")
            if not values <= fields:
                raise ValueError(f"{name} contains fields not declared by the resource model.")
            object.__setattr__(self, name, frozenset(values))
        if not self.read_fields:
            raise ValueError("read_fields must expose at least one field.")
        if self.key_field in self.update_fields:
            raise ValueError("Resource keys cannot be changed through the Admin API.")
        if (
            self.update_fields
            and not callable(self.update_handler)
            and not callable(self.delta_mutation_handler)
        ):
            raise ValueError(
                "Writable update_fields require an application-supplied atomic update_handler "
                "or delta_mutation_handler."
            )
        if self.update_handler is not None and not self.update_fields:
            raise ValueError("update_handler requires a non-empty update_fields allowlist.")
        if self.delta_mutation_handler is not None and not callable(self.delta_mutation_handler):
            raise TypeError("delta_mutation_handler must be callable.")
        if not isinstance(self.allow_delete, bool):
            raise TypeError("allow_delete must be a boolean.")
        context_fields = self.authorization_context_fields
        if isinstance(context_fields, (str, bytes)) or not isinstance(
            context_fields, (set, frozenset)
        ):
            raise TypeError("authorization_context_fields must be a set of model field names.")
        if not context_fields <= fields:
            raise ValueError("authorization_context_fields contains an unknown model field.")
        object.__setattr__(self, "authorization_context_fields", frozenset(context_fields))
        field_permissions = self.field_permissions
        if field_permissions is None:
            field_permissions = {}
        if not isinstance(field_permissions, Mapping):
            raise TypeError("field_permissions must map readable model fields to permissions.")
        if not field_permissions and self.field_authorizer is not None:
            raise ValueError("field_authorizer requires at least one field permission.")
        if field_permissions and not isinstance(self.field_authorizer, PermissionAuthorizer):
            raise TypeError("field_permissions require an orbit-auth-rbac PermissionAuthorizer.")
        normalized_permissions: dict[str, str] = {}
        for field_name, permission in field_permissions.items():
            if field_name not in self.read_fields:
                raise ValueError("field_permissions can only apply to readable fields.")
            if not isinstance(permission, str):
                raise TypeError("Field permission identifiers must be strings.")
            if _PERMISSION_NAME.fullmatch(permission) is None:
                raise ValueError("Field permission identifiers must use the RBAC identifier form.")
            normalized_permissions[field_name] = permission
        object.__setattr__(self, "field_permissions", MappingProxyType(normalized_permissions))

    def parse_key(self, value: str) -> KeyT:
        """Validate one bounded URL key using the Pydantic field's declared type."""
        annotation = self.model.model_fields[self.key_field].annotation
        if annotation is None:
            raise TypeError("The resource key field must declare a validation type.")
        return cast(KeyT, TypeAdapter(annotation).validate_python(value))

    def visible_read_fields(
        self,
        subject: RoleSubject | None,
        *,
        resource_attributes: Mapping[str, object] | None = None,
    ) -> tuple[str, ...]:
        """Return field names this subject may see for the supplied trusted record context.

        The resource catalog calls this without attributes, so fields guarded by tenant or
        record-specific policy stay out of general schema metadata. Entity serialization supplies
        server-loaded attributes and can reveal those fields on records the subject may access.
        """
        visible = set(self.read_fields)
        authorizer = self.field_authorizer
        permissions = self.field_permissions
        if authorizer is not None and permissions is not None:
            for field_name, permission in permissions.items():
                try:
                    allowed = authorizer.allows(
                        subject,
                        permission,
                        resource_attributes=resource_attributes,
                    )
                except (TypeError, ValueError):
                    allowed = False
                if not allowed:
                    visible.discard(field_name)
        return tuple(sorted(visible))

    def serialize(
        self,
        entity: EntityT,
        *,
        subject: RoleSubject | None = None,
    ) -> dict[str, object]:
        """Serialize allowlisted fields after evaluating configured field-level policies.

        Fields with a permission mapping are omitted unless the trusted subject is allowed. When
        authorization context fields are configured, their server-loaded model values are passed
        to the authorizer; request-provided values are never used for this decision.
        """
        if not isinstance(entity, self.model):
            raise TypeError("Repository returned an entity of the wrong model type.")
        attributes = entity.model_dump(mode="json", include=set(self.authorization_context_fields))
        fields = self.visible_read_fields(subject, resource_attributes=attributes)
        return cast(dict[str, object], entity.model_dump(mode="json", include=set(fields)))


def sql_resource(
    name: str,
    database: SQLDatabase,
    model: type[EntityT],
    *,
    table: str,
    key_field: str,
    read_fields: frozenset[str],
    create_fields: frozenset[str] = frozenset(),
    update_fields: frozenset[str] = frozenset(),
    update_handler: AtomicUpdate[SQLValue, EntityT] | None = None,
    delta_mutation_handler: DeltaMutation[SQLValue] | None = None,
    allow_delete: bool = False,
    field_permissions: Mapping[str, str] | None = None,
    field_authorizer: PermissionAuthorizer | None = None,
    authorization_context_fields: frozenset[str] = frozenset(),
) -> AdminResource[EntityT, SQLValue]:
    """Create an Admin resource backed by Orbit's validated asynchronous SQL repository."""
    if not isinstance(database, SQLDatabase):
        raise TypeError("database must implement the orbit-sql SQLDatabase contract.")
    repository = SQLRepository(database, model, table=table, primary_key=key_field)
    return AdminResource(
        name=name,
        model=model,
        repository=repository,
        key_field=key_field,
        read_fields=read_fields,
        create_fields=create_fields,
        update_fields=update_fields,
        update_handler=update_handler,
        delta_mutation_handler=delta_mutation_handler,
        allow_delete=allow_delete,
        field_permissions=field_permissions,
        field_authorizer=field_authorizer,
        authorization_context_fields=authorization_context_fields,
    )


__all__ = ["AdminMutationSnapshot", "AdminResource", "sql_resource"]
