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
"""Core plugin exposing explicit repository CRUD routes with deny-by-default role metadata."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any

from orbit import Application
from orbit.asgi import Headers, Request, Response
from orbit.asgi.request import HTTPError
from orbit.plugins import ControlAction, ControlResult, Plugin, PluginMetadata
from orbit.security.context import current_principal
from orbit_auth import Principal
from orbit_auth_rbac import RoleSubject
from orbit_data import RepositoryConflictError

from orbit_admin.audit import AdminAuditLog, AdminAuditSink
from orbit_admin.audit_delta import AdminDeltaAuditSink
from orbit_admin.csrf import AdminCSRFProtector
from orbit_admin.http_security import has_explicit_non_browser_authorization
from orbit_admin.resources import AdminResource

_READ = frozenset({"orbit.admin.read"})
_WRITE = frozenset({"orbit.admin.write"})
_MAX_PAGE_SIZE = 100
_MAX_KEY_CHARS = 255
_MAX_WRITE_BODY_BYTES = 1_048_576
_MAX_RESPONSE_BYTES = 2_097_152
_DELTA_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


class AdminPlugin(Plugin):
    """Register authenticated CRUD routes for explicitly declared application resources.

    Core passes bounded route-role metadata to the explicitly configured ``RouteAuthorizer`` after
    authentication. No resource is discovered from a database schema or imported implicitly.
    Mutating routes are registered only when their resource enables the corresponding operation.
    Optional encrypted delta auditing requires an application mutation handler for every writable
    resource and stores the resulting opaque delta reference in the operation audit record.
    """

    metadata = PluginMetadata(
        name="orbit-admin-python",
        version="0.1.0a1",
        capabilities=frozenset({"admin.repository-crud"}),
    )

    def __init__(
        self,
        resources: Sequence[AdminResource[Any, Any]],
        *,
        prefix: str = "/admin-api/v1",
        audit_log: AdminAuditSink | None = None,
        delta_audit: AdminDeltaAuditSink | None = None,
        csrf_secret: bytes | None = None,
        csrf_token_ttl_seconds: int = 600,
        operations: bool = True,
    ) -> None:
        """Capture a unique, immutable resource registry and a validated route prefix."""
        if isinstance(resources, (str, bytes)) or not isinstance(resources, Sequence):
            raise TypeError("Admin resources must be a sequence of AdminResource objects.")
        if not resources or any(not isinstance(item, AdminResource) for item in resources):
            raise ValueError("AdminPlugin requires at least one AdminResource.")
        detached = tuple(resources)
        names = tuple(item.name for item in detached)
        if len(names) != len(set(names)):
            raise ValueError("Admin resource names must be unique.")
        if (
            not isinstance(prefix, str)
            or not prefix.startswith("/")
            or prefix == "/"
            or prefix.endswith("/")
            or "//" in prefix
            or any(part in {".", ".."} for part in prefix.split("/"))
            or len(prefix.encode("utf-8")) > 256
        ):
            raise ValueError("Admin API prefix must be a bounded canonical absolute path.")
        self._resources = MappingProxyType({item.name: item for item in detached})
        self._prefix = prefix
        if audit_log is not None and not isinstance(audit_log, AdminAuditSink):
            raise TypeError("audit_log must implement the asynchronous AdminAuditSink contract.")
        self.audit_log: AdminAuditSink = AdminAuditLog() if audit_log is None else audit_log
        if delta_audit is not None and not isinstance(delta_audit, AdminDeltaAuditSink):
            raise TypeError("delta_audit must implement the AdminDeltaAuditSink contract.")
        if delta_audit is not None and any(
            (resource.create_fields or resource.update_fields or resource.allow_delete)
            and resource.delta_mutation_handler is None
            for resource in detached
        ):
            raise ValueError(
                "Encrypted delta auditing requires each writable resource to provide an "
                "atomic delta_mutation_handler."
            )
        self.delta_audit = delta_audit
        if csrf_secret is None:
            self._csrf_protector = None
            if (
                isinstance(csrf_token_ttl_seconds, bool)
                or not isinstance(csrf_token_ttl_seconds, int)
                or csrf_token_ttl_seconds != 600
            ):
                raise ValueError("csrf_token_ttl_seconds requires csrf_secret.")
        else:
            self._csrf_protector = AdminCSRFProtector(
                csrf_secret,
                token_ttl_seconds=csrf_token_ttl_seconds,
            )
        if not isinstance(operations, bool):
            raise TypeError("operations must be bool.")
        self._operations = operations
        self._application: Application | None = None
        actions = [
            ControlAction(
                id="review-resource-catalog",
                title="Review Admin resource catalog",
                description="Review allowlisted resource counts and endpoint prefix.",
                handler=self._review_resource_catalog,
            )
        ]
        if operations:
            actions.append(
                ControlAction(
                    id="review-operations-overview",
                    title="Review Admin operations overview",
                    description=(
                        "Show local application and service counts without making HTTP requests."
                    ),
                    handler=self._review_operations_overview,
                )
            )
        self.control_actions = tuple(actions)

    def setup(self, application: Application) -> None:
        """Register read and explicitly enabled mutation routes during Core composition."""
        if not isinstance(application, Application):
            raise TypeError("AdminPlugin requires an Orbit Application.")
        self._application = application
        if self._operations:
            from orbit_admin.operations import AdminOperationsPlugin

            AdminOperationsPlugin(audit_log=self.audit_log).setup(application)
        writable_resources = tuple(
            resource
            for resource in self._resources.values()
            if resource.create_fields or resource.update_fields or resource.allow_delete
        )
        if self._csrf_protector is not None and writable_resources:
            self._register_csrf_route(application)
            self._register_write_capabilities_route(application, writable_resources)
        self._register_catalog_route(application)
        for resource in self._resources.values():
            self._register_read_routes(application, resource)
            self._register_write_routes(application, resource)

    def _register_catalog_route(self, application: Application) -> None:
        """Expose only resource names and fields visible to the authenticated Admin subject."""

        @application.router.route(
            f"{self._prefix}/resources",
            method="GET",
            name="admin-resource-catalog",
            roles=_READ,
        )
        async def list_resources(request: Request) -> Response:
            """Return the explicit resource registry without repository data or row policies."""
            del request
            subject = _role_subject()
            items = [
                {
                    "name": resource.name,
                    "read_fields": list(resource.visible_read_fields(subject)),
                }
                for resource in self._resources.values()
            ]
            return _json_response({"items": items})

    def _register_csrf_route(self, application: Application) -> None:
        """Expose a no-store token endpoint only when browser writes are explicitly enabled."""
        protector = self._csrf_protector
        assert protector is not None

        @application.router.route(
            f"{self._prefix}/csrf-token",
            method="GET",
            name="admin-csrf-token",
            roles=_WRITE,
        )
        async def issue_csrf_token(request: Request) -> Response:
            """Return a short-lived token bound to this request's verified principal."""
            del request
            principal = current_principal()
            if not isinstance(principal, Principal):
                raise HTTPError(403, "security.csrf", "Authenticated Admin access is required.")
            token = protector.issue(principal)
            return Response.json(
                {"token": token},
                headers={"cache-control": "no-store", "pragma": "no-cache"},
            )

    def _register_write_capabilities_route(
        self,
        application: Application,
        resources: tuple[AdminResource[Any, Any], ...],
    ) -> None:
        """Expose write allowlists only when authenticated browser writes are enabled."""

        @application.router.route(
            f"{self._prefix}/write-capabilities",
            method="GET",
            name="admin-write-capabilities",
            roles=_WRITE,
        )
        async def list_write_capabilities(request: Request) -> Response:
            """Return the explicitly configured write surface without inspecting repository data."""
            del request
            return _json_response(
                {
                    "items": [
                        {
                            "name": resource.name,
                            "key_field": resource.key_field,
                            "create_fields": sorted(resource.create_fields),
                            "update_fields": sorted(resource.update_fields),
                            "allow_delete": resource.allow_delete,
                        }
                        for resource in resources
                    ]
                }
            )

    def _write_authorized(self, request: Request) -> bool:
        """Require a CSRF token for ambient browser credentials or explicit API authorization."""
        headers = request.headers
        if not isinstance(headers, Headers):
            return False
        origins = headers.getall("origin")
        cookies = headers.getall("cookie")
        if len(origins) > 1:
            return False
        if origins or cookies:
            protector = self._csrf_protector
            tokens = headers.getall("x-orbit-csrf-token")
            if protector is None or len(tokens) != 1:
                return False
            principal = current_principal()
            return isinstance(principal, Principal) and protector.verify(principal, tokens[0])
        return has_explicit_non_browser_authorization(request)

    def _register_read_routes(
        self, application: Application, resource: AdminResource[Any, Any]
    ) -> None:
        collection = f"{self._prefix}/resources/{resource.name}"
        item = f"{collection}/{{key}}"

        @application.router.route(
            collection,
            method="GET",
            name=f"admin-{resource.name}-list",
            roles=_READ,
        )
        async def list_items(request: Request) -> Response:
            """Return a bounded first page using only explicitly readable fields."""
            values = request.query_parameters.get("limit", [])
            if len(values) > 1:
                raise HTTPError(400, "admin.query", "The limit parameter must appear once.")
            limit = _page_limit(values[0] if values else None)
            entities = await resource.repository.list(limit=limit)
            subject = _role_subject()
            return _json_response(
                {"items": [resource.serialize(entity, subject=subject) for entity in entities]}
            )

        @application.router.route(
            item,
            method="GET",
            name=f"admin-{resource.name}-get",
            roles=_READ,
        )
        async def get_item(request: Request) -> Response:
            """Return one existing resource or a stable not-found response."""
            entity = await self._get(resource, _path_key(request))
            if entity is None:
                raise HTTPError(404, "admin.not-found", "Resource was not found.")
            return _json_response({"item": resource.serialize(entity, subject=_role_subject())})

    def _register_write_routes(
        self, application: Application, resource: AdminResource[Any, Any]
    ) -> None:
        collection = f"{self._prefix}/resources/{resource.name}"
        item = f"{collection}/{{key}}"
        if resource.create_fields:

            @application.router.route(
                collection,
                method="POST",
                name=f"admin-{resource.name}-create",
                roles=_WRITE,
            )
            async def create_item(request: Request) -> Response:
                """Validate allowed model fields, insert once, and record a payload-free audit."""
                if not self._write_authorized(request):
                    raise HTTPError(
                        403, "security.csrf", "Explicit non-browser authorization required."
                    )
                values = _write_object(_json_write_body(request), resource.create_fields)
                entity = resource.model.model_validate(values)
                try:
                    if self.delta_audit is None:
                        await resource.repository.add(entity)
                    else:
                        handler = resource.delta_mutation_handler
                        assert handler is not None
                        snapshot = await handler("crud.create", None, entity)
                        self._validate_snapshot(resource, snapshot)
                        if snapshot.before is not None:
                            raise RuntimeError("Create delta handler returned a before snapshot.")
                        entity = snapshot.after
                        if entity is None:
                            raise RuntimeError("Create delta handler returned no after snapshot.")
                except RepositoryConflictError:
                    await self.audit_log.record(
                        "crud.create",
                        target=resource.name,
                        success=False,
                        error_code="admin.conflict",
                    )
                    raise HTTPError(
                        409, "admin.conflict", "Resource conflicts with an existing item."
                    ) from None
                audit_target = resource.name
                if self.delta_audit is not None:
                    assert snapshot is not None
                    delta_id = await self._record_delta(
                        "crud.create", resource.name, snapshot.before, snapshot.after
                    )
                    audit_target = f"{resource.name}#delta={delta_id}"
                await self.audit_log.record("crud.create", target=audit_target, success=True)
                return _json_response(
                    {"item": resource.serialize(entity, subject=_role_subject())}, status=201
                )

        if resource.update_fields:

            @application.router.route(
                item,
                method="PUT",
                name=f"admin-{resource.name}-update",
                roles=_WRITE,
            )
            async def update_item(request: Request) -> Response:
                """Update only allowlisted fields while preserving the immutable resource key."""
                if not self._write_authorized(request):
                    raise HTTPError(
                        403, "security.csrf", "Explicit non-browser authorization required."
                    )
                key = _path_key(request)
                patch = _write_object(_json_write_body(request), resource.update_fields)
                update_handler = resource.update_handler
                if self.delta_audit is None and update_handler is None:
                    raise RuntimeError("Resource update handler is missing after validation.")
                try:
                    parsed_key = _parse_key(resource, key)
                    if self.delta_audit is None:
                        assert update_handler is not None
                        entity = await update_handler(parsed_key, patch)
                        snapshot = None
                    else:
                        handler = resource.delta_mutation_handler
                        assert handler is not None
                        snapshot = await handler("crud.update", parsed_key, patch)
                        self._validate_snapshot(resource, snapshot)
                        if snapshot.before is None:
                            entity = None
                        elif snapshot.after is None:
                            raise RuntimeError("Update delta handler returned no after snapshot.")
                        else:
                            entity = snapshot.after
                except RepositoryConflictError:
                    await self.audit_log.record(
                        "crud.update",
                        target=resource.name,
                        success=False,
                        error_code="admin.conflict",
                    )
                    raise HTTPError(
                        409, "admin.conflict", "Resource conflicts with an existing item."
                    ) from None
                if entity is None:
                    raise HTTPError(404, "admin.not-found", "Resource was not found.")
                audit_target = resource.name
                if self.delta_audit is not None:
                    assert snapshot is not None
                    delta_id = await self._record_delta(
                        "crud.update", resource.name, snapshot.before, snapshot.after
                    )
                    audit_target = f"{resource.name}#delta={delta_id}"
                await self.audit_log.record("crud.update", target=audit_target, success=True)
                return _json_response({"item": resource.serialize(entity, subject=_role_subject())})

        if resource.allow_delete:

            @application.router.route(
                item,
                method="DELETE",
                name=f"admin-{resource.name}-delete",
                roles=_WRITE,
            )
            async def delete_item(request: Request) -> Response:
                """Delete an existing resource and audit the outcome without storing its key."""
                if not self._write_authorized(request):
                    raise HTTPError(
                        403, "security.csrf", "Explicit non-browser authorization required."
                    )
                parsed_key = _parse_key(resource, _path_key(request))
                audit_target = resource.name
                if self.delta_audit is None:
                    deleted = await resource.repository.delete(parsed_key)
                    if not deleted:
                        raise HTTPError(404, "admin.not-found", "Resource was not found.")
                    snapshot = None
                else:
                    handler = resource.delta_mutation_handler
                    assert handler is not None
                    snapshot = await handler("crud.delete", parsed_key, {})
                    self._validate_snapshot(resource, snapshot)
                    if snapshot.before is None and snapshot.after is None:
                        raise HTTPError(404, "admin.not-found", "Resource was not found.")
                    if snapshot.before is None or snapshot.after is not None:
                        raise RuntimeError(
                            "Delete delta handler returned invalid entity snapshots."
                        )
                    delta_id = await self._record_delta(
                        "crud.delete", resource.name, snapshot.before, snapshot.after
                    )
                    audit_target = f"{resource.name}#delta={delta_id}"
                await self.audit_log.record("crud.delete", target=audit_target, success=True)
                return Response(status=204)

    async def _review_resource_catalog(self, _: Mapping[str, object]) -> ControlResult:
        """Report catalog size and endpoint prefix without reading protected records."""
        writable = sum(
            bool(resource.create_fields or resource.update_fields or resource.allow_delete)
            for resource in self._resources.values()
        )
        return ControlResult(
            "Admin resource catalog is configured.",
            (
                f"api_prefix: {self._prefix}",
                f"resource_count: {len(self._resources)}",
                f"resources_with_write_operations: {writable}",
            ),
        )

    async def _review_operations_overview(self, _: Mapping[str, object]) -> ControlResult:
        """Report local application state and service count without reading protected records."""
        application = self._application
        if application is None:
            return ControlResult(
                "Admin plugin is not composed into an application.", succeeded=False
            )
        return ControlResult(
            "Admin operations overview is ready.",
            (
                f"application_state: {application.state.application.phase.value}",
                f"registered_services: {len(application.services.descriptors)}",
            ),
        )

    @staticmethod
    async def _get(resource: AdminResource[Any, Any], raw_key: str) -> Any:
        """Parse the configured key type and read one entity from its repository."""
        return await resource.repository.get(_parse_key(resource, raw_key))

    async def _record_delta(
        self,
        action: str,
        target: str,
        before: Any,
        after: Any,
    ) -> str:
        """Persist a mutation delta and translate sink failures to a stable safe HTTP error."""
        sink = self.delta_audit
        assert sink is not None
        try:
            delta_id = await sink.record_change(action, target, before, after)
        except Exception:
            raise HTTPError(
                503,
                "admin.audit-unavailable",
                "The mutation may have completed; verify resource state before retrying.",
            ) from None
        if not isinstance(delta_id, str) or _DELTA_IDENTIFIER.fullmatch(delta_id) is None:
            raise HTTPError(
                503,
                "admin.audit-unavailable",
                "The mutation may have completed; verify resource state before retrying.",
            )
        return delta_id

    @staticmethod
    def _validate_snapshot(resource: AdminResource[Any, Any], snapshot: object) -> None:
        """Reject malformed handler snapshots before exposing or auditing them."""
        from orbit_admin.resources import AdminMutationSnapshot

        if not isinstance(snapshot, AdminMutationSnapshot):
            raise TypeError("delta_mutation_handler must return AdminMutationSnapshot.")
        if any(
            entity is not None and not isinstance(entity, resource.model)
            for entity in (snapshot.before, snapshot.after)
        ):
            raise TypeError("Mutation snapshots must contain the configured resource model.")


def _path_key(request: Request) -> str:
    """Return one bounded key parameter from Core's validated route match."""
    key = request.path_parameters.get("key")
    if not isinstance(key, str) or not 1 <= len(key) <= _MAX_KEY_CHARS:
        raise HTTPError(400, "admin.key", "Resource key is invalid.")
    return key


def _role_subject() -> RoleSubject | None:
    """Return only a structurally validated role subject from Core's request context."""
    principal = current_principal()
    return principal if isinstance(principal, RoleSubject) else None


def _parse_key(resource: AdminResource[Any, Any], raw_key: str) -> Any:
    """Convert a bounded path segment to the model's key type or return a safe client error."""
    from pydantic import ValidationError

    try:
        return resource.parse_key(raw_key)
    except (ValidationError, TypeError, ValueError):
        raise HTTPError(400, "admin.key", "Resource key is invalid.") from None


def _page_limit(value: str | None) -> int:
    """Parse the bounded decimal list limit and reject ambiguous or coercive inputs."""
    if value is None:
        return _MAX_PAGE_SIZE
    if not value.isascii() or not value.isdecimal() or len(value) > 3:
        raise HTTPError(400, "admin.limit", "The limit parameter must be a decimal integer.")
    limit = int(value)
    if not 1 <= limit <= _MAX_PAGE_SIZE:
        raise HTTPError(400, "admin.limit", "The limit parameter must be from 1 through 100.")
    return limit


def _write_object(value: object, allowed: frozenset[str]) -> Mapping[str, Any]:
    """Require a JSON object containing only explicitly writable model fields."""
    if not isinstance(value, dict):
        raise HTTPError(400, "admin.body", "The JSON body must be an object.")
    if not value:
        raise HTTPError(400, "admin.body", "The JSON body must contain writable fields.")
    if not value.keys() <= allowed:
        raise HTTPError(400, "admin.fields", "The JSON body contains fields that are not writable.")
    return value


def _json_write_body(request: Request) -> object:
    """Reject large write bodies before JSON decoding or model validation consumes CPU/memory."""
    if len(request.body) > _MAX_WRITE_BODY_BYTES:
        raise HTTPError(413, "admin.body-too-large", "Admin write bodies are limited to 1 MiB.")
    return request.json()


def _json_response(payload: object, *, status: int = 200) -> Response:
    """Serialize one uncached response under the Admin package's independent byte ceiling."""
    response = Response.json(
        payload,
        status=status,
        headers={"cache-control": "no-store", "pragma": "no-cache"},
    )
    if len(response.body) > _MAX_RESPONSE_BYTES:
        raise HTTPError(413, "admin.response-too-large", "Admin response exceeds the 2 MiB limit.")
    return response


__all__ = ["AdminPlugin"]
