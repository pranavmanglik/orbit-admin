"""Admin CRUD behavior, access rules, validation, and audit redaction."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from orbit import Application, ApplicationConfig
from orbit.asgi import ASGIApplication, Request
from orbit_auth import BasicAuthenticator, BasicCredential, Identity, Principal, RoleAuthorizer
from orbit_auth_rbac import PermissionAuthorizer
from orbit_data import RepositoryConflictError
from orbit_security import RateLimitResult
from orbit_sql_sqlite import SQLiteDatabase
from orbit_testing import TestClient
from pydantic import BaseModel, SecretStr

from orbit_admin import (
    AdminAuditLog,
    AdminAuditSink,
    AdminMutationSnapshot,
    AdminOperationsPlugin,
    AdminPlugin,
    AdminResource,
    SQLAdminAuditLog,
)
from orbit_admin.operations import AdminApplication


class Account(BaseModel):
    """Small test record with a field deliberately hidden from Admin responses."""

    id: int
    display_name: str
    recovery_secret: SecretStr
    region_id: str = "north"
    account_code: str = "acct-internal-001"


class MemoryRepository:
    """Deterministic typed repository used by the Admin route tests."""

    def __init__(self) -> None:
        self.items: dict[int, Account] = {}

    async def get(self, key: int) -> Account | None:
        """Look up one account."""
        return self.items.get(key)

    async def list(self, *, limit: int = 100) -> tuple[Account, ...]:
        """Return deterministic key order with the requested bound."""
        return tuple(self.items[key] for key in sorted(self.items)[:limit])

    async def add(self, entity: Account) -> None:
        """Insert one unique account."""
        if entity.id in self.items:
            raise RepositoryConflictError
        self.items[entity.id] = entity

    async def update(self, entity: Account) -> bool:
        """Replace one existing account."""
        if entity.id not in self.items:
            return False
        self.items[entity.id] = entity
        return True

    async def delete(self, key: int) -> bool:
        """Delete one account by its typed key."""
        return self.items.pop(key, None) is not None


def _resource(repository: MemoryRepository) -> AdminResource[Account, int]:
    """Create an explicit resource policy that keeps recovery secrets private."""

    async def atomic_update(key: int, patch: dict[str, object]) -> Account | None:
        """Apply the validated patch inside one fake repository operation."""
        existing = await repository.get(key)
        if existing is None:
            return None
        values = existing.model_dump(mode="python")
        values.update(patch)
        entity = Account.model_validate(values)
        await repository.update(entity)
        return entity

    return AdminResource(
        name="accounts",
        model=Account,
        repository=repository,
        key_field="id",
        read_fields=frozenset({"id", "display_name"}),
        create_fields=frozenset({"id", "display_name", "recovery_secret"}),
        update_fields=frozenset({"display_name"}),
        update_handler=atomic_update,
        allow_delete=True,
    )


def _application(
    repository: MemoryRepository,
    roles: tuple[str, ...] = ("orbit.admin.read", "orbit.admin.write"),
    max_body_bytes: int = 1_048_576,
    audit_log: AdminAuditSink | None = None,
    resource: AdminResource[Account, int] | None = None,
    delta_audit: object | None = None,
    csrf_secret: bytes | None = None,
) -> tuple[Application, ASGIApplication, AdminPlugin]:
    """Compose the plugin with explicit read/write Basic credentials and TLS enforcement."""
    application = Application(ApplicationConfig(name="admin-test", max_body_bytes=max_body_bytes))
    plugin = AdminPlugin(
        [resource or _resource(repository)],
        audit_log=audit_log,
        delta_audit=delta_audit,
        csrf_secret=csrf_secret,
    )
    application.plugins.register(plugin)
    credential = BasicCredential.create(
        "operator",
        "correct horse battery staple",
        roles=roles,
    )
    runtime = ASGIApplication(
        application,
        authenticator=BasicAuthenticator([credential]),
        authorizer=RoleAuthorizer(),
    )
    return application, runtime, plugin


async def test_admin_resource_catalog_is_available_in_orbit_cli() -> None:
    """The CLI reviews allowlisted resource counts without fetching records."""
    plugin = AdminPlugin([_resource(MemoryRepository())])

    result = await plugin.control_actions[0].handler({})

    assert result is not None
    assert result.summary == "Admin resource catalog is configured."
    assert "resource_count: 1" in result.details
    assert all("recovery_secret" not in item for item in result.details)

    application = Application(ApplicationConfig(name="admin-cli-overview"))
    application.register_plugin(plugin)
    await application.configure()
    overview = await plugin.control_actions[1].handler({})
    assert overview is not None and overview.succeeded
    assert "registered_services: 0" in overview.details
    await application.stop()


class MemoryDeltaAuditSink:
    """Capture operation snapshots and provide stable IDs for route integration tests."""

    def __init__(self) -> None:
        self.changes: list[tuple[str, str, Account | None, Account | None]] = []

    async def record_change(
        self,
        action: str,
        target: str,
        before: Account | None,
        after: Account | None,
    ) -> str:
        """Retain one test snapshot and return its opaque reference."""
        self.changes.append((action, target, before, after))
        return "change-123"


async def test_encrypted_delta_mode_uses_authoritative_handler_snapshots() -> None:
    """Require atomic snapshots for writes and link the object ID from operation metadata."""
    repository = MemoryRepository()
    before = Account(id=1, display_name="Before", recovery_secret=SecretStr("hidden"))
    repository.items[1] = before

    async def mutate(
        action: str,
        key: int | None,
        payload: BaseModel | dict[str, object],
    ) -> AdminMutationSnapshot:
        """Perform the mutation and return states observed by that one operation."""
        assert action == "crud.update"
        assert key == 1
        existing = repository.items[key]
        values = existing.model_dump(mode="python")
        values.update(payload)  # type: ignore[arg-type]
        after = Account.model_validate(values)
        repository.items[key] = after
        return AdminMutationSnapshot(before=existing, after=after)

    resource = replace(_resource(repository), delta_mutation_handler=mutate)
    sink = MemoryDeltaAuditSink()
    _, runtime, plugin = _application(repository, resource=resource, delta_audit=sink)

    async with TestClient(runtime, scheme="https") as client:
        response = await client.request(
            "PUT",
            "/admin-api/v1/resources/accounts/1",
            headers=_headers(),
            body=json.dumps({"display_name": "After"}).encode(),
        )

    assert response.status == 200
    assert sink.changes == [("crud.update", "accounts", before, repository.items[1])]
    record = plugin.audit_log.records[-1]
    assert record.target == "accounts#delta=change-123"


async def test_delta_persistence_failure_returns_sanitized_retry_guidance() -> None:
    """Do not expose sink failures or imply a mutation rolled back when audit persistence fails."""
    repository = MemoryRepository()
    before = Account(id=1, display_name="Before", recovery_secret=SecretStr("hidden"))
    repository.items[1] = before

    async def mutate(
        action: str,
        key: int | None,
        payload: BaseModel | dict[str, object],
    ) -> AdminMutationSnapshot:
        """Commit one update before the external audit object store fails."""
        assert action == "crud.update"
        assert key == 1
        values = repository.items[key].model_dump(mode="python")
        values.update(payload)  # type: ignore[arg-type]
        after = Account.model_validate(values)
        repository.items[key] = after
        return AdminMutationSnapshot(before=before, after=after)

    class FailingDeltaAuditSink:
        """Simulate a storage provider failure containing private implementation details."""

        async def record_change(
            self,
            action: str,
            target: str,
            before: Account | None,
            after: Account | None,
        ) -> str:
            """Fail after the application's mutation handler has completed."""
            del action, target, before, after
            raise RuntimeError("secret bucket name and credentials")

    resource = replace(_resource(repository), delta_mutation_handler=mutate)
    _, runtime, _ = _application(
        repository,
        resource=resource,
        delta_audit=FailingDeltaAuditSink(),
    )
    async with TestClient(runtime, scheme="https") as client:
        response = await client.request(
            "PUT",
            "/admin-api/v1/resources/accounts/1",
            headers=_headers(),
            body=json.dumps({"display_name": "After"}).encode(),
        )

    assert response.status == 503
    assert b"admin.audit-unavailable" in response.body
    assert b"verify resource state before retrying" in response.body
    assert b"secret bucket name" not in response.body
    assert repository.items[1].display_name == "After"


def test_encrypted_delta_mode_requires_atomic_mutation_snapshots() -> None:
    """Fail configuration early if any enabled write lacks its authoritative snapshot hook."""
    repository = MemoryRepository()
    with pytest.raises(ValueError, match="atomic delta_mutation_handler"):
        _application(repository, delta_audit=MemoryDeltaAuditSink())


def _headers() -> dict[str, str]:
    """Return explicit test-only HTTPS Basic credentials."""
    import base64

    raw = base64.b64encode(b"operator:correct horse battery staple").decode("ascii")
    return {"authorization": f"Basic {raw}", "content-type": "application/json"}


async def test_browser_mutation_requires_identity_bound_csrf_token() -> None:
    """Require a fresh token for ambient browser credentials before changing a record."""
    repository = MemoryRepository()
    _, runtime, _ = _application(repository, csrf_secret=b"a" * 32)
    origin = "https://admin.example.test"
    async with TestClient(runtime, scheme="https") as client:
        denied = await client.request(
            "POST",
            "/admin-api/v1/resources/accounts",
            headers={**_headers(), "origin": origin},
            body=json.dumps({"id": 2, "display_name": "Denied", "recovery_secret": "x"}).encode(),
        )
        assert denied.status == 403
        assert repository.items == {}

        issued = await client.request(
            "GET",
            "/admin-api/v1/csrf-token",
            headers={**_headers(), "origin": origin},
        )
        assert issued.status == 200
        assert issued.headers["cache-control"] == "no-store"
        token = issued.json()["token"]

        accepted = await client.request(
            "POST",
            "/admin-api/v1/resources/accounts",
            headers={
                **_headers(),
                "origin": origin,
                "x-orbit-csrf-token": token,
            },
            body=json.dumps({"id": 2, "display_name": "Allowed", "recovery_secret": "x"}).encode(),
        )

    assert accepted.status == 201
    assert repository.items[2].display_name == "Allowed"


async def test_browser_mutation_fails_closed_without_configured_csrf_secret() -> None:
    """Ambient cookies or Origin never authorize writes when CSRF protection is not enabled."""
    repository = MemoryRepository()
    _, runtime, _ = _application(repository)
    async with TestClient(runtime, scheme="https") as client:
        response = await client.request(
            "POST",
            "/admin-api/v1/resources/accounts",
            headers={**_headers(), "cookie": "orbit_session=present"},
            body=json.dumps({"id": 2, "display_name": "Denied", "recovery_secret": "x"}).encode(),
        )
    assert response.status == 403
    assert repository.items == {}


async def test_read_routes_require_auth_and_only_serialize_allowed_fields() -> None:
    repository = MemoryRepository()
    repository.items[1] = Account(
        id=1,
        display_name="Ada",
        recovery_secret=SecretStr("do-not-show"),
    )
    _, runtime, _ = _application(repository)

    async with TestClient(runtime, scheme="https") as client:
        anonymous = await client.request("GET", "/admin-api/v1/resources/accounts")
        anonymous_catalog = await client.request("GET", "/admin-api/v1/resources")
        catalog = await client.request("GET", "/admin-api/v1/resources", headers=_headers())
        assert anonymous.status == 401
        listed = await client.request(
            "GET",
            "/admin-api/v1/resources/accounts?limit=1",
            headers=_headers(),
        )
        item = await client.request(
            "GET",
            "/admin-api/v1/resources/accounts/1",
            headers=_headers(),
        )

    assert listed.json() == {"items": [{"id": 1, "display_name": "Ada"}]}
    assert item.json() == {"item": {"id": 1, "display_name": "Ada"}}
    assert anonymous_catalog.status == 401
    assert catalog.json() == {
        "items": [{"name": "accounts", "read_fields": ["display_name", "id"]}]
    }
    assert catalog.headers["cache-control"] == "no-store"
    assert "do-not-show" not in listed.body.decode()


async def test_browser_write_capabilities_require_write_role_and_csrf_configuration() -> None:
    repository = MemoryRepository()
    _, writer_runtime, _ = _application(repository, csrf_secret=b"c" * 32)
    _, reader_runtime, _ = _application(
        repository,
        roles=("orbit.admin.read",),
        csrf_secret=b"c" * 32,
    )
    async with TestClient(writer_runtime, scheme="https") as writer_client:
        anonymous = await writer_client.request("GET", "/admin-api/v1/write-capabilities")
        writer = await writer_client.request(
            "GET", "/admin-api/v1/write-capabilities", headers=_headers()
        )
    async with TestClient(reader_runtime, scheme="https") as reader_client:
        reader = await reader_client.request(
            "GET", "/admin-api/v1/write-capabilities", headers=_headers()
        )

    assert anonymous.status == 401
    assert reader.status == 403
    assert writer.status == 200
    assert writer.headers["cache-control"] == "no-store"
    assert writer.json() == {
        "items": [
            {
                "name": "accounts",
                "key_field": "id",
                "create_fields": ["display_name", "id", "recovery_secret"],
                "update_fields": ["display_name"],
                "allow_delete": True,
            }
        ]
    }

    _, csrf_disabled_runtime, _ = _application(repository)
    async with TestClient(csrf_disabled_runtime, scheme="https") as client:
        disabled = await client.request(
            "GET", "/admin-api/v1/write-capabilities", headers=_headers()
        )
    assert disabled.status == 404


async def test_field_permissions_omit_columns_unless_the_authenticated_role_allows_them() -> None:
    repository = MemoryRepository()
    repository.items[1] = Account(
        id=1,
        display_name="Ada",
        recovery_secret=SecretStr("do-not-show"),
    )
    resource = replace(
        _resource(repository),
        read_fields=frozenset({"id", "display_name", "account_code"}),
        field_permissions={"account_code": "accounts.account-code.read"},
        field_authorizer=PermissionAuthorizer(
            {"orbit.admin.sensitive": {"accounts.account-code.read"}}
        ),
    )
    _, runtime, _ = _application(repository, resource=resource)

    async with TestClient(runtime, scheme="https") as client:
        denied = await client.request(
            "GET", "/admin-api/v1/resources/accounts/1", headers=_headers()
        )
        denied_catalog = await client.request("GET", "/admin-api/v1/resources", headers=_headers())

    assert denied.status == 200
    assert denied.json() == {"item": {"id": 1, "display_name": "Ada"}}
    assert denied_catalog.json() == {
        "items": [{"name": "accounts", "read_fields": ["display_name", "id"]}]
    }
    assert "acct-internal-001" not in denied.body.decode()

    _, privileged_runtime, _ = _application(
        repository,
        roles=("orbit.admin.read", "orbit.admin.write", "orbit.admin.sensitive"),
        resource=resource,
    )
    async with TestClient(privileged_runtime, scheme="https") as client:
        allowed = await client.request(
            "GET", "/admin-api/v1/resources/accounts/1", headers=_headers()
        )
        allowed_catalog = await client.request("GET", "/admin-api/v1/resources", headers=_headers())

    assert allowed.json() == {
        "item": {"id": 1, "display_name": "Ada", "account_code": "acct-internal-001"}
    }
    assert allowed_catalog.json() == {
        "items": [{"name": "accounts", "read_fields": ["account_code", "display_name", "id"]}]
    }


def test_field_permission_can_bind_a_verified_claim_to_server_loaded_record_scope() -> None:
    repository = MemoryRepository()
    entity = Account(
        id=2,
        display_name="Lin",
        recovery_secret=SecretStr("hidden"),
        region_id="north",
    )
    resource = replace(
        _resource(repository),
        read_fields=frozenset({"id", "display_name", "account_code"}),
        field_permissions={"account_code": "accounts.account-code.read"},
        field_authorizer=PermissionAuthorizer(
            {"regional-support": {"accounts.account-code.read"}},
            attribute_bindings={"accounts.account-code.read": {"region_id": "region_id"}},
        ),
        authorization_context_fields=frozenset({"region_id"}),
    )
    matching = Principal(
        identity=Identity(subject="support-1", provider="internal", claims={"region_id": "north"}),
        roles=frozenset({"regional-support"}),
    )
    mismatched = Principal(
        identity=Identity(subject="support-2", provider="internal", claims={"region_id": "south"}),
        roles=frozenset({"regional-support"}),
    )

    assert "account_code" not in resource.visible_read_fields(matching)
    assert resource.serialize(entity, subject=matching)["account_code"] == "acct-internal-001"
    assert "account_code" not in resource.serialize(entity, subject=mismatched)


def test_resource_copies_mutable_field_policy_inputs() -> None:
    repository = MemoryRepository()
    readable = {"id", "display_name", "account_code"}
    scoped = {"region_id"}
    field_permissions = {"account_code": "accounts.account-code.read"}
    resource = replace(
        _resource(repository),
        read_fields=readable,
        field_permissions=field_permissions,
        field_authorizer=PermissionAuthorizer({"support": {"accounts.account-code.read"}}),
        authorization_context_fields=scoped,
    )
    readable.clear()
    scoped.clear()
    field_permissions.clear()

    assert resource.read_fields == frozenset({"id", "display_name", "account_code"})
    assert resource.authorization_context_fields == frozenset({"region_id"})
    assert resource.field_permissions == {"account_code": "accounts.account-code.read"}


async def test_operations_console_is_installed_by_the_admin_plugin_and_role_protected() -> None:
    repository = MemoryRepository()
    _, runtime, _ = _application(repository)
    async with TestClient(runtime, scheme="https") as client:
        anonymous = await client.request("GET", "/admin")
        overview = await client.request("GET", "/admin", headers=_headers())
        state = await client.request("GET", "/admin/state", headers=_headers())
    assert anonymous.status == 401
    assert overview.status == 200
    assert b"Orbit Administration" in overview.body
    assert overview.headers["cache-control"] == "no-store"
    assert state.status == 200
    assert state.json()["service_names"] == []


async def test_operations_rate_limit_is_owned_by_the_admin_plugin() -> None:
    application = Application(ApplicationConfig(name="admin-rate-test"))
    application.plugins.register(AdminOperationsPlugin(rate_limit=1, rate_period=60))
    runtime = ASGIApplication(
        application,
        authenticator=BasicAuthenticator(
            [
                BasicCredential.create(
                    "operator", "correct horse battery staple", roles=("orbit.admin.read",)
                )
            ]
        ),
        authorizer=RoleAuthorizer(),
    )
    async with TestClient(runtime, scheme="https") as client:
        first = await client.request("GET", "/admin", headers=_headers())
        second = await client.request("GET", "/admin", headers=_headers())
    assert first.status == 200
    assert second.status == 429
    assert "retry-after" in second.headers


async def test_admin_operations_overview_is_available_in_orbit_cli() -> None:
    """The CLI overview uses local Core state and does not issue an HTTP request."""
    application = Application(ApplicationConfig(name="admin-control-room-test"))
    plugin = AdminOperationsPlugin()
    application.register_plugin(plugin)
    await application.configure()

    result = await plugin.control_actions[0].handler({})

    assert result is not None
    assert result.summary == "Admin operations overview is ready."
    assert "registered_services: 0" in result.details
    await application.stop()


@pytest.mark.asyncio
async def test_operations_retry_after_uses_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    application = Application(ApplicationConfig(name="admin-retry-after"))
    admin = AdminApplication(application, audit_log=AdminAuditLog(), rate_limit=1, rate_period=60)
    monkeypatch.setattr(
        admin._rate_limiter,
        "check",
        lambda key: RateLimitResult(False, 0, 1.0001),
    )

    response = await admin.handle(Request("GET", "/admin/state"))

    assert response.status == 429
    assert response.headers["retry-after"] == "2"


async def test_mutations_are_field_limited_and_payload_free_audited() -> None:
    repository = MemoryRepository()
    _, runtime, plugin = _application(repository)

    async with TestClient(runtime, scheme="https") as client:
        created = await client.request(
            "POST",
            "/admin-api/v1/resources/accounts",
            headers=_headers(),
            body=json.dumps(
                {"id": 7, "display_name": "Grace", "recovery_secret": "private"}
            ).encode(),
        )
        updated = await client.request(
            "PUT",
            "/admin-api/v1/resources/accounts/7",
            headers=_headers(),
            body=b'{"display_name":"Grace Hopper"}',
        )
        deleted = await client.request(
            "DELETE",
            "/admin-api/v1/resources/accounts/7",
            headers=_headers(),
        )

    assert created.status == 201
    assert created.json() == {"item": {"id": 7, "display_name": "Grace"}}
    assert updated.json() == {"item": {"id": 7, "display_name": "Grace Hopper"}}
    assert deleted.status == 204
    assert len(plugin.audit_log.records) == 3
    assert [record.action for record in plugin.audit_log.records] == [
        "crud.create",
        "crud.update",
        "crud.delete",
    ]
    assert all(
        record.target == "accounts" and record.success for record in plugin.audit_log.records
    )
    assert "private" not in repr(plugin.audit_log.records)


async def test_crud_mutations_reject_browser_origin_requests() -> None:
    repository = MemoryRepository()
    repository.items[7] = Account(
        id=7,
        display_name="Existing",
        recovery_secret=SecretStr("private"),
    )
    _, runtime, plugin = _application(repository)
    browser_headers = {**_headers(), "origin": "https://attacker.example"}

    async with TestClient(runtime, scheme="https") as client:
        created = await client.request(
            "POST",
            "/admin-api/v1/resources/accounts",
            headers=browser_headers,
            body=b'{"id":8,"display_name":"Injected","recovery_secret":"private"}',
        )
        updated = await client.request(
            "PUT",
            "/admin-api/v1/resources/accounts/7",
            headers=browser_headers,
            body=b'{"display_name":"Injected"}',
        )
        deleted = await client.request(
            "DELETE",
            "/admin-api/v1/resources/accounts/7",
            headers=browser_headers,
        )

    assert [response.status for response in (created, updated, deleted)] == [403, 403, 403]
    assert all(
        response.json()["code"] == "security.csrf" for response in (created, updated, deleted)
    )
    assert set(repository.items) == {7}
    assert repository.items[7].display_name == "Existing"
    assert not plugin.audit_log.records


async def test_crud_plugin_can_use_durable_sql_audit_sink() -> None:
    repository = MemoryRepository()
    database = SQLiteDatabase(":memory:")
    audit_log = SQLAdminAuditLog(database, max_records=10)
    _, runtime, _ = _application(repository, audit_log=audit_log)

    async with TestClient(runtime, scheme="https") as client:
        response = await client.request(
            "POST",
            "/admin-api/v1/resources/accounts",
            headers=_headers(),
            body=json.dumps(
                {"id": 9, "display_name": "Katherine", "recovery_secret": "private"}
            ).encode(),
        )

    records = await audit_log.recent(limit=10)
    await database.aclose()

    assert response.status == 201
    assert len(records) == 1
    assert records[0].action == "crud.create"
    assert records[0].target == "accounts"
    assert records[0].success is True
    assert "private" not in repr(records[0])


async def test_admin_api_rejects_unknown_fields_and_unbounded_limits() -> None:
    _, runtime, _ = _application(MemoryRepository())

    async with TestClient(runtime, scheme="https") as client:
        unknown_field = await client.request(
            "POST",
            "/admin-api/v1/resources/accounts",
            headers=_headers(),
            body=b'{"id":1,"display_name":"Lin","recovery_secret":"x","is_admin":true}',
        )
        too_large = await client.request(
            "GET",
            "/admin-api/v1/resources/accounts?limit=101",
            headers=_headers(),
        )

    assert unknown_field.status == 400
    assert unknown_field.json()["code"] == "admin.fields"
    assert too_large.status == 400
    assert too_large.json()["code"] == "admin.limit"


async def test_write_body_and_serialized_response_are_bounded() -> None:
    repository = MemoryRepository()
    repository.items[9] = Account(
        id=9,
        display_name="x" * 2_100_000,
        recovery_secret=SecretStr("private"),
    )
    _, runtime, _ = _application(repository, max_body_bytes=2_000_000)

    async with TestClient(runtime, scheme="https") as client:
        oversized_write = await client.request(
            "POST",
            "/admin-api/v1/resources/accounts",
            headers=_headers(),
            body=b" " * (1_048_577),
        )
        oversized_read = await client.request(
            "GET",
            "/admin-api/v1/resources/accounts/9",
            headers=_headers(),
        )

    assert oversized_write.status == 413
    assert oversized_write.json()["code"] == "admin.body-too-large"
    assert oversized_read.status == 413
    assert oversized_read.json()["code"] == "admin.response-too-large"


async def test_read_role_cannot_mutate_resources() -> None:
    _, runtime, _ = _application(MemoryRepository(), roles=("orbit.admin.read",))

    async with TestClient(runtime, scheme="https") as client:
        denied = await client.request(
            "POST",
            "/admin-api/v1/resources/accounts",
            headers=_headers(),
            body=b'{"id":1,"display_name":"Lin","recovery_secret":"secret"}',
        )

    assert denied.status == 403
    assert denied.json()["code"] == "security.forbidden"


def test_admin_plugin_accepts_an_explicit_shared_audit_log() -> None:
    audit_log = AdminAuditLog(capacity=2)
    plugin = AdminPlugin([_resource(MemoryRepository())], audit_log=audit_log)
    assert plugin.audit_log is audit_log


def test_read_only_resource_does_not_register_mutation_routes() -> None:
    repository = MemoryRepository()
    readonly = AdminResource(
        name="accounts",
        model=Account,
        repository=repository,
        key_field="id",
        read_fields=frozenset({"id", "display_name"}),
    )
    application = Application(ApplicationConfig(name="readonly-admin"))
    application.plugins.register(AdminPlugin([readonly]))
    application.plugins.setup(application)

    methods = application.router.allowed_methods("/admin-api/v1/resources/accounts")
    assert "GET" in methods
    assert not {"POST", "PUT", "DELETE"} & set(methods)


def test_updates_require_an_explicit_atomic_handler() -> None:
    repository = MemoryRepository()
    with pytest.raises(ValueError, match="atomic update_handler"):
        AdminResource(
            name="accounts",
            model=Account,
            repository=repository,
            key_field="id",
            read_fields=frozenset({"id", "display_name"}),
            update_fields=frozenset({"display_name"}),
        )
