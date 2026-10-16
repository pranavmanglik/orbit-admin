# Orbit Admin for Python

`orbit-admin-python` is the optional Admin capability package for Orbit. It installs protected
operations views, payload-free auditing, and authenticated CRUD routes for explicitly configured
Pydantic repositories. It is distributed from the `python/` subdirectory of the `orbit-admin`
repository; the TypeScript dashboard remains an independent npm package at the repository root.

```bash
python -m pip install -e '.[dev]'
python -m pytest
ruff check .
ruff format --check .
mypy
```

The package depends directly on `orbit-core`, `orbit-auth`, `orbit-security`, `orbit-data`, and `orbit-sql`.
Database drivers remain separate provider packages. Configure and install the provider that matches
the application, then pass its `SQLDatabase` resource to `sql_resource` or provide an
`orbit-data.Repository` implementation directly. Core does not activate Admin routes or carry
Admin configuration.

## Explicit resource policy

```python
from orbit import Application, ApplicationConfig
from orbit_admin import AdminPlugin, sql_resource
from orbit.runtime import Runtime
from orbit_auth import BasicAuthenticator, BasicCredential, RoleAuthorizer

application = Application(ApplicationConfig(name="admin-service"))
accounts = sql_resource(
    "accounts",
    database,
    Account,
    table="accounts",
    key_field="id",
    read_fields=frozenset({"id", "display_name"}),
    create_fields=frozenset({"id", "display_name", "recovery_secret"}),
)
application.plugins.register(AdminPlugin([accounts]))
application.plugins.setup(application)
credential = BasicCredential.create(
    operator_name,
    operator_password_from_secret_store,
    roles=("orbit.admin.read", "orbit.admin.write"),
)
runtime = Runtime(
    application,
    authenticator=BasicAuthenticator([credential]),
    authorizer=RoleAuthorizer(),
)
```

Basic authentication must be explicitly configured with hashed credentials and requires HTTPS by
default. There are no built-in users. Do not keep passwords in source code or committed settings.
The static-user mechanism does not supply account recovery, federation, MFA, or session lifecycle;
production deployments should use a suitable identity provider and secret-rotation process.

Browser-originated CRUD remains disabled unless the plugin receives a random secret of at least
32 bytes through `AdminPlugin(..., csrf_secret=...)`. The plugin then exposes a role-protected,
no-store `/admin-api/v1/csrf-token` endpoint; send its short-lived token in
`X-Orbit-CSRF-Token` for create, update, and delete requests. Load the secret from a secret manager,
share it across application workers, keep the UI same-origin over HTTPS, and restrict credentialed
CORS to exact trusted origins. Without this option, ambient cookies and browser `Origin` requests
cannot mutate resources.

When this option is enabled, the TypeScript dashboard exposes browser CRUD controls only to
operators who also have `orbit.admin.write`. The protected write-capability route publishes the
explicit writable fields; the UI requests a fresh CSRF token for each mutation. It uses bounded JSON
object editors rather than deriving forms from a database schema. Edit and delete controls appear
only when the configured key field is present in the server-serialized row, so include the key in
`read_fields` when those controls are needed.

Every resource declares its response and create fields. Fields such as password hashes or internal
flags stay private unless explicitly included in `read_fields`; writes accept only the declared
allowlists. Update routes are disabled unless an application supplies an `update_handler` that
performs an atomic or optimistic-concurrency-safe update. Deletes are disabled by default. Lists
are capped at 100 rows; this initial `orbit-data.Repository` contract does not yet provide cursor
pagination. Routes require `orbit.admin.read` for reads and `orbit.admin.write` for mutations.

Mutations append bounded, payload-free records to the Admin package's process-local audit history
by default. That history is lost on process restart and differs across workers. For durable storage,
pass `SQLAdminAuditLog` backed by an application-owned `SQLDatabase`:

```python
from orbit_admin import AdminPlugin, SQLAdminAuditLog
from orbit_sql import SQL_DATABASE_KEY

database = await application.container.aresolve(SQL_DATABASE_KEY)
audit_log = SQLAdminAuditLog(database, max_records=1_000_000)
await audit_log.initialize()
application.plugins.register(AdminPlugin(resources, audit_log=audit_log))
```

The SQL sink stores no request body, entity values, resource key, credential, or secret. It keeps a
bounded newest-first history and prunes older rows transactionally. The database resource remains
owned and closed by the application. An audit insert follows its resource mutation; the shared SQL
transaction contract does not make those two operations atomic, so deployments requiring a
tamper-evident, transactionally coupled ledger need a dedicated audit design. Protect the audit
table with database permissions and backups. No live MySQL or PostgreSQL audit integration is
claimed.

### Encrypted state-diff audit

For deployments that need encrypted before/after snapshots, install the `encrypted-audit` extra
and configure `EncryptedObjectDeltaAuditSink` with an application-owned `orbit-storage` object
store, a 32-byte AES-256 key, and a stable key identifier. There are no generated or default keys.
The sink writes each bounded (1 MiB maximum) JSON snapshot as an async stream encrypted with
AES-256-GCM, using a fresh random nonce and authenticating the operation and resource name. A
consumer must verify the GCM tag before using any plaintext and must resolve the key identifier
through its secret manager. Rotate keys by changing the key identifier and retaining authorized
access to old keys for the required audit retention period; follow the deployment's cryptographic
policy and rotate well before 2^32 records per key because this sink uses random 96-bit nonces.

Pass the sink as `AdminPlugin(..., delta_audit=sink)`. Each writable `AdminResource` must then
provide a `delta_mutation_handler` that performs the mutation and returns
`AdminMutationSnapshot(before=..., after=...)` from the same repository transaction or from a
provider-specific compare-and-swap operation. The `sql_resource` factory accepts this handler
through its `delta_mutation_handler` argument, so SQL-backed resources can use the same audited
mutation contract. This avoids presenting a separate pre-read as the authoritative state changed
by an update. The operation audit record links to the encrypted object
through an opaque delta identifier appended to its `target` field. The encrypted object write
happens after the mutation handler completes, however, so a process crash or storage failure can
still leave an unrecorded mutation. Use an application-owned transactional outbox to close that
failure window. The sink
provides authenticated encryption, not an append-only hash chain; configure object versioning,
retention lock, least-privilege access, and independent backups when the deployment needs stronger
tamper resistance. The resource database and object store do not share a transaction.

If the delta sink fails after the mutation handler completes, the route returns
`503 admin.audit-unavailable` with guidance to verify the resource state before retrying. This
response does not mean the mutation rolled back. Sink exceptions and provider details are not
returned to the client; instrument the application boundary to record sanitized operational
context and alert on audit persistence failures.

## Operations API and security

`AdminPlugin(resources)` registers both the operations console and CRUD routes. Use
`AdminPlugin(resources, operations=False)` to omit the console, or install `AdminOperationsPlugin`
for operations views without CRUD resources. The operations endpoints are `/admin`, `/admin/state`,
`/admin/services`, `/admin/tasks`, `/admin/plugins`, `/admin/routes`, `/admin/dependencies`,
`/admin/config`, `/admin/lifecycle`, `/admin/health`, `/admin/diagnostics`, `/admin/events`,
`/admin/audit`, and `/admin/extensions/{name}`. Health refresh, service actions, and task restart
are explicit POST operations.

All read routes require `orbit.admin.read`; mutations require `orbit.admin.write`. Core's router
fails closed unless an authenticator and `RouteAuthorizer` are configured. Mutations require one
nonempty Authorization header and reject browser Origin headers. The operations console enforces a
bounded process-local rate limit (120 requests per 60 seconds by default) and returns `429` with
`Retry-After` when full. It is not a distributed quota. Responses are non-cacheable and mutation
audit records omit credentials, request bodies, entity values, and resource keys.

The package is an unpublished v0.1.0-alpha review candidate. Python tests cover operations routes,
auth/role enforcement, local rate limits, CRUD field allowlists, SQLite audit persistence, and
encrypted-delta authentication. The local CPython 3.11–3.14 matrix passes 64 tests per version,
Ruff lint/format, strict mypy, wheel/source builds, and pip-audit. Hosted CI, live MySQL/PostgreSQL
audit verification, transactional outbox integration for guaranteed audit delivery, production
browser/auth proxy review, external key management and object-retention validation, production load,
and the hosted package release process remain open gates. Local checks do not certify production
readiness.

Licensed under Apache-2.0.
