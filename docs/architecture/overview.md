# Orbit Admin: architecture and boundaries

## Responsibility

`@orbit-projects/orbit-admin` provides a TypeScript dashboard for Orbit operations and explicitly
configured business resources, plus an optional Python plugin that registers the matching APIs. The
browser package is installed and deployed separately; it does not add routes, credentials,
dependencies, or a UI framework to Core.

## Declared dependencies

The following dependency declarations come from the checked-in manifests. Optional groups and development dependencies are called out separately.

### `python/pyproject.toml`
- `orbit-core>=0.1.0a1,<0.2`
- `orbit-auth>=0.1.0a1,<0.2`
- `orbit-security>=0.1.0a1,<0.2`
- `orbit-data>=0.1.0a1,<0.2`
- `orbit-sql>=0.1.0a1,<0.2`
- `pydantic>=2.8,<3`
- Optional `dev` group: `pytest>=8,<10`, `pytest-asyncio>=0.24,<2`, `ruff>=0.8,<1`, `mypy>=1.13,<2`, `orbit-testing>=0.1.0a1,<0.2`, `orbit-sql-sqlite>=0.1.0a1,<0.2`.
### `package.json`
- `typescript (development)`

Declared dependencies do not mean that optional providers or services are bundled with this package.

## Implementation layout

Representative implementation files in this checkout:

- `python/src/orbit_admin/__init__.py`
- `python/src/orbit_admin/_safety.py`
- `python/src/orbit_admin/audit.py`
- `python/src/orbit_admin/client.py`
- `python/src/orbit_admin/operations.py`
- `python/src/orbit_admin/plugin.py`
- `python/src/orbit_admin/resources.py`
- `src/admin-client.ts`
- `src/main.ts`

## Current scope

The dashboard provides application state, services, tasks, plugins, routes, dependencies,
configuration, lifecycle, health, diagnostics, events, and administrative audit views. It also
lists configured Python resources and displays a bounded first page using the fields serialized by
the server. When browser writes are explicitly enabled, it offers create, update, and delete forms
using the Python plugin's write-field allowlists and identity-bound CSRF tokens. It does not expose
Core operational controls. It is not an analytics warehouse, identity manager, or replacement for
Core's server-rendered Admin fallback.

This repository provides two independent packages: the TypeScript dashboard at the root and an
optional Python plugin in `python/`. The Python package depends directly on Core, `orbit-auth`,
`orbit-auth-rbac`, `orbit-security`, `orbit-data`, and `orbit-sql`; it adds explicitly configured
repository CRUD routes, field-level RBAC filtering, and an optional SQL audit sink. It does not
start a separate process or add a web framework.
Core still owns the transitional `/admin` operations API and authentication internals; their
extraction remains open under ADR 0022.

Both packages are unpublished v0.1.0-alpha review candidates. The Python package passes 64 local
tests per CPython 3.11–3.14 version, plus lint, formatting, strict type checks, package builds, and
dependency audit. It has local SQLite coverage for its SQL audit sink, but no live SQL provider matrix
or production load evidence. Browser compatibility, reverse-proxy behavior, and production
authentication have not been exercised in this checkpoint.

## Request and dependency boundaries

The browser package calls Core's existing authenticated operations routes using same-origin GET
requests. It does not register routes or expose operational mutations. The Python plugin registers
Core routes carrying `orbit.admin.read` or `orbit.admin.write` role requirements; the host supplies
the authenticator and route authorizer. Non-browser writes require explicit Authorization. Browser
CRUD writes are opt-in through an identity-bound CSRF token and are rejected if no CSRF secret is
configured.

For CRUD, the application explicitly composes `AdminResource` values over `orbit-data.Repository`
implementations. `sql_resource` is a convenience over `orbit-sql.SQLDatabase`; the SQL provider
remains a separate package and owns its connection lifecycle. `SQLAdminAuditLog` uses that same
application-owned database resource but does not own or close it. Audit persistence and resource
mutation are not atomic as a unit.

`AdminResource.read_fields` is the outer exposure allowlist. Optional `field_permissions` require an
`orbit-auth-rbac.PermissionAuthorizer`; denied fields are omitted before Pydantic response
serialization. `authorization_context_fields` selects server-loaded model fields passed as resource
attributes for tenant/row policies. Those values never come from the write or query request.

Keep the static dashboard, route plugin, auth/role contracts, repository interfaces, SQL provider,
and application composition at these package boundaries. Do not infer a durable audit ledger,
database-driver integration, or identity provider from the Admin package itself.
