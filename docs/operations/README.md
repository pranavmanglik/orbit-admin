# Orbit Admin: operations

The repository ships two independently installed components: a static TypeScript dashboard and an
optional Python package. There are no package-defined `ORBIT_*` runtime variables; configure the
Core application, credentials, provider database, and deployment ingress directly.

## TypeScript dashboard

Build and deploy the static package separately from Core:

```bash
npm ci
npm run build
```

The browser client calls the host's same-origin `/admin` API and `/admin-api/v1/resources` catalog.
Configure a reverse proxy or static hosting path so both API prefixes reach the intended application
and the dashboard assets remain protected by the deployment's administrative network policy.
Validate forwarded host/protocol handling, HTTPS termination, allowed origins, and redirects in the
real proxy configuration. The client rejects redirects and non-JSON API responses; do not redirect
authenticated API calls to a login HTML page and expect the dashboard to interpret it. Resource
tables show only server-returned fields and request the first 100 rows. When CSRF writes are enabled,
an operator must have `orbit.admin.write`; the dashboard requests the separate write-capability
endpoint, obtains a fresh token for each mutation, and submits JSON objects through the server's
field allowlist. The editor does not infer field types from database schemas, so model validation
remains authoritative.

## Python plugin setup

Install `orbit-admin-python` with compatible `orbit-core`, `orbit-auth`, `orbit-auth-rbac`,
`orbit-security`, `orbit-data`, and `orbit-sql` packages. Install one SQL provider separately when using `sql_resource`
or the SQL audit sink. Configure an authenticator and route authorizer in the host `ASGIApplication`.
Register `AdminPlugin(resources)` for operations views plus explicitly defined CRUD, or set
`operations=False`; use `AdminOperationsPlugin` when only the Core operations views are needed.

The operations API exposes these routes:

- `/admin`
- `/admin/state`
- `/admin/services`
- `/admin/tasks`
- `/admin/plugins`
- `/admin/routes`
- `/admin/dependencies`
- `/admin/config`
- `/admin/lifecycle`
- `/admin/health`
- `/admin/diagnostics`
- `/admin/events`
- `/admin/audit`
- `/admin/extensions/{name}`

Health refresh and operational actions use these explicit POST routes:

- `/admin/health/refresh`
- `/admin/services/{name}/start`
- `/admin/services/{name}/stop`
- `/admin/services/{name}/restart`
- `/admin/services/{name}/reload`
- `/admin/tasks/{name}/restart`

Resource routes are under `/admin-api/v1/resources/{name}`. Read requests require
`orbit.admin.read`; write requests require `orbit.admin.write`. By default, non-browser writes must
provide one nonempty Authorization header and requests with `Origin` or ambient `Cookie` headers
are rejected. To enable browser writes, configure `AdminPlugin(..., csrf_secret=...)`; the
authenticated `/admin-api/v1/csrf-token` route returns a no-store, identity-bound token for the
`X-Orbit-CSRF-Token` header. Keep the UI same-origin, use HTTPS, configure the same secret across
workers, and allow only trusted CORS origins. Operations rate limiting defaults to 120 requests per
60 seconds per client key in each process.

When CSRF is configured and at least one resource is writable, `GET /admin-api/v1/write-capabilities`
is available to `orbit.admin.write` operators. It returns only configured create/update fields,
delete flags, and resource key names; the route is absent when browser writes are disabled. The UI
uses this response to build JSON editors and shows row actions only when a returned record contains
its configured key field.

Sensitive response fields can be given `field_permissions` backed by an
`orbit-auth-rbac.PermissionAuthorizer`. Unapproved fields are omitted from JSON serialization. For
tenant/row checks, configure `authorization_context_fields` to use fields from the
repository-loaded model and bind trusted `Principal.identity.claims` to those resource fields. Never
derive authorization context from request-supplied values.

## Lifecycle and audit storage

The application owns SQL provider lifecycle. Initialize `SQLAdminAuditLog` before accepting Admin
mutations, and close its `SQLDatabase` during application shutdown. The sink creates its namespaced
table on initialization and transactionally prunes older records to its configured retention
ceiling. The sink does not close the application-owned database.

The default audit sink is process-local and bounded. It is suitable only when losing history on
restart and maintaining separate histories per worker are acceptable. SQL persistence improves
durability but does not couple audit writes atomically to resource changes. Configure database
backups, retention, and operator access to match the deployment's audit requirements.

## Limits and release validation

Python CRUD writes are limited to 1 MiB; encoded responses are limited to 2 MiB; list pages are
limited to 100 entities. The browser client defaults to a 1 MiB response ceiling. Operations
rate-limits are process-local and do not combine across workers. Test the selected limits and
monitor 403, 413, and 429 responses under expected administrative traffic.

Before release, verify auth and role policy, CSRF behavior through the deployed proxy, TLS and
forwarded-header trust, browser compatibility, SQL permissions and backups, and startup/shutdown
ordering. A passing local suite does not validate hosted CI, live database compatibility, or
production topology.
