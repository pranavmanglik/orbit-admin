# Orbit Admin: security

This repository contains two separate packages with different trust boundaries: a browser dashboard
with opt-in CSRF-protected resource writes and an optional Python Admin plugin. The dashboard does
not add an authentication system. The Python plugin registers routes whose authentication and role
checks are enforced by the host Orbit Core application.

## Browser dashboard

The TypeScript client sends same-origin `GET` requests with same-origin credentials and rejects
redirects and non-JSON responses. When browser writes are enabled, it uses same-origin `POST`, `PUT`,
and `DELETE` requests with a fresh CSRF token for each mutation. Requests disable caching and response
bodies are limited to 1 MiB by default (configurable up to 16 MiB). It displays bounded server error
codes and does not render remote error bodies or response data as HTML. Protect the Core Admin API
with the host application's authenticator and authorizer; hiding the dashboard does not protect the
endpoints.

The dashboard does not send service-control requests. Resource CRUD controls appear only when the
authenticated operator has the write role and the server exposes CSRF protection. The browser gets a
fresh identity-bound token for each mutation and sends it in `X-Orbit-CSRF-Token`. The server filters
each row before serialization; catalog metadata omits fields that require record-specific
authorization. Serve it over HTTPS and publish it only on an administrative network boundary
appropriate to the sensitivity of the runtime configuration, diagnostics, and business data shown by
Admin.

## Python plugin

`AdminPlugin` exposes only resources explicitly supplied by the application. `read_fields`,
`create_fields`, and `update_fields` are independent allowlists; delete routes are off by default,
and updates require an application-supplied atomic handler. Reads require `orbit.admin.read` and
writes require `orbit.admin.write`. The host must configure both an authenticator and a route
authorizer. The recommended Basic Auth setup uses explicit hashed credentials and HTTPS; this
package provides no default account, password, or identity provider.

By default, every Python mutation route requires exactly one nonempty `Authorization` header and
rejects requests carrying an `Origin` or ambient `Cookie` before parsing the body or calling the
repository. Core still validates the credential and role. To support browser mutations, pass a
random secret of at least 32 bytes as `AdminPlugin(..., csrf_secret=...)`. The plugin exposes
`GET /admin-api/v1/csrf-token` to users with `orbit.admin.write`; the no-store token expires after
10 minutes by default, is bound to the verified provider and subject, and must be sent in the
`X-Orbit-CSRF-Token` header. Configure the same secret across workers and rotate it through a
secret manager. Token rotation revokes existing tokens.

Keep the Admin UI same-origin over HTTPS and configure CORS with exact trusted origins. Do not
allow untrusted origins to read credentialed CSRF-token responses. Browser mutations still require
Core authentication and role authorization; CSRF protection does not replace either control or a
production identity provider.

Request bodies are capped at 1 MiB and serialized Admin responses at 2 MiB. List routes return at
most 100 rows and do not yet expose cursor pagination. The operations view rate limit is local to a
process. It does not replace ingress abuse protection.

## Audit and sensitive data

The default audit history is bounded, process-local, and lost at restart. The SQL audit sink stores
operation metadata without request bodies, entity values, credentials, resource keys, or secrets;
its database and audit table still require appropriate access control and backups. An audit insert is
not atomic with the resource mutation. Use a separately reviewed transactional ledger when that
guarantee is required.

Encrypted state-diff storage can also fail after the resource mutation completes. Admin responds with
`503 admin.audit-unavailable`, without exposing provider details, and instructs the caller to verify
resource state before retrying. This is not a rollback guarantee. Use a transactional outbox when
every committed mutation must eventually have a durable audit record.

Avoid logging credentials, authorization headers, request bodies, entity contents, or raw provider
errors. `AdminResource.read_fields` is a static allowlist; use `field_permissions` for
role-sensitive columns and `authorization_context_fields` for server-loaded row/tenant checks. A
denied field is omitted from the serialized model. RBAC field checks receive only the selected
context fields from the fetched entity, never values copied out of a client request. Review which
Core diagnostics and configuration fields are visible to Admin readers.

## Vulnerability disclosure

Use this repository's [security policy](../../SECURITY.md) to report vulnerabilities privately.
