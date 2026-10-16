# Orbit Admin

`@orbit-projects/orbit-admin` provides an authenticated TypeScript Admin dashboard and an optional
Python plugin for operations and explicitly configured repository resources. The browser package
is installed and deployed separately; it does not add routes, credentials, dependencies, or a UI
framework to Orbit Core.

## Build the static dashboard

```bash
npm ci
npm test
npm run typecheck
npm run build
```

The deployable site is written to `dist/`. Serve it at a same-origin path such as `/orbit-admin/`
and proxy `/admin/*` and `/admin-api/v1/resources/*` to the same Orbit application. Same-origin
deployment avoids adding CORS or a cross-site credential path. The package makes only allowlisted
GET requests and caps each response at 1 MiB by default.

Enable Core Admin explicitly with `ApplicationConfig(admin_enabled=True)` and configure an
authenticator that grants `orbit.admin.read` only to approved operators. Core enables no default
identity or credentials. The dashboard never asks for, stores, or persists passwords, bearer
tokens, or session secrets. On a 401 it links to `/admin/state`, where the configured authenticator
can perform its normal browser sign-in or challenge. Basic Auth requires HTTPS; use trusted TLS
termination and Core's documented proxy configuration when TLS ends before the app.

The UI renders returned data with DOM `textContent`, not HTML interpolation; errors do not display
remote response bodies. Its requests use `credentials: "same-origin"`, `cache: "no-store"`, reject
redirects, require JSON responses, and enforce a streamed byte limit. Keep HTTPS, Core's
authorization policy, rate limits, and response redaction enabled. The static server or reverse
proxy should also send `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, and a strict
content security policy.

## Current scope

The dashboard provides Core operations views and tables for resources explicitly exposed by the
Python plugin. It requests at most 100 records per resource and renders only server-returned fields
as text. Browser create, edit, and delete controls appear only when the authenticated operator has
the write role and the Python plugin has CSRF protection enabled; writes use explicit JSON
field allowlists. The dashboard is not an identity manager or replacement for Core's server-rendered
Admin fallback.

When the Python plugin is registered, Orbit CLI provides **Review Admin resource catalog** and
**Review Admin operations overview** actions. They show allowlisted resource counts, endpoint policy,
and local service counts without fetching records, making HTTP requests, or exposing field values.

This repository provides two independent packages: the TypeScript dashboard at the root and an
optional Python plugin in `python/`. The Python package owns the operations API and explicitly
configured repository CRUD routes; it depends directly on Core, `orbit-auth`, `orbit-auth-rbac`,
`orbit-security`, `orbit-data`, and `orbit-sql`. Core provides runtime composition and stable
extension contracts. The Python package does not start a separate process or add a web framework,
and supports field-level role/row-scope filtering, bounded SQL audit history, and opt-in encrypted
state-diff audit objects through `orbit-storage`. Encrypted audit mode requires application-owned
atomic mutation handlers and does not make an object-store write atomic with the resource database.

Both packages are unpublished v0.1.0-alpha review candidates. The Python package has local SQLite
coverage for its SQL audit sink and AES-GCM tamper detection. Its CPython 3.11–3.14 tests, lint,
formatting, strict type checks, package builds, and dependency audits pass locally; the dashboard
typecheck, build, tests, and npm audit pass locally on Node.js 24.21.0. Hosted CI, live SQL provider coverage,
transactional outbox integration, production browser/auth proxy review, external key management,
object-retention validation, and production load evidence remain open release gates.

## Documentation

The package-specific guides cover [architecture](docs/architecture/overview.md), [operations and security](docs/operations/README.md), and [development](docs/development/README.md), with [security guidance](docs/security/overview.md). The [documentation index](docs/README.md) links to the full package overview and project policies.

## License

Apache-2.0.
