# Orbit Admin: development

This package declares support for `>=3.11,<3.15` in `python/pyproject.toml`. That declaration is distinct from evidence that hosted CI ran.

Use the checks for each language manifest present in this repository:

### Python package

```bash
cd python
python -m pip install -e '.[dev]' build
pip-audit --skip-editable --progress-spinner off
pytest
ruff check src tests
ruff format --check src tests
mypy
```
### TypeScript package

```bash
npm ci
npm run typecheck
npm run test
npm run build
npm audit
npm audit --omit=dev
```

Optional SDKs and live-service tests are described by the package README. Do not run an opt-in live test against a shared or production service unless its own documentation explicitly supports that use.

## Contribution expectations

Add focused regression coverage for behavior changes. Update the README and relevant guide when a contract, configuration option, security property, lifecycle rule, or operational assumption changes. Report the exact versions and services exercised; local checks do not imply hosted CI or release validation.

The TypeScript package's dependency audit, typecheck, production build, and 9 tests passed on
2026-10-10 using Node.js 24.21.0 and npm 11.19.0. Re-run both audit commands when changing its
manifest or lockfile; this local result does not replace hosted supply-chain checks.

The Python Admin package passed 64 tests per interpreter, Ruff lint/format, strict mypy, dependency
auditing, and wheel/sdist builds on CPython **3.11.14, 3.12.14, 3.13.15, and 3.14.7** against local Core, Auth,
Security, Data, SQL, SQLite, and Testing checkouts. Its in-process requests use `scheme="https"` to
exercise the default TLS requirement of Basic Auth; this does not validate real TLS termination or
deployment proxy configuration.
