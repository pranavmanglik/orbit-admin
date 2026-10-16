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
"""Optional authenticated operational console for Orbit Core applications."""

from __future__ import annotations

import html
import json
import logging
import re
from collections.abc import Mapping
from dataclasses import asdict
from math import ceil

from orbit.application import Application
from orbit.application import ApplicationSummary as AdminOverview
from orbit.asgi.request import Headers, HTTPError, Request
from orbit.asgi.response import Response
from orbit.diagnostics import inspect_composition
from orbit.plugins import ControlAction, ControlResult, Plugin, PluginMetadata
from orbit_security import RateLimiter
from pydantic import BaseModel

from orbit_admin.audit import AdminAuditLog, AdminAuditRecord, AdminAuditSink
from orbit_admin.http_security import has_explicit_non_browser_authorization

_LOG = logging.getLogger(__name__)
_ADMIN_TARGET_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")


def _audit_error_code(error: Exception) -> str:
    """Return a valid audit identifier without trusting custom exception attributes."""
    problem = getattr(error, "problem", None)
    code = getattr(problem, "code", None)
    if isinstance(code, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,126}", code):
        return code
    name = type(error).__name__
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name):
        return name
    return "operation.failed"


class AdminApplication:
    """Render a protected administrative dashboard and structured inspection endpoints."""

    def __init__(
        self,
        application: Application,
        *,
        audit_log: AdminAuditSink,
        rate_limit: int,
        rate_period: float,
    ) -> None:
        self._application = application
        self._audit_log = audit_log
        self._rate_limiter = RateLimiter(rate_limit, rate_period)

    async def overview(self) -> AdminOverview:
        """Build an overview from public application state; route roles protect this view."""
        return AdminOverview(
            state=self._application.state.application,
            service_names=tuple(d.name for d in self._application.services.descriptors),
        )

    async def _audit_records(self) -> tuple[AdminAuditRecord, ...]:
        """Return an optional bounded audit view when the injected sink supports reads."""
        recent = getattr(self._audit_log, "recent", None)
        if not callable(recent):
            return ()
        records = await recent(limit=100)
        if not isinstance(records, tuple) or any(
            not isinstance(record, AdminAuditRecord) for record in records
        ):
            return ()
        return records

    async def handle(self, request: Request) -> Response:
        """Serve authenticated HTML/JSON views or explicitly authorized operational commands."""
        client = request.client_host or "unknown-client"
        decision = self._rate_limiter.check(client)
        if not decision.allowed:
            response = Response.json(
                {"code": "security.rate-limited", "retry_after": decision.retry_after},
                status=429,
            )
            if not isinstance(response.headers, Headers):
                raise TypeError("Responses must expose validated headers.")
            return Response(
                response.status,
                response.body,
                {**response.headers, "retry-after": str(max(1, ceil(decision.retry_after)))},
            )
        overview = await self.overview()
        service_prefix = "/admin/services/"
        task_prefix = "/admin/tasks/"
        if request.method == "POST" and request.path.startswith(task_prefix):
            if not has_explicit_non_browser_authorization(request):
                raise HTTPError(
                    403, "security.csrf", "Explicit non-browser authorization required."
                )
            remainder = request.path[len(task_prefix) :].strip("/")
            name, separator, action = remainder.rpartition("/")
            if not separator or action != "restart" or not name:
                return Response.json({"code": "tasks.invalid-operation"}, status=400)
            if _ADMIN_TARGET_NAME.fullmatch(name) is None:
                return Response.json({"code": "tasks.invalid-name"}, status=400)
            try:
                await self._application.restart_task(name)
            except KeyError:
                await self._audit_log.record(
                    "task.restart", target=name, success=False, error_code="tasks.not-found"
                )
                return Response.json({"code": "tasks.not-found"}, status=404)
            except Exception as exc:
                await self._audit_log.record(
                    "task.restart",
                    target=name,
                    success=False,
                    error_code=_audit_error_code(exc),
                )
                raise
            await self._audit_log.record("task.restart", target=name, success=True)
            return Response.json({"status": "restarted", "task": name})
        if request.method == "POST" and request.path.startswith(service_prefix):
            if not has_explicit_non_browser_authorization(request):
                raise HTTPError(
                    403, "security.csrf", "Explicit non-browser authorization required."
                )
            remainder = request.path[len(service_prefix) :].strip("/")
            name, separator, action = remainder.rpartition("/")
            if not separator or action not in {"start", "stop", "restart", "reload"}:
                return Response.json({"code": "services.invalid-operation"}, status=400)
            if not name or _ADMIN_TARGET_NAME.fullmatch(name) is None:
                return Response.json({"code": "services.invalid-name"}, status=400)
            try:
                if action == "start":
                    await self._application.start_service(name)
                elif action == "stop":
                    await self._application.stop_service(name)
                elif action == "restart":
                    await self._application.restart_service(name)
                else:
                    await self._application.reload_service(name)
            except KeyError:
                await self._audit_log.record(
                    f"service.{action}", target=name, success=False, error_code="services.not-found"
                )
                return Response.json({"code": "services.not-found"}, status=404)
            except Exception as exc:
                await self._audit_log.record(
                    f"service.{action}",
                    target=name,
                    success=False,
                    error_code=_audit_error_code(exc),
                )
                raise
            status = {
                "start": "started",
                "stop": "stopped",
                "restart": "restarted",
                "reload": "reloaded",
            }[action]
            await self._audit_log.record(f"service.{action}", target=name, success=True)
            return Response.json({"status": status, "service": name})
        if request.method == "POST" and request.path == "/admin/health/refresh":
            # No ambient cookie-only authority for mutations. Browsers with a hostile Origin
            # are rejected even when a custom authenticator also accepts cookies.
            if not has_explicit_non_browser_authorization(request):
                raise HTTPError(
                    403, "security.csrf", "Explicit non-browser authorization required."
                )
            try:
                report = await self._application.health()
            except Exception as exc:
                await self._audit_log.record(
                    "health.refresh",
                    success=False,
                    error_code=_audit_error_code(exc),
                )
                raise
            await self._audit_log.record("health.refresh", success=True)
            return Response.json(report)
        if request.method not in {"GET", "HEAD"}:
            return Response(status=405, headers={"allow": "GET, HEAD"})
        composition = inspect_composition(self._application).model_dump(mode="json")
        views: dict[str, object] = {
            "/admin/lifecycle": [
                transition.model_dump(mode="json")
                for transition in self._application.lifecycle.history
            ],
            "/admin/audit": [
                record.model_dump(mode="json") for record in await self._audit_records()
            ],
            "/admin/health": {
                "status": self._application.state.application.health,
                "history": [
                    report.model_dump(mode="json") for report in self._application.health_history
                ],
                "services": [
                    {"name": state.name, "status": state.health}
                    for state in self._application.state.application.services
                ],
            },
            "/admin/diagnostics": self._application.diagnostics.collect(
                self._application
            ).model_dump(mode="json"),
            "/admin/state": overview.model_dump(mode="json"),
            "/admin/config": composition["configuration"],
            "/admin/services": composition["services"],
            "/admin/plugins": composition["plugins"],
            "/admin/routes": composition["routes"],
            "/admin/dependencies": composition["dependencies"],
            "/admin/events": [
                {
                    "id": str(d.event_id),
                    "name": d.name,
                    "subscribers": d.subscriber_count,
                    "failures": d.failures,
                }
                for d in self._application.events.history
            ],
            "/admin/tasks": [
                {
                    "name": task.name,
                    "state": task.state,
                    "attempts": task.attempts,
                    "last_failure": (
                        asdict(task.last_failure) if task.last_failure is not None else None
                    ),
                }
                for task in self._application.tasks.infos
            ],
        }
        headers = {
            "cache-control": "no-store",
            "x-frame-options": "DENY",
            "content-security-policy": (
                "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
            ),
        }
        for name in self._application.admin_contributions:
            path = "/admin/extensions/" + name
            if request.path in {"/admin", "/admin/", path}:
                try:
                    view = await self._application.inspect_admin_contribution(name)
                    if view is None:
                        raise TimeoutError("Administrative extension inspection is still pending.")
                    if not isinstance(view, BaseModel):
                        raise TypeError("Admin contributions must return Pydantic models.")
                    views[path] = view.model_dump(mode="json")
                except Exception:
                    _LOG.exception("Administrative extension inspection failed")
                    views[path] = {"status": "unavailable", "code": "admin.extension-failed"}
        if request.path in views:
            response = Response.json(views[request.path])
            return Response(
                response.status, response.body, {**headers, "content-type": "application/json"}
            )
        if request.path not in {"/admin", "/admin/"}:
            return Response.json({"code": "routing.route-not-found"}, status=404)
        name = html.escape(self._application.config.application.name)
        sections = "".join(
            "<section><h2>"
            + html.escape(path.removeprefix("/admin/").title())
            + "</h2><pre>"
            + html.escape(json.dumps(value, indent=2))
            + "</pre></section>"
            for path, value in views.items()
        )
        body = (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            "<title>Orbit Administration</title><style>"
            "body{font:16px system-ui;background:#111827;color:#e5e7eb;"
            "margin:2rem auto;max-width:1000px}h1{color:#a5b4fc}"
            "section{padding:1rem;background:#1f2937;margin:1rem 0;border-radius:8px}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}"
            "</style></head><body><h1>Orbit · " + name + "</h1>"
            "<p>Application state, services and runtime diagnostics</p>"
            + sections
            + "</body></html>"
        )
        return Response(200, body.encode(), {**headers, "content-type": "text/html; charset=utf-8"})


class AdminOperationsPlugin(Plugin):
    """Install bounded, authenticated operations views and commands under ``/admin``."""

    metadata = PluginMetadata(
        name="orbit-admin-operations",
        version="0.1.0a1",
        capabilities=frozenset({"admin.operations"}),
    )

    def __init__(
        self,
        *,
        audit_log: AdminAuditSink | None = None,
        rate_limit: int = 120,
        rate_period: float = 60.0,
    ) -> None:
        """Configure the per-process request limit and optional shared audit sink."""
        if (
            isinstance(rate_limit, bool)
            or not isinstance(rate_limit, int)
            or not 1 <= rate_limit <= 100_000
        ):
            raise ValueError("rate_limit must be from 1 through 100,000.")
        if (
            isinstance(rate_period, bool)
            or not isinstance(rate_period, (int, float))
            or not 0 < rate_period <= 86_400
        ):
            raise ValueError("rate_period must be greater than 0 and at most 86,400 seconds.")
        self._audit_log = audit_log if audit_log is not None else AdminAuditLog()
        if not isinstance(self._audit_log, AdminAuditSink):
            raise TypeError("audit_log must implement AdminAuditSink.")
        self._rate_limit = rate_limit
        self._rate_period = float(rate_period)
        self._console: AdminApplication | None = None
        self.control_actions = (
            ControlAction(
                id="review-operations-overview",
                title="Review Admin operations overview",
                description=(
                    "Show local application and service counts without making HTTP requests."
                ),
                handler=self._review_overview,
            ),
        )

    def setup(self, application: Application) -> None:
        """Register exact Admin routes with deny-by-default Core role metadata."""
        if not isinstance(application, Application):
            raise TypeError("AdminOperationsPlugin requires an Orbit Application.")
        console = AdminApplication(
            application,
            audit_log=self._audit_log,
            rate_limit=self._rate_limit,
            rate_period=self._rate_period,
        )
        self._console = console
        read_paths = (
            "/admin",
            "/admin/",
            "/admin/lifecycle",
            "/admin/audit",
            "/admin/health",
            "/admin/diagnostics",
            "/admin/state",
            "/admin/config",
            "/admin/services",
            "/admin/plugins",
            "/admin/routes",
            "/admin/dependencies",
            "/admin/events",
            "/admin/tasks",
            "/admin/extensions/{name}",
        )
        for index, path in enumerate(read_paths):

            async def read_view(
                request: Request, *, _console: AdminApplication = console
            ) -> Response:
                return await _console.handle(request)

            application.router.route(
                path,
                method="GET",
                name=f"admin-operations-read-{index}",
                roles=frozenset({"orbit.admin.read"}),
            )(read_view)
        writes = (
            ("/admin/health/refresh", "admin-operations-health-refresh"),
            ("/admin/tasks/{name}/restart", "admin-operations-task-restart"),
            ("/admin/services/{name}/{action}", "admin-operations-service-action"),
        )

        for path, name in writes:

            async def write_operation(
                request: Request, *, _console: AdminApplication = console
            ) -> Response:
                return await _console.handle(request)

            application.router.route(
                path,
                method="POST",
                name=name,
                roles=frozenset({"orbit.admin.write"}),
            )(write_operation)

    async def _review_overview(self, _: Mapping[str, object]) -> ControlResult:
        """Read the same bounded application summary used by the protected Admin overview."""
        if self._console is None:
            return ControlResult("Admin operations plugin is not configured.", succeeded=False)
        overview = await self._console.overview()
        return ControlResult(
            "Admin operations overview is ready.",
            (
                f"application_state: {overview.state}",
                f"registered_services: {len(overview.service_names)}",
            ),
        )


__all__ = ["AdminOperationsPlugin"]
