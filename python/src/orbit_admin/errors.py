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
"""Structured errors exposed by Orbit Admin capability boundaries."""

from orbit.errors import ErrorCategory, OrbitError, OrbitProblem


class AdminAuditPersistenceError(OrbitError):
    """Raised when an Admin audit record cannot be safely persisted."""

    def __init__(self) -> None:
        """Create a sanitized persistence error without retaining provider exception text."""
        super().__init__(
            OrbitProblem(
                code="admin.audit-persistence",
                message="Admin audit persistence failed.",
                category=ErrorCategory.PLUGIN,
            )
        )


__all__ = ["AdminAuditPersistenceError"]
