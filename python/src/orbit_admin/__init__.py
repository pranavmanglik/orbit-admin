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
"""Python Admin capability plugin for Orbit Core applications."""

from orbit_admin.audit import AdminAuditLog, AdminAuditRecord, AdminAuditSink, SQLAdminAuditLog
from orbit_admin.audit_delta import AdminDeltaAuditSink, EncryptedObjectDeltaAuditSink
from orbit_admin.client import AdminClient, AdminClientError, AdminHTTPResponse, AdminTransport
from orbit_admin.csrf import AdminCSRFProtector
from orbit_admin.errors import AdminAuditPersistenceError
from orbit_admin.operations import AdminOperationsPlugin
from orbit_admin.plugin import AdminPlugin
from orbit_admin.resources import AdminMutationSnapshot, AdminResource, sql_resource

__all__ = [
    "AdminAuditLog",
    "AdminAuditRecord",
    "AdminAuditSink",
    "AdminAuditPersistenceError",
    "AdminDeltaAuditSink",
    "EncryptedObjectDeltaAuditSink",
    "AdminClient",
    "AdminClientError",
    "AdminCSRFProtector",
    "AdminHTTPResponse",
    "AdminTransport",
    "AdminPlugin",
    "AdminOperationsPlugin",
    "AdminMutationSnapshot",
    "AdminResource",
    "SQLAdminAuditLog",
    "sql_resource",
]
