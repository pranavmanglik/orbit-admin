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
"""Shared request checks for browser-originated Admin mutations."""

from orbit.asgi.request import Headers, Request


def has_explicit_non_browser_authorization(request: Request) -> bool:
    """Require one nonempty Authorization field and reject browser Origin requests.

    Core's authenticator and route authorizer remain responsible for validating credentials and
    roles. This additional check prevents ambient browser credentials from authorizing cross-site
    state changes through Admin mutation endpoints.
    """
    if not isinstance(request.headers, Headers):
        raise TypeError("Admin mutations require Core Headers.")
    authorization = request.headers.getall("authorization")
    return (
        len(authorization) == 1
        and bool(authorization[0].strip())
        and not request.headers.getall("origin")
    )


__all__ = ["has_explicit_non_browser_authorization"]
