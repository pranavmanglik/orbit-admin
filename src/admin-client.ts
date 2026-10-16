/** Fixed Core Admin routes available to the dashboard client. */
export const ADMIN_SECTIONS = {
  state: { label: "Application", path: "/state", icon: "◈" },
  services: { label: "Services", path: "/services", icon: "▦" },
  tasks: { label: "Background tasks", path: "/tasks", icon: "⌁" },
  plugins: { label: "Plugins", path: "/plugins", icon: "⬡" },
  routes: { label: "Routes", path: "/routes", icon: "⇄" },
  dependencies: { label: "Dependencies", path: "/dependencies", icon: "⌘" },
  config: { label: "Configuration", path: "/config", icon: "⚙" },
  lifecycle: { label: "Lifecycle", path: "/lifecycle", icon: "◷" },
  health: { label: "Health", path: "/health", icon: "♡" },
  diagnostics: { label: "Diagnostics", path: "/diagnostics", icon: "⌗" },
  events: { label: "Events", path: "/events", icon: "◌" },
  audit: { label: "Admin audit", path: "/audit", icon: "▤" },
} as const;

export type AdminSection = keyof typeof ADMIN_SECTIONS;
export type AdminData = Record<string, unknown> | unknown[];
export type AdminResource = { name: string; read_fields: string[] };
export type AdminResourceRow = Record<string, unknown>;
export type AdminWriteCapability = {
  name: string;
  key_field: string;
  create_fields: string[];
  update_fields: string[];
  allow_delete: boolean;
};

const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;
const ERROR_CODE_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]{0,126}$/;
const RESOURCE_NAME_PATTERN = /^[a-z][a-z0-9-]{0,62}$/;
const RESOURCE_FIELD_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const MAX_RESOURCE_FIELDS = 512;
const MAX_RESOURCE_ROWS = 100;

export class AdminClientError extends Error {
  readonly status: number;
  readonly code: string;

  /** A safe application-facing error; remote response bodies are never stored here. */
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "AdminClientError";
    this.status = status;
    this.code = code;
  }
}

function validateApiBase(apiBase: string): string {
  if (
    typeof apiBase !== "string" ||
    !/^\/(?:[A-Za-z0-9_-]+)(?:\/[A-Za-z0-9_-]+)*\/?$/.test(apiBase) ||
    apiBase.length > 128
  ) {
    throw new TypeError("Admin API base must be a bounded same-origin path.");
  }
  return apiBase.replace(/\/$/, "");
}

function isResourceField(value: unknown): value is string {
  return typeof value === "string" && RESOURCE_FIELD_PATTERN.test(value);
}

function resourceKeySegment(value: string | number): string {
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new TypeError("Admin resource key must be finite.");
  }
  const key = String(value);
  if (
    key.length < 1 || key.length > 255 || key === "." || key === ".." ||
    /[\/?#\\\u0000-\u001f\u007f]/.test(key)
  ) {
    throw new TypeError("Admin resource key is not a safe path segment.");
  }
  try {
    return encodeURIComponent(key);
  } catch {
    throw new TypeError("Admin resource key is not a valid path segment.");
  }
}

function validatedWriteValues(values: unknown, allowedFields: string[]): Record<string, unknown> {
  if (
    typeof values !== "object" || values === null || Array.isArray(values) ||
    (Object.getPrototypeOf(values) !== Object.prototype && Object.getPrototypeOf(values) !== null)
  ) {
    throw new TypeError("Admin write data must be a JSON object.");
  }
  const entries = Object.entries(values);
  if (entries.length === 0 || entries.length > MAX_RESOURCE_FIELDS) {
    throw new TypeError("Admin write data must contain a bounded set of fields.");
  }
  const allowed = new Set(allowedFields);
  if (entries.some(([field]) => !allowed.has(field))) {
    throw new TypeError("Admin write data contains a field outside the server allowlist.");
  }
  return values as Record<string, unknown>;
}

async function readBoundedBody(response: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    if (!/^\d{1,10}$/.test(declared) || Number(declared) > maxBytes) {
      await response.body?.cancel();
      throw new AdminClientError(502, "admin.response-too-large", "Admin response is too large.");
    }
  }
  if (response.body === null) return new Uint8Array();

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      total += item.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new AdminClientError(
          502,
          "admin.response-too-large",
          "Admin response is too large.",
        );
      }
      chunks.push(item.value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function parseErrorCode(body: Uint8Array): string {
  try {
    const decoded: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
    if (
      typeof decoded === "object" &&
      decoded !== null &&
      "code" in decoded &&
      typeof decoded.code === "string" &&
      ERROR_CODE_PATTERN.test(decoded.code)
    ) {
      return decoded.code;
    }
  } catch {
    // Do not copy remote error bodies into the browser UI.
  }
  return "admin.request-failed";
}

/**
 * Create a same-origin client for the fixed Admin operations and resource API routes.
 *
 * Requests use GET, same-origin credentials, no cache, and reject redirects. Response bodies are
 * bounded while streaming; only validated error codes are read from error JSON, never its message.
 * Resource writes require the server's explicit field allowlist and a fresh CSRF token. This client
 * does not store credentials or implement authentication itself.
 */
export function createAdminClient(
  fetcher: typeof fetch = fetch,
  apiBase = "/admin",
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  resourceApiBase = "/admin-api/v1",
) {
  const base = validateApiBase(apiBase);
  const resourceBase = validateApiBase(resourceApiBase);
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 128 || maxResponseBytes > 16_777_216) {
    throw new RangeError("Admin response limit must be between 128 bytes and 16 MiB.");
  }

  async function getJson(path: string, unavailableMessage: string): Promise<AdminData> {
    let response: Response;
    try {
      response = await fetcher(path, {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        mode: "same-origin",
        referrerPolicy: "same-origin",
        headers: { accept: "application/json" },
      });
    } catch {
      throw new AdminClientError(0, "admin.unavailable", "Orbit Admin API is unavailable.");
    }
    const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (response.redirected || mediaType !== "application/json") {
      await response.body?.cancel();
      throw new AdminClientError(502, "admin.invalid-response", "Admin returned an invalid response.");
    }
    const body = await readBoundedBody(response, maxResponseBytes);
    if (!response.ok) {
      const code = parseErrorCode(body);
      if (response.status === 401) {
        throw new AdminClientError(401, code, "Authentication is required to view this section.");
      }
      if (response.status === 403) {
        throw new AdminClientError(403, code, "Your account cannot view this section.");
      }
      throw new AdminClientError(response.status, code, unavailableMessage);
    }
    try {
      const result: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
      if (typeof result !== "object" || result === null) throw new TypeError();
      return result as AdminData;
    } catch {
      throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid JSON.");
    }
  }

  async function writeJson(
    path: string,
    method: "POST" | "PUT" | "DELETE",
    csrfToken: string,
    values?: Record<string, unknown>,
  ): Promise<AdminResourceRow | null> {
    if (typeof csrfToken !== "string" || csrfToken.length < 1 || csrfToken.length > 160) {
      throw new TypeError("Admin writes require a bounded CSRF token.");
    }
    let encoded: string | undefined;
    if (values !== undefined) {
      encoded = JSON.stringify(values);
      if (new TextEncoder().encode(encoded).byteLength > 1_048_576) {
        throw new AdminClientError(413, "admin.body-too-large", "Admin write data is too large.");
      }
    }
    let response: Response;
    try {
      response = await fetcher(path, {
        method,
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        mode: "same-origin",
        referrerPolicy: "same-origin",
        headers: {
          accept: "application/json",
          "x-orbit-csrf-token": csrfToken,
          ...(encoded === undefined ? {} : { "content-type": "application/json" }),
        },
        ...(encoded === undefined ? {} : { body: encoded }),
      });
    } catch {
      throw new AdminClientError(
        0,
        "admin.unavailable",
        "The connection ended before Admin confirmed the change. Refresh and verify its state before retrying.",
      );
    }
    if (response.redirected) {
      await response.body?.cancel();
      throw new AdminClientError(502, "admin.invalid-response", "Admin returned an invalid response.");
    }
    if (method === "DELETE" && response.status === 204) {
      await response.body?.cancel();
      return null;
    }
    const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (mediaType !== "application/json") {
      await response.body?.cancel();
      throw new AdminClientError(502, "admin.invalid-response", "Admin returned an invalid response.");
    }
    const body = await readBoundedBody(response, maxResponseBytes);
    if (!response.ok) {
      const code = parseErrorCode(body);
      if (response.status === 401) {
        throw new AdminClientError(401, code, "Authentication is required to change this resource.");
      }
      if (response.status === 403) {
        throw new AdminClientError(403, code, "Your account cannot change this resource.");
      }
      if (code === "admin.audit-unavailable") {
        throw new AdminClientError(
          response.status,
          code,
          "The change may have completed. Refresh and verify resource state before retrying.",
        );
      }
      const message = response.status >= 500
        ? "Admin could not confirm the change. Refresh and verify resource state before retrying."
        : "Admin rejected the resource change.";
      throw new AdminClientError(response.status, code, message);
    }
    try {
      const decoded: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
      if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) throw new TypeError();
      const item = (decoded as Record<string, unknown>)["item"];
      if (typeof item !== "object" || item === null || Array.isArray(item)) throw new TypeError();
      return item as AdminResourceRow;
    } catch {
      throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid resource data.");
    }
  }

  return {
    /** Fetch one allowlisted Admin section and return its decoded JSON object or array. */
    async read(section: AdminSection): Promise<AdminData> {
      const definition = ADMIN_SECTIONS[section];
      if (definition === undefined) throw new TypeError("Unknown Admin section.");
      return await getJson(`${base}${definition.path}`, "Admin could not load this section.");
    },

    /** Load the server-authorized catalog without exposing row-scoped field names. */
    async listResources(): Promise<AdminResource[]> {
      const result = await getJson(`${resourceBase}/resources`, "Admin could not load resources.");
      if (Array.isArray(result)) {
        throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid resources.");
      }
      const body = result as Record<string, unknown>;
      const rawItems = body["items"];
      if (!Array.isArray(rawItems) || rawItems.length > 1000) {
        throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid resources.");
      }
      const names = new Set<string>();
      return rawItems.map((item): AdminResource => {
        if (typeof item !== "object" || item === null || Array.isArray(item)) {
          throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid resources.");
        }
        const resource = item as Record<string, unknown>;
        const name = resource["name"];
        const rawFields = resource["read_fields"];
        if (
          typeof name !== "string" || !RESOURCE_NAME_PATTERN.test(name) || names.has(name) ||
          !Array.isArray(rawFields) || rawFields.length > MAX_RESOURCE_FIELDS ||
          rawFields.some((field) => typeof field !== "string" || !RESOURCE_FIELD_PATTERN.test(field))
        ) {
          throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid resources.");
        }
        const fields = rawFields as string[];
        if (new Set(fields).size !== fields.length) {
          throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid resources.");
        }
        names.add(name);
        return { name, read_fields: [...fields] };
      });
    },

    /** Read at most one bounded page from a previously authorized resource collection. */
    async readResource(name: string): Promise<AdminResourceRow[]> {
      if (typeof name !== "string" || !RESOURCE_NAME_PATTERN.test(name)) {
        throw new TypeError("Admin resource name must be a lowercase slug.");
      }
      const result = await getJson(
        `${resourceBase}/resources/${name}?limit=${MAX_RESOURCE_ROWS}`,
        "Admin could not load this resource.",
      );
      if (Array.isArray(result)) {
        throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid resource data.");
      }
      const body = result as Record<string, unknown>;
      const rows = body["items"];
      if (!Array.isArray(rows) || rows.length > MAX_RESOURCE_ROWS) {
        throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid resource data.");
      }
      return rows.map((row): AdminResourceRow => {
        if (typeof row !== "object" || row === null || Array.isArray(row)) {
          throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid resource data.");
        }
        return row as AdminResourceRow;
      });
    },

    /** Fetch write controls only for operators whose route authorizer grants the write role. */
    async listWriteCapabilities(): Promise<AdminWriteCapability[]> {
      const result = await getJson(
        `${resourceBase}/write-capabilities`,
        "Admin write capabilities are unavailable.",
      );
      if (Array.isArray(result)) {
        throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid write capabilities.");
      }
      const rawItems = (result as Record<string, unknown>)["items"];
      if (!Array.isArray(rawItems) || rawItems.length > 1000) {
        throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid write capabilities.");
      }
      const names = new Set<string>();
      return rawItems.map((item): AdminWriteCapability => {
        if (typeof item !== "object" || item === null || Array.isArray(item)) {
          throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid write capabilities.");
        }
        const candidate = item as Record<string, unknown>;
        const name = candidate["name"];
        const keyField = candidate["key_field"];
        const createFields = candidate["create_fields"];
        const updateFields = candidate["update_fields"];
        const allowDelete = candidate["allow_delete"];
        if (
          typeof name !== "string" || !RESOURCE_NAME_PATTERN.test(name) || names.has(name) ||
          !isResourceField(keyField) || !Array.isArray(createFields) ||
          !Array.isArray(updateFields) || createFields.length > MAX_RESOURCE_FIELDS ||
          updateFields.length > MAX_RESOURCE_FIELDS ||
          !createFields.every(isResourceField) || !updateFields.every(isResourceField) ||
          new Set(createFields).size !== createFields.length ||
          new Set(updateFields).size !== updateFields.length || typeof allowDelete !== "boolean" ||
          (createFields.length === 0 && updateFields.length === 0 && !allowDelete)
        ) {
          throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid write capabilities.");
        }
        names.add(name);
        return {
          name,
          key_field: keyField,
          create_fields: [...createFields],
          update_fields: [...updateFields],
          allow_delete: allowDelete,
        };
      });
    },

    /** Fetch a fresh short-lived token bound to the current verified Admin identity. */
    async csrfToken(): Promise<string> {
      const result = await getJson(`${resourceBase}/csrf-token`, "Admin CSRF token is unavailable.");
      if (Array.isArray(result)) {
        throw new AdminClientError(502, "admin.invalid-response", "Admin returned an invalid CSRF token.");
      }
      const token = (result as Record<string, unknown>)["token"];
      if (typeof token !== "string" || !/^v1\.[A-Za-z0-9._-]{40,159}$/.test(token)) {
        throw new AdminClientError(502, "admin.invalid-response", "Admin returned an invalid CSRF token.");
      }
      return token;
    },

    /** Create one resource using the server-declared create-field allowlist. */
    async createResource(
      name: string,
      allowedFields: string[],
      csrfToken: string,
      values: unknown,
    ): Promise<AdminResourceRow> {
      if (!RESOURCE_NAME_PATTERN.test(name)) throw new TypeError("Admin resource name is invalid.");
      const payload = validatedWriteValues(values, allowedFields);
      const result = await writeJson(`${resourceBase}/resources/${name}`, "POST", csrfToken, payload);
      if (result === null) throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid resource data.");
      return result;
    },

    /** Update one resource using a safe key segment and the declared update-field allowlist. */
    async updateResource(
      name: string,
      key: string | number,
      allowedFields: string[],
      csrfToken: string,
      values: unknown,
    ): Promise<AdminResourceRow> {
      if (!RESOURCE_NAME_PATTERN.test(name)) throw new TypeError("Admin resource name is invalid.");
      const segment = resourceKeySegment(key);
      const payload = validatedWriteValues(values, allowedFields);
      const result = await writeJson(
        `${resourceBase}/resources/${name}/${segment}`,
        "PUT",
        csrfToken,
        payload,
      );
      if (result === null) throw new AdminClientError(502, "admin.invalid-response", "Admin returned invalid resource data.");
      return result;
    },

    /** Delete one resource; callers must obtain the key from the server-returned authorized row. */
    async deleteResource(name: string, key: string | number, csrfToken: string): Promise<void> {
      if (!RESOURCE_NAME_PATTERN.test(name)) throw new TypeError("Admin resource name is invalid.");
      await writeJson(
        `${resourceBase}/resources/${name}/${resourceKeySegment(key)}`,
        "DELETE",
        csrfToken,
      );
    },
  };
}
