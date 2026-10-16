import assert from "node:assert/strict";
import test from "node:test";

import { AdminClientError, createAdminClient } from "../dist/assets/admin-client.js";

test("client requests only fixed Core paths with same-origin credentials and no cache", async () => {
  let actualUrl;
  let actualOptions;
  const client = createAdminClient(async (url, options) => {
    actualUrl = url;
    actualOptions = options;
    return Response.json({ state: "running" }, { headers: { "cache-control": "no-store" } });
  });

  const result = await client.read("state");

  assert.deepEqual(result, { state: "running" });
  assert.equal(actualUrl, "/admin/state");
  assert.equal(actualOptions.credentials, "same-origin");
  assert.equal(actualOptions.cache, "no-store");
  assert.equal(actualOptions.redirect, "error");
  assert.equal(actualOptions.mode, "same-origin");
});

test("remote error text and credentials are not copied into client errors", async () => {
  const client = createAdminClient(async () => new Response(
    JSON.stringify({ code: "security.forbidden", message: "password=do-not-show" }),
    { status: 403, headers: { "content-type": "application/json" } },
  ));

  await assert.rejects(client.read("config"), (error) => {
    assert.ok(error instanceof AdminClientError);
    assert.equal(error.status, 403);
    assert.equal(error.code, "security.forbidden");
    assert.equal(error.message, "Your account cannot view this section.");
    assert.equal(error.message.includes("do-not-show"), false);
    return true;
  });
});

test("401 uses a safe status and ignores an invalid remote error code", async () => {
  const client = createAdminClient(async () => new Response(
    JSON.stringify({ code: "<script>alert(1)</script>" }),
    { status: 401, headers: { "content-type": "application/json" } },
  ));

  await assert.rejects(client.read("state"), (error) => {
    assert.ok(error instanceof AdminClientError);
    assert.equal(error.status, 401);
    assert.equal(error.code, "admin.request-failed");
    return true;
  });
});

test("redirected and non-JSON responses fail closed", async () => {
  const redirected = createAdminClient(async () => new Response("login", {
    headers: { "content-type": "text/html" },
  }));
  await assert.rejects(redirected.read("state"), { code: "admin.invalid-response" });

  const redirectedFlag = createAdminClient(async () => {
    const response = Response.json({ state: "running" });
    Object.defineProperty(response, "redirected", { value: true });
    return response;
  });
  await assert.rejects(redirectedFlag.read("state"), { code: "admin.invalid-response" });
});

test("response bytes are bounded from the stream, even without Content-Length", async () => {
  const client = createAdminClient(async () => new Response(
    JSON.stringify({ data: "x".repeat(300) }),
    { headers: { "content-type": "application/json" } },
  ), "/admin", 128);

  await assert.rejects(client.read("diagnostics"), { code: "admin.response-too-large" });
});

test("API path and byte limit cannot point to another origin or exceed the fixed ceiling", () => {
  assert.throws(() => createAdminClient(fetch, "https://example.invalid/admin"), TypeError);
  assert.throws(() => createAdminClient(fetch, "//example.invalid/admin"), TypeError);
  assert.throws(() => createAdminClient(fetch, "/admin/../outside"), TypeError);
  assert.throws(() => createAdminClient(fetch, "/admin%2f.."), TypeError);
  assert.throws(() => createAdminClient(fetch, "/admin", 16_777_217), RangeError);
});

test("resource browser reads a validated catalog and a bounded first page", async () => {
  const requests = [];
  const client = createAdminClient(async (url, options) => {
    requests.push([url, options]);
    if (url === "/admin-api/v1/resources") {
      return Response.json({ items: [{ name: "accounts", read_fields: ["display_name", "id"] }] });
    }
    return Response.json({ items: [{ display_name: "Ada", id: 1 }] });
  });

  assert.deepEqual(await client.listResources(), [
    { name: "accounts", read_fields: ["display_name", "id"] },
  ]);
  assert.deepEqual(await client.readResource("accounts"), [{ display_name: "Ada", id: 1 }]);
  assert.deepEqual(requests.map(([url]) => url), [
    "/admin-api/v1/resources",
    "/admin-api/v1/resources/accounts?limit=100",
  ]);
  for (const [, options] of requests) {
    assert.equal(options.credentials, "same-origin");
    assert.equal(options.cache, "no-store");
    assert.equal(options.redirect, "error");
  }
});

test("resource names and catalog field metadata are validated before use", async () => {
  let requests = 0;
  const invalidPathClient = createAdminClient(async () => {
    requests += 1;
    return Response.json({ items: [] });
  });
  await assert.rejects(invalidPathClient.readResource("../accounts"), TypeError);
  assert.equal(requests, 0);

  const invalidCatalogClient = createAdminClient(async () => Response.json({
    items: [{ name: "accounts", read_fields: ["<script>"] }],
  }));
  await assert.rejects(invalidCatalogClient.listResources(), { code: "admin.invalid-response" });
});

test("resource writes require a CSRF token and the declared field allowlist", async () => {
  const requests = [];
  const csrf = `v1.${"a".repeat(100)}`;
  const client = createAdminClient(async (url, options) => {
    requests.push([url, options]);
    if (url.endsWith("/write-capabilities")) {
      return Response.json({ items: [{
        name: "accounts",
        key_field: "id",
        create_fields: ["display_name"],
        update_fields: ["display_name"],
        allow_delete: true,
      }] });
    }
    if (url.endsWith("/csrf-token")) return Response.json({ token: csrf });
    if (options.method === "DELETE") return new Response(null, { status: 204 });
    return Response.json({ item: { display_name: "Ada" } });
  });

  const [capability] = await client.listWriteCapabilities();
  assert.equal(capability.name, "accounts");
  const token = await client.csrfToken();
  await client.createResource("accounts", capability.create_fields, token, { display_name: "Ada" });
  await client.updateResource("accounts", 7, capability.update_fields, token, { display_name: "Ada" });
  await client.deleteResource("accounts", 7, token);
  assert.deepEqual(requests.map(([url, options]) => [url, options.method]), [
    ["/admin-api/v1/write-capabilities", "GET"],
    ["/admin-api/v1/csrf-token", "GET"],
    ["/admin-api/v1/resources/accounts", "POST"],
    ["/admin-api/v1/resources/accounts/7", "PUT"],
    ["/admin-api/v1/resources/accounts/7", "DELETE"],
  ]);
  assert.equal(requests[2][1].headers["x-orbit-csrf-token"], csrf);
  assert.equal(requests[2][1].credentials, "same-origin");
  assert.equal(requests[2][1].cache, "no-store");
  await assert.rejects(
    client.createResource("accounts", capability.create_fields, token, { password_hash: "blocked" }),
    TypeError,
  );
  await assert.rejects(client.deleteResource("accounts", "../7", token), TypeError);

  const ambiguousOutcome = createAdminClient(async () => Response.json(
    { code: "admin.audit-unavailable", message: "password=never-display" },
    { status: 503 },
  ));
  await assert.rejects(
    ambiguousOutcome.createResource("accounts", ["display_name"], token, { display_name: "Ada" }),
    (error) => {
      assert.ok(error instanceof AdminClientError);
      assert.match(error.message, /may have completed/);
      assert.equal(error.message.includes("never-display"), false);
      return true;
    },
  );
});
