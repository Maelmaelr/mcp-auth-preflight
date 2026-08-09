import test from "node:test";
import assert from "node:assert/strict";

import {
  authorizationServerMetadataCandidates,
  MCP_PROTOCOL_VERSION,
  normalizePublicHttpsUrl,
  parseBearerChallenge,
  preflight,
  protectedResourceMetadataCandidates,
} from "../src/preflight.mjs";

function jsonResponse(url, document, status = 200, headers = {}) {
  const response = new Response(JSON.stringify(document), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
  Object.defineProperty(response, "url", { value: url });
  return response;
}

function emptyResponse(url, status, headers = {}) {
  const response = new Response(null, { status, headers });
  Object.defineProperty(response, "url", { value: url });
  return response;
}

function stubFetch(routes) {
  return async (input) => {
    const url = input instanceof URL ? input.href : String(input);
    const route = routes[url];
    if (!route) return emptyResponse(url, 404);
    return typeof route === "function" ? route(url) : route;
  };
}

test("normalizes only public HTTPS URLs", () => {
  assert.equal(normalizePublicHttpsUrl("https://MCP.Example.com/mcp").href, "https://mcp.example.com/mcp");
  assert.throws(() => normalizePublicHttpsUrl("http://mcp.example.com/mcp"), /HTTPS/);
  assert.throws(() => normalizePublicHttpsUrl("https://user:secret@mcp.example.com/mcp"), /credentials/);
  assert.throws(() => normalizePublicHttpsUrl("https://127.0.0.1/mcp"), /literal IP/);
  assert.throws(() => normalizePublicHttpsUrl("https://service.internal/mcp"), /local or reserved/);
  assert.throws(() => normalizePublicHttpsUrl("https://mcp.example.com/mcp#token"), /fragment/);
});

test("derives RFC 9728 path-specific and root metadata locations", () => {
  assert.deepEqual(
    protectedResourceMetadataCandidates("https://mcp.example.com/team/mcp").map((url) => url.href),
    [
      "https://mcp.example.com/.well-known/oauth-protected-resource/team/mcp",
      "https://mcp.example.com/.well-known/oauth-protected-resource",
    ],
  );
});

test("derives RFC 8414 and OIDC issuer metadata locations", () => {
  assert.deepEqual(
    authorizationServerMetadataCandidates("https://auth.example.com/tenant").map((url) => url.href),
    [
      "https://auth.example.com/.well-known/oauth-authorization-server/tenant",
      "https://auth.example.com/.well-known/openid-configuration/tenant",
      "https://auth.example.com/tenant/.well-known/openid-configuration",
    ],
  );
});

test("parses quoted Bearer challenge parameters", () => {
  assert.deepEqual(
    parseBearerChallenge('Bearer realm="mcp", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="files:read files:write"'),
    {
      realm: "mcp",
      resource_metadata: "https://mcp.example.com/.well-known/oauth-protected-resource",
      scope: "files:read files:write",
    },
  );
});

test("sends the complete 2026-07-28 per-request metadata envelope", async () => {
  const endpoint = "https://mcp.example.com/mcp";
  let observedRequest;
  const fetchImpl = async (input, init) => {
    const url = input instanceof URL ? input.href : String(input);
    if (url === endpoint) {
      observedRequest = init;
      return jsonResponse(endpoint, {
        jsonrpc: "2.0",
        id: "auth-preflight",
        result: {
          resultType: "complete",
          supportedVersions: [MCP_PROTOCOL_VERSION],
          capabilities: {},
        },
      });
    }
    return emptyResponse(url, 404);
  };

  await preflight(endpoint, { fetchImpl });

  assert.equal(observedRequest?.headers["mcp-protocol-version"], MCP_PROTOCOL_VERSION);
  assert.equal(observedRequest?.headers["mcp-method"], "server/discover");
  const body = JSON.parse(observedRequest?.body ?? "{}");
  assert.deepEqual(body.params?._meta, {
    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientInfo": {
      name: "mcp-auth-preflight",
      version: "0.1.0",
    },
    "io.modelcontextprotocol/clientCapabilities": {},
  });
});

test("passes a complete CIMD-oriented discovery surface", async () => {
  const endpoint = "https://mcp.example.com/mcp";
  const prmUrl = "https://mcp.example.com/.well-known/oauth-protected-resource";
  const issuer = "https://auth.example.com";
  const asUrl = "https://auth.example.com/.well-known/oauth-authorization-server";
  const fetchImpl = stubFetch({
    [endpoint]: emptyResponse(endpoint, 401, {
      "www-authenticate": `Bearer realm="mcp", resource_metadata="${prmUrl}", scope="tools:read"`,
    }),
    [prmUrl]: jsonResponse(prmUrl, {
      resource: endpoint,
      authorization_servers: [issuer],
      scopes_supported: ["tools:read"],
    }),
    [asUrl]: jsonResponse(asUrl, {
      issuer,
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      code_challenge_methods_supported: ["S256"],
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
    }),
  });

  const report = await preflight(endpoint, { fetchImpl, requireAuth: true });
  assert.equal(report.summary.status, "pass");
  assert.equal(report.summary.counts.fail, 0);
  assert.ok(report.findings.some((finding) => finding.code === "as.cimd_supported"));
  assert.equal(report.authorization_servers[0].issuer, "https://auth.example.com");
});

test("uses path-specific PRM fallback when the challenge does not provide one", async () => {
  const endpoint = "https://mcp.example.com/team/mcp";
  const prmUrl = "https://mcp.example.com/.well-known/oauth-protected-resource/team/mcp";
  const issuer = "https://login.example.com/tenant";
  const asUrl = "https://login.example.com/.well-known/oauth-authorization-server/tenant";
  const fetchImpl = stubFetch({
    [endpoint]: emptyResponse(endpoint, 401, { "www-authenticate": "Bearer realm=mcp" }),
    [prmUrl]: jsonResponse(prmUrl, { resource: endpoint, authorization_servers: [issuer] }),
    [asUrl]: jsonResponse(asUrl, {
      issuer,
      authorization_endpoint: "https://login.example.com/tenant/authorize",
      token_endpoint: "https://login.example.com/tenant/token",
      code_challenge_methods_supported: ["S256"],
      registration_endpoint: "https://login.example.com/tenant/register",
      authorization_response_iss_parameter_supported: true,
    }),
  });

  const report = await preflight(endpoint, { fetchImpl, requireAuth: true });
  assert.equal(report.protected_resource_metadata.url, prmUrl);
  assert.equal(report.summary.status, "warning");
  assert.ok(report.findings.some((finding) => finding.code === "as.dcr_only"));
});

test("fails when auth is required but no PRM can be discovered", async () => {
  const endpoint = "https://mcp.example.com/mcp";
  const report = await preflight(endpoint, {
    requireAuth: true,
    fetchImpl: stubFetch({
      [endpoint]: emptyResponse(endpoint, 401, { "www-authenticate": "Bearer realm=mcp" }),
    }),
  });
  assert.equal(report.summary.status, "fail");
  assert.ok(report.findings.some((finding) => finding.code === "prm.not_found"));
});

test("fails a required protected endpoint that is absent even when stale metadata remains", async () => {
  const endpoint = "https://mcp.example.com/mcp";
  const prmUrl = "https://mcp.example.com/.well-known/oauth-protected-resource";
  const issuer = "https://auth.example.com";
  const asUrl = "https://auth.example.com/.well-known/oauth-authorization-server";
  const fetchImpl = stubFetch({
    [endpoint]: emptyResponse(endpoint, 404),
    [prmUrl]: jsonResponse(prmUrl, {
      resource: endpoint,
      authorization_servers: [issuer],
    }),
    [asUrl]: jsonResponse(asUrl, {
      issuer,
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      code_challenge_methods_supported: ["S256"],
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
    }),
  });

  const report = await preflight(endpoint, { fetchImpl, requireAuth: true });
  const finding = report.findings.find((entry) => entry.code === "probe.unexpected_status");
  assert.equal(report.summary.status, "fail");
  assert.equal(finding?.level, "fail");
  assert.match(finding?.message ?? "", /should return 401 with a Bearer challenge/);
});

test("flags mismatched issuers, missing endpoints, and offline_access", async () => {
  const endpoint = "https://mcp.example.com/mcp";
  const prmUrl = "https://mcp.example.com/.well-known/oauth-protected-resource";
  const issuer = "https://auth.example.com/";
  const asUrl = "https://auth.example.com/.well-known/oauth-authorization-server";
  const fetchImpl = stubFetch({
    [endpoint]: emptyResponse(endpoint, 401, { "www-authenticate": `Bearer resource_metadata="${prmUrl}"` }),
    [prmUrl]: jsonResponse(prmUrl, {
      resource: "https://mcp.example.com/other",
      authorization_servers: [issuer],
      scopes_supported: ["offline_access"],
    }),
    [asUrl]: jsonResponse(asUrl, {
      issuer: "https://wrong.example.com/",
      authorization_endpoint: "https://auth.example.com/authorize",
    }),
  });

  const report = await preflight(endpoint, { fetchImpl, requireAuth: true });
  assert.equal(report.summary.status, "fail");
  for (const code of ["prm.resource_mismatch", "prm.offline_access", "as.issuer_mismatch", "as.token_endpoint_missing"]) {
    assert.ok(report.findings.some((finding) => finding.code === code), `expected ${code}`);
  }
});

test("continues to the OIDC insertion location after unusable OAuth metadata", async () => {
  const endpoint = "https://mcp.example.com/mcp";
  const prmUrl = "https://mcp.example.com/.well-known/oauth-protected-resource";
  const issuer = "https://auth.example.com/tenant";
  const oauthUrl = "https://auth.example.com/.well-known/oauth-authorization-server/tenant";
  const oidcUrl = "https://auth.example.com/.well-known/openid-configuration/tenant";
  const fetchImpl = stubFetch({
    [endpoint]: emptyResponse(endpoint, 401, { "www-authenticate": `Bearer resource_metadata="${prmUrl}"` }),
    [prmUrl]: jsonResponse(prmUrl, { resource: endpoint, authorization_servers: [issuer] }),
    [oauthUrl]: jsonResponse(oauthUrl, { issuer: "https://wrong.example.com" }),
    [oidcUrl]: jsonResponse(oidcUrl, {
      issuer,
      authorization_endpoint: "https://auth.example.com/tenant/authorize",
      token_endpoint: "https://auth.example.com/tenant/token",
      code_challenge_methods_supported: ["S256"],
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
    }),
  });

  const report = await preflight(endpoint, { fetchImpl, requireAuth: true });
  assert.equal(report.summary.status, "pass");
  assert.equal(report.authorization_servers[0].metadata.url, oidcUrl);
  assert.ok(report.findings.some((finding) => finding.code === "as.issuer_matches"));
  assert.ok(!report.findings.some((finding) => finding.code === "as.issuer_mismatch"));
});
