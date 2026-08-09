import { isIP } from "node:net";

export const MCP_PROTOCOL_VERSION = "2026-07-28";

const MAX_JSON_BYTES = 1_000_000;
const BLOCKED_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".home.arpa",
  ".test",
  ".invalid",
];

export function normalizePublicHttpsUrl(value, label = "URL") {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be an absolute URL`);
  }

  if (url.protocol !== "https:") {
    throw new Error(`${label} must use HTTPS`);
  }
  if (url.username || url.password) {
    throw new Error(`${label} must not contain embedded credentials`);
  }
  if (url.hash) {
    throw new Error(`${label} must not contain a fragment`);
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!hostname || hostname === "localhost" || isIP(hostname)) {
    throw new Error(`${label} must use a public DNS hostname, not localhost or a literal IP address`);
  }
  if (BLOCKED_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
    throw new Error(`${label} uses a local or reserved hostname`);
  }

  url.hostname = hostname;
  return url;
}

export function protectedResourceMetadataCandidates(endpointValue) {
  const endpoint = normalizePublicHttpsUrl(endpointValue, "MCP endpoint");
  const path = endpoint.pathname === "/" ? "" : endpoint.pathname.replace(/\/$/, "");
  const pathSpecific = new URL(`/.well-known/oauth-protected-resource${path}`, endpoint.origin);
  const root = new URL("/.well-known/oauth-protected-resource", endpoint.origin);
  return dedupeUrls([pathSpecific, root]);
}

export function authorizationServerMetadataCandidates(issuerValue) {
  const issuer = normalizePublicHttpsUrl(issuerValue, "Authorization server issuer");
  const issuerPath = issuer.pathname === "/" ? "" : issuer.pathname.replace(/\/$/, "");
  const oauth = new URL(`/.well-known/oauth-authorization-server${issuerPath}`, issuer.origin);
  const oidcInserted = new URL(`/.well-known/openid-configuration${issuerPath}`, issuer.origin);
  const oidcAppended = new URL(`${issuerPath}/.well-known/openid-configuration`, issuer.origin);
  return dedupeUrls([oauth, oidcInserted, oidcAppended]);
}

export function parseBearerChallenge(value) {
  if (!value || typeof value !== "string") return null;
  const match = /(?:^|,)\s*Bearer\s+/i.exec(value);
  if (!match) return null;

  const input = value.slice(match.index + match[0].length);
  const params = {};
  let index = 0;

  while (index < input.length) {
    while (/[\s,]/.test(input[index] ?? "")) index += 1;
    const keyMatch = /^[A-Za-z][A-Za-z0-9_-]*/.exec(input.slice(index));
    if (!keyMatch) break;
    const key = keyMatch[0].toLowerCase();
    index += keyMatch[0].length;
    while (/\s/.test(input[index] ?? "")) index += 1;
    if (input[index] !== "=") break;
    index += 1;
    while (/\s/.test(input[index] ?? "")) index += 1;

    let parsed = "";
    if (input[index] === '"') {
      index += 1;
      while (index < input.length) {
        const character = input[index];
        index += 1;
        if (character === '"') break;
        if (character === "\\" && index < input.length) {
          parsed += input[index];
          index += 1;
        } else {
          parsed += character;
        }
      }
    } else {
      const valueMatch = /^[^\s,]+/.exec(input.slice(index));
      if (!valueMatch) break;
      parsed = valueMatch[0];
      index += valueMatch[0].length;
    }
    params[key] = parsed;
  }

  return params;
}

export async function preflight(endpointValue, options = {}) {
  const endpoint = normalizePublicHttpsUrl(endpointValue, "MCP endpoint");
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 8_000;
  const requireAuth = options.requireAuth ?? false;
  if (typeof fetchImpl !== "function") throw new Error("A fetch implementation is required");

  const report = {
    schema_version: "mcp-auth-preflight/v1alpha1",
    checked_at: new Date().toISOString(),
    protocol_version: MCP_PROTOCOL_VERSION,
    endpoint: endpoint.href,
    require_auth: requireAuth,
    probe: null,
    protected_resource_metadata: null,
    authorization_servers: [],
    findings: [],
    summary: null,
  };

  let challengeMetadataUrl = null;
  try {
    const response = await safeFetch(
      endpoint,
      {
        method: "POST",
        headers: {
          accept: "application/json, text/event-stream",
          "content-type": "application/json",
          "mcp-protocol-version": MCP_PROTOCOL_VERSION,
          "mcp-method": "server/discover",
          "user-agent": "McpAuthPreflight/0.1",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "auth-preflight",
          method: "server/discover",
          params: {
            _meta: {
              "io.modelcontextprotocol/clientInfo": {
                name: "mcp-auth-preflight",
                version: "0.1.0",
              },
            },
          },
        }),
      },
      { fetchImpl, timeoutMs },
    );
    const challenge = parseBearerChallenge(response.headers.get("www-authenticate"));
    report.probe = {
      status: response.status,
      final_url: response.url || endpoint.href,
      bearer_challenge: challenge,
    };

    if (response.status === 401) {
      if (!challenge) {
        addFinding(report, "fail", "challenge.missing_bearer", "The MCP endpoint returned 401 without a parseable Bearer challenge.", endpoint.href);
      } else if (challenge.resource_metadata) {
        try {
          challengeMetadataUrl = normalizePublicHttpsUrl(challenge.resource_metadata, "resource_metadata").href;
          addFinding(report, "pass", "challenge.resource_metadata", "The Bearer challenge advertises a public HTTPS resource_metadata URL.", challengeMetadataUrl);
        } catch (error) {
          addFinding(report, "fail", "challenge.invalid_resource_metadata", error.message, endpoint.href);
        }
      } else {
        addFinding(report, "warn", "challenge.resource_metadata_absent", "The Bearer challenge does not advertise resource_metadata; well-known discovery must succeed.", endpoint.href);
      }
    } else if (response.status >= 200 && response.status < 300) {
      addFinding(
        report,
        requireAuth ? "fail" : "info",
        "probe.auth_not_challenged",
        "The unauthenticated discovery request was not challenged. Authorization may be optional or disabled for this operation.",
        endpoint.href,
      );
    } else {
      addFinding(
        report,
        requireAuth ? "fail" : "warn",
        "probe.unexpected_status",
        requireAuth
          ? `The unauthenticated discovery request returned HTTP ${response.status}; a required protected endpoint should return 401 with a Bearer challenge.`
          : `The unauthenticated discovery request returned HTTP ${response.status}; metadata fallback will still be checked.`,
        endpoint.href,
      );
    }
  } catch (error) {
    addFinding(report, "warn", "probe.request_failed", `The initial MCP request failed: ${error.message}`, endpoint.href);
  }

  const prmCandidates = dedupeUrls([
    ...(challengeMetadataUrl ? [new URL(challengeMetadataUrl)] : []),
    ...protectedResourceMetadataCandidates(endpoint),
  ]);
  const prmResult = await firstJsonDocument(prmCandidates, { fetchImpl, timeoutMs });
  if (!prmResult) {
    addFinding(
      report,
      requireAuth || report.probe?.status === 401 ? "fail" : "warn",
      "prm.not_found",
      "No valid Protected Resource Metadata document was found at the advertised or RFC 9728 well-known locations.",
      endpoint.href,
    );
    finalize(report);
    return report;
  }

  report.protected_resource_metadata = {
    url: prmResult.url,
    document: prmResult.document,
  };
  validateProtectedResourceMetadata(report, endpoint, prmResult);

  const issuers = Array.isArray(prmResult.document.authorization_servers)
    ? prmResult.document.authorization_servers
    : [];
  for (const issuerValue of issuers) {
    if (typeof issuerValue !== "string") continue;
    let issuer;
    try {
      issuer = normalizePublicHttpsUrl(issuerValue, "Authorization server issuer");
    } catch (error) {
      addFinding(report, "fail", "as.invalid_issuer_url", error.message, prmResult.url);
      continue;
    }

    const metadataResult = await authorizationServerMetadata(
      issuerValue,
      authorizationServerMetadataCandidates(issuer),
      { fetchImpl, timeoutMs },
    );
    if (!metadataResult) {
      addFinding(report, "fail", "as.metadata_not_found", "No RFC 8414 or OpenID Connect metadata document was found for the advertised authorization server.", issuer.href);
      report.authorization_servers.push({ issuer: issuer.href, metadata: null });
      continue;
    }

    const entry = {
      issuer: issuerValue,
      metadata: {
        url: metadataResult.url,
        document: metadataResult.document,
      },
    };
    report.authorization_servers.push(entry);
    validateAuthorizationServerMetadata(report, issuerValue, metadataResult);
  }

  finalize(report);
  return report;
}

function validateProtectedResourceMetadata(report, endpoint, result) {
  const document = result.document;
  if (!isPlainObject(document)) {
    addFinding(report, "fail", "prm.not_object", "Protected Resource Metadata must be a JSON object.", result.url);
    return;
  }

  if (typeof document.resource !== "string") {
    addFinding(report, "fail", "prm.resource_missing", "Protected Resource Metadata is missing its required resource identifier.", result.url);
  } else {
    try {
      const resource = normalizePublicHttpsUrl(document.resource, "Protected resource identifier");
      if (!equivalentResource(resource, endpoint)) {
        addFinding(report, "warn", "prm.resource_mismatch", `The metadata resource identifier (${resource.href}) differs from the tested MCP endpoint (${endpoint.href}).`, result.url);
      } else {
        addFinding(report, "pass", "prm.resource_matches", "The protected resource identifier matches the tested MCP endpoint.", result.url);
      }
    } catch (error) {
      addFinding(report, "fail", "prm.resource_invalid", error.message, result.url);
    }
  }

  if (!Array.isArray(document.authorization_servers) || document.authorization_servers.length === 0) {
    addFinding(report, "fail", "prm.authorization_servers_missing", "MCP Protected Resource Metadata must advertise at least one authorization server.", result.url);
  } else {
    addFinding(report, "pass", "prm.authorization_servers_present", `Protected Resource Metadata advertises ${document.authorization_servers.length} authorization server(s).`, result.url);
  }

  if (document.scopes_supported !== undefined) {
    if (!Array.isArray(document.scopes_supported) || document.scopes_supported.some((scope) => typeof scope !== "string" || !scope)) {
      addFinding(report, "fail", "prm.scopes_invalid", "scopes_supported must be an array of non-empty strings when present.", result.url);
    } else if (document.scopes_supported.includes("offline_access")) {
      addFinding(report, "warn", "prm.offline_access", "Protected resources should not advertise offline_access as a resource scope.", result.url);
    }
  }
}

function validateAuthorizationServerMetadata(report, advertisedIssuer, result) {
  const document = result.document;
  if (!isPlainObject(document)) {
    addFinding(report, "fail", "as.not_object", "Authorization server metadata must be a JSON object.", result.url);
    return;
  }

  if (document.issuer !== advertisedIssuer) {
    addFinding(report, "fail", "as.issuer_mismatch", `Metadata issuer must exactly match the advertised issuer (${advertisedIssuer}).`, result.url);
  } else {
    addFinding(report, "pass", "as.issuer_matches", "Authorization server metadata has an exact issuer match.", result.url);
  }

  for (const field of ["authorization_endpoint", "token_endpoint"]) {
    if (typeof document[field] !== "string") {
      addFinding(report, "fail", `as.${field}_missing`, `${field} is required for the authorization-code flow.`, result.url);
      continue;
    }
    try {
      normalizePublicHttpsUrl(document[field], field);
      addFinding(report, "pass", `as.${field}_valid`, `${field} is a public HTTPS URL.`, result.url);
    } catch (error) {
      addFinding(report, "fail", `as.${field}_invalid`, error.message, result.url);
    }
  }

  if (!Array.isArray(document.code_challenge_methods_supported) || !document.code_challenge_methods_supported.includes("S256")) {
    addFinding(report, "warn", "as.pkce_s256_not_advertised", "The authorization server does not advertise PKCE S256 support, which public MCP clients rely on.", result.url);
  } else {
    addFinding(report, "pass", "as.pkce_s256", "The authorization server advertises PKCE S256 support.", result.url);
  }

  if (document.client_id_metadata_document_supported === true) {
    addFinding(report, "pass", "as.cimd_supported", "The authorization server advertises Client ID Metadata Document support, the current preferred registration mechanism.", result.url);
  } else if (typeof document.registration_endpoint === "string") {
    addFinding(report, "warn", "as.dcr_only", "The authorization server advertises Dynamic Client Registration but not CIMD; DCR is retained for compatibility and deprecated in MCP 2026-07-28.", result.url);
  } else {
    addFinding(report, "info", "as.pre_registration_required", "Neither CIMD nor DCR is advertised; clients need a pre-registered client ID.", result.url);
  }

  if (document.authorization_response_iss_parameter_supported === true) {
    addFinding(report, "pass", "as.response_iss_supported", "The authorization server advertises authorization-response issuer identification.", result.url);
  } else {
    addFinding(report, "warn", "as.response_iss_not_advertised", "Authorization-response iss is not advertised; MCP recommends emitting it now for mix-up protection and future compatibility.", result.url);
  }
}

async function firstJsonDocument(urls, context) {
  for (const url of urls) {
    try {
      const response = await safeFetch(
        url,
        {
          method: "GET",
          headers: {
            accept: "application/json",
            "mcp-protocol-version": MCP_PROTOCOL_VERSION,
            "user-agent": "McpAuthPreflight/0.1",
          },
        },
        context,
      );
      if (response.status < 200 || response.status >= 300) continue;
      const document = await boundedJson(response);
      return { url: response.url || url.href, document };
    } catch {
      // Try the next standards-defined discovery location.
    }
  }
  return null;
}

async function authorizationServerMetadata(advertisedIssuer, urls, context) {
  let firstDocument = null;
  for (const url of urls) {
    const result = await jsonDocument(url, context);
    if (!result) continue;
    firstDocument ??= result;
    if (isPlainObject(result.document) && result.document.issuer === advertisedIssuer) {
      return result;
    }
  }
  return firstDocument;
}

async function jsonDocument(url, context) {
  try {
    const response = await safeFetch(
      url,
      {
        method: "GET",
        headers: {
          accept: "application/json",
          "mcp-protocol-version": MCP_PROTOCOL_VERSION,
          "user-agent": "McpAuthPreflight/0.1",
        },
      },
      context,
    );
    if (response.status < 200 || response.status >= 300) return null;
    const document = await boundedJson(response);
    return { url: response.url || url.href, document };
  } catch {
    return null;
  }
}

async function safeFetch(initialUrl, init, { fetchImpl, timeoutMs, maxRedirects = 3 }) {
  let current = normalizePublicHttpsUrl(initialUrl, "Fetch URL");
  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    const response = await fetchImpl(current, {
      ...init,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (response.status < 300 || response.status >= 400) return response;
    if (redirects === maxRedirects) throw new Error("Too many redirects");
    const location = response.headers.get("location");
    if (!location) throw new Error(`HTTP ${response.status} redirect has no Location header`);
    current = normalizePublicHttpsUrl(new URL(location, current), "Redirect URL");
  }
  throw new Error("Redirect limit exceeded");
}

async function boundedJson(response) {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_JSON_BYTES) {
    throw new Error("Metadata document is too large");
  }
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAX_JSON_BYTES) {
    throw new Error("Metadata document is too large");
  }
  return JSON.parse(text);
}

function equivalentResource(left, right) {
  if (left.href === right.href) return true;
  const normalizeRootSlash = (url) => {
    const copy = new URL(url);
    if (copy.pathname === "/") copy.pathname = "";
    return copy.href;
  };
  return normalizeRootSlash(left) === normalizeRootSlash(right);
}

function addFinding(report, level, code, message, url) {
  report.findings.push({ level, code, message, ...(url ? { url } : {}) });
}

function finalize(report) {
  const counts = { fail: 0, warn: 0, pass: 0, info: 0 };
  for (const finding of report.findings) counts[finding.level] += 1;
  report.summary = {
    status: counts.fail > 0 ? "fail" : counts.warn > 0 ? "warning" : "pass",
    counts,
  };
}

function dedupeUrls(values) {
  const seen = new Set();
  const result = [];
  for (const value of values) {
    const url = value instanceof URL ? value : new URL(value);
    if (seen.has(url.href)) continue;
    seen.add(url.href);
    result.push(url);
  }
  return result;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
