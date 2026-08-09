# Public MCP authorization preflight — Plain

- Checked: 2026-08-09
- Endpoint: `https://mcp.plain.com/mcp`
- Protocol target: MCP `2026-07-28`
- Surface tested: unauthenticated challenge and public metadata only

## Outcome

One normative discovery mismatch, two interoperability warnings, and seven passing checks.

This result does **not** claim a vulnerability, data exposure, or failure in Claude, ChatGPT, Codex, Cursor, or any other named client. No login, OAuth redirect, client registration, token exchange, or MCP tool call was performed.

## Repair candidate 1 — issuer identity

The Protected Resource Metadata advertises:

```json
{
  "authorization_servers": ["https://signin.auth.plain.com/"]
}
```

Both standards-defined public authorization-server documents return:

```json
{
  "issuer": "https://signin.auth.plain.com"
}
```

The trailing slash makes these different strings. [RFC 8414 section 3.3](https://www.rfc-editor.org/rfc/rfc8414.html#section-3.3) requires exact identity and says a client must not use metadata when the values differ.

Minimal likely repair: publish `https://signin.auth.plain.com` without the trailing slash in the resource server's `authorization_servers` array, matching the issuer already returned by the authorization server. Confirm the authorization server's configured issuer before applying the change.

## Repair candidate 2 — refresh-token scope placement

The `401` challenge requires `openid offline_access`, and the Protected Resource Metadata also lists `offline_access`. The current [MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) says protected resources should not advertise `offline_access` in either location because refresh-token issuance is a client/authorization-server concern, not a resource requirement.

Minimal likely repair: remove `offline_access` from the resource challenge and Protected Resource Metadata. Continue advertising it in authorization-server `scopes_supported` if the authorization server supports it; a capable client may then request it when it wants a refresh token.

## Warning — authorization-response issuer signal

The public authorization-server metadata does not advertise `authorization_response_iss_parameter_supported: true`. MCP currently recommends returning and validating the authorization-response `iss` parameter for mix-up protection and future compatibility. This is a warning, not a public-metadata failure; verify the actual authorization response with an authorized test client before recommending an authorization-server change.

## Passing public checks

- the endpoint returns `401` with an HTTPS `resource_metadata` link;
- the resource identifier exactly matches `https://mcp.plain.com/mcp`;
- one authorization server is advertised;
- authorization and token endpoints use HTTPS;
- PKCE `S256` is advertised;
- Client ID Metadata Documents are advertised;
- the public discovery chain is readable without credentials.

## Authorized recheck needed

After the public metadata repair, a complete interoperability conclusion still requires a designated test account and target client to verify:

1. client identification or registration;
2. redirect URI acceptance;
3. PKCE authorization-code exchange;
4. authorization-response `iss` handling;
5. token resource/audience validation;
6. refresh-token behavior;
7. one non-destructive authenticated MCP request.

That authenticated work should happen only with written scope, a test-data boundary, and explicit authorization. Production mutation and active security testing are outside this sample.
