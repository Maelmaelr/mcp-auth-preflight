# MCP Authorization Preflight

A dependency-free, read-only checker for the public authorization-discovery surface of a remote HTTP MCP server.

It answers a deliberately narrow question: can a standards-aware client discover the protected resource and authorization server metadata it needs before a user signs in?

It does not ask for credentials, follow an authorization redirect, register an OAuth client, exchange a code, test token audience enforcement, or claim compatibility with a named client. Those require an authorized test account and a real end-to-end flow.

See [`sample/plain-public-report.md`](sample/plain-public-report.md) for a real public-surface result and its deliberately limited repair claim.

## Checks

- initial unauthenticated MCP request and `401` challenge;
- Bearer `WWW-Authenticate` parsing and `resource_metadata` discovery;
- RFC 9728 path-specific and root Protected Resource Metadata fallbacks;
- exact MCP resource and authorization-server references;
- RFC 8414 and all current MCP-required OpenID Connect authorization-server metadata locations;
- authorization and token endpoints;
- PKCE `S256` advertisement;
- current MCP client registration posture: CIMD preferred, DCR deprecated but accepted;
- current authorization-response `iss` hardening signal;
- accidental `offline_access` advertisement as a resource scope.

The rules target the MCP 2026-07-28 authorization specification:

- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- https://datatracker.ietf.org/doc/html/rfc9728
- https://datatracker.ietf.org/doc/html/rfc8414

## Run

```bash
npm test
npm run preflight -- https://mcp.example.com/mcp
npm run preflight -- https://mcp.example.com/mcp --json
npm run preflight -- https://mcp.example.com/mcp --require-auth
```

Exit codes are `0` for no failing finding, `2` when a normative failure is found, and `1` for invalid input or an execution error.

## Safety boundary

The checker makes one unauthenticated, non-tool-calling `server/discover` request and reads only public metadata. It refuses HTTP URLs, embedded credentials, URL fragments, literal IP addresses, and local/internal hostname suffixes. It follows only bounded HTTPS redirects to syntactically public hostnames.

This is a local CLI, not a hardened multi-tenant fetch service. DNS rebinding and network-level address validation must be added before exposing it as a hosted endpoint. Never paste access tokens, client secrets, cookies, or private endpoints into it.

## Need the flow repaired?

The founding implementation engagement is **USD 399 fixed scope** for one remote MCP server, one authorization provider, and one target client. It includes the public discovery report, an authorized reproduction with a designated test account, an implementation-ready patch or configuration change, and one recheck. The work is capped at six focused hours with a 48-hour delivery target after access and scope are agreed.

[Open a public implementation request](https://github.com/Maelmaelr/mcp-auth-preflight/issues/new?template=implementation.yml). Do not include tokens, client secrets, private endpoints, customer data, or security-sensitive details. A private scope and payment route will be agreed separately before any authenticated work begins.

This project and its response workflow are AI-operated under human ownership. Identity, contracting, access, and payment steps require human approval. No compatibility outcome, security posture, or production change is guaranteed from public metadata alone.

## License

MIT. See [`LICENSE`](LICENSE).
