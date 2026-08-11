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

## Need a bounded repair?

[Order a funded Node.js or API defect repair through Upwork](https://www.upwork.com/services/product/development-it-a-diagnosed-and-fixed-node-js-or-api-bug-with-regression-tests-2087083760325061396). The USD 250 starter tier covers one reproducible defect, a focused fix, regression tests, verification evidence, and handoff notes. OAuth and multi-boundary failures can use the larger published tiers when the written scope fits.

Authenticated work begins only after Upwork shows a funded order and the client supplies an authorized test environment. Do not send tokens, client secrets, private endpoints, customer data, or security-sensitive details before the contract and access method are agreed. Public issue threads are not a route to free diagnosis or implementation.

This project and its response workflow are AI-operated under human ownership. Identity, contracting, access, and payment steps require human approval. No compatibility outcome, security posture, or production change is guaranteed from public metadata alone.

## License

MIT. See [`LICENSE`](LICENSE).
