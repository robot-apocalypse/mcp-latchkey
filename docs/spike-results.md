# Phase 0 spike results (2026-10-01)

Two dummy services (`/a/mcp`, `/b/mcp`) on one host
(`latchkey-spike.your-tailnet.ts.net`) behind one authorization server,
connected as two claude.ai custom connectors. Source: `spike/src/spike.ts`.

## Answers

| Question | Result |
|---|---|
| Does Claude send `resource` (RFC 8707)? | **Yes**, on both `/authorize` and `/token`, set to the exact service URL (`https://host/a/mcp`). |
| CIMD or DCR? | **CIMD.** `client_id=https://claude.ai/oauth/mcp-oauth-client-metadata`. `/register` was never called (the AS metadata advertised `client_id_metadata_document_supported: true`). |
| Discovery via `WWW-Authenticate`? | **Yes.** Claude followed `resource_metadata` from the 401 to `/.well-known/oauth-protected-resource/{svc}/mcp`. The root PRM path (deliberately 404) was never requested. |
| Separate tokens per connector? | **Yes.** Each connector got its own token bound to its own resource; every MCP request carried the matching token (`matches=true` throughout), never the other one. |

**Conclusion:** path-based services on one hostname behind one shared
authorization server work. Tokens can be scoped to a service via `resource`.

## Claude's client metadata document

```json
{
  "client_id": "https://claude.ai/oauth/mcp-oauth-client-metadata",
  "client_name": "Claude",
  "client_uri": "https://claude.ai",
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
  "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

## Flow observed (per connector)

1. `POST /{svc}/mcp` without token → 401 + `WWW-Authenticate` (UA `python-httpx`, i.e. Claude's backend).
2. `GET /.well-known/oauth-protected-resource/{svc}/mcp`, then `GET /.well-known/oauth-authorization-server`.
   Steps 1–2 happen twice (connect dialog, then connect).
3. Browser `GET /authorize` with CIMD `client_id`, `resource`, PKCE S256.
4. Backend `POST /token` with `client_id`, `resource`, `code_verifier`, `redirect_uri`.
5. MCP traffic (UA `Claude-User`).

## Other observations

- Every new MCP session starts with one **400** before the 200s. Diagnosed in
  the real gateway (2026-10-01): Claude first tries the 2026-07-28 protocol's
  `server/discover` with `mcp-protocol-version: 2026-07-28`; the TypeScript SDK
  (1.31) only supports up to 2025-11-25 and answers 400 "Unsupported protocol
  version", and Claude falls back to `initialize`. Harmless; goes away once the
  SDK supports 2026-07-28.
- The `/token` call comes from Claude's backend, the `/authorize` call from the
  user's browser: CORS on `/authorize` is irrelevant, the redirect is what matters.
- A fresh public Funnel hostname is scanned within minutes: `.env`, `.git/config`,
  `.aws/credentials`, `.env.anthropic`, `/anthropic/config.json`, SQL dumps.
  Latchkey must 404 everything outside its routes and never serve files.
- **Refresh** (observed 17:09Z, ~1h after connecting): Claude refreshed
  proactively (no 401 first) with `grant_type=refresh_token`, `client_id` (the
  CIMD URL) and `resource` (the service URL), form-encoded, from its backend.
  Not the `jwt-bearer` grant its metadata also lists. It accepted a rotated
  refresh token; latchkey's non-rotating one works too.

## Design consequences

- One issuer at the host root; one protected resource per service at
  `/{svc}/mcp` with per-path PRM, announced via `WWW-Authenticate`.
- Bind codes and tokens to `resource`; reject a token presented to any other
  service. Reject `/authorize` without `resource` (or with an unknown one).
- CIMD is the primary registration path. Keep DCR for other clients.
- Allowlist CIMD client IDs (default: Claude's) so the SSRF surface is a fixed
  set of URLs, and require `redirect_uri` ∈ fetched doc ∩ configured allowlist.
