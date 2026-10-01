# mcp-latchkey design

Per-person, per-service sign-in for self-hosted MCP servers. One gateway, one
hostname, one path per service; any OIDC provider proves identity; one YAML
file says who may use what.

## Goals and non-goals

- **Goal:** let a household or small group use remote MCP clients (Claude.ai
  web, desktop, mobile) against self-hosted MCP servers, with per-person,
  per-service access and no database or web UI.
- **Non-goal:** a user directory. No sign-up, invites, password resets or admin
  UI. Identity lives in the OIDC provider; access lives in config.
- **Non-goal:** being an enterprise gateway (Obot, Pomerium, ContextForge cover
  that).

## Request flow

```
client ─▶ /<svc>/mcp ── no/invalid token ─▶ 401 + WWW-Authenticate: resource_metadata=<PRM for svc>
         GET /.well-known/oauth-protected-resource/<svc>/mcp ─▶ { resource, authorization_servers: [issuer] }
         GET /.well-known/oauth-authorization-server
browser ─▶ /authorize (client_id = CIMD URL, resource = <issuer>/<svc>/mcp, PKCE S256)
         ─▶ IdP sign-in (OIDC code + PKCE + nonce) ─▶ /idp/callback
         ─▶ redirect to client callback with code (+ iss)
client ─▶ /token (code, verifier, resource) ─▶ access + refresh token bound to (user, svc, client)
client ─▶ /<svc>/mcp with Bearer ─▶ upstream
```

Verified against claude.ai in `spike-results.md`.

## Decisions

### Sign-in and access (Phase 1, implemented)

- **One issuer at the host root**, one protected resource per service. No root
  PRM document; discovery is via `WWW-Authenticate`.
- **Tokens are bound to (user, service, client).** `resource` is required at
  `/authorize`; a token presented to another service is `invalid_token`.
- **Config is the source of truth for access.** Every MCP request and every
  refresh re-checks `services.<svc>.allow`; removing a user takes effect at
  their next request.
- **Identity binding.** Users are declared by email; the IdP must report it
  verified. The first sign-in binds the user to the IdP's `(iss, sub)`; later
  sign-ins with the same email but another account are refused
  (`latchkey users unbind` resets).
- **Client registration.**
  - CIMD is the primary path (Claude uses it). Only URLs in
    `oauth.cimd_client_ids` are fetched: https, no redirects, 5s timeout, 64KB
    cap, document must name itself, cached 1h.
  - DCR is off by default (it is unauthenticated and persistent). When on,
    clients that never obtain a grant are pruned after 24h and the total is
    capped at 100.
  - Usable redirect URIs = client's own list ∩ `oauth.redirect_uris`. Errors
    before the redirect URI is validated are shown, never redirected.
- **Tokens.** Opaque random tokens, stored only as SHA-256 hashes in an
  AES-256-GCM encrypted state file. Access tokens 1h. Refresh tokens do not
  rotate (a lost response must not strand a client) and expire after 90 days
  unused. Refresh may omit `client_id` (public client); if present it must
  match.
- **State file** is shared by the server and the CLI; the server reloads it when
  it changes on disk (except while its own writes are in flight).
- **Logging:** paths only (query strings carry codes and state), never tokens.
  Sign-in decisions are logged with user and service.

### Upstream bridge (Phase 2, planned)

- The gateway connects to every upstream as an MCP **client** (SDK stdio or
  Streamable HTTP client) and serves it back per request with the low-level
  `Server`, passing tool JSON Schemas through unchanged. Uniform tool hiding,
  keepalive and audit logging across upstream types.
- **stdio upstreams:** run untrusted ones with `latchkey bridge` in their own
  container (2026-10-01 pentest: an in-process child runs as latchkey's uid and
  can read its secrets from `/proc/1/environ` and reach `127.0.0.1` upstreams).
  In-process children are for trusted servers. Either way: exactly one long-lived child per service, spawned lazily,
  respawned on exit, calls serialized (mutation confirm tokens and rotating
  upstream credentials live in that one process). Each child gets **only**
  `PATH`, the env listed for that service in config, its own `HOME` under
  `data_dir/<svc>`, and the MCP SDK's non-secret defaults (`LOGNAME`, `SHELL`,
  `TERM`, `USER`). Never the gateway's own environment.
- **HTTP upstreams:** URL plus optional credential presented to the upstream;
  the caller's bearer is never forwarded. Optional `X-MCP-User` header with the
  verified user.
- **Per service:** `hide_tools` (removed from `tools/list` and refused on call),
  optional `keepalive: { tool, args, every }`, tool call timeout (default 5m).
- **Audit log:** one line per tool call (user, service, tool, outcome,
  duration); no arguments or results.
- **Health:** `/health` reports each upstream's state.
- The 400 at the start of each session is Claude probing protocol 2026-07-28
  (`server/discover`) before falling back; see `spike-results.md`. Bump the SDK
  when it supports that version.

### Deployment (Phase 3+)

- Docker image; Tailscale Funnel sidecar owns the network namespace. Upstreams
  that need the tailnet (e.g. Firefly) share that namespace on their own
  127.0.0.1 ports; others are reached over the tailnet.
- Migration order: Toggl (stdio) → Mealie (HTTP) → gtasks (needs `AUTH_MODE=none`
  and a CLI Google Tasks sign-in) → Firefly. Old sidecars retire only after the
  new connector works.

## Known v1 limits

- **One upstream credential per service.** Latchkey decides who may use a
  service; the upstream acts as whoever configured it. A second user of the
  Toggl service acts as the owner's Toggl account.
- **Tools only.** Server-to-client features (notifications, progress, sampling,
  elicitation) are not forwarded through the bridge.
- **Config reload needs a restart** (or SIGHUP, later).
- **CLI vs server write race:** a revoke written at the same moment the server
  persists can be overwritten; re-run the revoke if it coincides with activity.
- **Pending sign-ins are bounded (1000) in memory:** flooding `/authorize` can
  evict someone's in-progress sign-in (they retry). Restart drops pending
  sign-ins.
