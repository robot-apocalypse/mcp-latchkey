# Security

Latchkey sits between the public internet and your MCP servers, so security
reports are very welcome.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (Security → Report a
vulnerability) rather than a public issue. Include steps to reproduce and the
version or commit you tested. I aim to acknowledge reports within a week.

## What latchkey protects, and what it doesn't

Latchkey decides **who** may reach **which** MCP service. In scope:

- The OAuth 2.1 authorization server: client registration (CIMD and DCR),
  `/authorize`, `/token`, PKCE, `resource` binding, redirect URI handling.
- Sign-in via the configured OIDC provider and identity binding.
- Token storage (hashed, encrypted at rest) and revocation.
- The boundary to upstreams: the `latchkey bridge` shared secret, headers sent
  to HTTP servers, hidden tools.
- Not a sandbox: a stdio server run *inside* latchkey (`stdio:`) shares its
  user, container and network, and can read its secrets. Run untrusted servers
  with `latchkey bridge` in their own container.

Out of scope, by design:

- **What an upstream does once called.** Each service acts with the single
  credential it was configured with; latchkey does not give upstreams
  per-user identities (see `docs/design.md`, "Known v1 limits").
- **Network exposure of upstreams.** HTTP upstreams must be reachable only by
  latchkey (for example `127.0.0.1` in the same network namespace, or a
  private network). An upstream reachable directly bypasses latchkey.
- **The OIDC provider's own security** and the host latchkey runs on.

## Hardening defaults

- Codes are only ever sent to allowlisted redirect URIs (default: Claude's).
- Client metadata documents are fetched only from allowlisted URLs.
- Dynamic client registration is off by default.
- Tokens are bound to one user, one service and one client, stored as SHA-256
  hashes in an AES-256-GCM encrypted file.
- Unknown paths return 404; request logs contain paths only, never query
  strings, bodies or tokens.
