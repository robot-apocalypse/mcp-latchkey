# mcp-latchkey

[![ci](https://github.com/robot-apocalypse/mcp-latchkey/actions/workflows/ci.yml/badge.svg)](https://github.com/robot-apocalypse/mcp-latchkey/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Per-person, per-service sign-in for your self-hosted MCP servers, built for Claude.ai and any OIDC provider.**

Remote MCP clients like Claude.ai (web, desktop and mobile) need every MCP server to be an
OAuth 2.1 authorization server. Most self-hosted MCP servers aren't, and building that into each
one means copying the same security-sensitive code again and again. Latchkey does it once, in
front of all of them:

```
claude.ai ──▶ https://mcp.example/<service>/mcp ──▶ latchkey ──┬─ stdio ─▶ npx some-mcp-server
                                                               ├─ http ──▶ 127.0.0.1:3101 (auth off)
                                                               └─ http ──▶ private-host:8000
```

- **One hostname, one path per service.** Add a service with a few lines of config; no new
  proxy, certificate or OAuth code.
- **Per-service tokens.** Each connector gets a token for exactly one service. A token for
  `recipes` is refused by `finances`.
- **Per-person access.** People sign in with your OIDC provider (Google preset; Authentik,
  Pocket-ID, Keycloak, …) and each service lists who may use it. Removing someone takes effect
  on their next request.
- **Wraps stdio and HTTP servers.** Runs stdio servers itself (one long-lived process each,
  with only the environment you give it) or forwards to Streamable HTTP servers. Hide tools that
  make no sense remotely, keep upstream sessions alive, and get an audit line per tool call.
- **Locked-down OAuth.** Codes only go to allowlisted redirect URIs; client metadata documents
  are fetched only from allowlisted URLs; tokens are stored hashed in an encrypted file.
- **No database, no web UI.** One YAML file and a small CLI.

Status: early, in daily use by the author with Claude.ai against four upstreams. See
[docs/design.md](docs/design.md) for the design and known limits.

## Quick start

```yaml
# latchkey.yaml
issuer: https://mcp.your-tailnet.ts.net
encryption_key: ${LATCHKEY_ENCRYPTION_KEY}
idp:
  preset: google
  client_id: ${GOOGLE_CLIENT_ID}
  client_secret: ${GOOGLE_CLIENT_SECRET}
users:
  alex:
    email: alex@example.com
services:
  whoami:
    allow: [alex]
    builtin: whoami
  recipes:
    allow: [alex]
    http:
      url: http://127.0.0.1:3101/mcp
```

```bash
docker run -d --name latchkey \
  -v $PWD/latchkey.yaml:/config/latchkey.yaml:ro -v $PWD/data:/data \
  -e LATCHKEY_ENCRYPTION_KEY -e GOOGLE_CLIENT_ID -e GOOGLE_CLIENT_SECRET \
  ghcr.io/robot-apocalypse/mcp-latchkey:edge
```

Put it behind HTTPS at `issuer` (e.g. Tailscale Funnel, see
[examples/docker-compose.yml](examples/docker-compose.yml)), register `<issuer>/idp/callback`
with your OIDC provider, then add a Claude.ai custom connector for `<issuer>/whoami/mcp`.

The full walkthrough is in **[docs/setup.md](docs/setup.md)**.

## CLI

In the image the CLI is on the path as `latchkey`; from a checkout use `node dist/cli.js`.

```
latchkey serve                                run the gateway
latchkey check-config                         validate config, list services and who may use them
latchkey users                                users, their services and bound IdP accounts
latchkey users unbind <user>                  forget a bound account (next sign-in rebinds)
latchkey tokens list [--user U] [--service S] active grants
latchkey tokens revoke --user U | --service S | --id ID
```

## How Claude.ai connects

Verified against claude.ai ([docs/spike-results.md](docs/spike-results.md)): Claude discovers
each service from the `WWW-Authenticate` header, registers with its client metadata document
(`https://claude.ai/oauth/mcp-oauth-client-metadata`), and sends `resource` on both the
authorization and token requests, so several services can share one hostname with separately
scoped tokens.

## Development

```bash
npm ci
npm test          # unit tests + an end-to-end OAuth flow against a mock OIDC provider
npm run build
```

## Security

See [SECURITY.md](SECURITY.md) for what latchkey does and does not protect, and how to report
a vulnerability.

## License

[Apache-2.0](LICENSE)
