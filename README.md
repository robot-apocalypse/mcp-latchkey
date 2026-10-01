# mcp-latchkey

**Per-person, per-service sign-in for your self-hosted MCP servers, built for Claude.ai and any OIDC provider.**

> Status: early development. Phase 1 (sign-in and access control) works; the
> upstream bridge that actually forwards to your MCP servers is Phase 2.

Remote MCP clients such as Claude.ai (web, desktop and mobile) need each server
to be an OAuth 2.1 authorization server. Latchkey does that once, in front of
all your MCP servers:

```
claude.ai ─▶ https://mcp.example/<service>/mcp ─▶ latchkey ─▶ your MCP servers
                                                  ├─ OAuth 2.1 AS (CIMD + DCR, PKCE, RFC 8707 resources)
                                                  ├─ sign-in via your OIDC provider (Google preset)
                                                  └─ who may use which service, from one config file
```

- **Per-service tokens.** Each connector gets a token for exactly one service; a token for
  `recipes` is rejected by `finances`.
- **Per-person access.** Users are declared by email and bound to their IdP account on first
  sign-in; each service lists who may use it. Removing someone takes effect on their next request.
- **Locked-down OAuth.** Codes only go to allowlisted redirect URIs; client metadata documents are
  fetched only from allowlisted URLs; tokens are stored hashed in an encrypted file.
- **No database, no web UI.** One YAML file and a small CLI.

## Quick start

```bash
cp latchkey.example.yaml latchkey.yaml   # edit issuer, users, services
export LATCHKEY_ENCRYPTION_KEY=$(openssl rand -base64 48) GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=...
npm ci && npm run build
node dist/cli.js check-config
node dist/cli.js serve
```

Register `<issuer>/idp/callback` as an authorized redirect URI with your OIDC provider. In
Claude.ai, add a custom connector per service: `<issuer>/<service>/mcp`.

To check sign-in before wiring up a real server, add a service with `builtin: whoami` and
connect to it; its one tool reports the user and service you are signed in as.

On a brand-new hostname, wait a few minutes before connecting: if some of Claude's servers
can't resolve it yet, the first attempt fails with "Couldn't register with … sign-in service".
Retrying works once DNS has propagated.

## CLI

In the Docker image the CLI is on the path as `latchkey`; from a checkout use `node dist/cli.js`.

```
latchkey check-config                         validate config, list services and who may use them
latchkey users                                users, their services and bound IdP accounts
latchkey users unbind <user>                  forget a bound account (next sign-in rebinds)
latchkey tokens list [--user U] [--service S] active grants
latchkey tokens revoke --user U | --service S | --id ID
```

## How Claude.ai connects

Verified against claude.ai in `docs/spike-results.md`: Claude discovers each service from the
`WWW-Authenticate` header, registers with its client metadata document
(`https://claude.ai/oauth/mcp-oauth-client-metadata`), and sends `resource` on both the
authorization and token requests, so several services can share one hostname.

## License

Apache-2.0
