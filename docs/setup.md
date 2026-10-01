# Setting up latchkey for Claude.ai

This walks through a complete setup: a Google sign-in, a public HTTPS hostname
via Tailscale Funnel, and one connector per service in Claude.ai. Any OIDC
provider and any HTTPS reverse proxy work too; Google and Funnel are just the
shortest path.

## 1. Pick a public URL

Latchkey needs one public HTTPS origin; services live under it at
`/<service>/mcp`. With Tailscale Funnel that is
`https://<hostname>.<tailnet>.ts.net`. This is the `issuer` in the config.

`examples/docker-compose.yml` runs a Tailscale sidecar. Give it this serve
config as `tailscale-serve.json`:

```json
{
  "TCP": { "443": { "HTTPS": true } },
  "Web": { "${TS_CERT_DOMAIN}:443": { "Handlers": { "/": { "Proxy": "http://127.0.0.1:8080" } } } },
  "AllowFunnel": { "${TS_CERT_DOMAIN}:443": true }
}
```

Funnel must be allowed for the node in your tailnet policy. Create an auth key
at Tailscale admin → Settings → Keys and put it in `.env` as `TS_AUTHKEY`.

A brand-new hostname can take a few minutes to resolve everywhere. If Claude's
first connect fails with "Couldn't register with … sign-in service", wait and
retry.

## 2. Create the OIDC client

**Google:** Google Cloud Console → APIs & Services → Credentials → Create
credentials → OAuth client ID → *Web application*. Add the authorized redirect
URI `<issuer>/idp/callback`. Latchkey asks only for `openid email`. Put the
client ID and secret in `.env` as `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`.

**Other providers** (Authentik, Pocket-ID, Keycloak, …): create a confidential
OIDC client with the same redirect URI and set `idp.issuer` instead of
`preset: google`. The provider must return a verified `email` claim.

## 3. Write the config

Start from `latchkey.example.yaml`:

- `issuer`: the public URL from step 1.
- `encryption_key`: `openssl rand -base64 48`, kept in `.env`.
- `users`: everyone who may sign in, by email.
- `services`: one entry per MCP server with `allow`, plus one of
  - `builtin: whoami` — a test tool that reports who you are signed in as;
  - `stdio: { command, args, env }` — latchkey runs the server itself;
  - `http: { url, headers }` — a Streamable HTTP server only latchkey can reach.

Check it with `latchkey check-config` (in Docker:
`docker compose run --rm latchkey latchkey check-config`).

### stdio servers

Latchkey keeps exactly one process per stdio service and runs calls to it one
at a time. The process gets only the `env` you list, `PATH`,
`HOME=<data_dir>/<service>` (so credentials it writes survive restarts) and the
MCP SDK's non-secret defaults (`LOGNAME`, `SHELL`, `TERM`, `USER`); never
latchkey's own environment or secrets. The image includes Node.js, so `npx`
packages work:

```yaml
  toggl:
    allow: [alex]
    stdio:
      command: npx
      args: [-y, "@togglhq/mcp@1.11.88"]   # pin versions
      env: { TOGGL_SENTRY: "off", NPM_CONFIG_UPDATE_NOTIFIER: "false" }
    hide_tools: [auth, logout]             # tools that make no sense remotely
    keepalive: { tool: workspace, args: { action: get-context }, every: 24h }
```

If the server needs a one-time interactive sign-in, run it in the container
with the same `HOME`, for example
`docker compose exec latchkey sh -c 'HOME=/data/toggl npx -y @togglhq/mcp@1.11.88 auth --manual'`.

### HTTP servers

Turn off the server's own authentication and make sure only latchkey can reach
it: run it in the sidecar's network namespace bound to `127.0.0.1`, or on a
private network. Put any credential the server itself expects in `headers`;
the caller's latchkey token is never forwarded.

## 4. Start it and test with whoami

```bash
docker compose up -d
docker compose logs -f latchkey
```

Add a `builtin: whoami` service, then in Claude.ai: Settings → Connectors →
Add custom connector → `<issuer>/whoami/mcp`. Sign in, and ask Claude to run
`whoami`. It should report your user and the service.

## 5. Connect the real services

Add one custom connector per service (`<issuer>/<service>/mcp`). Each gets its
own token, usable only for that service.

Config changes take effect on restart: `docker compose restart latchkey`.

## Operating it

```bash
latchkey users                          # who can use what, and bound accounts
latchkey tokens list                    # active grants
latchkey tokens revoke --user alex      # sign someone out everywhere
latchkey users unbind alex              # let alex sign in with a different account
```

Removing a user from a service's `allow` list takes effect on their next
request, no revoke needed.

Logs are JSON lines: `signin`, `signin-denied`, `token-issued`, one `tool`
line per tool call (user, service, tool, ok, ms; never arguments), and
`upstream-*` events.
