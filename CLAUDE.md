# mcp-latchkey

An OAuth 2.1 / OIDC gateway that gives self-hosted MCP servers per-person, per-service sign-in for Claude.ai remote connectors. It's open source (Apache-2.0) and public on GitHub as `robot-apocalypse/mcp-latchkey`.

**This repo is public.** Keep private deployment details (real hostnames, tailnet names, personal service lists, emails, tokens) out of code, docs, tests, commit messages and this file. Use `example.com`, `your-tailnet`, `alex`/`sam` as the existing docs do. Deployment config lives in a separate private repo.

## Docs to read first

- `docs/design.md`: request flow, decisions, known v1 limits, security review summary. Its "Upstream bridge (Phase 2, planned)" heading is stale: the bridge (`src/upstream.ts`, `src/bridge.ts`) is implemented.
- `docs/spike-results.md`: Claude.ai's observed OAuth behaviour (CIMD client ID, `resource` on authorize and token, discovery via `WWW-Authenticate`). Treat it as ground truth for what Claude actually does, and don't "fix" code against it without re-verifying.
- `docs/setup.md`: user walkthrough. `SECURITY.md`: threat model and scope. `latchkey.example.yaml` and `examples/docker-compose.yml`.

## Commands

```bash
npm ci
npm run typecheck
npm test            # vitest: unit tests + e2e OAuth flow against src/test/mockIdp.ts
npm run build       # tsc -p tsconfig.build.json -> dist/
node dist/cli.js check-config   # CLI from a checkout; in the image it is `latchkey`
```

Node >= 22 (the Dockerfile uses node:22-alpine). CI (`.github/workflows/ci.yml`) runs typecheck, test and build on push and PR. On pushes to `main` it publishes `ghcr.io/robot-apocalypse/mcp-latchkey:edge` (amd64+arm64), and `v*` tags publish semver tags.

## Source map

- `cli.ts`: `serve`, `bridge`, `check-config`, `users`, `tokens`.
- `config.ts`: zod schema for `latchkey.yaml` with `${VAR}` interpolation. Each service is exactly one of `builtin`, `stdio` or `http`, plus `allow`, `hide_tools`, `keepalive` and `timeout`.
- `app.ts`: Hono app with the OAuth endpoints (`/authorize`, `/token`, PRM/AS metadata, `/idp/callback`, consent page) and `/<svc>/mcp` proxying.
- `idp.ts`: OIDC client (Google preset or any issuer). `seal.ts`: sealed sign-in state.
- `oauth/clients.ts`: CIMD fetch allowlist and optional DCR.
- `store/`: encrypted state file (AES-256-GCM, hashed tokens), locked atomic writes, reload on disk change.
- `upstream.ts`: MCP client per upstream (stdio child or Streamable HTTP), re-served per request. Handles tool hiding, keepalive and audit lines.
- `bridge.ts`: `latchkey bridge`, which wraps one stdio server as HTTP behind a shared `BRIDGE_TOKEN`.
- `builtin.ts`: `whoami` test service.

## Invariants (don't regress)

- Tokens are bound to (user, service, client). A token for one service is refused by another, and `resource` is required.
- Access is re-checked against `allow` on every MCP request and every refresh.
- Never log tokens, query strings, bodies or tool arguments. Upstream errors returned to clients stay generic.
- stdio children get only `PATH`, their configured `env`, `HOME=<data_dir>/<svc>` and the SDK's non-secret defaults, never the gateway's env. The caller's bearer is never forwarded upstream.
- Codes go only to allowlisted redirect URIs, and CIMD documents are fetched only from allowlisted URLs. DCR is off by default.
- Config reload needs a process restart (no SIGHUP yet).

## Housekeeping

- `spike/` holds only an ignored `dist/` and `node_modules/` from the Phase 0 spike. No tracked source remains.
- Commit style: conventional-ish prefixes (`feat:`, `docs:`, `security:`).
