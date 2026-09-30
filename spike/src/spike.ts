// Phase 0 spike: how does Claude.ai behave with two MCP services on one host?
//
// Serves /a/mcp and /b/mcp behind ONE authorization server and logs every
// OAuth parameter Claude sends. Identity is NOT checked: /authorize
// auto-approves. That is only acceptable because the tools are dummies that
// return nothing but the caller's own token metadata, and codes only go to
// Claude's documented callbacks. Tear this down after the spike.
//
// Questions it answers (see docs/design.md, Phase 0):
//  1. Does Claude send `resource` on /authorize and /token?
//  2. Client ID Metadata Document (URL client_id) or /register (DCR)?
//  3. Does Claude discover per-path metadata via WWW-Authenticate on 401?
//     (Root /.well-known/oauth-protected-resource deliberately 404s.)
//  4. Do two connectors on one host keep separate tokens?
import crypto from 'node:crypto'
import fs from 'node:fs'
import { serve } from '@hono/node-server'
import { Hono, type Context } from 'hono'
import { cors } from 'hono/cors'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'

const SERVICES = ['a', 'b'] as const
const REDIRECTS = ['https://claude.ai/api/mcp/auth_callback', 'https://claude.com/api/mcp/auth_callback']
const LOG_FILE = process.env.SPIKE_LOG ?? '/data/spike.jsonl'

function log(event: string, data: Record<string, unknown>): void {
  const line = JSON.stringify({ t: new Date().toISOString(), event, ...data })
  console.log(line)
  try {
    fs.appendFileSync(LOG_FILE, line + '\n')
  } catch {
    // stdout still has it
  }
}

// Short fingerprints so logs can correlate tokens without holding them.
const fp = (s: string | undefined) => (s ? crypto.createHash('sha256').update(s).digest('hex').slice(0, 10) : null)

function origin(c: Context): string {
  const url = new URL(c.req.url)
  return `${c.req.header('x-forwarded-proto') ?? url.protocol.replace(':', '')}://${url.host}`
}

function headersOf(c: Context): Record<string, string> {
  const out: Record<string, string> = {}
  c.req.raw.headers.forEach((v, k) => {
    out[k] = k === 'authorization' ? `${v.split(' ')[0]} <fp:${fp(v.split(' ')[1])}>` : v
  })
  return out
}

interface Code { challenge: string; redirectUri: string; resource: string | null; clientId: string; expires: number }
interface Token { resource: string | null; clientId: string; kind: 'access' | 'refresh' }
const codes = new Map<string, Code>()
const tokens = new Map<string, Token>()

const app = new Hono()
app.use('*', async (c, next) => {
  await next()
  log('http', { method: c.req.method, path: c.req.path, status: c.res.status, ua: c.req.header('user-agent') ?? null })
})
app.use('/.well-known/*', cors())
app.use('/register', cors())
app.use('/token', cors())

app.get('/.well-known/oauth-authorization-server', (c) => {
  const issuer = origin(c)
  return c.json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    client_id_metadata_document_supported: true
  })
})

for (const svc of SERVICES) {
  app.get(`/.well-known/oauth-protected-resource/${svc}/mcp`, (c) => {
    const o = origin(c)
    return c.json({ resource: `${o}/${svc}/mcp`, authorization_servers: [o], scopes_supported: [] })
  })
}
// Deliberately absent so we learn whether Claude uses the 401 header.
app.get('/.well-known/oauth-protected-resource', (c) => c.json({ error: 'not_found' }, 404))

app.post('/register', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
  log('register', { body, headers: headersOf(c) })
  const uris = Array.isArray(body.redirect_uris) ? body.redirect_uris : []
  if (uris.length === 0 || !uris.every((u) => REDIRECTS.includes(u as string))) {
    return c.json({ error: 'invalid_redirect_uri' }, 400)
  }
  return c.json({ client_id: crypto.randomUUID(), redirect_uris: uris, token_endpoint_auth_method: 'none' }, 201)
})

async function fetchClientMetadata(clientId: string): Promise<unknown> {
  // Spike-grade SSRF guard: https only, short timeout, capped size.
  const url = new URL(clientId)
  if (url.protocol !== 'https:') return { error: 'not https' }
  const res = await fetch(url, { signal: AbortSignal.timeout(3000), redirect: 'error' })
  const text = (await res.text()).slice(0, 64 * 1024)
  try {
    return { status: res.status, doc: JSON.parse(text) }
  } catch {
    return { status: res.status, text: text.slice(0, 500) }
  }
}

app.get('/authorize', async (c) => {
  const q = c.req.query()
  const qs = new URL(c.req.url).searchParams
  log('authorize', { query: q, resource_all: qs.getAll('resource'), headers: headersOf(c) })
  if (q.client_id?.startsWith('https://')) {
    log('cimd', { client_id: q.client_id, fetched: await fetchClientMetadata(q.client_id).catch((e) => String(e)) })
  }
  if (!REDIRECTS.includes(q.redirect_uri ?? '')) return c.text('redirect_uri not allowed', 400)
  if (q.code_challenge_method !== 'S256' || !q.code_challenge || !q.state) return c.text('invalid_request', 400)
  const code = crypto.randomBytes(24).toString('base64url')
  codes.set(code, {
    challenge: q.code_challenge,
    redirectUri: q.redirect_uri,
    resource: q.resource ?? null,
    clientId: q.client_id ?? '',
    expires: Date.now() + 600_000
  })
  const to = new URL(q.redirect_uri)
  to.searchParams.set('code', code)
  to.searchParams.set('state', q.state)
  return c.redirect(to.toString())
})

app.post('/token', async (c) => {
  const ct = c.req.header('content-type') ?? ''
  const body = ct.includes('application/x-www-form-urlencoded')
    ? Object.fromEntries(new URLSearchParams(await c.req.text()))
    : ((await c.req.json().catch(() => ({}))) as Record<string, string>)
  const redacted = { ...body, code: fp(body.code), code_verifier: body.code_verifier ? '<set>' : undefined, refresh_token: fp(body.refresh_token) }
  log('token', { body: redacted, headers: headersOf(c) })

  const issue = (resource: string | null, clientId: string) => {
    const access = crypto.randomBytes(24).toString('base64url')
    const refresh = crypto.randomBytes(24).toString('base64url')
    tokens.set(access, { resource, clientId, kind: 'access' })
    tokens.set(refresh, { resource, clientId, kind: 'refresh' })
    log('issued', { access: fp(access), refresh: fp(refresh), resource, clientId })
    return c.json({ access_token: access, token_type: 'bearer', expires_in: 3600, refresh_token: refresh })
  }

  if (body.grant_type === 'refresh_token') {
    const t = tokens.get(body.refresh_token ?? '')
    if (!t || t.kind !== 'refresh') return c.json({ error: 'invalid_grant' }, 400)
    log('refresh', { stored_resource: t.resource, requested_resource: body.resource ?? null })
    return issue(t.resource, t.clientId)
  }
  const pending = codes.get(body.code ?? '')
  codes.delete(body.code ?? '')
  if (!pending || pending.expires < Date.now() || pending.redirectUri !== body.redirect_uri) {
    return c.json({ error: 'invalid_grant' }, 400)
  }
  const computed = crypto.createHash('sha256').update(body.code_verifier ?? '').digest('base64url')
  if (computed !== pending.challenge) return c.json({ error: 'invalid_grant' }, 400)
  log('code-resource', { at_authorize: pending.resource, at_token: body.resource ?? null })
  return issue(pending.resource ?? body.resource ?? null, pending.clientId)
})

function mcpServer(svc: string, token: Token | undefined): Server {
  const server = new Server({ name: `latchkey-spike-${svc}`, version: '0.0.0' }, { capabilities: { tools: {} } })
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: `whoami_${svc}`, description: `Spike: report which token reached service ${svc}.`, inputSchema: { type: 'object', properties: {} } }]
  }))
  server.setRequestHandler(CallToolRequestSchema, async () => ({
    content: [{ type: 'text', text: JSON.stringify({ service: svc, token_resource: token?.resource ?? null, client_id: token?.clientId ?? null }) }]
  }))
  return server
}

for (const svc of SERVICES) {
  app.all(`/${svc}/mcp`, async (c) => {
    const o = origin(c)
    const auth = c.req.header('authorization')
    const bearer = auth?.startsWith('Bearer ') ? auth.slice(7) : undefined
    const token = bearer ? tokens.get(bearer) : undefined
    if (!token || token.kind !== 'access') {
      log('mcp-401', { svc, had_bearer: !!bearer })
      c.header('WWW-Authenticate', `Bearer resource_metadata="${o}/.well-known/oauth-protected-resource/${svc}/mcp"`)
      return c.json({ error: 'unauthorized' }, 401)
    }
    const expected = `${o}/${svc}/mcp`
    log('mcp', { svc, token: fp(bearer), token_resource: token.resource, matches: token.resource === expected })
    const server = mcpServer(svc, token)
    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined })
    transport.onclose = () => { server.close().catch(() => {}) }
    await server.connect(transport)
    return transport.handleRequest(c.req.raw)
  })
}

app.get('/health', (c) => c.json({ ok: true }))

const port = parseInt(process.env.PORT ?? '3900')
serve({ fetch: app.fetch, port, hostname: '127.0.0.1' }, () => console.log(`latchkey spike on 127.0.0.1:${port}`))
