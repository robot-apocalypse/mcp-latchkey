import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { createApp } from './app.js'
import { CLAUDE_CIMD_CLIENT_IDS, CLAUDE_REDIRECT_URIS, parseConfig, type Config } from './config.js'
import { createIdp } from './idp.js'
import { _clearClientCache } from './oauth/clients.js'
import { Store } from './store/store.js'
import { startMockIdp, type MockIdp } from './test/mockIdp.js'

// Full sign-in as Claude.ai does it (see docs/spike-results.md): CIMD client,
// resource on authorize and token, PKCE, then MCP calls with the bearer.

const ISSUER = 'https://latchkey.test'
const CLAUDE = CLAUDE_CIMD_CLIENT_IDS[0]!
const CALLBACK = CLAUDE_REDIRECT_URIS[0]!

const claudeDoc = { client_id: CLAUDE, client_name: 'Claude', redirect_uris: [CALLBACK], token_endpoint_auth_method: 'none' }
const fakeFetch: typeof fetch = async (input) => {
  if (String(input) === CLAUDE) return new Response(JSON.stringify(claudeDoc), { headers: { 'content-type': 'application/json' } })
  return new Response('nope', { status: 404 })
}

let idpServer: MockIdp
let dir: string
let cfg: Config
let app: ReturnType<typeof createApp>
let store: Store
const events: Array<Record<string, unknown>> = []

function makeConfig(extra = ''): Config {
  return parseConfig(
    `
issuer: ${ISSUER}
data_dir: ${dir}
encryption_key: ${'k'.repeat(32)}
idp:
  issuer: ${idpServer.issuer}
  client_id: latchkey-test
  client_secret: shh
users:
  ian: { email: ian@example.com }
  partner: { email: partner@example.com }
services:
  toggl: { allow: [ian] }
  mealie: { allow: [ian, partner] }
${extra}`,
    {}
  )
}

function build(c: Config) {
  cfg = c
  store = new Store(dir, cfg.encryption_key)
  app = createApp({
    cfg,
    store,
    idp: createIdp(cfg, { allowInsecure: true }),
    fetchImpl: fakeFetch,
    log: (l) => events.push(l),
    mcp: async (service, grant) => Response.json({ service, user: grant.user })
  })
}

beforeAll(async () => {
  idpServer = await startMockIdp('latchkey-test')
})
afterAll(async () => {
  await idpServer.close()
})
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'latchkey-e2e-'))
  events.length = 0
  _clearClientCache()
  idpServer.nextUser = { sub: 'google-ian', email: 'ian@example.com', email_verified: true }
  build(makeConfig())
})

const pkce = () => {
  const verifier = crypto.randomBytes(32).toString('base64url')
  return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') }
}

const local = (url: string) => {
  const u = new URL(url)
  expect(u.origin).toBe(ISSUER)
  return u.pathname + u.search
}

/** Runs /authorize → IdP → /idp/callback and returns the final redirect (to Claude) or the error response. */
async function authorize(opts: { service?: string; resource?: string; redirectUri?: string; clientId?: string; challenge: string }) {
  const q = new URLSearchParams({
    response_type: 'code',
    client_id: opts.clientId ?? CLAUDE,
    redirect_uri: opts.redirectUri ?? CALLBACK,
    state: 'claude-state',
    code_challenge: opts.challenge,
    code_challenge_method: 'S256',
    resource: opts.resource ?? `${ISSUER}/${opts.service ?? 'toggl'}/mcp`
  })
  const r1 = await app.request(`/authorize?${q}`)
  if (r1.status !== 302) return { res: r1 }
  const toIdp = r1.headers.get('location')!
  expect(toIdp.startsWith(idpServer.issuer)).toBe(true)
  const r2 = await fetch(toIdp, { redirect: 'manual' })
  const r3 = await app.request(local(r2.headers.get('location')!))
  return { res: r3, location: r3.headers.get('location') }
}

async function token(params: Record<string, string>) {
  return app.request('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString()
  })
}

async function signIn(service = 'toggl') {
  const { verifier, challenge } = pkce()
  const { location } = await authorize({ service, challenge })
  const back = new URL(location!)
  expect(back.origin + back.pathname).toBe(CALLBACK)
  expect(back.searchParams.get('state')).toBe('claude-state')
  const res = await token({
    grant_type: 'authorization_code',
    client_id: CLAUDE,
    code: back.searchParams.get('code')!,
    code_verifier: verifier,
    redirect_uri: CALLBACK,
    resource: `${ISSUER}/${service}/mcp`
  })
  expect(res.status).toBe(200)
  return (await res.json()) as { access_token: string; refresh_token: string; expires_in: number }
}

const mcp = (service: string, tok?: string) => app.request(`/${service}/mcp`, { method: 'POST', headers: tok ? { authorization: `Bearer ${tok}` } : {} })

describe('discovery', () => {
  it('advertises CIMD, DCR and per-service protected resources', async () => {
    const as = await (await app.request('/.well-known/oauth-authorization-server')).json()
    expect(as).toMatchObject({ issuer: ISSUER, client_id_metadata_document_supported: true })
    expect(as).not.toHaveProperty('registration_endpoint')
    expect((await app.request('/register', { method: 'POST', body: '{}' })).status).toBe(400)
    const prm = await (await app.request('/.well-known/oauth-protected-resource/toggl/mcp')).json()
    expect(prm).toMatchObject({ resource: `${ISSUER}/toggl/mcp`, authorization_servers: [ISSUER] })
    expect((await app.request('/.well-known/oauth-protected-resource')).status).toBe(404)
    expect((await app.request('/.well-known/oauth-protected-resource/nope/mcp')).status).toBe(404)
  })

  it('401s with a per-service WWW-Authenticate challenge', async () => {
    const r = await mcp('toggl')
    expect(r.status).toBe(401)
    expect(r.headers.get('www-authenticate')).toBe(`Bearer resource_metadata="${ISSUER}/.well-known/oauth-protected-resource/toggl/mcp"`)
  })

  it('404s everything else (scanners)', async () => {
    for (const p of ['/', '/.env', '/.git/config', '/nope/mcp', '/toggl']) expect((await app.request(p)).status).toBe(404)
  })
})

describe('sign-in', () => {
  it('runs the Claude flow end to end and serves the MCP request', async () => {
    const t = await signIn('toggl')
    expect(t.expires_in).toBe(3600)
    const r = await mcp('toggl', t.access_token)
    expect(await r.json()).toEqual({ service: 'toggl', user: 'ian' })
    expect(events.some((e) => e.event === 'signin' && e.binding === 'bound')).toBe(true)
  })

  it('scopes tokens to their service', async () => {
    const t = await signIn('mealie')
    expect((await mcp('mealie', t.access_token)).status).toBe(200)
    const other = await mcp('toggl', t.access_token)
    expect(other.status).toBe(401)
    expect(other.headers.get('www-authenticate')).toContain('error="invalid_token"')
  })

  it('refreshes for the same client and service only', async () => {
    const t = await signIn('toggl')
    const bad = await token({ grant_type: 'refresh_token', client_id: CLAUDE, refresh_token: t.refresh_token, resource: `${ISSUER}/mealie/mcp` })
    expect(bad.status).toBe(400)
    const ok = await token({ grant_type: 'refresh_token', client_id: CLAUDE, refresh_token: t.refresh_token, resource: `${ISSUER}/toggl/mcp` })
    const fresh = (await ok.json()) as { access_token: string; refresh_token: string }
    expect(fresh.refresh_token).toBe(t.refresh_token)
    expect((await mcp('toggl', fresh.access_token)).status).toBe(200)
  })

  it('accepts a refresh without client_id, but not with the wrong one', async () => {
    const t = await signIn('toggl')
    expect((await token({ grant_type: 'refresh_token', refresh_token: t.refresh_token })).status).toBe(200)
    expect((await token({ grant_type: 'refresh_token', client_id: 'someone-else', refresh_token: t.refresh_token })).status).toBe(400)
  })

  it('requires client_id when redeeming a code', async () => {
    const { verifier, challenge } = pkce()
    const { location } = await authorize({ challenge })
    const code = new URL(location!).searchParams.get('code')!
    expect((await token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: CALLBACK })).status).toBe(401)
  })

  it('refuses a user without access to the service', async () => {
    idpServer.nextUser = { sub: 'google-partner', email: 'partner@example.com', email_verified: true }
    const { res } = await authorize({ service: 'toggl', challenge: pkce().challenge })
    expect(res.status).toBe(403)
    expect(await res.text()).toContain('does not have access')
  })

  it('refuses unknown and unverified emails', async () => {
    idpServer.nextUser = { sub: 'x', email: 'stranger@example.com', email_verified: true }
    expect((await authorize({ challenge: pkce().challenge })).res.status).toBe(403)
    idpServer.nextUser = { sub: 'google-ian', email: 'ian@example.com', email_verified: false }
    expect((await authorize({ challenge: pkce().challenge })).res.status).toBe(403)
  })

  it('refuses a different account presenting a bound email', async () => {
    await signIn('toggl')
    idpServer.nextUser = { sub: 'someone-else', email: 'ian@example.com', email_verified: true }
    const { res } = await authorize({ challenge: pkce().challenge })
    expect(res.status).toBe(403)
    expect(await res.text()).toContain('bound to a different account')
  })

  it('never redirects to an unlisted redirect_uri, or for an unlisted CIMD client', async () => {
    const evil = await authorize({ redirectUri: 'https://evil.example/cb', challenge: pkce().challenge })
    expect(evil.res.status).toBe(400)
    expect(evil.res.headers.get('location')).toBeNull()
    const otherClient = await authorize({ clientId: 'https://evil.example/client.json', challenge: pkce().challenge })
    expect(otherClient.res.status).toBe(400)
  })

  it('requires a known resource', async () => {
    expect((await authorize({ resource: 'https://evil.example/x/mcp', challenge: pkce().challenge })).res.status).toBe(400)
    expect((await authorize({ resource: `${ISSUER}/nope/mcp`, challenge: pkce().challenge })).res.status).toBe(400)
  })

  it('rejects a bad PKCE verifier and code reuse', async () => {
    const { verifier, challenge } = pkce()
    const { location } = await authorize({ challenge })
    const code = new URL(location!).searchParams.get('code')!
    const base = { grant_type: 'authorization_code', client_id: CLAUDE, code, redirect_uri: CALLBACK }
    expect((await token({ ...base, code_verifier: pkce().verifier })).status).toBe(400)
    // the failed attempt consumed the code
    expect((await token({ ...base, code_verifier: verifier })).status).toBe(400)
  })

  it('stops working as soon as config removes access', async () => {
    const t = await signIn('mealie')
    build({ ...cfg, services: { ...cfg.services, mealie: { allow: [] } } })
    expect((await mcp('mealie', t.access_token)).status).toBe(401)
    const r = await token({ grant_type: 'refresh_token', client_id: CLAUDE, refresh_token: t.refresh_token })
    expect(r.status).toBe(400)
  })
})

describe('dynamic client registration', () => {
  beforeEach(() => build(makeConfig('oauth: { dynamic_registration: true }')))

  it('registers only allowlisted redirect URIs and the client can sign in', async () => {
    const bad = await app.request('/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: ['https://evil.example/cb'] }) })
    expect(bad.status).toBe(400)
    const ok = await app.request('/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: [CALLBACK], client_name: 'Other' }) })
    expect(ok.status).toBe(201)
    const { client_id } = (await ok.json()) as { client_id: string }
    const { location } = await authorize({ clientId: client_id, challenge: pkce().challenge })
    expect(new URL(location!).searchParams.get('code')).toBeTruthy()
  })
})
