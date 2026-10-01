import crypto from 'node:crypto'
import { Hono, type Context } from 'hono'
import { cors } from 'hono/cors'
import { isAllowed, serviceForResource, serviceResource, userByEmail, type Config } from './config.js'
import { idpCallbackPath, type Idp } from './idp.js'
import { ClientError, resolveClient } from './oauth/clients.js'
import type { Grant, Store } from './store/store.js'

/** Serves an authenticated MCP request for one service (Phase 2: the upstream bridge). */
export type McpHandler = (service: string, grant: Grant, request: Request) => Promise<Response>

export interface AppDeps {
  cfg: Config
  store: Store
  idp: Idp
  mcp: McpHandler
  fetchImpl?: typeof fetch
  log?: (line: Record<string, unknown>) => void
}

interface PendingAuthorize {
  clientId: string
  redirectUri: string
  state: string
  codeChallenge: string
  service: string
  idpState: string
  idpNonce: string
  idpVerifier: string
  expiresAt: number
}

interface PendingCode {
  grant: Grant
  redirectUri: string
  codeChallenge: string
  expiresAt: number
}

const AUTHORIZE_TTL_MS = 10 * 60 * 1000
const CODE_TTL_MS = 60 * 1000
const MAX_PENDING = 1000

const random = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url')

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!)

function page(c: Context, status: 400 | 403 | 500, title: string, body: string) {
  c.header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'")
  c.header('Cache-Control', 'no-store')
  return c.html(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)}</title>` +
      `<body style="font:16px system-ui;max-width:32rem;margin:3rem auto;padding:0 1rem"><h1 style="font-size:1.25rem">${escapeHtml(title)}</h1><p>${escapeHtml(body)}</p>`,
    status
  )
}

function verifyPkce(verifier: string | undefined, challenge: string): boolean {
  if (!verifier || !/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) return false
  const computed = crypto.createHash('sha256').update(verifier).digest('base64url')
  const a = Buffer.from(computed)
  const b = Buffer.from(challenge)
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}

async function readTokenBody(c: Context): Promise<Record<string, string>> {
  const ct = c.req.header('content-type') ?? ''
  if (ct.includes('application/json')) {
    const j = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
    return Object.fromEntries(Object.entries(j).filter(([, v]) => typeof v === 'string')) as Record<string, string>
  }
  return Object.fromEntries(new URLSearchParams(await c.req.text()))
}

/** Bounded map with lazy expiry: a public endpoint must not be able to grow memory without limit. */
class Expiring<T extends { expiresAt: number }> {
  private m = new Map<string, T>()
  set(k: string, v: T) {
    if (this.m.size >= MAX_PENDING) this.sweep()
    if (this.m.size >= MAX_PENDING) this.m.delete(this.m.keys().next().value!)
    this.m.set(k, v)
  }
  take(k: string): T | undefined {
    const v = this.m.get(k)
    this.m.delete(k)
    return v && v.expiresAt >= Date.now() ? v : undefined
  }
  private sweep() {
    const now = Date.now()
    for (const [k, v] of this.m) if (v.expiresAt < now) this.m.delete(k)
  }
}

export function createApp(deps: AppDeps): Hono {
  const { cfg, store, idp } = deps
  const log = deps.log ?? ((line) => console.log(JSON.stringify({ t: new Date().toISOString(), ...line })))
  const pendingAuth = new Expiring<PendingAuthorize>()
  const pendingCodes = new Expiring<PendingCode>()
  const ttl = cfg.oauth.access_token_ttl
  const idle = cfg.oauth.refresh_token_idle_ttl

  const app = new Hono()

  // Paths only: query strings carry codes and state.
  app.use('*', async (c, next) => {
    await next()
    log({ event: 'http', method: c.req.method, path: c.req.path, status: c.res.status })
  })
  app.use('/.well-known/*', cors())
  app.use('/register', cors())
  app.use('/token', cors())

  // ---- discovery ---------------------------------------------------------

  app.get('/.well-known/oauth-authorization-server', (c) => {
    c.header('Cache-Control', 'no-store')
    return c.json({
      issuer: cfg.issuer,
      authorization_endpoint: `${cfg.issuer}/authorize`,
      token_endpoint: `${cfg.issuer}/token`,
      ...(cfg.oauth.dynamic_registration ? { registration_endpoint: `${cfg.issuer}/register` } : {}),
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      client_id_metadata_document_supported: cfg.oauth.cimd_client_ids.length > 0,
      scopes_supported: []
    })
  })

  // RFC 9728, one protected resource per service. There is deliberately no
  // root document: clients find the right one via WWW-Authenticate.
  app.get('/.well-known/oauth-protected-resource/:service/mcp', (c) => {
    const service = c.req.param('service')
    if (!cfg.services[service]) return c.notFound()
    c.header('Cache-Control', 'no-store')
    return c.json({
      resource: serviceResource(cfg, service),
      authorization_servers: [cfg.issuer],
      bearer_methods_supported: ['header'],
      scopes_supported: []
    })
  })

  // ---- RFC 7591 dynamic client registration --------------------------------

  app.post('/register', async (c) => {
    c.header('Cache-Control', 'no-store')
    if (!cfg.oauth.dynamic_registration) return c.json({ error: 'registration_not_supported' }, 400)
    const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
    const uris = Array.isArray(body.redirect_uris) ? body.redirect_uris : []
    if (uris.length === 0 || !uris.every((u) => typeof u === 'string' && cfg.oauth.redirect_uris.includes(u))) {
      log({ event: 'register-rejected', redirect_uris: uris.slice(0, 5) })
      return c.json({ error: 'invalid_redirect_uri', error_description: 'redirect_uris must be allowlisted callback URLs' }, 400)
    }
    const name = typeof body.client_name === 'string' ? body.client_name.slice(0, 100) : undefined
    let clientId: string
    try {
      clientId = await store.registerClient(uris as string[], name)
    } catch {
      return c.json({ error: 'temporarily_unavailable', error_description: 'too many registered clients' }, 503)
    }
    return c.json(
      {
        client_id: clientId,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        redirect_uris: uris,
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        ...(name ? { client_name: name } : {})
      },
      201
    )
  })

  // ---- authorization -----------------------------------------------------

  app.get('/authorize', async (c) => {
    const q = c.req.query()

    // Until client and redirect_uri are validated, errors are shown, never
    // redirected: redirecting to an unvalidated URI is the open-redirect bug.
    let client
    try {
      client = await resolveClient(cfg, store, q.client_id, deps.fetchImpl)
    } catch (e) {
      log({ event: 'authorize-rejected', reason: e instanceof ClientError ? e.message : 'client error' })
      return page(c, 400, 'Invalid sign-in request', e instanceof ClientError ? e.message : 'Unknown client.')
    }
    if (!q.redirect_uri || !client.redirectUris.includes(q.redirect_uri)) {
      log({ event: 'authorize-rejected', reason: 'redirect_uri', redirect_uri: q.redirect_uri ?? null })
      return page(c, 400, 'Invalid sign-in request', 'This redirect_uri is not allowed.')
    }
    const service = serviceForResource(cfg, q.resource)
    if (q.response_type !== 'code' || !q.state || !q.code_challenge || q.code_challenge_method !== 'S256' || !service) {
      log({ event: 'authorize-rejected', reason: 'params', resource: q.resource ?? null })
      return page(c, 400, 'Invalid sign-in request', 'Missing or unsupported parameters (code flow with PKCE S256 and a known resource are required).')
    }

    const idpState = random()
    const idpNonce = random()
    const idpVerifier = random()
    pendingAuth.set(idpState, {
      clientId: client.clientId,
      redirectUri: q.redirect_uri,
      state: q.state,
      codeChallenge: q.code_challenge,
      service,
      idpState,
      idpNonce,
      idpVerifier,
      expiresAt: Date.now() + AUTHORIZE_TTL_MS
    })
    try {
      const url = await idp.authorizationUrl({ state: idpState, nonce: idpNonce, codeVerifier: idpVerifier })
      return c.redirect(url.toString())
    } catch (e) {
      log({ event: 'idp-error', stage: 'discovery', error: String(e) })
      return page(c, 500, 'Sign-in unavailable', 'Could not reach the identity provider. Try again shortly.')
    }
  })

  app.get(idpCallbackPath, async (c) => {
    const idpState = c.req.query('state') ?? ''
    const pending = pendingAuth.take(idpState)
    if (!pending) return page(c, 400, 'Sign-in expired', 'This sign-in link has expired or was already used. Start again from your MCP client.')

    const back = (params: Record<string, string>) => {
      const url = new URL(pending.redirectUri)
      for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v)
      url.searchParams.set('state', pending.state)
      return c.redirect(url.toString())
    }

    if (c.req.query('error')) {
      return back({ error: 'access_denied', error_description: 'Sign-in was cancelled at the identity provider.' })
    }

    let identity
    try {
      // Rebuild the callback URL from the configured issuer: behind a proxy
      // the request URL's host/scheme are not the public ones.
      const callbackUrl = new URL(`${cfg.issuer}${idpCallbackPath}${new URL(c.req.url).search}`)
      identity = await idp.exchange(callbackUrl, { state: pending.idpState, nonce: pending.idpNonce, codeVerifier: pending.idpVerifier })
    } catch (e) {
      log({ event: 'idp-error', stage: 'exchange', error: String(e) })
      return page(c, 500, 'Sign-in failed', 'The identity provider response could not be verified.')
    }

    const user = identity.email && identity.emailVerified ? userByEmail(cfg, identity.email) : undefined
    if (!user) {
      log({ event: 'signin-denied', reason: 'unknown-or-unverified-email', service: pending.service })
      return page(c, 403, 'Not allowed', 'This account is not registered with this server.')
    }
    const binding = await store.bindIdentity(user, identity.iss, identity.sub)
    if (binding === 'mismatch') {
      log({ event: 'signin-denied', reason: 'identity-mismatch', user, service: pending.service })
      return page(c, 403, 'Not allowed', 'This email is bound to a different account. An admin can reset it with `latchkey users unbind`.')
    }
    if (!isAllowed(cfg, user, pending.service)) {
      log({ event: 'signin-denied', reason: 'service-not-allowed', user, service: pending.service })
      return page(c, 403, 'Not allowed', `Your account does not have access to “${pending.service}”.`)
    }

    const code = random()
    pendingCodes.set(code, {
      grant: { user, service: pending.service, clientId: pending.clientId },
      redirectUri: pending.redirectUri,
      codeChallenge: pending.codeChallenge,
      expiresAt: Date.now() + CODE_TTL_MS
    })
    log({ event: 'signin', user, service: pending.service, client: pending.clientId, binding })
    return back({ code, iss: cfg.issuer })
  })

  // ---- token -------------------------------------------------------------

  app.post('/token', async (c) => {
    c.header('Cache-Control', 'no-store')
    c.header('Pragma', 'no-cache')
    const body = await readTokenBody(c)
    const err = (error: string, description?: string, status: 400 | 401 = 400) =>
      c.json({ error, ...(description ? { error_description: description } : {}) }, status)

    // A resource, if given, must name a configured service.
    const requested = body.resource !== undefined ? serviceForResource(cfg, body.resource) : undefined
    if (body.resource !== undefined && !requested) return err('invalid_target')

    if (body.grant_type === 'authorization_code') {
      if (!body.client_id) return err('invalid_client', 'client_id is required', 401)
      const pending = body.code ? pendingCodes.take(body.code) : undefined
      if (!pending) return err('invalid_grant', 'unknown or expired code')
      if (pending.grant.clientId !== body.client_id) return err('invalid_grant', 'code was issued to another client')
      if (pending.redirectUri !== body.redirect_uri) return err('invalid_grant', 'redirect_uri mismatch')
      if (requested && requested !== pending.grant.service) return err('invalid_target')
      if (!verifyPkce(body.code_verifier, pending.codeChallenge)) return err('invalid_grant', 'PKCE verification failed')
      if (!isAllowed(cfg, pending.grant.user, pending.grant.service)) return err('invalid_grant', 'access revoked')
      const t = await store.issue(pending.grant, ttl, idle)
      log({ event: 'token-issued', user: pending.grant.user, service: pending.grant.service })
      return c.json({ access_token: t.accessToken, token_type: 'Bearer', expires_in: t.expiresIn, refresh_token: t.refreshToken })
    }

    if (body.grant_type === 'refresh_token') {
      if (!body.refresh_token) return err('invalid_request')
      // Public clients may omit client_id on refresh; if present it must match.
      const r = await store.refresh(body.refresh_token, body.client_id || undefined, requested, ttl, idle)
      if (!r) return err('invalid_grant')
      if (!isAllowed(cfg, r.grant.user, r.grant.service)) {
        await store.revoke({ user: r.grant.user, service: r.grant.service })
        log({ event: 'refresh-denied', reason: 'access-removed', user: r.grant.user, service: r.grant.service })
        return err('invalid_grant', 'access revoked')
      }
      return c.json({ access_token: r.tokens.accessToken, token_type: 'Bearer', expires_in: r.tokens.expiresIn, refresh_token: r.tokens.refreshToken })
    }

    return err('unsupported_grant_type')
  })

  // ---- protected services ------------------------------------------------

  app.get('/health', (c) => c.json({ ok: true }))

  app.all('/:service/mcp', async (c) => {
    const service = c.req.param('service')
    if (!cfg.services[service]) return c.notFound()
    const challenge = (error?: string) =>
      `Bearer resource_metadata="${cfg.issuer}/.well-known/oauth-protected-resource/${service}/mcp"` + (error ? `, error="${error}"` : '')

    const auth = c.req.header('authorization') ?? ''
    const token = /^Bearer\s+(\S+)$/i.exec(auth)?.[1]
    if (!token) {
      c.header('WWW-Authenticate', challenge())
      return c.json({ error: 'unauthorized' }, 401)
    }
    const grant = store.validateAccess(token)
    // A token for another service is as good as no token here (audience check).
    if (!grant || grant.service !== service) {
      if (grant) log({ event: 'token-wrong-service', user: grant.user, token_service: grant.service, service })
      c.header('WWW-Authenticate', challenge('invalid_token'))
      return c.json({ error: 'invalid_token' }, 401)
    }
    // Config is the source of truth: removing a user takes effect immediately.
    if (!isAllowed(cfg, grant.user, service)) {
      c.header('WWW-Authenticate', challenge('invalid_token'))
      return c.json({ error: 'invalid_token', error_description: 'access revoked' }, 401)
    }
    // Keep a copy of small bodies so a rejected request can be diagnosed.
    const peek = c.req.method === 'POST' ? c.req.raw.clone() : undefined
    const res = await deps.mcp(service, grant, c.req.raw)
    if (res.status >= 400 && peek) {
      const text = await peek.text().catch(() => '')
      let rpc: string | undefined
      try {
        const j = JSON.parse(text) as { method?: string } | Array<{ method?: string }>
        rpc = Array.isArray(j) ? j.map((m) => m.method).join(',') : j.method
      } catch {
        rpc = undefined
      }
      const detail = await res.clone().text().catch(() => '')
      log({ event: 'mcp-rejected', service, status: res.status, rpc: rpc ?? null, protocol: c.req.header('mcp-protocol-version') ?? null, detail: detail.slice(0, 300) })
    }
    return res
  })

  app.notFound((c) => c.json({ error: 'not_found' }, 404))
  app.onError((e, c) => {
    log({ event: 'error', path: c.req.path, error: String(e) })
    return c.json({ error: 'server_error' }, 500)
  })

  return app
}
