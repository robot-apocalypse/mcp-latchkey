import crypto from 'node:crypto'
import type { AddressInfo } from 'node:net'
import { serve, type ServerType } from '@hono/node-server'
import { Hono } from 'hono'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'

// A minimal OIDC provider for tests: discovery, an authorization endpoint that
// immediately "signs in" whoever `nextUser` says, a token endpoint issuing RS256
// id_tokens, and JWKS. Real HTTP, so openid-client is exercised for real.

export interface MockUser { sub: string; email?: string; email_verified?: boolean }

export interface MockIdp {
  issuer: string
  nextUser: MockUser
  close(): Promise<void>
}

export async function startMockIdp(clientId: string): Promise<MockIdp> {
  const { publicKey, privateKey } = await generateKeyPair('RS256')
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' }
  const codes = new Map<string, { user: MockUser; nonce?: string; challenge?: string }>()
  const state: { issuer: string; nextUser: MockUser } = { issuer: '', nextUser: { sub: '1', email: 'ian@example.com', email_verified: true } }

  const app = new Hono()
  app.get('/.well-known/openid-configuration', (c) =>
    c.json({
      issuer: state.issuer,
      authorization_endpoint: `${state.issuer}/authorize`,
      token_endpoint: `${state.issuer}/token`,
      jwks_uri: `${state.issuer}/jwks`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic']
    })
  )
  app.get('/jwks', (c) => c.json({ keys: [jwk] }))
  app.get('/authorize', (c) => {
    const q = c.req.query()
    const code = crypto.randomBytes(16).toString('hex')
    codes.set(code, { user: { ...state.nextUser }, nonce: q.nonce, challenge: q.code_challenge })
    const to = new URL(q.redirect_uri!)
    to.searchParams.set('code', code)
    to.searchParams.set('state', q.state!)
    return c.redirect(to.toString())
  })
  app.post('/token', async (c) => {
    const body = Object.fromEntries(new URLSearchParams(await c.req.text()))
    const entry = codes.get(body.code ?? '')
    codes.delete(body.code ?? '')
    if (!entry) return c.json({ error: 'invalid_grant' }, 400)
    const computed = crypto.createHash('sha256').update(body.code_verifier ?? '').digest('base64url')
    if (entry.challenge && computed !== entry.challenge) return c.json({ error: 'invalid_grant' }, 400)
    const idToken = await new SignJWT({ nonce: entry.nonce, email: entry.user.email, email_verified: entry.user.email_verified })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuer(state.issuer)
      .setAudience(clientId)
      .setSubject(entry.user.sub)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey)
    return c.json({ access_token: 'idp-at', token_type: 'Bearer', expires_in: 300, id_token: idToken })
  })

  const server: ServerType = await new Promise((resolve) => {
    const s = serve({ fetch: app.fetch, port: 0, hostname: '127.0.0.1' }, () => resolve(s))
  })
  state.issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`

  return {
    get issuer() {
      return state.issuer
    },
    get nextUser() {
      return state.nextUser
    },
    set nextUser(u: MockUser) {
      state.nextUser = u
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve()))
  }
}
