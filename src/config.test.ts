import { describe, expect, it } from 'vitest'
import { CLAUDE_REDIRECT_URIS, isAllowed, parseConfig, parseDuration, serviceForResource, userByEmail } from './config.js'

const env = { GOOGLE_ID: 'gid', GOOGLE_SECRET: 'gsecret', KEY: 'k'.repeat(32) }
const base = `
issuer: https://mcp.example.ts.net/
encryption_key: \${KEY}
idp: { preset: google, client_id: "\${GOOGLE_ID}", client_secret: "\${GOOGLE_SECRET}" }
users:
  ian: { email: Ian@Example.com }
  partner: { email: p@example.com }
services:
  mealie: { allow: [ian, partner], http: { url: http://x } }
  firefly: { allow: [ian] }
`

describe('parseConfig', () => {
  it('applies defaults, presets and env interpolation', () => {
    const cfg = parseConfig(base, env)
    expect(cfg.issuer).toBe('https://mcp.example.ts.net')
    expect(cfg.idp).toEqual({ issuer: 'https://accounts.google.com', clientId: 'gid', clientSecret: 'gsecret', scopes: ['openid', 'email'] })
    expect(cfg.oauth.redirect_uris).toEqual(CLAUDE_REDIRECT_URIS)
    expect(cfg.oauth.access_token_ttl).toBe(3_600_000)
    expect(cfg.oauth.refresh_token_idle_ttl).toBe(90 * 86_400_000)
    expect(cfg.users.ian?.email).toBe('ian@example.com')
    expect(cfg.services.mealie?.http).toEqual({ url: 'http://x' })
  })

  it('fails on a missing env var, naming it', () => {
    expect(() => parseConfig(base, { ...env, GOOGLE_SECRET: undefined })).toThrow(/GOOGLE_SECRET is not set/)
  })

  it('rejects unknown users in allow lists', () => {
    expect(() => parseConfig(base.replace('allow: [ian] }', 'allow: [bob] }'), env)).toThrow(/unknown user "bob"/)
  })

  it('rejects duplicate emails', () => {
    expect(() => parseConfig(base.replace('p@example.com', 'ian@example.com'), env)).toThrow(/same email/)
  })

  it('rejects a non-https issuer and short keys', () => {
    expect(() => parseConfig(base.replace('https://mcp', 'http://mcp'), env)).toThrow(/issuer/)
    expect(() => parseConfig(base, { ...env, KEY: 'short' })).toThrow(/encryption_key/)
  })

  it('rejects unknown top-level keys (typos)', () => {
    expect(() => parseConfig(base + 'servcies: {}\n', env)).toThrow()
  })
})

describe('helpers', () => {
  const cfg = parseConfig(base, env)
  it('maps emails to users case-insensitively', () => {
    expect(userByEmail(cfg, 'IAN@example.com')).toBe('ian')
    expect(userByEmail(cfg, 'nobody@example.com')).toBeUndefined()
  })
  it('checks access per service', () => {
    expect(isAllowed(cfg, 'partner', 'mealie')).toBe(true)
    expect(isAllowed(cfg, 'partner', 'firefly')).toBe(false)
    expect(isAllowed(cfg, 'ian', 'nope')).toBe(false)
  })
  it('maps resource URLs to services exactly', () => {
    expect(serviceForResource(cfg, 'https://mcp.example.ts.net/mealie/mcp')).toBe('mealie')
    expect(serviceForResource(cfg, 'https://mcp.example.ts.net/mealie/mcp/')).toBe('mealie')
    expect(serviceForResource(cfg, 'https://evil.example/mealie/mcp')).toBeUndefined()
    expect(serviceForResource(cfg, undefined)).toBeUndefined()
  })
  it('parses durations', () => {
    expect(parseDuration('30m')).toBe(1_800_000)
    expect(() => parseDuration('1w')).toThrow()
  })
})
