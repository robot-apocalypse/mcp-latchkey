import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { parseConfig } from '../config.js'
import { Store } from '../store/store.js'
import { _clearClientCache, resolveClient } from './clients.js'

const CLAUDE = 'https://claude.ai/oauth/mcp-oauth-client-metadata'
const cfg = parseConfig(
  `
issuer: https://mcp.example
encryption_key: ${'k'.repeat(32)}
idp: { issuer: https://idp.example, client_id: a, client_secret: b }
oauth: { dynamic_registration: true }
users: {}
services: {}
`,
  {}
)
const store = new Store(fs.mkdtempSync(path.join(os.tmpdir(), 'latchkey-clients-')), cfg.encryption_key)
const json = (body: unknown, init: ResponseInit = {}) => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' }, ...init })

beforeEach(() => _clearClientCache())

describe('resolveClient (CIMD)', () => {
  it('intersects the document redirect URIs with the allowlist', async () => {
    const f = vi.fn(async () => json({ client_id: CLAUDE, redirect_uris: ['https://claude.ai/api/mcp/auth_callback', 'https://evil.example/cb'] }))
    const c = await resolveClient(cfg, store, CLAUDE, f as unknown as typeof fetch)
    expect(c.redirectUris).toEqual(['https://claude.ai/api/mcp/auth_callback'])
    // cached
    await resolveClient(cfg, store, CLAUDE, f as unknown as typeof fetch)
    expect(f).toHaveBeenCalledTimes(1)
  })

  it('never fetches a URL that is not configured', async () => {
    const f = vi.fn()
    await expect(resolveClient(cfg, store, 'https://evil.example/c.json', f as unknown as typeof fetch)).rejects.toThrow(/not an allowed/)
    await expect(resolveClient(cfg, store, 'http://169.254.169.254/latest', f as unknown as typeof fetch)).rejects.toThrow()
    expect(f).not.toHaveBeenCalled()
  })

  it('rejects documents that do not describe themselves', async () => {
    const f = async () => json({ client_id: 'https://other.example', redirect_uris: ['https://claude.ai/api/mcp/auth_callback'] })
    await expect(resolveClient(cfg, store, CLAUDE, f as unknown as typeof fetch)).rejects.toThrow(/does not match/)
  })

  it('rejects oversized, failed and malformed documents', async () => {
    const big = async () => new Response('x'.repeat(70 * 1024))
    await expect(resolveClient(cfg, store, CLAUDE, big as unknown as typeof fetch)).rejects.toThrow(/too large/)
    const fail = async () => new Response('', { status: 500 })
    await expect(resolveClient(cfg, store, CLAUDE, fail as unknown as typeof fetch)).rejects.toThrow(/500/)
    const bad = async () => json({ client_id: CLAUDE })
    await expect(resolveClient(cfg, store, CLAUDE, bad as unknown as typeof fetch)).rejects.toThrow(/invalid/)
  })
})

describe('resolveClient (DCR)', () => {
  it('resolves registered clients and rejects unknown ones', async () => {
    const id = await store.registerClient(['https://claude.ai/api/mcp/auth_callback'])
    expect((await resolveClient(cfg, store, id)).redirectUris).toEqual(['https://claude.ai/api/mcp/auth_callback'])
    await expect(resolveClient(cfg, store, 'nope')).rejects.toThrow(/unknown/)
    await expect(resolveClient(cfg, store, undefined)).rejects.toThrow(/required/)
    // registered clients are refused once DCR is turned off
    const off = { ...cfg, oauth: { ...cfg.oauth, dynamic_registration: false } }
    await expect(resolveClient(off, store, id)).rejects.toThrow(/unknown/)
  })
})
