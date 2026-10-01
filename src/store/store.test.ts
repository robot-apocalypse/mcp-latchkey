import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Store } from './store.js'

const KEY = 'k'.repeat(32)
const HOUR = 3_600_000
const DAY = 86_400_000
let dir: string

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'latchkey-store-'))
})
afterEach(() => {
  vi.useRealTimers()
  fs.rmSync(dir, { recursive: true, force: true })
})

const grant = { user: 'ian', service: 'toggl', clientId: 'c1' }

describe('Store', () => {
  it('issues tokens that validate, and persists them encrypted with hashes only', async () => {
    const s = new Store(dir, KEY)
    const t = await s.issue(grant, HOUR, 90 * DAY)
    expect(s.validateAccess(t.accessToken)).toEqual(grant)
    expect(s.validateAccess('nope')).toBeNull()

    const raw = fs.readFileSync(s.file, 'utf8')
    expect(raw).not.toContain(t.accessToken)
    expect(raw).not.toContain('toggl')
    expect((fs.statSync(s.file).mode & 0o777).toString(8)).toBe('600')

    expect(new Store(dir, KEY).validateAccess(t.accessToken)).toEqual(grant)
  })

  it('fails loud with the wrong key', async () => {
    await new Store(dir, KEY).issue(grant, HOUR, DAY)
    expect(() => new Store(dir, 'x'.repeat(32))).toThrow()
  })

  it('expires access tokens', async () => {
    vi.useFakeTimers({ now: 1_000_000, toFake: ['Date'] })
    const s = new Store(dir, KEY)
    const t = await s.issue(grant, HOUR, 90 * DAY)
    vi.setSystemTime(1_000_000 + HOUR + 1)
    expect(s.validateAccess(t.accessToken)).toBeNull()
  })

  it('refreshes only for the same client and service', async () => {
    const s = new Store(dir, KEY)
    const t = await s.issue(grant, HOUR, DAY)
    expect(await s.refresh(t.refreshToken, 'other-client', 'toggl', HOUR, DAY)).toBeNull()
    expect(await s.refresh(t.refreshToken, 'c1', 'mealie', HOUR, DAY)).toBeNull()
    const r = await s.refresh(t.refreshToken, 'c1', 'toggl', HOUR, DAY)
    expect(r?.grant).toEqual(grant)
    expect(r?.tokens.refreshToken).toBe(t.refreshToken)
    expect(s.validateAccess(r!.tokens.accessToken)).toEqual(grant)
    // service omitted (client sent no resource) falls back to the token's own
    expect(await s.refresh(t.refreshToken, 'c1', undefined, HOUR, DAY)).not.toBeNull()
  })

  it('expires refresh tokens after the idle TTL, but use extends them', async () => {
    vi.useFakeTimers({ now: 1_000_000, toFake: ['Date'] })
    const s = new Store(dir, KEY)
    const t = await s.issue(grant, HOUR, 10 * DAY)
    vi.setSystemTime(1_000_000 + 9 * DAY)
    expect(await s.refresh(t.refreshToken, 'c1', 'toggl', HOUR, 10 * DAY)).not.toBeNull()
    vi.setSystemTime(1_000_000 + 18 * DAY)
    expect(await s.refresh(t.refreshToken, 'c1', 'toggl', HOUR, 10 * DAY)).not.toBeNull()
    vi.setSystemTime(1_000_000 + 29 * DAY)
    expect(await s.refresh(t.refreshToken, 'c1', 'toggl', HOUR, 10 * DAY)).toBeNull()
  })

  it('revoking a refresh token kills its access tokens', async () => {
    const s = new Store(dir, KEY)
    const a = await s.issue(grant, HOUR, DAY)
    const b = await s.issue({ ...grant, service: 'mealie' }, HOUR, DAY)
    expect(await s.revoke({ service: 'toggl' })).toBe(1)
    expect(s.validateAccess(a.accessToken)).toBeNull()
    expect(s.validateAccess(b.accessToken)).not.toBeNull()
    await expect(s.revoke({})).rejects.toThrow()
  })

  it('sees revocations written by another process (the CLI)', async () => {
    const server = new Store(dir, KEY)
    const t = await server.issue(grant, HOUR, DAY)
    expect(server.validateAccess(t.accessToken)).not.toBeNull()
    await new Promise((r) => setTimeout(r, 5)) // distinct mtime
    expect(await new Store(dir, KEY).revoke({ user: 'ian' })).toBe(1)
    expect(server.validateAccess(t.accessToken)).toBeNull()
  })

  it('keeps concurrent issues (no lost updates from reloads)', async () => {
    const s = new Store(dir, KEY)
    const issued = await Promise.all(Array.from({ length: 20 }, (_, i) => s.issue({ ...grant, clientId: `c${i}` }, HOUR, DAY)))
    for (const t of issued) expect(s.validateAccess(t.accessToken)).not.toBeNull()
    const reopened = new Store(dir, KEY)
    for (const t of issued) expect(reopened.validateAccess(t.accessToken)).not.toBeNull()
  })

  it('binds identities on first sign-in and refuses a different account later', async () => {
    const s = new Store(dir, KEY)
    expect(await s.bindIdentity('ian', 'https://accounts.google.com', '123')).toBe('bound')
    expect(await s.bindIdentity('ian', 'https://accounts.google.com', '123')).toBe('match')
    expect(await s.bindIdentity('ian', 'https://accounts.google.com', '999')).toBe('mismatch')
    expect(await s.unbindIdentity('ian')).toBe(true)
    expect(await s.bindIdentity('ian', 'https://accounts.google.com', '999')).toBe('bound')
  })

  it('caps registered clients and prunes ones that never got a grant', async () => {
    vi.useFakeTimers({ now: 1_000_000, toFake: ['Date'] })
    const s = new Store(dir, KEY)
    const kept = await s.registerClient(['https://claude.ai/api/mcp/auth_callback'])
    await s.issue({ ...grant, clientId: kept }, HOUR, 90 * DAY)
    for (let i = 0; i < 150; i++) await s.registerClient(['https://claude.ai/api/mcp/auth_callback'])
    // capped at 100, and the client with a live grant survived
    expect(s.getClient(kept)).toBeDefined()
    vi.setSystemTime(1_000_000 + 2 * DAY)
    const fresh = await s.registerClient(['https://claude.ai/api/mcp/auth_callback'])
    expect(s.getClient(fresh)).toBeDefined()
    expect(s.getClient(kept)).toBeDefined()
  })

  it('a revoke from another process during a server refresh sticks (no lost update)', async () => {
    // Reproduces the pentest finding: the CLI process runs while the server's
    // refresh write is in flight; previously the server's write landed last
    // and resurrected the revoked grant.
    const server = new Store(dir, KEY)
    const t = await server.issue(grant, HOUR, DAY)
    const pending = server.refresh(t.refreshToken, undefined, 'toggl', HOUR, DAY)
    const storeTs = path.join(path.dirname(fileURLToPath(import.meta.url)), 'store.ts')
    const out = execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e',
      `import { Store } from ${JSON.stringify(storeTs)}; console.log(await new Store(${JSON.stringify(dir)}, ${JSON.stringify(KEY)}).revoke({ user: 'ian' }))`
    ]).toString().trim()
    await pending.catch(() => null)
    expect(out).toBe('1')
    expect(server.validateAccess(t.accessToken)).toBeNull()
    expect(new Store(dir, KEY).listGrants()).toEqual([])
  })

  it('recovers from a stale lock file left by a crashed process', async () => {
    const s = new Store(dir, KEY)
    fs.writeFileSync(path.join(dir, 'state.json.enc.lock'), '999999')
    const old = new Date(Date.now() - 60_000)
    fs.utimesSync(path.join(dir, 'state.json.enc.lock'), old, old)
    await expect(s.issue(grant, HOUR, DAY)).resolves.toBeTruthy()
  })
})
