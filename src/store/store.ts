import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { atomicWrite } from './atomicWrite.js'

// Durable state, encrypted at rest (AES-256-GCM, key from config via scrypt).
// Tokens are stored only as SHA-256 hashes, so a leaked state file plus key
// still does not yield usable bearer tokens.
//
// The server and the `latchkey` CLI both write this file. Every change runs as
// lock → reload from disk → mutate → write → unlock (an O_EXCL lock file plus an
// in-process queue), so neither can overwrite the other's change; reads reload
// whenever the file changed on disk.

export interface Identity { iss: string; sub: string; boundAt: number }
export interface Client { redirectUris: string[]; name?: string; createdAt: number }
export interface Grant { user: string; service: string; clientId: string }
export interface RefreshRecord extends Grant { createdAt: number; lastUsedAt: number }
export interface AccessRecord extends Grant { expiresAt: number; refreshId: string }

interface State {
  version: 1
  identities: Record<string, Identity>
  clients: Record<string, Client>
  refreshTokens: Record<string, RefreshRecord>
  accessTokens: Record<string, AccessRecord>
}

export interface IssuedTokens { accessToken: string; refreshToken: string; expiresIn: number }

const LOCK_TIMEOUT_MS = 10_000
const LOCK_STALE_MS = 30_000
const MAX_CLIENTS = 100
const UNUSED_CLIENT_TTL_MS = 24 * 60 * 60 * 1000

const emptyState = (): State => ({ version: 1, identities: {}, clients: {}, refreshTokens: {}, accessTokens: {} })

export const hashToken = (t: string): string => crypto.createHash('sha256').update(t).digest('hex')
const newToken = (): string => crypto.randomBytes(32).toString('base64url')

export class Store {
  private state: State = emptyState()
  private fileStamp = ''
  private chain: Promise<unknown> = Promise.resolve()
  private readonly key: Buffer
  readonly file: string
  private readonly lockFile: string

  constructor(dataDir: string, secret: string) {
    this.file = path.join(dataDir, 'state.json.enc')
    this.lockFile = `${this.file}.lock`
    this.key = crypto.scryptSync(secret, 'mcp-latchkey/state/v1', 32)
    this.load()
  }

  // ---- persistence -------------------------------------------------------

  private stamp(): string {
    try {
      const s = fs.statSync(this.file)
      return `${s.mtimeMs}:${s.size}:${s.ino}`
    } catch {
      return 'missing'
    }
  }

  /** Reloads from disk if the file changed (or always, with force). */
  private load(force = false): void {
    const stamp = this.stamp()
    if (!force && stamp === this.fileStamp) return
    this.fileStamp = stamp
    if (stamp === 'missing') {
      this.state = emptyState()
      return
    }
    // Fail loud on a corrupt or wrong-key file rather than silently starting empty.
    const box = JSON.parse(fs.readFileSync(this.file, 'utf8')) as { iv: string; tag: string; data: string }
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(box.iv, 'base64'))
    decipher.setAuthTag(Buffer.from(box.tag, 'base64'))
    const plain = Buffer.concat([decipher.update(Buffer.from(box.data, 'base64')), decipher.final()])
    this.state = { ...emptyState(), ...(JSON.parse(plain.toString('utf8')) as State) }
  }

  private async write(): Promise<void> {
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv)
    const data = Buffer.concat([cipher.update(JSON.stringify(this.state), 'utf8'), cipher.final()])
    const box = { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') }
    await atomicWrite(this.file, JSON.stringify(box))
    this.fileStamp = this.stamp()
  }

  private async lock(): Promise<() => void> {
    fs.mkdirSync(path.dirname(this.lockFile), { recursive: true })
    const deadline = Date.now() + LOCK_TIMEOUT_MS
    for (;;) {
      try {
        const fd = fs.openSync(this.lockFile, 'wx', 0o600)
        fs.writeSync(fd, String(process.pid))
        fs.closeSync(fd)
        return () => fs.rmSync(this.lockFile, { force: true })
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e
        // A crashed holder must not wedge the store forever.
        try {
          if (Date.now() - fs.statSync(this.lockFile).mtimeMs > LOCK_STALE_MS) fs.rmSync(this.lockFile, { force: true })
        } catch {
          // removed meanwhile
        }
        if (Date.now() > deadline) throw new Error(`state file is locked (${this.lockFile})`)
        await new Promise((r) => setTimeout(r, 15))
      }
    }
  }

  /** The only way state changes. `fn` returns [result, changed]. */
  private mutate<T>(fn: () => [T, boolean]): Promise<T> {
    const run = this.chain.then(async () => {
      const unlock = await this.lock()
      try {
        this.load(true)
        const [result, changed] = fn()
        if (changed) await this.write()
        return result
      } finally {
        unlock()
      }
    })
    this.chain = run.catch(() => {})
    return run
  }

  // ---- identities --------------------------------------------------------

  /**
   * Binds a configured user to the IdP account that first signs in as them.
   * Later sign-ins must present the same (iss, sub); a reused or changed email
   * pointing at a different account is refused.
   */
  bindIdentity(user: string, iss: string, sub: string): Promise<'bound' | 'match' | 'mismatch'> {
    return this.mutate(() => {
      const existing = own(this.state.identities, user)
      if (existing) return [existing.iss === iss && existing.sub === sub ? 'match' : 'mismatch', false]
      this.state.identities[user] = { iss, sub, boundAt: Date.now() }
      return ['bound', true]
    })
  }

  identities(): Record<string, Identity> {
    this.load()
    return { ...this.state.identities }
  }

  unbindIdentity(user: string): Promise<boolean> {
    return this.mutate(() => {
      if (!own(this.state.identities, user)) return [false, false]
      delete this.state.identities[user]
      return [true, true]
    })
  }

  // ---- dynamically registered clients ------------------------------------

  /**
   * Registration is unauthenticated, so the client list must not grow without
   * bound: clients that never obtained a grant are dropped after a day, and
   * the total is capped (oldest unused first).
   */
  registerClient(redirectUris: string[], name?: string): Promise<string> {
    return this.mutate(() => {
      const used = new Set(Object.values(this.state.refreshTokens).map((r) => r.clientId))
      const now = Date.now()
      for (const [id, c] of Object.entries(this.state.clients)) {
        if (!used.has(id) && c.createdAt + UNUSED_CLIENT_TTL_MS < now) delete this.state.clients[id]
      }
      const unused = Object.entries(this.state.clients)
        .filter(([id]) => !used.has(id))
        .sort(([, a], [, b]) => a.createdAt - b.createdAt)
      while (Object.keys(this.state.clients).length >= MAX_CLIENTS && unused.length > 0) {
        delete this.state.clients[unused.shift()![0]]
      }
      if (Object.keys(this.state.clients).length >= MAX_CLIENTS) throw new Error('too many registered clients')
      const id = crypto.randomUUID()
      this.state.clients[id] = { redirectUris, name, createdAt: now }
      return [id, true]
    })
  }

  getClient(id: string): Client | undefined {
    this.load()
    return own(this.state.clients, id)
  }

  // ---- tokens ------------------------------------------------------------

  private prune(idleTtlMs: number): void {
    const now = Date.now()
    for (const [h, a] of Object.entries(this.state.accessTokens)) {
      if (a.expiresAt < now || !own(this.state.refreshTokens, a.refreshId)) delete this.state.accessTokens[h]
    }
    for (const [h, r] of Object.entries(this.state.refreshTokens)) {
      if (r.lastUsedAt + idleTtlMs < now) delete this.state.refreshTokens[h]
    }
  }

  private mintAccess(refreshId: string, grant: Grant, accessTtlMs: number): string {
    const access = newToken()
    this.state.accessTokens[hashToken(access)] = { ...grant, refreshId, expiresAt: Date.now() + accessTtlMs }
    return access
  }

  issue(grant: Grant, accessTtlMs: number, idleTtlMs: number): Promise<IssuedTokens> {
    return this.mutate(() => {
      this.prune(idleTtlMs)
      const refresh = newToken()
      const refreshId = hashToken(refresh)
      const now = Date.now()
      this.state.refreshTokens[refreshId] = { ...grant, createdAt: now, lastUsedAt: now }
      const access = this.mintAccess(refreshId, grant, accessTtlMs)
      return [{ accessToken: access, refreshToken: refresh, expiresIn: Math.floor(accessTtlMs / 1000) }, true]
    })
  }

  /**
   * Refresh tokens do not rotate (a lost response would otherwise strand the
   * client) but expire after `idleTtlMs` without use. The refresh must come
   * from the same client and be for the same service it was issued for.
   */
  refresh(refreshToken: string, clientId: string | undefined, service: string | undefined, accessTtlMs: number, idleTtlMs: number): Promise<{ tokens: IssuedTokens; grant: Grant } | null> {
    return this.mutate(() => {
      this.prune(idleTtlMs)
      const refreshId = hashToken(refreshToken)
      const rec = own(this.state.refreshTokens, refreshId)
      if (!rec || (clientId !== undefined && rec.clientId !== clientId)) return [null, false]
      if (service !== undefined && rec.service !== service) return [null, false]
      rec.lastUsedAt = Date.now()
      const grant: Grant = { user: rec.user, service: rec.service, clientId: rec.clientId }
      const access = this.mintAccess(refreshId, grant, accessTtlMs)
      return [{ tokens: { accessToken: access, refreshToken, expiresIn: Math.floor(accessTtlMs / 1000) }, grant }, true]
    })
  }

  /** Returns the grant behind a live access token, or null. Never writes. */
  validateAccess(token: string): Grant | null {
    this.load()
    const rec = own(this.state.accessTokens, hashToken(token))
    if (!rec || rec.expiresAt < Date.now() || !own(this.state.refreshTokens, rec.refreshId)) return null
    return { user: rec.user, service: rec.service, clientId: rec.clientId }
  }

  listGrants(): Array<RefreshRecord & { id: string }> {
    this.load()
    return Object.entries(this.state.refreshTokens).map(([h, r]) => ({ id: h.slice(0, 12), ...r }))
  }

  /** Revokes refresh tokens (and their access tokens) matching every given filter. */
  revoke(filter: { id?: string; user?: string; service?: string }): Promise<number> {
    if (!filter.id && !filter.user && !filter.service) return Promise.reject(new Error('revoke needs at least one filter'))
    return this.mutate(() => {
      let n = 0
      for (const [h, r] of Object.entries(this.state.refreshTokens)) {
        if (filter.id && !h.startsWith(filter.id)) continue
        if (filter.user && r.user !== filter.user) continue
        if (filter.service && r.service !== filter.service) continue
        delete this.state.refreshTokens[h]
        n++
      }
      for (const [h, a] of Object.entries(this.state.accessTokens)) {
        if (!own(this.state.refreshTokens, a.refreshId)) delete this.state.accessTokens[h]
      }
      return [n, n > 0]
    })
  }
}

function own<T>(rec: Record<string, T>, key: string): T | undefined {
  return Object.hasOwn(rec, key) ? rec[key] : undefined
}
