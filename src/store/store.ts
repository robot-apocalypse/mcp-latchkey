import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { atomicWrite } from './atomicWrite.js'

// Durable state, encrypted at rest (AES-256-GCM, key from config via scrypt).
// Tokens are stored only as SHA-256 hashes, so a leaked state file plus key
// still does not yield usable bearer tokens.
//
// The server and the `latchkey` CLI can both write this file. Every operation
// first re-reads it if it changed on disk, so a CLI revoke takes effect on the
// server's next request instead of being overwritten by its in-memory copy.

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

const emptyState = (): State => ({ version: 1, identities: {}, clients: {}, refreshTokens: {}, accessTokens: {} })

export const hashToken = (t: string): string => crypto.createHash('sha256').update(t).digest('hex')
const newToken = (): string => crypto.randomBytes(32).toString('base64url')

export class Store {
  private state: State = emptyState()
  private fileStamp = ''
  // While our own writes are queued, the file lags memory; reloading then would
  // drop mutations (e.g. a just-issued token) that are not yet on disk.
  private pendingWrites = 0
  private readonly key: Buffer
  readonly file: string

  constructor(dataDir: string, secret: string) {
    this.file = path.join(dataDir, 'state.json.enc')
    this.key = crypto.scryptSync(secret, 'mcp-latchkey/state/v1', 32)
    this.refresh_()
  }

  // ---- persistence -------------------------------------------------------

  private stamp(): string {
    try {
      const s = fs.statSync(this.file)
      return `${s.mtimeMs}:${s.size}`
    } catch {
      return 'missing'
    }
  }

  /** Reloads from disk if another process changed the file. */
  private refresh_(): void {
    if (this.pendingWrites > 0) return
    const stamp = this.stamp()
    if (stamp === this.fileStamp) return
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

  private async persist(): Promise<void> {
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv)
    const data = Buffer.concat([cipher.update(JSON.stringify(this.state), 'utf8'), cipher.final()])
    const box = { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') }
    this.pendingWrites++
    try {
      await atomicWrite(this.file, JSON.stringify(box))
    } finally {
      this.pendingWrites--
      if (this.pendingWrites === 0) this.fileStamp = this.stamp()
    }
  }

  // ---- identities --------------------------------------------------------

  /**
   * Binds a configured user to the IdP account that first signs in as them.
   * Later sign-ins must present the same (iss, sub); a reused or changed email
   * pointing at a different account is refused.
   */
  async bindIdentity(user: string, iss: string, sub: string): Promise<'bound' | 'match' | 'mismatch'> {
    this.refresh_()
    const existing = this.state.identities[user]
    if (existing) return existing.iss === iss && existing.sub === sub ? 'match' : 'mismatch'
    this.state.identities[user] = { iss, sub, boundAt: Date.now() }
    await this.persist()
    return 'bound'
  }

  identities(): Record<string, Identity> {
    this.refresh_()
    return { ...this.state.identities }
  }

  async unbindIdentity(user: string): Promise<boolean> {
    this.refresh_()
    if (!this.state.identities[user]) return false
    delete this.state.identities[user]
    await this.persist()
    return true
  }

  // ---- dynamically registered clients ------------------------------------

  async registerClient(redirectUris: string[], name?: string): Promise<string> {
    this.refresh_()
    const id = crypto.randomUUID()
    this.state.clients[id] = { redirectUris, name, createdAt: Date.now() }
    await this.persist()
    return id
  }

  getClient(id: string): Client | undefined {
    this.refresh_()
    return this.state.clients[id]
  }

  // ---- tokens ------------------------------------------------------------

  private prune(idleTtlMs: number): void {
    const now = Date.now()
    for (const [h, a] of Object.entries(this.state.accessTokens)) {
      if (a.expiresAt < now || !this.state.refreshTokens[a.refreshId]) delete this.state.accessTokens[h]
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

  async issue(grant: Grant, accessTtlMs: number, idleTtlMs: number): Promise<IssuedTokens> {
    this.refresh_()
    this.prune(idleTtlMs)
    const refresh = newToken()
    const refreshId = hashToken(refresh)
    const now = Date.now()
    this.state.refreshTokens[refreshId] = { ...grant, createdAt: now, lastUsedAt: now }
    const access = this.mintAccess(refreshId, grant, accessTtlMs)
    await this.persist()
    return { accessToken: access, refreshToken: refresh, expiresIn: Math.floor(accessTtlMs / 1000) }
  }

  /**
   * Refresh tokens do not rotate (a lost response would otherwise strand the
   * client) but expire after `idleTtlMs` without use. The refresh must come
   * from the same client and be for the same service it was issued for.
   */
  async refresh(refreshToken: string, clientId: string, service: string | undefined, accessTtlMs: number, idleTtlMs: number): Promise<{ tokens: IssuedTokens; grant: Grant } | null> {
    this.refresh_()
    this.prune(idleTtlMs)
    const refreshId = hashToken(refreshToken)
    const rec = this.state.refreshTokens[refreshId]
    if (!rec || rec.clientId !== clientId) return null
    if (service !== undefined && rec.service !== service) return null
    rec.lastUsedAt = Date.now()
    const grant: Grant = { user: rec.user, service: rec.service, clientId: rec.clientId }
    const access = this.mintAccess(refreshId, grant, accessTtlMs)
    await this.persist()
    return { tokens: { accessToken: access, refreshToken, expiresIn: Math.floor(accessTtlMs / 1000) }, grant }
  }

  /** Returns the grant behind a live access token, or null. Never writes. */
  validateAccess(token: string): Grant | null {
    this.refresh_()
    const rec = this.state.accessTokens[hashToken(token)]
    if (!rec || rec.expiresAt < Date.now() || !this.state.refreshTokens[rec.refreshId]) return null
    return { user: rec.user, service: rec.service, clientId: rec.clientId }
  }

  listGrants(): Array<RefreshRecord & { id: string }> {
    this.refresh_()
    return Object.entries(this.state.refreshTokens).map(([h, r]) => ({ id: h.slice(0, 12), ...r }))
  }

  /** Revokes refresh tokens (and their access tokens) matching every given filter. */
  async revoke(filter: { id?: string; user?: string; service?: string }): Promise<number> {
    this.refresh_()
    if (!filter.id && !filter.user && !filter.service) throw new Error('revoke needs at least one filter')
    let n = 0
    for (const [h, r] of Object.entries(this.state.refreshTokens)) {
      if (filter.id && !h.startsWith(filter.id)) continue
      if (filter.user && r.user !== filter.user) continue
      if (filter.service && r.service !== filter.service) continue
      delete this.state.refreshTokens[h]
      n++
    }
    for (const [h, a] of Object.entries(this.state.accessTokens)) {
      if (!this.state.refreshTokens[a.refreshId]) delete this.state.accessTokens[h]
    }
    if (n > 0) await this.persist()
    return n
  }
}
