import crypto from 'node:crypto'

// Authenticated, encrypted, expiring blobs (AES-256-GCM). Used to carry
// in-flight sign-in state through the browser instead of keeping it in server
// memory, so unauthenticated requests cannot fill or evict a server-side table.
// Each purpose gets its own key, so a blob sealed for one step can never be
// accepted by another.

export type Purpose = 'idp-state' | 'consent'

export class Sealer {
  private readonly keys: Record<Purpose, Buffer>

  constructor(secret: string) {
    const derive = (purpose: Purpose) => Buffer.from(crypto.hkdfSync('sha256', secret, 'mcp-latchkey', `seal/v1/${purpose}`, 32))
    this.keys = { 'idp-state': derive('idp-state'), consent: derive('consent') }
  }

  seal(purpose: Purpose, payload: object, ttlMs: number): string {
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', this.keys[purpose], iv)
    const body = JSON.stringify({ exp: Date.now() + ttlMs, p: payload })
    const data = Buffer.concat([cipher.update(body, 'utf8'), cipher.final()])
    return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64url')
  }

  /** Returns the payload, or undefined if forged, tampered with, for another purpose, or expired. */
  open<T>(purpose: Purpose, sealed: string | undefined): T | undefined {
    if (!sealed || sealed.length > 8192) return undefined
    try {
      const buf = Buffer.from(sealed, 'base64url')
      if (buf.length < 29) return undefined
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.keys[purpose], buf.subarray(0, 12))
      decipher.setAuthTag(buf.subarray(12, 28))
      const plain = Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8')
      const { exp, p } = JSON.parse(plain) as { exp: number; p: T }
      return exp >= Date.now() ? p : undefined
    } catch {
      return undefined
    }
  }
}
