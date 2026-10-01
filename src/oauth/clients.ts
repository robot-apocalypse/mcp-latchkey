import { z } from 'zod'
import type { Config } from '../config.js'
import type { Store } from '../store/store.js'

// Resolves an OAuth client_id to the redirect URIs it may use.
//
// Two registration paths:
//  - CIMD: the client_id is an https URL serving the client's metadata. Only
//    URLs listed in oauth.cimd_client_ids are fetched, so this is never a
//    general-purpose fetcher (SSRF): a fixed set of URLs, https only, no
//    redirects, short timeout, capped size.
//  - DCR: a UUID issued by POST /register and kept in the store.
//
// Either way the usable redirect URIs are the client's own list intersected
// with oauth.redirect_uris, so a code only ever goes to an allowlisted callback.

export interface ResolvedClient { clientId: string; name?: string; redirectUris: string[] }

const MAX_DOC_BYTES = 64 * 1024
const FETCH_TIMEOUT_MS = 5_000
const CACHE_MS = 60 * 60 * 1000

const cimdDoc = z.object({
  client_id: z.string(),
  client_name: z.string().optional(),
  redirect_uris: z.array(z.string()).min(1)
})

const cache = new Map<string, { at: number; doc: z.infer<typeof cimdDoc> }>()

export function _clearClientCache(): void {
  cache.clear()
}

export class ClientError extends Error {}

async function fetchCimd(url: string, fetchImpl: typeof fetch): Promise<z.infer<typeof cimdDoc>> {
  const hit = cache.get(url)
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.doc

  const res = await fetchImpl(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { accept: 'application/json' }
  }).catch((e: unknown) => {
    throw new ClientError(`could not fetch client metadata: ${String(e)}`)
  })
  if (!res.ok) throw new ClientError(`client metadata fetch returned ${res.status}`)
  const declared = Number(res.headers.get('content-length') ?? 0)
  if (declared > MAX_DOC_BYTES) throw new ClientError('client metadata document too large')
  const buf = Buffer.from(await res.arrayBuffer())
  if (buf.length > MAX_DOC_BYTES) throw new ClientError('client metadata document too large')

  const parsed = cimdDoc.safeParse(JSON.parse(buf.toString('utf8')))
  if (!parsed.success) throw new ClientError('invalid client metadata document')
  // The document must describe itself, or anyone could point at someone else's.
  if (parsed.data.client_id !== url) throw new ClientError('client metadata client_id does not match its URL')
  cache.set(url, { at: Date.now(), doc: parsed.data })
  return parsed.data
}

export async function resolveClient(cfg: Config, store: Store, clientId: string | undefined, fetchImpl: typeof fetch = fetch): Promise<ResolvedClient> {
  if (!clientId) throw new ClientError('client_id is required')
  const allowed = new Set(cfg.oauth.redirect_uris)

  if (clientId.startsWith('https://') || clientId.startsWith('http://')) {
    if (!cfg.oauth.cimd_client_ids.includes(clientId)) throw new ClientError('client_id is not an allowed client metadata URL')
    const doc = await fetchCimd(clientId, fetchImpl)
    return { clientId, name: doc.client_name, redirectUris: doc.redirect_uris.filter((u) => allowed.has(u)) }
  }

  if (!cfg.oauth.dynamic_registration) throw new ClientError('unknown client_id')
  const client = store.getClient(clientId)
  if (!client) throw new ClientError('unknown client_id')
  return { clientId, name: client.name, redirectUris: client.redirectUris.filter((u) => allowed.has(u)) }
}
