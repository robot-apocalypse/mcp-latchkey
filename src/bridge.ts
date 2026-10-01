import crypto from 'node:crypto'
import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { bodyLimit } from 'hono/body-limit'
import { parseDuration, type ServiceConfig } from './config.js'
import { serveUpstream, Upstream } from './upstream.js'

// `latchkey bridge`: run ONE stdio MCP server and expose it as Streamable HTTP,
// for use as an `http` upstream of the gateway.
//
// Why: a stdio server started by the gateway runs as the gateway's user, in the
// gateway's container and network namespace. It can read the gateway's secrets
// from /proc/<pid>/environ and reach every upstream bound to 127.0.0.1. Running
// it in its own container through this bridge gives it its own process tree
// and network, and the gateway reaches it with a shared secret.

export interface BridgeOptions {
  listen: { host: string; port: number }
  token: string
  command: string
  args: string[]
  home: string
  timeoutMs?: number
  log?: (line: Record<string, unknown>) => void
}

const BRIDGE_BODY_LIMIT = 4 * 1024 * 1024

function constantTimeEqual(a: string, b: string): boolean {
  const x = crypto.createHash('sha256').update(a).digest()
  const y = crypto.createHash('sha256').update(b).digest()
  return crypto.timingSafeEqual(x, y)
}

/** The child gets the bridge's environment minus the bridge's own secret. */
export function bridgeChildEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(env)) if (v !== undefined && k !== 'BRIDGE_TOKEN') out[k] = v
  return out
}

export function createBridge(opts: BridgeOptions) {
  if (opts.token.length < 32) throw new Error('BRIDGE_TOKEN must be at least 32 characters')
  const log = opts.log ?? ((line) => console.log(JSON.stringify({ t: new Date().toISOString(), ...line })))
  const def: ServiceConfig = {
    allow: [],
    stdio: { command: opts.command, args: opts.args, env: bridgeChildEnv(process.env), cwd: opts.home },
    hide_tools: [],
    timeout: opts.timeoutMs ?? parseDuration('5m')
  }
  const up = new Upstream('bridge', def, opts.home, log, opts.home)

  const app = new Hono()
  app.use('*', async (c, next) => {
    await next()
    log({ event: 'http', method: c.req.method, path: c.req.path, status: c.res.status })
  })
  app.get('/health', (c) => c.json({ ok: true, upstream: up.state }))
  app.use('/mcp', bodyLimit({ maxSize: BRIDGE_BODY_LIMIT, onError: (c) => c.json({ error: 'body too large' }, 413) }))
  app.all('/mcp', async (c) => {
    const token = /^Bearer\s+(\S+)$/i.exec(c.req.header('authorization') ?? '')?.[1]
    if (!token || !constantTimeEqual(token, opts.token)) return c.json({ error: 'unauthorized' }, 401)
    return serveUpstream(up, c.req.raw, (line) => log({ event: 'tool', ...line }))
  })
  app.notFound((c) => c.json({ error: 'not_found' }, 404))

  return {
    app,
    upstream: up,
    start() {
      up.getClient().catch(() => {})
      return serve({ fetch: app.fetch, port: opts.listen.port, hostname: opts.listen.host }, (info) => {
        log({ event: 'bridge-listening', address: `${info.address}:${info.port}`, command: opts.command })
      })
    }
  }
}
