import fs from 'node:fs'
import path from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolRequest, type CallToolResult, type Tool } from '@modelcontextprotocol/sdk/types.js'
import type { McpHandler } from './app.js'
import type { Config, ServiceConfig } from './config.js'

// The bridge: latchkey is an MCP *client* to every upstream and serves each
// one back per request. One connection per service, shared by all requests:
// for stdio servers that is a hard requirement (confirm tokens and rotating
// upstream credentials live in that one process), and it keeps tool hiding,
// keepalive and audit logging uniform across stdio and HTTP upstreams.
//
// Only tools are bridged (v1). Server-to-client features (notifications,
// progress, sampling, elicitation) are not forwarded.

type Log = (line: Record<string, unknown>) => void

export type UpstreamState = 'idle' | 'connecting' | 'up' | 'down'

export class Upstream {
  private client: Client | null = null
  private connecting: Promise<Client> | null = null
  private queue: Promise<unknown> = Promise.resolve()
  private keepaliveTimer: NodeJS.Timeout | undefined
  state: UpstreamState = 'idle'
  lastError: string | undefined

  constructor(
    readonly name: string,
    private readonly def: ServiceConfig,
    private readonly dataDir: string,
    private readonly log: Log,
    /** HOME for a stdio child; defaults to <dataDir>/<name>. */
    private readonly homeDir?: string
  ) {}

  private transport() {
    if (this.def.stdio) {
      const home = this.homeDir ?? path.resolve(this.dataDir, this.name)
      fs.mkdirSync(home, { recursive: true, mode: 0o700 })
      const t = new StdioClientTransport({
        command: this.def.stdio.command,
        args: this.def.stdio.args,
        // Only what the service is configured with: never latchkey's own
        // secrets (IdP client secret, encryption key, Tailscale key).
        env: { PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin', ...this.def.stdio.env, HOME: home },
        cwd: this.def.stdio.cwd ?? home,
        stderr: 'pipe'
      })
      t.stderr?.on('data', (chunk: Buffer) => {
        for (const line of chunk.toString('utf8').split('\n')) {
          if (line.trim()) this.log({ event: 'upstream-stderr', service: this.name, line: line.slice(0, 500) })
        }
      })
      return t
    }
    if (this.def.http) {
      return new StreamableHTTPClientTransport(new URL(this.def.http.url), { requestInit: { headers: this.def.http.headers } })
    }
    throw new Error(`service "${this.name}" has no upstream`)
  }

  /** Connects lazily; after a failure or exit, the next call reconnects. */
  getClient(): Promise<Client> {
    if (this.client) return Promise.resolve(this.client)
    if (!this.connecting) {
      this.state = 'connecting'
      const c = new Client({ name: 'mcp-latchkey', version: '0.1.0' })
      c.onclose = () => {
        if (this.client === c) {
          this.client = null
          this.state = 'down'
          this.log({ event: 'upstream-closed', service: this.name })
        }
      }
      this.connecting = c
        .connect(this.transport())
        .then(() => {
          this.client = c
          this.state = 'up'
          this.lastError = undefined
          const v = c.getServerVersion()
          this.log({ event: 'upstream-up', service: this.name, server: v ? `${v.name}@${v.version}` : null })
          return c
        })
        .catch((e: unknown) => {
          this.state = 'down'
          this.lastError = String(e)
          this.log({ event: 'upstream-error', service: this.name, error: this.lastError })
          c.close().catch(() => {})
          throw e
        })
        .finally(() => {
          this.connecting = null
        })
    }
    return this.connecting
  }

  // stdio servers get one call at a time: many keep unlocked state (token
  // refresh, confirm handshakes) that parallel calls would race on.
  private run<T>(fn: () => Promise<T>): Promise<T> {
    if (!this.def.stdio) return fn()
    const r = this.queue.then(fn, fn)
    this.queue = r.catch(() => {})
    return r
  }

  async instructions(): Promise<string | undefined> {
    return (await this.getClient()).getInstructions()
  }

  async listTools(): Promise<Tool[]> {
    const c = await this.getClient()
    const hidden = new Set(this.def.hide_tools)
    const tools: Tool[] = []
    let cursor: string | undefined
    do {
      const page = await this.run(() => c.listTools(cursor ? { cursor } : undefined))
      tools.push(...page.tools)
      cursor = page.nextCursor
    } while (cursor)
    return tools.filter((t) => !hidden.has(t.name))
  }

  async callTool(params: CallToolRequest['params']): Promise<CallToolResult> {
    if (this.def.hide_tools.includes(params.name)) {
      return { content: [{ type: 'text', text: `Tool "${params.name}" is not available.` }], isError: true }
    }
    const c = await this.getClient()
    try {
      return (await this.run(() =>
        c.callTool(params, undefined, { timeout: this.def.timeout, resetTimeoutOnProgress: true })
      )) as CallToolResult
    } catch (e) {
      // A dead connection should not stick: drop it so the next call reconnects.
      if (this.client === c && /closed|ECONNREFUSED|ECONNRESET|fetch failed/i.test(String(e))) {
        this.client = null
        this.state = 'down'
        c.close().catch(() => {})
      }
      throw e
    }
  }

  startKeepalive(): void {
    const ka = this.def.keepalive
    if (!ka) return
    const tick = async () => {
      try {
        const r = await this.callTool({ name: ka.tool, arguments: ka.args })
        this.log({ event: 'keepalive', service: this.name, ok: !r.isError, ...(r.isError ? { detail: firstText(r) } : {}) })
      } catch (e) {
        this.log({ event: 'keepalive', service: this.name, ok: false, detail: String(e).slice(0, 300) })
      }
    }
    void tick()
    this.keepaliveTimer = setInterval(() => void tick(), ka.every)
    this.keepaliveTimer.unref()
  }

  async close(): Promise<void> {
    clearInterval(this.keepaliveTimer)
    await this.client?.close().catch(() => {})
    this.client = null
    this.state = 'idle'
  }
}

function firstText(r: CallToolResult): string {
  const c = r.content?.[0]
  return c && c.type === 'text' ? c.text.slice(0, 300) : ''
}

/** Serves one MCP HTTP request against an upstream, reporting each tool call to `audit`. */
export async function serveUpstream(up: Upstream, request: Request, audit: (line: Record<string, unknown>) => void): Promise<Response> {
  // Instructions only matter on initialize; fetch them only then, and don't
  // fail the request over them.
  let instructions: string | undefined
  if (request.method === 'POST') {
    const body = await request.clone().text().catch(() => '')
    if (body.includes('"initialize"')) instructions = await up.instructions().catch(() => undefined)
  }

  const server = new Server({ name: `latchkey/${up.name}`, version: '0.1.0' }, { capabilities: { tools: {} }, instructions })
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: await up.listTools() }))
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const started = Date.now()
    try {
      const r = await up.callTool(req.params)
      audit({ tool: req.params.name, ok: !r.isError, ms: Date.now() - started })
      return r
    } catch (e) {
      audit({ tool: req.params.name, ok: false, ms: Date.now() - started, error: String(e).slice(0, 300) })
      // Details go to the log, not to the client.
      return { content: [{ type: 'text', text: `The ${up.name} service failed to handle this call.` }], isError: true }
    }
  })
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined })
  transport.onclose = () => {
    server.close().catch(() => {})
  }
  await server.connect(transport)
  return transport.handleRequest(request)
}

/** Builds one Upstream per stdio/http service and the MCP handler that serves them. */
export function createUpstreams(cfg: Config, log: Log): { upstreams: Map<string, Upstream>; handler: McpHandler } {
  const upstreams = new Map<string, Upstream>()
  for (const [name, def] of Object.entries(cfg.services)) {
    if (def.stdio || def.http) upstreams.set(name, new Upstream(name, def, cfg.data_dir, log))
  }

  const handler: McpHandler = async (service, grant, request) => {
    const up = upstreams.get(service)
    if (!up) {
      return Response.json({ error: 'upstream_not_configured', error_description: `service "${service}" has no upstream` }, { status: 501 })
    }
    return serveUpstream(up, request, (line) => log({ event: 'tool', user: grant.user, service, ...line }))
  }

  return { upstreams, handler }
}
