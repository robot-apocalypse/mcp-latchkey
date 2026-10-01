import { spawn, type ChildProcess } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { parseConfig, type Config } from './config.js'
import { createUpstreams, type Upstream } from './upstream.js'

const FAKE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'test', 'fake-upstream.mjs')
const PORT = 39_000 + Math.floor(Math.random() * 1000)
const grant = { user: 'ian', service: 'x', clientId: 'c' }
const logs: Array<Record<string, unknown>> = []
let httpChild: ChildProcess
let cfg: Config
let upstreams: Map<string, Upstream>
let handler: ReturnType<typeof createUpstreams>['handler']

beforeAll(async () => {
  httpChild = spawn(process.execPath, [FAKE, '--http', String(PORT)], { stdio: ['ignore', 'pipe', 'inherit'] })
  await new Promise<void>((resolve) => httpChild.stdout!.once('data', () => resolve()))

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'latchkey-up-'))
  process.env.LATCHKEY_SHOULD_NOT_LEAK = 'secret'
  cfg = parseConfig(
    `
issuer: https://mcp.example
data_dir: ${dir}
encryption_key: ${'k'.repeat(32)}
idp: { issuer: https://idp.example, client_id: a, client_secret: b }
users: { ian: { email: ian@example.com } }
services:
  local:
    allow: [ian]
    stdio: { command: ${process.execPath}, args: [${FAKE}], env: { ONLY_THIS: "1" } }
    hide_tools: [secret]
  remote:
    allow: [ian]
    http: { url: "http://127.0.0.1:${PORT}/mcp", headers: { x-upstream-key: k123 } }
  dead:
    allow: [ian]
    http: { url: "http://127.0.0.1:1/mcp" }
  bare:
    allow: [ian]
`,
    {}
  )
  ;({ upstreams, handler } = createUpstreams(cfg, (l) => logs.push(l)))
})

afterAll(async () => {
  for (const u of upstreams.values()) await u.close()
  httpChild.kill()
})

const call = (u: string, name: string, args: Record<string, unknown> = {}) => upstreams.get(u)!.callTool({ name, arguments: args })
const textOf = (r: { content?: Array<{ type: string; text?: string }> }) => r.content?.[0]?.text ?? ''

describe('stdio upstream', () => {
  it("gives the child only its configured env plus the SDK's non-secret defaults", async () => {
    const keys = JSON.parse(textOf(await call('local', 'env_keys'))) as string[]
    // StdioClientTransport always adds HOME, LOGNAME, PATH, SHELL, TERM, USER.
    const allowed = new Set(['HOME', 'LOGNAME', 'PATH', 'SHELL', 'TERM', 'USER', 'ONLY_THIS'])
    expect(keys.filter((k) => !allowed.has(k))).toEqual([])
    expect(keys).toContain('ONLY_THIS')
    expect(keys).not.toContain('LATCHKEY_SHOULD_NOT_LEAK')
  })

  it('keeps one long-lived process and serializes calls', async () => {
    const results = await Promise.all(Array.from({ length: 5 }, () => call('local', 'counter')))
    const nums = results.map((r) => Number(textOf(r))).sort((a, b) => a - b)
    expect(nums[4]! - nums[0]!).toBe(4)
  })

  it('supports two-step confirmation across calls', async () => {
    const first = JSON.parse(textOf(await call('local', 'confirm'))) as { confirm_token: string }
    expect(textOf(await call('local', 'confirm', { confirm_token: first.confirm_token }))).toBe('confirmed')
  })

  it('hides tools from listing and refuses calls to them', async () => {
    const names = (await upstreams.get('local')!.listTools()).map((t) => t.name)
    expect(names).toContain('counter')
    expect(names).not.toContain('secret')
    const r = await call('local', 'secret')
    expect(r.isError).toBe(true)
    expect(textOf(r)).not.toContain('should not see')
  })

  it('respawns after the child dies', async () => {
    const u = upstreams.get('local')!
    await u.close()
    expect(textOf(await call('local', 'counter'))).toBe('1')
  })
})

describe('http upstream', () => {
  it('sends the configured upstream headers', async () => {
    expect(textOf(await call('remote', 'whoami_hdr'))).toBe('k123')
  })

  it('reports an unreachable upstream as an error', async () => {
    await expect(call('dead', 'counter')).rejects.toThrow()
    expect(upstreams.get('dead')!.state).toBe('down')
  })
})

describe('handler', () => {
  const rpc = (service: string, body: unknown) =>
    handler(service, { ...grant, service }, new Request(`https://mcp.example/${service}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify(body)
    }))

  it('serves upstream tools with instructions over MCP and audit-logs calls', async () => {
    const init = await (await rpc('local', { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } })).text()
    expect(init).toContain('fake upstream instructions')
    const list = await (await rpc('local', { jsonrpc: '2.0', id: 2, method: 'tools/list' })).text()
    expect(list).toContain('counter')
    expect(list).not.toContain('"secret"')
    await (await rpc('local', { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'counter', arguments: {} } })).text()
    expect(logs.some((l) => l.event === 'tool' && l.service === 'local' && l.tool === 'counter' && l.ok === true && l.user === 'ian')).toBe(true)
  })

  it('501s a service with no upstream', async () => {
    expect((await rpc('bare', { jsonrpc: '2.0', id: 1, method: 'tools/list' })).status).toBe(501)
  })
})
