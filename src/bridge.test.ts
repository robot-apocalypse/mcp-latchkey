import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import { bridgeChildEnv, createBridge } from './bridge.js'

const FAKE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'test', 'fake-upstream.mjs')
const TOKEN = 't'.repeat(40)
process.env.BRIDGE_TOKEN = TOKEN
const bridge = createBridge({
  listen: { host: '127.0.0.1', port: 0 },
  token: TOKEN,
  command: process.execPath,
  args: [FAKE],
  home: fs.mkdtempSync(path.join(os.tmpdir(), 'latchkey-bridge-')),
  log: () => {}
})
afterAll(() => bridge.upstream.close())

const rpc = (body: unknown, auth?: string) =>
  bridge.app.request('/mcp', {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(auth ? { authorization: auth } : {}) },
    body: JSON.stringify(body)
  })

describe('latchkey bridge', () => {
  it('refuses requests without the exact bridge token', async () => {
    expect((await rpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' })).status).toBe(401)
    expect((await rpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' }, `Bearer ${TOKEN}x`)).status).toBe(401)
    expect((await rpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' }, 'Bearer short')).status).toBe(401)
  })

  it('serves the stdio server with the token', async () => {
    const r = await rpc({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'counter', arguments: {} } }, `Bearer ${TOKEN}`)
    expect(r.status).toBe(200)
    expect(await r.text()).toContain('"text":"1"')
  })

  it('never hands BRIDGE_TOKEN to the child', async () => {
    const r = await (await rpc({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'env_keys', arguments: {} } }, `Bearer ${TOKEN}`)).text()
    expect(r).not.toContain('BRIDGE_TOKEN')
    expect(bridgeChildEnv({ BRIDGE_TOKEN: 'x', PATH: '/bin' })).toEqual({ PATH: '/bin' })
  })

  it('requires a long token', () => {
    expect(() => createBridge({ listen: { host: '127.0.0.1', port: 0 }, token: 'short', command: 'x', args: [], home: '/tmp' })).toThrow(/32/)
  })
})
