// A small MCP server for bridge tests. Run as a stdio server (default) or,
// with `--http <port>`, as a Streamable HTTP server on 127.0.0.1.
//
// Tools:
//   env_keys   names of the environment variables this process received
//   counter    increments in-process state (proves one long-lived process)
//   confirm    two-step: first call returns a token, second call with it succeeds
//   secret     hidden by tests via hide_tools
//   whoami_hdr echoes the x-upstream-key request header (HTTP mode)
import http from 'node:http'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'

let count = 0
const pending = new Set()
const text = (t) => ({ content: [{ type: 'text', text: typeof t === 'string' ? t : JSON.stringify(t) }] })
const tools = ['env_keys', 'counter', 'confirm', 'secret', 'whoami_hdr'].map((name) => ({ name, description: name, inputSchema: { type: 'object', properties: {} } }))

function build(headers = {}) {
  const server = new Server({ name: 'fake-upstream', version: '1.0.0' }, { capabilities: { tools: {} }, instructions: 'fake upstream instructions' })
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }))
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const args = req.params.arguments ?? {}
    switch (req.params.name) {
      case 'env_keys':
        return text(Object.keys(process.env).sort())
      case 'counter':
        return text(String(++count))
      case 'confirm': {
        if (args.confirm_token && pending.delete(args.confirm_token)) return text('confirmed')
        if (args.confirm_token) return { ...text('invalid confirm_token'), isError: true }
        const token = Math.random().toString(36).slice(2)
        pending.add(token)
        return text({ confirm_required: true, confirm_token: token })
      }
      case 'secret':
        return text('you should not see this')
      case 'whoami_hdr':
        return text(headers['x-upstream-key'] ?? null)
      default:
        return { ...text('unknown tool'), isError: true }
    }
  })
  return server
}

const httpIdx = process.argv.indexOf('--http')
if (httpIdx >= 0) {
  const port = Number(process.argv[httpIdx + 1])
  http
    .createServer(async (req, res) => {
      const server = build(req.headers)
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined })
      res.on('close', () => server.close())
      await server.connect(transport)
      await transport.handleRequest(req, res)
    })
    .listen(port, '127.0.0.1', () => process.stdout.write('ready\n'))
} else {
  await build().connect(new StdioServerTransport())
}
