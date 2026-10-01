import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import type { McpHandler } from './app.js'
import type { Config } from './config.js'

// Built-in diagnostic service: `services.<name>.builtin: whoami` serves one
// tool that reports who latchkey thinks is calling. Use it to check sign-in and
// access rules from a client before wiring up a real upstream.

export const BUILTINS = ['whoami'] as const

export function builtinHandler(cfg: Config): McpHandler {
  return async (service, grant, request) => {
    const server = new Server({ name: `latchkey-${service}`, version: '0.1.0' }, { capabilities: { tools: {} } })
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'whoami',
          description: 'Report which latchkey user and service this connection is signed in as.',
          inputSchema: { type: 'object', properties: {} }
        }
      ]
    }))
    server.setRequestHandler(CallToolRequestSchema, async (req) => {
      if (req.params.name !== 'whoami') return { content: [{ type: 'text', text: `unknown tool ${req.params.name}` }], isError: true }
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ user: grant.user, email: cfg.users[grant.user]?.email, service, client: grant.clientId, issuer: cfg.issuer })
          }
        ]
      }
    })
    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined })
    transport.onclose = () => {
      server.close().catch(() => {})
    }
    await server.connect(transport)
    return transport.handleRequest(request)
  }
}
