#!/usr/bin/env node
import { parseArgs } from 'node:util'
import { serve } from '@hono/node-server'
import { createApp, type McpHandler } from './app.js'
import { loadConfig, serviceResource, type Config } from './config.js'
import { createIdp } from './idp.js'
import { Store } from './store/store.js'

const USAGE = `latchkey: per-person, per-service sign-in for MCP servers

Usage: latchkey <command> [options]

Commands:
  serve                         run the gateway
  check-config                  validate the config and print a summary
  tokens list [--user U] [--service S]
  tokens revoke (--id ID | --user U | --service S)...
  users                         list users, their access and bound IdP accounts
  users unbind <user>           forget a user's bound IdP account (next sign-in rebinds)

Options:
  -c, --config <path>           config file (default: $LATCHKEY_CONFIG or ./latchkey.yaml)
`

// Phase 2 replaces this with the upstream bridge.
const notYetBridged: McpHandler = async (service) =>
  Response.json({ error: 'upstream_not_configured', error_description: `service "${service}" has no upstream yet` }, { status: 501 })

function table(rows: string[][]): string {
  if (rows.length === 0) return ''
  const widths = rows[0]!.map((_, i) => Math.max(...rows.map((r) => (r[i] ?? '').length)))
  return rows.map((r) => r.map((cell, i) => cell.padEnd(widths[i]!)).join('  ').trimEnd()).join('\n')
}

const ago = (ms: number) => {
  const s = Math.round((Date.now() - ms) / 1000)
  if (s < 120) return `${s}s ago`
  if (s < 7200) return `${Math.round(s / 60)}m ago`
  if (s < 172800) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      config: { type: 'string', short: 'c' },
      user: { type: 'string' },
      service: { type: 'string' },
      id: { type: 'string' },
      help: { type: 'boolean', short: 'h' }
    }
  })
  const [cmd, sub, arg] = positionals
  if (values.help || !cmd) {
    process.stdout.write(USAGE)
    return cmd ? 0 : 1
  }

  const configPath = values.config ?? process.env.LATCHKEY_CONFIG ?? './latchkey.yaml'
  const cfg: Config = loadConfig(configPath)
  const store = () => new Store(cfg.data_dir, cfg.encryption_key)

  switch (cmd) {
    case 'serve': {
      const app = createApp({ cfg, store: store(), idp: createIdp(cfg), mcp: notYetBridged })
      serve({ fetch: app.fetch, port: cfg.listen.port, hostname: cfg.listen.host }, (info) => {
        console.log(JSON.stringify({ event: 'listening', address: `${info.address}:${info.port}`, issuer: cfg.issuer, services: Object.keys(cfg.services) }))
      })
      return -1 // keep running
    }

    case 'check-config': {
      console.log(`config ok: ${configPath}`)
      console.log(`issuer:   ${cfg.issuer}`)
      console.log(`idp:      ${cfg.idp.issuer} (scopes: ${cfg.idp.scopes.join(' ')})`)
      console.log(`clients:  CIMD ${cfg.oauth.cimd_client_ids.join(', ') || '(off)'}; DCR ${cfg.oauth.dynamic_registration ? 'on' : 'off'}`)
      console.log(`redirects: ${cfg.oauth.redirect_uris.join(', ')}`)
      console.log('')
      console.log(table([['SERVICE', 'URL', 'ALLOWED'], ...Object.entries(cfg.services).map(([s, d]) => [s, serviceResource(cfg, s), d.allow.join(', ') || '(nobody)'])]))
      return 0
    }

    case 'tokens': {
      const s = store()
      if (sub === 'list' || sub === undefined) {
        const rows = s
          .listGrants()
          .filter((g) => (!values.user || g.user === values.user) && (!values.service || g.service === values.service))
          .sort((a, b) => b.lastUsedAt - a.lastUsedAt)
          .map((g) => [g.id, g.user, g.service, g.clientId, ago(g.createdAt), ago(g.lastUsedAt)])
        console.log(rows.length ? table([['ID', 'USER', 'SERVICE', 'CLIENT', 'ISSUED', 'LAST USED'], ...rows]) : 'no tokens')
        return 0
      }
      if (sub === 'revoke') {
        if (!values.id && !values.user && !values.service) {
          console.error('tokens revoke needs --id, --user and/or --service')
          return 1
        }
        const n = await s.revoke({ id: values.id, user: values.user, service: values.service })
        console.log(`revoked ${n} token${n === 1 ? '' : 's'}`)
        return 0
      }
      break
    }

    case 'users': {
      const s = store()
      if (sub === 'unbind') {
        if (!arg) {
          console.error('usage: latchkey users unbind <user>')
          return 1
        }
        console.log((await s.unbindIdentity(arg)) ? `unbound ${arg}` : `${arg} was not bound`)
        return 0
      }
      const ids = s.identities()
      const rows = Object.entries(cfg.users).map(([u, d]) => [
        u,
        d.email,
        Object.entries(cfg.services).filter(([, svc]) => svc.allow.includes(u)).map(([n]) => n).join(', ') || '-',
        ids[u] ? `${ids[u].sub} (${ago(ids[u].boundAt)})` : 'not yet'
      ])
      console.log(table([['USER', 'EMAIL', 'SERVICES', 'BOUND ACCOUNT'], ...rows]))
      return 0
    }
  }
  process.stderr.write(USAGE)
  return 1
}

main(process.argv.slice(2)).then(
  (code) => {
    if (code >= 0) process.exit(code)
  },
  (e: unknown) => {
    console.error(e instanceof Error ? e.message : String(e))
    process.exit(1)
  }
)
