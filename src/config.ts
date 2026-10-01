import fs from 'node:fs'
import { parse as parseYaml } from 'yaml'
import { z } from 'zod'

// Claude's documented connector callbacks and its CIMD client ID
// (https://claude.com/docs/connectors/building/authentication; client ID
// observed in docs/spike-results.md).
export const CLAUDE_REDIRECT_URIS = [
  'https://claude.ai/api/mcp/auth_callback',
  'https://claude.com/api/mcp/auth_callback'
]
export const CLAUDE_CIMD_CLIENT_IDS = ['https://claude.ai/oauth/mcp-oauth-client-metadata']

const IDP_PRESETS: Record<string, { issuer: string; scopes: string[] }> = {
  google: { issuer: 'https://accounts.google.com', scopes: ['openid', 'email'] }
}

const DURATION_RE = /^(\d+)(s|m|h|d)$/
const UNIT_MS = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 } as const

/** "30m", "1h", "90d" → milliseconds. */
export function parseDuration(s: string): number {
  const m = DURATION_RE.exec(s.trim())
  if (!m) throw new Error(`invalid duration "${s}" (use e.g. 30m, 1h, 90d)`)
  return Number(m[1]) * UNIT_MS[m[2] as keyof typeof UNIT_MS]
}

const duration = z.string().refine((s) => DURATION_RE.test(s.trim()), 'use e.g. 30m, 1h, 90d').transform(parseDuration)
const name = z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/, 'lowercase letters, digits and dashes')
const httpsUrl = z.url().refine((u) => isSecureUrl(u), 'must be https (http only for localhost)')

function isSecureUrl(u: string): boolean {
  const url = new URL(u)
  return url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))
}

const userSchema = z.strictObject({
  email: z.email().transform((e) => e.toLowerCase())
})

// Upstream definitions are consumed in Phase 2; validated loosely here so
// configs written now keep working.
const serviceSchema = z.looseObject({
  allow: z.array(name).default([]),
  builtin: z.enum(['whoami']).optional()
})

const idpSchema = z
  .strictObject({
    preset: z.enum(Object.keys(IDP_PRESETS) as [string, ...string[]]).optional(),
    issuer: httpsUrl.optional(),
    client_id: z.string().min(1),
    client_secret: z.string().min(1),
    scopes: z.array(z.string()).optional()
  })
  .transform((idp, ctx) => {
    const preset = idp.preset ? IDP_PRESETS[idp.preset] : undefined
    const issuer = idp.issuer ?? preset?.issuer
    if (!issuer) {
      ctx.addIssue({ code: 'custom', message: 'idp needs `issuer` or a `preset`' })
      return z.NEVER
    }
    return {
      issuer,
      clientId: idp.client_id,
      clientSecret: idp.client_secret,
      scopes: idp.scopes ?? preset?.scopes ?? ['openid', 'email']
    }
  })

const configSchema = z
  .strictObject({
    issuer: httpsUrl.transform((u) => u.replace(/\/+$/, '')),
    listen: z
      .strictObject({ host: z.string().default('127.0.0.1'), port: z.number().int().min(1).max(65535).default(8080) })
      .default({ host: '127.0.0.1', port: 8080 }),
    data_dir: z.string().default('./data'),
    encryption_key: z.string().min(32, 'encryption_key must be at least 32 characters'),
    idp: idpSchema,
    oauth: z
      .strictObject({
        redirect_uris: z.array(httpsUrl).min(1).default(CLAUDE_REDIRECT_URIS),
        cimd_client_ids: z.array(httpsUrl).default(CLAUDE_CIMD_CLIENT_IDS),
        dynamic_registration: z.boolean().default(false),
        access_token_ttl: duration.default(parseDuration('1h')),
        refresh_token_idle_ttl: duration.default(parseDuration('90d'))
      })
      .prefault({}),
    users: z.record(name, userSchema),
    services: z.record(name, serviceSchema)
  })
  .superRefine((cfg, ctx) => {
    for (const [svc, def] of Object.entries(cfg.services)) {
      for (const u of def.allow) {
        if (!cfg.users[u]) ctx.addIssue({ code: 'custom', path: ['services', svc, 'allow'], message: `unknown user "${u}"` })
      }
    }
    const emails = new Map<string, string>()
    for (const [u, def] of Object.entries(cfg.users)) {
      const other = emails.get(def.email)
      if (other) ctx.addIssue({ code: 'custom', path: ['users', u, 'email'], message: `same email as user "${other}"` })
      emails.set(def.email, u)
    }
  })

export type Config = z.output<typeof configSchema>
export type ServiceConfig = Config['services'][string]

/** Replaces ${VAR} in every string value. Done after YAML parsing so values can't inject YAML. */
export function interpolateEnv(value: unknown, env: NodeJS.ProcessEnv, path = ''): unknown {
  if (typeof value === 'string') {
    return value.replace(/\$\{([A-Z0-9_]+)\}/g, (_, v: string) => {
      const out = env[v]
      if (out === undefined) throw new Error(`${path || 'config'}: environment variable ${v} is not set`)
      return out
    })
  }
  if (Array.isArray(value)) return value.map((v, i) => interpolateEnv(v, env, `${path}[${i}]`))
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, interpolateEnv(v, env, path ? `${path}.${k}` : k)])
    )
  }
  return value
}

export function parseConfig(yamlText: string, env: NodeJS.ProcessEnv = process.env): Config {
  const raw = interpolateEnv(parseYaml(yamlText) ?? {}, env)
  const result = configSchema.safeParse(raw)
  if (!result.success) {
    const lines = result.error.issues.map((i) => `  ${i.path.join('.') || '(root)'}: ${i.message}`)
    throw new Error(`invalid config:\n${lines.join('\n')}`)
  }
  return result.data
}

export function loadConfig(path: string, env: NodeJS.ProcessEnv = process.env): Config {
  return parseConfig(fs.readFileSync(path, 'utf8'), env)
}

export function userByEmail(cfg: Config, email: string): string | undefined {
  const e = email.toLowerCase()
  return Object.entries(cfg.users).find(([, u]) => u.email === e)?.[0]
}

export function isAllowed(cfg: Config, user: string, service: string): boolean {
  return !!cfg.users[user] && (cfg.services[service]?.allow.includes(user) ?? false)
}

export function serviceResource(cfg: Config, service: string): string {
  return `${cfg.issuer}/${service}/mcp`
}

/** Maps an RFC 8707 resource URL back to a configured service name. */
export function serviceForResource(cfg: Config, resource: string | undefined): string | undefined {
  if (!resource) return undefined
  return Object.keys(cfg.services).find((s) => serviceResource(cfg, s) === resource.replace(/\/+$/, ''))
}
