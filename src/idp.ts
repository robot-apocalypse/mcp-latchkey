import * as oidc from 'openid-client'
import type { Config } from './config.js'

// The upstream identity provider (Google, Authentik, Pocket-ID, ...). Latchkey
// is an OIDC relying party here: it only needs a verified (iss, sub, email).
// openid-client validates the id_token signature, issuer, audience, nonce and
// expiry; PKCE + state protect the code exchange.

export interface IdpIdentity { iss: string; sub: string; email: string | undefined; emailVerified: boolean }

export interface Idp {
  authorizationUrl(params: { state: string; nonce: string; codeVerifier: string }): Promise<URL>
  /** `callbackUrl` is the full public URL the IdP redirected the browser to. */
  exchange(callbackUrl: URL, params: { state: string; nonce: string; codeVerifier: string }): Promise<IdpIdentity>
}

export const idpCallbackPath = '/idp/callback'

export function createIdp(cfg: Config, opts: { allowInsecure?: boolean } = {}): Idp {
  const redirectUri = `${cfg.issuer}${idpCallbackPath}`
  let discovered: Promise<oidc.Configuration> | undefined

  // Discovery is lazy and retried on failure, so a briefly unreachable IdP at
  // boot does not wedge the gateway.
  const configuration = (): Promise<oidc.Configuration> => {
    discovered ??= oidc
      .discovery(
        new URL(cfg.idp.issuer),
        cfg.idp.clientId,
        cfg.idp.clientSecret,
        undefined,
        opts.allowInsecure ? { execute: [oidc.allowInsecureRequests] } : undefined
      )
      .catch((e: unknown) => {
        discovered = undefined
        throw e
      })
    return discovered
  }

  return {
    async authorizationUrl({ state, nonce, codeVerifier }) {
      const config = await configuration()
      return oidc.buildAuthorizationUrl(config, {
        redirect_uri: redirectUri,
        scope: cfg.idp.scopes.join(' '),
        state,
        nonce,
        code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
        code_challenge_method: 'S256',
        prompt: 'select_account'
      })
    },

    async exchange(callbackUrl, { state, nonce, codeVerifier }) {
      const config = await configuration()
      const tokens = await oidc.authorizationCodeGrant(config, callbackUrl, {
        pkceCodeVerifier: codeVerifier,
        expectedState: state,
        expectedNonce: nonce,
        idTokenExpected: true
      })
      const claims = tokens.claims()
      if (!claims) throw new Error('IdP returned no id_token')
      return {
        iss: claims.iss,
        sub: claims.sub,
        email: typeof claims.email === 'string' ? claims.email : undefined,
        emailVerified: claims.email_verified === true
      }
    }
  }
}
