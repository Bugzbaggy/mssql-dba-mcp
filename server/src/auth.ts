/**
 * Microsoft Entra (Azure AD) OAuth — this server as an OAuth *Resource Server*.
 *
 * This is the TypeScript counterpart to the reference MCP server's FastMCP `AzureProvider`,
 * but deliberately the *slim* half of it. the reference MCP server's AzureProvider does three
 * things: (1) a Dynamic-Client-Registration shim so Claude can register, (2) it
 * proxies authorize/token to Entra and mints its own JWT, and (3) On-Behalf-Of to
 * Power BI. Entra does **not** support DCR, so a 1:1 OAuth-proxy port would mean
 * hand-writing that shim. We don't: appdb-sql-mcp acts purely as a Resource Server.
 * It *verifies* Entra-issued access tokens (audience = our API) on every /mcp call;
 * the MCP client obtains those tokens from Entra directly (discovery via the
 * Protected-Resource-Metadata document we publish — see buildProtectedResourceMetadata).
 *
 * The OBO exchange that turns the verified user token into a *SQL* access token
 * (Path A) lives in connectionManager.ts, gated per-instance — see ENTRA_SQL_OBO.
 *
 * Auth is OFF by default (MCP_AUTH_MODE=off) so the existing X-DB-User/X-DB-Password
 * deployment keeps working until the Entra app + platform config are in place. Set
 * MCP_AUTH_MODE=required to enforce a valid Entra JWT on every /mcp request.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

export type AuthMode = "off" | "optional" | "required";

export interface EntraAuthConfig {
  mode: AuthMode;
  tenantId: string;
  /** App (client) ID of THIS server's Entra app registration. */
  clientId: string;
  /** Token audience we accept — the "Expose an API" App ID URI, default api://{clientId}. */
  audience: string;
  /** Issuer we accept — the v2 issuer for our tenant. */
  issuer: string;
  /** Scopes the caller's token MUST carry (the custom API scope, e.g. access_as_user). */
  requiredScopes: string[];
  /** This server's public resource identifier (the /mcp URL), advertised in PRM + RFC8707. */
  resourceUrl: string;
}

/** Identity extracted from a verified Entra token, threaded into the request context. */
export interface EntraIdentity {
  /** Raw bearer token — reused as the OBO user-assertion for the SQL token exchange (Path A). */
  token: string;
  /** Stable object ID of the signed-in user (audit key; never reassigned). */
  oid?: string;
  /** UPN / email — what a human recognises in the audit trail. */
  upn?: string;
  /** Tenant ID the token was issued for. */
  tid?: string;
}

export function loadAuthConfig(): EntraAuthConfig {
  const mode = (process.env.MCP_AUTH_MODE ?? "off").toLowerCase() as AuthMode;
  // example tenant default — same GUID the reference MCP server ships with.
  const tenantId = process.env.ENTRA_TENANT_ID ?? "00000000-0000-0000-0000-000000000000";
  const clientId = process.env.ENTRA_CLIENT_ID ?? "";
  const audience = process.env.ENTRA_API_AUDIENCE ?? (clientId ? `api://${clientId}` : "");
  const issuer = process.env.ENTRA_ISSUER ?? `https://login.microsoftonline.com/${tenantId}/v2.0`;
  const requiredScopes = (process.env.ENTRA_REQUIRED_SCOPES ?? "access_as_user")
    .split(/[ ,]+/).map((s) => s.trim()).filter(Boolean);
  const resourceUrl =
    process.env.MCP_RESOURCE_URL ??
    `${(process.env.MCP_PUBLIC_URL ?? "").replace(/\/$/, "")}/mcp`;

  if (mode !== "off") {
    if (!clientId) throw new Error("MCP_AUTH_MODE is set but ENTRA_CLIENT_ID is missing.");
    if (!audience) throw new Error("MCP_AUTH_MODE is set but ENTRA_API_AUDIENCE could not be derived.");
  }
  return { mode, tenantId, clientId, audience, issuer, requiredScopes, resourceUrl };
}

/**
 * Build the Resource-Server token verifier. It validates signature (via Entra's
 * JWKS), issuer, audience, and expiry, then maps the token to the SDK's AuthInfo.
 * `extra.entra` carries the identity connectionManager needs for audit + OBO.
 */
export function buildVerifier(cfg: EntraAuthConfig): OAuthTokenVerifier {
  // JWKS is fetched once and cached/rotated by jose; keys roll without a restart.
  const JWKS = createRemoteJWKSet(
    new URL(`https://login.microsoftonline.com/${cfg.tenantId}/discovery/v2.0/keys`),
  );

  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      const { payload } = await jwtVerify(token, JWKS, {
        issuer: cfg.issuer,
        audience: cfg.audience,
        // Pin the signing algorithm. Entra v2 access tokens are RS256; restricting the
        // accepted set is defence-in-depth against alg-substitution (jose already rejects
        // "none" and won't use an RSA JWKS key as an HMAC secret, but pinning is explicit).
        algorithms: ["RS256"],
      });

      // Entra puts delegated scopes in `scp` (space-delimited) and app roles in `roles`.
      const scp = typeof payload.scp === "string" ? payload.scp.split(" ").filter(Boolean) : [];
      const roles = Array.isArray(payload.roles) ? (payload.roles as string[]) : [];
      const scopes = [...scp, ...roles];

      // requireBearerAuth checks requiredScopes too, but failing here gives a precise error.
      for (const need of cfg.requiredScopes) {
        if (!scopes.includes(need)) {
          throw new Error(`Token is missing required scope "${need}".`);
        }
      }

      const p = payload as JWTPayload & {
        oid?: string; tid?: string; upn?: string; preferred_username?: string;
        azp?: string; appid?: string;
      };
      const identity: EntraIdentity = {
        token,
        oid: p.oid,
        upn: p.upn ?? p.preferred_username,
        tid: p.tid,
      };

      return {
        token,
        clientId: p.azp ?? p.appid ?? "",
        scopes,
        expiresAt: typeof payload.exp === "number" ? payload.exp : undefined,
        resource: cfg.resourceUrl ? new URL(cfg.resourceUrl) : undefined,
        extra: { entra: identity },
      };
    },
  };
}

/**
 * OAuth 2.0 Protected Resource Metadata (RFC 9728) — served at
 * /.well-known/oauth-protected-resource. An MCP client that gets a 401 reads this
 * to discover WHICH authorization server (Entra, our tenant) to send the user to.
 *
 * NOTE: Entra has no Dynamic Client Registration. A public MCP client (Claude) must
 * therefore use a pre-registered client_id for our app — see AAD-ENTRA-SETUP.md.
 */
export function buildProtectedResourceMetadata(cfg: EntraAuthConfig): Record<string, unknown> {
  return {
    resource: cfg.resourceUrl,
    authorization_servers: [cfg.issuer],
    scopes_supported: cfg.requiredScopes,
    bearer_methods_supported: ["header"],
    resource_name: "appdb-sql",
  };
}

/** Pull the verified identity back out of AuthInfo.extra (set by buildVerifier). */
export function identityFromAuth(auth: AuthInfo | undefined): EntraIdentity | undefined {
  const e = auth?.extra?.entra as EntraIdentity | undefined;
  return e?.token ? e : undefined;
}
