// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// OIDC authorization-code + PKCE shell, mirroring crates/auth:
//   * S256 only, 32-byte verifier / 16-byte state+nonce (pkce.rs)
//   * discovery fetched, issuer pinned by EXACT equality (discovery.rs)
//   * id-token claim order iss → aud → exp → iat(+120s) → nonce (jwt.rs)
// Signature verification (JWKS) stays server-side; the shell validates
// claims and the nonce it generated. Tokens live in memory only.

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  scopes_supported?: string[];
}

export const OIDC_ISSUER: string = import.meta.env.VITE_OIDC_ISSUER ?? "http://127.0.0.1:5556/dex";
export const OIDC_CLIENT_ID: string = import.meta.env.VITE_OIDC_CLIENT_ID ?? "kernel-v1-dev";
export const OIDC_SCOPES = "openid profile email groups";
export const IAT_SKEW_SEC = 120;

export function redirectUri(): string {
  return `${globalThis.location.origin}/callback`;
}

let discoveryCache: OidcDiscovery | null = null;

export async function getDiscovery(): Promise<OidcDiscovery> {
  if (discoveryCache !== null) return discoveryCache;
  const res = await fetch(`${OIDC_ISSUER}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`OIDC discovery failed: HTTP ${res.status}`);
  const doc = (await res.json()) as OidcDiscovery;
  // Exact-string pin, mirroring discovery.rs validate_pinned (no
  // prefix/suffix/case tolerance, trailing slash rejected).
  if (doc.issuer !== OIDC_ISSUER) {
    throw new Error(`OIDC issuer mismatch: expected ${OIDC_ISSUER}, got ${doc.issuer}`);
  }
  discoveryCache = doc;
  return doc;
}

function randomUrlSafe(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlDecode(s: string): Uint8Array {
  const b64 = s.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export interface PkcePair {
  verifier: string;
  challenge: string;
}

/** 32 random bytes → 43-char verifier; challenge = B64URL(SHA-256(v)). */
export async function createPkcePair(): Promise<PkcePair> {
  const verifier = randomUrlSafe(32);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return { verifier, challenge: base64UrlEncode(new Uint8Array(digest)) };
}

export interface AuthRequestParams {
  state: string;
  nonce: string;
  pkce: PkcePair;
  prompt?: "none";
}

export function newAuthRequest(pkce: PkcePair): AuthRequestParams {
  return { state: randomUrlSafe(16), nonce: randomUrlSafe(16), pkce };
}

export function buildAuthUrl(disc: OidcDiscovery, req: AuthRequestParams): string {
  const sp = new URLSearchParams({
    response_type: "code",
    client_id: OIDC_CLIENT_ID,
    redirect_uri: redirectUri(),
    scope: OIDC_SCOPES,
    state: req.state,
    nonce: req.nonce,
    code_challenge: req.pkce.challenge,
    code_challenge_method: "S256",
  });
  if (req.prompt !== undefined) sp.set("prompt", "none");
  return `${disc.authorization_endpoint}?${sp.toString()}`;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  id_token?: string;
  scope?: string;
}

export interface TokenError {
  error: string;
  error_description?: string;
}

/** Public-client exchange (no secret): code + S256 verifier. */
export async function exchangeCode(code: string, verifier: string): Promise<TokenResponse> {
  const disc = await getDiscovery();
  const res = await fetch(disc.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri(),
      client_id: OIDC_CLIENT_ID,
      code_verifier: verifier,
    }),
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as TokenError;
      detail = body.error_description ?? body.error;
    } catch {
      // keep the status line
    }
    throw new Error(`token exchange failed: ${detail}`);
  }
  return (await res.json()) as TokenResponse;
}

/** Claims subset of jwt.rs IdTokenClaims the shell validates. */
export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  azp?: string;
  nonce?: string;
  groups?: string[];
  email?: string;
  name?: string;
}

export function decodeIdTokenClaims(jwt: string): IdTokenClaims {
  const segments = jwt.split(".");
  if (segments.length !== 3) throw new Error("id_token: expected 3 segments");
  const payload = segments[1];
  if (payload === undefined) throw new Error("id_token: missing payload segment");
  const json = new TextDecoder().decode(base64UrlDecode(payload));
  return JSON.parse(json) as IdTokenClaims;
}

export interface PendingAuth {
  verifier: string;
  state: string;
  nonce: string;
}

const PENDING_KEY = "kernel-v1.oidc.pending";

export function savePendingAuth(pending: PendingAuth): void {
  sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending));
}

export function loadPendingAuth(): PendingAuth | null {
  const raw = sessionStorage.getItem(PENDING_KEY);
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as PendingAuth;
    if (typeof parsed.verifier !== "string" || typeof parsed.state !== "string") return null;
    return parsed;
  } catch {
    return null;
  }
}

export function clearPendingAuth(): void {
  sessionStorage.removeItem(PENDING_KEY);
}

/**
 * Validate claims in jwt.rs order. Returns an error reason or null.
 * `expectedNonce` null means the request carried no nonce.
 */
export function validateClaims(
  claims: IdTokenClaims,
  expectedNonce: string | null,
  nowEpochSec: number,
): string | null {
  if (claims.iss !== OIDC_ISSUER) return `issuer mismatch (${claims.iss})`;
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(OIDC_CLIENT_ID)) return `audience mismatch (${audiences.join(",")})`;
  if (nowEpochSec >= claims.exp) return "token expired";
  if (claims.iat > nowEpochSec + IAT_SKEW_SEC) return "token issued in the future";
  if (expectedNonce !== null && claims.nonce !== expectedNonce) return "nonce mismatch";
  return null;
}
