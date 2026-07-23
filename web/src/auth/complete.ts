// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Shared completion path for the OIDC code callback — used by both the
// top-level /callback route and the hidden-iframe silent renew. PKCE
// transit state (non-secret, single-use) rides sessionStorage because
// it must survive the redirect hop; tokens never do.
import {
  clearPendingAuth,
  decodeIdTokenClaims,
  exchangeCode,
  loadPendingAuth,
  validateClaims,
} from "./oidc";
import { resolveRole } from "./roles";
import { type Session, setSession } from "./session";

export interface CallbackResult {
  code: string | null;
  state: string | null;
  error: string | null;
}

/** Exchange the callback code, validate the id_token, install session. */
export async function completeAuth(code: string, state: string): Promise<Session> {
  const pending = loadPendingAuth();
  if (pending === null) throw new Error("no pending authorization request (state lost?)");
  if (pending.state !== state) throw new Error("authorization state mismatch — possible CSRF");

  const tokens = await exchangeCode(code, pending.verifier);
  if (tokens.id_token === undefined) throw new Error("token response missing id_token");

  const claims = decodeIdTokenClaims(tokens.id_token);
  const problem = validateClaims(claims, pending.nonce, Math.floor(Date.now() / 1000));
  if (problem !== null) throw new Error(`id_token rejected: ${problem}`);

  clearPendingAuth();

  const groups = claims.groups ?? [];
  const role = resolveRole(groups);
  if (role === null) {
    throw new Error(
      `no role binding for groups [${groups.join(", ")}] — ask an admin to bind you to viewers/analysts/policy-admins/admins`,
    );
  }

  const session: Session = {
    subject: claims.sub,
    email: claims.email ?? null,
    role,
    groups,
    accessToken: tokens.access_token,
    expiresAtEpochSec: claims.exp,
    devMode: false,
  };
  setSession(session);
  return session;
}
