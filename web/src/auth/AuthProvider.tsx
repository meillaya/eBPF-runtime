// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Session bootstrap + OIDC redirect orchestration. Dev-mode loopback
// bypasses everything (admin session); fleet mode runs code+PKCE with
// a prompt=none hidden-iframe silent renew before token expiry.

import type { ReactNode } from "react";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  useSyncExternalStore,
} from "react";
import { completeAuth } from "./complete";
import {
  buildAuthUrl,
  createPkcePair,
  getDiscovery,
  newAuthRequest,
  savePendingAuth,
} from "./oidc";
import {
  devBypassActive,
  devLoopbackSession,
  getSession,
  type Session,
  setSession,
  subscribeSession,
} from "./session";

export type AuthStatus = "resolving" | "authenticated" | "unauthenticated";

interface AuthContextValue {
  session: Session | null;
  status: AuthStatus;
  login: () => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const OIDC_IFRAME_MESSAGE = "kernel-v1.oidc.iframe-callback";

export interface OidcIframePayload {
  type: string;
  code: string | null;
  state: string | null;
  error: string | null;
}

const SILENT_RENEW_TIMEOUT_MS = 10_000;
const RENEW_LEAD_SEC = 60;

function silentRenew(): Promise<void> {
  return new Promise((resolve, reject) => {
    void (async () => {
      const disc = await getDiscovery();
      const pkce = await createPkcePair();
      const req = { ...newAuthRequest(pkce), prompt: "none" as const };
      savePendingAuth({ verifier: pkce.verifier, state: req.state, nonce: req.nonce });

      const iframe = document.createElement("iframe");
      iframe.className = "visually-hidden";
      iframe.setAttribute("aria-hidden", "true");

      const cleanup = (): void => {
        iframe.remove();
        globalThis.removeEventListener("message", onMessage);
        globalThis.clearTimeout(timer);
      };
      const onMessage = (ev: MessageEvent): void => {
        if (ev.origin !== globalThis.location.origin) return;
        const data = ev.data as OidcIframePayload | null;
        if (data === null || typeof data !== "object" || data.type !== OIDC_IFRAME_MESSAGE) return;
        if (data.state !== req.state) return;
        cleanup();
        if (data.error !== null || data.code === null || data.state === null) {
          reject(new Error(data.error ?? "silent renew rejected"));
          return;
        }
        completeAuth(data.code, data.state).then(
          () => resolve(),
          (cause: unknown) => reject(cause instanceof Error ? cause : new Error(String(cause))),
        );
      };
      globalThis.addEventListener("message", onMessage);
      const timer = globalThis.setTimeout(() => {
        cleanup();
        reject(new Error("silent renew timed out"));
      }, SILENT_RENEW_TIMEOUT_MS);

      iframe.src = buildAuthUrl(disc, req);
      document.body.appendChild(iframe);
    })().catch(reject);
  });
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const session = useSyncExternalStore(subscribeSession, getSession);
  const [status, setStatus] = useState<AuthStatus>("resolving");

  useEffect(() => {
    if (devBypassActive()) {
      setSession(devLoopbackSession());
      setStatus("authenticated");
      return;
    }
    setStatus(getSession() !== null ? "authenticated" : "unauthenticated");
  }, []);

  // Silent renew shortly before expiry; hard-expire on the deadline.
  useEffect(() => {
    if (session === null || session.expiresAtEpochSec === null || session.devMode) return;
    const nowMs = Date.now();
    const renewAtMs = (session.expiresAtEpochSec - RENEW_LEAD_SEC) * 1000;
    const renewDelay = Math.max(5_000, renewAtMs - nowMs);
    const renewTimer = globalThis.setTimeout(() => {
      silentRenew().catch(() => {
        // keep the current token; the expiry timer forces re-login
      });
    }, renewDelay);
    const expireDelay = Math.max(0, session.expiresAtEpochSec * 1000 - nowMs);
    const expireTimer = globalThis.setTimeout(() => {
      setSession(null);
    }, expireDelay);
    return () => {
      globalThis.clearTimeout(renewTimer);
      globalThis.clearTimeout(expireTimer);
    };
  }, [session]);

  const login = useCallback(async () => {
    const disc = await getDiscovery();
    const pkce = await createPkcePair();
    const req = newAuthRequest(pkce);
    savePendingAuth({ verifier: pkce.verifier, state: req.state, nonce: req.nonce });
    globalThis.location.assign(buildAuthUrl(disc, req));
  }, []);

  const logout = useCallback(() => {
    setSession(null);
  }, []);

  const value: AuthContextValue = { session, status, login, logout };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (ctx === null) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
