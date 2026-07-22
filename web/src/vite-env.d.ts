// SPDX-License-Identifier: Apache-2.0 OR MIT
/// <reference types="vite/client" />

/**
 * Typed surface for the Vite env vars the console reads. Anything not
 * listed here is invisible to the app (no untyped import.meta.env use).
 */
interface ImportMetaEnv {
  /** REST/WS base of the control-plane API. Empty string = same origin. */
  readonly VITE_API_BASE?: string;
  /** OIDC issuer (dev Dex: http://127.0.0.1:5556/dex). */
  readonly VITE_OIDC_ISSUER?: string;
  /** OIDC client id registered with the issuer (dev: kernel-v1-dev). */
  readonly VITE_OIDC_CLIENT_ID?: string;
  /** Set to "1" to force the OIDC redirect flow even on loopback. */
  readonly VITE_FORCE_OIDC?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
