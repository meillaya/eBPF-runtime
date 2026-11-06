import { UserManager, WebStorageStateStore } from "oidc-client-ts";
import { authEnabled, setUser } from "./api";

const issuer = import.meta.env.VITE_OIDC_ISSUER as string | undefined;
const clientId = import.meta.env.VITE_OIDC_CLIENT_ID as string | undefined;

export const manager =
  authEnabled && issuer && clientId
    ? new UserManager({
        authority: issuer,
        client_id: clientId,
        redirect_uri: window.location.origin + "/callback",
        response_type: "code",
        scope: "openid profile email groups",
        userStore: new WebStorageStateStore({ store: window.sessionStorage }),
      })
    : null;

export async function initAuth(): Promise<boolean> {
  if (!manager) {
    return false;
  }
  if (window.location.pathname === "/callback") {
    await manager.signinRedirectCallback();
    window.history.replaceState({}, "", "/");
  }
  const user = await manager.getUser();
  setUser(user);
  return Boolean(user);
}

export async function login() {
  await manager?.signinRedirect();
}

export async function logout() {
  await manager?.signoutRedirect();
  setUser(null);
}
