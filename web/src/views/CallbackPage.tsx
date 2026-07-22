// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// OIDC redirect landing (/callback). Two modes:
//   * top-level window → exchange code, install session, go home
//   * hidden iframe (silent renew) → post the code to the parent, which
//     owns the exchange (AuthProvider listens for OIDC_IFRAME_MESSAGE)
import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { OIDC_IFRAME_MESSAGE } from "../auth/AuthProvider";
import { completeAuth } from "../auth/complete";
import { Button } from "../ui/Button";
import { BootScreen, Spinner } from "../ui/Spinner";

export function CallbackPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const inIframe = globalThis.self !== globalThis.top;

  const code = params.get("code");
  const state = params.get("state");
  const oauthError = params.get("error");

  useEffect(() => {
    if (inIframe) {
      globalThis.parent.postMessage(
        { type: OIDC_IFRAME_MESSAGE, code, state, error: oauthError },
        globalThis.location.origin,
      );
      return;
    }
    if (oauthError !== null) {
      setError(`authorization denied: ${oauthError}`);
      return;
    }
    if (code === null || state === null) {
      setError("callback is missing code/state parameters");
      return;
    }
    completeAuth(code, state).then(
      () => navigate("/", { replace: true }),
      (cause: unknown) => setError(cause instanceof Error ? cause.message : String(cause)),
    );
  }, [inIframe, code, state, oauthError, navigate]);

  if (inIframe) {
    return <Spinner label="Completing silent sign-in" />;
  }

  return (
    <div className="callback-screen">
      {error === null ? (
        <BootScreen label="Completing sign-in" />
      ) : (
        <div className="well well--error" role="alert">
          <p className="well-title">Sign-in failed</p>
          <p className="well-detail">{error}</p>
          <div className="action-row">
            <Button variant="secondary" onClick={() => navigate("/", { replace: true })}>
              Back to console
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
