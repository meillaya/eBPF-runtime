// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Role-aware route guard. Hierarchy: viewer < analyst < policy-admin <
// admin (crates/auth/src/rbac.rs). The server re-checks every request;
// this gate only shapes what the UI offers.
import { type ReactNode, useEffect } from "react";
import { EmptyState } from "../ui/EmptyState";
import { BootScreen } from "../ui/Spinner";
import { useAuth } from "./AuthProvider";
import { ROLE_LABELS, type Role, roleAtLeast } from "./roles";

function LoginRedirect() {
  const { login } = useAuth();
  useEffect(() => {
    login().catch(() => {
      // discovery unreachable — BootScreen stays; operator can reload
    });
  }, [login]);
  return <BootScreen label="Redirecting to sign-in" />;
}

export function ForbiddenView({ required }: { required: Role }) {
  const { session } = useAuth();
  const current = session === null ? "none" : ROLE_LABELS[session.role];
  return (
    <div className="view-forbidden">
      <EmptyState
        tone="error"
        title="403 — insufficient role"
        hint={`This console area requires ${ROLE_LABELS[required]} or higher; you are signed in as ${current}. Ask an admin to bind your groups to a higher role (viewers < analysts < policy-admins < admins).`}
      />
    </div>
  );
}

export function RequireRole({ min, children }: { min: Role; children: ReactNode }) {
  const { session, status } = useAuth();
  if (status === "resolving") return <BootScreen />;
  if (status === "unauthenticated" || session === null) return <LoginRedirect />;
  if (!roleAtLeast(session.role, min)) return <ForbiddenView required={min} />;
  return <>{children}</>;
}
