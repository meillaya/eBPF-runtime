// SPDX-License-Identifier: Apache-2.0 OR MIT
import { Link } from "react-router-dom";
import { EmptyState } from "../ui/EmptyState";

export function NotFoundView() {
  return (
    <section aria-label="Not found">
      <EmptyState
        title="404 — no such console route"
        hint="The path does not map to any view. Telemetry routes live under Overview, Events, Alerts, Rules, Policies, and Agents."
        action={
          <Link className="btn btn--secondary" to="/">
            Back to overview
          </Link>
        }
      />
    </section>
  );
}
