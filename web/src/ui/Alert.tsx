// SPDX-License-Identifier: Apache-2.0 OR MIT
import type { ReactNode } from "react";
import { cx } from "../lib/format";

export type AlertTone = "info" | "warning" | "critical";

export interface AlertProps {
  tone: AlertTone;
  title: string;
  children?: ReactNode;
  /** critical → role=alert (assertive); otherwise role=status (polite). */
  action?: ReactNode;
  onDismiss?: () => void;
}

export function Alert({ tone, title, children, action, onDismiss }: AlertProps) {
  return (
    <div role={tone === "critical" ? "alert" : "status"} className={cx("alert", `alert--${tone}`)}>
      <AlertGlyph tone={tone} />
      <div className="alert-body">
        <p className="alert-title">{title}</p>
        {children !== undefined && <p className="alert-detail">{children}</p>}
      </div>
      {action}
      {onDismiss !== undefined && (
        <button
          type="button"
          className="btn btn--ghost btn--sm"
          onClick={onDismiss}
          aria-label="Dismiss notification"
        >
          ✕
        </button>
      )}
    </div>
  );
}

function AlertGlyph({ tone }: { tone: AlertTone }) {
  const d =
    tone === "critical"
      ? "M12 2 1 21h22L12 2zm0 6 7.5 13h-15L12 8zm-1 4v4h2v-4h-2zm0 5v2h2v-2h-2z"
      : tone === "warning"
        ? "M12 2 1 21h22L12 2zm-1 8h2v5h-2v-5zm0 6h2v2h-2v-2z"
        : "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm-1 5h2v2h-2V7zm0 4h2v6h-2v-6z";
  return (
    <svg
      viewBox="0 0 24 24"
      width="16"
      height="16"
      aria-hidden="true"
      focusable="false"
      className="alert-glyph"
    >
      <path d={d} fill="currentColor" />
    </svg>
  );
}
