// SPDX-License-Identifier: Apache-2.0 OR MIT
import type { ReactNode } from "react";
import { cx } from "../lib/format";

export interface EmptyStateProps {
  title: string;
  hint: string;
  action?: ReactNode;
  /** Dashed well turns red-tinted for error-flavored empties. */
  tone?: "neutral" | "error";
}

export function EmptyState({ title, hint, action, tone = "neutral" }: EmptyStateProps) {
  return (
    <div className={cx("well", tone === "error" && "well--error")}>
      <EmptyGlyph />
      <p className="well-title">{title}</p>
      <p className="well-hint">{hint}</p>
      {action}
    </div>
  );
}

function EmptyGlyph() {
  return (
    <svg
      viewBox="0 0 32 32"
      width="34"
      height="34"
      aria-hidden="true"
      focusable="false"
      className="well-glyph"
    >
      <path
        d="M16 3l11 6.5v13L16 29 5 22.5v-13L16 3z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <path
        d="M5 9.5 16 16l11-6.5M16 16v13"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.4"
        opacity="0.55"
      />
    </svg>
  );
}
