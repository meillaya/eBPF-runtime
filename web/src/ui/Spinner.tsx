// SPDX-License-Identifier: Apache-2.0 OR MIT
import { cx } from "../lib/format";

const SIZES = { sm: 14, md: 18, lg: 28 } as const;
export type SpinnerSize = keyof typeof SIZES;

export function Spinner({
  size = "md",
  label = "Loading",
}: {
  size?: SpinnerSize;
  label?: string;
}) {
  const px = SIZES[size];
  return (
    <span
      role="status"
      aria-label={label}
      className={cx("spinner", size === "lg" && "spinner--lg")}
      style={{ width: px, height: px }}
    >
      <svg viewBox="0 0 24 24" width={px} height={px} aria-hidden="true" focusable="false">
        <circle
          cx="12"
          cy="12"
          r="9"
          fill="none"
          stroke="currentColor"
          strokeOpacity="0.2"
          strokeWidth="3"
        />
        <path
          d="M21 12a9 9 0 0 0-9-9"
          fill="none"
          stroke="currentColor"
          strokeWidth="3"
          strokeLinecap="round"
        />
      </svg>
      <span className="visually-hidden">{label}</span>
    </span>
  );
}

/** Full-surface boot/loading screen. */
export function BootScreen({ label = "Resolving session" }: { label?: string }) {
  return (
    <div className="boot-screen" role="status" aria-busy="true">
      <Spinner size="lg" label={label} />
      <p className="boot-label">{label}</p>
    </div>
  );
}
