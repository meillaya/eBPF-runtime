// SPDX-License-Identifier: Apache-2.0 OR MIT
import type { ReactNode } from "react";
import { cx } from "../lib/format";

export interface PanelProps {
  title: string;
  meta?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  flush?: boolean;
  className?: string;
  /** Optional landmark for assistive tech on key panels. */
  as?: "section" | "div";
  labelledBy?: string;
}

/** Console panel: caption strip header + dense body. */
export function Panel({
  title,
  meta,
  actions,
  children,
  flush = false,
  className,
  as = "section",
}: PanelProps) {
  const Tag = as;
  return (
    <Tag className={cx("panel", className)}>
      <header className="panel-head">
        <h2 className="panel-title">{title}</h2>
        {(meta !== undefined || actions !== undefined) && (
          <div className="panel-meta">
            {meta}
            {actions}
          </div>
        )}
      </header>
      <div className={cx("panel-body", flush && "panel-body--flush")}>{children}</div>
    </Tag>
  );
}
