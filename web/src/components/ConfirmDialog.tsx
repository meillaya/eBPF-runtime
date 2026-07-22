// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Confirmation gate for every console mutation. Renders the audit
// intent (actor, action, target, timestamp — mirroring control-plane
// AuditRecord) so the operator sees exactly what will be recorded
// before confirming. Focus-trapped, Escape/overlay dismiss (DESIGN.md
// §9), cancel is the safe default focus.
import { type ReactNode, useEffect, useRef } from "react";
import { cx } from "../lib/format";
import { Button } from "../ui/Button";

export interface IntentEntry {
  label: string;
  value: string;
}

export interface ConfirmDialogProps {
  open: boolean;
  title: string;
  tone?: "info" | "danger";
  intent: ReadonlyArray<IntentEntry>;
  confirmLabel: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: ReactNode;
}

const FOCUSABLE = "button:not(:disabled), [href], input:not(:disabled), select, textarea";

export function ConfirmDialog({
  open,
  title,
  tone = "info",
  intent,
  confirmLabel,
  busy = false,
  onConfirm,
  onCancel,
  children,
}: ConfirmDialogProps) {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const restoreRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    restoreRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const cancel = dialogRef.current?.querySelector<HTMLButtonElement>("[data-cancel]");
    cancel?.focus();

    const onKey = (ev: KeyboardEvent): void => {
      if (ev.key === "Escape") {
        ev.stopPropagation();
        onCancel();
        return;
      }
      if (ev.key !== "Tab") return;
      const nodes = dialogRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE);
      if (nodes === undefined || nodes.length === 0) return;
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      if (first === undefined || last === undefined) return;
      if (ev.shiftKey && document.activeElement === first) {
        ev.preventDefault();
        last.focus();
      } else if (!ev.shiftKey && document.activeElement === last) {
        ev.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      restoreRef.current?.focus();
    };
  }, [open, onCancel]);

  if (!open) return null;

  return (
    // biome-ignore lint/a11y/noStaticElementInteractions: WAI-ARIA modal scrim — pointer-only dismiss; keyboard users exit via Escape (focus-trap effect) or the Cancel button, which owns default focus
    <div
      className="dialog-overlay"
      onMouseDown={(ev) => {
        if (ev.target === ev.currentTarget) onCancel();
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        className={cx("dialog", tone === "danger" && "dialog--danger")}
      >
        <header className="dialog-head">
          <h2 id="confirm-dialog-title" className="dialog-title">
            {title}
          </h2>
        </header>
        <div className="dialog-body">
          {children}
          <dl className="intent">
            {intent.map((entry) => (
              <div key={entry.label} style={{ display: "contents" }}>
                <dt>{entry.label}</dt>
                <dd>{entry.value}</dd>
              </div>
            ))}
          </dl>
        </div>
        <footer className="dialog-foot">
          <Button variant="ghost" data-cancel onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant={tone === "danger" ? "danger" : "primary"}
            loading={busy}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </footer>
      </div>
    </div>
  );
}
