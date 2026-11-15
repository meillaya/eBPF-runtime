import {
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";

/* The Register primitives: rules, registers and type. No icons, no cards, no badges. */

export function classNames(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

/* ------------------------------------------------------------------ buttons */

type ButtonVariant = "default" | "primary" | "danger";

export function Button({
  variant = "default",
  wide = false,
  className = "",
  children,
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  wide?: boolean;
}) {
  return (
    <button
      type={type}
      className={classNames(
        "btn",
        variant === "primary" ? "primary" : variant === "danger" ? "danger" : "",
        wide ? "wide" : "",
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}

export function LinkButton({
  className = "",
  children,
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type={type} className={classNames("link", className)} {...props}>
      {children}
    </button>
  );
}

export function TableButton({
  className = "",
  children,
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type={type} className={classNames("tbtn", className)} {...props}>
      {children}
    </button>
  );
}

/* ----------------------------------------------------------------- measures */

export function MeasureBand({ children, sub = false }: { children: ReactNode; sub?: boolean }) {
  return <div className={classNames("band", sub && "sub")}>{children}</div>;
}

export function Measure({
  value,
  label,
  note,
  signal = false,
}: {
  value: ReactNode;
  label: ReactNode;
  note?: ReactNode;
  signal?: boolean;
}) {
  return (
    <div className="measure">
      <div className="measure-value">{value}</div>
      <div className="measure-label">{label}</div>
      {note ? <div className={classNames("measure-note", signal && "sig")}>{note}</div> : null}
    </div>
  );
}

/* ---------------------------------------------------------------- registers */

export function Section({
  title,
  meta,
  tools,
  children,
  className = "",
  id,
}: {
  title: ReactNode;
  meta?: ReactNode;
  tools?: ReactNode;
  children: ReactNode;
  className?: string;
  id?: string;
}) {
  return (
    <section className={classNames("section", className)} id={id}>
      <div className="section-head">
        <h2 className="section-title">{title}</h2>
        {meta || tools ? (
          <div className="section-tools">
            {meta ? <span className="section-meta">{meta}</span> : null}
            {tools}
          </div>
        ) : null}
      </div>
      <div className="section-body">{children}</div>
    </section>
  );
}

export function Table({
  children,
  className = "",
  minWidth,
  label,
}: {
  children: ReactNode;
  className?: string;
  minWidth?: number;
  label: string;
}) {
  return (
    <div className="table-scroll">
      <table
        className={classNames("reg", className)}
        style={minWidth ? { minWidth } : undefined}
        aria-label={label}
      >
        {children}
      </table>
    </div>
  );
}

export function EmptyRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr>
      <td className="empty-cell" colSpan={colSpan}>
        {children}
      </td>
    </tr>
  );
}

/* ------------------------------------------------------------------- inputs */

export function SearchField({
  value,
  onChange,
  placeholder = "Search",
  label = "Search",
  id,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  label?: string;
  id?: string;
}) {
  const generated = useId();
  const inputId = id ?? generated;
  return (
    <label className="field search">
      <span>{label}</span>
      <input
        id={inputId}
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        spellCheck={false}
        autoComplete="off"
      />
    </label>
  );
}

export function SelectField({
  value,
  onChange,
  options,
  label,
  id,
}: {
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
  label: string;
  id?: string;
}) {
  const generated = useId();
  const selectId = id ?? generated;
  return (
    <label className="field" htmlFor={selectId}>
      <span>{label}</span>
      <select id={selectId} value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function FilterTabs<T extends string>({
  options,
  value,
  onChange,
  ariaLabel,
  variant = "filters",
}: {
  options: Array<{ value: T; label: string }>;
  value: T;
  onChange: (value: T) => void;
  ariaLabel: string;
  variant?: "filters" | "range";
}) {
  return (
    <div className={variant} role="group" aria-label={ariaLabel}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          className={variant === "range" ? undefined : "fbtn"}
          aria-pressed={option.value === value}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Field({
  label,
  hint,
  htmlFor,
  children,
}: {
  label: ReactNode;
  hint?: ReactNode;
  htmlFor?: string;
  children: ReactNode;
}) {
  return (
    <label className="field" htmlFor={htmlFor}>
      <span>{label}</span>
      {children}
      {hint ? <span className="hint-line">{hint}</span> : null}
    </label>
  );
}

export function CheckField({
  label,
  checked,
  onChange,
}: {
  label: ReactNode;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="check">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <span>{label}</span>
    </label>
  );
}

/* ------------------------------------------------------------------- layers */

function useDismiss(open: boolean, onClose: () => void, rootRef: React.RefObject<HTMLElement | null>) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      }
      if (event.key !== "Tab" || !rootRef.current) return;
      const focusable = rootRef.current.querySelectorAll<HTMLElement>(
        'button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])',
      );
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    const previousOverflow = document.body.style.overflow;
    const previousActive = document.activeElement as HTMLElement | null;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKey);
    const timer = window.setTimeout(() => {
      const target = rootRef.current?.querySelector<HTMLElement>(
        "button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled)",
      );
      target?.focus();
    }, 0);
    return () => {
      window.clearTimeout(timer);
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKey);
      previousActive?.focus?.();
    };
  }, [open, onClose, rootRef]);
}

export function Drawer({
  open,
  title,
  subtitle,
  onClose,
  children,
  footer,
  wide = false,
}: {
  open: boolean;
  title: ReactNode;
  subtitle?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useDismiss(open, onClose, ref);
  if (!open) return null;
  return createPortal(
    <div className="layer">
      <button type="button" className="scrim" aria-label="Close panel" onClick={onClose} />
      <aside
        ref={ref}
        className={classNames("drawer", wide && "wide")}
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === "string" ? title : "Details"}
      >
        <header className="drawer-head">
          <div>
            <h2 className="drawer-title">{title}</h2>
            {subtitle ? <p className="drawer-sub">{subtitle}</p> : null}
          </div>
          <Button className="drawer-close" onClick={onClose} aria-label="Close panel">
            Close
          </Button>
        </header>
        <div className="drawer-body">{children}</div>
        {footer ? <footer className="drawer-foot">{footer}</footer> : null}
      </aside>
    </div>,
    document.body,
  );
}

export function Dialog({
  open,
  title,
  subtitle,
  onClose,
  children,
  footer,
}: {
  open: boolean;
  title: ReactNode;
  subtitle?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useDismiss(open, onClose, ref);
  if (!open) return null;
  return createPortal(
    <div className="layer center modal-layer">
      <button type="button" className="scrim" aria-label="Close dialog" onClick={onClose} />
      <div
        ref={ref}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === "string" ? title : "Dialog"}
      >
        <header className="modal-head">
          <div>
            <h2 className="drawer-title">{title}</h2>
            {subtitle ? <p className="drawer-sub">{subtitle}</p> : null}
          </div>
          <Button className="drawer-close" onClick={onClose} aria-label="Close dialog">
            Close
          </Button>
        </header>
        <div className="modal-body">{children}</div>
        {footer ? <footer className="modal-foot">{footer}</footer> : null}
      </div>
    </div>,
    document.body,
  );
}

/* ------------------------------------------------------------------- status */

export function Banner({
  children,
  onDismiss,
}: {
  children: ReactNode;
  onDismiss?: () => void;
}) {
  return (
    <div className="banner" role="alert">
      <span className="banner-text">{children}</span>
      {onDismiss ? (
        <TableButton type="button" onClick={onDismiss}>
          Dismiss
        </TableButton>
      ) : null}
    </div>
  );
}

export function Toast({
  message,
  error = false,
  onClose,
}: {
  message: string;
  error?: boolean;
  onClose: () => void;
}) {
  useEffect(() => {
    const timer = window.setTimeout(onClose, 4500);
    return () => window.clearTimeout(timer);
  }, [onClose]);
  return (
    <div className={classNames("toast", error && "err")} role="status">
      <span>{message}</span>
      <LinkButton onClick={onClose}>Dismiss</LinkButton>
    </div>
  );
}

/* ------------------------------------------------------------------ details */

export function KeyValue({ rows, className = "" }: { rows: Array<[string, ReactNode]>; className?: string }) {
  return (
    <dl className={classNames("kv", className)}>
      {rows.map(([key, value]) => (
        <div key={key}>
          <dt>{key}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function DetailBlock({ title, children }: { title: ReactNode; children: ReactNode }) {
  return (
    <div>
      <h3 className="detail-title">{title}</h3>
      {children}
    </div>
  );
}

export function RawJSON({ value }: { value: unknown }) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return <pre className="json">{text}</pre>;
}

export function CodeBlock({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <pre className={classNames("code", className)}>{children}</pre>;
}

export function CopyButton({ value, label = "Copy JSON" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <TableButton
      type="button"
      onClick={() => {
        if (!navigator.clipboard) {
          setCopied(false);
          return;
        }
        void navigator.clipboard
          .writeText(value)
          .then(() => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1600);
          })
          .catch(() => setCopied(false));
      }}
    >
      {copied ? "Copied" : label}
    </TableButton>
  );
}

export function Meter({ value, total }: { value: number; total: number }) {
  const pct = total > 0 ? Math.max(0, Math.min(100, (value / total) * 100)) : 0;
  return (
    <div className="meter" role="img" aria-label={`${value} of ${total}`}>
      <span style={{ width: `${pct}%` }} />
    </div>
  );
}

/* ---------------------------------------------------------------- skeleton */

export function Skeleton({
  width = "100%",
  height = 14,
  className = "",
}: {
  width?: string | number;
  height?: string | number;
  className?: string;
}) {
  return <span className={`sk ${className}`.trim()} style={{ width, height }} aria-hidden="true" />;
}

export function SkeletonDashboard() {
  return (
    <div aria-label="Loading fleet data" className="skeleton-dashboard">
      <div className="band">
        {Array.from({ length: 4 }).map((_, index) => (
          <div className="measure" key={index}>
            <div className="sk-value" />
            <Skeleton width={88} height={12} />
            <div style={{ marginTop: 6 }}>
              <Skeleton width={132} height={12} />
            </div>
          </div>
        ))}
      </div>
      <div className="grid12 body-grid">
        <div className="col-8 stack">
          {Array.from({ length: 2 }).map((_, index) => (
            <div className="sk-table" key={index}>
              <Skeleton width={160} height={14} />
              <div style={{ marginTop: 10 }}>
                {Array.from({ length: 5 }).map((_, row) => (
                  <div className="sk-line" key={row} />
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="col-4 stack">
          {Array.from({ length: 3 }).map((_, index) => (
            <div className="sk-table" key={index}>
              <Skeleton width={120} height={14} />
              <div style={{ marginTop: 10 }}>
                {Array.from({ length: 3 }).map((_, row) => (
                  <div className="sk-line" key={row} />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- helpers */

export function severityClass(severity: string): string {
  switch (severity) {
    case "critical":
      return "sev-critical";
    case "high":
      return "sev-high";
    case "medium":
      return "sev-medium";
    case "low":
    case "info":
      return "sev-low";
    default:
      return "muted";
  }
}

export function stateClass(status: string): string {
  switch (status) {
    case "applied":
    case "promoted":
    case "ready":
    case "online":
    case "ok":
    case "accepted":
      return "";
    case "staged":
    case "committed":
    case "pending":
    case "rolling_out":
      return "state-strong";
    case "rejected":
    case "rolled_back":
    case "failed":
    case "offline":
    case "blocked":
      return "state-off";
    default:
      return "muted";
  }
}
