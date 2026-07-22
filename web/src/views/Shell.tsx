// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Console shell: nav rail + status topbar + content region. Landmarks
// and skip link per DESIGN.md §9; nav items filter by resolved role.
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useNow } from "../api/query";
import { useAuth } from "../auth/AuthProvider";
import { ROLE_LABELS, type Role, roleAtLeast } from "../auth/roles";
import { cx } from "../lib/format";

interface NavItem {
  to: string;
  label: string;
  min: Role;
  icon: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const NAV: NavSection[] = [
  {
    title: "Telemetry",
    items: [
      {
        to: "/",
        label: "Overview",
        min: "viewer",
        icon: "M3 13h4v8H3v-8zm7-10h4v18h-4V3zm7 6h4v12h-4V9z",
      },
      {
        to: "/events",
        label: "Events",
        min: "viewer",
        icon: "M4 5h16v2H4V5zm0 6h16v2H4v-2zm0 6h10v2H4v-2z",
      },
      {
        to: "/alerts",
        label: "Alerts",
        min: "viewer",
        icon: "M12 2 1 21h22L12 2zm-1 8h2v5h-2v-5zm0 6h2v2h-2v-2z",
      },
    ],
  },
  {
    title: "Detection",
    items: [
      {
        to: "/rules",
        label: "Rules",
        min: "viewer",
        icon: "M10 2a8 8 0 1 0 4.9 14.3l5.4 5.4 1.4-1.4-5.4-5.4A8 8 0 0 0 10 2zm0 2a6 6 0 1 1 0 12 6 6 0 0 1 0-12z",
      },
    ],
  },
  {
    title: "Fleet",
    items: [
      {
        to: "/policies",
        label: "Policies",
        min: "viewer",
        icon: "M12 2 3 6v6c0 5 3.8 8.6 9 10 5.2-1.4 9-5 9-10V6l-9-4zm0 2.2 7 3.1V12c0 3.9-2.9 6.9-7 8-4.1-1.1-7-4.1-7-8V7.3l7-3.1z",
      },
      {
        to: "/agents",
        label: "Agents",
        min: "viewer",
        icon: "M4 4h16v10H4V4zm2 2v6h12V6H6zm-2 12h16v2H4v-2z",
      },
    ],
  },
];

const VIEW_NAMES: Record<string, string> = {
  "/": "Overview",
  "/events": "Event stream",
  "/alerts": "Alert feed",
  "/rules": "Detection rules",
  "/policies": "Policy lifecycle",
  "/agents": "Agent inventory",
};

function NavIcon({ d }: { d: string }) {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" focusable="false">
      <path d={d} fill="currentColor" />
    </svg>
  );
}

function UtcClock() {
  const tick = useNow(1000);
  const iso = new Date(tick * 1000).toISOString();
  return (
    <span className="chip" role="timer" aria-label="Coordinated universal time">
      {iso.slice(11, 19)} UTC
    </span>
  );
}

export function Shell() {
  const { session, logout } = useAuth();
  const location = useLocation();
  const viewName = VIEW_NAMES[location.pathname] ?? "Console";

  return (
    <div className="shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>

      <nav className="rail" aria-label="Primary">
        <div className="rail-brand">
          <svg viewBox="0 0 32 32" width="30" height="30" aria-hidden="true" focusable="false">
            <path
              d="M16 4l10.4 6v12L16 28 5.6 22V10L16 4z"
              fill="none"
              stroke="currentColor"
              strokeOpacity="0.35"
              strokeWidth="1.5"
            />
            <path
              d="M16 8.5l6.5 3.75v7.5L16 23.5l-6.5-3.75v-7.5L16 8.5z"
              fill="none"
              stroke="var(--accent-live)"
              strokeWidth="1.5"
            />
            <circle cx="16" cy="16" r="2.4" fill="var(--accent-info)" />
          </svg>
          <div>
            <div className="rail-brand-name">KERNEL-V1</div>
            <div className="rail-brand-sub">Sentinel Console</div>
          </div>
        </div>

        {NAV.map((section) => {
          const visible = section.items.filter(
            (item) => session !== null && roleAtLeast(session.role, item.min),
          );
          if (visible.length === 0) return null;
          return (
            <div key={section.title}>
              <p className="rail-section">{section.title}</p>
              {visible.map((item) => (
                <NavLink key={item.to} to={item.to} end={item.to === "/"} className="rail-link">
                  <NavIcon d={item.icon} />
                  {item.label}
                </NavLink>
              ))}
            </div>
          );
        })}

        <div className="rail-foot">
          {session !== null && (
            <>
              <div className="session-id" title={session.subject}>
                <span className="stat-label">Signed in</span>
                <span className="session-name">{session.email ?? session.subject}</span>
                <span className={cx("badge", "badge--low")}>{ROLE_LABELS[session.role]}</span>
              </div>
              {!session.devMode && (
                <button type="button" className="btn btn--ghost btn--sm" onClick={logout}>
                  Sign out
                </button>
              )}
            </>
          )}
        </div>
      </nav>

      <header className="topbar">
        <p className="topbar-crumb">
          console / <strong>{viewName}</strong>
        </p>
        <div className="topbar-spacer" />
        {session?.devMode === true && (
          <span
            className="chip chip--dev"
            title="Loopback dev bypass: auth skipped, admin role assigned"
          >
            DEV BYPASS
          </span>
        )}
        <UtcClock />
      </header>

      <main className="main" id="main-content">
        <Outlet />
      </main>
    </div>
  );
}
