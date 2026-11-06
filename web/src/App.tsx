import { useCallback, useEffect, useState } from "react";
import { api, ApiError, authEnabled } from "./api";
import {
  initAuth,
  login,
  logout,
  roleAtLeast,
  roleLabel,
  type AuthIdentity,
} from "./auth";
import type {
  Agent,
  Alert,
  AnalyticsSummary,
  AuditRow,
  Event,
  HealthSnapshot,
  Meta,
  Policy,
  Role,
  Rollout,
} from "./types";
import { formatCompact, isOnline, relativeToMs } from "./lib/format";
import { AgentsView } from "./components/AgentsView";
import { AlertsView } from "./components/AlertsView";
import { AuditView } from "./components/AuditView";
import { EventsView } from "./components/EventsView";
import { Overview, type Range } from "./components/Overview";
import { PoliciesView } from "./components/PoliciesView";
import { AgentDrawer, AlertDrawer, EventDrawer } from "./components/Details";
import {
  Badge,
  Button,
  Card,
  Icon,
  Skeleton,
  SkeletonTable,
  Spinner,
  Toast,
  type IconName,
} from "./components/ui";
import "./styles.css";

type Tab = "overview" | "events" | "alerts" | "agents" | "policies" | "audit";

interface Session {
  status: "loading" | "signed-out" | "ready";
  identity: AuthIdentity | null;
}

const devIdentity: AuthIdentity = {
  name: "Development",
  groups: ["dev"],
  role: "admin",
};

const pageMeta: Record<Tab, { label: string; title: string; subtitle: string }> = {
  overview: {
    label: "Overview",
    title: "Fleet overview",
    subtitle: "Signals, health, and recent activity across the cluster.",
  },
  events: {
    label: "Events",
    title: "Event explorer",
    subtitle: "Process, file, and kernel activity delivered by the agents.",
  },
  alerts: {
    label: "Alerts",
    title: "Alerts",
    subtitle: "Rule matches that need a human decision.",
  },
  agents: {
    label: "Agents",
    title: "Agents",
    subtitle: "Node identities, sensor coverage, and heartbeats.",
  },
  policies: {
    label: "Policies",
    title: "Policies",
    subtitle: "Stage, validate, commit, and roll out rule packs.",
  },
  audit: {
    label: "Audit",
    title: "Audit trail",
    subtitle: "Administrative actions recorded by the control plane.",
  },
};

const navIcons: Record<Tab, IconName> = {
  overview: "overview",
  events: "activity",
  alerts: "bell",
  agents: "server",
  policies: "shield",
  audit: "list",
};

function errorMessage(reason: unknown): string {
  if (reason instanceof ApiError) {
    try {
      const body = JSON.parse(reason.body) as { error?: string };
      if (body.error) return body.error;
    } catch {
      // Fall through to the generic message.
    }
    return reason.message;
  }
  return reason instanceof Error ? reason.message : String(reason);
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  return (parts[0][0] + (parts[1]?.[0] ?? "")).toUpperCase();
}

function SignInScreen({ onLogin, error }: { onLogin: () => void; error?: string | null }) {
  return (
    <div className="auth-shell">
      <div className="auth-brand">
        <span className="brand-mark">
          <Icon name="layers" size={22} />
        </span>
        <div>
          <span className="eyebrow">CONTROL PLANE</span>
          <h1>eBPF fleet</h1>
        </div>
      </div>
      <div className="auth-card">
        <span className="auth-kicker">
          <Icon name="shield" size={16} /> Identity required
        </span>
        <h2>Sign in to the fleet</h2>
        <p>
          This dashboard uses your OIDC identity to decide whether you can read events, validate
          policies, change rule packs, or view the audit trail.
        </p>
        {error ? <div className="auth-error">{error}</div> : null}
        <Button variant="primary" icon="signout" onClick={onLogin}>
          Sign in
        </Button>
        <p className="auth-foot">
          Your group must be one of the fleet viewer, analyst, policy admin, or admin groups.
        </p>
      </div>
      <p className="auth-version">eBPF fleet · control plane dashboard</p>
    </div>
  );
}

function NoRoleScreen({ onSignOut, name }: { onSignOut: () => void; name: string }) {
  return (
    <div className="auth-shell">
      <div className="auth-brand">
        <span className="brand-mark">
          <Icon name="layers" size={22} />
        </span>
        <div>
          <span className="eyebrow">CONTROL PLANE</span>
          <h1>eBPF fleet</h1>
        </div>
      </div>
      <div className="auth-card">
        <span className="auth-kicker">
          <Icon name="lock" size={16} /> Signed in
        </span>
        <h2>No fleet role</h2>
        <p>
          {name} authenticated successfully, but the token carries no recognized fleet group.
          Ask an administrator to add one of the fleet viewer, analyst, policy admin, or admin
          groups.
        </p>
        <Button variant="secondary" icon="signout" onClick={onSignOut}>
          Sign out
        </Button>
      </div>
    </div>
  );
}

function BootScreen() {
  return (
    <div className="auth-shell">
      <div className="auth-brand">
        <span className="brand-mark">
          <Icon name="layers" size={22} />
        </span>
        <div>
          <span className="eyebrow">CONTROL PLANE</span>
          <h1>eBPF fleet</h1>
        </div>
      </div>
      <Spinner label="Checking identity…" />
    </div>
  );
}

function DashboardSkeleton() {
  return (
    <div className="view">
      <div className="kpi-grid">
        {Array.from({ length: 4 }).map((_, index) => (
          <div className="stat-card stat-loading" key={index}>
            <Skeleton width={38} height={38} />
            <Skeleton width="55%" height={12} />
            <Skeleton width="42%" height={28} />
            <Skeleton width="65%" height={11} />
          </div>
        ))}
      </div>
      <Card>
        <div className="skeleton-head">
          <Skeleton width={180} height={18} />
          <Skeleton width="100%" height={12} />
          <Skeleton width="72%" height={12} />
        </div>
        <SkeletonTable />
      </Card>
    </div>
  );
}

export default function App() {
  const [session, setSession] = useState<Session>({
    status: authEnabled ? "loading" : "ready",
    identity: authEnabled ? null : devIdentity,
  });
  const [tab, setTab] = useState<Tab>("overview");
  const [range, setRange] = useState<Range>("24");
  const [autoRefresh, setAutoRefresh] = useState(15);
  const [refresh, setRefresh] = useState(0);
  const [events, setEvents] = useState<Event[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [rollouts, setRollouts] = useState<Rollout[]>([]);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [analytics, setAnalytics] = useState<AnalyticsSummary | null>(null);
  const [analyticsError, setAnalyticsError] = useState<string | null>(null);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [health, setHealth] = useState<HealthSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; tone?: string } | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);

  const showToast = useCallback((message: string, tone?: string) => {
    setToast({ message, tone });
  }, []);

  const handleSessionExpired = useCallback(() => {
    if (!authEnabled) return;
    setSession({ status: "signed-out", identity: null });
    setError("Your session expired. Sign in again to continue.");
    setSelectedEvent(null);
    setSelectedAlert(null);
    setSelectedAgent(null);
  }, []);

  const handleError = useCallback((message: string) => {
    setError(message);
  }, []);

  const refreshNow = useCallback(() => {
    setRefresh((value) => value + 1);
  }, []);

  const clearToast = useCallback(() => setToast(null), []);

  useEffect(() => {
    if (!authEnabled) {
      setSession({ status: "ready", identity: devIdentity });
      return;
    }
    let cancelled = false;
    initAuth()
      .then((identity) => {
        if (cancelled) return;
        setSession(
          identity
            ? { status: "ready", identity }
            : { status: "signed-out", identity: null },
        );
      })
      .catch((reason) => {
        if (cancelled) return;
        setError(errorMessage(reason));
        setSession({ status: "signed-out", identity: null });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const role = session.identity?.role ?? null;
  const canAudit = roleAtLeast(role, "admin");
  const canManagePolicies = roleAtLeast(role, "policy-admin");
  const onlineAgents = agents.filter((agent) => isOnline(agent.last_seen_epoch)).length;

  useEffect(() => {
    if (tab === "audit" && !canAudit) {
      setTab("overview");
    }
  }, [canAudit, tab]);

  useEffect(() => {
    if (session.status !== "ready" || !session.identity || autoRefresh <= 0) {
      return;
    }
    const timer = window.setInterval(() => {
      setRefresh((value) => value + 1);
    }, autoRefresh * 1000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, session.identity, session.status]);

  useEffect(() => {
    if (session.status !== "ready" || !session.identity) {
      return;
    }
    if (session.identity.role === null) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    if (lastUpdated === null) {
      setLoading(true);
    } else {
      setRefreshing(true);
    }
    const run = async () => {
      try {
        const [eventPage, alertPage, agentPage, policyPage, rolloutPage] =
          await Promise.all([
            api.events(250),
            api.alerts(),
            api.agents(),
            api.policies(),
            api.rollouts(),
          ]);
        if (cancelled) return;
        setEvents(eventPage.events);
        setAlerts(alertPage.alerts);
        setAgents(agentPage.agents);
        setPolicies(policyPage.policies);
        setRollouts(rolloutPage.rollouts);

        const [metaResult, healthResult] = await Promise.allSettled([
          api.meta(),
          api.health(),
        ]);
        if (cancelled) return;
        if (metaResult.status === "fulfilled") {
          setMeta(metaResult.value);
        } else if (metaResult.reason instanceof ApiError && metaResult.reason.status === 401) {
          handleSessionExpired();
          return;
        }
        if (healthResult.status === "fulfilled") {
          setHealth(healthResult.value);
        }

        if (tab === "audit" && canAudit) {
          const auditPage = await api.audit();
          if (!cancelled) setAudit(auditPage.audit);
        }

        if (tab === "overview") {
          try {
            const summary = await api.analytics(Number(range));
            if (!cancelled) {
              setAnalytics(summary);
              setAnalyticsError(null);
            }
          } catch (analyticsFailure) {
            if (cancelled) return;
            if (analyticsFailure instanceof ApiError && analyticsFailure.status === 401) {
              handleSessionExpired();
              return;
            }
            setAnalytics(null);
            setAnalyticsError(errorMessage(analyticsFailure));
          }
        }

        if (!cancelled) {
          setLastUpdated(Date.now());
          setError(null);
        }
      } catch (reason) {
        if (cancelled) return;
        if (reason instanceof ApiError && reason.status === 401) {
          handleSessionExpired();
          return;
        }
        setError(errorMessage(reason));
      } finally {
        if (!cancelled) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
    // The load is intentionally keyed by the visible surface and the manual
    // refresh counter; the derived role and update handlers are stable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refresh, tab, range, session.status, session.identity, canAudit, handleSessionExpired]);

  const handleLogin = useCallback(() => {
    login().catch((reason) => setError(errorMessage(reason)));
  }, []);

  const handleLogout = useCallback(() => {
    setSession({ status: "signed-out", identity: null });
    void logout();
  }, []);

  if (session.status === "loading") {
    return <BootScreen />;
  }
  if (session.status === "signed-out") {
    return <SignInScreen onLogin={handleLogin} error={error} />;
  }
  if (!session.identity) {
    return <BootScreen />;
  }
  if (session.identity.role === null) {
    return <NoRoleScreen name={session.identity.name} onSignOut={handleLogout} />;
  }

  const identity = session.identity;
  const cluster = meta?.cluster_name ?? "fleet";
  const activeTab = tab;
  const current = pageMeta[activeTab];
  const tabs: Tab[] = ["overview", "events", "alerts", "agents", "policies"];
  if (canAudit) tabs.push("audit");

  const navCount = (item: Tab): string | null => {
    if (item === "events") return events.length ? formatCompact(events.length) : null;
    if (item === "alerts") return alerts.length ? formatCompact(alerts.length) : null;
    if (item === "agents") return `${onlineAgents}/${agents.length}`;
    if (item === "policies") return policies.length ? String(policies.length) : null;
    return null;
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">
            <Icon name="layers" size={22} />
          </span>
          <div className="brand-copy">
            <span className="eyebrow">CONTROL PLANE</span>
            <h1>eBPF fleet</h1>
          </div>
        </div>

        <div className="cluster-pill" title={meta?.version ? `v${meta.version}` : undefined}>
          <span className={`status-dot ${health?.api ? "dot-emerald" : "dot-amber"}`} />
          <span>{cluster}</span>
          {meta?.analytics ? <span className="cluster-tag">analytics</span> : null}
        </div>

        <nav className="side-nav" aria-label="Primary">
          {tabs.map((item) => (
            <button
              type="button"
              key={item}
              className={`nav-item ${activeTab === item ? "active" : ""}`}
              onClick={() => setTab(item)}
              aria-current={activeTab === item ? "page" : undefined}
            >
              <Icon name={navIcons[item]} size={18} />
              <span>{pageMeta[item].label}</span>
              {navCount(item) ? <span className="nav-count">{navCount(item)}</span> : null}
            </button>
          ))}
        </nav>

        <div className="sidebar-foot">
          <div className="sidebar-section-label">System</div>
          <div className="system-row">
            <span className={`status-dot ${health?.api ? "dot-emerald" : "dot-rose"}`} />
            <span>API</span>
            <span className="system-value">{health?.api ? "up" : "down"}</span>
          </div>
          <div className="system-row">
            <span className={`status-dot ${health?.database ? "dot-emerald" : "dot-rose"}`} />
            <span>Database</span>
            <span className="system-value">{health?.database ? "ready" : "not ready"}</span>
          </div>
          <div className="sidebar-section-label refresh-label">Refresh</div>
          <label className="refresh-select">
            <span>Auto</span>
            <select
              value={autoRefresh}
              onChange={(event) => setAutoRefresh(Number(event.target.value))}
              aria-label="Auto refresh interval"
            >
              <option value={0}>Off</option>
              <option value={10}>10s</option>
              <option value={15}>15s</option>
              <option value={30}>30s</option>
              <option value={60}>60s</option>
            </select>
          </label>
          <div className="last-updated">
            {lastUpdated ? `Updated ${relativeToMs(lastUpdated)}` : "Waiting for data"}
          </div>
          {meta ? <div className="sidebar-version">control plane v{meta.version}</div> : null}
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="page-heading">
            <span className="eyebrow">FLEET / {current.label.toUpperCase()}</span>
            <h2>{current.title}</h2>
            <p>{current.subtitle}</p>
          </div>
          <div className="topbar-actions">
            <div className="updated-chip" title={lastUpdated ? new Date(lastUpdated).toLocaleString() : undefined}>
              <span className={`status-dot ${refreshing ? "dot-amber" : "dot-emerald"}`} />
              {refreshing ? "Refreshing" : lastUpdated ? `Updated ${relativeToMs(lastUpdated)}` : "Waiting"}
            </div>
            <Button
              variant="secondary"
              size="sm"
              icon="refresh"
              loading={refreshing}
              onClick={refreshNow}
              title="Refresh now"
            >
              Refresh
            </Button>
            <div className="user-chip">
              <span className="avatar">{initials(identity.name)}</span>
              <span className="user-copy">
                <strong>{identity.name}</strong>
                <span>
                  {roleLabel(identity.role)}
                  {identity.email ? ` · ${identity.email}` : ""}
                </span>
              </span>
              {authEnabled ? (
                <Button variant="ghost" size="sm" icon="signout" onClick={handleLogout}>
                  Sign out
                </Button>
              ) : (
                <Badge tone="slate">dev auth</Badge>
              )}
            </div>
          </div>
        </header>

        <div className="content">
          {error ? (
            <div className="error-banner" role="alert">
              <Icon name="alert" size={17} />
              <span>{error}</span>
              <button type="button" className="icon-btn" onClick={() => setError(null)} aria-label="Dismiss error">
                <Icon name="close" size={15} />
              </button>
            </div>
          ) : null}

          {loading ? (
            <DashboardSkeleton />
          ) : (
            <>
              {activeTab === "overview" ? (
                <Overview
                  agents={agents}
                  events={events}
                  alerts={alerts}
                  policies={policies}
                  rollouts={rollouts}
                  analytics={analytics}
                  analyticsError={analyticsError}
                  health={health}
                  range={range}
                  onRange={setRange}
                  onNavigate={(destination) => setTab(destination)}
                  onEvent={setSelectedEvent}
                  onAlert={setSelectedAlert}
                  onAgent={setSelectedAgent}
                />
              ) : null}
              {activeTab === "events" ? <EventsView events={events} onEvent={setSelectedEvent} /> : null}
              {activeTab === "alerts" ? <AlertsView alerts={alerts} onAlert={setSelectedAlert} /> : null}
              {activeTab === "agents" ? <AgentsView agents={agents} onAgent={setSelectedAgent} /> : null}
              {activeTab === "policies" ? (
                <PoliciesView
                  policies={policies}
                  rollouts={rollouts}
                  agents={agents}
                  role={role}
                  onRefresh={refreshNow}
                  onToast={showToast}
                  onError={handleError}
                  onSessionExpired={handleSessionExpired}
                />
              ) : null}
              {activeTab === "audit" ? <AuditView audit={audit} role={role} /> : null}
            </>
          )}
        </div>
      </main>

      <EventDrawer event={selectedEvent} alerts={alerts} onClose={() => setSelectedEvent(null)} />
      <AlertDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onOpenEvent={(eventId) => {
          const event = events.find((candidate) => candidate.event_id === eventId);
          if (event) {
            setSelectedAlert(null);
            setSelectedEvent(event);
          }
        }}
      />
      <AgentDrawer agent={selectedAgent} onClose={() => setSelectedAgent(null)} />
      {toast ? (
        <Toast message={toast.message} tone={toast.tone} onClose={clearToast} />
      ) : null}
    </div>
  );
}
