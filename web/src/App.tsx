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
import { relativeToMs } from "./lib/format";
import { AgentsView } from "./components/AgentsView";
import { AlertsView } from "./components/AlertsView";
import { AuditView } from "./components/AuditView";
import { EventsView } from "./components/EventsView";
import { Overview, type Range } from "./components/Overview";
import { PoliciesView } from "./components/PoliciesView";
import { AgentDrawer, AlertDrawer, EventDrawer } from "./components/Details";
import {
  Banner,
  Button,
  LinkButton,
  SkeletonDashboard,
  Toast,
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

const pageMeta: Record<Tab, { label: string; title: string }> = {
  overview: { label: "Overview", title: "Fleet overview" },
  events: { label: "Events", title: "Event register" },
  alerts: { label: "Alerts", title: "Alerts" },
  agents: { label: "Agents", title: "Agents" },
  policies: { label: "Policies", title: "Policies" },
  audit: { label: "Audit", title: "Audit trail" },
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

function Masthead({
  cluster,
  version,
  health,
  lastUpdated,
  refreshing,
  autoRefresh,
  onAutoRefresh,
  onRefresh,
  identity,
  onSignOut,
}: {
  cluster: string;
  version?: string;
  health: HealthSnapshot | null;
  lastUpdated: number | null;
  refreshing: boolean;
  autoRefresh: number;
  onAutoRefresh: (value: number) => void;
  onRefresh: () => void;
  identity: AuthIdentity;
  onSignOut: () => void;
}) {
  return (
    <header className="masthead">
      <div className="wrap masthead-in">
        <div className="brand">
          <span className="wordmark">eBPF fleet</span>
          <span className="cluster" title={version ? `control plane v${version}` : undefined}>
            {cluster}
          </span>
        </div>
        <div className="masthead-meta">
          <span className="health">
            <span className={health?.api ? "h" : "h down"}>
              API <b>{health?.api ? "up" : "down"}</b>
            </span>
            <span className={health?.database ? "h" : "h down"}>
              database <b>{health?.database ? "ready" : "not ready"}</b>
            </span>
          </span>
          <span className="updated">
            {lastUpdated ? `updated ${relativeToMs(lastUpdated)}` : "waiting for data"}
          </span>
          <button
            type="button"
            className="mast-btn"
            onClick={onRefresh}
            aria-busy={refreshing}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing" : "Refresh"}
          </button>
          <label className="auto">
            auto
            <select
              value={autoRefresh}
              onChange={(event) => onAutoRefresh(Number(event.target.value))}
              aria-label="Auto refresh interval"
            >
              <option value={0}>off</option>
              <option value={10}>10s</option>
              <option value={15}>15s</option>
              <option value={30}>30s</option>
              <option value={60}>60s</option>
            </select>
          </label>
          <span className="identity">
            <b>{identity.name}</b>
            <span className="role">{roleLabel(identity.role)}</span>
            {authEnabled ? (
              <LinkButton onClick={onSignOut} style={{ color: "#fff", minHeight: 44 }}>
                Sign out
              </LinkButton>
            ) : (
              <span className="dev">dev auth</span>
            )}
          </span>
        </div>
      </div>
    </header>
  );
}

function AuthFrame({ children }: { children: React.ReactNode }) {
  return (
    <div className="auth">
      <header className="masthead">
        <div className="wrap masthead-in">
          <div className="brand">
            <span className="wordmark">eBPF fleet</span>
            <span className="cluster">control plane</span>
          </div>
        </div>
      </header>
      <main className="auth-main">
        <div className="wrap">{children}</div>
      </main>
      <div className="wrap auth-version">
        <span>eBPF fleet control plane</span>
        <span>Linux kernel activity recorder and policy rollout</span>
      </div>
    </div>
  );
}

function SignInScreen({ onLogin, error }: { onLogin: () => void; error?: string | null }) {
  return (
    <AuthFrame>
      <div className="signed">
        <h1 className="signed-title">Sign in to the fleet</h1>
        <p>
          Your OIDC identity decides what this console shows: events, alerts, the node fleet, and the
          policy pack you can stage or roll out.
        </p>
        {error ? <p className="status-line err">{error}</p> : null}
        <Button variant="primary" onClick={onLogin}>
          Sign in
        </Button>
      </div>
    </AuthFrame>
  );
}

function NoRoleScreen({ onSignOut, name }: { onSignOut: () => void; name: string }) {
  return (
    <AuthFrame>
      <div className="signed">
        <h1 className="signed-title">No fleet role</h1>
        <p>
          {name} authenticated, but the token carries no fleet group. An administrator needs to add one
          of the viewer, analyst, policy admin, or admin groups.
        </p>
        <Button onClick={onSignOut}>Sign out</Button>
      </div>
    </AuthFrame>
  );
}

function BootScreen() {
  return (
    <AuthFrame>
      <div className="boot">
        <p className="boot-word">Checking identity</p>
        <p className="boot-note">Reading the OIDC session and fleet role.</p>
      </div>
    </AuthFrame>
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
          identity ? { status: "ready", identity } : { status: "signed-out", identity: null },
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
        const [eventPage, alertPage, agentPage, policyPage, rolloutPage] = await Promise.all([
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

        const [metaResult, healthResult] = await Promise.allSettled([api.meta(), api.health()]);
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
    // The load is keyed by the visible surface, the analytics window and the
    // manual refresh counter; the derived role and update handlers are stable.
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
  const current = pageMeta[tab];
  const tabs: Tab[] = ["overview", "events", "alerts", "agents", "policies"];
  if (canAudit) tabs.push("audit");

  return (
    <>
      <a className="skip" href="#main">
        Skip to content
      </a>
      <Masthead
        cluster={cluster}
        version={meta?.version}
        health={health}
        lastUpdated={lastUpdated}
        refreshing={refreshing}
        autoRefresh={autoRefresh}
        onAutoRefresh={setAutoRefresh}
        onRefresh={refreshNow}
        identity={identity}
        onSignOut={handleLogout}
      />
      <nav className="navrow" aria-label="Primary">
        <div className="wrap">
          <div className="nav">
            {tabs.map((item) => (
              <button
                type="button"
                key={item}
                onClick={() => setTab(item)}
                aria-current={tab === item ? "page" : undefined}
              >
                {pageMeta[item].label}
              </button>
            ))}
          </div>
        </div>
      </nav>
      <main id="main">
        <div className="wrap">
          <h1 className="sr-only">{current.title}</h1>
          {error ? (
            <Banner onDismiss={() => setError(null)}>{error}</Banner>
          ) : null}
          {loading ? (
            <SkeletonDashboard />
          ) : (
            <>
              {tab === "overview" ? (
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
              {tab === "events" ? <EventsView events={events} onEvent={setSelectedEvent} /> : null}
              {tab === "alerts" ? <AlertsView alerts={alerts} onAlert={setSelectedAlert} /> : null}
              {tab === "agents" ? <AgentsView agents={agents} onAgent={setSelectedAgent} /> : null}
              {tab === "policies" ? (
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
              {tab === "audit" ? <AuditView audit={audit} role={role} /> : null}
            </>
          )}
        </div>
      </main>
      <footer className="foot">
        <div className="wrap foot-in">
          <span>
            {lastUpdated ? `snapshot ${new Date(lastUpdated).toLocaleString()}` : "no snapshot yet"}
            {autoRefresh > 0 ? `, poll ${autoRefresh}s` : ", auto refresh off"}
          </span>
          <span>
            {meta ? (
              <>
                control plane <b>v{meta.version}</b>
                {meta.analytics ? " with analytics" : " without analytics"}
              </>
            ) : (
              "control plane version unknown"
            )}
          </span>
        </div>
      </footer>

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
        <Toast
          message={toast.message}
          error={toast.tone === "rose"}
          onClose={clearToast}
        />
      ) : null}
    </>
  );
}
