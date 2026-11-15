import { useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import defaultPolicy from "../../../rules/default/sensitive-files.yaml?raw";
import type { Ack, Agent, Policy, Role, Rollout } from "../types";
import { api, ApiError } from "../api";
import { roleAtLeast } from "../auth";
import { formatTimestamp, shortId } from "../lib/format";
import {
  Button,
  CheckField,
  CopyButton,
  Dialog,
  Drawer,
  EmptyRow,
  Field,
  Measure,
  MeasureBand,
  Section,
  Table,
  TableButton,
  stateClass,
} from "./ui";

/* Policies, as a register: the version ledger, the stored pack, the working
   copy, and the acknowledgements that each rollout produces. */

interface PoliciesProps {
  policies: Policy[];
  rollouts: Rollout[];
  agents: Agent[];
  role: Role | null;
  onRefresh: () => void;
  onToast: (message: string, tone?: string) => void;
  onError: (message: string) => void;
  onSessionExpired: () => void;
}

const ONLINE_WINDOW_SECS = 120;

type StatusTone = "ok" | "err";

/* ------------------------------------------------------------------ helpers */

function errorMessage(reason: unknown): string {
  if (reason instanceof ApiError) {
    try {
      const body = JSON.parse(reason.body) as { error?: string };
      if (body.error) return body.error;
    } catch {
      // The body is not JSON; fall back to the HTTP status message.
    }
    return reason.message;
  }
  return reason instanceof Error ? reason.message : String(reason);
}

function pad2(value: number): string {
  return String(value).padStart(2, "0");
}

function clockOf(epochSeconds: number): string {
  const date = new Date(epochSeconds * 1000);
  return `${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`;
}

function dayLabel(date: Date): string {
  return date.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}

function shortDigest(digest: string): string {
  if (!digest) return "—";
  return digest.startsWith("sha256:") ? `sha256:${digest.slice(7, 19)}` : shortId(digest, 12);
}

function ruleCount(content: string): number {
  return (content.match(/^\s*-\s+id:/gm) ?? []).length;
}

function ruleLabel(count: number): string {
  return `${count} ${count === 1 ? "rule" : "rules"}`;
}

function agentLabel(agents: Agent[], agentId: string): string {
  return agents.find((agent) => agent.id === agentId)?.node_name ?? shortId(agentId, 18);
}

function rolePhrase(role: Role | null): string {
  switch (role) {
    case "admin":
      return "admin";
    case "policy-admin":
      return "policy admin";
    case "analyst":
      return "analyst";
    case "viewer":
      return "viewer";
    default:
      return "read-only";
  }
}

function sortedByVersion(policies: Policy[]): Policy[] {
  return [...policies].sort((left, right) => right.version - left.version);
}

function rolloutNote(rollout: Rollout): string {
  const ratio = `${Math.round(rollout.min_ratio * 100)}%`;
  const timeout =
    rollout.status === "pending"
      ? `timeout in ${Math.max(0, rollout.deadline_epoch - Math.floor(Date.now() / 1000))}s`
      : `timeout ${rollout.timeout_secs}s`;
  return `min ${ratio}, ${timeout}`;
}

/* ------------------------------------------------------------------- acks */

interface AcksState {
  version: number | null;
  acks: Ack[];
  loading: boolean;
  failed: boolean;
}

function useAcks(
  version: number | null,
  onError: (message: string) => void,
  onSessionExpired: () => void,
): AcksState {
  const [state, setState] = useState<AcksState>({
    version: null,
    acks: [],
    loading: false,
    failed: false,
  });

  useEffect(() => {
    if (version === null) return;
    let cancelled = false;
    setState({ version, acks: [], loading: true, failed: false });
    api
      .acks(version)
      .then((page) => {
        if (cancelled) return;
        // The endpoint is scoped by version; keep only rows for the requested
        // version so a broader payload cannot mislabel another rollout's acks.
        setState({
          version,
          acks: page.acks.filter((ack) => ack.policy_version === version),
          loading: false,
          failed: false,
        });
      })
      .catch((reason: unknown) => {
        if (cancelled) return;
        if (reason instanceof ApiError && reason.status === 401) {
          onSessionExpired();
        } else {
          onError(errorMessage(reason));
        }
        setState({ version, acks: [], loading: false, failed: true });
      });
    return () => {
      cancelled = true;
    };
  }, [onError, onSessionExpired, version]);

  if (version === null) {
    return { version: null, acks: [], loading: false, failed: false };
  }
  if (state.version !== version) {
    return { version, acks: [], loading: true, failed: false };
  }
  return state;
}

function AcksTable({
  state,
  agents,
  emptyText,
  label,
}: {
  state: AcksState;
  agents: Agent[];
  emptyText: string;
  label: string;
}) {
  if (state.loading) {
    return <p className="hint-line">Loading acknowledgements.</p>;
  }
  if (state.failed) {
    return <p className="hint-line">Acknowledgements could not be loaded.</p>;
  }
  if (!state.acks.length) {
    return <p className="empty-cell">{emptyText}</p>;
  }
  return (
    <Table className="mini" label={label} minWidth={380}>
      <colgroup>
        <col style={{ width: "26%" }} />
        <col style={{ width: "16%" }} />
        <col style={{ width: "44%" }} />
        <col style={{ width: "14%" }} />
      </colgroup>
      <thead>
        <tr>
          <th>Agent</th>
          <th>Status</th>
          <th>Message</th>
          <th className="n">Updated</th>
        </tr>
      </thead>
      <tbody>
        {state.acks.map((ack) => (
          <tr key={ack.agent_id}>
            <td>{agentLabel(agents, ack.agent_id)}</td>
            <td className="nowrap">
              <span className={stateClass(ack.status)}>{ack.status}</span>
            </td>
            <td>{ack.message || "—"}</td>
            <td className="n nowrap" title={formatTimestamp(ack.updated_at_epoch)}>
              {clockOf(ack.updated_at_epoch)}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function AcksDrawer({
  policy,
  agents,
  onClose,
  onError,
  onSessionExpired,
}: {
  policy: Policy | null;
  agents: Agent[];
  onClose: () => void;
  onError: (message: string) => void;
  onSessionExpired: () => void;
}) {
  const state = useAcks(policy ? policy.version : null, onError, onSessionExpired);
  return (
    <Drawer
      open={Boolean(policy)}
      onClose={onClose}
      title={policy ? `Acknowledgements, ${policy.name} v${policy.version}` : "Acknowledgements"}
      subtitle="Applied means the sensor thread has the engine active."
    >
      <AcksTable
        state={state}
        agents={agents}
        label={policy ? `Acknowledgements for ${policy.name} v${policy.version}` : "Acknowledgements"}
        emptyText={
          policy ? `No acknowledgements for ${policy.name} v${policy.version}.` : "No acknowledgements."
        }
      />
    </Drawer>
  );
}

/* ---------------------------------------------------------------- rollout */

function RolloutDialog({
  policy,
  onlineAgents,
  registeredAgents,
  rollbackTarget,
  onClose,
  onToast,
  onSessionExpired,
  onStarted,
}: {
  policy: Policy | null;
  onlineAgents: number;
  registeredAgents: number;
  rollbackTarget: Policy | null;
  onClose: () => void;
  onToast: (message: string, tone?: string) => void;
  onSessionExpired: () => void;
  onStarted: () => void;
}) {
  const [minRatio, setMinRatio] = useState("0.95");
  const [timeoutSecs, setTimeoutSecs] = useState("600");
  const [force, setForce] = useState(false);
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  useEffect(() => {
    if (policy) {
      setMinRatio("0.95");
      setTimeoutSecs("600");
      setForce(false);
      setFormError(null);
    }
  }, [policy]);

  const start = async () => {
    if (!policy || busy) return;
    const ratio = Number(minRatio);
    const seconds = Number(timeoutSecs);
    if (!Number.isFinite(ratio) || ratio <= 0 || ratio > 1) {
      setFormError("Minimum ratio must be greater than 0 and at most 1.");
      return;
    }
    if (!Number.isInteger(seconds) || seconds < 1 || seconds > 86_400) {
      setFormError("Timeout must be between 1 and 86400 seconds.");
      return;
    }
    setBusy(true);
    setFormError(null);
    try {
      const result = await api.rollout(policy.version, ratio, seconds, force);
      const expected = result.rollout.expected_agents;
      onToast(`Rollout started: ${expected} expected agent${expected === 1 ? "" : "s"}`);
      onStarted();
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) {
        onSessionExpired();
      } else {
        setFormError(errorMessage(reason));
      }
    } finally {
      setBusy(false);
    }
  };

  const denominator = force ? registeredAgents : onlineAgents;

  return (
    <Dialog
      open={Boolean(policy)}
      onClose={onClose}
      title={policy ? `Start rollout, ${policy.name} v${policy.version}` : "Start rollout"}
      subtitle={`${onlineAgents} online of ${registeredAgents} registered`}
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={() => void start()}
            disabled={busy}
            aria-busy={busy}
          >
            {busy ? "Starting" : "Start rollout"}
          </Button>
        </>
      }
    >
      <div className="form-grid">
        <Field label="Minimum ratio" htmlFor="rollout-ratio">
          <input
            id="rollout-ratio"
            type="number"
            min={0.01}
            max={1}
            step={0.01}
            value={minRatio}
            onChange={(event) => setMinRatio(event.target.value)}
          />
        </Field>
        <Field label="Timeout, seconds" htmlFor="rollout-timeout">
          <input
            id="rollout-timeout"
            type="number"
            min={1}
            max={86_400}
            step={1}
            value={timeoutSecs}
            onChange={(event) => setTimeoutSecs(event.target.value)}
          />
        </Field>
      </div>
      <CheckField
        label="Include offline agents in the denominator"
        checked={force}
        onChange={setForce}
      />
      <p className="modal-data">
        Denominator: {denominator} {denominator === 1 ? "agent" : "agents"}.
      </p>
      <p className="hint-line">
        {rollbackTarget
          ? `Rollback target ${rollbackTarget.name} v${rollbackTarget.version}. A rejected acknowledgement or a missed ratio at the deadline rolls back to it.`
          : "Rollback target required, no earlier version exists to fall back to."}
      </p>
      {formError ? (
        <p className="status-line err" role="alert">
          {formError}
        </p>
      ) : null}
    </Dialog>
  );
}

/* ------------------------------------------------------------------- view */

export function PoliciesView({
  policies,
  rollouts,
  agents,
  role,
  onRefresh,
  onToast,
  onError,
  onSessionExpired,
}: PoliciesProps) {
  const canValidate = roleAtLeast(role, "analyst");
  const canManage = roleAtLeast(role, "policy-admin");

  const sorted = useMemo(() => sortedByVersion(policies), [policies]);
  const latest = sorted[0] ?? null;
  const applied = useMemo(
    () => sorted.find((policy) => policy.status === "applied") ?? null,
    [sorted],
  );
  const nextVersion = (latest ? latest.version : 0) + 1;

  const onlineAgents = agents.filter(
    (agent) => Date.now() / 1000 - agent.last_seen_epoch <= ONLINE_WINDOW_SECS,
  ).length;
  const activeRollouts = rollouts.filter((rollout) => rollout.status === "pending").length;

  const rolloutByVersion = useMemo(() => {
    const map = new Map<number, Rollout>();
    for (const rollout of rollouts) {
      const current = map.get(rollout.version);
      if (!current || rollout.started_at_epoch > current.started_at_epoch) {
        map.set(rollout.version, rollout);
      }
    }
    return map;
  }, [rollouts]);

  const appliedRollout = applied ? (rolloutByVersion.get(applied.version) ?? null) : null;
  const rejectedAgents = appliedRollout ? appliedRollout.rejected_agents : 0;

  /* Register selection: which version the stored pack shows; which policy the
     acknowledgements section follows. */
  const [selectedVersion, setSelectedVersion] = useState<number | null>(null);
  const selected =
    (selectedVersion === null
      ? null
      : (sorted.find((policy) => policy.version === selectedVersion) ?? null)) ?? latest;

  const defaultAcksVersion = applied ? applied.version : (latest ? latest.version : null);
  const [pinnedAcksVersion, setPinnedAcksVersion] = useState<number | null>(null);
  const acksVersion =
    pinnedAcksVersion !== null && sorted.some((policy) => policy.version === pinnedAcksVersion)
      ? pinnedAcksVersion
      : defaultAcksVersion;
  useEffect(() => {
    if (pinnedAcksVersion !== null && pinnedAcksVersion === defaultAcksVersion) {
      setPinnedAcksVersion(null);
    }
  }, [defaultAcksVersion, pinnedAcksVersion]);
  const acksPolicy =
    acksVersion === null
      ? null
      : (sorted.find((policy) => policy.version === acksVersion) ?? null);
  /* The register follows the version under review; the band measures the
     rollout in effect, which is the applied version. */
  const acksState = useAcks(acksVersion, onError, onSessionExpired);
  const appliedAcksState = useAcks(defaultAcksVersion, onError, onSessionExpired);
  const appliedAcks = appliedAcksState.acks.filter((ack) => ack.status === "applied").length;
  const pendingAcks = appliedAcksState.acks.filter((ack) => ack.status === "pending").length;

  /* Layer state. */
  const [acksPolicyForDrawer, setAcksPolicyForDrawer] = useState<Policy | null>(null);
  const [rolloutFor, setRolloutFor] = useState<Policy | null>(null);
  const rollbackTarget = rolloutFor
    ? (sorted.find((policy) => policy.version < rolloutFor.version) ?? null)
    : null;

  /* Working copy. */
  const [name, setName] = useState("default");
  const [versionText, setVersionText] = useState(String(nextVersion));
  const [content, setContent] = useState(defaultPolicy);
  const [status, setStatus] = useState<{ tone: StatusTone; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const isBusy = busy !== null;
  const stagedPolicy = useMemo(
    () => sorted.find((policy) => policy.status === "staged") ?? null,
    [sorted],
  );

  const handleFailure = (reason: unknown) => {
    if (reason instanceof ApiError && reason.status === 401) {
      onSessionExpired();
      return;
    }
    setStatus({ tone: "err", text: errorMessage(reason) });
  };

  const loadCanonical = () => {
    setContent(defaultPolicy);
    setName("default");
    setVersionText(String(nextVersion));
    setStatus({ tone: "ok", text: "Loaded the canonical pack." });
  };

  const loadFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    try {
      const text = await file.text();
      setContent(text);
      setStatus({ tone: "ok", text: `Loaded ${file.name}.` });
    } catch (reason) {
      setStatus({ tone: "err", text: errorMessage(reason) });
    }
  };

  const validate = async () => {
    if (!canValidate || isBusy) return;
    setBusy("validate");
    setStatus(null);
    try {
      const result = await api.validate(content);
      if (result.valid) {
        const facts: string[] = [];
        if (result.rules !== undefined) facts.push(ruleLabel(result.rules));
        if (result.digest) facts.push(shortDigest(result.digest));
        setStatus({
          tone: "ok",
          text: `Valid${facts.length ? `, ${facts.join(", ")}` : ""}.`,
        });
      } else {
        setStatus({ tone: "err", text: result.error ?? "The parser rejected this pack." });
      }
    } catch (reason) {
      handleFailure(reason);
    } finally {
      setBusy(null);
    }
  };

  const stage = async () => {
    if (!canManage || isBusy) return;
    const parsedVersion = Number(versionText);
    const trimmedName = name.trim();
    if (!Number.isInteger(parsedVersion) || parsedVersion <= 0) {
      setStatus({ tone: "err", text: "Version must be a positive integer." });
      return;
    }
    if (!trimmedName) {
      setStatus({ tone: "err", text: "Policy name is required." });
      return;
    }
    setBusy("stage");
    setStatus(null);
    try {
      await api.stage(parsedVersion, content, trimmedName);
      onToast(`Staged ${trimmedName} v${parsedVersion}`);
      setStatus({ tone: "ok", text: `Staged ${trimmedName} v${parsedVersion}.` });
      setSelectedVersion(parsedVersion);
      setPinnedAcksVersion(parsedVersion);
      setVersionText(String(parsedVersion + 1));
      onRefresh();
    } catch (reason) {
      handleFailure(reason);
    } finally {
      setBusy(null);
    }
  };

  const commit = async (policy: Policy, source: "register" | "working") => {
    if (!canManage || isBusy) return;
    setBusy(source === "register" ? `commit:${policy.version}` : "commit:working");
    try {
      await api.commit(policy.version);
      onToast(`Committed ${policy.name} v${policy.version}`);
      setStatus({ tone: "ok", text: `Committed ${policy.name} v${policy.version}.` });
      setPinnedAcksVersion(policy.version);
      onRefresh();
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) {
        onSessionExpired();
      } else if (source === "working") {
        setStatus({ tone: "err", text: errorMessage(reason) });
      } else {
        onError(errorMessage(reason));
      }
    } finally {
      setBusy(null);
    }
  };

  /* Section meta: the register date, the role, and what the working copy can do. */
  const today = dayLabel(new Date());
  const workingMeta = canManage
    ? `${rolePhrase(role)} can stage, commit, roll out`
    : canValidate
      ? "analyst can validate"
      : "read-only role";
  const acksNote =
    defaultAcksVersion === null
      ? "no policy versions"
      : appliedAcksState.loading
        ? "loading"
        : appliedAcksState.failed
          ? "unavailable"
          : appliedAcksState.acks.length
            ? `${appliedAcks} applied${pendingAcks ? `, ${pendingAcks} pending` : ""}`
            : "none recorded";

  return (
    <>
      <MeasureBand sub>
        <Measure
          value={sorted.length}
          label="versions"
          note={latest ? `latest is v${latest.version}` : "none recorded"}
        />
        <Measure
          value={
            applied && appliedRollout
              ? `${appliedRollout.applied_agents}/${appliedRollout.expected_agents}`
              : "—"
          }
          label="rollout applied"
          note={
            applied
              ? appliedRollout
                ? `${applied.name} v${applied.version}, min ${Math.round(appliedRollout.min_ratio * 100)}%`
                : `${applied.name} v${applied.version}, no rollout`
              : "no applied version"
          }
        />
        <Measure
          value={
            defaultAcksVersion === null || appliedAcksState.loading || appliedAcksState.failed
              ? "—"
              : appliedAcksState.acks.length
          }
          label="acknowledgements"
          note={acksNote}
        />
        <Measure
          value={rejectedAgents}
          label="rejected agents"
          note={
            rejectedAgents > 0 && appliedRollout
              ? `${appliedRollout.name} v${appliedRollout.version} rollout`
              : "none recorded"
          }
          signal={rejectedAgents > 0}
        />
      </MeasureBand>

      <div className="grid12 body-grid">
        <div className="col-8 stack">
          <Section title="Version register" meta={`${today}, ${rolePhrase(role)}`}>
            <Table label="Policy version register" minWidth={780}>
              <colgroup>
                <col style={{ width: "14%" }} />
                <col style={{ width: "12%" }} />
                <col style={{ width: "20%" }} />
                <col style={{ width: "10%" }} />
                <col style={{ width: "19%" }} />
                <col style={{ width: "25%" }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Version</th>
                  <th>Status</th>
                  <th>Digest</th>
                  <th className="n">Created</th>
                  <th>Rollout</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sorted.length ? (
                  sorted.map((policy) => {
                    const rollout = rolloutByVersion.get(policy.version) ?? null;
                    return (
                      <tr key={policy.id}>
                        <td className="nowrap">
                          <b>
                            {policy.name} v{policy.version}
                          </b>
                        </td>
                        <td className="nowrap">
                          <span className={stateClass(policy.status)}>{policy.status}</span>
                        </td>
                        <td className="nowrap" title={policy.digest || undefined}>
                          <span className="muted">{shortDigest(policy.digest)}</span>
                        </td>
                        <td
                          className="n nowrap"
                          title={formatTimestamp(policy.created_at_epoch)}
                        >
                          {clockOf(policy.created_at_epoch)}
                        </td>
                        <td>
                          {rollout ? (
                            <>
                              <span className="nowrap">
                                {rollout.applied_agents} of {rollout.expected_agents}
                              </span>
                              <div className="cell-sub">
                                {rolloutNote(rollout)}
                                {rollout.rejected_agents > 0 ? (
                                  <span className="sig"> {rollout.rejected_agents} rejected</span>
                                ) : null}
                              </div>
                            </>
                          ) : (
                            <span className="muted">no rollout</span>
                          )}
                        </td>
                        <td>
                          <div className="row-actions">
                            <TableButton
                              type="button"
                              onClick={() => setSelectedVersion(policy.version)}
                            >
                              View YAML
                            </TableButton>
                            <TableButton
                              type="button"
                              onClick={() => setAcksPolicyForDrawer(policy)}
                            >
                              Acks
                            </TableButton>
                            {canManage && policy.status === "staged" ? (
                              <TableButton
                                type="button"
                                disabled={isBusy}
                                onClick={() => void commit(policy, "register")}
                              >
                                {busy === `commit:${policy.version}` ? "Committing" : "Commit"}
                              </TableButton>
                            ) : null}
                            {canManage && policy.status === "committed" ? (
                              <TableButton
                                type="button"
                                disabled={isBusy || activeRollouts > 0}
                                title={
                                  activeRollouts > 0
                                    ? "another rollout is pending"
                                    : "start a thresholded rollout"
                                }
                                onClick={() => setRolloutFor(policy)}
                              >
                                Start rollout
                              </TableButton>
                            ) : null}
                          </div>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <EmptyRow colSpan={6}>
                    No policy versions recorded. A policy admin can stage the canonical pack.
                  </EmptyRow>
                )}
              </tbody>
            </Table>
          </Section>

          <Section title="Rollouts">
            <Table label="Rollout register" minWidth={680}>
              <colgroup>
                <col style={{ width: "16%" }} />
                <col style={{ width: "14%" }} />
                <col style={{ width: "16%" }} />
                <col style={{ width: "22%" }} />
                <col style={{ width: "12%" }} />
                <col style={{ width: "20%" }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Policy</th>
                  <th>Status</th>
                  <th className="n">Applied</th>
                  <th className="n">Threshold</th>
                  <th>Rollback</th>
                  <th className="n">Started</th>
                </tr>
              </thead>
              <tbody>
                {rollouts.length ? (
                  rollouts.map((rollout) => (
                    <tr key={rollout.id}>
                      <td className="nowrap">
                        <b>
                          {rollout.name} v{rollout.version}
                        </b>
                      </td>
                      <td className="nowrap">
                        <span className={stateClass(rollout.status)}>{rollout.status}</span>
                      </td>
                      <td className="n nowrap">
                        {rollout.applied_agents} of {rollout.expected_agents}
                        {rollout.rejected_agents > 0 ? (
                          <div className="cell-sub sig">{rollout.rejected_agents} rejected</div>
                        ) : null}
                      </td>
                      <td className="n nowrap">
                        {Math.round(rollout.min_ratio * 100)}%
                        <div className="cell-sub">timeout {rollout.timeout_secs}s</div>
                      </td>
                      <td className="nowrap">
                        {rollout.previous_version !== null ? (
                          `v${rollout.previous_version}`
                        ) : (
                          <span className="muted">none</span>
                        )}
                      </td>
                      <td
                        className="n nowrap"
                        title={formatTimestamp(rollout.started_at_epoch)}
                      >
                        {clockOf(rollout.started_at_epoch)}
                      </td>
                    </tr>
                  ))
                ) : (
                  <EmptyRow colSpan={6}>No rollouts recorded.</EmptyRow>
                )}
              </tbody>
            </Table>
          </Section>

          <Section
            title="Stored pack"
            meta={
              selected
                ? `${selected.name} v${selected.version}, ${shortDigest(selected.digest)}, ${ruleLabel(ruleCount(selected.content))}`
                : "no stored pack"
            }
            tools={selected ? <CopyButton value={selected.content} label="Copy YAML" /> : undefined}
          >
            {selected ? (
              <pre className="pack" style={{ maxHeight: 420, overflowY: "auto" }}>
                {selected.content}
              </pre>
            ) : (
              <p className="empty-cell">No stored pack yet. Stage a version to store it.</p>
            )}
          </Section>
        </div>

        <div className="col-4 stack">
          <Section title="Working copy" meta={workingMeta}>
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <div className="form-grid">
                <Field label="Policy name" htmlFor="policy-name">
                  <input
                    id="policy-name"
                    value={name}
                    readOnly={!canValidate}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(event) => {
                      setName(event.target.value);
                      setStatus(null);
                    }}
                  />
                </Field>
                <Field label="Version" htmlFor="policy-version">
                  <input
                    id="policy-version"
                    type="number"
                    min={1}
                    step={1}
                    value={versionText}
                    readOnly={!canValidate}
                    onChange={(event) => {
                      setVersionText(event.target.value);
                      setStatus(null);
                    }}
                  />
                </Field>
              </div>
              <Field label="YAML" htmlFor="policy-yaml">
                <textarea
                  id="policy-yaml"
                  value={content}
                  rows={13}
                  readOnly={!canValidate}
                  spellCheck={false}
                  onChange={(event) => {
                    setContent(event.target.value);
                    setStatus(null);
                  }}
                />
              </Field>
              <div className="btn-row">
                <Button
                  type="button"
                  disabled={!canValidate || isBusy}
                  onClick={loadCanonical}
                >
                  Load canonical pack
                </Button>
                <Button
                  type="button"
                  disabled={!canValidate || isBusy}
                  onClick={() => fileRef.current?.click()}
                >
                  Load file
                </Button>
                <input
                  ref={fileRef}
                  type="file"
                  className="sr-only"
                  accept=".yaml,.yml,text/yaml"
                  onChange={(event) => void loadFile(event)}
                />
              </div>
              <div className="btn-row">
                <Button
                  type="button"
                  disabled={!canValidate || isBusy}
                  aria-busy={busy === "validate"}
                  onClick={() => void validate()}
                >
                  {busy === "validate" ? "Validating" : "Validate"}
                </Button>
                <Button
                  type="button"
                  variant="primary"
                  disabled={!canManage || isBusy}
                  aria-busy={busy === "stage"}
                  onClick={() => void stage()}
                >
                  {busy === "stage" ? "Staging" : "Stage version"}
                </Button>
                {canManage && stagedPolicy ? (
                  <Button
                    type="button"
                    disabled={isBusy}
                    aria-busy={busy === "commit:working"}
                    title={`Commit ${stagedPolicy.name} v${stagedPolicy.version}`}
                    onClick={() => void commit(stagedPolicy, "working")}
                  >
                    {busy === "commit:working" ? "Committing" : "Commit"}
                  </Button>
                ) : null}
              </div>
              <p
                className={status?.tone === "err" ? "status-line err" : "status-line"}
                role={status?.tone === "err" ? "alert" : "status"}
              >
                {status ? status.text : ""}
              </p>
            </div>
          </Section>

          <Section
            title="Acknowledgements"
            meta={acksPolicy ? `${acksPolicy.name} v${acksPolicy.version}` : "no version"}
          >
            <AcksTable
              state={acksState}
              agents={agents}
              label="Acknowledgements"
              emptyText={
                acksPolicy
                  ? `No acknowledgements for ${acksPolicy.name} v${acksPolicy.version}.`
                  : "No acknowledgements."
              }
            />
          </Section>
        </div>
      </div>

      <AcksDrawer
        policy={acksPolicyForDrawer}
        agents={agents}
        onClose={() => setAcksPolicyForDrawer(null)}
        onError={onError}
        onSessionExpired={onSessionExpired}
      />

      <RolloutDialog
        policy={rolloutFor}
        onlineAgents={onlineAgents}
        registeredAgents={agents.length}
        rollbackTarget={rollbackTarget}
        onClose={() => setRolloutFor(null)}
        onToast={onToast}
        onSessionExpired={onSessionExpired}
        onStarted={() => {
          if (rolloutFor) {
            setSelectedVersion(rolloutFor.version);
            setPinnedAcksVersion(rolloutFor.version);
          }
          setRolloutFor(null);
          onRefresh();
        }}
      />
    </>
  );
}
