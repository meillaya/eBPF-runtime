import { useEffect, useMemo, useRef, useState } from "react";
import defaultPolicy from "../../../rules/default/sensitive-files.yaml?raw";
import type { Ack, Agent, Policy, Role, Rollout } from "../types";
import { api, ApiError } from "../api";
import { roleAtLeast } from "../auth";
import {
  formatNumber,
  formatTimestamp,
  relativeTime,
  shortId,
  statusTone,
  titleCase,
} from "../lib/format";
import {
  Badge,
  Button,
  Card,
  CopyButton,
  Drawer,
  EmptyState,
  Field,
  Icon,
  Modal,
  ProgressBar,
  SearchInput,
  Segmented,
  TableShell,
} from "./ui";

type StatusFilter = "all" | "staged" | "committed" | "applied" | "rolled_back";

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
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<StatusFilter>("all");
  const [editorOpen, setEditorOpen] = useState(false);
  const [contentFor, setContentFor] = useState<Policy | null>(null);
  const [acksFor, setAcksFor] = useState<Policy | null>(null);
  const [rolloutFor, setRolloutFor] = useState<Policy | null>(null);
  const [busyVersion, setBusyVersion] = useState<number | null>(null);

  const canManage = roleAtLeast(role, "policy-admin");
  const canValidate = roleAtLeast(role, "analyst");
  const canOpenEditor = canManage || canValidate;
  const onlineAgents = agents.filter(
    (agent) => Date.now() / 1000 - agent.last_seen_epoch <= 120,
  ).length;
  const nextVersion = policies.reduce((max, policy) => Math.max(max, policy.version), 0) + 1;

  const rolloutByVersion = useMemo(() => {
    const map = new Map<number, Rollout>();
    for (const rollout of rollouts) {
      if (!map.has(rollout.version)) map.set(rollout.version, rollout);
    }
    return map;
  }, [rollouts]);

  const filtered = useMemo(
    () =>
      policies.filter((policy) => {
        if (status !== "all" && policy.status !== status) return false;
        if (!search.trim()) return true;
        return `${policy.name} ${policy.version} ${policy.digest}`
          .toLowerCase()
          .includes(search.trim().toLowerCase());
      }),
    [policies, search, status],
  );

  const activeRollouts = rollouts.filter((rollout) => rollout.status === "pending").length;

  const commit = async (policy: Policy) => {
    setBusyVersion(policy.version);
    try {
      await api.commit(policy.version);
      onToast(`Committed ${policy.name} v${policy.version}`);
      onRefresh();
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) {
        onSessionExpired();
      } else {
        onError(reason instanceof Error ? reason.message : String(reason));
      }
    } finally {
      setBusyVersion(null);
    }
  };

  return (
    <div className="view">
      <div className="mini-stats">
        <div className="mini-stat">
          <span>Versions</span>
          <strong>{policies.length}</strong>
        </div>
        <div className="mini-stat">
          <span>Staged</span>
          <strong>{policies.filter((policy) => policy.status === "staged").length}</strong>
        </div>
        <div className="mini-stat">
          <span>Active rollouts</span>
          <strong className={activeRollouts ? "text-amber" : ""}>{activeRollouts}</strong>
        </div>
        <div className="mini-stat">
          <span>Online denominator</span>
          <strong>{onlineAgents}</strong>
        </div>
      </div>

      <Card
        title="Policy versions"
        subtitle="Stage YAML, validate it with the agent parser, commit, then roll out a thresholded change."
        actions={
          canOpenEditor ? (
            <Button
              variant={canManage ? "primary" : "secondary"}
              size="sm"
              icon={canManage ? "plus" : "check"}
              onClick={() => setEditorOpen(true)}
            >
              {canManage ? "Stage policy" : "Validate policy"}
            </Button>
          ) : (
            <Badge tone="slate">read-only role</Badge>
          )
        }
        bodyClassName="table-body"
      >
        <div className="table-toolbar">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Search policy name, version, digest…"
          />
          <Segmented
            ariaLabel="Filter policies by status"
            size="sm"
            value={status}
            onChange={setStatus}
            options={[
              { value: "all", label: "All" },
              { value: "staged", label: "Staged" },
              { value: "committed", label: "Committed" },
              { value: "applied", label: "Applied" },
              { value: "rolled_back", label: "Rolled back" },
            ]}
          />
        </div>

        {filtered.length ? (
          <TableShell>
            <table className="data-table policy-table">
              <thead>
                <tr>
                  <th>Policy</th>
                  <th>Status</th>
                  <th>Rollout</th>
                  <th className="hide-sm">Digest</th>
                  <th className="hide-sm">Created</th>
                  <th className="actions-col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((policy) => {
                  const rollout = rolloutByVersion.get(policy.version);
                  const busy = busyVersion === policy.version;
                  const rolloutPending = rollout?.status === "pending";
                  return (
                    <tr key={policy.id}>
                      <td>
                        <div className="policy-name">
                          <span>{policy.name}</span>
                          <span className="version-chip">v{policy.version}</span>
                        </div>
                      </td>
                      <td>
                        <Badge tone={statusTone(policy.status)} dot>
                          {titleCase(policy.status)}
                        </Badge>
                      </td>
                      <td>
                        {rollout ? (
                          <div className="rollout-cell">
                            <div className="rollout-line">
                              <Badge tone={statusTone(rollout.status)}>{titleCase(rollout.status)}</Badge>
                              <span className="rollout-count">
                                {rollout.status} {rollout.applied_agents}/{rollout.expected_agents} applied
                              </span>
                            </div>
                            <ProgressBar
                              value={rollout.applied_agents}
                              total={rollout.expected_agents}
                              tone={
                                rollout.status === "rolled_back" || rollout.status === "failed"
                                  ? "rose"
                                  : rollout.status === "promoted"
                                    ? "emerald"
                                    : "teal"
                              }
                              label={`${rollout.status} applied ratio`}
                            />
                            <span className="rollout-reason">
                              {rollout.status === "pending"
                                ? `min ${Math.round(rollout.min_ratio * 100)}% · timeout in ${Math.max(
                                    0,
                                    rollout.deadline_epoch - Math.floor(Date.now() / 1000),
                                  )}s`
                                : rollout.reason || `${Math.round(rollout.min_ratio * 100)}% threshold`}
                            </span>
                          </div>
                        ) : (
                          <span className="muted-cell">—</span>
                        )}
                      </td>
                      <td className="mono muted-cell hide-sm" title={policy.digest}>
                        {shortId(policy.digest, 12)}
                      </td>
                      <td className="muted-cell hide-sm" title={formatTimestamp(policy.created_at_epoch)}>
                        {relativeTime(policy.created_at_epoch)}
                      </td>
                      <td>
                        <div className="row-actions">
                          <Button
                            variant="ghost"
                            size="sm"
                            icon="code"
                            onClick={() => setContentFor(policy)}
                          >
                            View
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            icon="list"
                            onClick={() => setAcksFor(policy)}
                          >
                            Acks
                          </Button>
                          {canManage && policy.status === "staged" ? (
                            <Button
                              variant="secondary"
                              size="sm"
                              icon="check"
                              loading={busy}
                              onClick={() => void commit(policy)}
                            >
                              Commit
                            </Button>
                          ) : null}
                          {canManage && policy.status === "committed" ? (
                            <Button
                              variant="primary"
                              size="sm"
                              icon="play"
                              disabled={rolloutPending || activeRollouts > 0}
                              title={
                                activeRollouts > 0
                                  ? "another rollout is pending"
                                  : "start a thresholded rollout"
                              }
                              onClick={() => setRolloutFor(policy)}
                            >
                              Roll out
                            </Button>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableShell>
        ) : (
          <EmptyState
            icon="shield"
            title={policies.length ? "No policies match" : "No policy versions"}
            description={
              policies.length
                ? "Change the filter or clear the search."
                : canManage
                  ? "Stage the default rule pack or load your own YAML to get started."
                  : "A policy admin can stage the first rule pack."
            }
            action={
              canOpenEditor && !policies.length ? (
                <Button
                  variant={canManage ? "primary" : "secondary"}
                  size="sm"
                  icon={canManage ? "plus" : "check"}
                  onClick={() => setEditorOpen(true)}
                >
                  {canManage ? "Stage the default pack" : "Validate a policy"}
                </Button>
              ) : undefined
            }
          />
        )}
      </Card>

      <Drawer
        open={editorOpen}
        onClose={() => setEditorOpen(false)}
        title={canManage ? "Stage a policy" : "Validate a policy"}
        subtitle={
          canManage
            ? "The control plane validates with the same parser the agent uses before storing the pack."
            : "Run the agent's rule parser without writing a new policy version."
        }
        size="lg"
      >
        <StagePolicyForm
          nextVersion={nextVersion}
          canValidate={canValidate}
          canStage={canManage}
          onClose={() => setEditorOpen(false)}
          onToast={onToast}
          onSessionExpired={onSessionExpired}
          onStaged={() => {
            setEditorOpen(false);
            onRefresh();
          }}
        />
      </Drawer>

      <Drawer
        open={Boolean(contentFor)}
        onClose={() => setContentFor(null)}
        title={contentFor ? `${contentFor.name} v${contentFor.version}` : "Policy"}
        subtitle={contentFor ? `Digest ${contentFor.digest}` : undefined}
        footer={
          contentFor ? (
            <div className="drawer-footer-actions">
              <CopyButton value={contentFor.content} label="Copy YAML" />
              <Button variant="secondary" size="sm" onClick={() => setContentFor(null)}>
                Close
              </Button>
            </div>
          ) : undefined
        }
      >
        {contentFor ? <pre className="yaml-block">{contentFor.content}</pre> : null}
      </Drawer>

      <AcksDrawer
        policy={acksFor}
        onClose={() => setAcksFor(null)}
        onSessionExpired={onSessionExpired}
        onError={onError}
      />

      <RolloutDialog
        policy={rolloutFor}
        onlineAgents={onlineAgents}
        onClose={() => setRolloutFor(null)}
        onToast={onToast}
        onSessionExpired={onSessionExpired}
        onStarted={() => {
          setRolloutFor(null);
          onRefresh();
        }}
      />
    </div>
  );
}

function StagePolicyForm({
  nextVersion,
  canValidate,
  canStage,
  onClose,
  onToast,
  onSessionExpired,
  onStaged,
}: {
  nextVersion: number;
  canValidate: boolean;
  canStage: boolean;
  onClose: () => void;
  onToast: (message: string, tone?: string) => void;
  onSessionExpired: () => void;
  onStaged: () => void;
}) {
  const [name, setName] = useState("default");
  const [version, setVersion] = useState(String(nextVersion));
  const [content, setContent] = useState(defaultPolicy);
  const [validation, setValidation] = useState<{ valid: boolean; message: string } | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleFailure = (reason: unknown) => {
    if (reason instanceof ApiError && reason.status === 401) {
      onSessionExpired();
    } else {
      setFormError(reason instanceof Error ? reason.message : String(reason));
    }
  };

  const validate = async () => {
    if (!canValidate) return;
    setValidation(null);
    setFormError(null);
    try {
      const result = await api.validate(content);
      setValidation(
        result.valid
          ? {
              valid: true,
              message: `Valid · ${result.rules ?? 0} rules · ${shortId(result.digest ?? "", 16)}`,
            }
          : { valid: false, message: result.error ?? "The parser rejected this pack." },
      );
    } catch (reason) {
      handleFailure(reason);
    }
  };

  const stage = async () => {
    const parsedVersion = Number(version);
    if (!Number.isInteger(parsedVersion) || parsedVersion <= 0) {
      setValidation({ valid: false, message: "Version must be a positive integer." });
      return;
    }
    if (!name.trim()) {
      setValidation({ valid: false, message: "Policy name is required." });
      return;
    }
    setBusy(true);
    setFormError(null);
    try {
      await api.stage(parsedVersion, content, name.trim());
      onToast(`Staged ${name.trim()} v${parsedVersion}`);
      onStaged();
    } catch (reason) {
      handleFailure(reason);
    } finally {
      setBusy(false);
    }
  };

  const loadFile = async (file: File | undefined) => {
    if (!file) return;
    setContent(await file.text());
    setValidation(null);
  };

  return (
    <div className="stage-form">
      <div className="form-grid">
        <Field label="Policy name" htmlFor="policy-name">
          <input
            id="policy-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            spellCheck={false}
          />
        </Field>
        <Field label="Version" htmlFor="policy-version" hint="Positive integer, unique per policy.">
          <input
            id="policy-version"
            type="number"
            min={1}
            value={version}
            onChange={(event) => setVersion(event.target.value)}
          />
        </Field>
      </div>
      <div className="editor-toolbar">
        <span className="editor-label">YAML</span>
        <div className="editor-actions">
          <input
            ref={fileRef}
            type="file"
            accept=".yaml,.yml,text/yaml"
            className="sr-only"
            onChange={(event) => void loadFile(event.target.files?.[0])}
          />
          <Button variant="ghost" size="sm" onClick={() => fileRef.current?.click()}>
            Load file
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setContent(defaultPolicy);
              setValidation(null);
              setFormError(null);
            }}
          >
            Default pack
          </Button>
        </div>
      </div>
      <textarea
        className="yaml-editor"
        value={content}
        onChange={(event) => {
          setContent(event.target.value);
          setValidation(null);
        }}
        spellCheck={false}
        aria-label="Policy YAML"
      />
      <div className="editor-meta">
        <span>{content.split("\n").length} lines</span>
        <span>{formatNumber(new Blob([content]).size)} bytes</span>
      </div>
      {validation ? (
        <div className={`validation ${validation.valid ? "validation-ok" : "validation-bad"}`}>
          <Icon name={validation.valid ? "check" : "alert"} size={16} />
          <span>{validation.message}</span>
        </div>
      ) : null}
      {formError ? (
        <div className="validation validation-bad">
          <Icon name="alert" size={16} />
          <span>{formError}</span>
        </div>
      ) : null}
      <div className="form-actions">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <div className="form-actions-right">
          <Button
            variant="secondary"
            icon="check"
            disabled={!canValidate}
            title={canValidate ? "Validate with the rule parser" : "Analyst role required"}
            onClick={() => void validate()}
          >
            Validate
          </Button>
          {canStage ? (
            <Button variant="primary" icon="plus" loading={busy} onClick={() => void stage()}>
              Stage policy
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function RolloutDialog({
  policy,
  onlineAgents,
  onClose,
  onToast,
  onSessionExpired,
  onStarted,
}: {
  policy: Policy | null;
  onlineAgents: number;
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
    if (!policy) return;
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
      onToast(
        `Rollout started: ${result.rollout.expected_agents} expected agent${
          result.rollout.expected_agents === 1 ? "" : "s"
        }`,
      );
      onStarted();
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) {
        onSessionExpired();
      } else {
        setFormError(reason instanceof Error ? reason.message : String(reason));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={Boolean(policy)}
      onClose={onClose}
      title={policy ? `Roll out ${policy.name} v${policy.version}` : "Roll out policy"}
      subtitle="The control plane snapshots the online fleet, broadcasts the target, and waits for applied acknowledgements."
      footer={
        <div className="form-actions">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" icon="play" loading={busy} onClick={() => void start()}>
            Start rollout
          </Button>
        </div>
      }
    >
      <div className="notice">
        <Icon name="alert" size={17} />
        <div>
          <strong>Rollback target required</strong>
          <p>
            The previous committed version must exist. Any rejected acknowledgement or a missed
            ratio at the deadline broadcasts that version and marks this rollout rolled back.
          </p>
        </div>
      </div>
      {formError ? (
        <div className="validation validation-bad modal-error">
          <Icon name="alert" size={16} />
          <span>{formError}</span>
        </div>
      ) : null}
      <div className="form-grid">
        <Field label="Minimum ratio" htmlFor="rollout-ratio" hint="Applied / expected, 0 < ratio ≤ 1.">
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
        <Field label="Timeout (seconds)" htmlFor="rollout-timeout" hint="1 to 86400 seconds.">
          <input
            id="rollout-timeout"
            type="number"
            min={1}
            max={86400}
            value={timeoutSecs}
            onChange={(event) => setTimeoutSecs(event.target.value)}
          />
        </Field>
      </div>
      <label className="check-row">
        <input type="checkbox" checked={force} onChange={(event) => setForce(event.target.checked)} />
        <span>
          Include offline agents in the denominator
          <small>Current online estimate: {onlineAgents}. Offline agents make the threshold harder.</small>
        </span>
      </label>
    </Modal>
  );
}

function AcksDrawer({
  policy,
  onClose,
  onError,
  onSessionExpired,
}: {
  policy: Policy | null;
  onClose: () => void;
  onError: (message: string) => void;
  onSessionExpired: () => void;
}) {
  const [acks, setAcks] = useState<Ack[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!policy) return;
    let cancelled = false;
    setLoading(true);
    setAcks([]);
    api
      .acks(policy.version)
      .then((page) => {
        if (!cancelled) setAcks(page.acks);
      })
      .catch((reason) => {
        if (cancelled) return;
        if (reason instanceof ApiError && reason.status === 401) {
          onSessionExpired();
        } else {
          onError(reason instanceof Error ? reason.message : String(reason));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [onError, onSessionExpired, policy]);

  return (
    <Drawer
      open={Boolean(policy)}
      onClose={onClose}
      title={policy ? `Acknowledgements v${policy.version}` : "Acknowledgements"}
      subtitle="One row per agent. Applied means the sensor thread has the engine active."
    >
      {loading ? (
        <div className="empty-state compact">
          <span className="spinner" />
          <p>Loading acknowledgements…</p>
        </div>
      ) : acks.length ? (
        <div className="ack-list">
          {acks.map((ack) => (
            <div className="ack-row" key={ack.agent_id}>
              <div className="ack-main">
                <span className="mono">{ack.agent_id}</span>
                <span className="muted-cell">{ack.message || "No message"}</span>
              </div>
              <Badge tone={statusTone(ack.status)}>{ack.status}</Badge>
              <span className="muted-cell ack-time">{relativeTime(ack.updated_at_epoch)}</span>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState
          icon="list"
          title="No acknowledgements"
          description="Agents acknowledge after the policy is committed and delivered."
        />
      )}
    </Drawer>
  );
}
