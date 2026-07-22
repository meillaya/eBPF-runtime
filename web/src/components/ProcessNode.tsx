// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// One treeitem row of the process tree. The row itself is the toggle
// target (no nested interactive element — clean ARIA tree pattern); the
// chevron is decorative. Identity is always PID + generation, never PID
// alone; the full exec path surfaces on hover/focus without layout shift.
import type { ProcessRecord, VisibleRow } from "../api/process-types";
import { cx, formatMonoShort, formatWall } from "../lib/format";
import { execBasename } from "../lib/process-tree";

export interface ProcessNodeProps {
  node: ProcessRecord;
  row: VisibleRow;
  idx: number;
  focused: boolean;
  fresh: boolean;
  onActivate: (idx: number) => void;
}

function Chevron({ expanded, hasChildren }: { expanded: boolean; hasChildren: boolean }) {
  return (
    <span
      className={cx("ptree-chevron", hasChildren && expanded && "ptree-chevron--open")}
      aria-hidden="true"
    >
      {hasChildren ? "▸" : "·"}
    </span>
  );
}

function describeNode(node: ProcessRecord, row: VisibleRow): string {
  const kind = node.isThread ? `thread ${node.pid}` : `PID ${node.pid}`;
  const gen = `generation ${node.generation}`;
  const exec = node.execPath ?? "no exec observed";
  const state = node.exited ? `exited with code ${node.exitCode ?? 0}` : "running";
  const children = row.hasChildren ? `, ${node.childKeys.length} children` : "";
  const orphan = node.ancestryIncomplete ? ", ancestry incomplete" : "";
  return `${kind}, ${gen}, ${exec}, ${state}${children}${orphan}`;
}

export function ProcessNode({ node, row, idx, focused, fresh, onActivate }: ProcessNodeProps) {
  const stateTone = node.isThread ? "thread" : node.exited ? "exited" : "running";
  const showTgid = node.tgid !== node.pid;
  return (
    <div
      role="treeitem"
      aria-level={row.depth + 1}
      aria-setsize={row.setSize}
      aria-posinset={row.posInSet}
      aria-expanded={row.hasChildren ? row.expanded : undefined}
      aria-label={describeNode(node, row)}
      tabIndex={focused ? 0 : -1}
      data-idx={idx}
      className={cx(
        "ptree-row",
        `ptree-row--${stateTone}`,
        node.reusedPid && "ptree-row--reused",
        fresh && "ptree-row--fresh",
      )}
      onClick={() => onActivate(idx)}
      onKeyDown={(ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          ev.stopPropagation();
          onActivate(idx);
        }
      }}
    >
      {Array.from({ length: row.depth }, (_, i) => (
        <span
          // biome-ignore lint/suspicious/noArrayIndexKey: static guide segments, no per-cell state
          key={i}
          className={cx(
            "ptree-guide",
            node.isThread && i === row.depth - 1 && "ptree-guide--thread",
            row.dashedGuide && i === row.depth - 1 && "ptree-guide--dashed",
          )}
          aria-hidden="true"
        />
      ))}
      <Chevron expanded={row.expanded} hasChildren={row.hasChildren} />
      <span className={cx("ptree-dot", `ptree-dot--${stateTone}`)} aria-hidden="true" />

      <span className="ptree-ident">
        <span className="strong">
          {node.isThread ? "TID" : "PID"} {node.pid}
        </span>
        {showTgid && <span className="ptree-tgid">TGID {node.tgid}</span>}
        <span
          className={cx("badge", node.reusedPid ? "badge--high" : "badge--info")}
          title={`Identity generation ${node.generation} for PID ${node.pid} in this window`}
        >
          G{node.generation}
        </span>
      </span>

      <span className="ptree-exec">
        {node.execPath !== undefined ? (
          <>
            <span className="ptree-exec-name" title={node.execPath}>
              {execBasename(node.execPath)}
            </span>
            <span className="ptree-exec-full" aria-hidden="true">
              {node.execPath}
            </span>
          </>
        ) : (
          <span className="ptree-exec-none">{node.isThread ? "thread" : "(no exec)"}</span>
        )}
        {node.execFailed && (
          <span
            className="badge badge--medium"
            title={`exec failed with errno ${node.execErrno ?? 0}`}
          >
            EXEC FAIL{node.execErrno !== undefined && ` ${node.execErrno}`}
          </span>
        )}
      </span>

      <span className="ptree-times" title="start: monotonic · wall (UTC)">
        <span>+{formatMonoShort(node.startNs)}</span>
        <span className="ptree-wall">{formatWall(node.wallStartIso)}</span>
      </span>

      <span className="ptree-flags">
        {node.isThread && <span className="badge badge--low">THREAD</span>}
        {node.exited && (
          <span className={cx("badge", node.exitCode === 0 ? "badge--info" : "badge--medium")}>
            EXIT {node.exitCode ?? 0}
          </span>
        )}
        {node.ancestryIncomplete && (
          <span
            className="badge badge--medium"
            title="Parent was reported but its identity is not in this window — ancestry is never invented"
          >
            ANCESTRY INCOMPLETE
          </span>
        )}
      </span>
    </div>
  );
}
