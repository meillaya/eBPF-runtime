// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Accessible process tree (ARIA tree pattern, CSS indent layout — no
// canvas/SVG). Flat treeitems with aria-level/setsize/posinset, roving
// tabindex, and full keyboard operation:
//   ↑/↓ traverse · → expand or enter · ← collapse or go to parent
//   Enter/Space toggle · Home/End jump · Escape collapse all
import { type KeyboardEvent, useEffect, useRef, useState } from "react";
import type { ProcessForest } from "../api/process-types";
import { flattenForest } from "../lib/process-tree";
import { ProcessNode } from "./ProcessNode";

export interface ProcessTreeProps {
  forest: ProcessForest;
  ariaLabel: string;
  /** Keys that should get the row-in animation (live arrivals). */
  freshKeys: ReadonlySet<string> | undefined;
}

export function ProcessTree({ forest, ariaLabel, freshKeys }: ProcessTreeProps) {
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const [focusedIdx, setFocusedIdx] = useState(0);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const seededRef = useRef(false);

  useEffect(() => {
    if (!seededRef.current && forest.roots.length > 0) {
      seededRef.current = true;
      setExpanded(new Set(forest.roots));
    }
  }, [forest]);

  const rows = flattenForest(forest, expanded);
  const rowByKey = new Map(rows.map((row, i) => [row.key, i]));

  const toggle = (key: string): void => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const expandAll = (): void => {
    const all = new Set<string>();
    for (const node of forest.nodes.values()) {
      if (node.childKeys.length > 0) all.add(node.key);
    }
    setExpanded(all);
  };

  const collapseAll = (): void => setExpanded(new Set());

  const focusRow = (idx: number): void => {
    if (rows.length === 0) return;
    const clamped = Math.max(0, Math.min(rows.length - 1, idx));
    setFocusedIdx(clamped);
    containerRef.current?.querySelector<HTMLElement>(`[data-idx="${clamped}"]`)?.focus();
  };

  const onActivate = (idx: number): void => {
    setFocusedIdx(idx);
    const row = rows[idx];
    if (row?.hasChildren) toggle(row.key);
  };

  const onKeyDown = (ev: KeyboardEvent<HTMLDivElement>): void => {
    const target = ev.target as HTMLElement;
    if (target.getAttribute("role") !== "treeitem") return;
    const idx = Number.parseInt(target.getAttribute("data-idx") ?? "-1", 10);
    const row = rows[idx];
    if (row === undefined) return;
    switch (ev.key) {
      case "ArrowDown":
        ev.preventDefault();
        focusRow(idx + 1);
        break;
      case "ArrowUp":
        ev.preventDefault();
        focusRow(idx - 1);
        break;
      case "ArrowRight":
        ev.preventDefault();
        if (row.hasChildren && !row.expanded) toggle(row.key);
        else focusRow(idx + 1);
        break;
      case "ArrowLeft": {
        ev.preventDefault();
        if (row.hasChildren && row.expanded) {
          toggle(row.key);
        } else if (row.parentKey !== undefined) {
          const parentIdx = rowByKey.get(row.parentKey);
          if (parentIdx !== undefined) focusRow(parentIdx);
        }
        break;
      }
      case "Home":
        ev.preventDefault();
        focusRow(0);
        break;
      case "End":
        ev.preventDefault();
        focusRow(rows.length - 1);
        break;
      case "Escape":
        ev.preventDefault();
        collapseAll();
        break;
      default:
        break;
    }
  };

  const visibleCount = rows.length;

  return (
    <div className="ptree">
      <div className="ptree-toolbar">
        <button type="button" className="btn btn--ghost btn--sm" onClick={expandAll}>
          Expand all
        </button>
        <button type="button" className="btn btn--ghost btn--sm" onClick={collapseAll}>
          Collapse all
        </button>
        <span className="ptree-toolbar-hint">↑↓ traverse · ⏎ toggle · esc collapse</span>
      </div>
      <div
        ref={containerRef}
        role="tree"
        aria-label={ariaLabel}
        className="ptree-wrap"
        onKeyDown={onKeyDown}
      >
        {rows.map((row, i) => {
          const node = forest.nodes.get(row.key);
          if (node === undefined) return null;
          return (
            <ProcessNode
              key={row.key}
              node={node}
              row={row}
              idx={i}
              focused={i === Math.min(focusedIdx, rows.length - 1)}
              fresh={freshKeys?.has(row.key) === true}
              onActivate={onActivate}
            />
          );
        })}
        {visibleCount === 0 && (
          <p className="ptree-none" role="status">
            No processes in this window.
          </p>
        )}
      </div>
    </div>
  );
}
