// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Dense data table with full keyboard support: roving tabindex across
// rows, Arrow/Home/End navigation, Enter/Space activation (DESIGN.md §9).
import { type KeyboardEvent, type ReactNode, useRef, useState } from "react";
import { cx } from "../lib/format";

export interface Column<T> {
  key: string;
  header: string;
  align?: "left" | "right";
  render: (row: T) => ReactNode;
}

export interface DataTableProps<T> {
  columns: ReadonlyArray<Column<T>>;
  rows: ReadonlyArray<T>;
  rowKey: (row: T) => string;
  ariaLabel: string;
  onRowActivate?: ((row: T) => void) | undefined;
  /** Roving tabindex without click activation (read-only tables). */
  focusable?: boolean;
  /** Keys that just arrived — get the row-in animation. */
  freshKeys?: ReadonlySet<string>;
  /** Rendered inside the table region when rows is empty. */
  empty?: ReactNode;
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  ariaLabel,
  onRowActivate,
  focusable = false,
  freshKeys,
  empty,
}: DataTableProps<T>) {
  const [focusIdx, setFocusIdx] = useState(0);
  const bodyRef = useRef<HTMLTableSectionElement | null>(null);

  const moveFocus = (next: number): void => {
    if (rows.length === 0) return;
    const clamped = Math.max(0, Math.min(rows.length - 1, next));
    setFocusIdx(clamped);
    const el = bodyRef.current?.querySelector<HTMLElement>(`tr[data-idx="${clamped}"]`);
    el?.focus();
  };

  const onKeyDown = (ev: KeyboardEvent<HTMLTableSectionElement>): void => {
    const target = ev.target as HTMLElement;
    if (target.tagName !== "TR") return;
    const idx = Number.parseInt(target.getAttribute("data-idx") ?? "-1", 10);
    switch (ev.key) {
      case "ArrowDown":
        ev.preventDefault();
        moveFocus(idx + 1);
        break;
      case "ArrowUp":
        ev.preventDefault();
        moveFocus(idx - 1);
        break;
      case "Home":
        ev.preventDefault();
        moveFocus(0);
        break;
      case "End":
        ev.preventDefault();
        moveFocus(rows.length - 1);
        break;
      case "Enter":
      case " ":
        if (onRowActivate !== undefined) {
          ev.preventDefault();
          const row = rows[idx];
          if (row !== undefined) onRowActivate(row);
        }
        break;
      default:
        break;
    }
  };

  const interactive = onRowActivate !== undefined || focusable;

  return (
    <div className="tbl-wrap">
      <table className="tbl" aria-label={ariaLabel}>
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.key} scope="col" className={col.align === "right" ? "num" : undefined}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody ref={bodyRef} onKeyDown={onKeyDown}>
          {rows.map((row, i) => {
            const key = rowKey(row);
            return (
              <tr
                key={key}
                data-idx={i}
                tabIndex={
                  interactive ? (i === Math.min(focusIdx, rows.length - 1) ? 0 : -1) : undefined
                }
                className={cx(freshKeys?.has(key) === true && "row--new")}
                onClick={interactive ? () => onRowActivate?.(row) : undefined}
              >
                {columns.map((col) => (
                  <td key={col.key} className={col.align === "right" ? "num" : undefined}>
                    {col.render(row)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
      {rows.length === 0 && empty}
    </div>
  );
}
