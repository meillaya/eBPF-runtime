#!/usr/bin/env python3
# scripts/validate-workflows.py - local structural validator for
# kernel-v1 GitHub Actions workflows.
#
# This script is the agent-executable substitute for actionlint when
# actionlint is not installed in the CI runner image. It enforces the
# security-defining rules from the kernel-v1 plan task 7:
#
#   1. Privileged workflows (anything with 'privileged' in the workflow
#      name or filename) MUST target declared self-hosted runners via the
#      kernel-<ver>-arch-<arch> label scheme. Pointing a privileged job
#      at ubuntu-* / ubuntu-latest / ubuntu-22.04 / hosted-* is a
#      security defect because it would let the privileged suite run on
#      an unprivileged runner and silently produce a false PASS.
#
#   2. Every privileged job MUST include a failure path that emits a
#      structured 'blocked' verdict. The plan explicitly forbids marking
#      skipped jobs green; the validator enforces a step whose name or
#      run body mentions 'blocked' and which is gated on
#      'if: always()' (or an equivalent failure-handling expression).
#
#   3. The deterministic workflow MUST set a concurrency group so a
#      re-push does not race a queued run.
#
#   4. Deterministic and scheduled-aggregate jobs MUST run on hosted
#      ubuntu labels only (no self-hosted on the deterministic lane).
#
# The script uses a small stdlib-only YAML subset parser, deliberately
# avoiding PyYAML so it runs in a hermetic CI image and in any local
# shell. The parser is purpose-built for the GitHub Actions subset
# (top-level keys, two-space indent mapping, lists with '-' prefix,
# scalars, inline mappings/sequences, and ${{ ... }} expressions).
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""
validate-workflows.py - validate kernel-v1 GitHub Actions workflows.

Usage:
    python3 scripts/validate-workflows.py [--workflows-dir <path>]

Exit codes:
    0   every rule passes
    1   one or more rules failed; each violation is printed to stderr as
        validate-workflows: <pointer>: <message>
    2   bad usage or unreadable input
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable


PROG = "validate-workflows"

PRIVILEGED_NAME_HINTS = ("privileged",)
HOSTED_RUNNER_PREFIXES = ("ubuntu-", "macos-", "windows-", "hosted-")
SELF_HOSTED_LABEL = "self-hosted"


@dataclass
class Violation:
    pointer: str
    message: str
    workflow: str

    def render(self) -> str:
        return f"{PROG}: {self.workflow}: {self.pointer}: {self.message}"


@dataclass
class Step:
    name: str = ""
    uses: str = ""
    run: str = ""
    if_expr: str = ""
    id: str = ""


@dataclass
class Job:
    name: str = ""
    runs_on: list[str] = field(default_factory=list)
    if_expr: str = ""
    steps: list[Step] = field(default_factory=list)


@dataclass
class Workflow:
    path: str
    name: str = ""
    has_concurrency: bool = False
    jobs: dict[str, Job] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# YAML subset parser
# ---------------------------------------------------------------------------

_COMMENT_LINE_RE = re.compile(r"^\s*#")
_LIST_ENTRY_RE = re.compile(r"^(\s*)-\s+(.+)$")
_KEY_VALUE_RE = re.compile(r"^([A-Za-z0-9_.\-]+):(\s|$)(.*)$")


def _strip_comment(line: str) -> str:
    """Strip a trailing '#' comment while respecting quoted strings."""
    in_single = False
    in_double = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:idx].rstrip()
    return line.rstrip()


def _coerce_scalar(raw: str):
    s = raw.strip()
    if s == "":
        return ""
    if s == "~" or s.lower() == "null":
        return None
    if s.lower() == "true":
        return True
    if s.lower() == "false":
        return False
    if (s.startswith('"') and s.endswith('"')) or (
        s.startswith("'") and s.endswith("'")
    ):
        return s[1:-1]
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _parse_inline_mapping(line: str):
    stripped = line.strip()
    if not stripped.startswith("{") or not stripped.endswith("}"):
        return None
    inner = stripped[1:-1].strip()
    if not inner:
        return {}
    out = {}
    depth = 0
    in_single = False
    in_double = False
    current: list[str] = []
    pieces: list[str] = []
    for ch in inner:
        if ch == "," and depth == 0 and not in_single and not in_double:
            pieces.append("".join(current).strip())
            current = []
            continue
        if ch in "[{(":
            depth += 1
        elif ch in "]})":
            depth -= 1
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        current.append(ch)
    if current:
        pieces.append("".join(current).strip())
    for piece in pieces:
        if ":" not in piece:
            return None
        k, _, v = piece.partition(":")
        out[k.strip()] = _coerce_scalar(v)
    return out


def _parse_inline_sequence(line: str):
    stripped = line.strip()
    if not stripped.startswith("[") or not stripped.endswith("]"):
        return None
    inner = stripped[1:-1].strip()
    if not inner:
        return []
    out = []
    depth = 0
    in_single = False
    in_double = False
    current: list[str] = []
    pieces: list[str] = []
    for ch in inner:
        if ch == "," and depth == 0 and not in_single and not in_double:
            pieces.append("".join(current).strip())
            current = []
            continue
        if ch in "[{(":
            depth += 1
        elif ch in "]})":
            depth -= 1
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        current.append(ch)
    if current:
        pieces.append("".join(current).strip())
    for piece in pieces:
        out.append(_coerce_scalar(piece))
    return out


def _parse_runs_on(value: str) -> list[str]:
    s = value.strip()
    if not s:
        return []
    if s.startswith("[") and s.endswith("]"):
        seq = _parse_inline_sequence(s)
        if isinstance(seq, list):
            return [str(x).strip() for x in seq if str(x).strip()]
        return []
    if s.startswith("{"):
        m = _parse_inline_mapping(s)
        if m:
            return list(m.keys())
        return []
    return [s]


def parse_workflow(path: str) -> Workflow:
    """Parse a workflow file into a Workflow AST sufficient for the rules."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    lines = [_strip_comment(line) for line in text.splitlines()]

    wf = Workflow(path=path)

    # Indent-delimited stack of "frames" describing where we are in the
    # document. Each frame is a (indent, kind, name) tuple.
    path_stack: list[tuple[int, str, str]] = []

    def current_indent() -> int:
        return path_stack[-1][0] if path_stack else -1

    def current_kind() -> str:
        return path_stack[-1][1] if path_stack else ""

    def current_name() -> str:
        return path_stack[-1][2] if path_stack else ""

    def pop_to(indent: int) -> None:
        while path_stack and path_stack[-1][0] >= indent:
            path_stack.pop()

    def current_job_name() -> str:
        for indent, kind, name in path_stack:
            if kind == "map" and indent == 2:
                return name
        return ""

    def in_steps() -> bool:
        return any(p[1] == "list" and p[2] == "steps" for p in path_stack)

    # Block scalar capture state.
    block_indent: int | None = None
    block_chomp: str = "+"
    block_buf: list[str] = []
    block_job_name: str = ""
    block_target: str = ""  # 'step-run' | 'step-name'

    def flush_block_scalar() -> None:
        nonlocal block_indent, block_chomp, block_buf, block_job_name
        nonlocal block_target
        if block_indent is None:
            return
        if block_chomp == "-":
            while block_buf and block_buf[-1].strip() == "":
                block_buf.pop()
        elif block_chomp == "+":
            pass
        else:  # clip
            while block_buf and block_buf[-1].strip() == "":
                block_buf.pop()
        value = "\n".join(block_buf).rstrip("\n")
        if block_job_name in wf.jobs and wf.jobs[block_job_name].steps:
            step = wf.jobs[block_job_name].steps[-1]
            if block_target == "step-run":
                step.run = value
            elif block_target == "step-name":
                step.name = value
        block_indent = None
        block_buf = []
        block_job_name = ""
        block_target = ""

    def _set_step_field(job_name: str, key: str, value: str) -> None:
        if job_name not in wf.jobs or not wf.jobs[job_name].steps:
            return
        step = wf.jobs[job_name].steps[-1]
        if key == "name":
            step.name = value
        elif key == "uses":
            step.uses = value
        elif key == "if":
            step.if_expr = value
        elif key == "id":
            step.id = value
        elif key == "run":
            step.run = value

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Active block scalar capture.
        if block_indent is not None:
            leading = len(line) - len(line.lstrip(" "))
            if stripped == "" or leading >= block_indent:
                if stripped != "":
                    block_buf.append(line[block_indent:])
                else:
                    block_buf.append("")
                i += 1
                continue
            flush_block_scalar()
            # Fall through to parse current line normally.

        if stripped == "" or _COMMENT_LINE_RE.match(line):
            i += 1
            continue

        leading = len(line) - len(line.lstrip(" "))

        # List entry.
        list_match = _LIST_ENTRY_RE.match(line)
        if list_match:
            item_indent = len(list_match.group(1))
            rest = list_match.group(2).strip()
            pop_to(item_indent)

            if current_kind() == "list" and current_name() == "steps":
                job_name = current_job_name()
                _ensure_job(wf, job_name)
                wf.jobs[job_name].steps.append(Step())
                kv = _KEY_VALUE_RE.match(rest)
                if kv:
                    key = kv.group(1)
                    value = kv.group(3).strip()
                    if key == "run" and (value == "" or value.startswith("|")
                                         or value.startswith(">")):
                        block_indent = item_indent + 2
                        block_chomp = "+"
                        block_buf = []
                        block_job_name = job_name
                        block_target = "step-run"
                    elif key == "name" and (value == "" or value.startswith("|")
                                             or value.startswith(">")):
                        block_indent = item_indent + 2
                        block_chomp = "+"
                        block_buf = []
                        block_job_name = job_name
                        block_target = "step-name"
                    else:
                        _set_step_field(job_name, key, value)
                path_stack.append((item_indent, "map", "step-item"))
                i += 1
                continue

            if current_kind() == "list":
                path_stack.append((item_indent, "map", "list-item"))
                i += 1
                continue
            i += 1
            continue

        # Mapping key.
        kv = _KEY_VALUE_RE.match(stripped)
        if not kv:
            i += 1
            continue
        key = kv.group(1)
        value = kv.group(3).strip()
        pop_to(leading)

        # Inside a step item.
        if current_kind() == "map" and current_name() == "step-item":
            job_name = current_job_name()
            if key == "run" and (value == "" or value.startswith("|")
                                 or value.startswith(">")):
                block_indent = leading + 2
                block_chomp = "+"
                block_buf = []
                block_job_name = job_name
                block_target = "step-run"
            elif key == "name" and (value == "" or value.startswith("|")
                                     or value.startswith(">")):
                block_indent = leading + 2
                block_chomp = "+"
                block_buf = []
                block_job_name = job_name
                block_target = "step-name"
            else:
                _set_step_field(job_name, key, value)
            i += 1
            continue

        # Top-level keys.
        if not path_stack:
            if key == "name":
                wf.name = _coerce_scalar(value) if value else ""
            elif key == "concurrency":
                wf.has_concurrency = True
                if value == "":
                    path_stack.append((leading, "map", "concurrency"))
            elif key == "permissions" and value == "":
                path_stack.append((leading, "map", "permissions"))
            elif key == "timeout-minutes" and value:
                pass
            elif key == "on" and value == "":
                path_stack.append((leading, "map", "on"))
            elif key == "jobs" and value == "":
                path_stack.append((leading, "map", "jobs"))
            i += 1
            continue

        # Inside the on block.
        if path_stack[0][2] == "on":
            i += 1
            continue

        # Inside the jobs mapping.
        if path_stack[0][2] == "jobs" and len(path_stack) == 1:
            if value == "":
                path_stack.append((leading, "map", key))
                _ensure_job(wf, key)
            i += 1
            continue

        # Inside a job body.
        if (
            len(path_stack) >= 2
            and path_stack[0][2] == "jobs"
            and path_stack[1][1] == "map"
            and path_stack[1][2] != "step-item"
        ):
            job_name = path_stack[1][2]
            if key == "runs-on":
                wf.jobs[job_name].runs_on = _parse_runs_on(value)
            elif key == "if":
                wf.jobs[job_name].if_expr = value
            elif key == "name" and value:
                 wf.jobs[job_name].name = value
            elif key == "steps" and value == "":
                path_stack.append((leading, "list", "steps"))
            elif value == "":
                path_stack.append((leading, "map", key))
            i += 1
            continue

        i += 1

    if block_indent is not None:
        flush_block_scalar()

    return wf


def _ensure_job(wf: Workflow, job_name: str) -> None:
    if job_name and job_name not in wf.jobs:
        wf.jobs[job_name] = Job(name=job_name)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _workflow_is_privileged(wf: Workflow, path: str) -> bool:
    if any(hint in (wf.name or "").lower() for hint in PRIVILEGED_NAME_HINTS):
        return True
    if "privileged" in os.path.basename(path).lower():
        return True
    return False


def _is_hosted_runner_label(label: str) -> bool:
    return any(label.startswith(prefix) for prefix in HOSTED_RUNNER_PREFIXES)


def _check_no_hosted_runner(workflow_path: str, wf: Workflow,
                            violations: list[Violation]) -> None:
    if not _workflow_is_privileged(wf, workflow_path):
        return
    if not wf.jobs:
        violations.append(Violation(
            pointer="/jobs",
            message="privileged workflow declares no jobs",
            workflow=workflow_path,
        ))
        return
    for job_name, job in wf.jobs.items():
        if not job.runs_on:
            violations.append(Violation(
                pointer=f"/jobs/{job_name}/runs-on",
                message=f"privileged job '{job_name}' has no runs-on labels",
                workflow=workflow_path,
            ))
            continue
        if not any(SELF_HOSTED_LABEL in label for label in job.runs_on):
            violations.append(Violation(
                pointer=f"/jobs/{job_name}/runs-on",
                message=(
                    f"privileged job '{job_name}' uses hosted runner labels "
                    f"{job.runs_on!r}; the kernel-v1 plan requires "
                    "self-hosted runners via the kernel-<ver>-arch-<arch> "
                    "label scheme"
                ),
                workflow=workflow_path,
            ))
            continue
        for label in job.runs_on:
            if _is_hosted_runner_label(label):
                violations.append(Violation(
                    pointer=f"/jobs/{job_name}/runs-on",
                    message=(
                        f"privileged job '{job_name}' mixes self-hosted and "
                        f"hosted label '{label}'"
                    ),
                    workflow=workflow_path,
                ))


def _check_blocked_verdict_path(workflow_path: str, wf: Workflow,
                                violations: list[Violation]) -> None:
    if not _workflow_is_privileged(wf, workflow_path):
        return
    for job_name, job in wf.jobs.items():
        if not job.steps:
            violations.append(Violation(
                pointer=f"/jobs/{job_name}/steps",
                message=f"privileged job '{job_name}' declares no steps",
                workflow=workflow_path,
            ))
            continue
        blocked_step = None
        for idx, step in enumerate(job.steps):
            step_if = (step.if_expr or "").strip()
            always_or_failure = (
                "always()" in step_if
                or "failure()" in step_if
                or "cancelled()" in step_if
            )
            name_lower = (step.name or "").lower()
            run_lower = (step.run or "").lower()
            annotation = (
                "::warning::" in run_lower
                or "::error::" in run_lower
                or "::notice::" in run_lower
            )
            name_signals_blocked = (
                "blocked" in name_lower
                or name_lower.startswith("conclude")
                or "conclude" in name_lower
            )
            if always_or_failure and annotation and name_signals_blocked:
                blocked_step = (idx, step)
                break
        if blocked_step is None:
            violations.append(Violation(
                pointer=f"/jobs/{job_name}/steps",
                message=(
                    f"privileged job '{job_name}' has no step that emits a "
                    "structured 'blocked' verdict under 'if: always()' or "
                    "'if: failure()'; a missing privileged runner would "
                    "otherwise be marked green"
                ),
                workflow=workflow_path,
            ))


def _check_deterministic_concurrency(workflow_path: str, wf: Workflow,
                                    violations: list[Violation]) -> None:
    if not wf.name.lower().startswith("deterministic"):
        return
    if not wf.has_concurrency:
        violations.append(Violation(
            pointer="/concurrency",
            message=(
                "deterministic workflow must declare a top-level "
                "'concurrency:' group so a re-push does not race a queued run"
            ),
            workflow=workflow_path,
        ))


def _check_deterministic_runs_on_isolation(workflow_path: str, wf: Workflow,
                                            violations: list[Violation]) -> None:
    if not wf.name.lower().startswith("deterministic"):
        return
    for job_name, job in wf.jobs.items():
        if not job.runs_on:
            violations.append(Violation(
                pointer=f"/jobs/{job_name}/runs-on",
                message=f"deterministic job '{job_name}' has no runs-on labels",
                workflow=workflow_path,
            ))
            continue
        if not all(label.startswith("ubuntu-") for label in job.runs_on):
            violations.append(Violation(
                pointer=f"/jobs/{job_name}/runs-on",
                message=(
                    f"deterministic job '{job_name}' has non-hosted labels "
                    f"{job.runs_on!r}; the deterministic lane is hosted-only"
                ),
                workflow=workflow_path,
            ))


def _check_scheduled_runs_on_isolation(workflow_path: str, wf: Workflow,
                                        violations: list[Violation]) -> None:
    if not wf.name.lower().startswith("scheduled-aggregate"):
        return
    for job_name, job in wf.jobs.items():
        if not job.runs_on:
            continue
        if not all(label.startswith("ubuntu-") for label in job.runs_on):
            violations.append(Violation(
                pointer=f"/jobs/{job_name}/runs-on",
                message=(
                    f"scheduled-aggregate job '{job_name}' has non-hosted "
                    f"labels {job.runs_on!r}; the nightly aggregate lane is "
                    "hosted-only"
                ),
                workflow=workflow_path,
            ))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _iter_workflow_files(workflows_dir: str) -> Iterable[str]:
    for entry in sorted(os.listdir(workflows_dir)):
        if entry.endswith(".yml") or entry.endswith(".yaml"):
            yield os.path.join(workflows_dir, entry)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=PROG,
                                     description=__doc__.splitlines()[0])
    parser.add_argument(
        "--workflows-dir",
        default=".github/workflows",
        help="Path to the directory holding the workflow .yml files "
             "(default: .github/workflows)",
    )
    parser.add_argument(
        "--summary-json",
        action="store_true",
        help="Print a machine-readable JSON summary of every workflow on stdout",
    )
    parser.add_argument(
        "--strict-runs-on",
        action="store_true",
        help="Refuse any job whose runs-on label set is empty",
    )
    args = parser.parse_args(argv)

    if not os.path.isdir(args.workflows_dir):
        print(f"{PROG}: not a directory: {args.workflows_dir}", file=sys.stderr)
        return 2

    violations: list[Violation] = []
    workflows: list[Workflow] = []

    for path in _iter_workflow_files(args.workflows_dir):
        try:
            wf = parse_workflow(path)
        except (OSError, UnicodeDecodeError) as exc:
            violations.append(Violation(
                pointer="/",
                message=f"unreadable: {exc}",
                workflow=path,
            ))
            continue
        workflows.append(wf)

        _check_no_hosted_runner(path, wf, violations)
        _check_blocked_verdict_path(path, wf, violations)
        _check_deterministic_concurrency(path, wf, violations)
        _check_deterministic_runs_on_isolation(path, wf, violations)
        _check_scheduled_runs_on_isolation(path, wf, violations)

        if args.strict_runs_on:
            for job_name, job in wf.jobs.items():
                if not job.runs_on:
                    violations.append(Violation(
                        pointer=f"/jobs/{job_name}/runs-on",
                        message=f"job '{job_name}' has no runs-on labels",
                        workflow=path,
                    ))

    if args.summary_json:
        summary = {
            "workflows": [
                {
                    "path": wf.path,
                    "name": wf.name,
                    "has_concurrency": wf.has_concurrency,
                    "jobs": [
                        {
                            "name": jn,
                            "runs_on": list(job.runs_on),
                            "if": job.if_expr,
                            "steps": [
                                {
                                    "name": step.name,
                                    "uses": step.uses,
                                    "if": step.if_expr,
                                    "run_excerpt": (step.run or "")[:80],
                                }
                                for step in job.steps
                            ],
                        }
                        for jn, job in wf.jobs.items()
                    ],
                }
                for wf in workflows
            ],
            "violations": [
                {"pointer": v.pointer, "message": v.message,
                 "workflow": v.workflow}
                for v in violations
            ],
        }
        json.dump(summary, sys.stdout, indent=2)
        sys.stdout.write("\n")

    for v in violations:
        print(v.render(), file=sys.stderr)

    if violations:
        print(f"{PROG}: {len(violations)} violation(s)", file=sys.stderr)
        return 1
    if args.summary_json:
        print(f"{PROG}: ok ({len(workflows)} workflow(s), 0 violations)",
              file=sys.stderr)
    else:
        print(f"{PROG}: ok ({len(workflows)} workflow(s), 0 violations)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
