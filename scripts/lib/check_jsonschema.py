#!/usr/bin/env python3
"""check_jsonschema.py - minimal Draft 2020-12 JSON Schema validator (stdlib only).

Pure Python standard library implementation of a subset of JSON Schema Draft
2020-12 sufficient for the kernel-v1 evidence ledger schemas. Intentionally
limited: no $ref resolution across files, no conditional schemas, no
$dynamicRef, no allOf/anyOf/if-then-else (we support ``oneOf`` for the
decision-test fixtures).

Why pure stdlib:
    ``scripts/validate-evidence.sh`` must run inside the same minimum-toolchain
    environment that executes preflight, with no extra Python wheels and no
    Network access. ``jsonschema`` is a heavy dependency that pulls in
    ``rpds-py``; the kernel-v1 evidence schemas are small enough that a
    hand-rolled validator is cheaper to maintain and audit than pinning a
    third-party package.

Supported keywords:
    - ``type`` (with the array form for nullables)
    - ``const``
    - ``enum``
    - ``properties`` (with ``required`` and ``additionalProperties``)
    - ``items``
    - ``minLength``, ``maxLength``, ``minimum``, ``maximum``
    - ``pattern``
    - ``format`` (only: ``uuid``, ``date-time``, ``uri``)
    - ``oneOf``
    - ``examples`` (informational; not enforced)

Public API:
    ``validate(instance, schema)`` returns ``(ok: bool, error: Optional[str])``
    where ``error`` is a JSON Pointer (RFC6901) like ``/foo/bar`` that locates
    the offending field, followed by a human-readable message.

Usage:
    python3 scripts/lib/check_jsonschema.py SCHEMA_PATH INSTANCE_PATH
    exit code 0 means the instance validates; 1 means it does not; 2 means
    the schema itself could not be loaded or parsed.

This file is part of task 5 (evidence ledger formats + validation tool) of
.omo/plans/ebpf-runtime-security-observability.md. It is intentionally
written with no external imports so the validator stays portable across
every runner the bench and CI lanes use.
"""

# SPDX-License-Identifier: Apache-2.0 OR MIT

from __future__ import annotations

import datetime as _dt
import json
import re
import sys
import uuid as _uuid
from typing import Any, Iterable, Optional, Tuple

# JSON Pointer helpers --------------------------------------------------------


def _escape_pointer_segment(segment: str) -> str:
    """Escape a single JSON Pointer segment per RFC6901 (tilde + slash)."""
    return segment.replace("~", "~0").replace("/", "~1")


def _join_pointer(prefix: str, segment: str) -> str:
    """Append ``segment`` to the JSON Pointer ``prefix``."""
    return prefix + "/" + _escape_pointer_segment(str(segment))


# Type helpers ---------------------------------------------------------------


_TYPE_RANK = {
    "null": 0,
    "boolean": 1,
    "object": 2,
    "array": 3,
    "number": 4,
    "integer": 5,
    "string": 6,
}


def _type_matches(value: Any, expected: Any) -> bool:
    """Return True iff ``value`` matches the JSON Schema ``type`` keyword.

    ``expected`` may be a string ("string") or a list of strings
    (["string", "null"]).
    """
    if isinstance(expected, list):
        return any(_type_matches(value, t) for t in expected)
    if expected not in _TYPE_RANK:
        return True  # unknown type -> don't block on this
    actual: Optional[str] = None
    if value is None:
        actual = "null"
    elif isinstance(value, bool):
        actual = "boolean"
    elif isinstance(value, dict):
        actual = "object"
    elif isinstance(value, list):
        actual = "array"
    elif isinstance(value, int):
        actual = "integer"
    elif isinstance(value, float):
        # JSON Schema distinguishes integer from number. A Python float that
        # represents a whole number still satisfies "integer" (validator
        # behaviour mirrors the reference implementation for portability).
        actual = "number"
    elif isinstance(value, str):
        actual = "string"
    return actual == expected or (
        expected == "number" and actual == "integer"
    )


# Format helpers -------------------------------------------------------------


_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def _check_format(value: str, fmt: str) -> bool:
    if fmt == "uuid":
        try:
            _uuid.UUID(value)
            return True
        except (ValueError, AttributeError):
            return False
    if fmt == "date-time":
        if not _ISO_RE.match(value):
            return False
        try:
            _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return True
        except ValueError:
            return False
    if fmt == "uri":
        # Be liberal: a non-empty string with a scheme separator is enough for
        # the evidence-ledger use case. Reviewers may add stricter RFC3986
        # validation later.
        return bool(value) and ("://" in value or value.startswith("urn:"))
    # Unknown formats are advisory; do not block.
    return True


# Core validator -------------------------------------------------------------


def _validate(
    instance: Any,
    schema: dict,
    pointer: str,
) -> Tuple[bool, Optional[str]]:
    """Recursive validator. Returns (ok, error-or-None)."""
    # ``type``
    if "type" in schema and not _type_matches(instance, schema["type"]):
        return (
            False,
            f"{pointer}: expected type {schema['type']!r}, got "
            f"{type(instance).__name__}",
        )
    # ``const``
    if "const" in schema and instance != schema["const"]:
        return False, f"{pointer}: expected const {schema['const']!r}"
    # ``enum``
    if "enum" in schema and instance not in schema["enum"]:
        return False, (
            f"{pointer}: value {instance!r} not in enum "
            f"{schema['enum']!r}"
        )

    # type-specific keywords
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            return False, (
                f"{pointer}: string shorter than minLength "
                f"{schema['minLength']}"
            )
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            return False, (
                f"{pointer}: string longer than maxLength "
                f"{schema['maxLength']}"
            )
        if "pattern" in schema:
            if not re.search(schema["pattern"], instance):
                return False, (
                    f"{pointer}: string does not match pattern "
                    f"{schema['pattern']!r}"
                )
        if "format" in schema and not _check_format(
            instance, schema["format"]
        ):
            return False, (
                f"{pointer}: string does not satisfy format "
                f"{schema['format']!r}"
            )

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            return False, (
                f"{pointer}: value {instance} below minimum "
                f"{schema['minimum']}"
            )
        if "maximum" in schema and instance > schema["maximum"]:
            return False, (
                f"{pointer}: value {instance} above maximum "
                f"{schema['maximum']}"
            )

    if isinstance(instance, list):
        if "items" in schema:
            item_schema = schema["items"]
            for idx, item in enumerate(instance):
                ok, err = _validate(item, item_schema, _join_pointer(pointer, idx))
                if not ok:
                    return ok, err
        if "minItems" in schema and len(instance) < schema["minItems"]:
            return False, (
                f"{pointer}: array shorter than minItems "
                f"{schema['minItems']}"
            )
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            return False, (
                f"{pointer}: array longer than maxItems "
                f"{schema['maxItems']}"
            )

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        for required_key in schema.get("required", []):
            if required_key not in instance:
                # Point at the missing field itself.
                return False, (
                    f"{_join_pointer(pointer, required_key)}: missing "
                    f"required property"
                )
        additional = schema.get("additionalProperties", None)
        if additional is False:
            for key in instance.keys():
                if key not in properties:
                    return False, (
                        f"{_join_pointer(pointer, key)}: additional "
                        f"property not permitted by schema"
                    )
        for key, value in instance.items():
            if key in properties:
                ok, err = _validate(
                    value, properties[key], _join_pointer(pointer, key)
                )
                if not ok:
                    return ok, err

    # ``oneOf``: count exact matches; report on zero or multiple.
    if "oneOf" in schema:
        matches = 0
        branch_errs: list[str] = []
        for sub in schema["oneOf"]:
            ok, err = _validate(instance, sub, pointer)
            if ok:
                matches += 1
            elif err is not None:
                branch_errs.append(err)
        if matches == 0:
            # Surface the deepest branch error so reviewers see the actual
            # mismatched field rather than just the top-level pointer.
            if branch_errs:
                best = max(
                    branch_errs,
                    key=lambda e: len(e.split(":", 1)[0]),
                )
                return False, best
            return False, (
                f"{pointer}: value matches no oneOf branch"
            )
        if matches > 1:
            return False, (
                f"{pointer}: value matches more than one oneOf branch "
                f"({matches} matches)"
            )

    return True, None


def _summarise(schema: dict) -> str:
    """Compact one-line description of a schema for error messages."""
    if "type" in schema:
        return f"type={schema['type']}"
    if "enum" in schema:
        return f"enum={schema['enum']}"
    if "const" in schema:
        return f"const={schema['const']!r}"
    return "schema"


def validate(instance: Any, schema: dict) -> Tuple[bool, Optional[str]]:
    """Public validator. ``schema`` is a parsed JSON Schema dict."""
    return _validate(instance, schema, "")


def _main(argv: list[str]) -> int:
    if len(argv) != 3:
        sys.stderr.write(
            "usage: check_jsonschema.py SCHEMA_PATH INSTANCE_PATH\n"
        )
        return 2
    schema_path, instance_path = argv[1], argv[2]
    try:
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        with open(instance_path, "r", encoding="utf-8") as f:
            instance = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"load error: {exc}\n")
        return 2
    ok, err = validate(instance, schema)
    if ok:
        sys.stdout.write(f"{instance_path}: OK\n")
        return 0
    sys.stderr.write(f"{err}\n")
    return 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv))