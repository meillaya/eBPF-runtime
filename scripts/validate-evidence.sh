#!/usr/bin/env bash
# scripts/validate-evidence.sh - validate kernel-v1 evidence ledger files.
#
# Usage:
#   ./scripts/validate-evidence.sh <file-or-dir>
#
# Walks the argument recursively when it is a directory. Each .json file
# inside is mapped to its matching schema by filename suffix, then validated
# against that schema with the best available Draft 2020-12 validator:
#
#   1. ajv-cli (ajv) when present
#   2. check-jsonschema (python-jsonschema CLI) when present
#   3. scripts/lib/check_jsonschema.py - pure-Python stdlib fallback
#
# Exit codes:
#   0  every file validated against its schema
#   1  one or more files failed validation (each failure prints a
#      validate-evidence: <path>: <json-pointer>: <message> line to stderr)
#   2  bad usage, missing schema, or unknown validator
#
# Schema resolution rules:
#   - The argument filename's basename (sans .json) is matched against the
#     SCHEMA_SUFFIX_TABLE below to pick the schema. Unknown basenames cause
#     the script to abort with a clear error.
#   - Schemas live under schemas/ and follow evidence-<kind>.v1.schema.json.
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail

LC_ALL=C
export LC_ALL

PROG="${0##*/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCHEMAS_DIR="${REPO_ROOT}/schemas"
LIB_DIR="${SCRIPT_DIR}/lib"
PYTHON_VALIDATOR="${LIB_DIR}/check_jsonschema.py"

# filename stem -> schema basename. First match wins; list specific prefixes
# before general ones. 'sensor-event' is an alias for the long
# 'privileged-sensor-event' prefix so invalid fixtures can use a shorter name.
SCHEMA_SUFFIX_TABLE='
task|evidence-task.v1.schema.json
privileged-sensor-event|evidence-privileged-sensor-event.v1.schema.json
sensor-event|evidence-privileged-sensor-event.v1.schema.json
compat-matrix|evidence-compat-matrix.v1.schema.json
fault-test|evidence-fault-test.v1.schema.json
benchmark-run|evidence-benchmark-run.v1.schema.json
final-verdict|evidence-final-verdict.v1.schema.json
'

usage() {
    cat <<'EOF'
Usage: validate-evidence.sh <file-or-dir>

Validate every .json file under the argument against its matching schema.

  file: validated directly; the filename stem is mapped to a schema by the
        table below.
  dir : walked recursively; every .json file inside is validated the same
        way.

Schemas used (from schemas/):
  task*                  -> evidence-task.v1.schema.json
  *privileged-sensor*    -> evidence-privileged-sensor-event.v1.schema.json
  *compat-matrix*        -> evidence-compat-matrix.v1.schema.json
  *fault-test*           -> evidence-fault-test.v1.schema.json
  *benchmark-run*        -> evidence-benchmark-run.v1.schema.json
  *final-verdict*        -> evidence-final-verdict.v1.schema.json

Exit codes: 0 all pass, 1 any failed validation, 2 bad usage.
EOF
}

err() {
    echo "${PROG}: $*" >&2
}

# Determine which validator to use. Preference: ajv, then check-jsonschema,
# then the pure-Python fallback. We probe once and cache the result so the
# walk below does not re-probe.
choose_validator() {
    if command -v ajv >/dev/null 2>&1; then
        echo ajv
        return 0
    fi
    if command -v check-jsonschema >/dev/null 2>&1; then
        echo check-jsonschema
        return 0
    fi
    if [[ -x "${PYTHON_VALIDATOR}" ]]; then
        echo python
        return 0
    fi
    return 1
}

# Pick the schema basename for a given JSON instance filename stem.
# Returns the basename on stdout, or aborts with an error on unknown stems.
resolve_schema() {
    local stem="$1"
    local line suffix schema
    while IFS='|' read -r suffix schema; do
        [[ -z "${suffix}" ]] && continue
        case "${stem}" in
            ${suffix}*) echo "${schema}"; return 0 ;;
        esac
    done <<<"${SCHEMA_SUFFIX_TABLE}"
    err "no schema maps to instance stem '${stem}'"
    return 1
}

# Run the chosen validator against one (schema, instance) pair. Returns the
# validator's exit status (0 OK, non-zero validation failure).
validate_one() {
    local validator="$1"
    local schema_path="$2"
    local instance_path="$3"
    case "${validator}" in
        ajv)
            ajv validate --spec=draft2020 -s "${schema_path}" -d "${instance_path}" \
                >/dev/null 2>&1
            ;;
        check-jsonschema)
            check-jsonschema --schemafile "${schema_path}" "${instance_path}" \
                >/dev/null 2>&1
            ;;
        python)
            python3 "${PYTHON_VALIDATOR}" "${schema_path}" "${instance_path}" \
                >/dev/null 2>&1
            ;;
    esac
}

# Translate the chosen validator's stderr into the canonical
# validate-evidence: <path>: <json-pointer>: <message> format. Each
# underlying validator emits slightly different shapes, so we re-run with
# stderr captured and rewrite the first line.
collect_failure_message() {
    local validator="$1"
    local schema_path="$2"
    local instance_path="$3"
    local out
    case "${validator}" in
        ajv)
            out="$(ajv validate --spec=draft2020 -s "${schema_path}" \
                -d "${instance_path}" 2>&1 >/dev/null || true)"
            # ajv prints 'instance/path/to/field error message'
            echo "${out}" | head -n 1
            ;;
        check-jsonschema)
            out="$(check-jsonschema --schemafile "${schema_path}" \
                "${instance_path}" 2>&1 >/dev/null || true)"
            echo "${out}" | head -n 1
            ;;
        python)
            out="$(python3 "${PYTHON_VALIDATOR}" "${schema_path}" \
                "${instance_path}" 2>&1 >/dev/null || true)"
            echo "${out}" | head -n 1
            ;;
    esac
}

# Walk a path, dispatching each .json file to validate_one. Returns the
# number of failed files via the FAILED global.
walk_and_validate() {
    local target="$1"
    local validator="$2"
    local f rel stem schema instance_path schema_path message status
    FAILED=0
    while IFS= read -r -d '' f; do
        rel="${f#${REPO_ROOT}/}"
        stem="${f##*/}"
        stem="${stem%.json}"
        if ! schema="$(resolve_schema "${stem}")"; then
            err "${rel}: cannot resolve schema (stem='${stem}')"
            FAILED=$((FAILED + 1))
            continue
        fi
        schema_path="${SCHEMAS_DIR}/${schema}"
        if [[ ! -f "${schema_path}" ]]; then
            err "${rel}: missing schema file '${schema_path}'"
            FAILED=$((FAILED + 1))
            continue
        fi
        instance_path="${f}"
        if validate_one "${validator}" "${schema_path}" "${instance_path}"; then
            continue
        fi
        status=$?
        message="$(collect_failure_message "${validator}" \
            "${schema_path}" "${instance_path}")"
        # Strip a leading absolute path and the legacy python validator
        # prefix so the canonical pointer does not duplicate them.
        message="${message#${instance_path}: }"
        message="${message#check_jsonschema: }"
        if [[ -z "${message}" ]]; then
            message="validator exit ${status}: schema ${schema} rejected ${stem}.json"
        fi
        # Canonical failure shape: '<prog>: <path>: <pointer>: <message>'.
        printf '%s: %s: %s\n' "${PROG}" "${rel}" \
            "$(printf '%s\n' "${message}" | head -n 1)" >&2
        FAILED=$((FAILED + 1))
    done < <(find "${target}" -type f -name '*.json' -print0 2>/dev/null \
        || true)
}

main() {
    if [[ $# -ne 1 ]]; then
        usage >&2
        return 2
    fi
    local target="$1"
    if [[ ! -e "${target}" ]]; then
        err "path does not exist: ${target}"
        return 2
    fi
    if ! validator="$(choose_validator)"; then
        err "no validator available (need ajv, check-jsonschema, or python)"
        return 2
    fi
    if [[ ! -d "${SCHEMAS_DIR}" ]]; then
        err "schemas directory missing: ${SCHEMAS_DIR}"
        return 2
    fi
    walk_and_validate "${target}" "${validator}"
    if [[ "${FAILED}" -gt 0 ]]; then
        err "${FAILED} file(s) failed validation"
        return 1
    fi
    return 0
}

main "$@"