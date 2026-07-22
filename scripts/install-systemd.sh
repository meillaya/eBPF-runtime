#!/usr/bin/env bash
# scripts/install-systemd.sh — install the kernel-v1-agent systemd service,
# tmpfiles.d, and sysusers.d configurations onto a Linux host.
#
# This script MUST be run as root (or via sudo).  It:
#   1. Validates that the kernel supports the required BPF capabilities
#   2. Installs the sysusers.d config and creates the kernel-v1 system user
#   3. Installs the tmpfiles.d config and creates /run/kernel-v1
#   4. Installs the systemd unit file
#   5. Runs daemon-reload, enables and starts the service
#
# Usage:
#   sudo scripts/install-systemd.sh [--binary /path/to/kernel-v1-agent]
#
# Flags:
#   --binary PATH   Path to the agent binary to install (default:
#                   target/release/agent).  The binary is copied to
#                   /usr/local/bin/kernel-v1-agent.
#   --no-start      Install and enable but do not start the service.
#   --help          Print usage and exit 0.
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail
LC_ALL=C
export LC_ALL

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEPLOY_DIR="${REPO_ROOT}/deploy/systemd"

SERVICE_NAME="kernel-v1-agent"
UNIT_FILE="${SERVICE_NAME}.service"
TMPFILES_CONF="${SERVICE_NAME}.tmpfiles.d.conf"
SYSUSERS_CONF="${SERVICE_NAME}.sysusers.d.conf"

INSTALL_UNIT_DIR="/etc/systemd/system"
INSTALL_TMPFILES_DIR="/usr/lib/tmpfiles.d"
INSTALL_SYSUSERS_DIR="/usr/lib/sysusers.d"
INSTALL_BIN_DIR="/usr/local/bin"
INSTALL_BIN="${INSTALL_BIN_DIR}/${SERVICE_NAME}"

BINARY_PATH="${REPO_ROOT}/target/release/agent"
NO_START=false

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die()  { echo "${PROG}: ERROR: $*" >&2; exit 1; }
info() { echo "${PROG}: $*"; }
warn() { echo "${PROG}: WARNING: $*" >&2; }

usage() {
    cat <<EOF
Usage: sudo ${PROG} [OPTIONS]

Install the kernel-v1-agent systemd service and supporting configs.

Options:
  --binary PATH   Agent binary to install (default: target/release/agent)
  --no-start      Install and enable but do not start the service
  --help          Show this help and exit
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)
            [[ $# -ge 2 ]] || die "--binary requires a path argument"
            BINARY_PATH="$2"; shift 2 ;;
        --no-start)
            NO_START=true; shift ;;
        --help|-h)
            usage ;;
        *)
            die "unknown argument: $1 (see --help)" ;;
    esac
done

# ---------------------------------------------------------------------------
# 0. Pre-flight checks
# ---------------------------------------------------------------------------
[[ "$(id -u)" -eq 0 ]] || die "this script must be run as root (use sudo)"

command -v systemctl >/dev/null 2>&1 \
    || die "systemctl not found; this host does not appear to run systemd"

[[ -f "${DEPLOY_DIR}/${UNIT_FILE}" ]] \
    || die "unit file not found: ${DEPLOY_DIR}/${UNIT_FILE}"
[[ -f "${DEPLOY_DIR}/${TMPFILES_CONF}" ]] \
    || die "tmpfiles config not found: ${DEPLOY_DIR}/${TMPFILES_CONF}"
[[ -f "${DEPLOY_DIR}/${SYSUSERS_CONF}" ]] \
    || die "sysusers config not found: ${DEPLOY_DIR}/${SYSUSERS_CONF}"

# ---------------------------------------------------------------------------
# 1. Validate kernel BPF capability support
# ---------------------------------------------------------------------------
info "validating kernel BPF capability support..."

# Check that the kernel exposes BTF (required for CO-RE BPF programs).
[[ -r /sys/kernel/btf/vmlinux ]] \
    || warn "/sys/kernel/btf/vmlinux not readable; CO-RE BPF may fail at load time"

# Check bpffs is mounted (the agent needs /sys/fs/bpf for pinning).
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
    warn "/sys/fs/bpf is not a mount point; the agent will attempt to mount bpffs"
fi

# Check tracefs is available (the agent reads /sys/kernel/debug/tracing).
if [[ ! -d /sys/kernel/debug/tracing ]]; then
    warn "tracefs not found at /sys/kernel/debug/tracing; tracing sensors may be unavailable"
fi

# Verify the kernel supports the four required capabilities by checking
# /proc/sys/kernel/cap_last_cap >= 39 (CAP_BPF is bit 39).
CAP_LAST_CAP="$(cat /proc/sys/kernel/cap_last_cap 2>/dev/null || echo 0)"
if [[ "${CAP_LAST_CAP}" -lt 39 ]]; then
    die "kernel cap_last_cap=${CAP_LAST_CAP} < 39; CAP_BPF (bit 39) is not supported by this kernel (need >= 5.8)"
fi
info "kernel supports CAP_BPF (cap_last_cap=${CAP_LAST_CAP})"

# Check unprivileged_bpf_disabled sysctl — if set to 2, BPF is permanently
# disabled and the service cannot function.
BPF_DISABLED="$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 0)"
if [[ "${BPF_DISABLED}" -eq 2 ]]; then
    die "kernel.unprivileged_bpf_disabled=2; BPF is permanently disabled on this host"
elif [[ "${BPF_DISABLED}" -eq 1 ]]; then
    info "unprivileged_bpf_disabled=1; ambient capabilities will bypass this (expected)"
fi

# ---------------------------------------------------------------------------
# 2. Install the agent binary
# ---------------------------------------------------------------------------
if [[ -f "${BINARY_PATH}" ]]; then
    info "installing agent binary: ${BINARY_PATH} -> ${INSTALL_BIN}"
    install -m 0755 -o root -g root "${BINARY_PATH}" "${INSTALL_BIN}"
else
    warn "agent binary not found at ${BINARY_PATH}; skipping binary install"
    warn "copy the binary to ${INSTALL_BIN} manually before starting the service"
fi

# ---------------------------------------------------------------------------
# 3. Install sysusers.d config and create the system user
# ---------------------------------------------------------------------------
info "installing sysusers.d config..."
install -m 0644 -o root -g root \
    "${DEPLOY_DIR}/${SYSUSERS_CONF}" \
    "${INSTALL_SYSUSERS_DIR}/${SERVICE_NAME}.conf"

# Create the user/group immediately (systemd-sysusers is idempotent).
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers "${INSTALL_SYSUSERS_DIR}/${SERVICE_NAME}.conf"
    info "system user 'kernel-v1' created via systemd-sysusers"
else
    # Fallback for systems without systemd-sysusers.
    if ! getent group kernel-v1 >/dev/null 2>&1; then
        groupadd --system kernel-v1
    fi
    if ! getent passwd kernel-v1 >/dev/null 2>&1; then
        useradd --system --gid kernel-v1 --home-dir /var/lib/kernel-v1 \
            --shell /usr/sbin/nologin --comment "kernel-v1 eBPF agent" kernel-v1
    fi
    info "system user 'kernel-v1' created via useradd fallback"
fi

# ---------------------------------------------------------------------------
# 4. Install tmpfiles.d config and create runtime directory
# ---------------------------------------------------------------------------
info "installing tmpfiles.d config..."
install -m 0644 -o root -g root \
    "${DEPLOY_DIR}/${TMPFILES_CONF}" \
    "${INSTALL_TMPFILES_DIR}/${SERVICE_NAME}.conf"

# Create the runtime directory immediately (systemd-tmpfiles is idempotent).
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create "${INSTALL_TMPFILES_DIR}/${SERVICE_NAME}.conf"
    info "runtime directory /run/kernel-v1 created via systemd-tmpfiles"
else
    mkdir -p /run/kernel-v1
    chown kernel-v1:kernel-v1 /run/kernel-v1
    chmod 0750 /run/kernel-v1
    info "runtime directory /run/kernel-v1 created via mkdir fallback"
fi

# ---------------------------------------------------------------------------
# 5. Install the systemd unit file
# ---------------------------------------------------------------------------
info "installing systemd unit..."
install -m 0644 -o root -g root \
    "${DEPLOY_DIR}/${UNIT_FILE}" \
    "${INSTALL_UNIT_DIR}/${UNIT_FILE}"

# ---------------------------------------------------------------------------
# 6. Reload, enable, and start
# ---------------------------------------------------------------------------
info "reloading systemd daemon..."
systemctl daemon-reload

info "enabling ${SERVICE_NAME}..."
systemctl enable "${SERVICE_NAME}"

if [[ "${NO_START}" == "true" ]]; then
    info "skipping service start (--no-start)"
else
    info "starting ${SERVICE_NAME}..."
    if systemctl start "${SERVICE_NAME}"; then
        info "service started successfully"
        systemctl --no-pager --full status "${SERVICE_NAME}" || true
    else
        warn "service failed to start; check: journalctl -u ${SERVICE_NAME} -n 50"
        exit 1
    fi
fi

info "installation complete"
info ""
info "Useful commands:"
info "  systemctl status ${SERVICE_NAME}"
info "  journalctl -u ${SERVICE_NAME} -f"
info "  systemctl stop ${SERVICE_NAME}"
info "  systemctl disable ${SERVICE_NAME}"
