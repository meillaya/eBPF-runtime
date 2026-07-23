#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# scripts/dev-vm.sh — QEMU VM launcher for privileged BPF testing.
#
# Launches a CachyOS/Arch Linux VM with:
#   - 4 vCPUs, 8 GB RAM, KVM acceleration
#   - CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN + CAP_NET_ADMIN (guest runs
#     as root; capabilities are inherent to the guest root user)
#   - kernel.unprivileged_bpf_disabled=0 (set via sysctl on boot)
#   - Workspace mounted via virtio-fs (tag=kernel-v1)
#   - BPF toolchain: clang, llvm, libbpf, bpftool, rustup
#
# Prerequisites (host):
#   - qemu-system-x86_64 (package: qemu-full or qemu-desktop)
#   - KVM module loaded:   sudo modprobe kvm_intel  (or kvm_amd)
#   - virtiofsd:           package: virtiofsd
#   - ~20 GB free disk for the VM image
#   - SSH key at ~/.ssh/id_ed25519.pub (or ~/.ssh/id_rsa.pub)
#
# Disk image — two paths:
#   PATH A (recommended): Download a CachyOS/Arch cloud image.
#     The script downloads a generic Arch cloud image and customizes it.
#     Set KERNEL_V1_VM_IMAGE to a pre-built qcow2 to skip download.
#
#   PATH B (advanced): Build with mkosi or pacstrap.
#     mkosi:
#       mkosi --distribution=arch --format=disk --output=arch-vm.raw
#       qemu-img convert -f raw -O qcow2 arch-vm.raw disk.qcow2
#     pacstrap:
#       See the Arch Wiki "Install Arch Linux in a VM" guide.
#       Create a qcow2, partition, pacstrap base linux, install grub.
#
# Usage:
#   scripts/dev-vm.sh              # create (if needed) + start VM
#   scripts/dev-vm.sh --ssh        # start VM + interactive SSH session
#   scripts/dev-vm.sh --run CMD    # start VM + run one-shot command
#   scripts/dev-vm.sh --destroy    # stop VM + delete all state
#   scripts/dev-vm.sh --status     # show VM state
#
# Environment overrides:
#   KERNEL_V1_VM_DIR      VM state directory (default: ~/.local/share/kernel-v1-vm)
#   KERNEL_V1_VM_IMAGE    Path to a pre-built qcow2 image (skips download)
#   KERNEL_V1_VM_CPUS     vCPU count (default: 4)
#   KERNEL_V1_VM_RAM      RAM in MB (default: 8192)
#   KERNEL_V1_VM_SSH_PORT Host SSH port (default: 2222)

set -euo pipefail
LC_ALL=C
export LC_ALL

PROG="${0##*/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ----------------------------- defaults --------------------------------
VM_DIR="${KERNEL_V1_VM_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/kernel-v1-vm}"
VM_DISK="${VM_DIR}/disk.qcow2"
VM_PID_FILE="${VM_DIR}/qemu.pid"
VM_VIRTIOFS_SOCK="${VM_DIR}/virtiofsd.sock"
VM_VIRTIOFS_PID="${VM_DIR}/virtiofsd.pid"
VM_SSH_PORT="${KERNEL_V1_VM_SSH_PORT:-2222}"
VM_CPUS="${KERNEL_V1_VM_CPUS:-4}"
VM_RAM="${KERNEL_V1_VM_RAM:-8192}"
VM_IMAGE_URL="${KERNEL_V1_VM_IMAGE:-}"
VM_USER="root"

# Arch Linux cloud image (generic, x86_64).
# This is a nocloud image with root login enabled via SSH key injection.
DEFAULT_IMAGE_URL="https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2"

# ----------------------------- helpers ---------------------------------

log()  { printf '[%s] %s\n' "${PROG}" "$*"; }
err()  { printf '[%s] ERROR: %s\n' "${PROG}" "$*" >&2; }
die()  { err "$@"; exit 1; }

vm_running() {
    [[ -f "${VM_PID_FILE}" ]] && kill -0 "$(cat "${VM_PID_FILE}")" 2>/dev/null
}

virtiofsd_running() {
    [[ -f "${VM_VIRTIOFS_PID}" ]] && kill -0 "$(cat "${VM_VIRTIOFS_PID}")" 2>/dev/null
}

find_ssh_pubkey() {
    local key
    for key in "${HOME}/.ssh/id_ed25519.pub" "${HOME}/.ssh/id_rsa.pub" "${HOME}/.ssh/id_ecdsa.pub"; do
        if [[ -f "${key}" ]]; then
            printf '%s' "${key}"
            return 0
        fi
    done
    return 1
}

ssh_cmd() {
    ssh -q \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -p "${VM_SSH_PORT}" \
        "${VM_USER}@127.0.0.1" \
        "$@"
}

wait_for_ssh() {
    local max_wait=120
    local elapsed=0
    log "waiting for SSH on 127.0.0.1:${VM_SSH_PORT}..."
    while ! ssh_cmd "true" 2>/dev/null; do
        elapsed=$((elapsed + 2))
        if [[ ${elapsed} -ge ${max_wait} ]]; then
            die "SSH not available after ${max_wait}s"
        fi
        sleep 2
    done
    log "SSH ready (${elapsed}s)"
}

# ----------------------------- prerequisites ---------------------------

check_prereqs() {
    command -v qemu-system-x86_64 >/dev/null 2>&1 \
        || die "qemu-system-x86_64 not found. Install: sudo pacman -S qemu-full"

    if [[ ! -e /dev/kvm ]]; then
        die "/dev/kvm not found. Load the module: sudo modprobe kvm_intel (or kvm_amd)"
    fi

    command -v virtiofsd >/dev/null 2>&1 \
        || die "virtiofsd not found. Install: sudo pacman -S virtiofsd"

    command -v ssh >/dev/null 2>&1 \
        || die "ssh client not found"
}

# ----------------------------- disk image ------------------------------

ensure_disk() {
    if [[ -f "${VM_DISK}" ]]; then
        log "disk image exists: ${VM_DISK}"
        return 0
    fi

    mkdir -p "${VM_DIR}"

    if [[ -n "${VM_IMAGE_URL}" && -f "${VM_IMAGE_URL}" ]]; then
        log "using pre-built image: ${VM_IMAGE_URL}"
        cp "${VM_IMAGE_URL}" "${VM_DISK}"
        return 0
    fi

    local url="${VM_IMAGE_URL:-${DEFAULT_IMAGE_URL}}"
    log "downloading Arch cloud image from ${url}..."
    log "(~600 MB; set KERNEL_V1_VM_IMAGE to a local qcow2 to skip)"

    if command -v curl >/dev/null 2>&1; then
        curl -fSL --progress-bar -o "${VM_DISK}.tmp" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "${VM_DISK}.tmp" "${url}"
    else
        die "neither curl nor wget found; download the image manually to ${VM_DISK}"
    fi

    mv "${VM_DISK}.tmp" "${VM_DISK}"

    # Resize to 20 GB for workspace + toolchain.
    log "resizing disk to 20G..."
    qemu-img resize "${VM_DISK}" 20G

    # Inject SSH public key for root login.
    local pubkey
    if pubkey="$(find_ssh_pubkey)"; then
        log "injecting SSH key: ${pubkey}"
        # Use guestfish (libguestfs) if available, otherwise document
        # the manual step.
        if command -v guestfish >/dev/null 2>&1; then
            guestfish --rw -a "${VM_DISK}" -i \
                mkdir-p /root/.ssh : \
                upload "${pubkey}" /root/.ssh/authorized_keys : \
                chmod 0700 /root/.ssh : \
                chmod 0600 /root/.ssh/authorized_keys
        else
            log "guestfish not found — SSH key injection skipped."
            log "On first boot, use the serial console to add your key:"
            log "  mkdir -p /root/.ssh && echo '$(cat "${pubkey}")' >> /root/.ssh/authorized_keys"
        fi
    else
        log "no SSH public key found — set one up for SSH access."
        log "  ssh-keygen -t ed25519"
    fi

    log "disk image ready: ${VM_DISK}"
}

# ----------------------------- VM lifecycle ----------------------------

start_vm() {
    if vm_running; then
        log "VM already running (pid $(cat "${VM_PID_FILE}"))"
        return 0
    fi

    check_prereqs
    ensure_disk
    mkdir -p "${VM_DIR}"

    # Clean up stale sockets / pid files.
    rm -f "${VM_VIRTIOFS_SOCK}" "${VM_PID_FILE}"

    # --- Start virtiofsd (workspace sharing) ---
    log "starting virtiofsd (tag=kernel-v1, dir=${WORKSPACE})..."
    virtiofsd \
        --socket-path="${VM_VIRTIOFS_SOCK}" \
        --shared-dir="${WORKSPACE}" \
        --sandbox none \
        &>"${VM_DIR}/virtiofsd.log" &
    echo $! > "${VM_VIRTIOFS_PID}"

    # Wait for the virtiofsd socket.
    local elapsed=0
    while [[ ! -S "${VM_VIRTIOFS_SOCK}" ]]; do
        elapsed=$((elapsed + 1))
        [[ ${elapsed} -ge 10 ]] && die "virtiofsd socket not created after 10s"
        sleep 1
    done

    # --- Start QEMU ---
    log "starting QEMU (${VM_CPUS} vCPUs, ${VM_RAM} MB RAM, KVM)..."
    qemu-system-x86_64 \
        -enable-kvm \
        -cpu host \
        -smp "${VM_CPUS}" \
        -m "${VM_RAM}" \
        -drive "file=${VM_DISK},format=qcow2,if=virtio,cache=writeback" \
        -chardev "socket,id=virtiofs-char,path=${VM_VIRTIOFS_SOCK}" \
        -device vhost-user-fs-pci,chardev=virtiofs-char,tag=kernel-v1 \
        -netdev "user,id=net0,hostfwd=tcp::${VM_SSH_PORT}-:22" \
        -device virtio-net-pci,netdev=net0 \
        -nographic \
        -daemonize \
        -pidfile "${VM_PID_FILE}" \
        -serial "file:${VM_DIR}/serial.log"

    log "QEMU started (pid $(cat "${VM_PID_FILE}"))"
    wait_for_ssh
}

stop_vm() {
    if vm_running; then
        local pid
        pid="$(cat "${VM_PID_FILE}")"
        log "stopping QEMU (pid ${pid})..."
        kill "${pid}" 2>/dev/null || true
        # Wait for process to exit.
        local elapsed=0
        while kill -0 "${pid}" 2>/dev/null; do
            elapsed=$((elapsed + 1))
            [[ ${elapsed} -ge 10 ]] && { kill -9 "${pid}" 2>/dev/null || true; break; }
            sleep 1
        done
        rm -f "${VM_PID_FILE}"
        log "QEMU stopped"
    else
        log "VM not running"
        rm -f "${VM_PID_FILE}"
    fi

    if virtiofsd_running; then
        local pid
        pid="$(cat "${VM_VIRTIOFS_PID}")"
        log "stopping virtiofsd (pid ${pid})..."
        kill "${pid}" 2>/dev/null || true
        rm -f "${VM_VIRTIOFS_PID}"
    fi
    rm -f "${VM_VIRTIOFS_SOCK}"
}

destroy_vm() {
    stop_vm
    if [[ -d "${VM_DIR}" ]]; then
        log "destroying VM state: ${VM_DIR}"
        rm -rf "${VM_DIR}"
        log "VM state destroyed"
    else
        log "no VM state to destroy"
    fi
}

# ----------------------------- guest setup -----------------------------

setup_guest() {
    log "configuring guest for BPF development..."

    ssh_cmd 'bash -s' <<'GUEST_SETUP'
set -euo pipefail

echo "[guest] setting sysctl for BPF..."
sysctl -w kernel.unprivileged_bpf_disabled=0

# Persist across reboots.
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-kernel-v1-bpf.conf <<'SYSCTL'
# kernel-v1 dev VM: enable unprivileged BPF for testing.
kernel.unprivileged_bpf_disabled = 0
SYSCTL

echo "[guest] mounting workspace via virtio-fs..."
MOUNT_POINT="/home/mei/projects/kernels/kernel-v1"
mkdir -p "${MOUNT_POINT}"
if ! mountpoint -q "${MOUNT_POINT}" 2>/dev/null; then
    mount -t virtiofs kernel-v1 "${MOUNT_POINT}"
fi

# Persist the mount.
if ! grep -q 'kernel-v1' /etc/fstab 2>/dev/null; then
    echo "kernel-v1 ${MOUNT_POINT} virtiofs defaults 0 0" >> /etc/fstab
fi

echo "[guest] installing BPF toolchain..."
if command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm --needed \
        clang llvm lld libbpf bpftool \
        base-devel linux-headers \
        2>&1 | tail -5

    # rustup (if not already installed).
    if ! command -v rustup >/dev/null 2>&1; then
        echo "[guest] installing rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --default-toolchain 1.95.0
        # shellcheck source=/dev/null
        source "${HOME}/.cargo/env" 2>/dev/null || true
    fi
else
    echo "[guest] WARNING: pacman not found; install clang/llvm/libbpf/bpftool/rustup manually"
fi

echo "[guest] verifying BPF capabilities..."
echo "  CapEff: $(awk '/^CapEff:/ {print $2}' /proc/self/status)"
echo "  unprivileged_bpf_disabled: $(cat /proc/sys/kernel/unprivileged_bpf_disabled)"
echo "  BTF: $(ls /sys/kernel/btf/vmlinux 2>/dev/null && echo 'present' || echo 'MISSING')"
echo "  LSM: $(cat /sys/kernel/security/lsm 2>/dev/null || echo 'unknown')"

echo "[guest] setup complete"
GUEST_SETUP

    log "guest setup complete"
}

# ----------------------------- status ----------------------------------

show_status() {
    if vm_running; then
        log "VM is RUNNING (pid $(cat "${VM_PID_FILE}"))"
        log "  SSH: ssh -p ${VM_SSH_PORT} ${VM_USER}@127.0.0.1"
        log "  Disk: ${VM_DISK}"
        log "  Serial log: ${VM_DIR}/serial.log"
        if ssh_cmd "true" 2>/dev/null; then
            log "  SSH: reachable"
            # shellcheck disable=SC2016 # intentional: expand on remote guest
            ssh_cmd 'echo "  Kernel: $(uname -r)"; echo "  CapEff: $(awk "/^CapEff:/ {print \$2}" /proc/self/status)"' 2>/dev/null || true
        else
            log "  SSH: not reachable"
        fi
    else
        log "VM is STOPPED"
    fi

    if virtiofsd_running; then
        log "virtiofsd is RUNNING (pid $(cat "${VM_VIRTIOFS_PID}"))"
    fi
}

# ----------------------------- arg parsing -----------------------------

usage() {
    cat <<EOF
Usage: ${PROG} [OPTIONS]

Launch a QEMU VM with BPF capabilities for privileged testing.

Options:
  --ssh          Start VM and open an interactive SSH session
  --run CMD      Start VM and run a one-shot command via SSH
  --destroy      Stop VM and delete all state (disk, sockets, logs)
  --status       Show VM state
  -h, --help     Show this help

Environment:
  KERNEL_V1_VM_DIR       VM state dir (default: ~/.local/share/kernel-v1-vm)
  KERNEL_V1_VM_IMAGE     Pre-built qcow2 path (skips download)
  KERNEL_V1_VM_CPUS      vCPU count (default: 4)
  KERNEL_V1_VM_RAM       RAM in MB (default: 8192)
  KERNEL_V1_VM_SSH_PORT  Host SSH port (default: 2222)

Prerequisites:
  - qemu-system-x86_64, KVM module loaded, virtiofsd
  - ~20 GB free disk for the VM image
  - SSH key pair (ssh-keygen -t ed25519)

Disk image (two paths):
  A) Automatic: downloads an Arch cloud image on first run.
  B) Manual: build with mkosi or pacstrap, set KERNEL_V1_VM_IMAGE.
     mkosi:
       mkosi --distribution=arch --format=disk --output=arch-vm.raw
       qemu-img convert -f raw -O qcow2 arch-vm.raw disk.qcow2
     pacstrap:
       See Arch Wiki "Install Arch Linux in a VM".

Examples:
  ${PROG} --ssh                          # interactive session
  ${PROG} --run 'cargo nextest run'      # one-shot command
  ${PROG} --run 'scripts/run-privileged-tests.sh --kernel current --arch x86_64 --out /tmp/evidence.json'
  ${PROG} --destroy                      # clean up
EOF
}

MODE="start"
RUN_CMD=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh)
            MODE="ssh"
            shift
            ;;
        --run)
            [[ $# -ge 2 ]] || die "--run requires a command"
            MODE="run"
            RUN_CMD="$2"
            shift 2
            ;;
        --destroy)
            MODE="destroy"
            shift
            ;;
        --status)
            MODE="status"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            err "unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

# ----------------------------- main ------------------------------------

case "${MODE}" in
    status)
        show_status
        ;;
    destroy)
        destroy_vm
        ;;
    ssh)
        start_vm
        setup_guest
        log "opening SSH session (exit with Ctrl-D or 'exit')..."
        ssh -t \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -p "${VM_SSH_PORT}" \
            "${VM_USER}@127.0.0.1"
        ;;
    run)
        start_vm
        setup_guest
        log "running: ${RUN_CMD}"
        ssh_cmd "${RUN_CMD}"
        ;;
    start)
        start_vm
        setup_guest
        log "VM ready. SSH: ssh -p ${VM_SSH_PORT} ${VM_USER}@127.0.0.1"
        ;;
esac
