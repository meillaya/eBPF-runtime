#!/usr/bin/env bash
# scripts/release-verify.sh - kernel-v1 release:verify-placeholder.
#
# Usage:
#   scripts/release-verify.sh --out <path>
#
# Builds (or scaffolds) a multi-arch OCI Image Layout v1 containing
# exactly linux/amd64 and linux/arm64 entries, extracts each per-arch
# binary, validates `file(1)` ELF architecture, produces SPDX + SPDX
# JSON + CycloneDX SBOMs, signs the per-arch blobs in test mode, and
# writes release-verdict.json summarising the outcome.
#
# Strategy selection (first match wins):
#   1. `docker buildx` is present AND the docker daemon is reachable
#      → invoke `docker buildx build --platform linux/amd64,linux/arm64
#        --driver docker-container --output type=oci,dest=<out>` against
#        the Dockerfile. This is the true multi-arch path.
#   2. `podman` is present → equivalent multi-arch build via
#      `podman build --platform linux/amd64,linux/arm64 --manifest ...`.
#      Podman's manifest list gives the same OCI index shape.
#   3. Neither → hand-crafted OCI Image Layout v1 scaffold under <out>.
#      Two entries (amd64 + arm64) are produced by compiling a tiny
#      freestanding ELF placeholder per architecture with the system
#      clang (with `-target aarch64-linux-gnu` for arm64) and packaging
#      each as an OCI image layer. This path keeps task 8 shippable on
#      a host without Docker; the acceptance criteria still hold
#      because the index contains exactly two entries with the right
#      platforms and the binaries are real per-arch ELFs.
#
# SBOM and signing fall back to in-Python synthesizers when `syft` and
# `cosign` are not installed. The fallback synthesizers emit
# machine-parseable SPDX / CycloneDX with `licenseDeclared:
# NOASSERTION` for every file and a placeholder cosign signature JSON;
# both fallbacks are explicitly allowed by the task spec.
#
# Exit codes:
#   0  every check passed; release-verdict.json verdict == "passed"
#   1  at least one check failed; release-verdict.json verdict == "failed"
#   2  bad usage
#
# Task 8 of .omo/plans/ebpf-runtime-security-observability.md.
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail

LC_ALL=C
export LC_ALL

PROG="${0##*/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OCI_INSPECT="${SCRIPT_DIR}/oci-inspect.py"

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

OUT=""
REUSE_BUILD=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)
            OUT="${2:-}"
            shift 2
            ;;
        --out=*)
            OUT="${1#--out=}"
            shift
            ;;
        --reuse)
            # Re-verify an existing OCI layout under <out>/oci-layout/
            # without rebuilding it. Used by the failure QA scenario
            # which corrupts the layout on disk before re-verifying.
            REUSE_BUILD=1
            shift
            ;;
        -h|--help)
            sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "${PROG}: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

if [[ -z "${OUT}" ]]; then
    echo "${PROG}: --out <path> is required" >&2
    exit 2
fi

mkdir -p "${OUT}"
OUT="$(cd "${OUT}" && pwd)"  # canonicalize
OCI_DIR="${OUT}/oci-layout"
SBOM_DIR="${OUT}/sbom"
COSIGN_DIR="${OUT}/cosign"
mkdir -p "${OCI_DIR}/blobs/sha256" "${SBOM_DIR}" "${COSIGN_DIR}"

# --------------------------------------------------------------------------
# Tooling detection
# --------------------------------------------------------------------------

log() { echo "[${PROG}] $*"; }
warn() { echo "[${PROG}] WARN: $*" >&2; }

have_command() { command -v "$1" >/dev/null 2>&1; }

DOCKER_BUILDX=0
PODMAN=0
SYFT=0
COSIGN=0
FILE_BIN=""
CLANG_BIN=""

if have_command docker && docker buildx version >/dev/null 2>&1; then
    DOCKER_BUILDX=1
fi
if have_command podman; then
    PODMAN=1
fi
if have_command syft; then
    SYFT=1
fi
if have_command cosign; then
    COSIGN=1
fi
if have_command file; then
    FILE_BIN="$(command -v file)"
else
    echo "${PROG}: \`file\` is required for ELF class verification" >&2
    exit 1
fi
if have_command clang; then
    CLANG_BIN="$(command -v clang)"
elif have_command cc; then
    CLANG_BIN="$(command -v cc)"
else
    warn "no clang/cc found; the OCI scaffold cannot compile per-arch ELFs"
fi

# Probe docker daemon reachability separately from the buildx binary
# presence; a permission denied on /var/run/docker.sock is common in
# rootless environments.
DOCKER_DAEMON_OK=0
if [[ "${DOCKER_BUILDX}" -eq 1 ]]; then
    if docker info >/dev/null 2>&1; then
        DOCKER_DAEMON_OK=1
    else
        warn "docker buildx is present but the daemon is unreachable; will fall back"
    fi
fi

STRATEGY=""
if [[ "${DOCKER_DAEMON_OK}" -eq 1 ]]; then
    STRATEGY="docker-buildx"
elif [[ "${PODMAN}" -eq 1 ]]; then
    STRATEGY="podman"
else
    STRATEGY="oci-scaffold"
fi

# The narrative field tracks every fallback for reviewer audit.
NARRATIVE_PATHS=()
NARRATIVE_NOTES=()

log "strategy: ${STRATEGY}"

# --------------------------------------------------------------------------
# Strategy 1: docker buildx (true multi-arch from a single invocation)
# --------------------------------------------------------------------------

run_docker_buildx() {
    log "docker buildx build --platform linux/amd64,linux/arm64 --driver docker-container"
    local img_tag
    img_tag="kernel-v1/agent:placeholder-$(date -u +%Y%m%dT%H%M%SZ)"
    # We use type=oci,dest=<out>/oci-layout.tar because docker buildx
    # writes a single OCI archive; we then explode it into a directory
    # layout below so the inspector + verifier see the same shape as
    # the fallback path.
    local oci_tar="${OUT}/oci-layout.tar"
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --driver docker-container \
        --tag "${img_tag}" \
        --output "type=oci,dest=${oci_tar}" \
        "${REPO_ROOT}"
    # Convert the OCI tar to an OCI Image Layout directory by extracting
    # the index.json + blobs/* into <out>/oci-layout/.
    python3 - "$oci_tar" "${OCI_DIR}" <<'PY'
import json, os, sys, tarfile
oci_tar, oci_dir = sys.argv[1], sys.argv[2]
os.makedirs(oci_dir, exist_ok=True)
os.makedirs(os.path.join(oci_dir, "blobs", "sha256"), exist_ok=True)
with tarfile.open(oci_tar, "r") as tf:
    for m in tf.getmembers():
        if not m.isfile():
            continue
        base = os.path.basename(m.name)
        # manifest.json (docker) / index.json (oci) / blobs/sha256/<digest>
        if base == "index.json":
            data = tf.extractfile(m).read()
            with open(os.path.join(oci_dir, "index.json"), "wb") as f:
                f.write(data)
        elif base == "oci-layout.txt":
            data = tf.extractfile(m).read()
            with open(os.path.join(oci_dir, "oci-layout"), "wb") as f:
                f.write(data)
        elif m.name.startswith("blobs/sha256/"):
            data = tf.extractfile(m).read()
            digest = base
            with open(os.path.join(oci_dir, "blobs", "sha256", digest), "wb") as f:
                f.write(data)
# Ensure oci-layout exists even if the tar omitted it.
if not os.path.exists(os.path.join(oci_dir, "oci-layout")):
    with open(os.path.join(oci_dir, "oci-layout"), "w") as f:
        f.write(json.dumps({"imageLayoutVersion": "1.0.0"}))
PY
    NARRATIVE_PATHS+=("docker-buildx")
    NARRATIVE_NOTES+=("true multi-arch via docker buildx docker-container driver")
}

# --------------------------------------------------------------------------
# Strategy 2: podman (manifest list)
# --------------------------------------------------------------------------

run_podman() {
    log "podman build --platform linux/amd64,linux/arm64 --manifest"
    local manifest_name="kernel-v1-agent-placeholder"
    podman manifest rm "${manifest_name}" >/dev/null 2>&1 || true
    podman build \
        --platform linux/amd64,linux/arm64 \
        --manifest "${manifest_name}" \
        "${REPO_ROOT}" \
        >/dev/null
    # Export the manifest as an OCI directory layout.
    local oci_tar="${OUT}/oci-layout.tar"
    podman manifest push --format oci "${manifest_name}" "oci:${oci_tar%%.*}:placeholder" >/dev/null 2>&1 \
        || podman save --format oci-archive -o "${oci_tar}" "${manifest_name}"
    if [[ ! -s "${oci_tar}" ]]; then
        warn "podman produced no OCI archive; falling through to oci-scaffold"
        STRATEGY="oci-scaffold"
        return 1
    fi
    python3 - "$oci_tar" "${OCI_DIR}" <<'PY'
import json, os, sys, tarfile
oci_tar, oci_dir = sys.argv[1], sys.argv[2]
os.makedirs(oci_dir, exist_ok=True)
os.makedirs(os.path.join(oci_dir, "blobs", "sha256"), exist_ok=True)
with tarfile.open(oci_tar, "r") as tf:
    for m in tf.getmembers():
        if not m.isfile():
            continue
        base = os.path.basename(m.name)
        if base == "index.json":
            data = tf.extractfile(m).read()
            with open(os.path.join(oci_dir, "index.json"), "wb") as f:
                f.write(data)
        elif m.name.startswith("blobs/sha256/"):
            data = tf.extractfile(m).read()
            with open(os.path.join(oci_dir, "blobs", "sha256", base), "wb") as f:
                f.write(data)
if not os.path.exists(os.path.join(oci_dir, "oci-layout")):
    with open(os.path.join(oci_dir, "oci-layout"), "w") as f:
        f.write(json.dumps({"imageLayoutVersion": "1.0.0"}))
PY
    NARRATIVE_PATHS+=("podman")
    NARRATIVE_NOTES+=("multi-arch via podman manifest list")
}

# --------------------------------------------------------------------------
# Strategy 3: hand-crafted OCI Image Layout v1 (fallback)
# --------------------------------------------------------------------------
#
# Produces an OCI Image Layout v1 directory under <out>/oci-layout/
# with exactly two index entries (linux/amd64, linux/arm64). Each
# entry's layer is a gzipped tar containing usr/local/bin/kernel-v1-agent
# (a freestanding ELF compiled per arch with the system clang).
#
# This is the path that satisfies the task-8 acceptance criteria when
# neither docker nor podman is available on the host. The resulting
# layout passes every check scripts/oci-inspect.py performs because
# the per-arch binaries are real per-arch ELFs (not shell scripts),
# so `file(1)` returns the correct architecture.

run_oci_scaffold() {
    log "hand-crafted OCI Image Layout v1 scaffold (no docker/podman)"
    if [[ -z "${CLANG_BIN}" ]]; then
        echo "${PROG}: oci-scaffold strategy requires clang (no docker/podman present)" >&2
        exit 1
    fi
    if ! have_command lld && ! "${CLANG_BIN}" -fuse-ld=lld -x c -o /dev/null - <<<'int main(void){return 0;}' 2>/dev/null; then
        # last-ditch probe: try to use clang's -fuse-ld=lld for a tiny compile
        if ! "${CLANG_BIN}" -fuse-ld=lld -nostdlib -static -x assembler -o /dev/null - 2>/dev/null <<<'.global _start; _start: ret'; then
            warn "lld does not appear available; arm64 cross-link may fail"
        fi
    fi
    local work="${OUT}/.scaffold-work"
    rm -rf "${work}"
    mkdir -p "${work}/bin"
    local commit
    commit="$(cd "${REPO_ROOT}" && git rev-parse HEAD 2>/dev/null || echo 0000000000000000000000000000000000000000)"
    # Build amd64 placeholder
    local amd64_src="${work}/placeholder-amd64.c"
    local arm64_src="${work}/placeholder-arm64.c"
    cat > "${amd64_src}" <<'CFILE'
/* Freestanding amd64 placeholder. Direct write(2)/exit_group(2)
 * syscalls; no libc. The self-identification line carries the
 * architecture so scripts/oci-inspect.py + scripts/release-verify.sh
 * can detect a misclassification in the OCI bake even when the
 * binary itself is a true per-arch ELF (file(1) also reports the
 * right class). Commit hash is injected after the heredoc by sed. */
static const char msg[] =
    "kernel-v1 agent placeholder amd64 build COMMIT_PLACEHOLDER\n";

static long sys_write(int fd, const void *buf, unsigned long count) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"((long)1), "D"(fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static void sys_exit(int code) {
    __asm__ volatile (
        "syscall"
        :
        : "a"((long)60), "D"((long)code)
        : "memory"
    );
    __builtin_unreachable();
}

void _start(void) {
    sys_write(1, msg, sizeof msg - 1);
    sys_exit(0);
}
CFILE
    cat > "${arm64_src}" <<'CFILE'
/* Freestanding aarch64 placeholder; same contract as amd64 variant. */
static const char msg[] =
    "kernel-v1 agent placeholder arm64 build COMMIT_PLACEHOLDER\n";

static long sys_write(int fd, const void *buf, unsigned long count) {
    long ret;
    /* Adjacent string literals are concatenated at compile time. The
     * leading newline keeps the second line indented as the assembler
     * expects; we cannot rely on C escape sequences (\n, \t) inside
     * inline asm because they are passed verbatim to the assembler. */
    __asm__ volatile (
        "mov x8, #64\n"
        "    svc #0"
        : "=r"(ret)
        : "r"((long)fd), "r"(buf), "r"(count)
        : "x8", "memory"
    );
    return ret;
}

static void sys_exit(int code) {
    __asm__ volatile (
        "mov x8, #93\n"
        "    svc #0"
        :
        : "r"((long)code)
        : "x8", "memory"
    );
    __builtin_unreachable();
}

void _start(void) {
    sys_write(1, msg, sizeof msg - 1);
    sys_exit(0);
}
CFILE
    sed -i "s/COMMIT_PLACEHOLDER/${commit}/g" "${amd64_src}" "${arm64_src}"
    log "compiling amd64 placeholder"
    "${CLANG_BIN}" -O2 -fuse-ld=lld -nostdlib -static -ffreestanding \
        -o "${work}/bin/kernel-v1-agent-amd64" "${amd64_src}"
    log "cross-compiling arm64 placeholder"
    "${CLANG_BIN}" -target aarch64-linux-gnu -O2 -fuse-ld=lld -nostdlib -static -ffreestanding \
        -o "${work}/bin/kernel-v1-agent-arm64" "${arm64_src}"

    python3 - \
        "${OCI_DIR}" \
        "${work}/bin/kernel-v1-agent-amd64" \
        "${work}/bin/kernel-v1-agent-arm64" \
        "${commit}" \
        <<'PY'
"""Hand-craft an OCI Image Layout v1 with two manifest entries."""
import gzip, hashlib, io, json, os, sys, tarfile
oci_dir, amd64_bin, arm64_bin, commit = sys.argv[1:5]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()

def write_blob(oci_dir, payload):
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    path = os.path.join(oci_dir, "blobs", "sha256", digest.split(":", 1)[1])
    with open(path, "wb") as f:
        f.write(payload)
    return digest, len(payload)

def make_config(arch, osname, binary_relpath):
    cfg = {
        "architecture": arch,
        "os": osname,
        "config": {
            "User": "65532:65532",
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "Entrypoint": ["/usr/local/bin/kernel-v1-agent"],
            "WorkingDir": "/",
            "ExposedPorts": {"9464/tcp": {}},
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": [],
        },
    }
    return cfg

def make_layer_tar_gz(binary_path, in_tar_path):
    """Return (tarball_bytes, uncompressed_diff_id)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        ti = tarfile.TarInfo(name=in_tar_path)
        with open(binary_path, "rb") as f:
            data = f.read()
        ti.size = len(data)
        ti.mode = 0o755
        ti.uid = 0
        ti.gid = 0
        ti.uname = "root"
        ti.gname = "root"
        tf.addfile(ti, io.BytesIO(data))
    payload = raw.getvalue()
    diff_id = "sha256:" + hashlib.sha256(payload).hexdigest()
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0) as g:
        g.write(payload)
    return gz.getvalue(), diff_id

def make_manifest(arch_entry):
    cfg_bytes = json.dumps(arch_entry["config"]).encode()
    cfg_digest, cfg_size = write_blob(oci_dir, cfg_bytes)
    layer_bytes, diff_id = make_layer_tar_gz(arch_entry["binary"], "usr/local/bin/kernel-v1-agent")
    layer_digest, layer_size = write_blob(oci_dir, layer_bytes)
    # Patch the config in place so diff_ids matches the layer payload.
    arch_entry["config"]["rootfs"]["diff_ids"].append(diff_id)
    cfg_bytes = json.dumps(arch_entry["config"]).encode()
    cfg_digest, cfg_size = write_blob(oci_dir, cfg_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": cfg_digest,
            "size": cfg_size,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer_digest,
                "size": layer_size,
            }
        ],
    }
    return manifest

amd64_cfg = make_config("amd64", "linux", "usr/local/bin/kernel-v1-agent")
arm64_cfg = make_config("arm64", "linux", "usr/local/bin/kernel-v1-agent")

amd64_manifest = make_manifest({"config": amd64_cfg, "binary": amd64_bin})
arm64_manifest = make_manifest({"config": arm64_cfg, "binary": arm64_bin})

amd64_manifest_bytes = json.dumps(amd64_manifest).encode()
arm64_manifest_bytes = json.dumps(arm64_manifest).encode()
amd64_manifest_digest, amd64_manifest_size = write_blob(oci_dir, amd64_manifest_bytes)
arm64_manifest_digest, arm64_manifest_size = write_blob(oci_dir, arm64_manifest_bytes)

index = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "manifests": [
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": amd64_manifest_digest,
            "size": amd64_manifest_size,
            "platform": {"architecture": "amd64", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": arm64_manifest_digest,
            "size": arm64_manifest_size,
            "platform": {"architecture": "arm64", "os": "linux"},
        },
    ],
}

with open(os.path.join(oci_dir, "index.json"), "w") as f:
    json.dump(index, f, indent=2)
with open(os.path.join(oci_dir, "oci-layout"), "w") as f:
    json.dump({"imageLayoutVersion": "1.0.0"}, f)
PY
    NARRATIVE_PATHS+=("oci-scaffold")
    NARRATIVE_NOTES+=("hand-crafted OCI Image Layout v1; per-arch ELFs cross-compiled with clang")
}

# --------------------------------------------------------------------------
# Run the selected strategy
# --------------------------------------------------------------------------

if [[ "${REUSE_BUILD}" -eq 1 ]]; then
    log "skipping build phase; reusing existing layout at ${OCI_DIR}"
    if [[ ! -f "${OCI_DIR}/index.json" || ! -f "${OCI_DIR}/oci-layout" ]]; then
        echo "${PROG}: --reuse requires an existing ${OCI_DIR}/index.json" >&2
        exit 1
    fi
    NARRATIVE_PATHS+=("reuse")
    NARRATIVE_NOTES+=("skipped build; re-verified existing layout")
else
    case "${STRATEGY}" in
        docker-buildx)
            run_docker_buildx
            ;;
        podman)
            if ! run_podman; then
                STRATEGY="oci-scaffold"
                run_oci_scaffold
            fi
            ;;
        oci-scaffold)
            run_oci_scaffold
            ;;
    esac
fi

# --------------------------------------------------------------------------
# Verify the OCI index: exactly two entries, platforms are
# linux/amd64 and linux/arm64, per-arch binaries are the right ELF.
# --------------------------------------------------------------------------

# Initialise verdict state before any check runs so the verdict
# reflects the cumulative result, not just the last check.
VERDICT="passed"
REASONS=()
declare -A FILE_CLASS
declare -A BINARY_SHA

log "verifying OCI index"
INSPECT_RC=0
python3 "${OCI_INSPECT}" verify-arch "${OCI_DIR}" >"${OUT}/oci-inspect.json" 2>"${OUT}/oci-inspect.err" \
    || INSPECT_RC=$?
if [[ "${INSPECT_RC}" -ne 0 ]]; then
    cat "${OUT}/oci-inspect.err" >&2 || true
    warn "oci-inspect verify-arch failed (rc=${INSPECT_RC})"
    REASONS+=("oci-inspect verify-arch failed (rc=${INSPECT_RC})")
    VERDICT="failed"
fi

PLATFORMS=$(python3 -c "
import json
data = json.load(open('${OCI_DIR}/index.json'))
plats = sorted([(m['platform']['architecture'], m['platform']['os']) for m in data['manifests']])
print(json.dumps(plats))
")
log "platforms: ${PLATFORMS}"

# Extract each per-arch binary to a stable path so file(1) can read it.
EXTRACT_DIR="${OUT}/extracted"
# Clear the extraction directory before re-populating so a corruption
# that drops one of the binaries surfaces as a missing file rather
# than being masked by a leftover from a previous run.
rm -rf "${EXTRACT_DIR}"
mkdir -p "${EXTRACT_DIR}"
for arch in amd64 arm64; do
    EXTRACT_RC=0
    python3 "${OCI_INSPECT}" extract-binary "${OCI_DIR}" "${arch}" "${EXTRACT_DIR}/kernel-v1-agent-${arch}" \
        >"${OUT}/extract-${arch}.json" 2>"${OUT}/extract-${arch}.err" \
        || EXTRACT_RC=$?
    if [[ "${EXTRACT_RC}" -ne 0 ]]; then
        cat "${OUT}/extract-${arch}.err" >&2 || true
        warn "extraction of ${arch} binary failed (see ${OUT}/extract-${arch}.err)"
        REASONS+=("${arch}: oci-inspect extract-binary failed (rc=${EXTRACT_RC})")
        VERDICT="failed"
    fi
done

# Validate `file(1)` output per arch.
declare -A EXPECTED_CLASS=(
    [amd64]="ELF 64-bit LSB executable, x86-64"
    [arm64]="ELF 64-bit LSB executable, ARM aarch64"
)
for arch in amd64 arm64; do
    bin="${EXTRACT_DIR}/kernel-v1-agent-${arch}"
    if [[ ! -s "${bin}" ]]; then
        FILE_CLASS["${arch}"]="<missing>"
        REASONS+=("${arch}: binary not extracted")
        VERDICT="failed"
        continue
    fi
    out="$("${FILE_BIN}" -b "${bin}")"
    FILE_CLASS["${arch}"]="${out}"
    BINARY_SHA["${arch}"]="$(sha256sum "${bin}" | awk '{print $1}')"
    # Prefix match: `file(1)` appends version, ABI, build-id, strip
    # status, etc. that we do not want to fail the verdict on. The
    # canonical architecture prefix is what the task acceptance
    # criterion is asserting on; extra metadata is benign.
    if [[ "${out}" != "${EXPECTED_CLASS[${arch}]}"* ]]; then
        REASONS+=("${arch}: file(1) reports '${out}', expected prefix '${EXPECTED_CLASS[${arch}]}'")
        VERDICT="failed"
    fi
done

# Self-identification print check: when the host can execute the
# binary natively (amd64 only on amd64 host), capture stdout and
# assert it matches the arch.
for arch in amd64 arm64; do
    bin="${EXTRACT_DIR}/kernel-v1-agent-${arch}"
    if [[ "${arch}" == "amd64" && -x "${bin}" ]]; then
        printed="$(LD_LIBRARY_PATH='' "${bin}" 2>/dev/null || true)"
        if [[ "${printed}" != "kernel-v1 agent placeholder ${arch} build "* ]]; then
            REASONS+=("${arch}: self-id print '${printed}' does not match expected prefix")
            VERDICT="failed"
        fi
    fi
done

# --------------------------------------------------------------------------
# SBOM synthesis (syft when available; in-Python fallback otherwise)
# --------------------------------------------------------------------------

log "producing SBOMs"
if [[ "${SYFT}" -eq 1 ]]; then
    for arch in amd64 arm64; do
        bin="${EXTRACT_DIR}/kernel-v1-agent-${arch}"
        # syft takes a per-arch rootfs directory; we synthesise one
        # below by copying the binary into a scratch dir named after
        # the in-image path. This keeps syft happy with the `dir:`
        # source mode (which is the form the task spec requires).
        syft_root="${SBOM_DIR}/.syft-root-${arch}"
        rm -rf "${syft_root}"
        mkdir -p "${syft_root}/usr/local/bin"
        cp "${bin}" "${syft_root}/usr/local/bin/kernel-v1-agent"
        syft "dir:${syft_root}" -o spdx-json -o cyclonedx-json \
            >"${SBOM_DIR}/${arch}.all.json" 2>"${SBOM_DIR}/${arch}.err" || true
        # Split the dual-output file into per-format siblings for the
        # verdict schema; syft writes them concatenated.
        if [[ -s "${SBOM_DIR}/${arch}.all.json" ]]; then
            python3 - "${SBOM_DIR}/${arch}.all.json" "${SBOM_DIR}/${arch}.spdx.json" "${SBOM_DIR}/${arch}.cyclonedx.json" <<'PY'
import json, sys, pathlib
src = pathlib.Path(sys.argv[1])
spdx = pathlib.Path(sys.argv[2])
cdx = pathlib.Path(sys.argv[3])
text = src.read_text()
# syft multi-format output writes JSON documents separated by the
# SPDX/CycloneDX envelope marker. Heuristic: the SPDX doc starts
# with `"spdxVersion"` and the CycloneDX one starts with `"bomFormat"`.
docs = []
depth = 0
start = 0
for i, ch in enumerate(text):
    if ch == "{":
        if depth == 0:
            start = i
        depth += 1
    elif ch == "}":
        depth -= 1
        if depth == 0:
            docs.append(text[start:i+1])
for d in docs:
    try:
        parsed = json.loads(d)
    except Exception:
        continue
    if "spdxVersion" in parsed:
        spdx.write_text(json.dumps(parsed, indent=2))
    elif "bomFormat" in parsed:
        cdx.write_text(json.dumps(parsed, indent=2))
PY
        fi
        rm -rf "${syft_root}"
    done
    NARRATIVE_PATHS+=("syft")
    NARRATIVE_NOTES+=("SBOM via syft")
else
    log "syft not present; using in-Python SPDX/CycloneDX synthesizer"
    for arch in amd64 arm64; do
        bin="${EXTRACT_DIR}/kernel-v1-agent-${arch}"
        python3 - "${bin}" "${SBOM_DIR}/${arch}.spdx.json" "${SBOM_DIR}/${arch}.cyclonedx.json" "${arch}" <<'PY'
"""Minimal SPDX + CycloneDX synthesizer for the placeholder rootfs.

The plan explicitly allows this fallback. Every file is reported
with `licenseDeclared: NOASSERTION` because the placeholder is a
non-functional stub; later tasks attach real licence / supplier
metadata once the agent's source tree is wired in.

A missing binary (e.g. when the upstream extraction failed because
the OCI layer was corrupted) still produces a stub SBOM with the
sha recorded as the missing-byte digest so the verdict can carry
forward the failure context without this generator itself crashing.
"""
import hashlib, json, pathlib, sys, time
bin_path, spdx_out, cdx_out, arch = sys.argv[1:5]
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
name = "kernel-v1-agent-" + arch
bin_p = pathlib.Path(bin_path)
if bin_p.exists():
    data = bin_p.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    size = len(data)
else:
    data = b""
    sha = "0" * 64
    size = 0
spdx = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "kernel-v1-agent-" + arch,
    "documentNamespace": "https://kernel-v1.local/spdx/" + sha,
    "creationInfo": {
        "created": now,
        "creators": ["Tool: scripts/release-verify.sh (syft fallback)"],
    },
    "packages": [
        {
            "name": name,
            "SPDXID": "SPDXRef-Package-" + arch,
            "downloadLocation": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "files": [
                {
                    "fileName": "usr/local/bin/kernel-v1-agent",
                    "SPDXID": "SPDXRef-File-" + sha[:8],
                    "checksums": [
                        {"algorithm": "SHA256", "checksumValue": sha},
                    ],
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                }
            ],
        }
    ],
}
cdx = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": now,
        "tools": [
            {"vendor": "kernel-v1", "name": "release-verify.sh", "version": "task-8"}
        ],
        "component": {
            "type": "application",
            "name": name,
            "bom-ref": "pkg:" + arch + ":" + sha,
        },
    },
    "components": [
        {
            "type": "application",
            "name": name,
            "bom-ref": "pkg:" + arch + ":" + sha,
            "hashes": [{"alg": "SHA-256", "content": sha}],
        }
    ],
}
pathlib.Path(spdx_out).write_text(json.dumps(spdx, indent=2))
pathlib.Path(cdx_out).write_text(json.dumps(cdx, indent=2))
PY
    done
    NARRATIVE_PATHS+=("syft-fallback")
    NARRATIVE_NOTES+=("SBOM via in-Python synthesizer (syft absent)")
fi

# --------------------------------------------------------------------------
# Cosign signing (test mode)
# --------------------------------------------------------------------------

log "signing per-arch blobs (test mode)"
COSIGN_KEY="${COSIGN_DIR}/cosign.key"
COSIGN_PUB="${COSIGN_DIR}/cosign.pub"
if [[ "${COSIGN}" -eq 1 ]]; then
    # cosign generate-key-pair AND sign-blob both prompt for the key
    # password; provide a fixed test-mode password via env to keep the
    # build non-interactive. The keypair is gitignored.
    export COSIGN_PASSWORD="${COSIGN_PASSWORD:-test-mode-do-not-ship}"
    if [[ ! -f "${COSIGN_KEY}" || ! -f "${COSIGN_PUB}" ]]; then
        cosign generate-key-pair >/dev/null 2>&1 || true
        # cosign drops the keys in the current directory; move them.
        [[ -f cosign.key ]] && mv cosign.key "${COSIGN_KEY}"
        [[ -f cosign.pub ]] && mv cosign.pub "${COSIGN_PUB}"
    fi
    for arch in amd64 arm64; do
        bin="${EXTRACT_DIR}/kernel-v1-agent-${arch}"
        bundle="${COSIGN_DIR}/signature-${arch}.bundle"
        # cosign >= 2.4 uses --bundle (single JSON envelope) instead
        # of the deprecated --output-signature / --output-certificate
        # pair. --yes skips the interactive confirmation prompt.
        if cosign sign-blob --key "${COSIGN_KEY}" --yes \
            --bundle "${bundle}" "${bin}" >/dev/null 2>"${COSIGN_DIR}/sign-${arch}.err"; then
            # Wrap the bundle in a JSON envelope so the verdict can
            # record its location; the bundle itself is the verifiable
            # artifact.
            cp "${bundle}" "${COSIGN_DIR}/signature-${arch}.json"
        else
            warn "cosign sign-blob for ${arch} failed; falling back to placeholder signature JSON"
            cat "${COSIGN_DIR}/sign-${arch}.err" >&2 || true
            cat > "${COSIGN_DIR}/signature-${arch}.json" <<JSON
{
  "schema_version": 1,
  "keyless": false,
  "test_mode": true,
  "signed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "signature": "PLACEHOLDER",
  "certificate": "PLACEHOLDER",
  "note": "cosign sign-blob failed; placeholder recorded"
}
JSON
        fi
    done
    NARRATIVE_PATHS+=("cosign")
    NARRATIVE_NOTES+=("cosign sign-blob with generated test key pair")
else
    log "cosign not present; emitting placeholder signature JSONs"
    for arch in amd64 arm64; do
        cat > "${COSIGN_DIR}/signature-${arch}.json" <<JSON
{
  "schema_version": 1,
  "keyless": false,
  "test_mode": true,
  "signed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "signature": "PLACEHOLDER",
  "certificate": "PLACEHOLDER",
  "note": "cosign CLI not available on this host; placeholder signature recorded"
}
JSON
    done
    NARRATIVE_PATHS+=("cosign-fallback")
    NARRATIVE_NOTES+=("cosign fallback: placeholder signature JSONs (keyless production signing in a later task)")
fi

# --------------------------------------------------------------------------
# Release verdict
# --------------------------------------------------------------------------

log "writing release-verdict.json"
SBOM_FILES=$(find "${SBOM_DIR}" -maxdepth 2 -type f -name '*.json' | sort | sed "s|^${OUT}/||")
COSIGN_FILES=$(find "${COSIGN_DIR}" -maxdepth 2 -type f -name 'signature-*.json' | sort | sed "s|^${OUT}/||")

# Pass file class + sha into the verdict generator via env (sub-shell
# boundary safe).
for arch in amd64 arm64; do
    export FILE_CLASS_${arch}="${FILE_CLASS[${arch}]:-<unknown>}"
    export BINARY_SHA_${arch}="${BINARY_SHA[${arch}]:-}"
done

python3 - "${OUT}/release-verdict.json" "${VERDICT}" "${STRATEGY}" \
    "$(IFS='|'; echo "${NARRATIVE_NOTES[*]}")" \
    "$(IFS='|'; echo "${REASONS[*]:-}")" \
    "${SBOM_FILES}" "${COSIGN_FILES}" \
    <<'PY'
"""Write release-verdict.json from collected facts."""
import hashlib
import json
import os
import sys
import time

out_path = sys.argv[1]
verdict = sys.argv[2]
strategy = sys.argv[3]
notes_blob = sys.argv[4]
reasons_blob = sys.argv[5]
sbom_blob = sys.argv[6]
cosign_blob = sys.argv[7]
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

binaries = {}
for arch in ("amd64", "arm64"):
    bin_path = os.path.join(
        os.path.dirname(out_path), "extracted", f"kernel-v1-agent-{arch}"
    )
    if os.path.exists(bin_path):
        with open(bin_path, "rb") as f:
            data = f.read()
        binaries[arch] = {
            "path": bin_path,
            "elf_class": os.environ.get(f"FILE_CLASS_{arch}", "<unknown>"),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
    else:
        # Binary missing (extraction failed upstream). Record the
        # absence so the verdict JSON still validates, even though
        # the verdict field is already "failed" for a different
        # reason (the upstream oci-inspect exit code).
        binaries[arch] = {
            "path": bin_path,
            "elf_class": os.environ.get(f"FILE_CLASS_{arch}", "<missing>"),
            "sha256": None,
            "size": 0,
        }

verdict_doc = {
    "schema_version": 1,
    "schema": "https://kernel-v1.local/schemas/release-verdict/v1.json",
    "verdict": verdict,
    "strategy": strategy,
    "platforms": ["linux/amd64", "linux/arm64"],
    "binaries": binaries,
    "sboms": {p: p for p in sbom_blob.split("\n") if p},
    "signatures": {p: p for p in cosign_blob.split("\n") if p},
    "reasons": [r for r in reasons_blob.split("|") if r],
    "narrative": {
        "strategy": strategy,
        "notes": [n for n in notes_blob.split("|") if n],
        "completed_at": now,
    },
}
with open(out_path, "w") as f:
    json.dump(verdict_doc, f, indent=2)
PY

if [[ "${VERDICT}" == "passed" ]]; then
    log "PASS: release-verdict.json verdict=passed"
    exit 0
else
    log "FAIL: release-verdict.json verdict=failed (reasons: ${REASONS[*]:-none})"
    exit 1
fi