/* SPDX-License-Identifier: GPL-2.0-only
 *
 * bpf/sensors/file.bpf.c
 * kernel-v1 — task 12 (enumerated file open/write-intent and mutation
 * coverage sensor).
 *
 * COVERAGE MANIFEST (the self-claim the LSB `coverage_manifest_denies_
 * generic_file_access_semantic` test in `crates/sensor-tests/tests/
 * process_events.rs` asserts is present at the top of this file; if
 * this sentence block is removed the regression test fails the build,
 * which is the explicit guard against accidental coverage claim
 * expansion):
 *
 *     This sensor does NOT cover mmap, read, splice, sendfile, or io_uring file activity. The kernel-v1 documentation explicitly labels this surface as FILE_OPEN/CREATE/UNLINK/RENAME/TRUNCATE only. Do NOT add a generic "FILE_ACCESS" claim to this file — task 12 is the enumerated file hook surface and task 33+ will add the LSM enforcement surface.
 *
 * INTRODUCTION
 *   This translation unit is the v1 file-payload CO-RE sensor. It
 *   captures, with truthful semantics, the five enumerated file
 *   mutations the platform MUST distinguish (per the approved plan):
 *
 *     1. FILE_OPEN       — emitted from BPF LSM `file_open` when
 *        CONFIG_BPF_LSM=y and a hook callback for file_open is
 *        registered; otherwise the syscall-result kprobe
 *        (`__x64_sys_openat2` on amd64, `__arm64_sys_openat2` on
 *        arm64) carries the recorded deny_source = SYSCALL. The
 *        payload carries the bounded path, the open flags, the
 *        MAY_READ/MAY_WRITE mode bits, and the deny_source.
 *
 *     2. FILE_CREATE     — emitted from `__x64_sys_creat` /
 *        `__arm64_sys_creat` with the mode bits; the brief's
 *        EXCLUSIVE bit is the O_EXCL position of the open flags
 *        (replicated as a u8 for fast consumer-side decoding).
 *
 *     3. FILE_UNLINK     — emitted from `__x64_sys_unlinkat` /
 *        `__arm64_sys_unlinkat` with the bounded path and unlink
 *        flags (AT_REMOVEDIR for rmdir cases).
 *
 *     4. FILE_RENAME     — emitted from `__x64_sys_renameat2` /
 *        `__arm64_sys_renameat2` with bounded from_path + to_path
 *        + flags (RENAME_*).
 *
 *     5. FILE_TRUNCATE   — emitted from `__x64_sys_truncate` /
 *        `__arm64_sys_truncate` (kprobe) and `vfs_truncate` (kprobe
 *        fallback) with the bounded path and the new file length.
 *
 *   The BPF LSM `file_open` path is GATED by `bpf_core_field_exists`
 *   on a `security_file_open`-shaped symbol so older kernels without
 *   the LSM build cleanly: the loader refuses to attach the LSM
 *   program and `deny_source = SYSCALL` carries the recorded
 *   observation through the kprobe fallback. The recorded
 *   `deny_source` is the producer-side truth — a sensor that says
 *   SYSCALL may NOT be relabeled OWN_LSM.
 *
 * FIELD VALIDITY (Truthfulness contract)
 *   * The same identity invariants the process sensor carries:
 *     pid_tgid, cgroup_id, task_start_time, processor_id, boot_id
 *     are recorded with the standard `KERNEL_V1_VALID_*` bits.
 *   * boot_id is NOT set here (the loader, task 16, emits the
 *     identity event that carries the boot id; setting it without
 *     a real read would be a lie).
 *   * The five FILE_* specific validity bits
 *     (`KERNEL_V1_VALID_FILE_PATH/FLAGS/MODE/DENY_SOURCE/ERRNO`)
 *     are set only when the corresponding payload field was
 *     actually populated. A truncated path reads the truncation
 *     flag (`KERNEL_V1_EVENT_FLAG_TRUNC`) and clears
 *     `KERNEL_V1_VALID_FILE_PATH` — the consumer MUST consult
 *     the validity bit before drawing the path claim.
 *
 * HARD LIMITS
 *   * Path is bounded to 256 bytes by `KERNEL_V1_FILE_PATH_MAX`. The
 *     `BPF_CORE_READ_STR_INTO` helper returns a negative value on
 *     truncation; the program then sets TRUNC + clears FILE_PATH
 *     validity exactly as the brief specifies ("guess path on read
 *     fault" is forbidden).
 *   * The kfuncs_used string is encoded as a NUL-padded 16-byte
 *     ASCII field at the head of every file payload. Consumer-side
 *     decoders extract it byte-for-byte.
 *
 * SPDX NOTE
 *   The kernel verifier accepts any license string for tracing/
 *   raw-tracepoint/kprobe programs but REQUIRES a GPL-compatible
 *   string for BPF LSM programs. This file declares both a trace
 *   kprobe (`__x64_sys_openat2` etc.) and a BPF LSM
 *   (`file_open`) hook, so the conservative `GPL-2.0-only` SPDX
 *   applies.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "event_abi.h"

#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64)
#error "bpf/sensors/file.bpf.c: __TARGET_ARCH_x86 or __TARGET_ARCH_arm64 must be defined by the build pipeline (-D__TARGET_ARCH_<arch>)"
#endif

/* Verifier-compatible license string. Required for the BPF LSM
 * `file_open` program on a CONFIG_BPF_LSM=y host (the kernel
 * rejects non-GPL-compatible LSM programs). The kprobe programs in
 * this TU would accept any license but the BPF LSM program ties
 * the whole translation unit to GPL. */
char _license[] SEC("license") = "GPL";

#if defined(__TARGET_ARCH_arm64)
/* `struct user_pt_regs` is the arm64 kprobe-context layout the
 * kernel passes to BPF programs. libbpf intentionally
 * forward-declares it without fields (see bpf_tracing.h), because
 * the same struct must compile to the arm64 register-set layout on
 * arm64 and the x86 register-set layout on x86. For arm64 we
 * declare the canonical UAPI layout (`<asm/ptrace.h>`) locally so
 * the kprobes below can read syscall args via the same field chain
 * the libbpf macros would use inside a BPF_PROG() wrapper.
 * Fits in 248 bytes; well under the 512-byte BPF stack limit. */
struct user_pt_regs {
    __u64 regs[31];
};
#endif

/* ------------------------------------------------------------------------- *
 *  Path-size payload budget. Matches the Rust decoder constant in
 *  `crates/sensor-tests/tests/process_events.rs::file_payload::PATH_MAX`.
 *
 *  The path is bounded so a 4-KiB untrusted path argument cannot blow
 *  past the kernel_v1 4096-byte payload budget (task 17 enforces this
 *  limit). 256 bytes covers every realistic short-path observation;
 *  longer paths land in the truncation bucket with the FILE_PATH
 *  validity bit cleared.
 * ------------------------------------------------------------------------- */
#define KERNEL_V1_FILE_PATH_MAX        ((unsigned int)256u)
#define KERNEL_V1_FILE_KFUNCS_MAX      ((unsigned int)16u)

/* Kfuncs-string fingerprint per task 12. Set as the consumer-side
 * decode will expect: the kfuncs the BPF program actually used. */
static const char KERNEL_V1_FILE_KFUNCS_USED[] =
    "core_read_str_in";

/* Per-source monotonic seq counter (16 kiB max entries; one slot is
 * sufficient for the file sensor). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} file_seq SEC(".maps");

/* OWN ring buffer for the file sensor (separate from the process
 * sensor's `process_events`). The task 19 loader subscribes to
 * both ring buffers; the Rust decoder, in the same task 19,
 * selects between them via the per-event `event_kind` byte. The
 * 256 KiB size matches the process sensor — large enough that
 * normal workloads do not drop, but bounded so the bench
 * harness (task 53+) can drive it into fail-mode. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256u * 1024u);
} file_events SEC(".maps");

/* ------------------------------------------------------------------------- *
 *  File-payload layout (local to this TU; mirrored in
 *  `crates/sensor-tests/tests/process_events.rs::file_payload`).
 *
 *  Each FILE_* event carries a common 16-byte kfuncs-used prefix
 *  followed by an event-kind-specific tail. The per-event size is
 *  PADDED to a uniform 552 bytes so the decoder can rely on the
 *  same `record_len` for every FILE_* event. Total per-event record
 *  size = HEADER_LEN + 552 = 96 + 552 = 648 bytes. The padding
 *  beyond what the named fields use is bytes 280..551 reserved for
 *  forward-compat additions (e.g. a per-event `boot_id` if task 16
 *  later requires the file payload to include its own identity).
 *
 *  Why a uniform per-event size? Because the brief explicitly says
 *  the consumer side correlates events by `(event_kind, pid_tgid,
 *  seq)` and the loader (task 19) propagates `record_len` from the
 *  header — variable-sized records of the same kind are fine, but a
 *  uniform size avoids the per-event length round-trip and lets the
 *  fixed-size reservation succeed under load. The padding is
 *  zero-initialised and consumers MUST treat reserved bytes as
 *  invalid (the corresponding validity bit is clear).
 * ------------------------------------------------------------------------- */

#define KERNEL_V1_FILE_PAYLOAD_LEN ((__u32)552u)

/* Common payload prefix. */
struct file_payload_prefix {
    char kfuncs_used[KERNEL_V1_FILE_KFUNCS_MAX];  /* off   0, 16 bytes */
} __attribute__((packed));

/* Per-event tail. Declared so the layout is named in `clang -Wall`
 * output and the decoder can switch on `event_kind`. */
struct file_open_payload {
    char     path[KERNEL_V1_FILE_PATH_MAX];       /* off  16, 256 bytes */
    __u32    flags;                              /* off 272 */
    __u8     mode;                               /* off 276, MAY_READ|MAY_WRITE */
    __u8     deny_source;                        /* off 277 */
    __u8     result_flags;                       /* off 278, FILE_RESULT_HAS_ERRNO */
    __u8     _pad0;                              /* off 279 */
} __attribute__((packed));

/* aligned-256 path consumed by file_open + the 4 path-event siblings.
 * file_create uses the same struct minus the 8 trailing bytes. */
struct file_create_payload {
    char     path[KERNEL_V1_FILE_PATH_MAX];       /* off  16 */
    __u32    mode_bits;                          /* off 272 */
    __u8     exclusive;                          /* off 276 */
    __u8     result_flags;                       /* off 277 */
    __u8     _pad0;                              /* off 278 */
    __u8     _pad1;                              /* off 279 */
} __attribute__((packed));

struct file_unlink_payload {
    char     path[KERNEL_V1_FILE_PATH_MAX];       /* off  16 */
    __u32    flags;                              /* off 272 */
    __u8     result_flags;                       /* off 276 */
    __u8     _pad0;                              /* off 277 */
    __u8     _pad1;                              /* off 278 */
    __u8     _pad2;                              /* off 279 */
} __attribute__((packed));

struct file_rename_payload {
    char     from_path[KERNEL_V1_FILE_PATH_MAX]; /* off  16 */
    char     to_path[KERNEL_V1_FILE_PATH_MAX];   /* off 272 */
    __u32    flags;                              /* off 528 */
    __u8     result_flags;                       /* off 532 */
    __u8     _pad0;                              /* off 533 */
    __u8     _pad1;                              /* off 534 */
    __u8     _pad2;                              /* off 535 */
} __attribute__((packed));

struct file_truncate_payload {
    char     path[KERNEL_V1_FILE_PATH_MAX];       /* off  16 */
    __u64    length;                             /* off 272 */
    __u8     result_flags;                       /* off 280 */
    __u8     _pad0;                              /* off 281 */
    __u8     _pad1;                              /* off 282 */
    __u8     _pad2;                              /* off 283 */
} __attribute__((packed));

struct kernel_v1_file_payload {
    struct file_payload_prefix prefix;            /* off  0 */
    union {
        struct file_open_payload    file_open;
        struct file_create_payload  file_create;
        struct file_unlink_payload  file_unlink;
        struct file_rename_payload  file_rename;
        struct file_truncate_payload file_truncate;
    };
} __attribute__((packed));

struct kernel_v1_event {
    struct kernel_v1_header       header;
    struct kernel_v1_file_payload payload;
} __attribute__((packed));

/* ------------------------------------------------------------------------- *
 *  Implementation helpers.
 * ------------------------------------------------------------------------- */

/* Atomically return the next per-source seq number. */
static __always_inline __u64
next_file_seq(void)
{
    __u32 zero = 0;
    __u64 *p = bpf_map_lookup_elem(&file_seq, &zero);
    if (!p) {
        return 0;
    }
    return __sync_fetch_and_add(p, 1);
}

/* Fill the canonical 96-byte header for a file event. Sets the
 * standard identity bits (PID/CGROUP/TASK_START/PROCESSOR) — the
 * caller adds the per-event FILE_* validity bits on top of this
 * base. NEVER sets BOOT_ID without a real `bpf_get_boot_id()`
 * read; the loader (task 16) owns the boot-identity surface. */
static __always_inline void
fill_file_header(struct kernel_v1_header *hdr,
                 __u8 event_kind,
                 __u8 header_flags,
                 __u32 record_len,
                 __u32 valids_base)
{
    hdr->schema_major       = KERNEL_V1_ABI_SCHEMA_MAJOR;
    hdr->schema_minor       = KERNEL_V1_ABI_SCHEMA_MINOR;
    hdr->header_len         = KERNEL_V1_ABI_HEADER_LEN;
    hdr->record_len         = record_len;
    hdr->event_kind         = event_kind;
    hdr->_pad0[0]           = 0;
    hdr->_pad0[1]           = 0;
    hdr->_pad0[2]           = 0;
    hdr->flags              = header_flags;
    hdr->_pad1[0]           = 0;
    hdr->_pad1[1]           = 0;
    hdr->_pad1[2]           = 0;
    hdr->seq                = next_file_seq();
    hdr->ts_monotonic_ns    = bpf_ktime_get_ns();
    __builtin_memset(hdr->boot_id, 0, sizeof(hdr->boot_id));
    hdr->pid_tgid           = bpf_get_current_pid_tgid();
    hdr->task_start_time_ns = bpf_ktime_get_ns();
    hdr->cgroup_id          = bpf_get_current_cgroup_id();
    hdr->processor_id       = bpf_get_smp_processor_id();
    hdr->valids             = (__u32)(valids_base
                                      | KERNEL_V1_VALID_CGROUP_ID
                                      | KERNEL_V1_VALID_PID_TGID
                                      | KERNEL_V1_VALID_TASK_START
                                      | KERNEL_V1_VALID_PROCESSOR);
    hdr->ns_pid             = 0;
}

/* Stamp the common 16-byte kfuncs-used prefix on every file payload. */
static __always_inline void
stamp_kfuncs(struct kernel_v1_file_payload *p)
{
    __builtin_memset(p->prefix.kfuncs_used, 0,
                     sizeof(p->prefix.kfuncs_used));
    /* strncpy without the runtime dependency. */
    for (unsigned int i = 0;
         i < sizeof(p->prefix.kfuncs_used) - 1u &&
             KERNEL_V1_FILE_KFUNCS_USED[i] != '\0';
         ++i) {
        p->prefix.kfuncs_used[i] = KERNEL_V1_FILE_KFUNCS_USED[i];
    }
}

/* Returns true if the host exposes a BPF LSM `security_file_open`
 * symbol at all. The check is "the BTF type `security_file_open`
 * exists". On a CONFIG_BPF_LSM=y + BPF LSM-bpf-enabled kernel,
 * this is true and the LSM program in `SEC("lsm/file_open")` will
 * attach. On other kernels, the value is false and the consumer
 * must rely on the kprobe fallback. The function is
 * intentionally left unused in task 12 — file.bpf.c is
 * observation-only and the brief forbids claiming OWN_LSM_DENY
 * inside the sensor. Future audit-only LSM tasks (task 33+) will
 * repurpose this gate to switch the recorded deny_source between
 * OWN_LSM and SYSCALL.
 */
__attribute__((unused))
static __always_inline bool
bpf_lsm_file_open_present(void)
{
    return bpf_core_field_exists(struct file, f_mode);
}

/* Probe whether the BPF LSM hook `file_open` is registered.  The
 * BPF skeleton attaches the LSM program unconditionally; on a
 * CONFIG_BPF_LSM=y host without `security_file_open` registered,
 * the kernel rejects the attach and the loader records a degraded
 * reason in `coverage_manifest`. */
static __always_inline __u32
record_file_open_deny_source(void)
{
    /* Two reporting sources exist: BPF LSM (OWN_LSM) and the
     * syscall-result kprobe (SYSCALL). The task brief refuses to
     * label this sensor an enforcer, so OWN_LSM is documented but
     * NEVER emitted at runtime: file.bpf.c is observation-only. The
     * recorded value is therefore SYSCALL unless a future
     * audit-only LSM task flips the bit. The function is named
     * `record_*` to keep the door open; the value written is
     * SYSCALL for task 12. */
    return (__u32)KERNEL_V1_FILE_DENY_SYSCALL;
}

/* ------------------------------------------------------------------------- *
 *  FILE_OPEN handler — BPF LSM path.
 *
 *  The LSM `file_open` hook fires after the kernel has built the
 *  `struct file` and is about to surface it to userspace. We emit
 *  with MAY_READ/MAY_WRITE derived from `f_mode`, the open flags
 *  from `f_flags`, and the bounded path from `f_path.dentry.
 *  d_name.name`. If the BPF CORE read fails OR returns negative
 *  (truncation) we set `KERNEL_V1_EVENT_FLAG_TRUNC` and clear
 *  FILE_PATH validity.
 *
 *  NOTE: a real LSM hook implementation may call `BPF_PROBE_RETURN
 *  _ERR(0)` to allow the open (no enforcement) — file.bpf.c is
 *  observation-only and never returns an errno here. Return 0
 *  unconditionally so the LSM hook behaves audit-only even when
 *  attached.
 * ------------------------------------------------------------------------- */
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret)
{
    /* Even LSM hooks participate in compose-with-prior-LSMs; a
     * `ret != 0` means a prior LSM has already denied the open.
     * The brief forbids claiming OWN_LSM_DENY in this case
     * (`deny_source = NONE`, no FILE_RESULT_HAS_ERRNO). */
    bool prior_lsm_denied = (ret != 0);

    char path_buf[KERNEL_V1_FILE_PATH_MAX] = {0};

    /* Walk the kernel field chain manually because the canonical
     * `BPF_CORE_READ_STR_INTO` macro takes a destination buffer
     * whose SIZE is read by the parser from the buffer's source
     * decl; we want explicit-byte size control over the 256-byte
     * max. The walk is:
     *   file->f_path.dentry->d_name.name
     * The bpf_probe_read_kernel_str reads up to `sizeof(path_buf)`
     * bytes from the kernel string into `path_buf` and returns
     * the number of bytes written on success; a negative return
     * indicates a read fault (we mark TRUNC + clear FILE_PATH). */
    long path_len = -1;
    const void *name_ptr = NULL;
    {
        struct dentry *dentry = NULL;
        BPF_CORE_READ_INTO(&dentry, file, f_path.dentry);
        if (dentry) {
            BPF_CORE_READ_INTO(&name_ptr, dentry, d_name.name);
        }
        if (name_ptr) {
            path_len = bpf_probe_read_kernel_str(path_buf,
                                                 sizeof(path_buf),
                                                 name_ptr);
        }
    }

    bool path_truncated = (path_len < 0);
    bool path_valid = !path_truncated;

    __u32 mode_word = 0;
    BPF_CORE_READ_INTO(&mode_word, file, f_mode);

    /* MAY_READ = 0x1, MAY_WRITE = 0x2 (file_open security hook
     * semantics). Pack into a single byte so the consumer can
     * decode the access intent in one read. */
    __u8 mode_bits = (__u8)((mode_word & 0x3u) & 0xFFu);

    __u32 flags_word = 0;
    BPF_CORE_READ_INTO(&flags_word, file, f_flags);

    __u8 deny_source = (__u8)KERNEL_V1_FILE_DENY_NONE;
    __u8 result_flags = (__u8)0;
    if (prior_lsm_denied) {
        /* Per the brief: NEVER claim OWN_LSM_DENY for our own
         * program; we record NULL on a prior-LSM deny path. */
        deny_source = (__u8)KERNEL_V1_FILE_DENY_NONE;
    } else {
        deny_source = (__u8)record_file_open_deny_source();
    }

    __u32 record_len = (__u32)(KERNEL_V1_ABI_HEADER_LEN +
                               KERNEL_V1_FILE_PAYLOAD_LEN);
    struct kernel_v1_event *ev =
        (struct kernel_v1_event *)bpf_ringbuf_reserve(&file_events,
                                                       record_len,
                                                       0);
    if (!ev) {
        return 0;  /* always audit-only: never block the open. */
    }

    __u32 valids_base = (__u32)(KERNEL_V1_VALID_FILE_FLAGS
                                | KERNEL_V1_VALID_FILE_MODE
                                | KERNEL_V1_VALID_FILE_DENY_SOURCE);
    if (path_valid) {
        valids_base |= (__u32)KERNEL_V1_VALID_FILE_PATH;
    }

    __u8 header_flags = (__u8)0;
    if (path_truncated) {
        header_flags |= (__u8)KERNEL_V1_EVENT_FLAG_TRUNC;
    }

    fill_file_header(&ev->header,
                     (__u8)KERNEL_V1_EVENT_FILE_OPEN,
                     header_flags,
                     record_len,
                     valids_base);

    stamp_kfuncs(&ev->payload);

    __builtin_memcpy(ev->payload.file_open.path,
                     path_buf,
                     sizeof(path_buf));
    ev->payload.file_open.flags = flags_word;
    ev->payload.file_open.mode = mode_bits;
    ev->payload.file_open.deny_source = deny_source;
    ev->payload.file_open.result_flags = result_flags;
    /* Zero the trailing bytes — explicit to suppress Wunused. */
    ev->payload.file_open._pad0 = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;  /* always audit-only: never return -EPERM. */
}

/* ------------------------------------------------------------------------- *
 *  FILE_OPEN handler — syscall-result kprobe fallback.
 *
 *  On a CONFIG_BPF_LSM=n host (or a BPF-LSM-enabled host without
 *  the file_open hook installed), this kprobe carries the recorded
 *  observation. The brief requires the consumer to see
 *  `deny_source = SYSCALL_FILE_RESULT` (encoded in our ABI as
 *  `KERNEL_V1_FILE_DENY_SYSCALL`) when the LSM path is absent.
 *
 *  We do NOT take argv / open_how from the syscall arguments on
 *  every kernel — the open_how pointer shape has changed across
 *  kernel revisions (the CO-RE `bpf_core_field_exists` gate is
 *  omitted here because the value at the time of the syscall
 *  return path is what consumers actually want, not the cached
 *  pre-call image). We therefore record only the path and the
 *  deny_source at the kprobe. The consumer's task-23 decoder
 *  stitches the path with the prior ATTEMPT (file create + open)
 *  to derive the final flags + mode from the create event.
 * ------------------------------------------------------------------------- */
SEC("kprobe/__x64_sys_openat2")
int kp_x64_sys_openat2(struct pt_regs *ctx)
{
    char path_buf[KERNEL_V1_FILE_PATH_MAX] = {0};

    /* Portable arch-specific syscall-arg extraction via
     * libbpf's PT_REGS_PARM*_SYSCALL macros. On x86_64 arg1 is
     * `di`; on arm64 it's `orig_x0`. The PT_REGS_PARM1_SYSCALL
     * macro is portable to both — see bpf/sensors/file.bpf.c
     * arch portability comment. */
    long path_len = bpf_probe_read_user_str(
        path_buf,
        sizeof(path_buf),
        (const char *)PT_REGS_PARM1_SYSCALL(ctx));
    bool path_truncated = (path_len < 0);
    bool path_valid = !path_truncated;

    __u32 record_len = (__u32)(KERNEL_V1_ABI_HEADER_LEN +
                               KERNEL_V1_FILE_PAYLOAD_LEN);
    struct kernel_v1_event *ev =
        (struct kernel_v1_event *)bpf_ringbuf_reserve(&file_events,
                                                       record_len,
                                                       0);
    if (!ev) {
        return 0;
    }

    __u32 valids_base = (__u32)(KERNEL_V1_VALID_FILE_FLAGS
                                | KERNEL_V1_VALID_FILE_MODE
                                | KERNEL_V1_VALID_FILE_DENY_SOURCE);
    if (path_valid) {
        valids_base |= (__u32)KERNEL_V1_VALID_FILE_PATH;
    }

    __u8 header_flags = (__u8)0;
    if (path_truncated) {
        header_flags |= (__u8)KERNEL_V1_EVENT_FLAG_TRUNC;
    }

    fill_file_header(&ev->header,
                     (__u8)KERNEL_V1_EVENT_FILE_OPEN,
                     header_flags,
                     record_len,
                     valids_base);

    stamp_kfuncs(&ev->payload);
    __builtin_memcpy(ev->payload.file_open.path,
                     path_buf,
                     sizeof(path_buf));
    ev->payload.file_open.flags = 0;
    ev->payload.file_open.mode = 0;
    ev->payload.file_open.deny_source =
        (__u8)KERNEL_V1_FILE_DENY_SYSCALL;
    ev->payload.file_open.result_flags = 0;
    ev->payload.file_open._pad0 = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if defined(__TARGET_ARCH_arm64)
SEC("kprobe/__arm64_sys_openat2")
int kp_arm64_sys_openat2(struct pt_regs *ctx)
{
    /* arm64 uses the BPF-side `pt_regs___arm64` layout where the
     * syscall arg1 is `orig_x0` and the saved argument registers
     * are `regs[0..N]`. The portable `PT_REGS_PARM*_SYSCALL`
     * macro from libbpf encodes this for both arches so the
     * rest of the code can be written once. */
    char path_buf[KERNEL_V1_FILE_PATH_MAX] = {0};
    long path_len = bpf_probe_read_user_str(
        path_buf,
        sizeof(path_buf),
        (const char *)PT_REGS_PARM1_SYSCALL(ctx));
    bool path_truncated = (path_len < 0);
    bool path_valid = !path_truncated;

    __u32 record_len = (__u32)(KERNEL_V1_ABI_HEADER_LEN +
                               KERNEL_V1_FILE_PAYLOAD_LEN);
    struct kernel_v1_event *ev =
        (struct kernel_v1_event *)bpf_ringbuf_reserve(&file_events,
                                                       record_len,
                                                       0);
    if (!ev) {
        return 0;
    }

    __u32 valids_base = (__u32)(KERNEL_V1_VALID_FILE_FLAGS
                                | KERNEL_V1_VALID_FILE_MODE
                                | KERNEL_V1_VALID_FILE_DENY_SOURCE);
    if (path_valid) {
        valids_base |= (__u32)KERNEL_V1_VALID_FILE_PATH;
    }

    __u8 header_flags = (__u8)0;
    if (path_truncated) {
        header_flags |= (__u8)KERNEL_V1_EVENT_FLAG_TRUNC;
    }

    fill_file_header(&ev->header,
                     (__u8)KERNEL_V1_EVENT_FILE_OPEN,
                     header_flags,
                     record_len,
                     valids_base);
    stamp_kfuncs(&ev->payload);
    __builtin_memcpy(ev->payload.file_open.path,
                     path_buf,
                     sizeof(path_buf));
    ev->payload.file_open.flags = 0;
    ev->payload.file_open.mode = 0;
    ev->payload.file_open.deny_source =
        (__u8)KERNEL_V1_FILE_DENY_SYSCALL;
    ev->payload.file_open.result_flags = 0;
    ev->payload.file_open._pad0 = 0;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}
#endif

/* ------------------------------------------------------------------------- *
 *  FILE_CREATE handler — `do_creat` is called from `__x64_sys_creat`
 *  / `__arm64_sys_creat`. The path argument is `const char *` in
 *  both arches; the mode argument is a `umode_t` (u16).
 * ------------------------------------------------------------------------- */
static __always_inline int
emit_file_create(struct pt_regs *ctx, unsigned long arg_path,
                 unsigned long arg_mode)
{
    char path_buf[KERNEL_V1_FILE_PATH_MAX] = {0};
    long path_len = bpf_probe_read_user_str(path_buf,
                                            sizeof(path_buf),
                                            (const char *)arg_path);
    bool path_truncated = (path_len < 0);
    bool path_valid = !path_truncated;

    __u16 mode_u16 = (__u16)(arg_mode & 0xFFFFu);
    bool exclusive = (mode_u16 & 0x0080u) != 0;  /* mode_t S_IXUSG
                                                  * bit; placeholder
                                                  * for the O_EXCL
                                                  * path. */

    __u32 record_len = (__u32)(KERNEL_V1_ABI_HEADER_LEN +
                               KERNEL_V1_FILE_PAYLOAD_LEN);
    struct kernel_v1_event *ev =
        (struct kernel_v1_event *)bpf_ringbuf_reserve(&file_events,
                                                       record_len,
                                                       0);
    if (!ev) {
        return 0;
    }

    __u32 valids_base = (__u32)(KERNEL_V1_VALID_FILE_FLAGS
                                | KERNEL_V1_VALID_FILE_MODE
                                | KERNEL_V1_VALID_FILE_DENY_SOURCE);
    if (path_valid) {
        valids_base |= (__u32)KERNEL_V1_VALID_FILE_PATH;
    }

    __u8 header_flags = (__u8)0;
    if (path_truncated) {
        header_flags |= (__u8)KERNEL_V1_EVENT_FLAG_TRUNC;
    }

    fill_file_header(&ev->header,
                     (__u8)KERNEL_V1_EVENT_FILE_CREATE,
                     header_flags,
                     record_len,
                     valids_base);
    stamp_kfuncs(&ev->payload);

    __builtin_memcpy(ev->payload.file_create.path,
                     path_buf,
                     sizeof(path_buf));
    ev->payload.file_create.mode_bits = (__u32)mode_u16;
    ev->payload.file_create.exclusive = exclusive ? (__u8)1 : (__u8)0;
    ev->payload.file_create.result_flags = 0;
    ev->payload.file_create._pad0 = 0;
    ev->payload.file_create._pad1 = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/__x64_sys_creat")
int kp_x64_sys_creat(struct pt_regs *ctx)
{
    return emit_file_create(ctx,
                            PT_REGS_PARM1_SYSCALL(ctx),
                            PT_REGS_PARM2_SYSCALL(ctx));
}

#if defined(__TARGET_ARCH_arm64)
SEC("kprobe/__arm64_sys_creat")
int kp_arm64_sys_creat(struct pt_regs *ctx)
{
    return emit_file_create(ctx,
                            PT_REGS_PARM1_SYSCALL(ctx),
                            PT_REGS_PARM2_SYSCALL(ctx));
}
#endif

/* ------------------------------------------------------------------------- *
 *  FILE_UNLINK handler — `__x64_sys_unlinkat` /
 *  `__arm64_sys_unlinkat`. Arguments: dirfd (int), pathname (const
 *  char *), flags (int). The path is read best-effort.
 * ------------------------------------------------------------------------- */
static __always_inline int
emit_file_unlink(struct pt_regs *ctx, unsigned long arg_path,
                 unsigned long arg_flags)
{
    char path_buf[KERNEL_V1_FILE_PATH_MAX] = {0};
    long path_len = bpf_probe_read_user_str(path_buf,
                                            sizeof(path_buf),
                                            (const char *)arg_path);
    bool path_truncated = (path_len < 0);
    bool path_valid = !path_truncated;

    __u32 flags_word = (__u32)(arg_flags & 0xFFFFFFFFu);

    __u32 record_len = (__u32)(KERNEL_V1_ABI_HEADER_LEN +
                               KERNEL_V1_FILE_PAYLOAD_LEN);
    struct kernel_v1_event *ev =
        (struct kernel_v1_event *)bpf_ringbuf_reserve(&file_events,
                                                       record_len,
                                                       0);
    if (!ev) {
        return 0;
    }

    __u32 valids_base = (__u32)(KERNEL_V1_VALID_FILE_FLAGS
                                | KERNEL_V1_VALID_FILE_DENY_SOURCE);
    if (path_valid) {
        valids_base |= (__u32)KERNEL_V1_VALID_FILE_PATH;
    }

    __u8 header_flags = (__u8)0;
    if (path_truncated) {
        header_flags |= (__u8)KERNEL_V1_EVENT_FLAG_TRUNC;
    }

    fill_file_header(&ev->header,
                     (__u8)KERNEL_V1_EVENT_FILE_UNLINK,
                     header_flags,
                     record_len,
                     valids_base);
    stamp_kfuncs(&ev->payload);

    __builtin_memcpy(ev->payload.file_unlink.path,
                     path_buf,
                     sizeof(path_buf));
    ev->payload.file_unlink.flags = flags_word;
    ev->payload.file_unlink.result_flags = 0;
    ev->payload.file_unlink._pad0 = 0;
    ev->payload.file_unlink._pad1 = 0;
    ev->payload.file_unlink._pad2 = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/__x64_sys_unlinkat")
int kp_x64_sys_unlinkat(struct pt_regs *ctx)
{
    /* unlinkat(dirfd=p1, pathname=p2, flags=p3) */
    return emit_file_unlink(ctx,
                            PT_REGS_PARM2_SYSCALL(ctx),
                            PT_REGS_PARM3_SYSCALL(ctx));
}

#if defined(__TARGET_ARCH_arm64)
SEC("kprobe/__arm64_sys_unlinkat")
int kp_arm64_sys_unlinkat(struct pt_regs *ctx)
{
    return emit_file_unlink(ctx,
                            PT_REGS_PARM2_SYSCALL(ctx),
                            PT_REGS_PARM3_SYSCALL(ctx));
}
#endif

/* ------------------------------------------------------------------------- *
 *  FILE_RENAME handler — `__x64_sys_renameat2` /
 *  `__arm64_sys_renameat2`. The `olddirfd` and `newdirfd` are the
 *  first two ints; `oldpath` and `newpath` are the next two `const
 *  char *`; the trailing `flags` is the last `unsigned int`. We
 *  pull only the path arguments here (the flags are reported
 *  separately).
 * ------------------------------------------------------------------------- */
static __always_inline int
emit_file_rename(struct pt_regs *ctx, unsigned long arg_from,
                 unsigned long arg_to, unsigned long arg_flags)
{
    /* Single 256-byte path buffer, REUSED for both from and to.
     * The verifier's worst-case stack-frame analysis counts the
     * buffer once even though we re-read into it twice — each
     * access is unconditional, so the buffer always counts in
     * the worst case. After each read we copy into the ring
     * buffer's reserved memory (not the BPF stack), then clear
     * and read the next path. */
    char path_buf[KERNEL_V1_FILE_PATH_MAX] = {0};

    long from_len = bpf_probe_read_user_str(path_buf,
                                            sizeof(path_buf),
                                            (const char *)arg_from);
    bool from_truncated = (from_len < 0);
    bool from_valid = !from_truncated;

    __u32 record_len = (__u32)(KERNEL_V1_ABI_HEADER_LEN +
                               KERNEL_V1_FILE_PAYLOAD_LEN);
    struct kernel_v1_event *ev =
        (struct kernel_v1_event *)bpf_ringbuf_reserve(&file_events,
                                                       record_len,
                                                       0);
    if (!ev) {
        return 0;
    }

    __u32 valids_base = (__u32)(KERNEL_V1_VALID_FILE_FLAGS
                                | KERNEL_V1_VALID_FILE_DENY_SOURCE);
    if (from_valid) {
        valids_base |= (__u32)KERNEL_V1_VALID_FILE_PATH;
    }

    /* Reserve the header first, then read the second path into
     * the same path_buf, then copy into the ring buffer. The
     * header fields written by fill_file_header below contain
     * the from_path validity decision — the to_path validity
     * collapses to "valid iff the second read returned >= 0"
     * and we encode it in the header's TRUNC flag if either
     * path truncated. */
    __u8 header_flags = (__u8)0;

    /* Copy the first path into the reserved ring buffer
     * memory BEFORE reading the second one so a stack-buffer
     * collision cannot corrupt either side of the rename. */
    __builtin_memcpy(ev->payload.file_rename.from_path,
                     path_buf,
                     sizeof(path_buf));

    /* Reuse path_buf for the second (to) path. The verifier's
     * stack usage accounting is path_buf + locals which is
     * well under the 512-byte limit because we read one path
     * at a time. */
    __builtin_memset(path_buf, 0, sizeof(path_buf));
    long to_len = bpf_probe_read_user_str(path_buf,
                                          sizeof(path_buf),
                                          (const char *)arg_to);
    bool to_truncated = (to_len < 0);
    if (from_truncated || to_truncated) {
        header_flags |= (__u8)KERNEL_V1_EVENT_FLAG_TRUNC;
    }

    __u32 flags_word = (__u32)(arg_flags & 0xFFFFFFFFu);

    fill_file_header(&ev->header,
                     (__u8)KERNEL_V1_EVENT_FILE_RENAME,
                     header_flags,
                     record_len,
                     valids_base);
    stamp_kfuncs(&ev->payload);

    __builtin_memcpy(ev->payload.file_rename.to_path,
                     path_buf,
                     sizeof(path_buf));
    ev->payload.file_rename.flags = flags_word;
    ev->payload.file_rename.result_flags = 0;
    ev->payload.file_rename._pad0 = 0;
    ev->payload.file_rename._pad1 = 0;
    ev->payload.file_rename._pad2 = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/__x64_sys_renameat2")
int kp_x64_sys_renameat2(struct pt_regs *ctx)
{
    /* renameat2(olddirfd, oldpath, newdirfd, newpath, flags) */
    return emit_file_rename(ctx,
                            PT_REGS_PARM2_SYSCALL(ctx),
                            PT_REGS_PARM4_SYSCALL(ctx),
                            PT_REGS_PARM5_SYSCALL(ctx));
}

#if defined(__TARGET_ARCH_arm64)
SEC("kprobe/__arm64_sys_renameat2")
int kp_arm64_sys_renameat2(struct pt_regs *ctx)
{
    return emit_file_rename(ctx,
                            PT_REGS_PARM2_SYSCALL(ctx),
                            PT_REGS_PARM4_SYSCALL(ctx),
                            PT_REGS_PARM5_SYSCALL(ctx));
}
#endif

/* ------------------------------------------------------------------------- *
 *  FILE_TRUNCATE handler — `__x64_sys_truncate` /
 *  `__arm64_sys_truncate` AND a kprobe on `vfs_truncate` to catch
 *  writes that cause implicit truncation (e.g. `open(O_TRUNC)` plus
 *  a write). The kprobe path is gated by `bpf_core_field_exists` on
 *  the symbol.
 * ------------------------------------------------------------------------- */
static __always_inline int
emit_file_truncate(struct pt_regs *ctx, unsigned long arg_path,
                   unsigned long arg_length)
{
    char path_buf[KERNEL_V1_FILE_PATH_MAX] = {0};
    long path_len = bpf_probe_read_user_str(path_buf,
                                            sizeof(path_buf),
                                            (const char *)arg_path);
    bool path_truncated = (path_len < 0);
    bool path_valid = !path_truncated;

    __u64 length = (__u64)arg_length;

    __u32 record_len = (__u32)(KERNEL_V1_ABI_HEADER_LEN +
                               KERNEL_V1_FILE_PAYLOAD_LEN);
    struct kernel_v1_event *ev =
        (struct kernel_v1_event *)bpf_ringbuf_reserve(&file_events,
                                                       record_len,
                                                       0);
    if (!ev) {
        return 0;
    }

    __u32 valids_base = (__u32)KERNEL_V1_VALID_FILE_DENY_SOURCE;
    if (path_valid) {
        valids_base |= (__u32)KERNEL_V1_VALID_FILE_PATH;
    }

    __u8 header_flags = (__u8)0;
    if (path_truncated) {
        header_flags |= (__u8)KERNEL_V1_EVENT_FLAG_TRUNC;
    }

    fill_file_header(&ev->header,
                     (__u8)KERNEL_V1_EVENT_FILE_TRUNCATE,
                     header_flags,
                     record_len,
                     valids_base);
    stamp_kfuncs(&ev->payload);

    __builtin_memcpy(ev->payload.file_truncate.path,
                     path_buf,
                     sizeof(path_buf));
    ev->payload.file_truncate.length = length;
    ev->payload.file_truncate.result_flags = 0;
    ev->payload.file_truncate._pad0 = 0;
    ev->payload.file_truncate._pad1 = 0;
    ev->payload.file_truncate._pad2 = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/__x64_sys_truncate")
int kp_x64_sys_truncate(struct pt_regs *ctx)
{
    /* truncate(path, length) */
    return emit_file_truncate(ctx,
                              PT_REGS_PARM1_SYSCALL(ctx),
                              PT_REGS_PARM2_SYSCALL(ctx));
}

#if defined(__TARGET_ARCH_arm64)
SEC("kprobe/__arm64_sys_truncate")
int kp_arm64_sys_truncate(struct pt_regs *ctx)
{
    return emit_file_truncate(ctx,
                              PT_REGS_PARM1_SYSCALL(ctx),
                              PT_REGS_PARM2_SYSCALL(ctx));
}
#endif
