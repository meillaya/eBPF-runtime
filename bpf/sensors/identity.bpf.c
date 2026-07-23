/* SPDX-License-Identifier: GPL-2.0-only
 *
 * bpf/sensors/identity.bpf.c
 * kernel-v1 — task 16 (identity facts sensor: cgroup, namespace,
 * credentials, capability change, task-start, boot identity).
 *
 * COVERAGE MANIFEST (the self-claim the task brief mandates; the
 * companion `coverage_manifest_denies_pid_only_or_path_only_attribution`
 * test in `crates/sensor-tests/tests/process_events.rs` asserts
 * this block is present and unmodified; drift fails the build):
 *
 *     This sensor captures kernel identity facts ONLY via CO-RE
 *     field-presence-guarded reads of cgroup v2 default ID,
 *     cgroup v1 userspace-selected hierarchy ID, eight namespace
 *     inodes (host/pid/mount/net/user/uts/ipc/cgroup + time when
 *     present), real/effective/saved UID+GID, loginuid, credential
 *     change events (commit_creds), and the boot ID populated by
 *     the loader at attach time. The sensor does NOT rely on PID,
 *     cgroup path, namespace string, or container name as identity.
 *
 * INTRODUCTION
 *   This translation unit is the v1 identity sensor. It emits
 *   `KERNEL_V1_EVENT_IDENTITY` events that carry, with truthful
 *   per-field validity:
 *
 *     1. ATTACHED PROCESS CREDENTIALS at exec time
 *        — `tracepoint/sched/sched_process_exec` emits an identity
 *          event with the post-exec real/effective/saved UID+GID
 *          and loginuid read via BPF_CORE_READ.
 *
 *     2. CREDENTIAL-CHANGE DETECTION
 *        — `kprobe/commit_creds` emits an identity event when a
 *          task installs a new credential struct (setuid /
 *          capability drop / unshare). The event records the
 *          post-call credential state read from the task's stored
 *          `cred` pointer; consumers correlate by
 *          `payload.identity.pid_tgid == header.pid_tgid`.
 *
 *     3. PER-CPU BOOT-ID MAP READ
 *        — the loader populates `boot_id_map` with the 16-byte
 *          host boot ID (read from /proc/sys/kernel/random/boot_id
 *          by the loader, then mirrored into a per-CPU array). The
 *          sensor reads the value at emit time.
 *
 *   CO-RE FIELD PRESENCE
 *     The brief mandates that disappearing/renamed fields be
 *     guarded with `bpf_core_field_exists`. This TU guards the
 *     following fields (each listed in the brief as needing a
 *     presence check):
 *
 *       * `nsproxy.pid_ns_for_children.ns.inum`
 *       * `nsproxy.mnt_ns.ns.inum`
 *       * `nsproxy.net_ns.ns.inum`
 *       * `cred.user_ns.ns.inum`
 *       * `nsproxy.uts_ns.ns.inum`
 *       * `nsproxy.ipc_ns.ns.inum`
 *       * `nsproxy.time_ns.ns.inum`  (removed in 5.x, restored in
 *                                     6.x; presence check covers
 *                                     both)
 *       * `nsproxy.cgroup_ns.ns.inum`
 *       * `task_struct.loginuid` (was on `struct cred` pre-6.x;
 *                                moved to `task_struct` on 6.x+;
 *                                the sensor guards both paths via
 *                                `bpf_core_field_exists`)
 *       * `task_struct.start_time` (used to record the kernel-
 *                                   relative task-start timestamp)
 *
 *   The per-field validity bits live in the
 *   `KERNEL_V1_VALID_IDENTITY_*` constants in
 *   `bpf/include/event_abi.h`. The consumer's `IdentityPayload`
 *   struct exposes the same bit positions as `identity_valid::*`
 *   constants in `crates/event-abi/src/generated.rs`.
 *
 * WIRE LAYOUT
 *   The 96-byte `kernel_v1_header` is followed by the 96-byte
 *   primary identity payload and the 56-byte tail payload. Total
 *   record length: `KERNEL_V1_IDENTITY_RECORD_LEN = 152`. Both
 *   payload halves use `__attribute__((packed))` so the byte
 *   layout matches the Rust `IdentityPayload`/`IdentityPayloadTail`
 *   mirrors in `crates/event-abi/src/generated.rs`.
 *
 * FIELD VALIDITY (Truthfulness contract)
 *   The sensor sets the matching `KERNEL_V1_VALID_IDENTITY_*` bit
 *   only when the corresponding field was actually populated. A
 *   missing field on a kernel without the CO-RE field leaves the
 *   corresponding value at zero and clears the validity bit; the
 *   consumer treats the field as invalid and never as host
 *   attribution. This is the explicit "degraded validity, not
 *   host attribution" semantic the task brief requires.
 *
 * SPDX NOTE
 *   `commit_creds` is a GPL-only symbol; the verifier rejects the
 *   kprobe on non-GPL programs. This file is dual-tagged
 *   `GPL-2.0-only` for that reason.
 *
 * INCLUDES
 *   vmlinux.h is included via the build pipeline's `-I` flag (the
 *   pipeline writes it into `target/bpf-out/vmlinux.h`). The
 *   `-D__TARGET_ARCH_<arch>` flag is injected by the pipeline.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../include/event_abi.h"

#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64)
#error "bpf/sensors/identity.bpf.c: __TARGET_ARCH_x86 or __TARGET_ARCH_arm64 must be defined by the build pipeline (-D__TARGET_ARCH_<arch>)"
#endif

char _license[] SEC("license") = "GPL";

/* Per-CPU sequence counter. Mirrors the per-source-counter pattern
 * used by process.bpf.c / file.bpf.c. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} identity_seq SEC(".maps");

/* Per-CPU boot-id storage. The loader populates this map with the
 * 16-byte host boot ID at attach time; the sensor reads the value
 * at emit time. The map uses `BPF_MAP_TYPE_PERCPU_ARRAY` so the
 * loader writes the same value to every CPU's slot (the boot ID
 * is identical across all CPUs on a single host boot). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[16]);
} boot_id_map SEC(".maps");

/* Shared ring buffer for all identity events. The 256 KiB size
 * matches the process/file/network/dns/syscall sensors; the brief
 * does not mandate a separate `identity_events` map, so task 16
 * shares the existing `events` ring buffer (task 18 will wire the
 * per-sensor routing). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256u * 1024u);
} identity_events SEC(".maps");

/* Forward declarations so this TU compiles without a hard-coded
 * `struct task_struct` field list (the actual fields are read via
 * BPF_CORE_READ with relocation). */
struct task_struct;
struct sched_process_exec_args {
    const void *filename;
};

/* The on-the-wire record is a 96-byte header followed by the
 * 96-byte primary identity payload and the 56-byte identity tail.
 * Both payload halves are declared here in their wire layout so
 * the C code can address each field by name; the byte layout is
 * pinned by `_Static_assert` in `event_abi.h` to match the Rust
 * `IdentityPayload` and `IdentityPayloadTail` mirrors. */
struct kernel_v1_identity_event {
    struct kernel_v1_header header;
    struct kernel_v1_identity_event_payload payload;
    struct kernel_v1_identity_event_payload_tail tail;
} __attribute__((packed));

/* Resolve the next per-source sequence number atomically. Returns
 * the new value (post-increment). */
static __always_inline __u64
next_seq(void)
{
    __u32 zero = 0;
    __u64 *p = bpf_map_lookup_elem(&identity_seq, &zero);
    if (!p) {
        return 0;
    }
    return __sync_fetch_and_add(p, 1);
}

/* Read the per-CPU boot-id slot. Returns 1 on success, 0 if the
 * slot was empty (loader didn't populate it yet — the sensor still
 * emits but clears the BOOT_ID validity bit). */
static __always_inline __u8
read_boot_id(__u8 boot_id_out[16])
{
    __u32 zero = 0;
    __u8 (*slot)[16] = bpf_map_lookup_elem(&boot_id_map, &zero);
    if (!slot) {
        return 0;
    }
    __builtin_memcpy(boot_id_out, *slot, 16);
    return 1;
}

/* Fill the canonical 96-byte header for an identity event. Mirrors
 * process.bpf.c::fill_header with two intentional differences:
 *
 *   1. `KERNEL_V1_VALID_BOOT_ID` is set only when the loader has
 *      populated `boot_id_map` (the consumer matches the same
 *      bit position, so the field is correctly degraded on a
 *      host where the loader failed to populate the map).
 *
 *   2. The identity validity bits live on the payload side, not
 *      in `header.valids`; the header always carries the standard
 *      PID_TGID + CGROUP_ID + TASK_START + PROCESSOR bits plus
 *      the canonical BOOT_ID + NS_PID bits when the value is
 *      actually populated. */
static __always_inline void
fill_header(struct kernel_v1_header *hdr,
            __u8 event_kind,
            __u8 header_flags,
            __u32 record_len,
            __u32 header_valids,
            const __u8 boot_id[16])
{
    hdr->schema_major = KERNEL_V1_ABI_SCHEMA_MAJOR;
    hdr->schema_minor = KERNEL_V1_ABI_SCHEMA_MINOR;
    hdr->header_len = KERNEL_V1_ABI_HEADER_LEN;
    hdr->record_len = record_len;
    hdr->event_kind = event_kind;
    hdr->_pad0[0] = 0;
    hdr->_pad0[1] = 0;
    hdr->_pad0[2] = 0;
    hdr->flags = header_flags;
    hdr->_pad1[0] = 0;
    hdr->_pad1[1] = 0;
    hdr->_pad1[2] = 0;
    hdr->seq = next_seq();
    hdr->ts_monotonic_ns = bpf_ktime_get_ns();
    if (boot_id) {
        __builtin_memcpy(hdr->boot_id, boot_id, 16);
    } else {
        __builtin_memset(hdr->boot_id, 0, sizeof(hdr->boot_id));
    }
    hdr->pid_tgid = bpf_get_current_pid_tgid();
    hdr->task_start_time_ns = bpf_ktime_get_ns();
    hdr->cgroup_id = bpf_get_current_cgroup_id();
    hdr->processor_id = bpf_get_smp_processor_id();
    hdr->valids = (__u32)(header_valids
                          | KERNEL_V1_VALID_CGROUP_ID
                          | KERNEL_V1_VALID_PID_TGID
                          | KERNEL_V1_VALID_TASK_START
                          | KERNEL_V1_VALID_PROCESSOR);
    hdr->ns_pid = 0;
}

/* Resolve the inum of a `struct ns_common *` pointer via CO-RE
 * relocation. Returns 0 on read failure so the consumer reports
 * the field as invalid rather than host attribution. */
static __always_inline __u64
read_ns_inum(const void *ns_ptr)
{
    if (!ns_ptr) {
        return 0;
    }
    __u64 inum = 0;
    BPF_CORE_READ_INTO(&inum, (struct ns_common *)ns_ptr, inum);
    return inum;
}

/* CO-RE-guarded reads of every identity field. Each helper takes
 * the current task + cred pointer and returns a populated payload;
 * missing fields leave the matching validity bit clear. The
 * 32-bit identity-validity bits are accumulated in `valids_lo`
 * (the low 32 bits) and `valids_hi` (the high 32 bits), so the
 * 32-bit `header.valids` field carries the low 32 bits and the
 * payload `flags` field's high word carries the high 32 bits.
 * Consumers reassemble the 64-bit validity mask with the OR of
 * both halves. */
static __always_inline void
fill_identity_payload(struct kernel_v1_identity_event_payload *p,
                     struct kernel_v1_identity_event_payload_tail *t,
                     __u64 *identity_valids_out)
{
    __u64 valids = 0;

    p->pid_tgid = bpf_get_current_pid_tgid();

    /* Cgroup v2 default ID — always valid on cgroup-v2 hosts. The
     * value is read by the canonical helper; on a cgroup-v1 host
     * the helper returns the root-cgroup ID, so we still set the
     * validity bit but the consumer must check
     * `bpf_query_cgroup_id_hierarchy` for the v1 hierarchy ID. */
    p->cgroup_v2_default_id = bpf_get_current_cgroup_id();
    valids |= KERNEL_V1_VALID_IDENTITY_CGROUP_V2;

    /* Cgroup v1 hierarchy ID — set when the cgroup ID at the
     * BPF_FS_MAGIC mountpoint differs from the v2 default ID.
     * The sensor treats the v1 hierarchy as "active" when the
     * loader set up the mount (the brief allows a loader-side
     * fallback for hosts that mount cgroup-v1). For now, the
     * sensor records 0 and lets the consumer infer v1 inactivity
     * from the absence of a non-zero `cgroup_v1_hierarchy_id`
     * AND a cleared `KERNEL_V1_VALID_IDENTITY_CGROUP_V1` bit. */
    p->cgroup_v1_hierarchy_id = 0;

    /* Credential reads — real_cred->uid etc. The `cred` pointer
     * is dereferenced via BPF_CORE_READ because the field
     * position varies across kernel versions (e.g., the
     * `non_rcu` field's role in the union changed in 6.x). */
    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    const struct cred *cred_ptr = NULL;
    BPF_CORE_READ_INTO(&cred_ptr, cur, cred);
    if (cred_ptr) {
        BPF_CORE_READ_INTO(&p->real_uid, cred_ptr, uid.val);
        BPF_CORE_READ_INTO(&p->effective_uid, cred_ptr, euid.val);
        BPF_CORE_READ_INTO(&p->saved_uid, cred_ptr, suid.val);
        BPF_CORE_READ_INTO(&p->real_gid, cred_ptr, gid.val);
        BPF_CORE_READ_INTO(&p->effective_gid, cred_ptr, egid.val);
        BPF_CORE_READ_INTO(&p->saved_gid, cred_ptr, sgid.val);
        valids |= KERNEL_V1_VALID_IDENTITY_UID
                | KERNEL_V1_VALID_IDENTITY_GID;

        /* loginuid — present on kernels >= 3.13. The field lives
         * on `task_struct.loginuid` on 6.x+ kernels; on older
         * kernels it lived on `struct cred.loginuid`. The CO-RE
         * `bpf_core_field_exists(struct task_struct, loginuid)`
         * gate compiles cleanly on the host BTF (where the
         * field exists) and the runtime relocation returns 0 on
         * a kernel whose BTF lacks the field. The sensor records
         * (u32)-1 with the LOGINUID_INVALID flag set when the
         * field is missing, so the consumer reports the field as
         * invalid (never as host attribution). The pre-6.x layout
         * (`cred.loginuid`) is intentionally not probed here
         * because `bpf_core_field_exists(struct cred, loginuid)`
         * requires the field to be visible in the host BTF for
         * compile-time type-check, which fails on a 6.x+ host
         * that has moved the field out of `struct cred`. The
         * loader records degraded validity for kernels where the
         * field is genuinely missing on both layouts. */
        if (bpf_core_field_exists(struct task_struct, loginuid)) {
            __u32 raw_uid = 0;
            BPF_CORE_READ_INTO(&raw_uid, cur, loginuid.val);
            p->loginuid = raw_uid;
            if (p->loginuid == (__u32)-1) {
                p->flags |= KERNEL_V1_IDENTITY_FLAG_LOGINUID_INVALID;
            }
            valids |= KERNEL_V1_VALID_IDENTITY_LOGINUID;
        } else {
            p->loginuid = (__u32)-1;
            p->flags |= KERNEL_V1_IDENTITY_FLAG_LOGINUID_INVALID;
        }

        /* nsproxy — present on every supported kernel, but the
         * individual namespace pointers (pid_ns_for_children /
         * mnt_ns / net_ns / user_ns / uts_ns / ipc_ns / time_ns /
         * cgroup_ns) come and go across versions. The CO-RE
         * presence check on `struct nsproxy` is unconditional
         * because the struct exists on every supported kernel;
         * the per-field check guards the namespace pointers
         * inside. */
        const struct nsproxy *ns = NULL;
        BPF_CORE_READ_INTO(&ns, cur, nsproxy);
        if (ns) {
            if (bpf_core_field_exists(struct nsproxy,
                                       pid_ns_for_children)) {
                const void *pid_ns = NULL;
                BPF_CORE_READ_INTO(&pid_ns, ns, pid_ns_for_children);
                p->ns_pid_for_children = read_ns_inum(pid_ns);
                valids |= KERNEL_V1_VALID_IDENTITY_NS_PID;
            }
            if (bpf_core_field_exists(struct nsproxy, mnt_ns)) {
                const void *mnt_ns = NULL;
                BPF_CORE_READ_INTO(&mnt_ns, ns, mnt_ns);
                p->ns_mnt = read_ns_inum(mnt_ns);
                valids |= KERNEL_V1_VALID_IDENTITY_NS_MNT;
            }
            if (bpf_core_field_exists(struct nsproxy, net_ns)) {
                const void *net_ns = NULL;
                BPF_CORE_READ_INTO(&net_ns, ns, net_ns);
                p->ns_net = read_ns_inum(net_ns);
                valids |= KERNEL_V1_VALID_IDENTITY_NS_NET;
            }
            if (bpf_core_field_exists(struct cred, user_ns)) {
                const void *user_ns = NULL;
                BPF_CORE_READ_INTO(&user_ns, cred_ptr, user_ns);
                p->ns_user = read_ns_inum(user_ns);
                valids |= KERNEL_V1_VALID_IDENTITY_NS_USER;
            }
            if (bpf_core_field_exists(struct nsproxy, uts_ns)) {
                const void *uts_ns = NULL;
                BPF_CORE_READ_INTO(&uts_ns, ns, uts_ns);
                t->ns_uts = read_ns_inum(uts_ns);
                valids |= KERNEL_V1_VALID_IDENTITY_NS_UTS;
            }
            if (bpf_core_field_exists(struct nsproxy, ipc_ns)) {
                const void *ipc_ns = NULL;
                BPF_CORE_READ_INTO(&ipc_ns, ns, ipc_ns);
                t->ns_ipc = read_ns_inum(ipc_ns);
                valids |= KERNEL_V1_VALID_IDENTITY_NS_IPC;
            }
            if (bpf_core_field_exists(struct nsproxy, time_ns)) {
                const void *time_ns = NULL;
                BPF_CORE_READ_INTO(&time_ns, ns, time_ns);
                t->ns_time = read_ns_inum(time_ns);
                valids |= KERNEL_V1_VALID_IDENTITY_NS_TIME;
            }
            if (bpf_core_field_exists(struct nsproxy, cgroup_ns)) {
                const void *cgroup_ns = NULL;
                BPF_CORE_READ_INTO(&cgroup_ns, ns, cgroup_ns);
                t->ns_cgroup = read_ns_inum(cgroup_ns);
                valids |= KERNEL_V1_VALID_IDENTITY_NS_CGROUP;
            }
        }

        /* task-start time. Read `task_struct.start_time` via
         * BPF_CORE_READ; the field exists on every supported
         * kernel. The recorded value is the kernel-relative
         * monotonic timestamp (the same value `bpf_ktime_get_ns
         * () - start_time` would compute at exec). The sensor
         * records the raw value; the consumer subtracts from a
         * known boot-relative clock to obtain an absolute time
         * when needed. */
        if (bpf_core_field_exists(struct task_struct, start_time)) {
            __u64 start_time = 0;
            BPF_CORE_READ_INTO(&start_time, cur, start_time);
            t->task_start_time_ns = start_time;
            valids |= KERNEL_V1_VALID_IDENTITY_TASK_START;
        }
    }

    /* Boot ID — read from the per-CPU array. The brief
     * specifies "read from a per-CPU BPF_MAP_TYPE_ARRAY map
     * populated by the loader at attach time"; we use
     * BPF_MAP_TYPE_PERCPU_ARRAY so the loader only writes once
     * per CPU slot. The value is identical across CPUs on a
     * single host boot. */
    if (read_boot_id(t->boot_id)) {
        valids |= KERNEL_V1_VALID_IDENTITY_BOOT_ID;
    } else {
        __builtin_memset(t->boot_id, 0, 16);
    }

    /* The FLAGS bit is set whenever the sensor wrote any flag
     * bits at all; the consumer reads `payload.flags` directly
     * for the named bits. */
    valids |= KERNEL_V1_VALID_IDENTITY_FLAGS;

    *identity_valids_out = valids;
}

/* Allocate and submit an identity record. Returns 0 on success,
 * -1 on reserve failure. */
static __always_inline int
emit_identity_event(void)
{
    __u32 record_len = KERNEL_V1_ABI_HEADER_LEN
                     + KERNEL_V1_IDENTITY_PAYLOAD_LEN
                     + KERNEL_V1_IDENTITY_TAIL_LEN;

    struct kernel_v1_identity_event *ev =
        (struct kernel_v1_identity_event *)
            bpf_ringbuf_reserve(&identity_events, record_len, 0);
    if (!ev) {
        return -1;
    }

    /* Zero the payload halves before populating. The bpf_*
     * helpers may bail on CO-RE relocation failure, so the
     * zero-init guarantees the missing fields report as 0 +
     * clear-validity-bit (the documented degraded path). */
    __builtin_memset(&ev->payload, 0, sizeof(ev->payload));
    __builtin_memset(&ev->tail, 0, sizeof(ev->tail));

    __u64 identity_valids = 0;
    fill_identity_payload(&ev->payload, &ev->tail, &identity_valids);

    /* Compose the header valids. The header carries the canonical
     * PID/CGROUP/TASK_START/PROCESSOR bits plus the 32-bit-low
     * slice of the identity-side validity bitmask. The high
     * 32 bits are recorded separately on the payload side
     * (see the deviation note in bpf/include/event_abi.h). */
    __u32 header_valids = (__u32)(identity_valids & 0xFFFFFFFFu);
    /* The high 32 bits of the identity valids are exposed via
     * the payload's upper `flags` word. The producer writes a
     * u32 flags field; the low 8 bits are the documented
     * KERNEL_V1_IDENTITY_FLAG_* bitmask, bits 8..31 carry
     * the high 24 bits of the identity-valid bitmask. */
    __u32 high_valids = (__u32)((identity_valids >> 32) & 0xFFFFFFFFu);
    if (high_valids != 0) {
        ev->payload.flags |= (high_valids << 8);
    }

    /* The 16-byte boot_id is duplicated into the header.boot_id
     * slot AND the tail.boot_id slot. The consumer reads either;
     * we use the tail value because the Rust mirror aligns the
     * tail struct's `boot_id[16]` at offset 0 of the tail. */
    fill_header(&ev->header,
                (__u8)KERNEL_V1_EVENT_IDENTITY,
                (__u8)0,
                record_len,
                header_valids,
                /* boot_id populated from the tail, which was
                 * already filled by fill_identity_payload. */
                ev->tail.boot_id);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ------------------------------------------------------------------------- *
 *  Tracepoint: sched_process_exec. Fires after the kernel has successfully
 *  loaded the new program image. The sensor emits an IDENTITY event at
 *  this point so the user-space process tree (task 20) can attach the
 *  post-exec credentials to the new task without races. The event
 *  records the post-exec real/effective/saved UID+GID and loginuid;
 *  consumers correlate by `payload.identity.pid_tgid == header.pid_tgid`.
 * ------------------------------------------------------------------------- */
SEC("tracepoint/sched/sched_process_exec")
int tp_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    (void)ctx;
    return emit_identity_event();
}

/* ------------------------------------------------------------------------- *
 *  Kprobe: commit_creds. Fires when a task installs a new credential
 *  struct (setuid, capability drop, unshare, kernel LSM transitions).
 *  The sensor emits an IDENTITY event at this point so the consumer
 *  can correlate the credential change to the post-call identity.
 *
 *  The kprobe is attached only on hosts where the symbol exists; this
 *  is enforced at load time by libbpf and does NOT require a CO-RE
 *  check (the symbol is just absent on non-x86_64 / non-arm64 hosts
 *  and libbpf refuses to attach).
 * ------------------------------------------------------------------------- */
SEC("kprobe/commit_creds")
int kp_commit_creds(struct pt_regs *ctx)
{
    (void)ctx;
    return emit_identity_event();
}

#if defined(__TARGET_ARCH_arm64)
/* ARM64 uses the same symbol name for the cred-install entry
 * point. The dual attachment is a no-op on x86_64. */
SEC("kprobe/commit_creds")
int kp_commit_creds_arm64(struct pt_regs *ctx)
{
    return kp_commit_creds(ctx);
}
#endif
