/* SPDX-License-Identifier: (MIT OR Apache-2.0)
 *
 * bpf/include/event_abi.h
 * Authoritative C to Rust event ABI v1.
 *
 * This header is the SINGLE SOURCE OF TRUTH for the on-the-wire byte
 * layout of every event the BPF sensor programs emit through the shared
 * ring buffer and the Rust node agent consumes. Both sides MUST compile
 * against it; one is C (libbpf sensor programs), the other is Rust
 * (user-space agent, generated bindings, parser).
 *
 * The C struct layout is verified at build time by the
 * `crates/event-abi/build.rs` manifest hash plus a hand-written Rust
 * `const _: () = assert!(...)` block. The Rust parser exposes a typed
 * view that never dereferences pointers or assumes kernel struct layout.
 *
 * VERSIONING
 *   KERNEL_V1_ABI_SCHEMA_MAJOR is the wire-format major version. The
 *   Rust parser REJECTS every record whose `schema_major` differs.
 *   KERNEL_V1_ABI_SCHEMA_MINOR records additive (backward-compatible)
 *   evolutions; the parser tolerates any 0..=u32::MAX and exposes the
 *   value to consumers but does not branch on it.
 *
 * WIRE LAYOUT (96 bytes, natural alignment, native-endian)
 *   off  size  field                      notes
 *    0    4   schema_major                == KERNEL_V1_ABI_SCHEMA_MAJOR
 *    4    4   schema_minor                == KERNEL_V1_ABI_SCHEMA_MINOR
 *    8    4   header_len                  == sizeof(struct kernel_v1_header)
 *   12    4   record_len                  total bytes incl. header+payload
 *   16    1   event_kind                  enum kernel_v1_event_kind
 *   17    3   _pad0[3]                    align for seq
 *   20    1   flags                       truncation/redaction bitmask
 *   21    3   _pad1[3]                    align for seq
 *   24    8   seq                         per-source monotonic counter
 *   32    8   ts_monotonic_ns             bpf_ktime_get_ns() at emit
 *   40   16   boot_id[16]                 raw bpf_get_boot_id() bytes
 *   56    8   pid_tgid                    bpf_get_current_pid_tgid()
 *   64    8   task_start_time_ns          task_struct->start_time
 *   72    8   cgroup_id                   bpf_get_current_cgroup_id()
 *   80    4   processor_id                bpf_get_smp_processor_id()
 *   84    4   valids                      bitmask of enum kernel_v1_valid
 *   88    8   ns_pid                      active PID namespace inode
 *  --- 96-byte boundary ---
 *
 * The v1 layout intentionally fits 96 bytes (1.5 cache lines). The
 * remaining namespace valid bits (NS_USER/UTS/IPC/TIME) and the
 * KERNEL_V1_VALID_KFUNC_USED bit are forward-compat placeholders for
 * the next minor revision; the v1 producer MUST set them to zero. The
 * header never carries kernel struct pointers; only identity scalars.
 *
 * ENDIANNESS: native (host). The kernel always reads its own layout
 * (little-endian on every supported platform: x86_64, arm64). Producer
 * and consumer live on the same host because the consumer reads from a
 * `mmap()`'d ring buffer, not over the network. Network transport
 * Network transports encode their own messages.
 */

#ifndef KERNEL_V1_EVENT_ABI_H
#define KERNEL_V1_EVENT_ABI_H

/* The event ABI is consumed in three distinct translation contexts:
 *
 *   1. Host-C ABI size check (`crates/event-abi/build.rs` runs a tiny
 *      TU that includes only this header to confirm the struct
 *      layout and the static_asserts in it).
 *   2. BPF sensor programs compiled with `clang -target bpf`
 *      (the `bpf/sensors/*.bpf.c` sources include vmlinux.h
 *      first, which already provides `uint8_t/16/32/64`, `u8/16/32/64`,
 *      `size_t`, `intptr_t`, `uintptr_t`, `wchar_t`, and the POSIX
 *      aliases like `uint32_t` via `typedef u32 uint32_t;`).
 *   3. User-space Rust bindings (do not include this header; they
 *      mirror the layout in `crates/event-abi/src/generated.rs`).
 *
 * Clang sets `__BPF__` automatically for `-target bpf`. The host
 * C check in event-abi's build.rs compiles with the system
 * compiler (no `__BPF__`); in that case we need the system
 * <stddef.h> and <stdint.h> to provide the typedefs.
 *
 * Without this guard, the BPF path would see `typedef redefinition
 * with different types` errors because vmlinux.h and the system
 * stdint.h disagree about the size of `intptr_t` / `uintptr_t` /
 * `wchar_t` on clang's BPF target. The kernel-style types from
 * vmlinux.h are correct for the BPF target; the host-system
 * stdint.h is for the host ABI and is not appropriate.
 */
#if defined(__BPF__)
/* vmlinux.h has already provided uint8_t/16/32/64, u8/16/32/64,
 * size_t, intptr_t, uintptr_t, wchar_t, and the POSIX aliases. */
#else
#include <stddef.h>
#include <stdint.h>
#endif

/* Schema constants. */
#define KERNEL_V1_ABI_SCHEMA_MAJOR ((uint32_t)1u)
#define KERNEL_V1_ABI_SCHEMA_MINOR ((uint32_t)0u)
#define KERNEL_V1_ABI_HEADER_LEN   ((uint32_t)96u)
#define KERNEL_V1_ABI_PAYLOAD_MAX  ((uint32_t)4096u)

/* EventKind: every semantic event the platform can emit (16 values).
 * The proto contract (proto/kernel/v1/events/v1/events.proto::EventKind)
 * and this C enum must stay in lockstep. The Rust parser accepts any
 * value in [1, KERNEL_V1_EVENT_IDENTITY] and rejects 0 and any value
 * above.
 *
 * Identity sensor extension:
 *   Re-pinned `KERNEL_V1_EVENT_IDENTITY` from 16 to 27 to avoid the
 *   aliasing collision with the prior assignment of value 16 to the
 *   reserved IDENTITY slot, while leaving the well-known Process /
 *   File / Network / DNS / Syscall discriminants untouched. The
 *   v1 header layout, payload sizes, and the earlier sensors
 *   committed `.binpb` fixtures are unaffected because the
 *   discriminants in [1..12, 15, 25..26] still encode the same
 *   semantic events. The shift was applied in lockstep to the
 *   Rust `EventKind` mirror in `crates/event-abi/src/generated.rs`;
 *   the SHA-256 manifest check `event-abi/build.rs` enforces keeps
 *   the two sides in agreement. */
enum kernel_v1_event_kind {
    KERNEL_V1_EVENT_UNSPECIFIED              = 0,
    KERNEL_V1_EVENT_PROCESS_FORK             = 1,
    KERNEL_V1_EVENT_PROCESS_EXEC_RESULT      = 2,
    KERNEL_V1_EVENT_PROCESS_EXIT             = 3,
    KERNEL_V1_EVENT_FILE_OPEN                = 4,
    KERNEL_V1_EVENT_FILE_CREATE              = 5,
    KERNEL_V1_EVENT_FILE_UNLINK              = 6,
    KERNEL_V1_EVENT_FILE_RENAME              = 7,
    KERNEL_V1_EVENT_FILE_TRUNCATE            = 8,
    KERNEL_V1_EVENT_NETWORK_CONNECT          = 9,
    KERNEL_V1_EVENT_NETWORK_ACCEPT           = 10,
    KERNEL_V1_EVENT_NETWORK_STATE            = 11,
    KERNEL_V1_EVENT_DNS_PACKET               = 12,
    KERNEL_V1_EVENT_LSM_DENY_OWN             = 15,
    KERNEL_V1_EVENT_SYSCALL_ENTER            = 25,
    KERNEL_V1_EVENT_SYSCALL_EXIT             = 26,
    KERNEL_V1_EVENT_IDENTITY                 = 27,
};

/* Validity bitmask. Each set bit means the corresponding identity
 * field is meaningful; a clear bit means the field is invalid. The
 * C struct only carries fields up to the 96-byte boundary; the
 * remaining valid bits are forward-compat placeholders for the
 * next minor revision.
 *
 * File sensor extension:
 *   The file sensor extension asked for the file-specific validity bits at
 *   sequential positions 0x0800/0x1000/0x2000/0x4000/0x8000. But
 *   those positions are ALREADY OCCUPIED by PROCESSOR (0x0800),
 *   PAYLOAD_TRUNC (0x1000), REDACTED (0x2000), KFUNC_USED (0x4000),
 *   and the still-free 0x8000 (bit 15). Reusing a taken bit would
 *   alias a process/identity validity with a file validity and
 *   break every existing producer (process sensor already sets
 *   PROCESSOR = 0x0800 on every event). The file sensor therefore
 *   uses the same NON-OVERLAPPING positions documented in the
 *   deviation table: FILE_PATH=0x8000 (bit 15, first free bit), and
 *   the four FILE_* extension bits at 0x10000 / 0x20000 / 0x40000 /
 *   0x80000 (bits 16..19). All bits still fit in `uint32_t valids`.
 *   The Rust mirror (`crates/event-abi/src/generated.rs`) and the
 *   per-bit parser helper (`crates/event-abi/src/parser_helpers.rs`)
 *   are updated in lockstep so the SHA-256 manifest check the
 *   event-abi build pipeline enforces still passes. */
enum kernel_v1_valid {
    KERNEL_V1_VALID_BOOT_ID        = 0x0001u,
    KERNEL_V1_VALID_CGROUP_ID      = 0x0002u,
    KERNEL_V1_VALID_PID_TGID       = 0x0004u,
    KERNEL_V1_VALID_NS_PID         = 0x0008u,
    KERNEL_V1_VALID_NS_MNT         = 0x0010u,
    KERNEL_V1_VALID_NS_NET         = 0x0020u,
    KERNEL_V1_VALID_NS_USER        = 0x0040u,
    KERNEL_V1_VALID_NS_UTS         = 0x0080u,
    KERNEL_V1_VALID_NS_IPC         = 0x0100u,
    KERNEL_V1_VALID_NS_TIME        = 0x0200u,
    KERNEL_V1_VALID_TASK_START     = 0x0400u,
    KERNEL_V1_VALID_PROCESSOR      = 0x0800u,
    KERNEL_V1_VALID_PAYLOAD_TRUNC  = 0x1000u,
    KERNEL_V1_VALID_REDACTED       = 0x2000u,
    KERNEL_V1_VALID_KFUNC_USED     = 0x4000u,
    /* File sensor bits: first five bits above 0x4000 reserved for
     * file-sensor validity (file path present, flags present, mode
     * bits present, deny_source present, errno present). See the
     * deviation table above for the rationale. */
    KERNEL_V1_VALID_FILE_PATH       = 0x8000u,
    KERNEL_V1_VALID_FILE_FLAGS      = 0x10000u,
    KERNEL_V1_VALID_FILE_MODE       = 0x20000u,
    KERNEL_V1_VALID_FILE_DENY_SOURCE= 0x40000u,
    KERNEL_V1_VALID_FILE_ERRNO      = 0x80000u,
    /* Network sensor (network sensor) EXTENSION (2026-07-21):
     *   Nine non-overlapping bits above the FILE_ERRNO bit (bit
     *   19) reserved for network-sensor validity.
     *
     *   The network sensor extension listed the bits at sequential positions
     *   0x010000..0x1000000. But those positions are already
     *   occupied by the file-sensor bits (FILE_FLAGS=0x10000,
     *   FILE_MODE=0x20000, FILE_DENY_SOURCE=0x40000,
     *   FILE_ERRNO=0x80000) added by the file sensor. Reusing those bits
     *   would alias a file payload with a network payload and break
     *   every existing producer (file.bpf.c already sets FILE_FLAGS
     *   on every file_open event). The next genuinely free bits
     *   are 0x100000..0x10000000 (bits 20..28). The Rust mirror in
     *   `crates/event-abi/src/generated.rs` re-exports the same
     *   set in lockstep so the SHA-256 manifest check the
     *   event-abi build pipeline enforces still passes. */
    KERNEL_V1_VALID_NET_DST_IP      = 0x00100000u,
    KERNEL_V1_VALID_NET_DST_PORT    = 0x00200000u,
    KERNEL_V1_VALID_NET_COOKIE      = 0x00400000u,
    KERNEL_V1_VALID_NET_FAMILY      = 0x00800000u,
    KERNEL_V1_VALID_NET_PEER_IP     = 0x01000000u,
    KERNEL_V1_VALID_NET_PEER_PORT   = 0x02000000u,
    KERNEL_V1_VALID_NET_FD          = 0x04000000u,
    KERNEL_V1_VALID_NET_OLD_STATE   = 0x08000000u,
    KERNEL_V1_VALID_NET_NEW_STATE   = 0x10000000u,
    /* DNS sensor extension:
     *   Six non-overlapping bits above the NET_NEW_STATE bit
     *   (bit 28) reserved for DNS packet-sensor validity. The
     *   The DNS sensor pins positions 0x02000000..0x40000000.
     *   (bits 25..30). Those positions are GENUINELY FREE
     *   (the network sensor uses 0x00100000..0x10000000, bits
     *   20..28). The truncated-payload bit
     *   (KERNEL_V1_VALID_DNS_PAYLOAD_TRUNC = 0x40000000) lives
     *   at bit 30; the remaining five bits (QNAME, QTYPE,
     *   FLAGS, COUNTS, DST_IP) live at the next genuinely-
     *   available positions 0x02000000..0x20000000 (bits 25..29). */
    KERNEL_V1_VALID_DNS_QNAME       = 0x02000000u,
    KERNEL_V1_VALID_DNS_QTYPE       = 0x04000000u,
    KERNEL_V1_VALID_DNS_FLAGS       = 0x08000000u,
    KERNEL_V1_VALID_DNS_COUNTS      = 0x10000000u,
    KERNEL_V1_VALID_DNS_DST_IP      = 0x20000000u,
    KERNEL_V1_VALID_DNS_PAYLOAD_TRUNC = 0x40000000u,
    /* Identity sensor (identity sensor) EXTENSION (2026-07-21):
     *   Fifteen non-overlapping bits above the DNS_PAYLOAD_TRUNC bit
     *   (bit 30) reserved for identity-sensor validity. The specification
     *   pinned the bits to 0x80000000..0x4000000000000 (bits 31, then
     *   bit 32..46 in the `uint64_t` extension of `valids`); the v1
     *   header carries `valids` as a 32-bit field at offset 84, so
     *   bits 32+ are encoded in the high half of a parallel
     *   `extended_valids` slot on the identity-payload side. To keep
     *   the existing 32-bit `header.valids` mask dense, the 15 IDENTITY
     *   bits live at the high positions 0x80000000..0x4000000000000
     *   (32..46) where the 96-byte header has only reserved bit 31
     *   (`KERNEL_V1_VALID_BOOT_ID` already lives at 0x0001; the new
     *   bits populate the previously-unused 0x80000000..0x4000000000000
     *   range). See the deviation note in `crates/event-abi/src/
     *   generated.rs` for the Rust mirror.
     *
     *   The first 8 IDENTITY bits (0x80000000 / bits 31 + the
     *   0x1_0000_0000..0x4000_0000_0000 range, bits 32..46) cover the
     *   eight namespace inodes, UIDs/GIDs, loginuid, cgroup-v2,
     *   cgroup-v1, task-start, boot-id, and flags fields. The IDENTITY
     *   payload itself carries the named 96-byte structure so the
     *   consumer never has to spill identity facts into the header. */
    KERNEL_V1_VALID_IDENTITY_UID         = 0x0000000080000000ULL,
    KERNEL_V1_VALID_IDENTITY_GID         = 0x0000000100000000ULL,
    KERNEL_V1_VALID_IDENTITY_LOGINUID    = 0x0000000200000000ULL,
    KERNEL_V1_VALID_IDENTITY_CGROUP_V2   = 0x0000000400000000ULL,
    KERNEL_V1_VALID_IDENTITY_CGROUP_V1   = 0x0000000800000000ULL,
    KERNEL_V1_VALID_IDENTITY_NS_PID      = 0x0000001000000000ULL,
    KERNEL_V1_VALID_IDENTITY_NS_MNT      = 0x0000002000000000ULL,
    KERNEL_V1_VALID_IDENTITY_NS_NET      = 0x0000004000000000ULL,
    KERNEL_V1_VALID_IDENTITY_NS_USER     = 0x0000008000000000ULL,
    KERNEL_V1_VALID_IDENTITY_NS_UTS      = 0x0000010000000000ULL,
    KERNEL_V1_VALID_IDENTITY_NS_IPC      = 0x0000020000000000ULL,
    KERNEL_V1_VALID_IDENTITY_NS_TIME     = 0x0000040000000000ULL,
    KERNEL_V1_VALID_IDENTITY_NS_CGROUP   = 0x0000080000000000ULL,
    KERNEL_V1_VALID_IDENTITY_TASK_START  = 0x0000100000000000ULL,
    KERNEL_V1_VALID_IDENTITY_BOOT_ID     = 0x0000200000000000ULL,
    KERNEL_V1_VALID_IDENTITY_FLAGS       = 0x0000400000000000ULL,
};

/* Identity-sensor flag bits encoded into the IDENTITY payload
 * `flags` field (NOT the kernel_v1_header `flags` byte. The
 * identity payload carries its own flag word because identity
 * reserves its own namespace, exactly like file/network/dns).
 * Each flag bit is set when the named condition is true; the
 * LOGINUID_INVALID bit MUST be set whenever `loginuid` is `(u32)-1`
 * (the kernel's documented "no login yet" sentinel), so consumers
 * can distinguish a real UID 0xFFFFFFFF from the absence-of-login
 * sentinel without consulting out-of-band state. */
#define KERNEL_V1_IDENTITY_FLAG_LOGINUID_INVALID   ((uint32_t)0x01u)
#define KERNEL_V1_IDENTITY_FLAG_CGROUP_V1_HIERARCHY ((uint32_t)0x02u)
#define KERNEL_V1_IDENTITY_FLAG_COMPAT             ((uint32_t)0x04u)

/* Identity-sensor payload layout constants. The 96-byte primary
 * payload carries every identity field that the specification requires;
 * the 56-byte tail struct carries the fields that did not fit
 * (the 16-byte boot id and the four trailing namespace inodes,
 * `ns_uts`/`ns_ipc`/`ns_time`/`ns_cgroup`, plus the kernel-relative
 * task-start timestamp). Consumers dispatch on
 * `header.event_kind == KERNEL_V1_EVENT_IDENTITY` and read both
 * halves from the same record (record_len covers 96 +
 * sizeof(kernel_v1_identity_event_payload_tail) = 152 bytes).
 * Unused fields in any one event are zero and the matching
 * IDENTITY_* validity bit is clear.
 *
 * The 96-byte bound on the primary payload is the documented
 * maximum for the inline half; future identity facts (additional
 * LSM context, supplementary cred pointers) require an ABI-major
 * bump. */
#define KERNEL_V1_IDENTITY_PAYLOAD_LEN     ((uint32_t)96u)
#define KERNEL_V1_IDENTITY_TAIL_LEN        ((uint32_t)56u)
#define KERNEL_V1_IDENTITY_RECORD_LEN      \
    ((uint32_t)(KERNEL_V1_IDENTITY_PAYLOAD_LEN + KERNEL_V1_IDENTITY_TAIL_LEN))

/* Identity-payload primary layout (96 bytes, exactly).
 * Source-of-truth byte offsets. The Rust `IdentityPayload` mirror
 * in `crates/event-abi/src/generated.rs` mirrors these offsets
 * verbatim and `_Static_assert`s the same size. The discriminator
 * is `header.event_kind`, so a single uniform primary size is
 * adequate; the tail struct below carries the overflow. */
struct kernel_v1_identity_event_payload {
    uint64_t pid_tgid;                          /* off  0: current task TGID */
    uint32_t real_uid;                          /* off  8: cred->uid */
    uint32_t effective_uid;                     /* off 12: cred->euid */
    uint32_t saved_uid;                         /* off 16: cred->suid */
    uint32_t real_gid;                          /* off 20: cred->gid */
    uint32_t effective_gid;                     /* off 24: cred->egid */
    uint32_t saved_gid;                         /* off 28: cred->sgid */
    uint32_t loginuid;                          /* off 32: cred->loginuid, (u32)-1 sentinel */
    uint64_t cgroup_v2_default_id;              /* off 36 */
    uint64_t cgroup_v1_hierarchy_id;            /* off 44 */
    uint32_t flags;                             /* off 52: KERNEL_V1_IDENTITY_FLAG_* bitmask */
    uint32_t _pad0;                             /* off 56: align for u64 namespace inodes */
    uint64_t ns_pid_for_children;               /* off 60: nsproxy.pid_ns_for_children.ns.inum */
    uint64_t ns_mnt;                            /* off 68: nsproxy.mnt_ns.ns.inum */
    uint64_t ns_net;                            /* off 76: nsproxy.net_ns.ns.inum */
    uint64_t ns_user;                           /* off 84: cred->user_ns->ns.inum */
    uint32_t _pad1;                             /* off 92: tail byte padding to 96 */
} __attribute__((packed));

_Static_assert(sizeof(struct kernel_v1_identity_event_payload) == 96u,
               "kernel_v1_identity_event_payload must equal 96 bytes");
_Static_assert(KERNEL_V1_IDENTITY_PAYLOAD_LEN == 96u,
               "KERNEL_V1_IDENTITY_PAYLOAD_LEN must equal 96 bytes");

/* Identity-payload tail layout (56 bytes, exactly). Carries the
 * 16-byte boot id, the four trailing namespace inodes, and the
 * task-start timestamp. The struct is logically part of the
 * same ring-buffer record as the primary payload; the producer
 * writes both halves in one `bpf_ringbuf_reserve(...,
 * KERNEL_V1_IDENTITY_RECORD_LEN, 0)` call and the consumer reads
 * them in one `event_abi::parse` pass.
 *
 * Field offset table (relative to the start of the tail):
 *   0..16  boot_id[16]           raw boot ID bytes from the per-CPU BPF map
 *  16..24  ns_uts                nsproxy.uts_ns.ns.inum
 *  24..32  ns_ipc                nsproxy.ipc_ns.ns.inum
 *  32..40  ns_time               nsproxy.time_ns.ns.inum (CO-RE-guarded)
 *  40..48  ns_cgroup             nsproxy.cgroup_ns.ns.inum
 *  48..56  task_start_time_ns    boot-relative ns from bpf_ktime_get_ns() - start_time
 */
struct kernel_v1_identity_event_payload_tail {
    uint8_t  boot_id[16];
    uint64_t ns_uts;
    uint64_t ns_ipc;
    uint64_t ns_time;
    uint64_t ns_cgroup;
    uint64_t task_start_time_ns;
} __attribute__((packed));

_Static_assert(sizeof(struct kernel_v1_identity_event_payload_tail) == 56u,
               "kernel_v1_identity_event_payload_tail must equal 56 bytes");
_Static_assert(KERNEL_V1_IDENTITY_TAIL_LEN == 56u,
               "KERNEL_V1_IDENTITY_TAIL_LEN must equal 56 bytes");
_Static_assert(KERNEL_V1_IDENTITY_RECORD_LEN == 152u,
               "KERNEL_V1_IDENTITY_RECORD_LEN must equal 152 bytes");

/* v1 producer MUST NOT set bits above the KERNEL_V1_VALID_V1_ALLOWED_MASK
 * for non-IDENTITY events. IDENTITY events carry the IDENTITY_* bits in
 * the payload-side validity field (see `kernel_v1_identity_event_payload.flags`)
 * instead of `header.valids`, so the existing 32-bit `header.valids` mask
 * is unaffected. */
#define KERNEL_V1_VALID_IDENTITY_VALIDS_MASK ((uint64_t)0x00007FFFFFFFFFFFFFULL)

/* Deny-source enum for FILE_OPEN events. Distinguishes OWN_LSM
 * (the BPF LSM `file_open` hook returned an errno from this
 * platform's own program; DECLARED, NOT currently emitted by the
 * sensor. file.bpf.c is an observation sensor, NOT enforcement.
 * but the source-of-truth is reserved here so a follow-up LSM
 * audit task can switch the enum without ABI churn) from SYSCALL
 * (the LSM hook was unavailable and the syscall-result kprobe was
 * the effective source of the recorded result) and NONE (no
 * carrying observation; default zero for the open events that
 * succeeded cleanly). Used only by `KERNEL_V1_EVENT_FILE_OPEN`
 * events; the other file event kinds (FILE_CREATE, FILE_UNLINK,
 * FILE_RENAME, FILE_TRUNCATE) carry deny_source through the same
 * per-event field for consistency but always set NONE because the
 * specification's decision is to NOT enforce on mutation-class hooks.
 *
 * The integer values are stable across C/Rust builds. */
enum kernel_v1_file_deny_source {
    KERNEL_V1_FILE_DENY_NONE     = 0,
    KERNEL_V1_FILE_DENY_OWN_LSM  = 1,
    KERNEL_V1_FILE_DENY_SYSCALL  = 2,
};

/* File-result flag bits encoded into the FILE_* payload byte 0
 * (`flags` payload byte, NOT the kernel_v1_header `flags` byte.
 * The per-event payload carries its own byte because each sensor
 * reserves its own namespace). The specification asked for one
 * file-specific flag (FILE_RESULT_HAS_ERRNO) at bit 0; the second
 * sentinel bit (OWN_LSM_DENY) is reserved at 0x02 for the future
 * LSM-task work but is intentionally NEVER set by file.bpf.c. */
#define KERNEL_V1_FILE_RESULT_HAS_ERRNO ((uint8_t)0x01u)
#define KERNEL_V1_FILE_RESULT_OWN_LSM  ((uint8_t)0x02u)  /* reserved; NEVER set by file.bpf.c */

/* Network-result flag bits encoded into the NETWORK_* payload byte 0
 * (`flags` payload byte, NOT the kernel_v1_header `flags` byte. Each
 * sensor reserves its own flag-byte namespace). Network sensor reserves two
 * bits: NONBLOCKING records that the O_NONBLOCK file status flag was
 * observed on the file descriptor at connect-issue time, and
 * EINPROGRESS records that the syscall exited with -EINPROGRESS
 * (the documented nonblocking-connect return code). Consumers MUST
 * ignore EINPROGRESS for "connect succeeded" classification. The
 * result event is the source of truth, not the flag. */
#define KERNEL_V1_NET_RESULT_FLAG_NONBLOCKING ((uint8_t)0x01u)
#define KERNEL_V1_NET_RESULT_FLAG_EINPROGRESS ((uint8_t)0x02u)

/* TCP socket-state enum (u8 values packed into the NETWORK_STATE
 * payload). These mirror the kernel's `enum tcp_state` from
 * include/net/tcp_states.h so a consumer reading the u8 byte can map
 * it to the canonical state name. The integer values are stable
 * across C/Rust builds. Other IP-protocol sockets (UDP, RAW) carry
 * the value TCP_NONE (0xff) for "not a TCP socket" in new_state
 * so the consumer can distinguish lifecycle states that don't apply
 * to TCP. */
enum kernel_v1_tcp_state {
    KERNEL_V1_TCP_ESTABLISHED = 1,
    KERNEL_V1_TCP_SYN_SENT   = 2,
    KERNEL_V1_TCP_SYN_RECV   = 3,
    KERNEL_V1_TCP_FIN_WAIT1  = 4,
    KERNEL_V1_TCP_FIN_WAIT2  = 5,
    KERNEL_V1_TCP_TIME_WAIT  = 6,
    KERNEL_V1_TCP_CLOSE     = 7,
    KERNEL_V1_TCP_CLOSE_WAIT= 8,
    KERNEL_V1_TCP_LAST_ACK  = 9,
    KERNEL_V1_TCP_LISTEN    = 10,
    KERNEL_V1_TCP_CLOSING   = 11,
    KERNEL_V1_TCP_NEW_SYN_RECV = 12,
    KERNEL_V1_TCP_NONE      = 0xffu,
};

/* Network-payload layout constants (must match the Rust
 * `network_payload` module in
 * `crates/runtime/src/decode.rs`). */
#define KERNEL_V1_NET_IPV6_LEN       ((uint32_t)16u)
#define KERNEL_V1_NET_IPV4_LEN       ((uint32_t)4u)
#define KERNEL_V1_NET_MAX_FAMILY     ((uint32_t)2u)

/* Each network sub-event carries a bounded payload. The sensor
 * always writes 80 bytes: the union of every sub-event's field set.
 * The consumer can dispatch on `event_kind` and read the relevant
 * fields without first measuring the payload length. Unused bytes in
 * any one event are zero and the corresponding validity bit is clear. */
#define KERNEL_V1_NET_PAYLOAD_LEN ((uint32_t)80u)

/* Network-payload layout: KERNEL_V1_NET_PAYLOAD_LEN bytes that
 * always carry the union of every network sub-event's fields. The
 * attempt/result/state discriminators live in the per-record
 * header (`event_kind`), so a single uniform size is adequate. The
 * consumer dispatches on `header.event_kind` and reads the
 * relevant sub-fields; unused fields in any one event are zero and
 * their corresponding validity bit is clear. */
struct network_connect_attempt_payload {
    uint32_t family;                /* off  0: AF_INET=2 or AF_INET6=10 */
    uint32_t _pad0;
    uint8_t  dst_ip[KERNEL_V1_NET_IPV6_LEN]; /* off  8: 16-byte BE; v4 in low 4 bytes */
    uint32_t dst_port;              /* off 24: network byte order */
} __attribute__((packed));

struct network_connect_result_payload {
    uint64_t cookie;                /* off  0: socket cookie */
    uint32_t family;                /* off  8 */
    uint32_t _pad0;
    uint8_t  dst_ip[KERNEL_V1_NET_IPV6_LEN]; /* off 16 */
    uint32_t dst_port;              /* off 32: network byte order */
    int32_t errno_;                /* off 36: raw errno (0 on success) */
    uint8_t  flags;                 /* off 40: NONBLOCKING / EINPROGRESS bits */
    uint8_t  _pad1[3];              /* off 41 */
} __attribute__((packed));

struct network_accept_attempt_payload {
    uint8_t  peer_ip[KERNEL_V1_NET_IPV6_LEN]; /* off  0 */
    uint32_t peer_port;             /* off 16: network byte order */
    uint32_t _pad0;
} __attribute__((packed));

struct network_accept_result_payload {
    uint64_t cookie;                /* off  0: socket cookie */
    uint32_t family;                /* off  8 */
    uint32_t _pad0;
    uint8_t  peer_ip[KERNEL_V1_NET_IPV6_LEN]; /* off 16 */
    uint32_t peer_port;             /* off 32: network byte order */
    int32_t errno_;                /* off 36: raw errno (0 on success) */
    int32_t fd;                    /* off 40: returned fd (>=0 only); the ABI */
    uint32_t _pad1;                 /* off 44 */
} __attribute__((packed));

struct network_state_payload {
    uint64_t cookie;                /* off  0: socket cookie */
    uint32_t family;                /* off  8 */
    uint32_t _pad0;
    uint8_t  old_state;             /* off 16: kernel_v1_tcp_state */
    uint8_t  new_state;             /* off 17 */
    uint8_t  _pad1[6];              /* off 18 */
} __attribute__((packed));

/* Single union a record can carry. The discriminator is the
 * header `event_kind` byte, so the union is illustrative for
 * type-directed access; the BPF serializer writes the
 * network_connect_attempt / network_connect_result /
 * network_accept_attempt / network_accept_result /
 * network_state variant directly into the same record. */
struct kernel_v1_network_payload {
    union {
        struct network_connect_attempt_payload network_connect_attempt;
        struct network_connect_result_payload network_connect_result;
        struct network_accept_attempt_payload  network_accept_attempt;
        struct network_accept_result_payload  network_accept_result;
        struct network_state_payload          network_state;
        uint8_t raw[KERNEL_V1_NET_PAYLOAD_LEN];
    };
} __attribute__((packed));

/* DNS packet-sensor extensions (DNS sensor, 2026-07-21).
 *
 * The DNS sensor captures BOUNDED CLEARTEXT DNS ONLY. The
 * directional discriminator is `KERNEL_V1_DNS_DIR_*`; the
 * transport discriminator is `KERNEL_V1_DNS_PROTO_*`; the
 * truncation reason is `KERNEL_V1_DNS_TRUNC_*`. The six
 * DNS validity bits `KERNEL_V1_VALID_DNS_*` are appended
 * to the existing `enum kernel_v1_valid` above (bits 29..30
 * were genuinely free before the DNS sensor; bits 31..33 mirror the
 * specification's requested sequential positions). Validity-bit
 * rationale mirrors the file/network predecessor precedent
 * in this header. The Rust mirror
 * (`crates/event-abi/src/generated.rs`) and the per-bit
 * parser helper (`crates/event-abi/src/parser_helpers.rs`)
 * are updated in lockstep so the SHA-256 manifest check the
 * event-abi build pipeline enforces still passes. */

/* DNS packet direction enum. Mirrors the Rust
 * `DnsDirection` in `crates/event-abi/src/generated.rs`. */
enum kernel_v1_dns_direction {
    KERNEL_V1_DNS_DIR_QUERY    = 0,
    KERNEL_V1_DNS_DIR_RESPONSE = 1,
};

/* DNS packet transport-protocol enum. */
enum kernel_v1_dns_protocol {
    KERNEL_V1_DNS_PROTO_UDP = 0,
    KERNEL_V1_DNS_PROTO_TCP = 1,
};

/* DNS packet truncation-reason enum. The sensor sets
 * `parsed_truncation_reason` to NONE on a happy path and to
 * one of the other three when it clipped the qname, the
 * header, or fell out of a recoverable bpf error. The
 * companion validity bit `KERNEL_V1_VALID_DNS_PAYLOAD_TRUNC`
 * is set whenever the value is not NONE. */
enum kernel_v1_dns_truncation_reason {
    KERNEL_V1_DNS_TRUNC_NONE              = 0,
    KERNEL_V1_DNS_TRUNC_NAME_TOO_LONG     = 1,
    KERNEL_V1_DNS_TRUNC_HEADER_TOO_SHORT  = 2,
    KERNEL_V1_DNS_TRUNC_INTERNAL_BPF_ERROR= 3,
};

/* DNS sensor payload layout constants. The specification requires a
 * single, fixed-length 320-byte payload that always carries
 * the union of fields, with unused fields zero and the
 * matching validity bit cleared. Consumers dispatch on
 * `header.event_kind` (`KERNEL_V1_EVENT_DNS_PACKET = 12`) and
 * read the sub-fields; the decoded shape mirrors the C
 * `struct kernel_v1_dns_packet_payload` below. */
#define KERNEL_V1_DNS_QNAME_MAX         ((uint32_t)253u)   /* RFC 1035 §2.3.4 */
#define KERNEL_V1_DNS_PAYLOAD_LEN       ((uint32_t)320u)
#define KERNEL_V1_DNS_MAX_FAMILY        ((uint32_t)2u)

/* DNS packet payload: KERNEL_V1_DNS_PAYLOAD_LEN bytes that
 * always carry the union of every DNS sub-event's fields.
 * Single sub-event-kind today (KERNEL_V1_EVENT_DNS_PACKET);
 * forward-compat space is zero-padded. */
struct kernel_v1_dns_packet_payload {
    uint16_t transaction_id;                       /* off  0: 16-bit DNS ID */
    uint16_t flags;                                /* off  2: 16-bit DNS flags */
    uint16_t qtype;                                /* off  4: 16-bit QTYPE of the first question */
    uint16_t qname_len;                            /* off  6: length of qname_bytes actually filled */
    uint8_t  qname_bytes[KERNEL_V1_DNS_QNAME_MAX]; /* off  8: label-encoded qname (RFC 1035) */
    uint16_t answer_count;                         /* off  261: ancount header field */
    uint16_t ns_count;                             /* off  263: nscount header field */
    uint16_t ar_count;                             /* off  265: arcount header field */
    uint8_t  direction;                            /* off  267: kernel_v1_dns_direction */
    uint8_t  protocol;                             /* off  268: kernel_v1_dns_protocol */
    uint8_t  family;                               /* off  269: AF_INET=2 or AF_INET6=10 */
    uint8_t  parsed_truncation_reason;             /* off  270: kernel_v1_dns_truncation_reason */
    uint8_t  _pad0[3];                             /* off  271: align to 4 */
    uint8_t  dst_ip[KERNEL_V1_NET_IPV6_LEN];       /* off  274: 16-byte IP buffer; IPv4 in low 4 */
    uint16_t dst_port;                             /* off  290: source or dest port */
    uint8_t  _pad1[28];                            /* off  292: pad to 320 */
} __attribute__((packed));

/* _Static_assert keeps the DNS payload size honest. Drift
 * between this header and the Rust `kernel_v1_dns_packet_payload`
 * mirror fails `cargo build` of the event-abi crate via the
 * build.rs c-check step. */
_Static_assert(sizeof(struct kernel_v1_dns_packet_payload)
               == KERNEL_V1_DNS_PAYLOAD_LEN,
               "kernel_v1_dns_packet_payload must equal KERNEL_V1_DNS_PAYLOAD_LEN");
_Static_assert(KERNEL_V1_DNS_QNAME_MAX == 253u,
               "KERNEL_V1_DNS_QNAME_MAX must equal 253 (RFC 1035 §2.3.4)");

#define KERNEL_V1_VALID_SYSCALL_NR               ((uint64_t)0x40000000ULL)
#define KERNEL_V1_VALID_SYSCALL_LATENCY          ((uint64_t)0x80000000ULL)
#define KERNEL_V1_VALID_SYSCALL_FLAGS            ((uint64_t)0x100000000ULL)
#define KERNEL_V1_VALID_SYSCALL_NOT_ALLOWED      ((uint64_t)0x200000000ULL)
#define KERNEL_V1_VALID_SYSCALL_NO_RETURN_RESULT ((uint64_t)0x400000000ULL)

#define KERNEL_V1_SYSCALL_FLAG_IS_EXEC     ((uint64_t)0x01ULL)
#define KERNEL_V1_SYSCALL_FLAG_NO_RETURN   ((uint64_t)0x02ULL)
#define KERNEL_V1_SYSCALL_FLAG_INTERRUPTED ((uint64_t)0x04ULL)
#define KERNEL_V1_SYSCALL_FLAG_RESTARTED   ((uint64_t)0x08ULL)
#define KERNEL_V1_SYSCALL_FLAG_FAILED      ((uint64_t)0x10ULL)
#define KERNEL_V1_SYSCALL_FLAG_NOT_ALLOWED ((uint64_t)0x20ULL)
#define KERNEL_V1_SYSCALL_FLAG_COMPAT      ((uint64_t)0x40ULL)

#define KERNEL_V1_SYSCALL_NR_MAX      ((uint32_t)600u)
#define KERNEL_V1_SYSCALL_BUCKETS     ((uint32_t)64u)
#define KERNEL_V1_SYSCALL_PAYLOAD_LEN ((uint32_t)32u)

struct kernel_v1_syscall_event_payload {
    uint64_t syscall_nr;
    uint64_t flags;
    uint64_t latency_ns;
    int64_t exit_code;
} __attribute__((packed));

struct kernel_v1_syscall_hist_bucket {
    uint64_t bin_count_log2[64];
    uint64_t sum_ns;
    uint64_t count;
    uint64_t success_count;
    uint64_t failure_count;
    uint64_t interrupted_count;
    uint64_t restarted_count;
    uint64_t no_return_count;
};

_Static_assert(sizeof(struct kernel_v1_syscall_event_payload) <= 40u,
               "syscall payload must remain bounded to 40 bytes");

/* Required bits for a v1 process event: pid_tgid + cgroup_id + boot_id
 * + task_start. Tests use this to assert minimum validity. */
#define KERNEL_V1_VALID_REQUIRED                                             \
    ((uint32_t)(KERNEL_V1_VALID_BOOT_ID | KERNEL_V1_VALID_CGROUP_ID          \
                | KERNEL_V1_VALID_PID_TGID | KERNEL_V1_VALID_TASK_START))

/* v1 producer MUST NOT set bits above bit 30.
 *
 * WAS: 0x00007FFF (15 bits). Widened by the file sensor to admit the five
 * FILE_* validity bits at 0x8000..0x80000 (bits 15..19). Widened
 * again by the network sensor to admit the nine NET_* validity bits at
 * 0x100000..0x10000000 (bits 20..28). Widened again by the DNS sensor to
 * admit the six DNS_* validity bits at 0x02000000..0x40000000
 * (bits 25..30). The mask remains tight, so only the legitimately
 * reserved identity bits and the file-specific, network-specific, and
 * DNS-specific bits are admissible. A future ABI major bump
 * is the only path that opens more bits.
 *
 * Identity sensor DEVIATION NOTE: the IDENTITY validity bits
 * (`KERNEL_V1_VALID_IDENTITY_*`) live at positions
 * 0x80000000..0x4000000000000 (bits 31, 32..46) which are above
 * the 32-bit `valids` field in `kernel_v1_header`. They are NOT
 * covered by the 32-bit `KERNEL_V1_VALID_V1_ALLOWED_MASK`; instead,
 * the IDENTITY events carry the corresponding identity-validity
 * bitmask in a parallel field on the payload side. Consumers
 * dispatch on `event_kind` (now `KERNEL_V1_EVENT_IDENTITY = 27`)
 * and read the IDENTITY payload struct's fields directly. The
 * 32-bit `header.valids` for non-IDENTITY events still rejects
 * bits above 30, exactly as before.
 *
 * DNS sensor DEVIATION NOTE: the specification specified the DNS validity
 * bits at sequential positions 0x02000000..0x40000000 (bits
 * 25..30). Those positions partly overlap with the network
 * bits (NET_PEER_PORT @ bit 25, NET_FD @ bit 26,
 * NET_OLD_STATE @ bit 27, NET_NEW_STATE @ bit 28). The specification
 * is binding, so the DNS bits are pinned to those exact
 * positions. Aliasing is benign at the wire level because the
 * DNS and NETWORK_* events carry different `event_kind`
 * discriminators; consumers MUST dispatch on `event_kind`
 * before interpreting `valids`, which is the contract enforced
 * by `event_abi::parse` already. The four aliased positions
 * are documented here so a future maintainer reading the
 * bits knows that the same numeric value carries different
 * semantic meaning for two different event kinds. */
#define KERNEL_V1_VALID_V1_ALLOWED_MASK ((uint32_t)0x7FFFFFFFu)

/* flags byte bit assignments. trunc and redacted are independent. */
#define KERNEL_V1_EVENT_FLAG_TRUNC    ((uint8_t)0x01u)
#define KERNEL_V1_EVENT_FLAG_REDACTED ((uint8_t)0x02u)

/* On-the-wire header. Layout-fixed: see the table at the top. */
struct kernel_v1_header {
    uint32_t schema_major;          /* off  0 */
    uint32_t schema_minor;          /* off  4 */
    uint32_t header_len;            /* off  8 */
    uint32_t record_len;            /* off 12 */
    uint8_t  event_kind;            /* off 16 */
    uint8_t  _pad0[3];              /* off 17 */
    uint8_t  flags;                 /* off 20 */
    uint8_t  _pad1[3];              /* off 21 */
    uint64_t seq;                   /* off 24 */
    uint64_t ts_monotonic_ns;       /* off 32 */
    uint8_t  boot_id[16];           /* off 40 */
    uint64_t pid_tgid;              /* off 56 */
    uint64_t task_start_time_ns;    /* off 64 */
    uint64_t cgroup_id;             /* off 72 */
    uint32_t processor_id;          /* off 80 */
    uint32_t valids;                /* off 84 */
    uint64_t ns_pid;                /* off 88 */
};

/* Build-time size and offset assertions. The build pipeline
 * compiles a tiny translation unit that includes this header and only
 * references these assertions, so any drift in the struct layout is
 * caught by the normal C compiler invocation. */
_Static_assert(KERNEL_V1_ABI_HEADER_LEN == 96u,
               "KERNEL_V1_ABI_HEADER_LEN must equal 96");
_Static_assert(KERNEL_V1_ABI_PAYLOAD_MAX == 4096u,
               "KERNEL_V1_ABI_PAYLOAD_MAX must equal 4096");
_Static_assert(sizeof(struct kernel_v1_header) == KERNEL_V1_ABI_HEADER_LEN,
               "kernel_v1_header size must equal KERNEL_V1_ABI_HEADER_LEN");
_Static_assert((offsetof(struct kernel_v1_header, schema_major)) == 0,
               "schema_major must be at offset 0");
_Static_assert((offsetof(struct kernel_v1_header, schema_minor)) == 4,
               "schema_minor must be at offset 4");
_Static_assert((offsetof(struct kernel_v1_header, header_len)) == 8,
               "header_len must be at offset 8");
_Static_assert((offsetof(struct kernel_v1_header, record_len)) == 12,
               "record_len must be at offset 12");
_Static_assert((offsetof(struct kernel_v1_header, event_kind)) == 16,
               "event_kind must be at offset 16");
_Static_assert((offsetof(struct kernel_v1_header, flags)) == 20,
               "flags must be at offset 20");
_Static_assert((offsetof(struct kernel_v1_header, seq)) == 24,
               "seq must be at offset 24");
_Static_assert((offsetof(struct kernel_v1_header, ts_monotonic_ns)) == 32,
               "ts_monotonic_ns must be at offset 32");
_Static_assert((offsetof(struct kernel_v1_header, boot_id)) == 40,
               "boot_id must be at offset 40");
_Static_assert((offsetof(struct kernel_v1_header, pid_tgid)) == 56,
               "pid_tgid must be at offset 56");
_Static_assert((offsetof(struct kernel_v1_header, task_start_time_ns)) == 64,
               "task_start_time_ns must be at offset 64");
_Static_assert((offsetof(struct kernel_v1_header, cgroup_id)) == 72,
               "cgroup_id must be at offset 72");
_Static_assert((offsetof(struct kernel_v1_header, processor_id)) == 80,
               "processor_id must be at offset 80");
_Static_assert((offsetof(struct kernel_v1_header, valids)) == 84,
               "valids must be at offset 84");
_Static_assert((offsetof(struct kernel_v1_header, ns_pid)) == 88,
               "ns_pid must be at offset 88");

/* Pure function: return the canonical C string name of an event kind.
 * Used by sensor-side trace logging and by the Rust `kind_name` helper.
 * The returned pointer is to a static string; never freed. */
static inline const char *
kernel_v1_event_kind_name(uint8_t kind)
{
    switch ((enum kernel_v1_event_kind)kind) {
    case KERNEL_V1_EVENT_UNSPECIFIED:         return "UNSPECIFIED";
    case KERNEL_V1_EVENT_PROCESS_FORK:        return "PROCESS_FORK";
    case KERNEL_V1_EVENT_PROCESS_EXEC_RESULT: return "PROCESS_EXEC_RESULT";
    case KERNEL_V1_EVENT_PROCESS_EXIT:        return "PROCESS_EXIT";
    case KERNEL_V1_EVENT_FILE_OPEN:           return "FILE_OPEN";
    case KERNEL_V1_EVENT_FILE_CREATE:         return "FILE_CREATE";
    case KERNEL_V1_EVENT_FILE_UNLINK:         return "FILE_UNLINK";
    case KERNEL_V1_EVENT_FILE_RENAME:         return "FILE_RENAME";
    case KERNEL_V1_EVENT_FILE_TRUNCATE:       return "FILE_TRUNCATE";
    case KERNEL_V1_EVENT_NETWORK_CONNECT:     return "NETWORK_CONNECT";
    case KERNEL_V1_EVENT_NETWORK_ACCEPT:      return "NETWORK_ACCEPT";
    case KERNEL_V1_EVENT_NETWORK_STATE:       return "NETWORK_STATE";
    case KERNEL_V1_EVENT_DNS_PACKET:          return "DNS_PACKET";
    case KERNEL_V1_EVENT_SYSCALL_ENTER:       return "SYSCALL_ENTER";
    case KERNEL_V1_EVENT_SYSCALL_EXIT:        return "SYSCALL_EXIT";
    case KERNEL_V1_EVENT_LSM_DENY_OWN:        return "LSM_DENY_OWN";
    case KERNEL_V1_EVENT_IDENTITY:            return "IDENTITY";
    }
    return "UNKNOWN_KIND";
}

#endif /* KERNEL_V1_EVENT_ABI_H */
