/* SPDX-License-Identifier: (MIT OR Apache-2.0)
 *
 * bpf/include/event_abi.h
 * kernel-v1 — authoritative C↔Rust event ABI v1.
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
 * (gRPC, Kafka) encodes a separate protobuf (task 6).
 */

#ifndef KERNEL_V1_EVENT_ABI_H
#define KERNEL_V1_EVENT_ABI_H

/* The event ABI is consumed in three distinct translation contexts:
 *
 *   1. Host-C ABI size check (`crates/event-abi/build.rs` runs a tiny
 *      TU that includes only this header to confirm the struct
 *      layout and the static_asserts in it).
 *   2. BPF sensor programs compiled with `clang -target bpf`
 *      (task 10's `bpf/sensors/*.bpf.c` sources include vmlinux.h
 *      first, which already provides `__u8/16/32/64`, `u8/16/32/64`,
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
/* vmlinux.h has already provided __u8/16/32/64, u8/16/32/64,
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

/* EventKind — every semantic event the platform can emit (15 values).
 * The proto contract (proto/kernel/v1/events/v1/events.proto::EventKind)
 * and this C enum must stay in lockstep. The Rust parser accepts any
 * value in [1, KERNEL_V1_EVENT_IDENTITY] and rejects 0 and any value
 * above. */
enum kernel_v1_event_kind {
    KERNEL_V1_EVENT_UNSPECIFIED              = 0,
    KERNEL_V1_EVENT_PROCESS_FORK             = 1,
    KERNEL_V1_EVENT_PROCESS_EXEC_RESULT      = 2,
    KERNEL_V1_EVENT_PROCESS_EXIT             = 3,
    KERNEL_V1_EVENT_FILE_OPEN                = 4,
    KERNEL_V1_EVENT_FILE_CREATE              = 5,
    KERNEL_V1_EVENT_FILE_UNLINK              = 6,
    KERNEL_V1_EVENT_FILE_RENAME              = 7,
    KERNEL_V1_EVENT_NETWORK_CONNECT          = 8,
    KERNEL_V1_EVENT_NETWORK_ACCEPT           = 9,
    KERNEL_V1_EVENT_NETWORK_STATE            = 10,
    KERNEL_V1_EVENT_DNS_PACKET               = 11,
    KERNEL_V1_EVENT_SYSCALL_ENTER            = 12,
    KERNEL_V1_EVENT_SYSCALL_EXIT             = 13,
    KERNEL_V1_EVENT_LSM_DENY_OWN             = 14,
    KERNEL_V1_EVENT_IDENTITY                 = 15,
};

/* Validity bitmask. Each set bit means the corresponding identity
 * field is meaningful; a clear bit means the field is invalid. The
 * C struct only carries fields up to the 96-byte boundary; the
 * remaining valid bits are forward-compat placeholders. */
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
};

/* Required bits for a v1 process event: pid_tgid + cgroup_id + boot_id
 * + task_start. Tests use this to assert minimum validity. */
#define KERNEL_V1_VALID_REQUIRED                                             \
    ((uint32_t)(KERNEL_V1_VALID_BOOT_ID | KERNEL_V1_VALID_CGROUP_ID          \
                | KERNEL_V1_VALID_PID_TGID | KERNEL_V1_VALID_TASK_START))

/* v1 producer MUST NOT set bits above 14. */
#define KERNEL_V1_VALID_V1_ALLOWED_MASK ((uint32_t)0x00007FFFu)

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

/* Build-time size and offset assertions. The kernel-v1 build pipeline
 * (task 10) compiles a tiny TU that includes this header and only
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
