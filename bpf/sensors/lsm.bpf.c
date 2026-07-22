/* SPDX-License-Identifier: GPL-2.0-only
 *
 * bpf/sensors/lsm.bpf.c
 * kernel-v1 — task 33 (audit-first BPF LSM deny engine).
 *
 * INTRODUCTION
 *   This translation unit is the v1 audit-first enforcement surface.
 *   It attaches three BPF LSM hooks -- file_open, bprm_check_security
 *   (binary exec), and socket_connect -- and evaluates ONE
 *   authoritative, kernel-observable selector per hook family against
 *   a small policy map. Every invocation emits an audit decision
 *   event; the hook returns an errno ONLY when ALL of the following
 *   hold:
 *
 *     1. the policy for this hook family exists and its selector
 *        matches the kernel-observable context exactly (prefix match
 *        on the bounded selector bytes);
 *     2. the policy mode is DENY (mode == 1); every policy SHIPS at
 *        audit-only (mode == 0) and only the staged validated-map
 *        path (task 34) may promote a policy to deny;
 *     3. no prior LSM has already decided (the incoming `ret == 0`);
 *     4. the kill-switch is NOT engaged (deny_disabled == 0).
 *
 *   In every other case the hook returns 0 (allow) or preserves the
 *   incoming nonzero `ret` unchanged. The engine NEVER denies from
 *   user-space enrichment or heuristics: the only selectors are the
 *   kernel-observable file path component, the binary path
 *   (bprm->filename), and the socket address (sockaddr).
 *
 * OWN-DENIAL ATTRIBUTION (the central truthfulness invariant)
 *   The deny_source recorded in an audit decision event is OWN_LSM
 *   ONLY when THIS program returns an errno (decision == DENY). A
 *   nonzero incoming `ret` means a prior LSM (SELinux, AppArmor, or
 *   another BPF program) already decided; the engine records
 *   PRIOR_LSM, preserves that `ret` byte-for-byte, and NEVER relabels
 *   it OWN_LSM. An audit-mode match records NONE (the syscall result
 *   is unchanged). This is the producer-side truth the consumer
 *   relies on: a record that says PRIOR_LSM or NONE may NOT be
 *   relabeled OWN_LSM downstream.
 *
 * PRIOR-RET PRESERVATION
 *   BPF LSM hooks compose: the trampoline passes the running return
 *   value as the trailing `ret` argument. If `ret != 0` on entry, a
 *   prior hook already denied; we return `ret` UNCHANGED so we never
 *   override another LSM's decision (the brief's "preservation of
 *   nonzero prior BPF-program ret").
 *
 * FAIL-OPEN
 *   Unknown or unsupported context fails open: an unreadable selector
 *   (path read fault, unknown sockaddr family, missing/empty policy
 *   map entry, selector longer than the bounded buffer) returns 0 and
 *   records decision == FAIL_OPEN_UNKNOWN or ALLOW with deny_source
 *   NONE. The engine NEVER denies on a context it cannot observe
 *   truthfully ("guess path on read fault" is forbidden, mirroring
 *   file.bpf.c).
 *
 * KILL-SWITCH
 *   A single-slot lsm_kill_switch map carries deny_disabled. When
 *   deny_disabled == 1, every deny-mode decision degrades to
 *   audit-only (decision == DENY_SUPPRESSED_KILLSWITCH, return 0).
 *   The agent flips this slot from the gRPC control plane; the map
 *   read is a single bpf_map_lookup_elem so the deny-disabled state
 *   takes effect within bench/schemas/enforcement.v1.json#
 *   kill_switch_max_ms (default 5000) of the command reaching the
 *   agent (bench/kill-switch.sh measures the p99).
 *
 * FIELD VALIDITY (Truthfulness contract)
 *   * Identity invariants mirror the file/process sensors: pid_tgid,
 *     cgroup_id, task_start, processor_id are recorded with the
 *     standard KERNEL_V1_VALID_* bits. boot_id is NOT set here (the
 *     loader/task-16 identity event owns it; setting it without a
 *     real read would be a lie).
 *   * The selector bytes are bounded to KERNEL_V1_LSM_SELECTOR_MAX
 *     (256). A truncated selector sets KERNEL_V1_EVENT_FLAG_TRUNC and
 *     is treated as no-match (fail-open); the consumer MUST consult
 *     the flag before drawing the selector claim.
 *
 * SECTION NAMES AND THE LOADER DENY-LINK POLICY
 *   The hooks use the canonical libbpf LSM section names
 *   ("lsm/file_open", "lsm/bprm_check_security",
 *   "lsm/socket_connect"). They deliberately do NOT contain the
 *   substring "OWN_LSM_DENY": the task-18 loader refuses to attach
 *   any hook whose section name carries that marker (crates/bpf-
 *   loader/src/lib.rs::probe_and_load). The own-denial semantic lives
 *   in the decision payload's deny_source field, not in the section
 *   name, so the loader's deny-link guard is unaffected and deny
 *   links are never pinned (the loader pins nothing for this sensor).
 *
 * SPDX NOTE
 *   BPF LSM programs (BPF_PROG_TYPE_LSM) are REQUIRED by the kernel
 *   verifier to carry a GPL-compatible license string. This file
 *   declares GPL-2.0-only and the license section "GPL"; MIT/Apache
 *   is NOT acceptable for this program type and would be rejected at
 *   load time. (See README.md "Kernel-side BPF SPDX policy".)
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "event_abi.h"

#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64)
#error "bpf/sensors/lsm.bpf.c: __TARGET_ARCH_x86 or __TARGET_ARCH_arm64 must be defined by the build pipeline (-D__TARGET_ARCH_<arch>)"
#endif

/* Verifier-compatible license string. REQUIRED for BPF LSM programs
 * (the kernel rejects non-GPL-compatible LSM programs). */
char _license[] SEC("license") = "GPL";

/* ------------------------------------------------------------------------- *
 *  Engine constants. Anchored in bench/schemas/enforcement.v1.json; the
 *  numbers here MUST match the schema defaults (the bench harness reads
 *  the schema, the C producer encodes the same values).
 * ------------------------------------------------------------------------- */
#define KERNEL_V1_LSM_SELECTOR_MAX     ((unsigned int)256u)
#define KERNEL_V1_LSM_KFUNCS_MAX       ((unsigned int)16u)
#define KERNEL_V1_LSM_POLICY_SLOTS     ((unsigned int)4u)   /* slot 0 reserved; 1..3 = families */
#define KERNEL_V1_LSM_PAYLOAD_LEN      ((__u32)320u)

/* Hook-family wire encoding (enforcement.v1.json#hook_family_*). */
#define KERNEL_V1_LSM_HOOK_FILE_OPEN   ((__u8)1u)
#define KERNEL_V1_LSM_HOOK_BPRM_EXEC   ((__u8)2u)
#define KERNEL_V1_LSM_HOOK_SOCK_CONN   ((__u8)3u)

/* Selector type (authoritative, kernel-observable). */
#define KERNEL_V1_LSM_SEL_PATH_PREFIX  ((__u8)1u)
#define KERNEL_V1_LSM_SEL_SOCKADDR     ((__u8)2u)

/* Policy mode (enforcement.v1.json#mode_audit / mode_deny). */
#define KERNEL_V1_LSM_MODE_AUDIT       ((__u8)0u)
#define KERNEL_V1_LSM_MODE_DENY        ((__u8)1u)
#define KERNEL_V1_LSM_MODE_NONE        ((__u8)0xFFu)  /* no policy applied */

/* Decision enum recorded in every audit decision event. */
enum kernel_v1_lsm_decision {
    KERNEL_V1_LSM_DECISION_ALLOW                = 0, /* no match; fail-open allow */
    KERNEL_V1_LSM_DECISION_AUDIT_MATCH          = 1, /* audit-mode match; result unchanged */
    KERNEL_V1_LSM_DECISION_DENY                 = 2, /* deny-mode match; THIS program returns errno */
    KERNEL_V1_LSM_DECISION_PRESERVE_PRIOR       = 3, /* prior LSM decided; preserve nonzero ret */
    KERNEL_V1_LSM_DECISION_DENY_SUPPRESSED_KILL = 4, /* deny matched but kill-switch engaged */
    KERNEL_V1_LSM_DECISION_FAIL_OPEN_UNKNOWN    = 5, /* unknown/unsupported context; fail-open */
};

/* Deny-source enum. OWN_LSM is set ONLY when this program returns an
 * errno; PRIOR_LSM means another LSM already decided; NONE means no
 * denial occurred (audit/allow/fail-open). */
enum kernel_v1_lsm_deny_source {
    KERNEL_V1_LSM_DENY_NONE      = 0,
    KERNEL_V1_LSM_DENY_OWN_LSM   = 1,
    KERNEL_V1_LSM_DENY_PRIOR_LSM = 2,
};

/* Decision result-flag bits (payload result_flags byte). */
#define KERNEL_V1_LSM_RESULT_HAS_ERRNO ((__u8)0x01u)
#define KERNEL_V1_LSM_RESULT_OWN_LSM   ((__u8)0x02u)  /* set ONLY when this program returns errno */

/* Kfuncs-string fingerprint. Consumer-side decode expects this. */
static const char KERNEL_V1_LSM_KFUNCS_USED[] = "lsm_decide";

/* ------------------------------------------------------------------------- *
 *  Maps.
 * ------------------------------------------------------------------------- */

/* Per-source monotonic seq counter (one slot). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lsm_seq SEC(".maps");

/* OWN ring buffer for LSM decision events. 256 KiB matches the other
 * sensors: large enough that normal workloads do not drop, bounded so
 * the bench harness can drive it into fail-mode. A failed reserve
 * (ring full) is itself a fail-open path: the hook still returns the
 * correct decision, it just cannot record it. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256u * 1024u);
} lsm_events SEC(".maps");

/* Policy entry. ONE authoritative selector per hook family. The
 * explicit mode/version/generation triple lets the staged validated-
 * map path (task 34) atomically promote a policy and lets the consumer
 * correlate a decision to the exact policy generation that produced
 * it. deny_errno is the negative errno returned on a deny-mode match
 * (e.g. -13 EACCES). */
struct lsm_policy_entry {
    __u8  mode;                                  /* off   0: AUDIT(0)/DENY(1) */
    __u8  hook_family;                           /* off   1: FILE_OPEN/BPRM_EXEC/SOCK_CONN */
    __u8  selector_type;                         /* off   2: PATH_PREFIX/SOCKADDR */
    __u8  _pad0;                                 /* off   3 */
    __u32 version;                               /* off   4 */
    __s32 deny_errno;                            /* off   8: negative errno on deny */
    __u32 _pad1;                                 /* off  12 */
    __u64 generation;                            /* off  16 */
    __u32 selector_len;                          /* off  24: bytes of selector[] meaningful */
    __u32 _pad2;                                 /* off  28 */
    __u8  selector[KERNEL_V1_LSM_SELECTOR_MAX];  /* off  32: path prefix / sockaddr bytes */
} __attribute__((packed));

_Static_assert(sizeof(struct lsm_policy_entry) == 288u,
               "lsm_policy_entry must equal 288 bytes");

/* Policy map: ARRAY keyed by hook_family (1..3). Slot 0 is reserved
 * (unused). The bounded single-lookup-per-family keeps the verifier
 * path trivial; the audit-first MVP evaluates one authoritative
 * selector per family. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, KERNEL_V1_LSM_POLICY_SLOTS);
    __type(key, __u32);
    __type(value, struct lsm_policy_entry);
} lsm_policy SEC(".maps");

/* Kill-switch. Single slot. deny_disabled == 1 forces every deny-mode
 * decision to degrade to audit-only (return 0). last_toggle_ns is
 * informational (ktime of the last agent toggle). */
struct lsm_kill_switch {
    __u8  deny_disabled;                         /* off 0: 1 = suppress all deny */
    __u8  _pad0[3];                              /* off 1 */
    __u32 _pad1;                                 /* off 4 */
    __u64 last_toggle_ns;                        /* off 8 */
} __attribute__((packed));

_Static_assert(sizeof(struct lsm_kill_switch) == 16u,
               "lsm_kill_switch must equal 16 bytes");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lsm_kill_switch);
} lsm_kill_switch SEC(".maps");

/* ------------------------------------------------------------------------- *
 *  LSM decision payload (local to this TU). Fixed 320 bytes so the
 *  consumer can dispatch on event_kind without measuring the payload.
 *  Carried on event_kind == KERNEL_V1_EVENT_LSM_DENY_OWN (15); the
 *  own-denial semantic is field-gated (deny_source == OWN_LSM AND
 *  result_flags & OWN_LSM), set ONLY when this program returns an
 *  errno. Audit/allow/preserve/fail-open decisions reuse the same
 *  carrier with deny_source == NONE/PRIOR_LSM so a single ring buffer
 *  surfaces the whole decision stream.
 * ------------------------------------------------------------------------- */
struct kernel_v1_lsm_decision_payload {
    char  kfuncs_used[KERNEL_V1_LSM_KFUNCS_MAX]; /* off   0, 16 bytes */
    __u8  hook_family;                           /* off  16 */
    __u8  decision;                              /* off  17: kernel_v1_lsm_decision */
    __u8  deny_source;                           /* off  18: kernel_v1_lsm_deny_source */
    __u8  mode;                                  /* off  19: applied policy mode (NONE if no policy) */
    __u32 version;                               /* off  20: applied policy version */
    __u64 generation;                            /* off  24: applied policy generation */
    __s32 result_errno;                          /* off  32: errno this hook returns (0 if none) */
    __s32 prior_ret;                             /* off  36: incoming prior-LSM ret (preserved) */
    __u32 selector_len;                          /* off  40: bytes of selector[] meaningful */
    __u8  result_flags;                          /* off  44: HAS_ERRNO/OWN_LSM bits */
    __u8  _pad0[3];                              /* off  45 */
    __u8  selector[KERNEL_V1_LSM_SELECTOR_MAX];  /* off  48, 256 bytes */
    __u8  _pad1[16];                             /* off 304 */
} __attribute__((packed));

_Static_assert(sizeof(struct kernel_v1_lsm_decision_payload)
               == KERNEL_V1_LSM_PAYLOAD_LEN,
               "kernel_v1_lsm_decision_payload must equal KERNEL_V1_LSM_PAYLOAD_LEN");

struct kernel_v1_lsm_event {
    struct kernel_v1_header               header;
    struct kernel_v1_lsm_decision_payload payload;
} __attribute__((packed));

/* ------------------------------------------------------------------------- *
 *  Implementation helpers.
 * ------------------------------------------------------------------------- */

/* Atomically return the next per-source seq number. */
static __always_inline __u64
next_lsm_seq(void)
{
    __u32 zero = 0;
    __u64 *p = bpf_map_lookup_elem(&lsm_seq, &zero);
    if (!p) {
        return 0;
    }
    return __sync_fetch_and_add(p, 1);
}

/* Fill the canonical 96-byte header for an LSM decision event. Sets
 * the standard identity bits; NEVER sets BOOT_ID without a real read. */
static __always_inline void
fill_lsm_header(struct kernel_v1_header *hdr,
                __u8 header_flags,
                __u32 record_len)
{
    hdr->schema_major       = KERNEL_V1_ABI_SCHEMA_MAJOR;
    hdr->schema_minor       = KERNEL_V1_ABI_SCHEMA_MINOR;
    hdr->header_len         = KERNEL_V1_ABI_HEADER_LEN;
    hdr->record_len         = record_len;
    hdr->event_kind         = (__u8)KERNEL_V1_EVENT_LSM_DENY_OWN;
    hdr->_pad0[0]           = 0;
    hdr->_pad0[1]           = 0;
    hdr->_pad0[2]           = 0;
    hdr->flags              = header_flags;
    hdr->_pad1[0]           = 0;
    hdr->_pad1[1]           = 0;
    hdr->_pad1[2]           = 0;
    hdr->seq                = next_lsm_seq();
    hdr->ts_monotonic_ns    = bpf_ktime_get_ns();
    __builtin_memset(hdr->boot_id, 0, sizeof(hdr->boot_id));
    hdr->pid_tgid           = bpf_get_current_pid_tgid();
    hdr->task_start_time_ns = bpf_ktime_get_ns();
    hdr->cgroup_id          = bpf_get_current_cgroup_id();
    hdr->processor_id       = bpf_get_smp_processor_id();
    hdr->valids             = (__u32)(KERNEL_V1_VALID_CGROUP_ID
                                      | KERNEL_V1_VALID_PID_TGID
                                      | KERNEL_V1_VALID_TASK_START
                                      | KERNEL_V1_VALID_PROCESSOR
                                      | KERNEL_V1_VALID_FILE_DENY_SOURCE);
    hdr->ns_pid             = 0;
}

/* Stamp the common 16-byte kfuncs-used prefix. */
static __always_inline void
stamp_lsm_kfuncs(struct kernel_v1_lsm_decision_payload *p)
{
    __builtin_memset(p->kfuncs_used, 0, sizeof(p->kfuncs_used));
    for (unsigned int i = 0;
         i < sizeof(p->kfuncs_used) - 1u &&
             KERNEL_V1_LSM_KFUNCS_USED[i] != '\0';
         ++i) {
        p->kfuncs_used[i] = KERNEL_V1_LSM_KFUNCS_USED[i];
    }
}

/* Emit one audit decision event. Called on EVERY hook invocation
 * (allow / audit-match / deny / preserve / kill-switch-suppressed /
 * fail-open). A failed ring-buffer reserve is a silent drop: the
 * caller still returns the correct decision. The OWN_LSM deny_source
 * and the OWN_LSM result-flag bit are passed in by the caller and are
 * set ONLY on the deny path where this program returns an errno. */
static __always_inline void
emit_decision(__u8 hook_family,
              __u8 decision,
              __u8 deny_source,
              __u8 mode,
              __u32 version,
              __u64 generation,
              __s32 result_errno,
              __s32 prior_ret,
              const __u8 *sel_buf,
              __u32 sel_len,
              bool sel_valid,
              __u8 result_flags)
{
    __u32 record_len = (__u32)(KERNEL_V1_ABI_HEADER_LEN +
                               KERNEL_V1_LSM_PAYLOAD_LEN);
    struct kernel_v1_lsm_event *ev =
        (struct kernel_v1_lsm_event *)bpf_ringbuf_reserve(&lsm_events,
                                                          record_len,
                                                          0);
    if (!ev) {
        return;  /* ring full: fail-open already decided; drop the record. */
    }

    __u8 header_flags = 0;
    __u32 bounded_len = sel_len;
    if (bounded_len > KERNEL_V1_LSM_SELECTOR_MAX) {
        bounded_len = KERNEL_V1_LSM_SELECTOR_MAX;
        header_flags |= (__u8)KERNEL_V1_EVENT_FLAG_TRUNC;
    }
    if (!sel_valid) {
        bounded_len = 0;
    }

    fill_lsm_header(&ev->header, header_flags, record_len);
    stamp_lsm_kfuncs(&ev->payload);

    ev->payload.hook_family  = hook_family;
    ev->payload.decision     = decision;
    ev->payload.deny_source  = deny_source;
    ev->payload.mode         = mode;
    ev->payload.version      = version;
    ev->payload.generation   = generation;
    ev->payload.result_errno = result_errno;
    ev->payload.prior_ret    = prior_ret;
    ev->payload.selector_len = bounded_len;
    ev->payload.result_flags = result_flags;
    ev->payload._pad0[0]     = 0;
    ev->payload._pad0[1]     = 0;
    ev->payload._pad0[2]     = 0;

    __builtin_memset(ev->payload.selector, 0,
                     sizeof(ev->payload.selector));
    if (sel_valid && bounded_len > 0) {
        /* sel_buf is the caller's KERNEL_V1_LSM_SELECTOR_MAX stack
         * buffer; ev->payload.selector lives in ring-buffer memory
         * (NOT the BPF stack). Copy the meaningful prefix directly
         * into the reservation -- a stack temp here would push the
         * inlined frame past the 512-byte BPF stack limit. The
         * constant-bound loop keeps the verifier's bounds analysis
         * trivial. */
        for (__u32 i = 0; i < KERNEL_V1_LSM_SELECTOR_MAX; ++i) {
            if (i < bounded_len) {
                ev->payload.selector[i] = sel_buf[i];
            }
        }
    }
    __builtin_memset(ev->payload._pad1, 0, sizeof(ev->payload._pad1));

    bpf_ringbuf_submit(ev, 0);
}

/* Bounded prefix compare: true iff obs[0..cmp_len) == pol[0..cmp_len).
 * Both buffers are KERNEL_V1_LSM_SELECTOR_MAX bytes; the loop bound is
 * the compile-time constant so the verifier accepts it. cmp_len is
 * masked to the buffer size by the caller. */
static __always_inline bool
selector_prefix_match(const __u8 *obs, const __u8 *pol, __u32 cmp_len)
{
    __u8 mismatch = 0;
    for (__u32 i = 0; i < KERNEL_V1_LSM_SELECTOR_MAX; ++i) {
        if (i < cmp_len) {
            if (obs[i] != pol[i]) {
                mismatch = 1;
            }
        }
    }
    return mismatch == 0;
}

/* Read the kill-switch deny_disabled bit. A missing map entry is
 * treated as deny-disabled == 0 (the default shipped state); the
 * agent is responsible for populating slot 0. */
static __always_inline bool
kill_switch_engaged(void)
{
    __u32 zero = 0;
    struct lsm_kill_switch *ks = bpf_map_lookup_elem(&lsm_kill_switch, &zero);
    if (!ks) {
        return false;
    }
    return ks->deny_disabled != 0;
}

/* The shared decision engine. Returns the value the LSM hook must
 * return to the kernel:
 *   - prior_ret (unchanged) when a prior LSM already decided;
 *   - a negative errno when THIS program denies (deny-mode match);
 *   - 0 in every other case (audit match, allow, fail-open,
 *     kill-switch-suppressed deny).
 *
 * obs_buf is a KERNEL_V1_LSM_SELECTOR_MAX stack buffer holding the
 * kernel-observable selector bytes; obs_len is how many bytes are
 * meaningful; obs_valid is false when the selector could not be read
 * truthfully (fail-open). */
static __always_inline int
lsm_decide(__u8 hook_family,
           const __u8 *obs_buf,
           __u32 obs_len,
           bool obs_valid,
           int prior_ret)
{
    /* (1) Preserve a nonzero prior BPF-program ret. Another LSM
     *     (SELinux/AppArmor/another BPF program) already decided; we
     *     MUST NOT override it and MUST NOT claim OWN_LSM. */
    if (prior_ret != 0) {
        emit_decision(hook_family,
                      (__u8)KERNEL_V1_LSM_DECISION_PRESERVE_PRIOR,
                      (__u8)KERNEL_V1_LSM_DENY_PRIOR_LSM,
                      KERNEL_V1_LSM_MODE_NONE, 0, 0,
                      (__s32)prior_ret, (__s32)prior_ret,
                      obs_buf, obs_len, obs_valid,
                      (__u8)KERNEL_V1_LSM_RESULT_HAS_ERRNO);
        return prior_ret;  /* unchanged */
    }

    /* (2) Fail-open on unknown/unsupported context. */
    if (!obs_valid) {
        emit_decision(hook_family,
                      (__u8)KERNEL_V1_LSM_DECISION_FAIL_OPEN_UNKNOWN,
                      (__u8)KERNEL_V1_LSM_DENY_NONE,
                      KERNEL_V1_LSM_MODE_NONE, 0, 0,
                      0, 0, obs_buf, 0, false, 0);
        return 0;
    }

    /* (3) Look up the policy for this hook family. A missing map
     *     entry, a family mismatch, or an empty selector is a
     *     fail-open allow (no policy => nothing to enforce). */
    __u32 key = (__u32)hook_family;
    struct lsm_policy_entry *pol = bpf_map_lookup_elem(&lsm_policy, &key);
    if (!pol) {
        emit_decision(hook_family,
                      (__u8)KERNEL_V1_LSM_DECISION_ALLOW,
                      (__u8)KERNEL_V1_LSM_DENY_NONE,
                      KERNEL_V1_LSM_MODE_NONE, 0, 0,
                      0, 0, obs_buf, obs_len, obs_valid, 0);
        return 0;
    }
    if (pol->hook_family != hook_family || pol->selector_len == 0) {
        emit_decision(hook_family,
                      (__u8)KERNEL_V1_LSM_DECISION_ALLOW,
                      (__u8)KERNEL_V1_LSM_DENY_NONE,
                      pol->mode, pol->version, pol->generation,
                      0, 0, obs_buf, obs_len, obs_valid, 0);
        return 0;
    }

    /* (4) Bounded authoritative-selector match. The policy selector is
     *     a prefix; the observed selector must be at least as long and
     *     match byte-for-byte over the policy selector length. */
    __u32 plen = pol->selector_len;
    if (plen > KERNEL_V1_LSM_SELECTOR_MAX) {
        plen = KERNEL_V1_LSM_SELECTOR_MAX;
    }
    bool matched = false;
    if (obs_len >= plen) {
        matched = selector_prefix_match(obs_buf, pol->selector, plen);
    }
    if (!matched) {
        /* Wrong selector: audit-only allow, never a denial. */
        emit_decision(hook_family,
                      (__u8)KERNEL_V1_LSM_DECISION_ALLOW,
                      (__u8)KERNEL_V1_LSM_DENY_NONE,
                      pol->mode, pol->version, pol->generation,
                      0, 0, obs_buf, obs_len, obs_valid, 0);
        return 0;
    }

    /* (5) Selector matched. The mode decides the outcome. */
    if (pol->mode == KERNEL_V1_LSM_MODE_AUDIT) {
        /* AUDIT-FIRST: a matching selector is recorded but the
         * syscall result is NEVER changed. */
        emit_decision(hook_family,
                      (__u8)KERNEL_V1_LSM_DECISION_AUDIT_MATCH,
                      (__u8)KERNEL_V1_LSM_DENY_NONE,
                      pol->mode, pol->version, pol->generation,
                      0, 0, obs_buf, obs_len, obs_valid, 0);
        return 0;
    }

    if (pol->mode == KERNEL_V1_LSM_MODE_DENY) {
        /* (5a) Kill-switch overrides deny: degrade to audit-only. */
        if (kill_switch_engaged()) {
            emit_decision(hook_family,
                          (__u8)KERNEL_V1_LSM_DECISION_DENY_SUPPRESSED_KILL,
                          (__u8)KERNEL_V1_LSM_DENY_NONE,
                          pol->mode, pol->version, pol->generation,
                          0, 0, obs_buf, obs_len, obs_valid, 0);
            return 0;
        }
        /* (5b) THIS program denies. Record OWN_LSM and return the
         *      policy errno. This is the ONLY path that sets
         *      deny_source == OWN_LSM and the OWN_LSM result bit. */
        __s32 err = pol->deny_errno;
        if (err >= 0) {
            err = -13;  /* defensive: a deny must be a negative errno (EACCES) */
        }
        emit_decision(hook_family,
                      (__u8)KERNEL_V1_LSM_DECISION_DENY,
                      (__u8)KERNEL_V1_LSM_DENY_OWN_LSM,
                      pol->mode, pol->version, pol->generation,
                      err, 0, obs_buf, obs_len, obs_valid,
                      (__u8)(KERNEL_V1_LSM_RESULT_HAS_ERRNO |
                             KERNEL_V1_LSM_RESULT_OWN_LSM));
        return (int)err;
    }

    /* (6) Unknown mode value: fail-open (never deny on an
     *     unrecognised policy encoding). */
    emit_decision(hook_family,
                  (__u8)KERNEL_V1_LSM_DECISION_FAIL_OPEN_UNKNOWN,
                  (__u8)KERNEL_V1_LSM_DENY_NONE,
                  pol->mode, pol->version, pol->generation,
                  0, 0, obs_buf, obs_len, obs_valid, 0);
    return 0;
}

/* ------------------------------------------------------------------------- *
 *  HOOK 1: file_open. Selector = kernel-observable file path component
 *  (file->f_path.dentry->d_name.name). Full-path prefix walking is a
 *  documented refinement; the dentry name component is the
 *  kernel-observable fact available at this hook (mirrors file.bpf.c).
 * ------------------------------------------------------------------------- */
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret)
{
    __u8 sel_buf[KERNEL_V1_LSM_SELECTOR_MAX];
    __builtin_memset(sel_buf, 0, sizeof(sel_buf));

    bool sel_valid = false;
    __u32 sel_len = 0;

    const void *name_ptr = NULL;
    struct dentry *dentry = NULL;
    BPF_CORE_READ_INTO(&dentry, file, f_path.dentry);
    if (dentry) {
        BPF_CORE_READ_INTO(&name_ptr, dentry, d_name.name);
    }
    if (name_ptr) {
        long n = bpf_probe_read_kernel_str(sel_buf, sizeof(sel_buf),
                                           name_ptr);
        if (n > 0) {
            sel_valid = true;
            sel_len = (__u32)n;  /* includes the NUL; harmless for prefix match */
        }
    }

    return lsm_decide(KERNEL_V1_LSM_HOOK_FILE_OPEN, sel_buf, sel_len,
                      sel_valid, ret);
}

/* ------------------------------------------------------------------------- *
 *  HOOK 2: bprm_check_security (binary exec). Selector = bprm->filename
 *  (the full path passed to execve -- authoritative and kernel-
 *  observable).
 * ------------------------------------------------------------------------- */
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm, int ret)
{
    __u8 sel_buf[KERNEL_V1_LSM_SELECTOR_MAX];
    __builtin_memset(sel_buf, 0, sizeof(sel_buf));

    bool sel_valid = false;
    __u32 sel_len = 0;

    const char *filename = NULL;
    BPF_CORE_READ_INTO(&filename, bprm, filename);
    if (filename) {
        long n = bpf_probe_read_kernel_str(sel_buf, sizeof(sel_buf),
                                           filename);
        if (n > 0) {
            sel_valid = true;
            sel_len = (__u32)n;
        }
    }

    return lsm_decide(KERNEL_V1_LSM_HOOK_BPRM_EXEC, sel_buf, sel_len,
                      sel_valid, ret);
}

/* ------------------------------------------------------------------------- *
 *  HOOK 3: socket_connect. Selector = the sockaddr bytes (family +
 *  address + port), kernel-observable from the `address` argument. The
 *  policy selector holds the sockaddr prefix to match; the comparison
 *  is over addrlen bytes (bounded to the buffer). An unreadable address
 *  or a zero/negative addrlen fails open.
 * ------------------------------------------------------------------------- */
SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret)
{
    __u8 sel_buf[KERNEL_V1_LSM_SELECTOR_MAX];
    __builtin_memset(sel_buf, 0, sizeof(sel_buf));

    bool sel_valid = false;
    __u32 sel_len = 0;

    if (address && addrlen > 0) {
        __u32 want = (__u32)addrlen;
        if (want > KERNEL_V1_LSM_SELECTOR_MAX) {
            want = KERNEL_V1_LSM_SELECTOR_MAX;
        }
        long n = bpf_probe_read_kernel(sel_buf, want, address);
        if (n == 0) {
            sel_valid = true;
            sel_len = want;
        }
    }

    return lsm_decide(KERNEL_V1_LSM_HOOK_SOCK_CONN, sel_buf, sel_len,
                      sel_valid, ret);
}
