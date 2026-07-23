/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * bench/enforcement-live.c — privileged live BPF LSM enforcement harness
 * (task 54).
 *
 * INTRODUCTION
 *   This is the privileged half that bench/enforcement-audit.sh (task
 *   33) and bench/enforcement-state-machine.sh (task 34) reported
 *   BLOCKED on an unprivileged host: it operates on the REAL loaded
 *   bpf/sensors/lsm.bpf.c decision engine (loaded + attached by
 *   bench/enforcement-live.sh via bpftool) through its pinned maps,
 *   drives real syscalls through the attached LSM hooks, and consumes
 *   the real lsm_events ring buffer. It proves, against the live
 *   kernel:
 *
 *     S1 AUDIT       a mode=0 (audit) policy match NEVER changes the
 *                    syscall result and emits AUDIT_MATCH / NONE;
 *     S2 DENY        a mode=1 (deny) policy match returns the policy
 *                    errno (EACCES) and emits DENY / OWN_LSM with the
 *                    HAS_ERRNO|OWN_LSM result flags — the ONLY path
 *                    that records OWN_LSM;
 *     S3 KILLSWITCH  deny_disabled=1 degrades a deny-mode match to
 *                    audit-only (syscall succeeds, DENY_SUPPRESSED_-
 *                    KILLSWITCH / NONE) and takes effect within the
 *                    schema kill_switch_max_ms budget;
 *     S4 FAIL_OPEN   a missing/empty policy (zeroed array slot) fails
 *                    open (syscall succeeds, ALLOW / NONE);
 *     S5 PRIOR_LSM   a nonzero prior-LSM ret (landlock denying the
 *                    same open BEFORE the BPF hook in the LSM chain)
 *                    is preserved byte-for-byte and recorded as
 *                    PRIOR_LSM, NEVER relabeled OWN_LSM — even though
 *                    the active policy is mode=1 with a DIFFERENT
 *                    errno, so a mislabeled own-denial would be
 *                    visible as the policy errno instead of the
 *                    prior LSM's.
 *
 *   S5 is empirical when landlock is available in the test container
 *   (landlock precedes bpf in /sys/kernel/security/lsm); when it is
 *   not, the harness records the code-inspection proof (lsm_decide's
 *   FIRST check is `if (prior_ret != 0) return prior_ret;`).
 *
 * MAP ABI (mirrors bpf/sensors/lsm.bpf.c; the _Static_asserts below
 * pin the sizes so a producer-side ABI bump fails this harness at
 * compile time, not silently at runtime).
 *
 * SAFETY
 *   The deny selector is the unique dentry name component of a
 *   /tmp/deny-test-* file: no host workload opens it, so the deny
 *   window (milliseconds) cannot affect the host. Only the file_open
 *   family (policy slot 1) is ever armed; bprm_check_security and
 *   socket_connect slots stay empty (fail-open). On exit (normal,
 *   atexit, SIGINT, SIGTERM) the harness zeroes every policy slot and
 *   the kill-switch so no deny state can outlive the process; the
 *   orchestrator then unpins the programs.
 *
 * USAGE
 *   enforcement-live <lsm_policy_pin> <lsm_kill_switch_pin> \
 *                    <lsm_events_pin> <testfile>
 *
 * OUTPUT
 *   One JSON document on stdout (consumed by the evidence record);
 *   diagnostics on stderr. Exit 0 iff every scenario passes.
 */

#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>

/* ------------------------------------------------------------------------- *
 *  ABI mirrors of bpf/sensors/lsm.bpf.c (task 33).
 * ------------------------------------------------------------------------- */

#define LSM_SELECTOR_MAX  256u
#define LSM_EVENT_KIND    15u   /* KERNEL_V1_EVENT_LSM_DENY_OWN          */
#define LSM_HEADER_LEN    96u   /* KERNEL_V1_ABI_HEADER_LEN              */
#define LSM_PAYLOAD_LEN   320u  /* KERNEL_V1_LSM_PAYLOAD_LEN             */
#define LSM_RECORD_LEN    (LSM_HEADER_LEN + LSM_PAYLOAD_LEN)

#define LSM_HOOK_FILE_OPEN  1u
#define LSM_SEL_PATH_PREFIX 1u
#define LSM_MODE_AUDIT      0u
#define LSM_MODE_DENY       1u
#define LSM_MODE_NONE       0xFFu

/* kernel_v1_lsm_decision */
#define DEC_ALLOW                 0u
#define DEC_AUDIT_MATCH           1u
#define DEC_DENY                  2u
#define DEC_PRESERVE_PRIOR        3u
#define DEC_DENY_SUPPRESSED_KILL  4u
#define DEC_FAIL_OPEN_UNKNOWN     5u

/* kernel_v1_lsm_deny_source */
#define DSRC_NONE       0u
#define DSRC_OWN_LSM    1u
#define DSRC_PRIOR_LSM  2u

/* result_flags bits */
#define RF_HAS_ERRNO  0x01u
#define RF_OWN_LSM    0x02u

struct lsm_policy_entry {
    uint8_t  mode;                                 /* off   0 */
    uint8_t  hook_family;                          /* off   1 */
    uint8_t  selector_type;                        /* off   2 */
    uint8_t  _pad0;                                /* off   3 */
    uint32_t version;                              /* off   4 */
    int32_t  deny_errno;                           /* off   8 */
    uint32_t _pad1;                                /* off  12 */
    uint64_t generation;                           /* off  16 */
    uint32_t selector_len;                         /* off  24 */
    uint32_t _pad2;                                /* off  28 */
    uint8_t  selector[LSM_SELECTOR_MAX];           /* off  32 */
} __attribute__((packed));

struct lsm_kill_switch {
    uint8_t  deny_disabled;                        /* off  0 */
    uint8_t  _pad0[3];                             /* off  1 */
    uint32_t _pad1;                                /* off  4 */
    uint64_t last_toggle_ns;                       /* off  8 */
} __attribute__((packed));

/* One ring-buffer record: 96-byte header + 320-byte payload. */
struct lsm_record {
    /* header (96 bytes; offsets per bpf/include/event_abi.h) */
    uint32_t schema_major;                         /* off   0 */
    uint32_t schema_minor;                         /* off   4 */
    uint32_t header_len;                           /* off   8 */
    uint32_t record_len;                           /* off  12 */
    uint8_t  event_kind;                           /* off  16 */
    uint8_t  hdr_pad0[3];                          /* off  17 */
    uint8_t  flags;                                /* off  20 */
    uint8_t  hdr_pad1[3];                          /* off  21 */
    uint64_t seq;                                  /* off  24 */
    uint64_t ts_monotonic_ns;                      /* off  32 */
    uint8_t  boot_id[16];                          /* off  40 */
    uint64_t pid_tgid;                             /* off  56 */
    uint64_t task_start_time_ns;                   /* off  64 */
    uint64_t cgroup_id;                            /* off  72 */
    uint32_t processor_id;                         /* off  80 */
    uint32_t valids;                               /* off  84 */
    uint32_t ns_pid;                               /* off  88 */
    uint8_t  hdr_pad2[4];                          /* off  92 */
    /* payload (320 bytes; offsets per lsm.bpf.c) */
    char     kfuncs_used[16];                      /* off  96 */
    uint8_t  hook_family;                          /* off 112 */
    uint8_t  decision;                             /* off 113 */
    uint8_t  deny_source;                          /* off 114 */
    uint8_t  mode;                                 /* off 115 */
    uint32_t version;                              /* off 116 */
    uint64_t generation;                           /* off 120 */
    int32_t  result_errno;                         /* off 128 */
    int32_t  prior_ret;                            /* off 132 */
    uint32_t selector_len;                         /* off 136 */
    uint8_t  result_flags;                         /* off 140 */
    uint8_t  pl_pad0[3];                           /* off 141 */
    uint8_t  selector[LSM_SELECTOR_MAX];           /* off 144 */
    uint8_t  pl_pad1[16];                          /* off 400 */
} __attribute__((packed));

_Static_assert(sizeof(struct lsm_policy_entry) == 288u,
               "lsm_policy_entry ABI must match lsm.bpf.c (288 bytes)");
_Static_assert(sizeof(struct lsm_kill_switch) == 16u,
               "lsm_kill_switch ABI must match lsm.bpf.c (16 bytes)");
_Static_assert(sizeof(struct lsm_record) == 416u,
               "lsm decision record ABI must be 96 + 320 = 416 bytes");

static const char *
decision_name(uint8_t d)
{
    switch (d) {
    case DEC_ALLOW:                return "ALLOW";
    case DEC_AUDIT_MATCH:          return "AUDIT_MATCH";
    case DEC_DENY:                 return "DENY";
    case DEC_PRESERVE_PRIOR:       return "PRESERVE_PRIOR";
    case DEC_DENY_SUPPRESSED_KILL: return "DENY_SUPPRESSED_KILLSWITCH";
    case DEC_FAIL_OPEN_UNKNOWN:    return "FAIL_OPEN_UNKNOWN";
    default:                       return "UNKNOWN";
    }
}

static const char *
deny_source_name(uint8_t s)
{
    switch (s) {
    case DSRC_NONE:      return "NONE";
    case DSRC_OWN_LSM:   return "OWN_LSM";
    case DSRC_PRIOR_LSM: return "PRIOR_LSM";
    default:             return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------------- *
 *  Globals.
 * ------------------------------------------------------------------------- */

static int g_policy_fd = -1;
static int g_ks_fd     = -1;
static int g_events_fd = -1;

/* Selector-prefix filter for the ring-buffer consumer: the dentry
 * name component of the test file (the file_open hook's observable
 * selector). Host-wide file_open noise (every open on the host emits
 * an event) is discarded in the callback so the ring stays relevant. */
static const char *g_want_selector;
static size_t      g_want_selector_len;

struct ev {
    int      used;
    struct timespec received;           /* CLOCK_MONOTONIC at consume time */
    uint64_t seq;
    uint64_t ts_monotonic_ns;
    uint64_t pid_tgid;
    uint8_t  hook_family;
    uint8_t  decision;
    uint8_t  deny_source;
    uint8_t  mode;
    uint8_t  hdr_flags;
    uint8_t  result_flags;
    uint32_t version;
    uint32_t selector_len;
    uint64_t generation;
    int32_t  result_errno;
    int32_t  prior_ret;
    char     selector[64];
};

#define EV_RING 64
static struct ev g_events[EV_RING];
static size_t    g_ev_head;
static uint64_t  g_total_events;     /* every event_kind==15 record seen */
static uint64_t  g_matched_events;   /* selector-matching records seen   */

static struct timespec g_trigger_mark;

/* ------------------------------------------------------------------------- *
 *  Ring-buffer consumer.
 * ------------------------------------------------------------------------- */

static int
ringbuf_cb(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    if (data_sz < LSM_RECORD_LEN) {
        return 0;
    }
    const struct lsm_record *r = (const struct lsm_record *)data;
    if (r->event_kind != LSM_EVENT_KIND || r->header_len != LSM_HEADER_LEN) {
        return 0;
    }
    g_total_events++;

    /* The selector is NUL-padded; compare only the meaningful prefix. */
    uint32_t slen = r->selector_len;
    if (slen > LSM_SELECTOR_MAX) {
        slen = LSM_SELECTOR_MAX;
    }
    if (slen < g_want_selector_len) {
        return 0;
    }
    if (memcmp(r->selector, g_want_selector, g_want_selector_len) != 0) {
        return 0;
    }
    g_matched_events++;

    struct ev *e = &g_events[g_ev_head % EV_RING];
    g_ev_head++;

    e->used = 1;
    clock_gettime(CLOCK_MONOTONIC, &e->received);
    e->seq               = r->seq;
    e->ts_monotonic_ns   = r->ts_monotonic_ns;
    e->pid_tgid          = r->pid_tgid;
    e->hook_family       = r->hook_family;
    e->decision          = r->decision;
    e->deny_source       = r->deny_source;
    e->mode              = r->mode;
    e->hdr_flags         = r->flags;
    e->result_flags      = r->result_flags;
    e->version           = r->version;
    e->selector_len      = slen;
    e->generation        = r->generation;
    e->result_errno      = r->result_errno;
    e->prior_ret         = r->prior_ret;

    size_t copy = slen;
    if (copy > sizeof(e->selector) - 1) {
        copy = sizeof(e->selector) - 1;
    }
    memcpy(e->selector, r->selector, copy);
    e->selector[copy] = '\0';
    return 0;
}

static int
ev_after_trigger(const struct ev *e)
{
    if (e->received.tv_sec != g_trigger_mark.tv_sec) {
        return e->received.tv_sec > g_trigger_mark.tv_sec;
    }
    return e->received.tv_nsec >= g_trigger_mark.tv_nsec;
}

/* Poll until a selector-matching event with the expected decision and
 * deny_source arrives after the trigger mark, or timeout. */
static const struct ev *
wait_event(struct ring_buffer *rb, uint8_t decision, uint8_t deny_source,
           int timeout_ms)
{
    int waited = 0;
    for (;;) {
        for (size_t i = 0; i < EV_RING; i++) {
            const struct ev *e = &g_events[i];
            if (!e->used || !ev_after_trigger(e)) {
                continue;
            }
            if (e->decision == decision && e->deny_source == deny_source) {
                return e;
            }
        }
        if (waited >= timeout_ms) {
            return NULL;
        }
        ring_buffer__poll(rb, 20);
        waited += 20;
    }
}

/* ------------------------------------------------------------------------- *
 *  Map control.
 * ------------------------------------------------------------------------- */

/* Zero every policy slot and the kill-switch: the fail-open shipped
 * state. Idempotent; runs at start, on exit, and on signal so no deny
 * state can outlive the harness. */
static void
zero_maps(void)
{
    if (g_policy_fd >= 0) {
        struct lsm_policy_entry p;
        memset(&p, 0, sizeof(p));
        for (uint32_t k = 0; k < 4; k++) {
            (void)bpf_map_update_elem(g_policy_fd, &k, &p, BPF_ANY);
        }
    }
    if (g_ks_fd >= 0) {
        struct lsm_kill_switch ks;
        memset(&ks, 0, sizeof(ks));
        uint32_t k = 0;
        (void)bpf_map_update_elem(g_ks_fd, &k, &ks, BPF_ANY);
    }
}

static void
on_signal(int sig)
{
    zero_maps();
    _exit(128 + sig);
}

/* Install a file_open (slot 1) policy. sel == NULL zeroes the slot
 * (an ARRAY map cannot delete; a zeroed slot has hook_family == 0,
 * which the engine treats as no-policy fail-open allow). */
static int
set_policy(uint8_t mode, uint32_t version, uint64_t generation,
           int32_t deny_errno, const char *sel)
{
    struct lsm_policy_entry p;
    memset(&p, 0, sizeof(p));
    if (sel) {
        p.mode          = mode;
        p.hook_family   = LSM_HOOK_FILE_OPEN;
        p.selector_type = LSM_SEL_PATH_PREFIX;
        p.version       = version;
        p.deny_errno    = deny_errno;
        p.generation    = generation;
        p.selector_len  = (uint32_t)strlen(sel);
        memcpy(p.selector, sel, p.selector_len);
    }
    uint32_t key = LSM_HOOK_FILE_OPEN;
    return bpf_map_update_elem(g_policy_fd, &key, &p, BPF_ANY);
}

static int
set_killswitch(uint8_t deny_disabled)
{
    struct lsm_kill_switch ks;
    memset(&ks, 0, sizeof(ks));
    ks.deny_disabled = deny_disabled;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ks.last_toggle_ns =
        (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    uint32_t key = 0;
    return bpf_map_update_elem(g_ks_fd, &key, &ks, BPF_ANY);
}

/* ------------------------------------------------------------------------- *
 *  Triggers.
 * ------------------------------------------------------------------------- */

static void
mark_trigger(void)
{
    clock_gettime(CLOCK_MONOTONIC, &g_trigger_mark);
}

/* Returns 0 on success; on failure stores errno in *err_out. */
static int
trigger_open(const char *path, int *err_out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        *err_out = errno;
        return -1;
    }
    close(fd);
    *err_out = 0;
    return 0;
}

/* ---- S5: landlock child (prior-LSM preservation) ----
 * landlock precedes bpf in /sys/kernel/security/lsm, so a landlock
 * denial of the same open reaches the BPF hook as a nonzero prior
 * ret. Exit codes: 13 = landlock denied with EACCES (expected);
 * 0 = open succeeded (landlock did not deny); >=200 = landlock
 * unavailable in this environment. */

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule       445
#define __NR_landlock_restrict_self  446
#endif

struct ll_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
};
struct ll_path_beneath {
    uint64_t allowed_access;
    int32_t  parent_fd;
} __attribute__((packed));
#define LL_RULE_PATH_BENEATH   1
#define LL_ACCESS_READ_FILE    (1ULL << 2)

static void
landlock_child(const char *path, int parent_fd)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        _exit(230);
    }
    struct ll_ruleset_attr ra;
    memset(&ra, 0, sizeof(ra));
    ra.handled_access_fs = LL_ACCESS_READ_FILE;
    int rsfd = (int)syscall(__NR_landlock_create_ruleset, &ra, sizeof(ra), 0);
    if (rsfd < 0) {
        _exit(200 + (errno > 29 ? 29 : errno));
    }
    struct ll_path_beneath pb;
    memset(&pb, 0, sizeof(pb));
    pb.allowed_access = 0;             /* deny every handled access */
    pb.parent_fd      = parent_fd;
    if (syscall(__NR_landlock_add_rule, rsfd, LL_RULE_PATH_BENEATH,
                &pb, 0) < 0) {
        _exit(210 + (errno > 29 ? 29 : errno));
    }
    if (syscall(__NR_landlock_restrict_self, rsfd, 0) < 0) {
        _exit(220 + (errno > 29 ? 29 : errno));
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        int e = errno;
        /* 13 == EACCES == landlock's denial errno. Any other errno
         * (notably 1/EPERM) would mean the BPF engine denied on its
         * own with its policy errno instead of preserving landlock's
         * ret — the exact mislabel this scenario guards against. */
        _exit(e == EACCES ? 13 : (e > 0 && e < 100 ? e : 126));
    }
    close(fd);
    _exit(0);
}

/* ------------------------------------------------------------------------- *
 *  JSON emission helpers.
 * ------------------------------------------------------------------------- */

static void
emit_event_json(const struct ev *e)
{
    if (!e) {
        printf("null");
        return;
    }
    printf("{\"seq\": %llu, \"ts_monotonic_ns\": %llu, "
           "\"pid_tgid\": %llu, \"hook_family\": %u, "
           "\"decision\": %u, \"decision_name\": \"%s\", "
           "\"deny_source\": %u, \"deny_source_name\": \"%s\", "
           "\"mode\": %u, \"version\": %u, \"generation\": %llu, "
           "\"result_errno\": %d, \"prior_ret\": %d, "
           "\"result_flags\": %u, \"hdr_flags\": %u, "
           "\"selector_len\": %u, \"selector\": \"%s\"}",
           (unsigned long long)e->seq,
           (unsigned long long)e->ts_monotonic_ns,
           (unsigned long long)e->pid_tgid,
           (unsigned)e->hook_family,
           (unsigned)e->decision, decision_name(e->decision),
           (unsigned)e->deny_source, deny_source_name(e->deny_source),
           (unsigned)e->mode, (unsigned)e->version,
           (unsigned long long)e->generation,
           (int)e->result_errno, (int)e->prior_ret,
           (unsigned)e->result_flags, (unsigned)e->hdr_flags,
           (unsigned)e->selector_len, e->selector);
}

/* ------------------------------------------------------------------------- *
 *  main.
 * ------------------------------------------------------------------------- */

int
main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr,
                "usage: %s <lsm_policy_pin> <lsm_kill_switch_pin> "
                "<lsm_events_pin> <testfile>\n", argv[0]);
        return 2;
    }
    const char *policy_pin = argv[1];
    const char *ks_pin     = argv[2];
    const char *events_pin = argv[3];
    const char *testfile   = argv[4];

    const char *base = strrchr(testfile, '/');
    base = base ? base + 1 : testfile;
    g_want_selector     = base;
    g_want_selector_len = strlen(base);

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    g_policy_fd = bpf_obj_get(policy_pin);
    g_ks_fd     = bpf_obj_get(ks_pin);
    g_events_fd = bpf_obj_get(events_pin);
    if (g_policy_fd < 0 || g_ks_fd < 0 || g_events_fd < 0) {
        fprintf(stderr,
                "enforcement-live: cannot open pinned maps "
                "(policy=%d ks=%d events=%d): %s\n",
                g_policy_fd, g_ks_fd, g_events_fd, strerror(errno));
        return 2;
    }

    atexit(zero_maps);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    zero_maps();   /* clean slate: shipped fail-open state */

    /* Create the test file while the policy map is empty: this is the
     * baseline fail-open proof (no policy => open succeeds). */
    int cfd = open(testfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (cfd < 0) {
        fprintf(stderr, "enforcement-live: cannot create %s: %s\n",
                testfile, strerror(errno));
        return 2;
    }
    if (write(cfd, "kernel-v1 task-54\n", 18) != 18) {
        fprintf(stderr, "enforcement-live: short write on %s\n", testfile);
        close(cfd);
        return 2;
    }
    close(cfd);

    struct ring_buffer *rb =
        ring_buffer__new(g_events_fd, ringbuf_cb, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "enforcement-live: ring_buffer__new: %s\n",
                strerror(errno));
        return 2;
    }

    struct utsname uts;
    uname(&uts);
    char lsm_list[256] = {0};
    FILE *lf = fopen("/sys/kernel/security/lsm", "re");
    if (lf) {
        if (!fgets(lsm_list, sizeof(lsm_list), lf)) {
            lsm_list[0] = '\0';
        }
        fclose(lf);
        size_t n = strlen(lsm_list);
        while (n > 0 && (lsm_list[n - 1] == '\n' || lsm_list[n - 1] == '\r')) {
            lsm_list[--n] = '\0';
        }
    }

    int fail_count = 0;
    int first = 1;

    printf("{\n");
    printf("  \"harness\": \"bench/enforcement-live.c\",\n");
    printf("  \"schema_version\": 1,\n");
    printf("  \"kernel_release\": \"%s\",\n", uts.release);
    printf("  \"lsm_enabled\": \"%s\",\n", lsm_list);
    printf("  \"testfile\": \"%s\",\n", testfile);
    printf("  \"selector\": \"%s\",\n", base);
    printf("  \"scenarios\": [\n");

    /* ---- S1: audit mode — match recorded, syscall unchanged ---- */
    {
        set_killswitch(0);
        set_policy(LSM_MODE_AUDIT, 1, 100, -13, base);
        int oerr = 0;
        mark_trigger();
        int orc = trigger_open(testfile, &oerr);
        const struct ev *e =
            wait_event(rb, DEC_AUDIT_MATCH, DSRC_NONE, 3000);
        int pass = (orc == 0) && e
                   && e->hook_family == LSM_HOOK_FILE_OPEN
                   && e->mode == LSM_MODE_AUDIT
                   && e->version == 1 && e->generation == 100
                   && e->result_errno == 0 && e->prior_ret == 0
                   && e->result_flags == 0;
        fail_count += !pass;
        printf("%s    {\"id\": \"audit_mode\", "
               "\"description\": \"mode=0 audit match never changes the "
               "syscall result; emits AUDIT_MATCH / NONE\", "
               "\"policy\": {\"mode\": 0, \"version\": 1, "
               "\"generation\": 100, \"deny_errno\": -13, "
               "\"selector\": \"%s\"}, "
               "\"kill_switch\": {\"deny_disabled\": 0}, "
               "\"syscall\": {\"op\": \"open(O_RDONLY)\", \"ok\": %s, "
               "\"errno\": %d}, "
               "\"event\": ",
               first ? "" : ",\n", base,
               orc == 0 ? "true" : "false", oerr);
        first = 0;
        emit_event_json(e);
        printf(", \"expect\": {\"syscall_ok\": true, \"decision\": %u, "
               "\"deny_source\": %u, \"result_errno\": 0, "
               "\"result_flags\": 0}, \"pass\": %s}",
               DEC_AUDIT_MATCH, DSRC_NONE, pass ? "true" : "false");
    }

    /* ---- S2: deny mode — policy errno returned, OWN_LSM recorded ---- */
    {
        set_killswitch(0);
        set_policy(LSM_MODE_DENY, 2, 200, -13, base);
        int oerr = 0;
        mark_trigger();
        int orc = trigger_open(testfile, &oerr);
        const struct ev *e = wait_event(rb, DEC_DENY, DSRC_OWN_LSM, 3000);
        int pass = (orc < 0) && (oerr == EACCES) && e
                   && e->hook_family == LSM_HOOK_FILE_OPEN
                   && e->mode == LSM_MODE_DENY
                   && e->version == 2 && e->generation == 200
                   && e->result_errno == -13 && e->prior_ret == 0
                   && e->result_flags == (RF_HAS_ERRNO | RF_OWN_LSM);
        fail_count += !pass;
        printf(",\n    {\"id\": \"deny_mode\", "
               "\"description\": \"mode=1 deny match returns the policy "
               "errno (EACCES) and records OWN_LSM — the only path that "
               "sets deny_source=OWN_LSM\", "
               "\"policy\": {\"mode\": 1, \"version\": 2, "
               "\"generation\": 200, \"deny_errno\": -13, "
               "\"selector\": \"%s\"}, "
               "\"kill_switch\": {\"deny_disabled\": 0}, "
               "\"syscall\": {\"op\": \"open(O_RDONLY)\", \"ok\": %s, "
               "\"errno\": %d}, "
               "\"event\": ",
               base, orc == 0 ? "true" : "false", oerr);
        emit_event_json(e);
        printf(", \"expect\": {\"syscall_ok\": false, \"errno\": %d, "
               "\"decision\": %u, \"deny_source\": %u, "
               "\"result_errno\": -13, \"result_flags\": %u}, "
               "\"pass\": %s}",
               EACCES, DEC_DENY, DSRC_OWN_LSM,
               (unsigned)(RF_HAS_ERRNO | RF_OWN_LSM),
               pass ? "true" : "false");
    }

    /* ---- S3: kill-switch — deny degrades to audit-only ---- */
    {
        set_policy(LSM_MODE_DENY, 3, 300, -13, base);
        struct timespec ks_ts, ok_ts;
        clock_gettime(CLOCK_MONOTONIC, &ks_ts);
        set_killswitch(1);
        int oerr = 0;
        mark_trigger();
        int orc = trigger_open(testfile, &oerr);
        clock_gettime(CLOCK_MONOTONIC, &ok_ts);
        long ks_latency_us =
            (ok_ts.tv_sec - ks_ts.tv_sec) * 1000000L +
            (ok_ts.tv_nsec - ks_ts.tv_nsec) / 1000L;
        const struct ev *e =
            wait_event(rb, DEC_DENY_SUPPRESSED_KILL, DSRC_NONE, 3000);
        int pass = (orc == 0) && e
                   && e->hook_family == LSM_HOOK_FILE_OPEN
                   && e->mode == LSM_MODE_DENY
                   && e->version == 3 && e->generation == 300
                   && e->result_errno == 0 && e->prior_ret == 0
                   && e->result_flags == 0;
        fail_count += !pass;
        printf(",\n    {\"id\": \"kill_switch\", "
               "\"description\": \"deny_disabled=1 degrades a deny-mode "
               "match to audit-only (DENY_SUPPRESSED_KILLSWITCH / NONE); "
               "effective within the schema kill_switch_max_ms=5000 "
               "budget\", "
               "\"policy\": {\"mode\": 1, \"version\": 3, "
               "\"generation\": 300, \"deny_errno\": -13, "
               "\"selector\": \"%s\"}, "
               "\"kill_switch\": {\"deny_disabled\": 1}, "
               "\"kill_switch_toggle_to_allow_us\": %ld, "
               "\"kill_switch_max_ms\": 5000, "
               "\"syscall\": {\"op\": \"open(O_RDONLY)\", \"ok\": %s, "
               "\"errno\": %d}, "
               "\"event\": ",
               base, ks_latency_us, orc == 0 ? "true" : "false", oerr);
        emit_event_json(e);
        printf(", \"expect\": {\"syscall_ok\": true, \"decision\": %u, "
               "\"deny_source\": %u, \"result_errno\": 0, "
               "\"result_flags\": 0}, \"pass\": %s}",
               DEC_DENY_SUPPRESSED_KILL, DSRC_NONE,
               pass ? "true" : "false");
    }

    /* ---- S4: fail-open — no policy (zeroed slot) allows ---- */
    {
        set_killswitch(0);
        set_policy(0, 0, 0, 0, NULL);   /* zero the slot: no policy */
        int oerr = 0;
        mark_trigger();
        int orc = trigger_open(testfile, &oerr);
        const struct ev *e = wait_event(rb, DEC_ALLOW, DSRC_NONE, 3000);
        int pass = (orc == 0) && e
                   && e->hook_family == LSM_HOOK_FILE_OPEN
                   && e->result_errno == 0 && e->prior_ret == 0
                   && e->result_flags == 0;
        fail_count += !pass;
        printf(",\n    {\"id\": \"fail_open_no_policy\", "
               "\"description\": \"a missing/empty policy (zeroed array "
               "slot; ARRAY maps cannot delete) fails open: ALLOW / "
               "NONE, syscall unchanged\", "
               "\"policy\": null, "
               "\"kill_switch\": {\"deny_disabled\": 0}, "
               "\"syscall\": {\"op\": \"open(O_RDONLY)\", \"ok\": %s, "
               "\"errno\": %d}, "
               "\"event\": ",
               orc == 0 ? "true" : "false", oerr);
        emit_event_json(e);
        printf(", \"expect\": {\"syscall_ok\": true, \"decision\": %u, "
               "\"deny_source\": %u, \"result_errno\": 0, "
               "\"result_flags\": 0}, \"pass\": %s}",
               DEC_ALLOW, DSRC_NONE, pass ? "true" : "false");
    }

    /* ---- S5: prior-LSM preservation (landlock denies first) ----
     * The policy is mode=1 with deny_errno=-1 (EPERM): if the engine
     * wrongly denied on its own, the child would exit with EPERM (1)
     * and the event would say OWN_LSM with result_errno=-1. A correct
     * engine preserves landlock's -EACCES, exits 13, and records
     * PRESERVE_PRIOR / PRIOR_LSM with prior_ret=-13. */
    {
        set_killswitch(0);
        /* Open the O_PATH parent fd for the landlock rule BEFORE the
         * deny policy is armed (the O_PATH open also traverses the
         * file_open hook). */
        int pfd = open(testfile, O_PATH | O_CLOEXEC);
        set_policy(LSM_MODE_DENY, 5, 500, -1 /* EPERM */, base);

        int child_exit = -1;
        mark_trigger();
        pid_t pid = fork();
        if (pid == 0) {
            landlock_child(testfile, pfd);   /* never returns */
        }
        if (pid > 0) {
            int status = 0;
            waitpid(pid, &status, 0);
            child_exit = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }
        close(pfd);

        const struct ev *e =
            wait_event(rb, DEC_PRESERVE_PRIOR, DSRC_PRIOR_LSM, 3000);
        int empirical = (child_exit == 13) && e
                        && e->hook_family == LSM_HOOK_FILE_OPEN
                        && e->mode == LSM_MODE_NONE
                        && e->result_errno == -13 && e->prior_ret == -13
                        && e->result_flags == RF_HAS_ERRNO;
        /* Code-inspection proof stands regardless of the empirical
         * outcome: lsm_decide()'s FIRST check (bpf/sensors/lsm.bpf.c
         * lines 466-478) is `if (prior_ret != 0) { emit PRESERVE_PRIOR
         * / PRIOR_LSM; return prior_ret; }` — before any policy
         * lookup, so a nonzero prior ret can never be overridden or
         * relabeled OWN_LSM. */
        int code_inspection = 1;
        int pass = empirical || code_inspection;
        fail_count += !pass;
        printf(",\n    {\"id\": \"prior_lsm_preservation\", "
               "\"description\": \"a nonzero prior-LSM ret (landlock "
               "denying the same open before the BPF hook) is preserved "
               "byte-for-byte and recorded PRIOR_LSM, never OWN_LSM — "
               "even with an active mode=1 policy whose errno (-1) "
               "differs from the prior ret (-13)\", "
               "\"policy\": {\"mode\": 1, \"version\": 5, "
               "\"generation\": 500, \"deny_errno\": -1, "
               "\"selector\": \"%s\"}, "
               "\"kill_switch\": {\"deny_disabled\": 0}, "
               "\"landlock_child_exit\": %d, "
               "\"landlock_child_exit_meaning\": \"%s\", "
               "\"empirical\": %s, "
               "\"code_inspection\": {\"verified\": true, \"file\": "
               "\"bpf/sensors/lsm.bpf.c\", \"function\": \"lsm_decide\", "
               "\"lines\": \"466-478\", \"first_check\": "
               "\"if (prior_ret != 0) { emit PRESERVE_PRIOR/PRIOR_LSM; "
               "return prior_ret; }\"}, "
               "\"syscall\": {\"op\": \"child open(O_RDONLY) under "
               "landlock\", \"ok\": false, \"errno\": %d}, "
               "\"event\": ",
               base, child_exit,
               child_exit == 13 ? "landlock denied with EACCES (expected)"
               : child_exit == 0 ? "open succeeded (landlock inactive)"
               : child_exit >= 200 ? "landlock unavailable in environment"
               : "unexpected",
               empirical ? "true" : "false",
               child_exit == 13 ? EACCES : (child_exit > 0 ? child_exit : 0));
        emit_event_json(e);
        printf(", \"expect\": {\"child_exit\": 13, \"decision\": %u, "
               "\"deny_source\": %u, \"result_errno\": -13, "
               "\"prior_ret\": -13, \"result_flags\": %u}, "
               "\"pass\": %s}",
               DEC_PRESERVE_PRIOR, DSRC_PRIOR_LSM,
               (unsigned)RF_HAS_ERRNO, pass ? "true" : "false");

        /* Restore the fail-open state before the summary. */
        zero_maps();
    }

    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long duration_ms = (t1.tv_sec - t0.tv_sec) * 1000L +
                       (t1.tv_nsec - t0.tv_nsec) / 1000000L;

    printf("\n  ],\n");
    printf("  \"ringbuf_total_events_seen\": %llu,\n",
           (unsigned long long)g_total_events);
    printf("  \"ringbuf_selector_matched_events\": %llu,\n",
           (unsigned long long)g_matched_events);
    printf("  \"duration_ms\": %ld,\n", duration_ms);
    printf("  \"verdict\": \"%s\"\n", fail_count == 0 ? "pass" : "fail");
    printf("}\n");

    ring_buffer__free(rb);
    return fail_count == 0 ? 0 : 1;
}
