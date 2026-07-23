// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// tests/privileged/task53/harness.c — kernel-v1 task 53 privileged BPF
// sensor proof harness.
//
// Loads bpf/sensors/process.bpf.c (compiled object passed by path) with
// libbpf, attaches every program (3 raw tracepoints + 1 kprobe), consumes
// the shared ring buffer, and independently generates a ground-truth
// workload of fork/exec/exit events by spawning /bin/true children whose
// PIDs are recorded in an oracle table. The oracle is the independent
// witness: loss is (oracle-expected - oracle-matched), never a claim made
// from agent counters alone.
//
// Modes:
//   ordering    — modest rate, active consumer; every oracle child MUST be
//                 observed with fork -> exec -> exit causal ordering and
//                 per-CPU seq monotonicity. Zero loss required.
//   supported   — at the declared supported-load envelope (default
//                 1000 events/s/cpu from bench/schemas/supported-load.v1.json),
//                 one rate-pinned worker thread per CPU, active consumer;
//                 zero critical fixture loss required.
//   saturation  — tiny ring (schema tiny_ring_size_bytes, default 4096),
//                 consumer PAUSED while workers flood, then drained; the
//                 reserve-failure delta (oracle expected - matched) MUST be
//                 non-zero and reconciled (never a false zero).
//
// Run inside a privileged container with --pid=host so the PIDs the harness
// sees from fork() equal the global PIDs the BPF programs report.
//
// Build: gcc -O2 -o harness harness.c -lbpf -lelf -lz -lpthread

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* ---- event ABI constants (mirror bpf/include/event_abi.h) ---- */
#define HDR_LEN 96u
#define KIND_FORK 1u /* KERNEL_V1_EVENT_PROCESS_FORK        */
#define KIND_EXEC 2u /* KERNEL_V1_EVENT_PROCESS_EXEC_RESULT */
#define KIND_EXIT 3u /* KERNEL_V1_EVENT_PROCESS_EXIT        */

/* process.bpf.c header flags byte (bits 2..7 are process-specific) */
#define PROCESS_FLAG_NO_RETURN 0x04u
#define PROCESS_FLAG_EXEC_FAILED 0x08u
#define PROCESS_FLAG_EXEC_COMPLETED 0x10u

#define MAX_CPUS 256u

/* ---- oracle table: pid -> child record ---- */
struct child_rec {
    uint32_t pid;
    uint64_t fork_ts;
    uint64_t exec_ts;    /* raw-tracepoint exec (EXEC_COMPLETED) */
    uint64_t exec_kp_ts; /* kprobe exec (EXEC_FAILED|NO_RETURN)  */
    uint64_t exit_ts;
    uint8_t fork_seen;
    uint8_t exec_seen;
    uint8_t exec_kp_seen;
    uint8_t exit_seen;
};

static struct child_rec *g_recs;
static uint32_t g_nrecs;
static uint32_t g_rec_cap;
static uint32_t *g_slots; /* slot -> rec index + 1; 0 = empty */
static uint32_t g_nslots; /* power of two */
static uint64_t g_pid_reuse_resets;
static pthread_mutex_t g_map_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t hash_pid(uint32_t pid)
{
    return (pid * 2654435761u) & (g_nslots - 1);
}

static void oracle_init(uint32_t max_children)
{
    g_rec_cap = max_children + 64;
    g_recs = calloc(g_rec_cap, sizeof(*g_recs));
    g_nslots = 1;
    while (g_nslots < max_children * 4)
        g_nslots <<= 1;
    g_slots = calloc(g_nslots, sizeof(*g_slots));
    if (!g_recs || !g_slots) {
        fprintf(stderr, "harness: oracle alloc failed\n");
        exit(1);
    }
}

/* Record a freshly-forked child pid. Tolerates PID reuse by resetting the
 * record (counted so the run can prove reuse pressure stayed negligible). */
static void oracle_insert(uint32_t pid)
{
    pthread_mutex_lock(&g_map_lock);
    uint32_t i = hash_pid(pid);
    while (g_slots[i] != 0) {
        struct child_rec *r = &g_recs[g_slots[i] - 1];
        if (r->pid == pid) {
            memset(r, 0, sizeof(*r));
            r->pid = pid;
            g_pid_reuse_resets++;
            pthread_mutex_unlock(&g_map_lock);
            return;
        }
        i = (i + 1) & (g_nslots - 1);
    }
    if (g_nrecs >= g_rec_cap) { /* grow records array */
        g_rec_cap *= 2;
        g_recs = realloc(g_recs, g_rec_cap * sizeof(*g_recs));
        if (!g_recs) {
            fprintf(stderr, "harness: oracle grow failed\n");
            exit(1);
        }
    }
    g_slots[i] = ++g_nrecs;
    struct child_rec *r = &g_recs[g_nrecs - 1];
    memset(r, 0, sizeof(*r));
    r->pid = pid;
    pthread_mutex_unlock(&g_map_lock);
}

static struct child_rec *oracle_lookup(uint32_t pid)
{
    pthread_mutex_lock(&g_map_lock);
    uint32_t i = hash_pid(pid);
    struct child_rec *found = NULL;
    while (g_slots[i] != 0) {
        struct child_rec *r = &g_recs[g_slots[i] - 1];
        if (r->pid == pid) {
            found = r;
            break;
        }
        i = (i + 1) & (g_nslots - 1);
    }
    pthread_mutex_unlock(&g_map_lock);
    return found;
}

/* ---- consumer-side event log (touched only by the consumer thread) ----
 * Matching against the oracle happens in a single final pass AFTER every
 * worker has joined, which removes the fork-return vs consume race: an
 * event committed before its parent thread registered the child pid is
 * still matched once all registrations are in. */
struct ev_rec {
    uint64_t ts;
    uint64_t seq;
    uint32_t pid; /* fork: child pid from payload; exec/exit: tgid */
    uint32_t cpu;
    uint8_t kind;
    uint8_t flags;
};

static struct ev_rec *g_evs;
static uint64_t g_nevs, g_ev_cap = 1 << 16;
static uint64_t cnt_fork, cnt_exec, cnt_exit, cnt_other, consumed_total;
static uint64_t seq_last[MAX_CPUS];
static uint8_t seq_seen[MAX_CPUS];
static uint64_t percpu_seq_violations;
static uint64_t m_fork, m_exec, m_exec_kp, m_exit; /* oracle matches */

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    consumed_total++;
    if (size < HDR_LEN) {
        cnt_other++;
        return 0;
    }
    const uint8_t *d = data;
    struct ev_rec e = {0};
    uint64_t pid_tgid = 0;
    e.kind = d[16];
    e.flags = d[20];
    memcpy(&e.seq, d + 24, 8);
    memcpy(&e.ts, d + 32, 8);
    memcpy(&pid_tgid, d + 56, 8);
    memcpy(&e.cpu, d + 80, 4);

    if (e.cpu < MAX_CPUS) {
        if (seq_seen[e.cpu] && e.seq <= seq_last[e.cpu])
            percpu_seq_violations++;
        seq_seen[e.cpu] = 1;
        seq_last[e.cpu] = e.seq;
    }

    if (e.kind == KIND_FORK) {
        cnt_fork++;
        if (size >= HDR_LEN + 16) {
            uint64_t child_pid = 0;
            memcpy(&child_pid, d + HDR_LEN + 8, 8); /* payload.child_pid */
            e.pid = (uint32_t)child_pid;
        }
    } else if (e.kind == KIND_EXEC) {
        cnt_exec++;
        e.pid = (uint32_t)(pid_tgid >> 32);
    } else if (e.kind == KIND_EXIT) {
        cnt_exit++;
        e.pid = (uint32_t)(pid_tgid >> 32);
    } else {
        cnt_other++;
    }

    if (g_nevs >= g_ev_cap) {
        g_ev_cap *= 2;
        g_evs = realloc(g_evs, g_ev_cap * sizeof(*g_evs));
        if (!g_evs) {
            fprintf(stderr, "harness: event log grow failed\n");
            exit(1);
        }
    }
    g_evs[g_nevs++] = e;
    return 0;
}

/* Final reconciliation pass: match the consumed event log against the
 * complete oracle. Runs single-threaded after workers + consumer joined. */
static void oracle_reconcile(void)
{
    for (uint64_t i = 0; i < g_nevs; i++) {
        struct ev_rec *e = &g_evs[i];
        if (!e->pid)
            continue;
        struct child_rec *r = oracle_lookup(e->pid);
        if (!r)
            continue; /* not one of our children (host noise) */
        if (e->kind == KIND_FORK) {
            if (!r->fork_seen) {
                r->fork_seen = 1;
                r->fork_ts = e->ts;
                m_fork++;
            }
        } else if (e->kind == KIND_EXEC) {
            if ((e->flags & PROCESS_FLAG_EXEC_COMPLETED) && !r->exec_seen) {
                r->exec_seen = 1;
                r->exec_ts = e->ts;
                m_exec++;
            } else if ((e->flags & PROCESS_FLAG_EXEC_FAILED) &&
                       !r->exec_kp_seen) {
                r->exec_kp_seen = 1;
                r->exec_kp_ts = e->ts;
                m_exec_kp++;
            }
        } else if (e->kind == KIND_EXIT) {
            if (!r->exit_seen) {
                r->exit_seen = 1;
                r->exit_ts = e->ts;
                m_exit++;
            }
        }
    }
}

/* ---- consumer thread ---- */
static struct ring_buffer *g_rb;
static atomic_int g_consumer_stop;
static int g_consumer_rt;  /* SCHED_FIFO priority; 0 = SCHED_OTHER */
static int g_consumer_cpu = -1; /* dedicated CPU; -1 = unpinned */
static time_t g_gen_deadline;   /* wall bound so a contended host cannot hang the run */

static void *consumer_fn(void *arg)
{
    (void)arg;
    if (g_consumer_cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(g_consumer_cpu % CPU_SETSIZE, &set);
        pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    }
    if (g_consumer_rt > 0) {
        struct sched_param sp = {.sched_priority = g_consumer_rt};
        if (sched_setscheduler(0, SCHED_FIFO, &sp))
            fprintf(stderr, "harness: SCHED_FIFO(%d) failed: %s\n",
                    g_consumer_rt, strerror(errno));
    }
    while (!atomic_load(&g_consumer_stop))
        ring_buffer__poll(g_rb, 5 /* ms */);
    return NULL;
}

/* ---- worker threads: ground-truth event generators ---- */
struct worker_args {
    int cpu;              /* -1 = no pinning */
    uint64_t count;       /* children to spawn */
    uint64_t interval_ns; /* 0 = flood */
    const char *bin;      /* program the children exec */
    uint64_t spawned;     /* out */
};

static void *worker_fn(void *argp)
{
    struct worker_args *a = argp;
    if (a->cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(a->cpu % CPU_SETSIZE, &set);
        pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    }
    char *argv[] = {(char *)a->bin, NULL};
    char *envp[] = {NULL};
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t i = 0; i < a->count; i++) {
        if ((i & 7) == 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec >= g_gen_deadline)
                break;
        }
        pid_t p = fork();
        if (p == 0) {
            execve(a->bin, argv, envp);
            _exit(127);
        }
        if (p < 0) {
            usleep(1000);
            continue;
        }
        oracle_insert((uint32_t)p);
        a->spawned++;
        int st;
        waitpid(p, &st, 0);
        if (a->interval_ns) {
            uint64_t ns = (uint64_t)t0.tv_nsec + (i + 1) * a->interval_ns;
            struct timespec dl = {
                .tv_sec = t0.tv_sec + (time_t)(ns / 1000000000ull),
                .tv_nsec = (long)(ns % 1000000000ull),
            };
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &dl, NULL);
        }
    }
    return NULL;
}

/* ---- main ---- */
struct config {
    const char *obj_path;
    const char *mode;
    const char *out_path;
    const char *bin;
    uint32_t ring_size;         /* 0 = keep object default */
    int workers;
    uint64_t children_per_worker;
    uint64_t rate_children_per_worker; /* 0 = flood */
    double drain_s;
    double max_gen_s;
};

static double ts_diff_s(struct timespec *a, struct timespec *b)
{
    return (double)(b->tv_sec - a->tv_sec) +
           (double)(b->tv_nsec - a->tv_nsec) / 1e9;
}

int main(int argc, char **argv)
{
    struct config cfg = {
        .mode = "ordering",
        .bin = "/bin/true",
        .workers = 4,
        .children_per_worker = 25,
        .rate_children_per_worker = 100,
        .drain_s = 2.0,
        .max_gen_s = 120.0,
    };
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] != '-' && !cfg.obj_path) {
            cfg.obj_path = a;
        } else if (!strncmp(a, "--mode=", 7)) {
            cfg.mode = a + 7;
        } else if (!strncmp(a, "--out=", 6)) {
            cfg.out_path = a + 6;
        } else if (!strncmp(a, "--bin=", 6)) {
            cfg.bin = a + 6;
        } else if (!strncmp(a, "--ring-size=", 12)) {
            cfg.ring_size = (uint32_t)strtoul(a + 12, NULL, 10);
        } else if (!strncmp(a, "--workers=", 10)) {
            cfg.workers = atoi(a + 10);
        } else if (!strncmp(a, "--children=", 11)) {
            cfg.children_per_worker = strtoul(a + 11, NULL, 10);
        } else if (!strncmp(a, "--rate=", 7)) {
            cfg.rate_children_per_worker = strtoul(a + 7, NULL, 10);
        } else if (!strncmp(a, "--drain=", 8)) {
            cfg.drain_s = atof(a + 8);
        } else if (!strncmp(a, "--consumer-rt=", 14)) {
            g_consumer_rt = atoi(a + 14);
        } else if (!strncmp(a, "--max-gen=", 10)) {
            cfg.max_gen_s = atof(a + 10);
        } else {
            fprintf(stderr,
                    "usage: harness <obj.bpf.o> [--mode=ordering|supported|saturation] "
                    "[--out=f.json] [--ring-size=N] [--workers=N] [--children=N] "
                    "[--rate=N] [--drain=S]\n");
            return 2;
        }
    }
    if (!cfg.obj_path) {
        fprintf(stderr, "harness: object path required\n");
        return 2;
    }
    int sat = !strcmp(cfg.mode, "saturation");

    libbpf_set_print(NULL); /* keep stderr for harness diagnostics only */

    /* open + optional ring resize + load */
    struct bpf_object *obj = bpf_object__open_file(cfg.obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "harness: open %s failed\n", cfg.obj_path);
        return 1;
    }
    struct bpf_map *ring_map = bpf_object__find_map_by_name(obj, "process_events");
    if (!ring_map) {
        fprintf(stderr, "harness: map process_events not found\n");
        return 1;
    }
    uint32_t ring_default = (uint32_t)bpf_map__max_entries(ring_map);
    if (cfg.ring_size && cfg.ring_size != ring_default) {
        if (bpf_map__set_max_entries(ring_map, cfg.ring_size)) {
            fprintf(stderr, "harness: ring resize to %u failed\n", cfg.ring_size);
            return 1;
        }
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "harness: bpf_object__load failed (verifier)\n");
        return 1;
    }
    uint32_t ring_loaded = (uint32_t)bpf_map__max_entries(ring_map);

    /* attach every program; tolerate kprobe attach failure (symbol may be
     * absent on non-x86_64 or renamed kernels) */
    struct bpf_link *links[16];
    int nlinks = 0, kprobe_attached = 0, nprogs = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj)
    {
        nprogs++;
        struct bpf_link *l = bpf_program__attach(prog);
        if (libbpf_get_error(l)) {
            const char *nm = bpf_program__name(prog);
            if (nm && strstr(nm, "kp_")) {
                fprintf(stderr,
                        "harness: kprobe %s attach failed (%s); continuing "
                        "without the failed-exec probe\n",
                        nm, strerror(errno));
                continue;
            }
            fprintf(stderr, "harness: attach %s failed\n",
                    bpf_program__name(prog));
            return 1;
        }
        if (strstr(bpf_program__name(prog), "kp_"))
            kprobe_attached = 1;
        if (nlinks < 16)
            links[nlinks++] = l;
    }

    g_rb = ring_buffer__new(bpf_map__fd(ring_map), handle_event, NULL, NULL);
    if (libbpf_get_error(g_rb)) {
        fprintf(stderr, "harness: ring_buffer__new failed\n");
        return 1;
    }

    uint64_t max_children = (uint64_t)cfg.workers * cfg.children_per_worker;
    oracle_init((uint32_t)(max_children > 1024 ? max_children : 1024));
    g_evs = calloc(g_ev_cap, sizeof(*g_evs));
    if (!g_evs) {
        fprintf(stderr, "harness: event log alloc failed\n");
        return 1;
    }

    /* Pin workers 1:1 onto CPUs; when a CPU is spare, leave CPU 0 for the
     * consumer so its drain loop never contends with generators. Must be
     * decided BEFORE the consumer thread starts (it reads g_consumer_cpu). */
    long ncpu_w = sysconf(_SC_NPROCESSORS_ONLN);
    int skip0 = (!sat && cfg.workers < (int)ncpu_w);
    if (skip0)
        g_consumer_cpu = 0;

    /* consumer: paused during a saturation flood, active otherwise */
    pthread_t consumer_tid;
    int consumer_running = 0;
    atomic_store(&g_consumer_stop, 0);
    if (!sat) {
        pthread_create(&consumer_tid, NULL, consumer_fn, NULL);
        consumer_running = 1;
    }

    struct worker_args *wa = calloc(cfg.workers, sizeof(*wa));
    pthread_t *wt = calloc(cfg.workers, sizeof(*wt));
    uint64_t interval_ns = cfg.rate_children_per_worker
                               ? 1000000000ull / cfg.rate_children_per_worker
                               : 0;
    struct timespec t_gen_start, t_gen_done;
    clock_gettime(CLOCK_MONOTONIC, &t_gen_start);
    g_gen_deadline = t_gen_start.tv_sec + (time_t)cfg.max_gen_s;
    for (int i = 0; i < cfg.workers; i++) {
        wa[i].cpu = sat ? -1 : i + (skip0 ? 1 : 0);
        wa[i].count = cfg.children_per_worker;
        wa[i].interval_ns = interval_ns;
        wa[i].bin = cfg.bin;
        pthread_create(&wt[i], NULL, worker_fn, &wa[i]);
    }
    uint64_t spawned = 0;
    for (int i = 0; i < cfg.workers; i++) {
        pthread_join(wt[i], NULL);
        spawned += wa[i].spawned;
    }
    clock_gettime(CLOCK_MONOTONIC, &t_gen_done);
    double gen_s = ts_diff_s(&t_gen_start, &t_gen_done);

    if (sat) { /* start the consumer only now: the flood saw a paused sink */
        pthread_create(&consumer_tid, NULL, consumer_fn, NULL);
        consumer_running = 1;
    }
    usleep((useconds_t)(cfg.drain_s * 1e6));
    atomic_store(&g_consumer_stop, 1);
    pthread_join(consumer_tid, NULL);
    (void)consumer_running;

    /* ---- score the oracle ---- */
    oracle_reconcile();
    uint64_t complete = 0, ordering_violations = 0, gap_children = 0;
    uint64_t first_gap_pid = 0, last_gap_pid = 0;
    for (uint32_t i = 0; i < g_nrecs; i++) {
        struct child_rec *r = &g_recs[i];
        int kp_ok = kprobe_attached ? r->exec_kp_seen : 1;
        if (r->fork_seen && r->exec_seen && r->exit_seen && kp_ok) {
            complete++;
            if (r->fork_ts > r->exec_ts || r->exec_ts > r->exit_ts)
                ordering_violations++;
            if (kprobe_attached && r->exec_kp_seen &&
                r->exec_kp_ts > r->exec_ts)
                ordering_violations++;
        } else {
            gap_children++;
            if (!first_gap_pid)
                first_gap_pid = r->pid;
            last_gap_pid = r->pid;
        }
    }
    uint64_t expected_oracle =
        spawned * (3 + (uint64_t)(kprobe_attached ? 1 : 0));
    uint64_t matched_oracle = m_fork + m_exec + m_exit +
                              (kprobe_attached ? m_exec_kp : 0);
    uint64_t reserve_failure_delta =
        expected_oracle > matched_oracle ? expected_oracle - matched_oracle : 0;

    /* events/s/cpu actually produced; workers pin 1:1 onto the online CPU
     * set (two workers per CPU still share one CPU), so divide by the
     * number of distinct CPUs the workers occupied. */
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    double cpus_used = sat ? (double)cfg.workers
                           : (double)(cfg.workers < ncpu ? cfg.workers : ncpu);
    double actual_rate_per_cpu =
        gen_s > 0 ? (double)(spawned * (3 + (uint64_t)(kprobe_attached ? 1 : 0))) /
                        gen_s / cpus_used
                  : 0;

    const char *verdict = "failed";
    char reason[256];
    if (sat) {
        /* saturation MUST shed, and the shed MUST be reconciled by the
         * independent oracle — a zero drop counter here is the red flag */
        if (reserve_failure_delta > 0 && gap_children > 0 &&
            consumed_total > 0) {
            verdict = "passed";
            snprintf(reason, sizeof(reason),
                     "saturation-detected-no-critical-loss: tiny ring (%u B) "
                     "shed %llu of %llu oracle events; loss reconciled by "
                     "independent oracle (never a false zero)",
                     ring_loaded, (unsigned long long)reserve_failure_delta,
                     (unsigned long long)expected_oracle);
        } else {
            snprintf(reason, sizeof(reason),
                     "saturation not proven: reserve_failure_delta=%llu "
                     "gap_children=%llu consumed=%llu",
                     (unsigned long long)reserve_failure_delta,
                     (unsigned long long)gap_children,
                     (unsigned long long)consumed_total);
        }
    } else {
        /* ordering / supported: zero critical loss is mandatory */
        if (complete == spawned && spawned > 0 && ordering_violations == 0 &&
            percpu_seq_violations == 0 && reserve_failure_delta == 0) {
            verdict = "passed";
            snprintf(reason, sizeof(reason),
                     "%s: %llu/%llu oracle children complete with causal "
                     "fork->exec->exit ordering, per-CPU seq monotonic, zero "
                     "critical loss at %.1f events/s/cpu",
                     cfg.mode, (unsigned long long)complete,
                     (unsigned long long)spawned, actual_rate_per_cpu);
        } else {
            snprintf(reason, sizeof(reason),
                     "%s: complete=%llu/%llu ordering_violations=%llu "
                     "seq_violations=%llu reserve_failure_delta=%llu",
                     cfg.mode, (unsigned long long)complete,
                     (unsigned long long)spawned,
                     (unsigned long long)ordering_violations,
                     (unsigned long long)percpu_seq_violations,
                     (unsigned long long)reserve_failure_delta);
        }
    }

    /* ---- emit JSON verdict ---- */
    FILE *out = cfg.out_path ? fopen(cfg.out_path, "w") : stdout;
    if (!out) {
        fprintf(stderr, "harness: cannot open %s\n", cfg.out_path);
        return 1;
    }
    fprintf(out,
            "{\n"
            "  \"mode\": \"%s\",\n"
            "  \"obj_path\": \"%s\",\n"
            "  \"programs_attached\": %d,\n"
            "  \"kprobe_attached\": %s,\n"
            "  \"ring_size_default_bytes\": %u,\n"
            "  \"ring_size_loaded_bytes\": %u,\n"
            "  \"workers\": %d,\n"
            "  \"children_per_worker\": %llu,\n"
            "  \"children_spawned\": %llu,\n"
            "  \"target_rate_children_per_worker\": %llu,\n"
            "  \"consumer_rt_priority\": %d,\n"
            "  \"generation_duration_s\": %.3f,\n"
            "  \"drain_s\": %.1f,\n"
            "  \"actual_rate_events_per_sec_per_cpu\": %.1f,\n"
            "  \"events_consumed_total\": %llu,\n"
            "  \"fork_events\": %llu,\n"
            "  \"exec_events\": %llu,\n"
            "  \"exit_events\": %llu,\n"
            "  \"other_events\": %llu,\n"
            "  \"oracle_expected_events\": %llu,\n"
            "  \"oracle_fork_matched\": %llu,\n"
            "  \"oracle_exec_matched\": %llu,\n"
            "  \"oracle_exec_kprobe_matched\": %llu,\n"
            "  \"oracle_exit_matched\": %llu,\n"
            "  \"oracle_complete_children\": %llu,\n"
            "  \"ordering_violations\": %llu,\n"
            "  \"percpu_seq_violations\": %llu,\n"
            "  \"pid_reuse_resets\": %llu,\n"
            "  \"reserve_failure_delta\": %llu,\n"
            "  \"gap_children\": %llu,\n"
            "  \"gap_start\": %llu,\n"
            "  \"gap_end\": %llu,\n"
            "  \"verdict\": \"%s\",\n"
            "  \"verdict_reason\": \"%s\"\n"
            "}\n",
            cfg.mode, cfg.obj_path, nprogs,
            kprobe_attached ? "true" : "false", ring_default, ring_loaded,
            cfg.workers, (unsigned long long)cfg.children_per_worker,
            (unsigned long long)spawned,
            (unsigned long long)cfg.rate_children_per_worker, g_consumer_rt,
            gen_s, cfg.drain_s, actual_rate_per_cpu,
            (unsigned long long)consumed_total,
            (unsigned long long)cnt_fork, (unsigned long long)cnt_exec,
            (unsigned long long)cnt_exit, (unsigned long long)cnt_other,
            (unsigned long long)expected_oracle,
            (unsigned long long)m_fork, (unsigned long long)m_exec,
            (unsigned long long)m_exec_kp, (unsigned long long)m_exit,
            (unsigned long long)complete,
            (unsigned long long)ordering_violations,
            (unsigned long long)percpu_seq_violations,
            (unsigned long long)g_pid_reuse_resets,
            (unsigned long long)reserve_failure_delta,
            (unsigned long long)gap_children,
            (unsigned long long)first_gap_pid,
            (unsigned long long)last_gap_pid, verdict, reason);
    if (cfg.out_path)
        fclose(out);

    fprintf(stderr, "harness[%s]: %s — %s\n", cfg.mode, verdict, reason);

    /* cleanup: links first, then the object (unpins/unloads everything) */
    for (int i = 0; i < nlinks; i++)
        bpf_link__destroy(links[i]);
    ring_buffer__free(g_rb);
    bpf_object__close(obj);

    return strcmp(verdict, "passed") == 0 ? 0 : 1;
}
