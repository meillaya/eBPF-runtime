/* SPDX-License-Identifier: GPL-2.0-only */
/* allow: SIZE_OK — architecture syscall tables and verifier-visible map declarations are indivisible BPF ABI data. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
typedef __s32 int32_t;
typedef __s64 int64_t;

#include "../include/event_abi.h"
#pragma clang optimize on

char LICENSE[] SEC("license") = "GPL";

#define EINTR 4
#define ERESTARTSYS 512
#define X32_SYSCALL_BIT 0x40000000U
#ifndef BPF_MAP_TYPE_LRU_PERCPU_ARRAY
#define BPF_MAP_TYPE_LRU_PERCPU_ARRAY BPF_MAP_TYPE_PERCPU_ARRAY
#endif

#if defined(__TARGET_ARCH_x86)
#define NR_OPEN 2
#define NR_OPENAT 257
#define NR_OPENAT2 437
#define NR_READ 0
#define NR_WRITE 1
#define NR_CLOSE 3
#define NR_EXECVE 59
#define NR_EXECVEAT 322
#define NR_EXIT 60
#define NR_EXIT_GROUP 231
#define NR_NANOSLEEP 35
#define NR_CLOCK_NANOSLEEP 230
#define NR_PSELECT6 270
#define NR_PPOLL 271
#define NR_FUTEX 202
#define NR_CONNECT 42
#define NR_ACCEPT 43
#define NR_ACCEPT4 288
#define NR_SENDTO 44
#define NR_RECVFROM 45
#define NR_SETSID 112
#define NR_SETUID 105
#define NR_SETGID 106
#define NR_KILL 62
#define NR_TKILL 200
#define NR_TGKILL 234
#define NR_PRCTL 157
#define NR_SECCOMP 317
#define NR_RESTART_SYSCALL 219
#elif defined(__TARGET_ARCH_arm64)
#define NR_OPEN -1
#define NR_OPENAT 56
#define NR_OPENAT2 437
#define NR_READ 63
#define NR_WRITE 64
#define NR_CLOSE 57
#define NR_EXECVE 221
#define NR_EXECVEAT 281
#define NR_EXIT 93
#define NR_EXIT_GROUP 94
#define NR_NANOSLEEP 101
#define NR_CLOCK_NANOSLEEP 115
#define NR_PSELECT6 72
#define NR_PPOLL 73
#define NR_FUTEX 98
#define NR_CONNECT 203
#define NR_ACCEPT 202
#define NR_ACCEPT4 242
#define NR_SENDTO 206
#define NR_RECVFROM 207
#define NR_SETSID 157
#define NR_SETUID 146
#define NR_SETGID 144
#define NR_KILL 129
#define NR_TKILL 130
#define NR_TGKILL 131
#define NR_PRCTL 167
#define NR_SECCOMP 277
#define NR_RESTART_SYSCALL 128
#else
#error "syscall sensor supports x86_64 and arm64"
#endif

struct syscall_entry {
    __u64 start_ns;
    __u32 syscall_nr;
    __u32 allowlist_index;
    __u64 flags;
};

struct kernel_v1_syscall_event {
    struct kernel_v1_header header;
    struct kernel_v1_syscall_event_payload payload;
} __attribute__((packed));

enum syscall_counter_id {
    KERNEL_V1_SYSCALL_NOT_ALLOWED = 0,
    KERNEL_V1_SYSCALL_ORPHAN_ENTER = 1,
    KERNEL_V1_SYSCALL_ORPHAN_EXIT = 2,
    KERNEL_V1_SYSCALL_NO_RETURN = 3,
    KERNEL_V1_SYSCALL_COUNTER_MAX = 4,
};

const volatile __s32 kconfig_syscall_allowlist[28] SEC(".rodata") = {
    NR_OPEN, NR_OPENAT, NR_OPENAT2, NR_READ, NR_WRITE, NR_CLOSE,
    NR_EXECVE, NR_EXECVEAT, NR_EXIT, NR_EXIT_GROUP, NR_NANOSLEEP,
    NR_CLOCK_NANOSLEEP, NR_PSELECT6, NR_PPOLL, NR_FUTEX, NR_CONNECT,
    NR_ACCEPT, NR_ACCEPT4, NR_SENDTO, NR_RECVFROM, NR_SETSID, NR_SETUID,
    NR_SETGID, NR_KILL, NR_TKILL, NR_TGKILL, NR_PRCTL, NR_SECCOMP,
};

const volatile __u8 kconfig_syscall_enabled[KERNEL_V1_SYSCALL_NR_MAX] SEC(".rodata") = {
#if defined(__TARGET_ARCH_x86)
    [NR_OPEN] = 1,
#endif
    [NR_OPENAT] = 1, [NR_OPENAT2] = 1, [NR_READ] = 1, [NR_WRITE] = 1,
    [NR_CLOSE] = 1, [NR_EXECVE] = 1, [NR_EXECVEAT] = 1, [NR_EXIT] = 1,
    [NR_EXIT_GROUP] = 1, [NR_NANOSLEEP] = 1, [NR_CLOCK_NANOSLEEP] = 1,
    [NR_PSELECT6] = 1, [NR_PPOLL] = 1, [NR_FUTEX] = 1, [NR_CONNECT] = 1,
    [NR_ACCEPT] = 1, [NR_ACCEPT4] = 1, [NR_SENDTO] = 1, [NR_RECVFROM] = 1,
    [NR_SETSID] = 1, [NR_SETUID] = 1, [NR_SETGID] = 1, [NR_KILL] = 1,
    [NR_TKILL] = 1, [NR_TGKILL] = 1, [NR_PRCTL] = 1, [NR_SECCOMP] = 1,
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct syscall_entry);
} syscall_entry_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_ARRAY);
    __uint(max_entries, KERNEL_V1_SYSCALL_NR_MAX);
    __type(key, __u32);
    __type(value, struct kernel_v1_syscall_hist_bucket);
} syscall_histogram SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, KERNEL_V1_SYSCALL_COUNTER_MAX);
    __type(key, __u32);
    __type(value, __u64);
} syscall_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} syscall_events SEC(".maps");

static __attribute__((noinline)) void bump_counter(__u32 id)
{
    __u64 *value = bpf_map_lookup_elem(&syscall_counters, &id);
    if (value)
        (*value)++;
}

static __attribute__((noinline)) int allowlist_index(__u32 nr)
{
    if (nr >= KERNEL_V1_SYSCALL_NR_MAX || !kconfig_syscall_enabled[nr])
        return -1;
    return nr;
}

static __attribute__((noinline)) __u64 entry_key(__u64 pid_tgid, __u32 nr)
{
    return (pid_tgid << 32) | (__u64)nr;
}

static __attribute__((noinline)) __u32 latency_bucket(__u64 latency_ns)
{
    if (!latency_ns)
        return 0;
    return 63 - (__u32)__builtin_clzll(latency_ns);
}

static __attribute__((noinline)) void emit_event(__u8 kind, __u32 nr, __u64 flags,
                                       __u64 latency_ns, __s64 exit_code)
{
    struct kernel_v1_syscall_event *event =
        bpf_ringbuf_reserve(&syscall_events, sizeof(*event), 0);
    if (!event)
        return;
    event->header.schema_major = KERNEL_V1_ABI_SCHEMA_MAJOR;
    event->header.schema_minor = KERNEL_V1_ABI_SCHEMA_MINOR;
    event->header.header_len = KERNEL_V1_ABI_HEADER_LEN;
    event->header.record_len = sizeof(*event);
    event->header.event_kind = kind;
    event->header.ts_monotonic_ns = bpf_ktime_get_ns();
    event->header.pid_tgid = bpf_get_current_pid_tgid();
    event->header.cgroup_id = bpf_get_current_cgroup_id();
    event->header.processor_id = bpf_get_smp_processor_id();
    event->header.valids = KERNEL_V1_VALID_PID_TGID |
                           KERNEL_V1_VALID_CGROUP_ID |
                           KERNEL_V1_VALID_PROCESSOR |
                           KERNEL_V1_VALID_SYSCALL_NR;
    if (latency_ns)
        event->header.valids |= KERNEL_V1_VALID_SYSCALL_LATENCY;
    event->payload.syscall_nr = nr;
    event->payload.flags = flags;
    event->payload.latency_ns = latency_ns;
    event->payload.exit_code = exit_code;
    bpf_ringbuf_submit(event, 0);
}

static __attribute__((noinline)) void update_histogram(__u32 nr, __u64 latency_ns,
                                              __s64 exit_code, __u64 flags)
{
    struct kernel_v1_syscall_hist_bucket *hist =
        bpf_map_lookup_elem(&syscall_histogram, &nr);
    if (!hist)
        return;
    __u32 bucket = latency_bucket(latency_ns);
    __sync_fetch_and_add(&hist->bin_count_log2[bucket], 1);
    __sync_fetch_and_add(&hist->sum_ns, latency_ns);
    __sync_fetch_and_add(&hist->count, 1);
    if (exit_code < 0)
        __sync_fetch_and_add(&hist->failure_count, 1);
    else
        __sync_fetch_and_add(&hist->success_count, 1);
    if (flags & KERNEL_V1_SYSCALL_FLAG_INTERRUPTED)
        __sync_fetch_and_add(&hist->interrupted_count, 1);
    if (flags & KERNEL_V1_SYSCALL_FLAG_RESTARTED)
        __sync_fetch_and_add(&hist->restarted_count, 1);
}

SEC("raw_tracepoint/sys_enter")
int syscall_enter(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 nr = (__u32)ctx->args[1];
    __u64 flags = 0;
#if defined(__TARGET_ARCH_x86)
    if (nr & X32_SYSCALL_BIT) {
        nr &= ~X32_SYSCALL_BIT;
        flags |= KERNEL_V1_SYSCALL_FLAG_COMPAT;
    }
#endif
    int index = allowlist_index(nr);
    if (index < 0) {
        bump_counter(KERNEL_V1_SYSCALL_NOT_ALLOWED);
        emit_event(KERNEL_V1_EVENT_SYSCALL_ENTER, nr,
                   flags | KERNEL_V1_SYSCALL_FLAG_NOT_ALLOWED, 0, 0);
        return 0;
    }
    if (nr == NR_EXECVE || nr == NR_EXECVEAT)
        flags |= KERNEL_V1_SYSCALL_FLAG_IS_EXEC;
    if (nr == NR_EXIT || nr == NR_EXIT_GROUP) {
        flags |= KERNEL_V1_SYSCALL_FLAG_NO_RETURN;
        bump_counter(KERNEL_V1_SYSCALL_NO_RETURN);
        emit_event(KERNEL_V1_EVENT_SYSCALL_EXIT, nr, flags, 0, 0);
        return 0;
    }
    struct syscall_entry entry = {
        .start_ns = bpf_ktime_get_ns(),
        .syscall_nr = nr,
        .allowlist_index = (__u32)index,
        .flags = flags,
    };
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 key = entry_key(pid_tgid, nr);
    if (bpf_map_update_elem(&syscall_entry_state, &key, &entry, BPF_ANY))
        bump_counter(KERNEL_V1_SYSCALL_ORPHAN_EXIT);
    emit_event(KERNEL_V1_EVENT_SYSCALL_ENTER, nr, flags, 0, 0);
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int syscall_exit(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 nr = (__u32)ctx->args[1];
#if defined(__TARGET_ARCH_x86)
    nr &= ~X32_SYSCALL_BIT;
#endif
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 key = entry_key(pid_tgid, nr);
    struct syscall_entry *entry = bpf_map_lookup_elem(&syscall_entry_state, &key);
    if (!entry) {
        bump_counter(KERNEL_V1_SYSCALL_ORPHAN_ENTER);
        return 0;
    }
    __s64 exit_code = (__s64)ctx->args[2];
    __u64 latency_ns = bpf_ktime_get_ns() - entry->start_ns;
    __u64 flags = entry->flags;
    if (exit_code < 0)
        flags |= KERNEL_V1_SYSCALL_FLAG_FAILED;
    if (exit_code == -EINTR || exit_code == -ERESTARTSYS)
        flags |= KERNEL_V1_SYSCALL_FLAG_INTERRUPTED;
    if (nr == NR_RESTART_SYSCALL)
        flags |= KERNEL_V1_SYSCALL_FLAG_RESTARTED;
    update_histogram(nr, latency_ns, exit_code, flags);
    emit_event(KERNEL_V1_EVENT_SYSCALL_EXIT, nr, flags, latency_ns, exit_code);
    bpf_map_delete_elem(&syscall_entry_state, &key);
    return 0;
}
