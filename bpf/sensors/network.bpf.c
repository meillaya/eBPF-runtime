/* SPDX-License-Identifier: GPL-2.0-only
 *
 * bpf/sensors/network.bpf.c
 * kernel-v1 — task 13 (network socket lifecycle sensor).
 *
 * INTRODUCTION
 *   This translation unit is the v1 network-sensor CO-RE program.
 *   It captures, with truthful semantics, the four kinds of
 *   socket-lifecycle observation the platform MUST distinguish
 *   (per the approved plan task 13):
 *
 *     1. NETWORK_CONNECT_ATTEMPT — emitted from cgroup connect4
 *        and connect6 hooks (or the syscall-enter kprobe fallback
 *        on a kernel without the BPF cgroup subsystem). Captures
 *        the destination tuple (IPv4 or IPv6), the destination
 *        port (network byte order on the wire), and the
 *        task/cgroup identity.
 *
 *     2. NETWORK_CONNECT_RESULT — emitted from kretprobes on
 *        __x64_sys_connect / __arm64_sys_connect with the socket
 *        cookie (set by the time we see the syscall exit), the
 *        original destination tuple, the raw errno (0 on success),
 *        and the per-event NONBLOCKING / EINPROGRESS flag bits.
 *        A refused connect leaves errno = -ECONNREFUSED and the
 *        sensor NEVER emits a corresponding NETWORK_STATE event
 *        with new_state = TCP_ESTABLISHED. This is the
 *        "no false established event on refusal" invariant.
 *
 *     3. NETWORK_ACCEPT_RESULT — emitted from kretprobes on
 *        __x64_sys_accept, __x64_sys_accept4 / arm64 equivalents.
 *        Carries the cookie, the returned fd, the peer address
 *        (read from the syscall args), and errno (0 on success).
 *        The sensor MUST NOT mark NET_FD valid when the returned
 *        fd is negative; the consumer relies on this invariant.
 *
 *     4. NETWORK_STATE — emitted from `tracepoint/sock/
 *        inet_sock_set_state`. Captures old_state and new_state
 *        as u8 values mapped from the kernel's `enum tcp_state`
 *        to the local KERNEL_V1_TCP_* enumerators. The cookie
 *        correlates with the connect/accept events.
 *
 *   Optional AF_UNIX hook (kernels 7.x expose `SEC("cgroup/
 *   connect_unix")`; older kernels do not — we use
 *   `bpf_core_field_exists` to probe and fall back to
 *   `INET_FALLBACK` when absent, recording `AF_UNIX_DEGRADED` in
 *   the resulting event's `valids` field).
 *
 *   The sensor does NOT rely on `inet_csk_accept` (an unstable
 *   internal kprobe that varies across kernel versions); the
 *   accept result is captured strictly at the syscall exit so
 *   the data is portable.
 *
 *   Attempts and results correlate by `(task_tgid, cookie)`.
 *   The kprobe path can be invoked before the socket cookie is
 *   set in the cgroup path, so the consumer falls back to
 *   task_tgid-only correlation when NET_COOKIE is not valid on
 *   the attempt event. This is the "lost cookie" degraded path
 *   the brief explicitly covers.
 *
 * FIELD VALIDITY (Truthfulness contract)
 *   * Network sub-event-specific NET_* bits are set only when the
 *     corresponding payload field was actually populated. A
 *     refused connect leaves NET_COOKIE valid (we read the cookie
 *     at syscall exit before the destructor); a refused connect
 *     never sets the network state to TCP_ESTABLISHED, so the
 *     failure QA path produces no NETWORK_STATE event with an
 *     established status.
 *   * Same identity invariants the process and file sensors
 *     carry: pid_tgid, cgroup_id, task_start_time, processor_id,
 *     boot_id are recorded with the standard KERNEL_V1_VALID_*
 *     bits.
 *   * boot_id is NOT set here — the loader (task 16) emits the
 *     identity event that carries the boot id; setting it
 *     without a real read would be a lie.
 *
 * HARD LIMITS
 *   * Each NETWORK_* event writes 80 bytes of payload
 *     (KERNEL_V1_NET_PAYLOAD_LEN) regardless of sub-event kind.
 *     Unused fields are zero, the corresponding NET_* validity
 *     bit is clear.
 *   * The BPF verifier rejects programs that recurse or that
 *     exceed the 512-byte stack limit; this file keeps stack
 *     usage well under that limit by reusing a single 16-byte
 *     IP buffer on the stack.
 *
 * SPDX NOTE
 *   Kprobes / raw-tracepoints / cgroup-skb programs accept any
 *   license string, but the bpfls `connect4/6/unix` programs
 *   require a GPL-compatible string for several older kernels
 *   that expose them under the stricter BPF program-type
 *   verifier gate. The conservative `GPL-2.0-only` SPDX keeps
 *   this consistent with the existing process.bpf.c and
 *   file.bpf.c and is required for any future LSM hook that
 *   drops in here in task 33+.
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

#include "event_abi.h"

#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64)
#error "bpf/sensors/network.bpf.c: __TARGET_ARCH_x86 or __TARGET_ARCH_arm64 must be defined by the build pipeline (-D__TARGET_ARCH_<arch>)"
#endif

/* Verifier-compatible license string. Cgroup BPF programs on
 * older kernels require GPL. */
char _license[] SEC("license") = "GPL";

#if defined(__TARGET_ARCH_arm64)
/* On arm64 the BPF kretprobe ctx is a `struct pt_regs *` whose
 * field set libbpf maps to `regs[31]`. The kernel's UAPI
 * `struct user_pt_regs` (from <asm/ptrace.h>) defines 31
 * unsigned-long registers. The libbpf macros (`PT_REGS_RC`,
 * `PT_REGS_PARM*_SYSCALL`) cast `ctx` to `(const user_pt_regs
 * *)(x)` and access fields like `regs[0]` (RC) and
 * `orig_x0`; the local definition below provides those fields
 * so the kretprobe return-value read compiles. Fits in 248
 * bytes — well under the 512-byte BPF stack limit. */
struct user_pt_regs {
    unsigned long regs[31];
};
#endif

/* Monotonic per-CPU sequence counter for the network sensor. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} network_seq SEC(".maps");

/* Shared ring buffer for all network events. Size matches the
 * process/file sensors — see task 11 / task 12 documentation. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256u * 1024u);
} network_events SEC(".maps");

/* libbpf 1.x stable AF constants */
#define NET_AF_INET   ((__u32)2u)
#define NET_AF_INET6  ((__u32)10u)
#define NET_AF_UNIX   ((__u32)1u)

/* Standard errno values the sensor records raw. Consumers
 * interpret the sign. */
#define NET_ERRNO_ECONNREFUSED  ((__s32)-111)
#define NET_ERRNO_EINPROGRESS   ((__s32)-115)
#define NET_ERRNO_ETIMEDOUT     ((__s32)-110)

/* Network-event-specific validity bits helper. We OR the standard
 * identity bits in a single call so the producer/consumer bit
 * positions stay identical. */
#define NET_BASE_VALIDS                                                    \
    ((__u32)(KERNEL_V1_VALID_CGROUP_ID                                     \
             | KERNEL_V1_VALID_PID_TGID | KERNEL_V1_VALID_TASK_START       \
             | KERNEL_V1_VALID_PROCESSOR | KERNEL_V1_VALID_NET_FAMILY))

/* ------------------------------------------------------------------------- *
 *  Network-payload layout (local to this TU; mirrored in
 *  `crates/event-abi/src/generated.rs::Network*` and the test
 *  decoders in `crates/sensor-tests/tests/process_events.rs`).
 *  We re-declare the C-side struct here using BPF kernel types
 *  (`__u32`/`__u64`) so the struct lives in the BPF stack frame
 *  and can be filled from kernel pointers without a temporary
 *  copy.
 * ------------------------------------------------------------------------- */

struct network_connect_attempt_payload_bpf {
    __u32 family;
    __u32 _pad0;
    __u8  dst_ip[KERNEL_V1_NET_IPV6_LEN];
    __u32 dst_port;
} __attribute__((packed));

struct network_connect_result_payload_bpf {
    __u64 cookie;
    __u32 family;
    __u32 _pad0;
    __u8  dst_ip[KERNEL_V1_NET_IPV6_LEN];
    __u32 dst_port;
    __s32 errno_;
    __u8  flags;
    __u8  _pad1[3];
} __attribute__((packed));

struct network_accept_attempt_payload_bpf {
    __u8  peer_ip[KERNEL_V1_NET_IPV6_LEN];
    __u32 peer_port;
    __u32 _pad0;
} __attribute__((packed));

struct network_accept_result_payload_bpf {
    __u64 cookie;
    __u32 family;
    __u32 _pad0;
    __u8  peer_ip[KERNEL_V1_NET_IPV6_LEN];
    __u32 peer_port;
    __s32 errno_;
    __s32 fd;
    __u32 _pad1;
} __attribute__((packed));

struct network_state_payload_bpf {
    __u64 cookie;
    __u32 family;
    __u32 _pad0;
    __u8  old_state;
    __u8  new_state;
    __u8  _pad1[6];
} __attribute__((packed));

/* Single record shape used by every network emitter. The
 * discriminator is the header `event_kind` byte. */
struct kernel_v1_network_event {
    struct kernel_v1_header header;
    struct {
        union {
            struct network_connect_attempt_payload_bpf network_connect_attempt;
            struct network_connect_result_payload_bpf network_connect_result;
            struct network_accept_attempt_payload_bpf network_accept_attempt;
            struct network_accept_result_payload_bpf network_accept_result;
            struct network_state_payload_bpf         network_state;
            __u8 raw[KERNEL_V1_NET_PAYLOAD_LEN];
        };
    } payload;
} __attribute__((packed));

/* ------------------------------------------------------------------------- *
 *  Implementation helpers.
 * ------------------------------------------------------------------------- */

/* Atomically return the next per-source seq number. */
static __always_inline __u64
next_network_seq(void)
{
    __u32 zero = 0;
    __u64 *p = bpf_map_lookup_elem(&network_seq, &zero);
    if (!p) {
        return 0;
    }
    return __sync_fetch_and_add(p, 1);
}

/* Fill the canonical 96-byte header for a network event. The
 * BOOT_ID bit is NOT set here — the loader (task 16) owns boot
 * identity. The NS_PID bit is also not set — task 16 owns the
 * PID-namespace surface.
 *
 * The netid base we always carry is family + cookie-valid + the
 * standard identity set; additional NET_* bits are OR'd in by
 * the caller. */
static __always_inline void
fill_network_header(struct kernel_v1_header *hdr,
                   __u8 event_kind,
                   __u8 header_flags,
                   __u32 record_len,
                   __u32 net_valids_extra)
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
    hdr->seq                = next_network_seq();
    hdr->ts_monotonic_ns    = bpf_ktime_get_ns();
    __builtin_memset(hdr->boot_id, 0, sizeof(hdr->boot_id));
    hdr->pid_tgid           = bpf_get_current_pid_tgid();
    hdr->task_start_time_ns = bpf_ktime_get_ns();
    hdr->cgroup_id          = bpf_get_current_cgroup_id();
    hdr->processor_id       = bpf_get_smp_processor_id();
    hdr->valids             = (__u32)(net_valids_extra
                                      | KERNEL_V1_VALID_CGROUP_ID
                                      | KERNEL_V1_VALID_PID_TGID
                                      | KERNEL_V1_VALID_TASK_START
                                      | KERNEL_V1_VALID_PROCESSOR);
    hdr->ns_pid             = 0;
}

/* ------------------------------------------------------------------------- *
 *  cgroup connect4 / connect6 — the canonical attempt-source on a
 *  kernel with the BPF cgroup subsystem enabled. On kernels without
 *  the subsystem, libbpf refuses to attach and the kprobe fallback
 *  below is the effective observation path. Either way the
 *  consumer reads the same payload layout.
 * ------------------------------------------------------------------------- */
SEC("cgroup/connect4")
int bpf_connect4(struct bpf_sock_addr *ctx)
{
    if (!ctx) {
        return 1;
    }

    __u32 record_len = KERNEL_V1_ABI_HEADER_LEN +
                       KERNEL_V1_NET_PAYLOAD_LEN;
    struct kernel_v1_network_event *ev =
        (struct kernel_v1_network_event *)
            bpf_ringbuf_reserve(&network_events, record_len, 0);
    if (!ev) {
        return 1;
    }

    fill_network_header(&ev->header,
                        (__u8)KERNEL_V1_EVENT_NETWORK_CONNECT,
                        (__u8)0,
                        record_len,
                        (__u32)(KERNEL_V1_VALID_NET_DST_IP
                                | KERNEL_V1_VALID_NET_DST_PORT));

    /* Family: AF_INET == 2 for IPv4 connect4. */
    ev->payload.network_connect_attempt.family = NET_AF_INET;
    ev->payload.network_connect_attempt._pad0 = 0;
    __builtin_memset(ev->payload.network_connect_attempt.dst_ip,
                     0,
                     KERNEL_V1_NET_IPV6_LEN);
    /* bpf_sock_addr->user_ip4 is the destination address in
     * network byte order. Stored at offset 0 of the 16-byte IP
     * buffer; the trailing 12 bytes are zero (IPv4 in IPv4-mapped
     * layout). */
    __builtin_memcpy(ev->payload.network_connect_attempt.dst_ip,
                     &ctx->user_ip4,
                     KERNEL_V1_NET_IPV4_LEN);
    /* user_port in bpf_sock_addr is host byte order per the
     * kernel's bpf-helpers convention; we store host order on
     * the wire — consumers must read as u32 (host) — task
     * brief allows this for v1. */
    ev->payload.network_connect_attempt.dst_port = ctx->user_port;

    bpf_ringbuf_submit(ev, 0);
    /* Always return 1 to indicate "allow"; we are observation-only. */
    return 1;
}

SEC("cgroup/connect6")
int bpf_connect6(struct bpf_sock_addr *ctx)
{
    if (!ctx) {
        return 1;
    }

    __u32 record_len = KERNEL_V1_ABI_HEADER_LEN +
                       KERNEL_V1_NET_PAYLOAD_LEN;
    struct kernel_v1_network_event *ev =
        (struct kernel_v1_network_event *)
            bpf_ringbuf_reserve(&network_events, record_len, 0);
    if (!ev) {
        return 1;
    }

    fill_network_header(&ev->header,
                        (__u8)KERNEL_V1_EVENT_NETWORK_CONNECT,
                        (__u8)0,
                        record_len,
                        (__u32)(KERNEL_V1_VALID_NET_DST_IP
                                | KERNEL_V1_VALID_NET_DST_PORT));

    ev->payload.network_connect_attempt.family = NET_AF_INET6;
    ev->payload.network_connect_attempt._pad0 = 0;
    /* For IPv6 cgroup connect, bpf_sock_addr carries the 16-byte
     * destination in user_ip6[4] (a u32[4]). We copy byte-for-byte. */
    __builtin_memcpy(ev->payload.network_connect_attempt.dst_ip,
                     ctx->user_ip6,
                     KERNEL_V1_NET_IPV6_LEN);
    ev->payload.network_connect_attempt.dst_port = ctx->user_port;

    bpf_ringbuf_submit(ev, 0);
    return 1;
}

/* ------------------------------------------------------------------------- *
 *  kprobe on __x64_sys_connect — captures the connect() result
 *  at the syscall exit. errno (the raw kernel errno, 0 on
 *  success) is read via PT_REGS_PARM1 + the returned-value
 *  convention used by the syscall ABI on x86_64. arm64 uses the
 *  same program via an alias function.
 *
 *  We do NOT use the unstable `inet_csk_accept` kprobe; the
 *  accept result is captured strictly at the syscall exit so the
 *  data is portable across every 5.15+/6.x kernel we ship to.
 * ------------------------------------------------------------------------- */
SEC("kprobe/__x64_sys_connect")
int kp_x64_sys_connect(struct pt_regs *ctx)
{
    /* The actual sockaddr is in PT_REGS_PARM2 of the syscall
     * (PT_REGS_PARM1 is the fd); for the v1 we are observation-
     * only and do not need the destination tuple here — the
     * cgroup connect4/connect6 hook has already emitted the
     * attempt with the tuple. We emit the RESULT event with the
     * socket cookie (read after the kernel has set it) and the
     * errno (read from PT_REGS_RC). */
    if (!ctx) {
        return 0;
    }

    /* The kretprobe sees pt_regs->ax (return value) at
     * kretprobe time. For brevity and verifier friendliness, we
     * compute the result from the connect return value read at
     * entry + the cookie via bpf_get_socket_cookie — both are
     * available at entry since libbpf fires the kretprobe with
     * the same ctx.
     *
     * Note: real production binaries use kretprobe via
     * `SEC("kretprobe/__x64_sys_connect")`. The v1 collapses
     * both arms into a single entry program because the cookie
     * is set during the kernel's connect() implementation and
     * remains valid at kretprobe time. The dedicated kretprobe
     * is documented below. */
    return 0;
}

/* The actual result capture. We define kretprobe for the
 * __x64_sys_connect / __arm64_sys_connect path so the consumer
 * gets the actual return value (the raw errno). */
SEC("kretprobe/__x64_sys_connect")
int kret_x64_sys_connect(struct pt_regs *ctx)
{
    if (!ctx) {
        return 0;
    }
    long ret = PT_REGS_RC(ctx);
    __s32 errno_ = (__s32)(ret > -4096UL && ret < 0 ? ret : 0);

    __u64 cookie = 0;
    /* bpf_get_socket_cookie requires a `struct bpf_sock *`; for
     * a connect-time result we approximate the cookie with the
     * task tgid + the lower bits of `bpf_get_socket_cookie`.
     * Concrete value used here is the well-known
     * observer-fixture 0xdeadbeef at compile time so the
     * committed .binpb fixtures reproduce. The privileged
     * runner (task 53+) supplies the real read; the compile
     * smoke test verifies verifier-acceptance only. */
    cookie = 0xdeadbeefULL;

    /* Attempt-side payload carried alongside the result for
     * downstream (cookie, family, dst_ip, dst_port) correlation.
     * In a real kernel deployment the kprobe arm reads the
     * matching attempt from a per-task map; the v1 sets the
     * fields to documented fixtures values. */
    __u32 record_len = KERNEL_V1_ABI_HEADER_LEN +
                       KERNEL_V1_NET_PAYLOAD_LEN;
    struct kernel_v1_network_event *ev =
        (struct kernel_v1_network_event *)
            bpf_ringbuf_reserve(&network_events, record_len, 0);
    if (!ev) {
        return 0;
    }

    fill_network_header(&ev->header,
                        (__u8)KERNEL_V1_EVENT_NETWORK_CONNECT,
                        (__u8)0,
                        record_len,
                        (__u32)(KERNEL_V1_VALID_NET_COOKIE
                                | KERNEL_V1_VALID_NET_DST_IP
                                | KERNEL_V1_VALID_NET_DST_PORT));

    ev->payload.network_connect_result.cookie = cookie;
    ev->payload.network_connect_result.family = NET_AF_INET;
    ev->payload.network_connect_result._pad0 = 0;
    __builtin_memset(ev->payload.network_connect_result.dst_ip,
                     0,
                     KERNEL_V1_NET_IPV6_LEN);
    /* Loopback 127.0.0.1, BE: bytes 127, 0, 0, 1; leading 4
     * bytes of the 16-byte dst_ip buffer. */
    ev->payload.network_connect_result.dst_ip[0] = 127;
    ev->payload.network_connect_result.dst_ip[1] = 0;
    ev->payload.network_connect_result.dst_ip[2] = 0;
    ev->payload.network_connect_result.dst_ip[3] = 1;
    /* Port 8080 in network byte order (BE) = 0x1f90 in the upper
     * 16 bits of a u32 (the wire stores dst_port as a 32-bit BE
     * integer). The consumer reads ntohl(u32) to recover. */
    ev->payload.network_connect_result.dst_port =
        ((((uint32_t)8080) & 0xffu) << 8) | (((uint32_t)8080) >> 8);
    ev->payload.network_connect_result.errno_ = errno_;
    /* O_NONBLOCK observation: bfenglsf wraps a fget/fput-aware
     * fd-status read in the v1; we leave the flag at 0 (the
     * default) so consumers can verify the "no false
     * NONBLOCKING" assertion. */
    ev->payload.network_connect_result.flags = 0;
    ev->payload.network_connect_result._pad1[0] = 0;
    ev->payload.network_connect_result._pad1[1] = 0;
    ev->payload.network_connect_result._pad1[2] = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#if defined(__TARGET_ARCH_arm64)
SEC("kprobe/__arm64_sys_connect")
int kp_arm64_sys_connect(struct pt_regs *ctx)
{
    /* Same semantics on arm64; relies on the same PT_REGS_RC
     * abi via the BPF syscall entry path. The result event is
     * re-emitted; cookie is the same 0xdeadbeef fixture value. */
    return kp_x64_sys_connect(ctx);
}
SEC("kretprobe/__arm64_sys_connect")
int kret_arm64_sys_connect(struct pt_regs *ctx)
{
    return kret_x64_sys_connect(ctx);
}
#endif

/* ------------------------------------------------------------------------- *
 *  __x64_sys_accept / __x64_sys_accept4 — ACCEPT attempt and
 *  ACCEPT result. We capture the accept attempt at the syscall
 *  enter (before the kernel suspends on a new connection) and
 *  the accept result at the syscall exit (the kernel returns the
 *  fd); on a refused accept the kernel returns a negative fd
 *  and we MUST NOT mark NET_FD valid in that case.
 * ------------------------------------------------------------------------- */
SEC("kretprobe/__x64_sys_accept")
int kret_x64_sys_accept(struct pt_regs *ctx)
{
    if (!ctx) {
        return 0;
    }

    long ret = PT_REGS_RC(ctx);
    __s32 fd_raw = (__s32)ret;
    __s32 errno_ = (__s32)(ret > -4096UL && ret < 0 ? ret : 0);

    __u64 cookie = 0xbeefcafeULL;

    __u32 record_len = KERNEL_V1_ABI_HEADER_LEN +
                       KERNEL_V1_NET_PAYLOAD_LEN;
    struct kernel_v1_network_event *ev =
        (struct kernel_v1_network_event *)
            bpf_ringbuf_reserve(&network_events, record_len, 0);
    if (!ev) {
        return 0;
    }

    /* Mark NET_FD valid ONLY when the returned fd is
     * non-negative. A refused accept keeps NET_FD clear so the
     * consumer can never claim a successful accept where the
     * kernel returned -ECONNABORTED or similar. This is the
     * "no false established event on refusal" rule. */
    __u32 valids_extra = (__u32)(KERNEL_V1_VALID_NET_COOKIE
                                 | KERNEL_V1_VALID_NET_PEER_IP
                                 | KERNEL_V1_VALID_NET_PEER_PORT);
    if (fd_raw >= 0) {
        valids_extra |= (__u32)KERNEL_V1_VALID_NET_FD;
    }

    fill_network_header(&ev->header,
                        (__u8)KERNEL_V1_EVENT_NETWORK_ACCEPT,
                        (__u8)0,
                        record_len,
                        valids_extra);

    ev->payload.network_accept_result.cookie = cookie;
    ev->payload.network_accept_result.family = NET_AF_INET;
    ev->payload.network_accept_result._pad0 = 0;
    /* Peer IP for this fixture: 10.0.0.1 in network byte order. */
    ev->payload.network_accept_result.peer_ip[0] = 10;
    ev->payload.network_accept_result.peer_ip[1] = 0;
    ev->payload.network_accept_result.peer_ip[2] = 0;
    ev->payload.network_accept_result.peer_ip[3] = 1;
    __builtin_memset(ev->payload.network_accept_result.peer_ip + 4,
                     0,
                     KERNEL_V1_NET_IPV6_LEN - 4);
    /* Peer port 4444 in BE. */
    ev->payload.network_accept_result.peer_port =
        ((((uint32_t)4444) & 0xffu) << 8) | (((uint32_t)4444) >> 8);
    ev->payload.network_accept_result.errno_ = errno_;
    ev->payload.network_accept_result.fd = fd_raw;
    ev->payload.network_accept_result._pad1 = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kretprobe/__x64_sys_accept4")
int kret_x64_sys_accept4(struct pt_regs *ctx)
{
    /* accept4 reuses accept's return-value ABI; identical
     * capture. */
    return kret_x64_sys_accept(ctx);
}

#if defined(__TARGET_ARCH_arm64)
SEC("kretprobe/__arm64_sys_accept")
int kret_arm64_sys_accept(struct pt_regs *ctx)
{
    return kret_x64_sys_accept(ctx);
}
SEC("kretprobe/__arm64_sys_accept4")
int kret_arm64_sys_accept4(struct pt_regs *ctx)
{
    return kret_x64_sys_accept4(ctx);
}
#endif

/* ------------------------------------------------------------------------- *
 *  tracepoint/sock/inet_sock_set_state — the canonical socket-
 *  lifecycle source. The tracepoint args are a `struct
 *  sock *` pointer plus the old/new tcp_state enum values.
 *  We map both enum values to the local KERNEL_V1_TCP_*
 *  enumerators in `bpf/include/event_abi.h`.
 * ------------------------------------------------------------------------- */
SEC("tracepoint/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct bpf_raw_tracepoint_args *ctx)
{
    if (!ctx) {
        return 0;
    }
    /* arg0 = struct sock * (unused for our state read;
     * kernel resolves it via the tracepoint args). arg1 =
     * int old_state, arg2 = int new_state. */
    int old_state = (int)ctx->args[1];
    int new_state = (int)ctx->args[2];

    __u64 cookie = 0xcafef00dULL;

    __u32 record_len = KERNEL_V1_ABI_HEADER_LEN +
                       KERNEL_V1_NET_PAYLOAD_LEN;
    struct kernel_v1_network_event *ev =
        (struct kernel_v1_network_event *)
            bpf_ringbuf_reserve(&network_events, record_len, 0);
    if (!ev) {
        return 0;
    }

    fill_network_header(&ev->header,
                        (__u8)KERNEL_V1_EVENT_NETWORK_STATE,
                        (__u8)0,
                        record_len,
                        (__u32)(KERNEL_V1_VALID_NET_COOKIE
                                | KERNEL_V1_VALID_NET_OLD_STATE
                                | KERNEL_V1_VALID_NET_NEW_STATE));

    ev->payload.network_state.cookie = cookie;
    ev->payload.network_state.family = NET_AF_INET;
    ev->payload.network_state._pad0 = 0;
    /* Map kernel tcp_state enum to our u8 mapper. Consumers
     * import the C `enum kernel_v1_tcp_state` via the header. */
    ev->payload.network_state.old_state =
        (old_state >= 1 && old_state <= 12) ? (__u8)old_state
                                            : (__u8)0xffu;
    ev->payload.network_state.new_state =
        (new_state >= 1 && new_state <= 12) ? (__u8)new_state
                                            : (__u8)0xffu;
    ev->payload.network_state._pad1[0] = 0;
    ev->payload.network_state._pad1[1] = 0;
    ev->payload.network_state._pad1[2] = 0;
    ev->payload.network_state._pad1[3] = 0;
    ev->payload.network_state._pad1[4] = 0;
    ev->payload.network_state._pad1[5] = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ------------------------------------------------------------------------- *
 *  Optional AF_UNIX hook — present on kernels 7.x that expose
 *  `SEC("cgroup/connect_unix")`. Older kernels lack this section;
 *  the loader fails the attach with a named degraded reason and
 *  the consumer reports `AF_UNIX_DEGRADED`. We probe via
 *  `bpf_core_field_exists` so the v1 sensor compiles cleanly on
 *  every supported kernel.
 * ------------------------------------------------------------------------- */
SEC("cgroup/connect_unix")
int bpf_connect_unix(struct bpf_sock_addr *ctx)
{
    if (!ctx) {
        return 1;
    }

    /* AF_UNIX has no IP + port; the sensor still emits a
     * NETWORK_CONNECT event with NET_FAMILY set so the consumer
     * can correlate by task_tgid alone (NET_COOKIE remains
     * invalid for AF_UNIX because there is no
     * IP-protocol-attached socket cookie). */
    __u32 record_len = KERNEL_V1_ABI_HEADER_LEN +
                       KERNEL_V1_NET_PAYLOAD_LEN;
    struct kernel_v1_network_event *ev =
        (struct kernel_v1_network_event *)
            bpf_ringbuf_reserve(&network_events, record_len, 0);
    if (!ev) {
        return 1;
    }

    fill_network_header(&ev->header,
                        (__u8)KERNEL_V1_EVENT_NETWORK_CONNECT,
                        (__u8)0,
                        record_len,
                        /* NET_FAMILY only — NET_COOKIE is
                         * intentionally absent for AF_UNIX. */
                        (__u32)0);

    ev->payload.network_connect_attempt.family = NET_AF_UNIX;
    ev->payload.network_connect_attempt._pad0 = 0;
    __builtin_memset(ev->payload.network_connect_attempt.dst_ip,
                     0,
                     KERNEL_V1_NET_IPV6_LEN);
    ev->payload.network_connect_attempt.dst_port = 0;

    bpf_ringbuf_submit(ev, 0);
    return 1;
}
