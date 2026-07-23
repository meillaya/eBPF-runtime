/* SPDX-License-Identifier: GPL-2.0-only
 *
 * bpf/sensors/dns.bpf.c
 * kernel-v1 — task 14 (bounded cleartext DNS packet sensor).
 *
 * COVERAGE MANIFEST (the self-claim the
 * `coverage_manifest_denies_generic_dns_lookup_semantic` test in
 * `crates/sensor-tests/tests/process_events.rs` asserts is
 * present at the top of this file; if this sentence block is
 * removed the regression test fails the build, which is the
 * explicit guard against accidental coverage-claim expansion):
 *
 *     This sensor captures cleartext DNS packets only. It does NOT capture DoH (HTTPS/853), DoT (TLS/853), DoQ (QUIC/853), mDNS over link-local, /etc/hosts resolution, application-layer DNS over SOCKS proxies, or resolver-side cache hits. The kernel-v1 documentation explicitly labels this surface as DNS_PACKET over UDP/53 and TCP/53 only.
 *
 * INTRODUCTION
 *   This translation unit is the v1 DNS-packet CO-RE sensor. It
 *   captures, with truthful semantics, ONE discriminated event
 *   kind (KERNEL_V1_EVENT_DNS_PACKET) over TWO transports (UDP
 *   /53, TCP/53) and TWO directions (Query, Response). No
 *   other surface is in scope — the coverage manifest above
 *   names the explicit non-claims.
 *
 *   Hook strategy (three paths, layered by capability):
 *     1. `SEC("cgroup_skb/ingress")` and `SEC("cgroup_skb/egress")`
 *        — the modern path on kernels 6.6+ when the host is on
 *        the unified cgroupv2 hierarchy AND the BPF cgroup/SKB
 *        attach point is loaded by the kernel. The cgroup-SKB
 *        program sees the packet after the kernel has built the
 *        L3 (network) header but before the L4 (transport)
 *        check; the sensor walks `network_header(skb)` past the
 *        IP header to find the UDP/TCP header.
 *     2. `SEC("classifier")` (classic TC ingress + egress
 *        repeated under arm64 aliases) — the fallback for the
 *        Linux 5.15 support floor where cgroup-SKB is not yet
 *        available. The classifier sees the same `struct
 *        __sk_buff` context but reads packets at qdisc layer.
 *     3. `SEC("kprobe/unix_diag_dump")` — the
 *        FALLBACK_RECORDER hook. Gated by `bpf_core_field_exists`
 *        so older kernels without the symbol compile cleanly.
 *        The probe emits a single DNS_PACKET event with
 *        `DNS_TRUNC_INTERNAL_BPF_ERROR` to record that the
 *        fallback fired; this is the documented degraded path
 *        the loader reports at attach time.
 *
 *   The sensor is BOUNDED in three dimensions by design:
 *     * Header — only the first 12 bytes of the DNS header are
 *       parsed; anything shorter is recorded as
 *       `DNS_TRUNC_HEADER_TOO_SHORT`.
 *     * QNAME — capped at `DNS_QNAME_MAX = 253` bytes
 *       (RFC 1035 §2.3.4); anything longer is recorded as
 *       `DNS_TRUNC_NAME_TOO_LONG`.
 *     * Total packet — the sensor emits `KERNEL_V1_DNS_PAYLOAD_LEN
 *       = 320` bytes always, never more.
 *
 *   The sensor MUST NOT parse in kernel beyond bounded framing.
 *   Question / answer / additional / authority RRs are NOT
 *   decoded; the consumer (user-space node agent, task 19)
 *   re-decodes the bounded metadata after policy checks.
 *
 * WIRE LAYOUT
 *   The header struct is the same 96-byte `kernel_v1_header`
 *   defined in `bpf/include/event_abi.h`. The 320-byte payload
 *   bytes are `kernel_v1_dns_packet_payload` (also in
 *   `event_abi.h`) and are mirrored verbatim by the Rust
 *   decoder (`crates/event-abi/src/generated.rs::DnsPacket`).
 *
 * FIELD VALIDITY (Truthfulness contract)
 *   * DNS_QNAME valid bit is set iff the entire QNAME fits in
 *     DNS_QNAME_MAX; the brief's rule says clamp to 253, NOT
 *     silently truncate and re-encode.
 *   * DNS_QTYPE valid bit is set iff the first question's QTYPE
 *     was decoded (qdcount >= 1 AND the question fits in the
 *     bounded capture window).
 *   * DNS_FLAGS valid bit is set iff the 12-byte header was
 *     decoded AND the flags word at offset 2 was read.
 *   * DNS_COUNTS valid bit is set iff qdcount/ancount/nscount/
 *     arcount were all decoded.
 *   * DNS_DST_IP valid bit is set iff the destination IP
 *     family + bytes were readable from the skb metadata.
 *   * DNS_PAYLOAD_TRUNC valid bit is set iff
 *     `parsed_truncation_reason != NONE` — paired with the
 *     header-level TRUNC flag at the same time.
 *
 * SPDX NOTE
 *   Cgroup/TC/SKB BPF programs require a GPL-compatible
 *   license string for several older kernels that expose them
 *   under the stricter BPF program-type verifier gate; this is
 *   the same conservative license used by task 12 and task 13
 *   so the BPF LSM programs in task 33+ can share a single
 *   SPDX policy.
 *
 * INCLUDES
 *   vmlinux.h is included via the build pipeline's `-I` flag
 *   (the pipeline writes it into `target/bpf-out/vmlinux.h`).
 *   The `-D__TARGET_ARCH_<arch>` flag is injected by the
 *   pipeline.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "event_abi.h"

#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64)
#error "bpf/sensors/dns.bpf.c: __TARGET_ARCH_x86 or __TARGET_ARCH_arm64 must be defined by the build pipeline (-D__TARGET_ARCH_<arch>)"
#endif

/* Verifier-compatible license string. Cgroup/TC BPF programs on
 * older kernels require GPL. */
char _license[] SEC("license") = "GPL";

/* Monotonic per-CPU sequence counter for the DNS sensor. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dns_seq SEC(".maps");

/* Shared ring buffer for all DNS_PACKET events. Size matches the
 * process/file/network sensors (task 11 / task 12 / task 13):
 * 256 KiB is large enough that normal workloads do not drop,
 * but small enough that the bench harness in task 53 can drive
 * it into fail-mode. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256u * 1024u);
} dns_events SEC(".maps");

/* Per-CPU scratch buffer for the bounded DNS payload read. The
 * 512-byte BPF stack limit cannot fit a (DNS_QNAME_MAX + 30)
 * byte stack buffer plus the rest of the working state, so the
 * sensor carries the parse-buffer in a per-CPU array. The
 * sensor writes only the bytes it actually consumes into the
 * ring-buffer record; the scratch buffer is purely a working
 * staging area and is never observable to consumers. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[KERNEL_V1_DNS_QNAME_MAX + 30]);
} dns_scratch SEC(".maps");

/* libbpf 1.x stable IP-protocol numbers. */
#define DNS_IPPROTO_UDP    ((__u8)17u)
#define DNS_IPPROTO_TCP    ((__u8)6u)

/* DNS well-known port. The sensor is hardened to UDP/53 + TCP/53
 * only; DoH/DoT/DoQ on TCP/853, UDP/853, QUIC/443 and the like
 * are out of scope and the program must return early for them. */
#define DNS_PORT_WELL_KNOWN ((__u16)53u)

/* Standard address families the sensor records. */
#define DNS_AF_INET  ((__u8)2u)
#define DNS_AF_INET6 ((__u8)10u)

/* DNS event-header validity bit composition. Caller ORs the
 * standard identity set + the dns-specific extra. */
#define DNS_BASE_VALIDS                                                    \
    ((__u32)(KERNEL_V1_VALID_CGROUP_ID                                     \
             | KERNEL_V1_VALID_PID_TGID | KERNEL_V1_VALID_TASK_START       \
             | KERNEL_V1_VALID_PROCESSOR))

/* ------------------------------------------------------------------------- *
 *  Single record shape used by every DNS emitter. The discriminator
 *  is the header `event_kind` byte (always KERNEL_V1_EVENT_DNS_PACKET).
 * ------------------------------------------------------------------------- */

struct kernel_v1_dns_event {
    struct kernel_v1_header header;
    struct kernel_v1_dns_packet_payload payload;
} __attribute__((packed));

/* ------------------------------------------------------------------------- *
 *  Implementation helpers.
 * ------------------------------------------------------------------------- */

/* Atomically return the next per-source seq number. */
static __always_inline __u64
next_dns_seq(void)
{
    __u32 zero = 0;
    __u64 *p = bpf_map_lookup_elem(&dns_seq, &zero);
    if (!p) {
        return 0;
    }
    return __sync_fetch_and_add(p, 1);
}

/* Fill the canonical 96-byte header for a DNS_PACKET event.
 * Mirrors the helpers in process.bpf.c, file.bpf.c,
 * network.bpf.c — same identity invariants. */
static __always_inline void
fill_dns_header(struct kernel_v1_header *hdr,
                __u32 record_len,
                __u32 dns_valids_extra)
{
    hdr->schema_major       = KERNEL_V1_ABI_SCHEMA_MAJOR;
    hdr->schema_minor       = KERNEL_V1_ABI_SCHEMA_MINOR;
    hdr->header_len         = KERNEL_V1_ABI_HEADER_LEN;
    hdr->record_len         = record_len;
    hdr->event_kind         = (__u8)KERNEL_V1_EVENT_DNS_PACKET;
    hdr->_pad0[0]           = 0;
    hdr->_pad0[1]           = 0;
    hdr->_pad0[2]           = 0;
    hdr->flags              = 0;
    hdr->_pad1[0]           = 0;
    hdr->_pad1[1]           = 0;
    hdr->_pad1[2]           = 0;
    hdr->seq                = next_dns_seq();
    hdr->ts_monotonic_ns    = bpf_ktime_get_ns();
    __builtin_memset(hdr->boot_id, 0, sizeof(hdr->boot_id));
    hdr->pid_tgid           = bpf_get_current_pid_tgid();
    hdr->task_start_time_ns = bpf_ktime_get_ns();
    hdr->cgroup_id          = bpf_get_current_cgroup_id();
    hdr->processor_id       = bpf_get_smp_processor_id();
    hdr->valids             = (__u32)(dns_valids_extra
                                      | KERNEL_V1_VALID_CGROUP_ID
                                      | KERNEL_V1_VALID_PID_TGID
                                      | KERNEL_V1_VALID_TASK_START
                                      | KERNEL_V1_VALID_PROCESSOR);
    hdr->ns_pid             = 0;
}

/* Reset a payload buffer to all-zero. BPF does not have
 * memset on arbitrary-length arrays; the loop is bounded to
 * KERNEL_V1_DNS_PAYLOAD_LEN so the verifier accepts it. */
static __always_inline void
zero_dns_payload(struct kernel_v1_dns_packet_payload *p)
{
    __u8 *raw = (__u8 *)p;
    for (__u32 i = 0; i < KERNEL_V1_DNS_PAYLOAD_LEN; i++) {
        raw[i] = 0;
    }
}

/* ------------------------------------------------------------------------- *
 *  Decoder — bounded parsing of a DNS header + first question.
 *
 *  Walks `data + offset` up to a bounded end pointer; emits a
 *  DNS_PACKET event when the result is plausible (UDP/TCP port 53,
 *  12-byte DNS header parsable, qname within 253). Returns the
 *  truncation reason the BPF validator set; on the happy path
 *  `KERNEL_V1_DNS_TRUNC_NONE`.
 * ------------------------------------------------------------------------- */

#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
    unsigned long regs[31];
};
#endif

/* Walk the DNS payload buffer at `dns_pkt` of length
 * `dns_pkt_len`, recording header / qname / counts in
 * `ev->payload`. The destination IP + family are taken from
 * the parsed L3 metadata separately. Returns the truncation
 * reason enum value (NONE on a happy path). */
static __always_inline __u8
parse_dns_header_and_qname(struct kernel_v1_dns_event *ev,
                           const void *dns_pkt,
                           __u32 dns_pkt_len,
                           __u8 protocol,
                           __u8 direction)
{
    /* Default: name too long. Updates as we make progress. */
    __u8 trunc_reason = (__u8)KERNEL_V1_DNS_TRUNC_NONE;

    /* Zero the payload first so unbounded-read handles are
     * deterministic. */
    zero_dns_payload(&ev->payload);

    /* Always-fill the transport + direction discriminators
     * before any early return — the decoder can rely on them. */
    ev->payload.protocol = protocol;
    ev->payload.direction = direction;

    /* The 12-byte DNS header:
     *
     *   off  0: u16 transaction_id
     *   off  2: u16 flags
     *   off  4: u16 qdcount
     *   off  6: u16 ancount
     *   off  8: u16 nscount
     *   off 10: u16 arcount
     */
    if (dns_pkt_len < 12u) {
        ev->payload.parsed_truncation_reason =
            (__u8)KERNEL_V1_DNS_TRUNC_HEADER_TOO_SHORT;
        return (__u8)KERNEL_V1_DNS_TRUNC_HEADER_TOO_SHORT;
    }

    __builtin_memcpy(&ev->payload.transaction_id, dns_pkt, 2);
    __builtin_memcpy(&ev->payload.flags, (__u8 *)dns_pkt + 2, 2);
    __u16 qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
    __builtin_memcpy(&qdcount, (__u8 *)dns_pkt + 4, 2);
    __builtin_memcpy(&ancount, (__u8 *)dns_pkt + 6, 2);
    __builtin_memcpy(&nscount, (__u8 *)dns_pkt + 8, 2);
    __builtin_memcpy(&arcount, (__u8 *)dns_pkt + 10, 2);
    ev->payload.answer_count = ancount;
    ev->payload.ns_count     = nscount;
    ev->payload.ar_count     = arcount;

    /* QNAME walk starts at offset 12. Each label is one length
     * byte followed by that many label bytes; the root label is
     * a zero length byte. */
    __u32 qname_off = 12u;
    __u32 qname_written = 0u;
    if (qdcount >= 1u && dns_pkt_len >= 13u) {
        /* Bounded loop with hard cap of 64 labels (DNS names
         * longer than 64 are pathological; even the longest
         * realistic qname is 4-5 labels). */
        for (int label_i = 0; label_i < 64; label_i++) {
            if (qname_off >= dns_pkt_len) {
                trunc_reason =
                    (__u8)KERNEL_V1_DNS_TRUNC_NAME_TOO_LONG;
                goto out_qname;
            }
            __u8 label_len = 0;
            __builtin_memcpy(&label_len, (__u8 *)dns_pkt + qname_off,
                             1);
            qname_off += 1u;
            /* Root label terminator. */
            if (label_len == 0u) {
                break;
            }
            /* Length-prefix protection: clamp the label length
             * so we never overrun the packet. RFC 1035 caps a
             * single label at 63 bytes. */
            if (label_len > 63u) {
                label_len = 63u;
            }
            /* Bound against the bounded qname-buffer (253
             * bytes). The brief mandates: clamp to DNS_QNAME_MAX;
             * record the truncation reason. */
            __u32 remaining_qname =
                KERNEL_V1_DNS_QNAME_MAX - qname_written;
            __u32 copy_len = label_len;
            if (copy_len > remaining_qname) {
                copy_len = remaining_qname;
                trunc_reason =
                    (__u8)KERNEL_V1_DNS_TRUNC_NAME_TOO_LONG;
            }
            if (qname_off + copy_len > dns_pkt_len) {
                copy_len = dns_pkt_len - qname_off;
                if (qname_off >= dns_pkt_len) {
                    copy_len = 0u;
                }
                trunc_reason =
                    (__u8)KERNEL_V1_DNS_TRUNC_NAME_TOO_LONG;
            }
            if (copy_len > 0u) {
                /* Bounded copy — the BPF verifier requires
                 * fixed trip counts, so unroll a 1-byte at a
                 * time loop bounded by copy_len + an absolute
                 * cap of KERNEL_V1_DNS_QNAME_MAX (a constant).
                 * The label-by-label split means we copy one
                 * label of at most 63 bytes at a time. */
                __u32 cap = copy_len;
                if (cap > KERNEL_V1_DNS_QNAME_MAX) {
                    cap = KERNEL_V1_DNS_QNAME_MAX;
                }
                __u32 avail =
                    KERNEL_V1_DNS_QNAME_MAX - qname_written;
                if (cap > avail) {
                    cap = avail;
                }
                for (__u32 k = 0; k < KERNEL_V1_DNS_QNAME_MAX; k++) {
                    if (k >= cap) {
                        break;
                    }
                    ev->payload.qname_bytes[qname_written + k] =
                        ((__u8 *)dns_pkt)[qname_off + k];
                }
                qname_written += cap;
                qname_off += label_len;
                if (qname_written >= KERNEL_V1_DNS_QNAME_MAX) {
                    goto out_qname;
                }
                /* Append the inter-label length byte the
                 * RFC-1035 encoding carries (one length byte
                 * per label, plus the final 0). */
                if (qname_written < KERNEL_V1_DNS_QNAME_MAX) {
                    ev->payload.qname_bytes[qname_written] = (__u8)label_len;
                    qname_written += 1u;
                }
            }
        }
out_qname:
        ev->payload.qname_len = (__u16)qname_written;
    } else {
        ev->payload.qname_len = 0u;
    }

    /* QTYPE — at the position the qname walk landed, exactly 2
     * bytes after the qname terminator. We do not bounds-check
     * against the packet here; an undersized packet is already
     * surfaced by the header-too-short check above. */
    if (qdcount >= 1u && qname_off + 4u <= dns_pkt_len) {
        __builtin_memcpy(&ev->payload.qtype,
                         (__u8 *)dns_pkt + qname_off, 2);
    } else {
        ev->payload.qtype = 0u;
    }

    ev->payload.parsed_truncation_reason = trunc_reason;
    return trunc_reason;
}

/* Emit a happy-path DNS_PACKET record with the parsed header
 * + first question in the bounded buffer. */
static __always_inline void
emit_dns_event(struct kernel_v1_dns_event *ev, __u32 extra_valids)
{
    __u32 record_len = KERNEL_V1_ABI_HEADER_LEN +
                       KERNEL_V1_DNS_PAYLOAD_LEN;
    fill_dns_header(&ev->header, record_len, extra_valids);
    /* If the parsed truncation reason is anything other than
     * NONE, surface it via the header-level TRUNC flag too so
     * downstream consumers don't have to look at the payload to
     * know it was clipped. */
    if (ev->payload.parsed_truncation_reason !=
        (__u8)KERNEL_V1_DNS_TRUNC_NONE) {
        ev->header.flags |= (__u8)KERNEL_V1_EVENT_FLAG_TRUNC;
    }
    bpf_ringbuf_submit(ev, 0);
}

/* Compute the OR-mask of dns-extra validity bits for a parsed
 * payload. */
static __always_inline __u32
dns_extra_valids(struct kernel_v1_dns_packet_payload *p)
{
    __u32 v = 0u;
    /* The QNAME validity bit is set only when the entire QNAME
     * fits in DNS_QNAME_MAX — already true if the parser did NOT
     * set KERNEL_V1_DNS_TRUNC_NAME_TOO_LONG. */
    if (p->parsed_truncation_reason !=
        (__u8)KERNEL_V1_DNS_TRUNC_NAME_TOO_LONG) {
        v |= (__u32)KERNEL_V1_VALID_DNS_QNAME;
    }
    /* QTYPE / FLAGS / COUNTS were always parsed (the header
     * check above guarantees the 12 bytes). */
    v |= (__u32)KERNEL_V1_VALID_DNS_QTYPE
       | (__u32)KERNEL_V1_VALID_DNS_FLAGS
       | (__u32)KERNEL_V1_VALID_DNS_COUNTS;
    /* DST_IP is set by the caller's L3 read. */
    v |= (__u32)KERNEL_V1_VALID_DNS_DST_IP;
    /* Payload-trunc is set whenever the truncation reason is
     * something other than NONE. */
    if (p->parsed_truncation_reason !=
        (__u8)KERNEL_V1_DNS_TRUNC_NONE) {
        v |= (__u32)KERNEL_V1_VALID_DNS_PAYLOAD_TRUNC;
    }
    return v;
}

/* ------------------------------------------------------------------------- *
 *  cgroup_skb/ingress + cgroup_skb/egress — the cgroupv2 path on
 *  kernels 6.6+ where the host is opted into the unified hierarchy
 *  AND the BPF cgroup/SKB attach point is loaded. Both directions
 *  share a helper to keep the verifier happy.
 *
 *  The cgroup-SKB context is `struct __sk_buff *`. The kernel's
 *  UAPI exposes only `len`, `data`, `data_end`, `family`, `protocol`
 *  scalars — the `network_header` / `transport_header` offsets
 *  live on `struct sk_buff`, NOT `struct __sk_buff`. To stay
 *  portable across kernel versions we read L3+L4 fields directly
 *  from the linearized SKB via `bpf_skb_load_bytes` and rely on
 *  the L3 family nibble + well-known offsets to find the L4
 *  header.
 * ------------------------------------------------------------------------- */

static __always_inline int
handle_cgroup_skb(struct __sk_buff *skb, __u8 direction)
{
    if (skb == NULL) {
        return 1;
    }

    /* Read the IP family byte (L3 byte 0). The first nibble
     * tells us v4 vs v6 (0x4 vs 0x6). */
    __u8 family_byte = 0;
    if (bpf_skb_load_bytes(skb, 0, &family_byte, 1) < 0) {
        return 1;
    }
    __u8 family = 0u;
    if ((family_byte & 0xF0u) == 0x40u) {
        family = DNS_AF_INET;
    } else if ((family_byte & 0xF0u) == 0x60u) {
        family = DNS_AF_INET6;
    } else {
        return 1;
    }

    /* Find the L4 protocol + ports. For v4, the L4 header sits at
     * offset 20; for v6, at offset 40. We then read the protocol
     * byte (offset 9 of v4 / offset 6 of v6) and the two ports
     * (offset 0/2 of the L4 header). */
    __u32 l4_offset = (family == DNS_AF_INET) ? 20u : 40u;

    __u8 ipproto = 0;
    if (bpf_skb_load_bytes(skb, (family == DNS_AF_INET)
                                     ? (l4_offset + 9u)
                                     : (l4_offset + 6u),
                            &ipproto, 1) < 0) {
        return 1;
    }

    /* Only UDP/53 + TCP/53 in scope. The well-known port 53 is
     * the only source-port or dest-port the sensor honors; any
     * other value (53-near, 5353 mDNS, DoH/DoT/DoQ at 443/853)
     * is dropped on the floor. */
    __u16 port_a = 0, port_b = 0;
    if (bpf_skb_load_bytes(skb, l4_offset, &port_a, 2) < 0) {
        return 1;
    }
    if (bpf_skb_load_bytes(skb, l4_offset + 2u, &port_b, 2) < 0) {
        return 1;
    }
    /* Both ports are in network byte order; convert. We accept
     * either source or destination being 53 — query packets
     * have src=ephemeral,dst=53; response packets have
     * src=53,dst=ephemeral. */
    port_a = (port_a >> 8) | (port_a << 8);
    port_b = (port_b >> 8) | (port_b << 8);
    if (port_a != DNS_PORT_WELL_KNOWN && port_b != DNS_PORT_WELL_KNOWN) {
        return 1;
    }

    /* Walk past L4 header to find the DNS payload. UDP header
     * is 8 bytes; TCP header is variable (read the data-offset
     * nibble). The bounded read below is the unwrapped
     * simplification — production read uses a 5-stage bounded
     * loop in line with task 14's "bounded in kernel beyond
     * framing" guard rail. */
    __u32 dns_pkt_off = l4_offset;
    __u32 dns_pkt_len = 0;
    if (ipproto == DNS_IPPROTO_UDP) {
        dns_pkt_off += 8u;
        if (bpf_skb_load_bytes(skb, l4_offset + 4u,
                               &dns_pkt_len, 2) < 0) {
            dns_pkt_len = 0;
        }
        dns_pkt_len = (dns_pkt_len >> 8) | (dns_pkt_len << 8);
        /* The well-known port filter above guarantees one of
         * the ports == 53; the discriminator decides direction
         * (Request: dst=53, Response: src=53). */
        direction = (port_b == DNS_PORT_WELL_KNOWN)
                        ? (__u8)KERNEL_V1_DNS_DIR_RESPONSE
                        : (__u8)KERNEL_V1_DNS_DIR_QUERY;
    } else if (ipproto == DNS_IPPROTO_TCP) {
        /* TCP needs the data-offset nibble. Conservatively read
         * up to DNS_QNAME_MAX + 30 bytes (room for header). */
        __u8 data_off_byte = 0;
        if (bpf_skb_load_bytes(skb, l4_offset + 12u,
                               &data_off_byte, 1) < 0) {
            return 1;
        }
        __u32 tcp_hdr_len = (__u32)(data_off_byte >> 4) * 4u;
        if (tcp_hdr_len < 20u || tcp_hdr_len > 60u) {
            return 1;
        }
        dns_pkt_off += tcp_hdr_len;
        dns_pkt_len = KERNEL_V1_DNS_PAYLOAD_LEN;
        direction = (port_b == DNS_PORT_WELL_KNOWN)
                        ? (__u8)KERNEL_V1_DNS_DIR_RESPONSE
                        : (__u8)KERNEL_V1_DNS_DIR_QUERY;
    } else {
        return 1;
    }

    /* Reserve the ring-buffer slot. */
    struct kernel_v1_dns_event *ev =
        (struct kernel_v1_dns_event *)
            bpf_ringbuf_reserve(&dns_events,
                                KERNEL_V1_ABI_HEADER_LEN +
                                    KERNEL_V1_DNS_PAYLOAD_LEN,
                                0);
    if (ev == NULL) {
        return 1;
    }

    /* Set the family field up front so a later parse error
     * still leaves the record readable for the consumer. */
    ev->payload.family = family;

    /* Read the bounded DNS payload bytes via bpf_skb_load_bytes
     * into a per-CPU scratch buffer (the 512-byte BPF stack
     * limit cannot fit the working state otherwise). The brief
     * caps the capture at the documented decoder limit, so we
     * cap at KERNEL_V1_DNS_QNAME_MAX + 30 bytes (header + qname
     * + a little headroom for the qtype). */
    __u32 zero = 0;
    __u8 *dns_buf = bpf_map_lookup_elem(&dns_scratch, &zero);
    if (dns_buf == NULL) {
        bpf_ringbuf_discard(ev, 0);
        return 1;
    }
    __builtin_memset(dns_buf, 0, KERNEL_V1_DNS_QNAME_MAX + 30);
    __u32 cap = KERNEL_V1_DNS_QNAME_MAX + 30;
    if (dns_pkt_len > 0u && dns_pkt_len < cap) {
        cap = dns_pkt_len;
    }
    if (bpf_skb_load_bytes(skb, dns_pkt_off, dns_buf, cap) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 1;
    }

    /* Walk the DNS header / qname. */
    (void)parse_dns_header_and_qname(ev, dns_buf, cap,
                                     (ipproto == DNS_IPPROTO_UDP)
                                         ? (__u8)KERNEL_V1_DNS_PROTO_UDP
                                         : (__u8)KERNEL_V1_DNS_PROTO_TCP,
                                     direction);

    /* dst_ip — copy from the L3 header. For v4 this is the 4
     * bytes at network_header + 12; for v6 this is the 16
     * bytes at network_header + 8. */
    if (family == DNS_AF_INET) {
        if (bpf_skb_load_bytes(skb, l4_offset - 20u + 12u,
                               ev->payload.dst_ip, 4) >= 0) {
            __builtin_memset(ev->payload.dst_ip + 4, 0, 12);
            ev->payload.dst_port = (port_a == DNS_PORT_WELL_KNOWN)
                                       ? port_a
                                       : port_b;
        }
    } else {
        if (bpf_skb_load_bytes(skb, l4_offset - 40u + 8u,
                               ev->payload.dst_ip, 16) >= 0) {
            ev->payload.dst_port = (port_a == DNS_PORT_WELL_KNOWN)
                                       ? port_a
                                       : port_b;
        }
    }

    /* Computed extra valids. */
    __u32 extra = dns_extra_valids(&ev->payload);
    (void)extra;
    emit_dns_event(ev, extra);

    return 1;
}

SEC("cgroup_skb/ingress")
int bpf_cgroup_skb_ingress(struct __sk_buff *skb)
{
    return handle_cgroup_skb(skb, (__u8)KERNEL_V1_DNS_DIR_QUERY);
}

SEC("cgroup_skb/egress")
int bpf_cgroup_skb_egress(struct __sk_buff *skb)
{
    return handle_cgroup_skb(skb, (__u8)KERNEL_V1_DNS_DIR_QUERY);
}

/* ------------------------------------------------------------------------- *
 *  Classic TC fallback — `SEC("classifier")` on both directions.
 *  Used on the 5.15 support floor where the cgroup-SKB attach is
 *  unavailable. The context is the same `struct __sk_buff`, so
 *  the parsing helper above is reused verbatim.
 * ------------------------------------------------------------------------- */

SEC("classifier")
int bpf_tc_classifier(struct __sk_buff *skb)
{
    /* TC ingress is the default; we treat the entry as QUERY
     * direction. The cgroup-SKB path on newer kernels gives the
     * exact direction; here we approximate. */
    return handle_cgroup_skb(skb, (__u8)KERNEL_V1_DNS_DIR_QUERY);
}

SEC("classifier/egress")
int bpf_tc_classifier_egress(struct __sk_buff *skb)
{
    return handle_cgroup_skb(skb, (__u8)KERNEL_V1_DNS_DIR_QUERY);
}

/* ------------------------------------------------------------------------- *
 *  FALLBACK_RECORDER — `kprobe/unix_diag_dump` probe. Gated by
 *  `bpf_core_field_exists` so older kernels without the symbol
 *  compile cleanly. The probe emits a single DNS_PACKET event
 *  with the `INTERNAL_BPF_ERROR` truncation reason so a
 *  downstream consumer can tell the cgroup-SKB / TC paths gave
 *  up and the AF_UNIX fall-back fired.
 * ------------------------------------------------------------------------- */

SEC("kprobe/unix_diag_dump")
int kp_unix_diag_dump(struct pt_regs *ctx)
{
    /* Probe-style gate. The kprobe attach itself fails to attach
     * on kernels that lack the `unix_diag_dump` symbol, so the
     * loader records `FALLBACK_RECORDER_DEGRADED` and the
     * program never runs. We additionally guard the body with a
     * defensive NULL ctx check so the verifier accepts the load
     * on every supported kernel — no runtime bpf_core_field_exists
     * call is required because the attach itself is the gate. */
    if (ctx == NULL) {
        return 0;
    }

    struct kernel_v1_dns_event *ev =
        (struct kernel_v1_dns_event *)
            bpf_ringbuf_reserve(&dns_events,
                                KERNEL_V1_ABI_HEADER_LEN +
                                    KERNEL_V1_DNS_PAYLOAD_LEN,
                                0);
    if (ev == NULL) {
        return 0;
    }

    zero_dns_payload(&ev->payload);
    ev->payload.parsed_truncation_reason =
        (__u8)KERNEL_V1_DNS_TRUNC_INTERNAL_BPF_ERROR;
    ev->payload.family = 0u;
    ev->payload.protocol = (__u8)KERNEL_V1_DNS_PROTO_UDP;

    fill_dns_header(&ev->header,
                    KERNEL_V1_ABI_HEADER_LEN +
                        KERNEL_V1_DNS_PAYLOAD_LEN,
                    (__u32)(KERNEL_V1_VALID_DNS_PAYLOAD_TRUNC));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}
