/* SPDX-License-Identifier: GPL-2.0-only
 *
 * sdk/examples/hello_probe.bpf.c
 * Minimal custom probe for the eBPF fleet C probe SDK.
 *
 * Attaches to the stable `sched/sched_process_exec` tracepoint (no
 * host-specific kprobe symbol) and emits one SDK event per successful exec
 * with the command name and the task start time read through CO-RE.
 *
 * The event envelope is defined in `sdk/include/fleet_probe.h`; this file
 * is compiled by the `probe` crate's unit test:
 *
 *     clang -target bpf -g -O2 -D__TARGET_ARCH_x86 \
 *           -I<vmlinux.h dir> -I<sdk/include> \
 *           -c sdk/examples/hello_probe.bpf.c \
 *           -o target/probe-sdk/tests/hello_probe.bpf.o
 *
 * The object is a diagnostic fixture, not a sensor. It is not embedded in
 * the runtime and the runtime does not decode its events yet. `fleet probe
 * verify` will be able to load it once the Lead wires the CLI.
 */

#include "fleet_probe.h"

/* Kernel-loaded BPF programs must be GPL-compatible: bpf_probe_read_kernel
 * (used by fleet_probe_submit) and any LSM program are GPL-only. */
char _license[] SEC("license") = "GPL";

/* The map name follows the `<probe>_events` convention so a future loader
 * can discover it like the sensors' `<sensor>_events` maps. */
FLEET_PROBE_RINGBUF(hello_events, FLEET_PROBE_RINGBUF_BYTES);

/* Probe-defined event kind for this example. SDK kinds are 16-bit and
 * namespaced by the probe, not by the fleet schema. */
#define HELLO_PROBE_KIND_EXEC ((__u16)1)

/* Fixed payload for kind HELLO_PROBE_KIND_EXEC. `comm` is NUL-padded by
 * bpf_get_current_comm(); the decoder should not assume NUL termination. */
struct hello_probe_exec {
    __u8 comm[FLEET_PROBE_COMM_LEN];
    __u64 task_start_ns;
};

SEC("tracepoint/sched/sched_process_exec")
int hello_probe_exec(void *ctx)
{
    struct hello_probe_exec payload = {0};
    struct task_struct *task;
    long comm_rc;

    (void)ctx;

    comm_rc = bpf_get_current_comm(&payload.comm, sizeof(payload.comm));
    if (comm_rc != 0)
        return 0;

    task = (struct task_struct *)bpf_get_current_task_btf();
    payload.task_start_ns = BPF_CORE_READ(task, start_time);

    /* payload_len is a compile-time constant (sizeof of a fixed struct), as
     * the helper requires. A tracepoint program's return value is ignored
     * by the kernel; drop the status explicitly instead of pretending the
     * event is retried. */
    (void)fleet_probe_submit(&hello_events, HELLO_PROBE_KIND_EXEC, &payload,
                             (__u32)sizeof(payload));
    return 0;
}
