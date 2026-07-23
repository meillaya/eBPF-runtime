/* SPDX-License-Identifier: (MIT OR Apache-2.0)
 *
 * bpf/sensors/placeholder.bpf.c
 * kernel-v1 — task 10 (libbpf-cargo CO-RE build pipeline)
 *
 * This translation unit exists ONLY as a compile-time smoke test for
 * the deterministic CO-RE build pipeline. It is NOT loaded into the
 * kernel by anything in this task. Tasks 11-17 replace it with real
 * sensor programs (process / file / network / dns / syscall / identity
 * / lsm). The loader crate (`crates/bpf-loader`) consumes the
 * resulting .o and .skel.rs at task 18; the happy QA in this task
 * only opens the object via `libbpf_rs::Object::open_mem_bytes`
 * without attaching or loading.
 *
 * The TU exercises every flag the pipeline must validate:
 *   * `-target bpf`                          — both amd64 and arm64
 *   * `-D__TARGET_ARCH_x86` / `arm64`        — CO-RE arch dispatch
 *   * `-I../include`                          — finds event_abi.h
 *   * `clang -O2 -g -Wall`                   — optimisation + line info
 *   * libbpf `SEC("tracepoint/...")` section  — exercises the
 *                                              skeleton generator
 *   * `bpf_get_current_pid_tgid()` helper    — exercises libbpf link
 *
 * The tracepoint payload is intentionally minimal because the program
 * never actually runs; the kernel never sees this object. The
 * pipeline just has to prove the same flags compile both arches and
 * that the .o carries .BTF / .BTF.ext.
 *
 * BTF line info is preserved via `-g`. The verifier/BTF line info
 * is retained for diagnostics per the task brief: "retain verifier/
 * BTF line info for diagnostics". The loader surface in task 18
 * reads it back out of the .o when an attach fails.
 *
 * Must NOT change without re-running `bpf:build` twice and asserting
 * identical object/skeleton digests (the deterministic-build gate).
 *
 * Include order: vmlinux.h first (so the CO-RE type/field
 * information is available before the libbpf helpers pull in any
 * uapi/compiler.h machinery that may rely on those types), then
 * libbpf's bpf_helpers / bpf_tracing, then event_abi.h last.
 * event_abi.h includes <stdint.h> for its uint32_t/uint64_t
 * constants and struct fields; stdint.h is host-style and would
 * conflict with vmlinux.h's __u* types if included before it.
 * Putting vmlinux.h first and event_abi.h last makes both sets of
 * types visible. */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* event_abi.h is the on-the-wire header locked by task 9. Including
 * it here proves the CO-RE build picks it up and that the static
 * size/offset assertions in it still compile under -target bpf. */
#include "event_abi.h"

/* `__user` is a sparse annotation used by the kernel uapi. libbpf
 * does not define it for -target bpf because BPF never dereferences
 * user pointers directly; the verifier rewrites the loads. Define a
 * no-op so `const char __user *pathname` below parses cleanly. */
#ifndef __user
#define __user
#endif

/* The kernel's bpf-prog license section is a string (not a SPDX
 * identifier). The libbpf-cargo SkeletonBuilder derives the .rodata
 * "license" field from the C source's first SPDX match plus the
 * surrounding comment when present; for this compile-only placeholder
 * we use a permissive identifier because the program is never
 * loaded. Real LSM-attached programs in task 33 will use
 * "GPL\0" per the README's kernel-side SPDX policy. */
char _license[] SEC("license") = "Dual MIT/Apache-2.0";

/* Tiny dummy map so the skeleton generator emits a meaningful
 * `placeholder.skel.rs` (skels of zero-map programs degenerate to a
 * near-empty struct, which is harder to test). The map is declared
 * but not used by the tracepoint handler. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} placeholder_dummy_map SEC(".maps");

/* Task 10 placeholder: emit a `KERNEL_V1_EVENT_PROCESS_EXEC_RESULT`
 * event into a per-CPU array map if a kernel ring buffer were
 * available. We declare the ring buffer here so the linker keeps
 * the `.bss`/`.data` sections that BTF describes, but the actual
 * ring buffer allocation and `bpf_ringbuf_output` is a no-op stub
 * because this TU is compile-only. Task 11 wires the real
 * `bpf_ringbuf_output` call against the task-9 ABI. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1u << 20); /* 1 MiB; ringbuf size ignored at
                                    * skeleton-generation time. */
} placeholder_events_rb SEC(".maps");

/* `handle_sys_enter_openat` is a single BPF program attached to the
 * `syscalls/sys_enter_openat` tracepoint. The tracepoint payload
 * argument layout (`struct trace_event_raw_sys_enter`) is part of
 * the kernel ABI and is described by vmlinux BTF, so this is a real
 * CO-RE read — proof that the generated vmlinux.h from
 * /sys/kernel/btf/vmlinux relocates cleanly under -target bpf on
 * both arches.
 *
 * The program body is intentionally a no-op: it reads the path
 * pointer into a stack variable so the BPF verifier can prove the
 * program has a defined return path, but it does not submit to a
 * ring buffer (task 11's real exec sensor does that). The compile
 * pipeline does not load this object. */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    /* CO-RE-relocated pointer read: `ctx->args[1]` is the pathname
     * argument to openat(2). We do not actually dereference it; the
     * pointer load alone exercises the CO-RE relocation path. */
    const char __user *pathname = (const char __user *)ctx->args[1];
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    /* Touch the event_abi.h schema so the build fails if the struct
     * layout drifts. The size/offset static_asserts in event_abi.h
     * would have already failed the compile, so this is purely a
     * smoke test for the include path. */
    struct kernel_v1_header hdr;
    hdr.schema_major = KERNEL_V1_ABI_SCHEMA_MAJOR;
    hdr.schema_minor = KERNEL_V1_ABI_SCHEMA_MINOR;
    hdr.event_kind = KERNEL_V1_EVENT_PROCESS_EXEC_RESULT;
    hdr.header_len = KERNEL_V1_ABI_HEADER_LEN;
    hdr.pid_tgid = pid_tgid;
    (void)hdr;

    /* Suppress the unused-variable warning while keeping the CO-RE
     * read and the event_abi.h smoke test live in the verifier
     * trace. */
    (void)pathname;
    return 0;
}

/* The `__TARGET_ARCH_*` macro is set by the build pipeline. The
 * `bpf_target` macro is the vmlinux.h BTF-defined equivalent. We
 * fail the compile with a clear diagnostic if neither is set, so
 * any future flag drift in the pipeline surfaces immediately
 * instead of silently producing a mis-targeted object. */
#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64)
#error "bpf/sensors/placeholder.bpf.c: __TARGET_ARCH_x86 or __TARGET_ARCH_arm64 must be defined by the build pipeline (-D__TARGET_ARCH_<arch>)"
#endif
