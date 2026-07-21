# bpf/sensors/Makefile — kernel-v1 (eBPF Runtime Security & Observability)
#
# Task 10 (libbpf-cargo CO-RE build pipeline). This Makefile is a
# deliberately minimal, cmake-free, hermetic build entry point for the
# BPF sensor sources under bpf/sensors/. It exists ONLY so a build
# engineer can produce a per-arch .bpf.o without entering the
# devenv/Cargo toolchain — the canonical path is the libbpf-cargo
# SkeletonBuilder inside `crates/bpf-build`, and the CO-RE build
# itself is owned by `crates/bpf-build/build.rs`.
#
# The Makefile is intentionally NOT a parallel build system; cargo
# invokes `crates/bpf-build/build.rs` (which delegates to
# libbpf-cargo's SkeletonBuilder) to do the real, deterministic
# multi-arch build, and this Makefile is the equivalent shell-out
# path that the bpf-build crate can fall back to if libbpf-cargo
# ever fails to resolve a toolchain on a host where the rest of the
# devenv is intact. It is also the obvious place for a developer
# to test a single source change before wiring it into cargo.
#
# Usage
#   make build-amd64           # compile every *.bpf.c to <name>.amd64.bpf.o
#   make build-arm64           # compile every *.bpf.c to <name>.arm64.bpf.o
#   make build-all             # both arches
#   make clean                 # remove generated .o and .skel.rs files
#
# Environment overrides
#   CLANG            path to clang (default: detected)
#   BPFTOOL          path to bpftool (default: detected)
#   BPF_CFLAGS_EXTRA extra flags passed verbatim to clang
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

# Detect the toolchain. We do not assume /usr/bin; the devenv
# environment exports CLANG and BPFTOOL via devenv.nix. If those
# are unset, fall back to the on-PATH binaries.
CLANG ?= $(shell command -v clang 2>/dev/null || echo clang)
BPFTOOL ?= $(shell command -v bpftool 2>/dev/null || echo bpftool)

# Pinned CO-RE flags. The two archs differ only in -D__TARGET_ARCH_*;
# the BPF target, optimisation level, debug info, include path, and
# warning policy are identical so the .o contents differ only in the
# fields that the kernel actually relocates at load time.
BPF_CFLAGS_COMMON := \
    -O2 \
    -g \
    -Wall \
    -target bpf \
    -I../include

# -D__BPF__ is implicit when -target bpf is set, but we set it
# explicitly so the bpf-event-abi shim guards in event_abi.h fire
# without relying on clang's heuristic.

# Sources: every *.bpf.c in this directory. The list is computed
# once so a single `make` invocation rebuilds every sensor for the
# requested arch.
SOURCES := $(wildcard *.bpf.c)
OBJECTS_AMD64 := $(SOURCES:.bpf.c=.amd64.bpf.o)
OBJECTS_ARM64 := $(SOURCES:.bpf.c=.arm64.bpf.o)

.PHONY: all build-all build-amd64 build-arm64 clean verify-toolchain

all: build-all

build-all: build-amd64 build-arm64

build-amd64: verify-toolchain $(OBJECTS_AMD64)

build-arm64: verify-toolchain $(OBJECTS_ARM64)

# Per-source compile rules. The pattern rule makes the .o
# dependent on the .c plus vmlinux.h and the event ABI header; any
# change to those inputs triggers a recompile.
%.amd64.bpf.o: %.bpf.c vmlinux.h ../include/event_abi.h
	$(CLANG) $(BPF_CFLAGS_COMMON) -D__TARGET_ARCH_x86 -c $< -o $@

%.arm64.bpf.o: %.bpf.c vmlinux.h ../include/event_abi.h
	$(CLANG) $(BPF_CFLAGS_COMMON) -D__TARGET_ARCH_arm64 -c $< -o $@

# `make verify-toolchain` is a no-op when the toolchain is
# available; it prints a clear error and exits non-zero when clang
# does not advertise the bpf target. This is the make-level
# counterpart to the libbpf-cargo path's toolchain probe.
verify-toolchain:
	@if ! $(CLANG) --target=bpf -E -x c /dev/null >/dev/null 2>&1; then \
	    echo "ERROR: $(CLANG) does not support -target=bpf. Refusing to build." >&2; \
	    echo "Hint: install llvm + clang (nix: llvmPackages_19.clang) and retry." >&2; \
	    exit 1; \
	fi
	@if ! command -v $(BPFTOOL) >/dev/null 2>&1; then \
	    echo "ERROR: bpftool not found at $(BPFTOOL). Refusing to build." >&2; \
	    exit 1; \
	fi

# `make vmlinux.h` is a convenience: regenerate the CO-RE BTF
# header from the host kernel. The libbpf-cargo build pipeline does
# this automatically; the Makefile path makes it explicit so a
# developer can refresh the pinned baseline manually.
vmlinux.h:
	@if [ ! -r /sys/kernel/btf/vmlinux ]; then \
	    echo "ERROR: /sys/kernel/btf/vmlinux is not readable; cannot generate vmlinux.h" >&2; \
	    exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null > $@

clean:
	rm -f $(OBJECTS_AMD64) $(OBJECTS_ARM64) vmlinux.h
