# Build the C sensors without going through cargo.
#
# The normal path is the loader build script, which calls bpf-build and
# embeds the objects in the Rust binary. This file is for a quick manual
# compile of one sensor.
#
#   make build-amd64           # <sensor>.amd64.bpf.o
#   make build-arm64           # <sensor>.arm64.bpf.o
#   make build-all
#   make clean
#
# CLANG and BPFTOOL can be overridden in the environment.

CLANG ?= $(shell command -v clang-19 2>/dev/null || command -v clang 2>/dev/null || echo /usr/lib/llvm19/bin/clang)
BPFTOOL ?= $(shell command -v bpftool 2>/dev/null || echo bpftool)

BPF_CFLAGS_COMMON := \
    -O2 \
    -g \
    -Wall \
    -Wno-missing-declarations \
    -Wno-address-of-packed-member \
    -target bpf \
    -I../include

SOURCES := $(wildcard *.bpf.c)
OBJECTS_AMD64 := $(SOURCES:.bpf.c=.amd64.bpf.o)
OBJECTS_ARM64 := $(SOURCES:.bpf.c=.arm64.bpf.o)

.PHONY: all build-all build-amd64 build-arm64 clean verify-toolchain

all: build-all

build-all: build-amd64 build-arm64

build-amd64: verify-toolchain $(OBJECTS_AMD64)

build-arm64: verify-toolchain $(OBJECTS_ARM64)

%.amd64.bpf.o: %.bpf.c vmlinux.h ../include/event_abi.h
	$(CLANG) $(BPF_CFLAGS_COMMON) -D__TARGET_ARCH_x86 -c $< -o $@

%.arm64.bpf.o: %.bpf.c vmlinux.h ../include/event_abi.h
	$(CLANG) $(BPF_CFLAGS_COMMON) -D__TARGET_ARCH_arm64 -c $< -o $@

verify-toolchain:
	@major=$$($(CLANG) --version | sed -n 's/.*version \([0-9][0-9]*\).*/\1/p' | head -1); \
	if [ "$$major" != "19" ]; then \
	    echo "ERROR: clang 19 is required, found '$$major'." >&2; \
	    echo "clang 20 and newer emit a memcpy extern that libbpf cannot resolve." >&2; \
	    exit 1; \
	fi
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { \
	    echo "ERROR: bpftool not found at $(BPFTOOL)." >&2; \
	    exit 1; \
	}

vmlinux.h:
	@test -r /sys/kernel/btf/vmlinux || { \
	    echo "ERROR: /sys/kernel/btf/vmlinux is not readable." >&2; \
	    exit 1; \
	}
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f $(OBJECTS_AMD64) $(OBJECTS_ARM64) vmlinux.h
