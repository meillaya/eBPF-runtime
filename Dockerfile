# Dockerfile — kernel-v1 (eBPF Runtime Security & Observability)
#
# Multi-stage OCI bake for the `agent` image. Buildx syntax; designed
# to be invoked via:
#
#   docker buildx build \
#     --platform linux/amd64,linux/arm64 \
#     --driver docker-container \
#     --tag ghcr.io/kernel-v1/agent:PLACEHOLDER \
#     --output type=oci,dest=- \
#     .
#
# The buildx driver MUST be `docker-container` (not `docker`) — this
# is the only driver that supports true multi-platform builds from a
# single Buildx invocation without requiring `--load` (which loads
# only a single platform into the local daemon and silently masks
# arm64 failures; that is exactly the anti-pattern this task forbids).
#
# Two named build stages — `runtime-amd64` and `runtime-arm64` — use
# pinned digests sourced from release/base-images.json. The digests
# are exposed as ARGs so they can be overridden at build time without
# editing this file (e.g. when task 50 promotes a new base image).
#
# At task 8 the `builder` stage emits a single placeholder shell
# payload at `/kernel-v1-agent-placeholder`; both runtime stages copy
# that same placeholder. Tasks 49-51 replace this stage with a real
# Rust build (`cargo build --release --target
# x86_64-unknown-linux-musl` for amd64 and the aarch64 counterpart for
# arm64) plus the CO-RE BPF objects.
#
# Task 8 of .omo/plans/ebpf-runtime-security-observability.md.
# SPDX-License-Identifier: Apache-2.0 OR MIT

# syntax=docker/dockerfile:1.7

# ----- Pinned base image digests (overridable at build time) -----
# The defaults below are obvious placeholders (all zeros); they are
# replaced by real digests during a CI run when the base-image
# promotion step runs (task 50 territory). Until then, the
# release:verify-placeholder fallback path constructs an OCI layout
# by hand and does NOT touch this file.
ARG PINNED_BASE_AMD64=PLACEHOLDER_AGENT_RUNTIME_AMD64_DIGEST@sha256:0000000000000000000000000000000000000000000000000000000000000000
ARG PINNED_BASE_ARM64=PLACEHOLDER_AGENT_RUNTIME_ARM64_DIGEST@sha256:0000000000000000000000000000000000000000000000000000000000000000

# ----- Builder stage (placeholder payload only) -----
# The builder produces the single payload that both runtime stages
# will COPY. The placeholder is a tiny shell script that prints the
# self-identification line on stdout; this keeps the scaffold build
# hermetic (no Rust toolchain, no BPF toolchain) while still proving
# the multi-arch copy path works end-to-end.
FROM --platform=$BUILDPLATFORM alpine:3.20 AS builder
RUN mkdir -p / && \
    printf '%s\n' \
      '#!/bin/sh' \
      'echo "kernel-v1 agent placeholder ${TARGETARCH} build PLACEHOLDER"' \
      'exit 0' \
      > /kernel-v1-agent-placeholder && \
    chmod 0755 /kernel-v1-agent-placeholder

# ----- amd64 runtime stage -----
# Pinned digest FROM; the COPY comes from the shared builder stage
# (which produces a single payload at /kernel-v1-agent-placeholder
# in this scaffold). Tasks 49-51 replace this stage with a real
# platform-conditional Rust build.
FROM ${PINNED_BASE_AMD64} AS runtime-amd64
COPY --from=builder /kernel-v1-agent-placeholder /usr/local/bin/kernel-v1-agent
RUN chmod 0755 /usr/local/bin/kernel-v1-agent
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/kernel-v1-agent"]
EXPOSE 9464

# ----- arm64 runtime stage -----
FROM ${PINNED_BASE_ARM64} AS runtime-arm64
COPY --from=builder /kernel-v1-agent-placeholder /usr/local/bin/kernel-v1-agent
RUN chmod 0755 /usr/local/bin/kernel-v1-agent
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/kernel-v1-agent"]
EXPOSE 9464