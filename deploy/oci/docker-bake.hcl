# SPDX-License-Identifier: Apache-2.0 OR MIT
# deploy/oci/docker-bake.hcl — Docker Bake definitions for kernel-v1
# multi-arch OCI image builds (linux/amd64 + linux/arm64).
#
# Usage:
#   # Build all targets, push to registry:
#   docker buildx bake -f deploy/oci/docker-bake.hcl --push
#
#   # Build a single target to OCI layout (no push):
#   docker buildx bake -f deploy/oci/docker-bake.hcl agent --set agent.output=type=oci,dest=/tmp/agent.oci
#
#   # Build with SBOM + provenance attestation (default):
#   docker buildx bake -f deploy/oci/docker-bake.hcl --push
#
#   # Override registry/tag:
#   REGISTRY=ghcr.io/myorg TAG=v1.2.3 docker buildx bake -f deploy/oci/docker-bake.hcl --push
#
# Requirements:
#   - Docker Buildx v0.10+ with docker-container driver
#   - docker buildx create --name k1-builder --driver docker-container --use
#   - Syft (for SBOM generation): https://github.com/anchore/syft
#   - QEMU binfmt for arm64 emulation (or native arm64 builder)
#
# NEVER use --load for multi-arch builds. Use --push or OCI layout output.

variable "REGISTRY" {
  default = "ghcr.io/kernel-v1"
}

variable "TAG" {
  default = "latest"
}

variable "REPO_ROOT" {
  default = "../.."
}

# =====================================================================
# Shared settings
# =====================================================================

group "default" {
  targets = ["agent", "control-plane"]
}

# =====================================================================
# Agent image
# =====================================================================

target "agent" {
  context    = "${REPO_ROOT}"
  dockerfile = "deploy/oci/Dockerfile.agent"
  platforms  = ["linux/amd64", "linux/arm64"]
  tags       = ["${REGISTRY}/agent:${TAG}"]

  # SBOM generation via Syft (BuildKit attestation).
  # Produces an SPDX SBOM attestation attached to the image manifest.
  attest = [
    "type=sbom,generator=syft",
    "type=provenance,mode=max",
  ]

  # Provenance attestation: full SLSA provenance with builder ID,
  # build args, and source metadata. mode=max includes all layers.
  provenance = "mode=max"

  # SBOM scanner: Syft scans the final image filesystem.
  sbom = "generator=syft"

  args = {
    # Digests are pinned in the Dockerfile; override here for CI promotion.
    # RUST_BUILDER_AMD64 = "..."
    # RUST_BUILDER_ARM64 = "..."
    # RUNTIME_AMD64      = "..."
    # RUNTIME_ARM64      = "..."
  }

  labels = {
    "org.opencontainers.image.source"  = "https://github.com/kernel-v1/kernel-v1"
    "org.opencontainers.image.title"   = "kernel-v1-agent"
    "org.opencontainers.image.description" = "eBPF runtime security node agent"
    "org.opencontainers.image.licenses" = "Apache-2.0 OR MIT"
  }
}

# =====================================================================
# Control-plane image
# =====================================================================

target "control-plane" {
  context    = "${REPO_ROOT}"
  dockerfile = "deploy/oci/Dockerfile.control-plane"
  platforms  = ["linux/amd64", "linux/arm64"]
  tags       = ["${REGISTRY}/control-plane:${TAG}"]

  attest = [
    "type=sbom,generator=syft",
    "type=provenance,mode=max",
  ]

  provenance = "mode=max"
  sbom       = "generator=syft"

  args = {
    # Digests are pinned in the Dockerfile; override here for CI promotion.
  }

  labels = {
    "org.opencontainers.image.source"  = "https://github.com/kernel-v1/kernel-v1"
    "org.opencontainers.image.title"   = "kernel-v1-control-plane"
    "org.opencontainers.image.description" = "Fleet control-plane query and live-stream API"
    "org.opencontainers.image.licenses" = "Apache-2.0 OR MIT"
  }
}
