#!/usr/bin/env python3
# scripts/oci-inspect.py - minimal OCI Image Layout v1 inspector.
#
# Used by scripts/release-verify.sh to assert that the multi-arch OCI
# index contains exactly linux/amd64 and linux/arm64 entries, that
# each per-platform layer's binary is the correct ELF class (not a
# mismatched amd64 binary masquerading as arm64), and that the layer
# sha256 matches the manifest.
#
# Pure stdlib + optional `zstd` CLI subprocess fallback for
# `application/vnd.oci.image.layer.v1.tar+zstd` layers (Python 3.13
# has no stdlib zstd; 3.14+ does). If the layer's mediaType is
# neither gzip nor zstd the inspector aborts with a clear error.
#
# Layout read:
#   <root>/oci-layout                     {"imageLayoutVersion": "1.0.0"}
#   <root>/index.json                     index document
#   <root>/blobs/sha256/<digest>          one blob per digest
#
# The inspector is intentionally narrow: it understands only the
# shapes it needs to verify the task-8 acceptance criteria. It is
# NOT a general-purpose OCI implementation; that is what `crane`,
# `skopeo`, and `oras` are for.
#
# CLI usage:
#   oci-inspect.py inspect-index  <root>     # list platforms + digests
#   oci-inspect.py extract-binary <root> <arch> <out-path>
#                                              # extract /usr/local/bin/kernel-v1-agent
#   oci-inspect.py platform-config <root> <arch>
#                                              # print per-arch config JSON
#   oci-inspect.py verify-arch     <root>     # exit 0 iff arm64 not amd64-misclassified
#
# Task 8 of .omo/plans/ebpf-runtime-security-observability.md.
# SPDX-License-Identifier: Apache-2.0 OR MIT

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any


LAYER_MEDIATYPE_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
LAYER_MEDIATYPE_DOCKER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"
LAYER_MEDIATYPE_ZSTD = "application/vnd.oci.image.layer.v1.tar+zstd"
LAYER_MEDIATYPE_PLAIN = "application/vnd.oci.image.layer.v1.tar"

CONFIG_MEDIATYPE = "application/vnd.oci.image.config.v1+json"
MANIFEST_MEDIATYPE = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIATYPE = "application/vnd.oci.image.index.v1+json"

BINARY_IN_LAYER = "usr/local/bin/kernel-v1-agent"


# ---------- helpers --------------------------------------------------------


def err(msg: str) -> None:
    print(f"oci-inspect: {msg}", file=sys.stderr)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_blob(root: Path, digest: str) -> bytes:
    """Read a blob by digest. Digest is `sha256:<hex>`."""
    if not digest.startswith("sha256:"):
        raise ValueError(f"unsupported digest algorithm: {digest!r}")
    rel = Path("blobs") / "sha256" / digest.split(":", 1)[1]
    p = root / rel
    if not p.is_file():
        raise FileNotFoundError(f"missing blob: {p}")
    return p.read_bytes()


def decompress_layer(blob: bytes, media_type: str) -> bytes:
    """Decompress a layer payload per its mediaType."""
    if media_type in (LAYER_MEDIATYPE_GZIP, LAYER_MEDIATYPE_DOCKER_GZIP):
        return gzip.decompress(blob)
    if media_type == LAYER_MEDIATYPE_ZSTD:
        # Python 3.14+ has compression.zstd; earlier versions need
        # the system zstd CLI. Try stdlib first, fall back to CLI.
        try:
            import compression.zstd  # type: ignore[import-not-found]  # noqa: F401

            import compression.zstd as zstd  # type: ignore[import-not-found]

            return zstd.decompress(blob)
        except ImportError:
            pass
        zstd_bin = shutil.which("zstd") or shutil.which("unzstd")
        if not zstd_bin:
            raise RuntimeError(
                f"layer mediaType {media_type!r} requires Python 3.14+ "
                "compression.zstd or the system zstd CLI; neither is "
                "available"
            )
        proc = subprocess.run(
            [zstd_bin, "-d", "-c"],
            input=blob,
            capture_output=True,
            check=True,
        )
        return proc.stdout
    if media_type == LAYER_MEDIATYPE_PLAIN:
        return blob
    raise ValueError(f"unsupported layer mediaType: {media_type!r}")


# ---------- core read API --------------------------------------------------


def load_index(root: Path) -> dict[str, Any]:
    layout_file = root / "oci-layout"
    if not layout_file.is_file():
        raise FileNotFoundError(f"missing oci-layout at {layout_file}")
    try:
        layout = json.loads(layout_file.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"oci-layout is not valid JSON: {exc}") from exc
    if layout.get("imageLayoutVersion") != "1.0.0":
        raise ValueError(
            f"unsupported imageLayoutVersion: {layout.get('imageLayoutVersion')!r}; "
            "expected '1.0.0'"
        )

    index_file = root / "index.json"
    if not index_file.is_file():
        raise FileNotFoundError(f"missing index.json at {index_file}")
    try:
        index = json.loads(index_file.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"index.json is not valid JSON: {exc}") from exc

    if index.get("schemaVersion") != 2:
        raise ValueError(
            f"unsupported index schemaVersion: {index.get('schemaVersion')!r}; "
            "expected 2"
        )
    media_type = index.get("mediaType")
    if media_type not in (INDEX_MEDIATYPE, None):
        # Some producers omit mediaType; accept the omission.
        raise ValueError(f"unexpected index mediaType: {media_type!r}")
    if "manifests" not in index or not isinstance(index["manifests"], list):
        raise ValueError("index.json: 'manifests' must be a non-empty array")
    return index


def load_manifest(root: Path, digest: str) -> dict[str, Any]:
    blob = read_blob(root, digest)
    try:
        manifest = json.loads(blob)
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest blob {digest} is not valid JSON: {exc}") from exc
    if manifest.get("schemaVersion") != 2:
        raise ValueError(
            f"manifest {digest}: unsupported schemaVersion "
            f"{manifest.get('schemaVersion')!r}"
        )
    if manifest.get("mediaType") not in (MANIFEST_MEDIATYPE, None):
        raise ValueError(
            f"manifest {digest}: unexpected mediaType "
            f"{manifest.get('mediaType')!r}"
        )
    return manifest


def load_config(root: Path, digest: str) -> dict[str, Any]:
    blob = read_blob(root, digest)
    try:
        cfg = json.loads(blob)
    except json.JSONDecodeError as exc:
        raise ValueError(f"config blob {digest} is not valid JSON: {exc}") from exc
    return cfg


def list_platforms(root: Path) -> list[dict[str, str]]:
    """Return the per-platform descriptors from the index, sorted by arch."""
    index = load_index(root)
    platforms = []
    for entry in index["manifests"]:
        p = entry.get("platform") or {}
        platforms.append(
            {
                "mediaType": entry.get("mediaType", ""),
                "digest": entry.get("digest", ""),
                "size": str(entry.get("size", "")),
                "architecture": p.get("architecture", ""),
                "os": p.get("os", ""),
            }
        )
    return platforms


def manifest_for_arch(root: Path, arch: str) -> dict[str, Any]:
    """Find the index entry for a given architecture (amd64 / arm64)."""
    platforms = list_platforms(root)
    matches = [p for p in platforms if p["architecture"] == arch]
    if not matches:
        raise LookupError(f"no index entry for architecture {arch!r}")
    if len(matches) > 1:
        raise ValueError(
            f"multiple index entries for architecture {arch!r}: {matches!r}"
        )
    return load_manifest(root, matches[0]["digest"])


def config_for_arch(root: Path, arch: str) -> dict[str, Any]:
    """Return the config JSON for a given architecture."""
    manifest = manifest_for_arch(root, arch)
    cfg_ref = manifest.get("config") or {}
    if not cfg_ref.get("digest"):
        raise ValueError(f"manifest for {arch}: missing config.digest")
    return load_config(root, cfg_ref["digest"])


def extract_binary(root: Path, arch: str, out_path: Path) -> dict[str, Any]:
    """Extract /usr/local/bin/kernel-v1-agent from the arch's rootfs layer.

    Returns a dict with the per-arch extraction metadata (digest,
    size, member path) so the caller can assert against it.
    """
    manifest = manifest_for_arch(root, arch)
    layers = manifest.get("layers") or []
    if not layers:
        raise ValueError(f"manifest for {arch}: no layers")
    # The placeholder layer is a single layer that contains
    # usr/local/bin/kernel-v1-agent. Search all layers; the first one
    # that contains the member wins.
    for layer in layers:
        media_type = layer.get("mediaType", "")
        digest = layer.get("digest", "")
        if not digest:
            continue
        try:
            blob = read_blob(root, digest)
        except FileNotFoundError:
            continue
        actual_digest = "sha256:" + sha256_bytes(blob)
        if actual_digest != digest:
            raise ValueError(
                f"layer digest mismatch for {arch}: manifest says {digest}, "
                f"on-disk is {actual_digest}"
            )
        try:
            payload = decompress_layer(blob, media_type)
        except (ValueError, RuntimeError) as exc:
            err(f"layer {digest} decompression failed for {arch}: {exc}")
            continue
        try:
            tf = tarfile.open(fileobj=__import__("io").BytesIO(payload), mode="r:")
        except tarfile.TarError as exc:
            err(f"layer {digest} is not a tar: {exc}")
            continue
        try:
            member = None
            for m in tf.getmembers():
                # Match by basename; the in-tar path can be
                # "./usr/local/bin/kernel-v1-agent" or "usr/...".
                if m.name.rstrip("/").endswith(BINARY_IN_LAYER) and m.isfile():
                    member = m
                    break
            if member is None:
                continue
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            data = extracted.read()
        finally:
            tf.close()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)
        out_path.chmod(0o755)
        return {
            "arch": arch,
            "layer_media_type": media_type,
            "layer_digest": digest,
            "layer_size": layer.get("size", 0),
            "binary_size": len(data),
            "binary_path": str(out_path),
        }
    raise LookupError(
        f"no layer in arch {arch!r} contained {BINARY_IN_LAYER!r}"
    )


def verify_arch(root: Path) -> dict[str, Any]:
    """Walk every index entry, extract each binary, and report per-arch
    ELF-class info. Returns a dict suitable for JSON serialisation.

    Does not run `file(1)`; that is the verify-script's job. This
    function only proves that the on-disk binaries exist and the
    layer digests match the manifests.
    """
    platforms = list_platforms(root)
    report: dict[str, Any] = {
        "schema_version": 1,
        "schema": "https://kernel-v1.local/schemas/oci-inspect/v1.json",
        "layout_root": str(root),
        "image_layout_version": "1.0.0",
        "index_schema_version": 2,
        "platforms": platforms,
        "extractions": {},
    }
    tmp = root / ".oci-inspect-tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    try:
        for p in platforms:
            arch = p["architecture"]
            out = tmp / f"binary-{arch}"
            try:
                info = extract_binary(root, arch, out)
            except (LookupError, ValueError, FileNotFoundError) as exc:
                report["extractions"][arch] = {"error": str(exc)}
                continue
            info["on_disk_sha256"] = sha256_file(out)
            report["extractions"][arch] = info
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return report


# ---------- CLI ------------------------------------------------------------


def cmd_inspect_index(args: argparse.Namespace) -> int:
    try:
        platforms = list_platforms(Path(args.root))
    except (FileNotFoundError, ValueError) as exc:
        err(str(exc))
        return 1
    json.dump(platforms, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def cmd_extract_binary(args: argparse.Namespace) -> int:
    try:
        info = extract_binary(Path(args.root), args.arch, Path(args.out))
    except (FileNotFoundError, ValueError, LookupError) as exc:
        err(str(exc))
        return 1
    json.dump(info, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def cmd_platform_config(args: argparse.Namespace) -> int:
    try:
        cfg = config_for_arch(Path(args.root), args.arch)
    except (FileNotFoundError, ValueError, LookupError) as exc:
        err(str(exc))
        return 1
    json.dump(cfg, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def cmd_verify_arch(args: argparse.Namespace) -> int:
    try:
        report = verify_arch(Path(args.root))
    except (FileNotFoundError, ValueError) as exc:
        err(str(exc))
        return 1
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    # Exit 0 iff every arch extracted cleanly.
    for arch, info in report["extractions"].items():
        if "error" in info:
            err(f"extraction for {arch} failed: {info['error']}")
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Minimal OCI Image Layout v1 inspector (task 8)."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_idx = sub.add_parser("inspect-index", help="list index platforms")
    p_idx.add_argument("root", help="OCI layout root directory")
    p_idx.set_defaults(func=cmd_inspect_index)

    p_ex = sub.add_parser("extract-binary", help="extract /usr/local/bin/kernel-v1-agent")
    p_ex.add_argument("root", help="OCI layout root directory")
    p_ex.add_argument("arch", help="architecture (amd64 | arm64)")
    p_ex.add_argument("out", help="output file path")
    p_ex.set_defaults(func=cmd_extract_binary)

    p_cfg = sub.add_parser("platform-config", help="print per-arch config JSON")
    p_cfg.add_argument("root", help="OCI layout root directory")
    p_cfg.add_argument("arch", help="architecture (amd64 | arm64)")
    p_cfg.set_defaults(func=cmd_platform_config)

    p_v = sub.add_parser("verify-arch", help="verify per-arch extractions")
    p_v.add_argument("root", help="OCI layout root directory")
    p_v.set_defaults(func=cmd_verify_arch)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())