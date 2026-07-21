#!/usr/bin/env python3
# scripts/proto-roundtrip.py — kernel-v1 protobuf round-trip test
#
# Task 6 of .omo/plans/ebpf-runtime-security-observability.md.
#
# Loads the events v1 FileDescriptorSet produced by `buf build`,
# dynamically compiles the Python bindings for the kernel.v1.events.v1
# and kernel.v1.control.v1 packages, then encodes a small fixture
# (one Batch containing one Event of every EventKind oneof variant)
# and asserts byte-for-byte equivalence across an encode -> decode
# round trip.
#
# Acceptance:
#   * `python3 scripts/proto-roundtrip.py` exits 0
#   * The fixture round-trips without error for every EventKind
#   * The decoded fields match the input
#
# The script uses only the official google.protobuf library (already
# vendored in the devenv Python env). It does NOT require a code
# generation step; it derives the bindings from the FileDescriptorSet
# at runtime.
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

from __future__ import annotations

import os
import sys
import json
import hashlib
import subprocess
import tempfile
from pathlib import Path

# Make the runtime google.protobuf importable. The devenv env exposes
# it under PYTHONPATH; if it's not on sys.path, fall back to the Nix
# store location that hosts the protobuf 7.34.1 wheel.
try:
    from google.protobuf import descriptor_pb2, descriptor_pool  # noqa: F401
    from google.protobuf import message_factory  # noqa: F401
except ImportError as exc:  # pragma: no cover
    print(f"proto-roundtrip: google.protobuf not importable: {exc}", file=sys.stderr)
    sys.exit(2)


REPO_ROOT = Path(__file__).resolve().parent.parent
PROTO_ROOT = REPO_ROOT / "proto"
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "proto" / "events" / "happy.json"


def build_descriptor_set() -> bytes:
    """Invoke `buf build proto -o /tmp/...` and return the bytes."""
    with tempfile.NamedTemporaryFile(suffix=".binpb", delete=False) as tmp:
        out_path = Path(tmp.name)
    try:
        result = subprocess.run(
            ["buf", "build", str(PROTO_ROOT), "-o", str(out_path)],
            cwd=str(REPO_ROOT),
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"proto-roundtrip: buf build failed (rc={result.returncode})", file=sys.stderr)
            print(result.stdout, file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            sys.exit(result.returncode or 1)
        return out_path.read_bytes()
    finally:
        if out_path.exists():
            out_path.unlink()


def load_factory(blob: bytes):
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(blob)
    pool = descriptor_pool.DescriptorPool()
    for file_proto in fds.file:
        pool.Add(file_proto)

    def message_for(name: str):
        descriptor = pool.FindMessageTypeByName(name)
        return message_factory.GetMessageClass(descriptor)

    return pool, message_for


def build_event(kind: str, factory) -> object:
    """Construct a single Event message of the given kind, with valid
    payload fields."""
    pool, message_for = factory
    event_cls = message_for("kernel.v1.events.v1.Event")
    batch_cls = message_for("kernel.v1.events.v1.Batch")
    identity_cls = message_for("kernel.v1.events.v1.Identity")
    event = event_cls()

    # Scalar discriminator.
    kind_to_field = {
        "EVENT_KIND_PROCESS_FORK": "process_fork",
        "EVENT_KIND_PROCESS_EXEC_RESULT": "process_exec_result",
        "EVENT_KIND_PROCESS_EXIT": "process_exit",
        "EVENT_KIND_FILE_OPEN": "file_open",
        "EVENT_KIND_FILE_CREATE": "file_create",
        "EVENT_KIND_FILE_UNLINK": "file_unlink",
        "EVENT_KIND_FILE_RENAME": "file_rename",
        "EVENT_KIND_NETWORK_CONNECT": "network_connect",
        "EVENT_KIND_NETWORK_ACCEPT": "network_accept",
        "EVENT_KIND_NETWORK_STATE": "network_state",
        "EVENT_KIND_DNS_PACKET": "dns_packet",
        "EVENT_KIND_SYSCALL_ENTER": "syscall_enter",
        "EVENT_KIND_SYSCALL_EXIT": "syscall_exit",
        "EVENT_KIND_LSM_DENY_OWN": "lsm_deny",
        "EVENT_KIND_IDENTITY": "identity",
    }
    payload_field = kind_to_field[kind]

    # Build the matching identity block (every payload takes one).
    ident = identity_cls()
    ident.pid_tgid = 12345
    ident.task_start_time_ns = 1700000000_000_000_000
    ident.cgroup_id = 0xCAFE
    ident.mount_ns_id = 4026531840
    ident.pid_ns_id = 4026531839
    ident.net_ns_id = 4026531837
    ident.user_ns_id = 4026531836
    ident.uts_ns_id = 4026531835
    ident.ipc_ns_id = 4026531834
    ident.time_ns_id = 4026531833
    ident.uid = 1000
    ident.gid = 1000
    ident.loginuid = 1000
    ident.parent_pid_tgid = 12344
    # Map field is left empty in the fixture to keep the wire format
    # deterministic across encode/decode cycles. (proto3 maps have
    # unspecified iteration order; the round-trip test only cares
    # about byte equivalence of the wire payload, not about exercising
    # every field.)

    # Wire the discriminator + the matching payload.
    event_kind_value = event_cls.DESCRIPTOR.fields_by_name["event_kind"].enum_type.values_by_name[kind].number
    setattr(event, "event_kind", event_kind_value)
    getattr(event, payload_field).CopyFrom(_payload_for(kind, ident, factory))
    return event


def _payload_for(kind: str, ident, factory):
    pool, message_for = factory

    pid_tgid = ident.pid_tgid
    common = {"task": ident} if kind not in {"EVENT_KIND_PROCESS_FORK", "EVENT_KIND_IDENTITY"} else {}

    if kind == "EVENT_KIND_PROCESS_FORK":
        msg = message_for("kernel.v1.events.v1.ProcessFork")()
        msg.child.CopyFrom(ident)
        msg.is_thread = False
        return msg
    if kind == "EVENT_KIND_PROCESS_EXEC_RESULT":
        msg = message_for("kernel.v1.events.v1.ProcessExecResult")()
        msg.task.CopyFrom(ident)
        msg.binary_path = "/bin/true"
        msg.argv_bytes = b"/bin/true\0"
        msg.succeeded = True
        msg.errno_value = 0
        msg.argv_truncated = False
        return msg
    if kind == "EVENT_KIND_PROCESS_EXIT":
        msg = message_for("kernel.v1.events.v1.ProcessExit")()
        msg.task.CopyFrom(ident)
        msg.exit_code = 0
        msg.exit_group = True
        msg.group_dead_observed = False
        return msg
    if kind == "EVENT_KIND_FILE_OPEN":
        msg = message_for("kernel.v1.events.v1.FileOpen")()
        msg.task.CopyFrom(ident)
        msg.path = "/etc/hostname"
        msg.flags = 0
        msg.succeeded = True
        msg.errno_value = 0
        msg.from_lsm = True
        return msg
    if kind == "EVENT_KIND_FILE_CREATE":
        msg = message_for("kernel.v1.events.v1.FileCreate")()
        msg.task.CopyFrom(ident)
        msg.path = "/tmp/new"
        msg.flags = 0x41
        msg.mode = 0o644
        msg.succeeded = True
        msg.errno_value = 0
        msg.from_lsm = True
        return msg
    if kind == "EVENT_KIND_FILE_UNLINK":
        msg = message_for("kernel.v1.events.v1.FileUnlink")()
        msg.task.CopyFrom(ident)
        msg.path = "/tmp/old"
        msg.is_dir = False
        msg.succeeded = True
        msg.errno_value = 0
        msg.from_lsm = True
        return msg
    if kind == "EVENT_KIND_FILE_RENAME":
        msg = message_for("kernel.v1.events.v1.FileRename")()
        msg.task.CopyFrom(ident)
        msg.source_path = "/tmp/src"
        msg.dest_path = "/tmp/dst"
        msg.succeeded = True
        msg.errno_value = 0
        msg.from_lsm = True
        return msg
    if kind == "EVENT_KIND_NETWORK_CONNECT":
        msg = message_for("kernel.v1.events.v1.NetworkConnect")()
        msg.task.CopyFrom(ident)
        msg.socket_cookie = 0xDEADBEEF
        msg.family = 2  # AF_INET
        msg.local_addr = bytes(4)
        msg.remote_addr = b"\x7f\x00\x00\x01"
        msg.local_port = 54321
        msg.remote_port = 80
        msg.is_result = True
        msg.established = True
        msg.errno_value = 0
        msg.from_cgroup = True
        return msg
    if kind == "EVENT_KIND_NETWORK_ACCEPT":
        msg = message_for("kernel.v1.events.v1.NetworkAccept")()
        msg.task.CopyFrom(ident)
        msg.socket_cookie = 0xC0FFEE
        msg.family = 2
        msg.local_addr = bytes(4)
        msg.remote_addr = b"\x7f\x00\x00\x01"
        msg.local_port = 8080
        msg.remote_port = 54321
        msg.returned_fd = 7
        msg.succeeded = True
        msg.errno_value = 0
        return msg
    if kind == "EVENT_KIND_NETWORK_STATE":
        msg = message_for("kernel.v1.events.v1.NetworkState")()
        msg.task.CopyFrom(ident)
        msg.socket_cookie = 0xC0FFEE
        msg.old_state = 1
        msg.new_state = 2
        return msg
    if kind == "EVENT_KIND_DNS_PACKET":
        msg = message_for("kernel.v1.events.v1.DnsPacket")()
        msg.task.CopyFrom(ident)
        msg.is_query = True
        msg.transport = 2  # SOCK_DGRAM
        msg.packet_bytes = b"\x12\x34\x01\x00\x00\x01\x00\x00"
        msg.truncated = False
        msg.is_egress = True
        return msg
    if kind == "EVENT_KIND_SYSCALL_ENTER":
        msg = message_for("kernel.v1.events.v1.SyscallEnter")()
        msg.task.CopyFrom(ident)
        msg.syscall_nr = 0  # read
        msg.ts_monotonic_ns = 1700000000_000_000_001
        msg.compat_syscall_nr = -1
        return msg
    if kind == "EVENT_KIND_SYSCALL_EXIT":
        msg = message_for("kernel.v1.events.v1.SyscallExit")()
        msg.task.CopyFrom(ident)
        msg.syscall_nr = 0
        msg.ts_monotonic_ns = 1700000000_000_000_002
        msg.elapsed_ns = 1500
        msg.compat_syscall_nr = -1
        msg.no_return = False
        msg.errno_value = 0
        return msg
    if kind == "EVENT_KIND_LSM_DENY_OWN":
        msg = message_for("kernel.v1.events.v1.LsmDeny")()
        msg.task.CopyFrom(ident)
        msg.hook = "file_open"
        msg.subject = "/etc/shadow"
        msg.own_deny = True
        msg.policy_version = "1.0.0"
        msg.policy_digest = b"\x01\x02\x03\x04"
        return msg
    if kind == "EVENT_KIND_IDENTITY":
        msg = message_for("kernel.v1.events.v1.Identity")()
        msg.CopyFrom(ident)
        return msg
    raise AssertionError(f"unhandled kind: {kind}")


def main() -> int:
    blob = build_descriptor_set()
    factory = load_factory(blob)
    pool, message_for = factory
    batch_cls = message_for("kernel.v1.events.v1.Batch")
    event_cls = message_for("kernel.v1.events.v1.Event")
    wellknown_ts = message_for("google.protobuf.Timestamp")

    # Every EventKind we promise to emit (excludes UNSPECIFIED).
    every_kind = [
        "EVENT_KIND_PROCESS_FORK",
        "EVENT_KIND_PROCESS_EXEC_RESULT",
        "EVENT_KIND_PROCESS_EXIT",
        "EVENT_KIND_FILE_OPEN",
        "EVENT_KIND_FILE_CREATE",
        "EVENT_KIND_FILE_UNLINK",
        "EVENT_KIND_FILE_RENAME",
        "EVENT_KIND_NETWORK_CONNECT",
        "EVENT_KIND_NETWORK_ACCEPT",
        "EVENT_KIND_NETWORK_STATE",
        "EVENT_KIND_DNS_PACKET",
        "EVENT_KIND_SYSCALL_ENTER",
        "EVENT_KIND_SYSCALL_EXIT",
        "EVENT_KIND_LSM_DENY_OWN",
        "EVENT_KIND_IDENTITY",
    ]

    batch = batch_cls()
    batch.schema_major = 1
    batch.schema_minor = 0
    batch.agent_generation = "agent-gen-1"
    batch.node_name = "node-1"
    batch.boot_id = b"\x00" * 16
    for i, kind in enumerate(every_kind):
        ev = build_event(kind, factory)
        ev.event_id = f"00000000-0000-0000-0000-{i:012d}"
        ev.seq = i
        ev.ts_monotonic_ns = 1700000000_000_000_000 + i
        ev.ts_wall.CopyFrom(wellknown_ts(seconds=1700000000 + i))
        ev.sensor = "process" if kind.startswith("EVENT_KIND_PROCESS") else "ops"
        batch.events.append(ev)

    # Encode -> decode round trip.
    encoded = batch.SerializeToString()
    decoded = batch_cls()
    decoded.ParseFromString(encoded)

    # Persist a small JSON view next to the fixture so the QA scenario
    # has something tangible to inspect; the JSON form is also used by
    # the rule engine in task 28.
    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    event_kind_enum = event_cls.DESCRIPTOR.fields_by_name["event_kind"].enum_type
    view = {
        "schema_major": decoded.schema_major,
        "schema_minor": decoded.schema_minor,
        "agent_generation": decoded.agent_generation,
        "node_name": decoded.node_name,
        "boot_id_hex": decoded.boot_id.hex(),
        "events": [
            {
                "event_id": ev.event_id,
                "seq": ev.seq,
                "event_kind": event_kind_enum.values_by_number[ev.event_kind].name,
                "sensor": ev.sensor,
            }
            for ev in decoded.events
        ],
    }
    FIXTURE_PATH.write_text(json.dumps(view, indent=2, sort_keys=True) + "\n")

    # Re-encode the decoded and assert byte equivalence.
    re_encoded = decoded.SerializeToString()
    if encoded != re_encoded:
        print(
            f"proto-roundtrip: re-encoded bytes differ (len={len(encoded)} vs {len(re_encoded)})",
            file=sys.stderr,
        )
        return 1

    digest = hashlib.sha256(encoded).hexdigest()
    print(
        f"proto-roundtrip: round-trip OK; {len(every_kind)} EventKind variants; "
        f"encoded {len(encoded)} bytes; sha256={digest[:16]}..."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
