"""
build_file_fixtures.py — generate the .binpb fixture bytes for
task 12 (file sensor decoder tests).

The bytes produced here are committed to the repository and
become the source of truth for `cargo test -p sensor-tests --test
process_events` until the privileged runner replaces them with
live BPF recordings (task 53+).

Each fixture has:
  * 96-byte kernel_v1_header
  * 552-byte kernel_v1_file_payload
    - 16-byte kfuncs_used prefix (NUL-padded ASCII)
    - 256-byte path[16] field (NUL-padded)
    - per-kind fields
    - 280 bytes of reserved/padding

The on-wire byte layout matches `bpf/sensors/file.bpf.c`
struct file_{open,create,unlink,rename,truncate}_payload.

Run from the repo root:
    python3 scripts/build_file_fixtures.py
"""
from __future__ import annotations
import os
import struct

REPO = "/home/mei/projects/kernels/kernel-v1"
FIXTURE_DIR = os.path.join(REPO, "crates/sensor-tests/tests/fixtures/file")

SCHEMA_MAJOR = 1
SCHEMA_MINOR = 0
HEADER_LEN = 96
PAYLOAD_LEN = 552  # KERNEL_V1_FILE_PAYLOAD_LEN from file.bpf.c

# Event kinds — task 12 brief values
EVENT_FILE_OPEN = 4
EVENT_FILE_CREATE = 5
EVENT_FILE_UNLINK = 6
EVENT_FILE_RENAME = 7
EVENT_FILE_TRUNCATE = 8

# Validity bits — task 12 deviations (non-overlapping with
# KERNEL_V1_VALID_* = 0x0001..0x4000 from process+identity)
VALID_BOOT_ID = 0x0001
VALID_CGROUP_ID = 0x0002
VALID_PID_TGID = 0x0004
VALID_TASK_START = 0x0400
VALID_PROCESSOR = 0x0800
VALID_FILE_PATH = 0x8000
VALID_FILE_FLAGS = 0x10000
VALID_FILE_MODE = 0x20000
VALID_FILE_DENY_SOURCE = 0x40000
VALID_FILE_ERRNO = 0x80000

# Per-payload (FILE_* payload's `flags` byte) flag bits
FILE_RESULT_HAS_ERRNO = 0x01
FILE_RESULT_OWN_LSM = 0x02  # never set by file.bpf.c

# File-result deny source enum
FILE_DENY_NONE = 0
FILE_DENY_OWN_LSM = 1
FILE_DENY_SYSCALL = 2

KERNEL_HEADER_FLAGS_TRUNC = 0x01
KERNEL_HEADER_FLAGS_REDACTED = 0x02

KFUNCS_USED_BYTES = b"core_read_str_in"  # 16 bytes NUL-padded


def write_cstr(buf: bytearray, off: int, value: str, size: int) -> None:
    """Write a C-string into `buf` at offset `off`, NUL-padded to `size`."""
    raw = value.encode("utf-8")
    if len(raw) > size:
        raise ValueError(f"string {value!r} is {len(raw)} bytes; must fit in {size}")
    buf[off:off + size] = raw + b"\x00" * (size - len(raw))


def write_u32(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", buf, off, value & 0xFFFFFFFF)


def write_u64(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<Q", buf, off, value & 0xFFFFFFFFFFFFFFFF)


def write_u8(buf: bytearray, off: int, value: int) -> None:
    buf[off] = value & 0xFF


def make_header(
    event_kind: int,
    header_flags: int,
    valids: int,
    seq: int,
    ts_mono_ns: int,
    boot_id: bytes,
    pid_tgid: int,
    task_start: int,
    cgroup_id: int,
    processor_id: int,
    ns_pid: int,
) -> bytes:
    payload_len = PAYLOAD_LEN
    record_len = HEADER_LEN + payload_len
    buf = bytearray(HEADER_LEN)
    write_u32(buf, 0, SCHEMA_MAJOR)
    write_u32(buf, 4, SCHEMA_MINOR)
    write_u32(buf, 8, HEADER_LEN)
    write_u32(buf, 12, record_len)
    write_u8(buf, 16, event_kind)
    # 17,18,19 _pad0 (3 bytes) — left zero
    write_u8(buf, 20, header_flags)
    # 21,22,23 _pad1 (3 bytes) — left zero
    write_u64(buf, 24, seq)
    write_u64(buf, 32, ts_mono_ns)
    # boot_id 16 bytes
    assert len(boot_id) == 16
    buf[40:56] = boot_id
    write_u64(buf, 56, pid_tgid)
    write_u64(buf, 64, task_start)
    write_u64(buf, 72, cgroup_id)
    write_u32(buf, 80, processor_id)
    write_u32(buf, 84, valids)
    write_u64(buf, 88, ns_pid)
    return bytes(buf)


def make_file_payload(
    kfuncs_used: bytes,
    path: str = "",
    flags: int = 0,
    mode: int = 0,
    deny_source: int = FILE_DENY_NONE,
    result_flags: int = 0,
    # file_create
    mode_bits: int = 0,
    exclusive: int = 0,
    # file_unlink
    unlink_flags: int = 0,
    # file_rename
    from_path: str = "",
    to_path: str = "",
    rename_flags: int = 0,
    # file_truncate
    length: int = 0,
) -> bytes:
    """Build the 552-byte file payload.

    Layout:
      off   0  16 bytes kfuncs_used prefix (NUL-padded)
      off  16  depending on event kind:
         file_open:
           off 16  256 bytes path
           off 272  u32   flags
           off 276  u8    mode
           off 277  u8    deny_source
           off 278  u8    result_flags
           off 279  u8    _pad0
         file_create:
           off 16  256 bytes path
           off 272  u32   mode_bits
           off 276  u8    exclusive
           off 277  u8    result_flags
           off 278  u8    _pad0
           off 279  u8    _pad1
         file_unlink:
           off 16  256 bytes path
           off 272  u32   unlink_flags
           off 276  u8    result_flags
           off 277  u8    _pad0
           off 278  u8    _pad1
           off 279  u8    _pad2
         file_rename:
           off 16  256 bytes from_path
           off 272 256 bytes to_path
           off 528  u32   flags
           off 532  u8    result_flags
           off 533  u8    _pad0
           off 534  u8    _pad1
           off 535  u8    _pad2
         file_truncate:
           off 16  256 bytes path
           off 272  u64   length
           off 280  u8    result_flags
           off 281  u8    _pad0
           off 282  u8    _pad1
           off 283  u8    _pad2
    """
    buf = bytearray(PAYLOAD_LEN)
    # kfuncs prefix
    kfuncs_off = 0
    if len(kfuncs_used) > 16:
        raise ValueError(f"kfuncs_used length {len(kfuncs_used)} must be <= 16")
    buf[kfuncs_off:kfuncs_off + len(kfuncs_used)] = kfuncs_used
    # rest is NUL-padded
    return bytes(buf)


def make_open_payload(path: str, flags: int, mode: int,
                      deny_source: int, result_flags: int) -> bytes:
    buf = bytearray(PAYLOAD_LEN)
    write_cstr(buf, 0, "core_read_str_in", 16)  # off 0  kfuncs_used
    write_cstr(buf, 16, path, 256)              # off 16 path
    write_u32(buf, 272, flags)                  # off 272 flags
    write_u8(buf, 276, mode)                    # off 276 mode
    write_u8(buf, 277, deny_source)             # off 277 deny_source
    write_u8(buf, 278, result_flags)            # off 278 result_flags
    # 279 _pad0 — zero
    return bytes(buf)


def make_create_payload(path: str, mode_bits: int,
                        exclusive: bool, result_flags: int) -> bytes:
    buf = bytearray(PAYLOAD_LEN)
    write_cstr(buf, 0, "core_read_str_in", 16)
    write_cstr(buf, 16, path, 256)
    write_u32(buf, 272, mode_bits)
    write_u8(buf, 276, 1 if exclusive else 0)
    write_u8(buf, 277, result_flags)
    return bytes(buf)


def make_unlink_payload(path: str, unlink_flags: int,
                        result_flags: int) -> bytes:
    buf = bytearray(PAYLOAD_LEN)
    write_cstr(buf, 0, "core_read_str_in", 16)
    write_cstr(buf, 16, path, 256)
    write_u32(buf, 272, unlink_flags)
    write_u8(buf, 276, result_flags)
    return bytes(buf)


def make_rename_payload(from_path: str, to_path: str, flags: int,
                        result_flags: int) -> bytes:
    buf = bytearray(PAYLOAD_LEN)
    write_cstr(buf, 0, "core_read_str_in", 16)
    write_cstr(buf, 16, from_path, 256)
    write_cstr(buf, 272, to_path, 256)
    write_u32(buf, 528, flags)
    write_u8(buf, 532, result_flags)
    return bytes(buf)


def make_truncate_payload(path: str, length: int, result_flags: int) -> bytes:
    buf = bytearray(PAYLOAD_LEN)
    write_cstr(buf, 0, "core_read_str_in", 16)
    write_cstr(buf, 16, path, 256)
    write_u64(buf, 272, length)
    write_u8(buf, 280, result_flags)
    return bytes(buf)


# Validate files / paths for the fixture set (must exist on the
# recording host because they are observed paths the brief calls
# for: /tmp/sensor-tests-*).
PATH_READ = "/tmp/sensor-tests-read"
PATH_WRITE = "/tmp/sensor-tests-write"
PATH_CREATE = "/tmp/sensor-tests-create"
PATH_UNLINK = "/tmp/sensor-tests-unlink"
PATH_FROM = "/tmp/sensor-tests-from"
PATH_TO = "/tmp/sensor-tests-to"
PATH_TRUNC = "/tmp/sensor-tests-truncate"


# Common identity header. Each fixture uses a distinct seq + boot_id
# so the per-fixture tests can correlate them.
BOOT_ID = bytes([0xAB, 0xCD]) + (b"\x00" * 12) + bytes([0x12, 0x34])
BASE_SEQ = 0x0102_0304_0506_0708
TS_MONO_NS = 0x1112_1314_1516_1718
PID_TGID = 0x0000_0000_0000_04D2  # 1234
TASK_START = 0x1234_5678_9ABC_DEF0
CGROUP_ID = 0xA1A2_A3A4_A5A6_A7A8
PROCESSOR_ID = 3
NS_PID = 0xFFFF


def base_valids() -> int:
    return (
        VALID_CGROUP_ID | VALID_PID_TGID | VALID_TASK_START
        | VALID_PROCESSOR
    )


# -----------------------------------------------------------------
# Fixture builders
# -----------------------------------------------------------------

def build_open_read() -> bytes:
    valids = base_valids() | VALID_FILE_PATH | VALID_FILE_FLAGS | VALID_FILE_MODE \
        | VALID_FILE_DENY_SOURCE
    h = make_header(
        event_kind=EVENT_FILE_OPEN,
        header_flags=0,
        valids=valids,
        seq=BASE_SEQ,
        ts_mono_ns=TS_MONO_NS,
        boot_id=BOOT_ID,
        pid_tgid=PID_TGID,
        task_start=TASK_START,
        cgroup_id=CGROUP_ID,
        processor_id=PROCESSOR_ID,
        ns_pid=NS_PID,
    )
    p = make_open_payload(
        path=PATH_READ,
        flags=0x0,            # O_RDONLY=0 in openat2
        mode=0x01,            # MAY_READ bit
        deny_source=FILE_DENY_SYSCALL,  # the recorded LSM was unavailable
        result_flags=0,
    )
    return h + p


def build_open_write() -> bytes:
    valids = base_valids() | VALID_FILE_PATH | VALID_FILE_FLAGS | VALID_FILE_MODE \
        | VALID_FILE_DENY_SOURCE
    h = make_header(
        event_kind=EVENT_FILE_OPEN,
        header_flags=0,
        valids=valids,
        seq=BASE_SEQ + 1,
        ts_mono_ns=TS_MONO_NS + 1,
        boot_id=BOOT_ID,
        pid_tgid=PID_TGID + 1,
        task_start=TASK_START + 1,
        cgroup_id=CGROUP_ID,
        processor_id=PROCESSOR_ID,
        ns_pid=NS_PID,
    )
    p = make_open_payload(
        path=PATH_WRITE,
        flags=0x1,            # O_WRONLY
        mode=0x02,            # MAY_WRITE bit
        deny_source=FILE_DENY_SYSCALL,
        result_flags=0,
    )
    return h + p


def build_create() -> bytes:
    valids = base_valids() | VALID_FILE_PATH | VALID_FILE_MODE \
        | VALID_FILE_DENY_SOURCE
    h = make_header(
        event_kind=EVENT_FILE_CREATE,
        header_flags=0,
        valids=valids,
        seq=BASE_SEQ + 2,
        ts_mono_ns=TS_MONO_NS + 2,
        boot_id=BOOT_ID,
        pid_tgid=PID_TGID + 2,
        task_start=TASK_START + 2,
        cgroup_id=CGROUP_ID,
        processor_id=PROCESSOR_ID,
        ns_pid=NS_PID,
    )
    # mode_bits = 0o644 (rw-r--r--) with O_EXCL flag traced as
    # bit 7 of the mode byte (the brief's exclusive byte).
    p = make_create_payload(
        path=PATH_CREATE,
        mode_bits=0o644,
        exclusive=True,
        result_flags=0,
    )
    return h + p


def build_unlink() -> bytes:
    valids = base_valids() | VALID_FILE_PATH | VALID_FILE_FLAGS \
        | VALID_FILE_DENY_SOURCE
    h = make_header(
        event_kind=EVENT_FILE_UNLINK,
        header_flags=0,
        valids=valids,
        seq=BASE_SEQ + 3,
        ts_mono_ns=TS_MONO_NS + 3,
        boot_id=BOOT_ID,
        pid_tgid=PID_TGID + 3,
        task_start=TASK_START + 3,
        cgroup_id=CGROUP_ID,
        processor_id=PROCESSOR_ID,
        ns_pid=NS_PID,
    )
    p = make_unlink_payload(
        path=PATH_UNLINK,
        unlink_flags=0x200,        # AT_REMOVEDIR-like flag
        result_flags=0,
    )
    return h + p


def build_rename() -> bytes:
    valids = base_valids() | VALID_FILE_PATH | VALID_FILE_FLAGS \
        | VALID_FILE_DENY_SOURCE
    h = make_header(
        event_kind=EVENT_FILE_RENAME,
        header_flags=0,
        valids=valids,
        seq=BASE_SEQ + 4,
        ts_mono_ns=TS_MONO_NS + 4,
        boot_id=BOOT_ID,
        pid_tgid=PID_TGID + 4,
        task_start=TASK_START + 4,
        cgroup_id=CGROUP_ID,
        processor_id=PROCESSOR_ID,
        ns_pid=NS_PID,
    )
    p = make_rename_payload(
        from_path=PATH_FROM,
        to_path=PATH_TO,
        flags=1,           # RENAME_NOREPLACE
        result_flags=0,
    )
    return h + p


def build_truncate() -> bytes:
    valids = base_valids() | VALID_FILE_PATH | VALID_FILE_DENY_SOURCE
    h = make_header(
        event_kind=EVENT_FILE_TRUNCATE,
        header_flags=0,
        valids=valids,
        seq=BASE_SEQ + 5,
        ts_mono_ns=TS_MONO_NS + 5,
        boot_id=BOOT_ID,
        pid_tgid=PID_TGID + 5,
        task_start=TASK_START + 5,
        cgroup_id=CGROUP_ID,
        processor_id=PROCESSOR_ID,
        ns_pid=NS_PID,
    )
    p = make_truncate_payload(
        path=PATH_TRUNC,
        length=42,
        result_flags=0,
    )
    return h + p


def build_open_read_degraded() -> bytes:
    """File-open recorded through the syscall-result kprobe because
    BPF LSM was unavailable. The byte-identical header to open_read
    EXCEPT:
      * deny_source = SYSCALL (was already SYSCALL on open_read, but
        this fixture's COMMENT in the test asserts the SYSCALL path
        was taken — so we keep it identical and the test confirms
        the recorder wrote SYSCALL, not NONE).
      * FILE_PATH valid = false (path was unreadable; this is the
        degraded-only marker — the path itself is empty).
      * flags & FILE_RESULT_HAS_ERRNO == 0 (no error).
    """
    valids = base_valids() | VALID_FILE_FLAGS | VALID_FILE_MODE \
        | VALID_FILE_DENY_SOURCE
    h = make_header(
        event_kind=EVENT_FILE_OPEN,
        header_flags=KERNEL_HEADER_FLAGS_TRUNC,  # TRUNC set: path unreadable
        valids=valids,                            # FILE_PATH deliberately NOT set
        seq=BASE_SEQ + 6,
        ts_mono_ns=TS_MONO_NS + 6,
        boot_id=BOOT_ID,
        pid_tgid=PID_TGID + 6,
        task_start=TASK_START + 6,
        cgroup_id=CGROUP_ID,
        processor_id=PROCESSOR_ID,
        ns_pid=NS_PID,
    )
    # Path intentionally empty (the read returned <= 0). flags=0
    # because the syscall-result kprobe path doesn't capture O_*
    # flags on the recorded side; mode=0; deny_source=SYSCALL.
    p = make_open_payload(
        path="",  # path unreadable in this degraded scenario
        flags=0,
        mode=0,
        deny_source=FILE_DENY_SYSCALL,
        result_flags=0,  # FILE_RESULT_HAS_ERRNO NOT set
    )
    return h + p


def main() -> int:
    os.makedirs(FIXTURE_DIR, exist_ok=True)

    fixtures = {
        "open_read": build_open_read(),
        "open_write": build_open_write(),
        "create": build_create(),
        "unlink": build_unlink(),
        "rename": build_rename(),
        "truncate": build_truncate(),
        "open_read_degraded": build_open_read_degraded(),
    }
    for name, blob in fixtures.items():
        path = os.path.join(FIXTURE_DIR, f"{name}.binpb")
        with open(path, "wb") as f:
            f.write(blob)
        print(f"wrote {path} ({len(blob)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
