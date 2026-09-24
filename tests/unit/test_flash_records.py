"""File system records (pico-keys-sdk/src/fs/flash.c) with the real write
cache (low_flash_v2.c) over a model store that checks, at every commit, the
state a power cut would leave (flash_harness.c):

  * records never cross a sector boundary (payload at most 4096 - header);
  * no commit ever holds part of an operation, even when an operation needs
    a sector while the cache is full;
  * a file written from a pointer into another file (possibly into a cached
    sector) gets the right content.

    python -m pytest tests/unit/test_flash_records.py
"""

import ctypes
import os
import random
import struct

import pytest

from conftest import REPO, SDK_SRC, build_shared

HEADER = 2 * struct.calcsize("P") + 4          # next, prev, fid, length
MAX_PAYLOAD = 4096 - HEADER
STORE = 128 * 4096                              # LF_STORE_LOGICAL_SIZE
# fids without bit 0x1000: the allocator never fills the gap above a
# record whose fid has it ("size blocked")


@pytest.fixture(scope="module")
def fs():
    here = os.path.dirname(os.path.abspath(__file__))
    sdk = os.path.join(REPO, "pico-keys-sdk")
    lib = build_shared(
        "flashrec",
        [os.path.join(SDK_SRC, "fs", "flash.c"), os.path.join(SDK_SRC, "fs", "low_flash_v2.c"),
         os.path.join(here, "flash_harness.c")],
        include_dirs=[SDK_SRC, os.path.join(SDK_SRC, "fs"), os.path.join(sdk, "mbedtls", "include")],
        defines=["ENABLE_EMULATION", "LF_STORE_V2",
                 'MBEDTLS_CONFIG_FILE="%s"' % os.path.join(sdk, "config", "mbedtls_config.h")])
    u8p = ctypes.c_char_p
    lib.h_init.restype = None
    lib.h_put.argtypes = [ctypes.c_uint16, ctypes.c_int, u8p, ctypes.c_uint16]
    lib.h_copy.argtypes = [ctypes.c_uint16, ctypes.c_uint16, ctypes.c_int]
    lib.h_delete.argtypes = [ctypes.c_uint16]
    lib.h_plant.argtypes = [ctypes.c_uint16, u8p, ctypes.c_uint16, ctypes.c_uint16]
    lib.h_record.argtypes = [ctypes.c_uint16]
    lib.h_record.restype = ctypes.c_size_t
    lib.h_image.argtypes = [ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
    lib.h_image.restype = None
    lib.h_allow_sector_records.argtypes = [ctypes.c_int]
    lib.h_allow_sector_records.restype = None
    lib.h_stress.argtypes = [ctypes.c_int, ctypes.c_uint]
    lib.h_txn_begin.restype = None
    lib.h_damage_next.argtypes = [ctypes.c_uint16, ctypes.c_size_t]
    lib.h_last_error.restype = ctypes.c_char_p
    lib.h_free.restype = ctypes.c_uint32
    return lib


def image(fs, off, n):
    buf = ctypes.create_string_buffer(n)
    fs.h_image(off, buf, n)
    return buf.raw


def healthy(fs):
    assert fs.h_failures() == 0, fs.h_last_error().decode()
    assert fs.h_verify_view() == 0


def test_payload_limit_is_a_sector_minus_the_header(fs):
    fs.h_init()
    assert fs.h_put(0xC001, 0, os.urandom(MAX_PAYLOAD), MAX_PAYLOAD) == 0
    for n in (MAX_PAYLOAD + 1, MAX_PAYLOAD + 4, 4095, 4096):
        assert fs.h_put(0xC002, 0, os.urandom(n), n) != 0, n
    # the refusals left nothing behind: the list takes new files as before
    for i in range(40):
        data = os.urandom(300)
        assert fs.h_put(0xC100 + i, 0, data, len(data)) == 0
    # and a record of the largest size in the middle of them
    assert fs.h_put(0xC002, 0, os.urandom(MAX_PAYLOAD), MAX_PAYLOAD) == 0
    assert fs.h_commit() == 0
    healthy(fs)


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_no_commit_holds_part_of_an_operation(fs, seed):
    """Random creates, rewrites, deletes and copies with commits in between
    (as command boundaries): every commit, also those forced by a full cache
    inside a command, holds whole operations only."""
    rnd = random.Random(seed)
    fs.h_init()
    fids = [0xC000 + i for i in range(48)] + [0xE100 + i for i in range(6)]
    persistent = {f: f >= 0xE100 for f in fids}
    present = set()
    forced = 0
    for step in range(1500):
        fid = rnd.choice(fids)
        before = fs.h_commits()
        kind = rnd.random()
        if kind < 0.55:
            n = rnd.choice([rnd.randrange(1, 200), rnd.randrange(200, 1500), rnd.randrange(1500, MAX_PAYLOAD + 1)])
            if persistent[fid]:
                n = rnd.randrange(1, 600)
            rc = fs.h_put(fid, persistent[fid], os.urandom(n), n)
            if rc == 0:
                present.add(fid)
        elif kind < 0.8:
            rc = fs.h_delete(fid)
            assert rc == 0
            present.discard(fid)
        elif present:
            src = rnd.choice(sorted(f for f in present if not persistent[f]) or [None])
            if src is not None and not persistent[fid] and fid != src:
                if fs.h_copy(src, fid, 0) == 0:
                    present.add(fid)
        forced += fs.h_commits() > before
        if rnd.random() < 0.3:
            assert fs.h_commit() == 0
        assert fs.h_failures() == 0, (step, fs.h_last_error().decode())
        if step % 50 == 0:
            assert fs.h_verify_view() == 0, step
    assert fs.h_commit() == 0
    healthy(fs)
    assert forced > 0, "no operation ran into a full cache: the test proves nothing"


@pytest.mark.parametrize("size", range(MAX_PAYLOAD + 1, 4097))
def test_records_of_earlier_firmware_up_to_a_sector(fs, size):
    """Earlier firmware stored payloads up to 4096 bytes, ending at a sector
    boundary with the header in the sector below. They stay readable,
    rewritable in place (same size, smaller), deletable; applications cannot
    grow them past the limit (the old content stays), carried data can."""
    fs.h_init()
    above = {0xC100 + i: os.urandom(700) for i in range(3)}
    for fid, data in above.items():
        assert fs.h_put(fid, 0, data, len(data)) == 0
    old = os.urandom(size)
    assert fs.h_plant(0xC001, old, size, size) == 0
    healthy(fs)
    same = os.urandom(size)
    assert fs.h_put(0xC001, 0, same, size) == 0            # in place, same size
    assert fs.h_commit() == 0
    healthy(fs)
    smaller = os.urandom(size - 100)
    assert fs.h_put(0xC001, 0, smaller, len(smaller)) == 0
    assert fs.h_commit() == 0
    healthy(fs)
    # growing it again is a new record: over the limit, refused, content kept
    assert fs.h_put(0xC001, 0, os.urandom(size), size) != 0
    assert fs.h_commit() == 0
    healthy(fs)
    assert fs.h_delete(0xC001) == 0
    assert fs.h_commit() == 0
    healthy(fs)
    # a new record of that size: refused for applications, taken for carried data
    assert fs.h_put(0xC002, 0, os.urandom(size), size) != 0
    fs.h_allow_sector_records(1)
    carried = os.urandom(size)
    assert fs.h_put(0xC002, 0, carried, size) == 0
    fs.h_allow_sector_records(0)
    assert fs.h_commit() == 0
    healthy(fs)
    assert fs.h_delete(0xC002) == 0
    assert fs.h_commit() == 0
    healthy(fs)


def test_old_record_grown_past_the_limit_keeps_its_content(fs):
    fs.h_init()
    old = os.urandom(4088)
    assert fs.h_plant(0xC001, old, len(old), len(old)) == 0
    assert fs.h_put(0xC001, 0, os.urandom(4090), 4090) != 0
    assert fs.h_commit() == 0
    healthy(fs)


def test_damaged_length_is_bounded_by_the_sector(fs):
    """A 4095-byte record of earlier firmware whose length write was lost
    (0xFFFF): rewriting it smaller, then deleting it, touches nothing
    outside its sector, and every other record stays as it was."""
    fs.h_init()
    above = {0xC100 + i: os.urandom(1500) for i in range(20)}
    for fid, data in above.items():
        assert fs.h_put(fid, 0, data, len(data)) == 0
    payload = os.urandom(4095)
    assert fs.h_plant(0xC001, payload, 4095, 0xFFFF) == 0
    rec = fs.h_record(0xC001)
    sector_end = rec + HEADER + 4095
    span = min(64 * 1024, STORE - sector_end)
    before = image(fs, sector_end, span)
    new = os.urandom(200)
    assert fs.h_put(0xC001, 0, new, len(new)) == 0          # in place: the length is repaired
    assert fs.h_commit() == 0
    healthy(fs)
    assert image(fs, sector_end, span) == before            # beyond the record: untouched
    assert fs.h_delete(0xC001) == 0
    assert fs.h_commit() == 0
    healthy(fs)
    for fid, data in above.items():
        assert fs.h_put(fid, 0, data, len(data)) == 0       # the neighbours: intact and writable
    assert fs.h_commit() == 0
    healthy(fs)


def test_damaged_next_pointer_ends_the_list_and_is_repaired(fs):
    """The last record's next pointer was never written (0xFF...): new
    records still find room (linked where the damage was), and the damaged
    record can be deleted without its pointer spreading."""
    fs.h_init()
    for i in range(4):
        assert fs.h_put(0xC100 + i, 0, os.urandom(500), 500) == 0
    assert fs.h_damage_next(0xC103, (1 << (8 * struct.calcsize("P"))) - 1) == 0
    assert fs.h_put(0xC200, 0, os.urandom(300), 300) == 0
    assert fs.h_commit() == 0
    healthy(fs)
    assert fs.h_delete(0xC103) == 0
    assert fs.h_put(0xC201, 0, os.urandom(300), 300) == 0
    assert fs.h_commit() == 0
    healthy(fs)


@pytest.mark.parametrize("seed", [7, 8])
def test_commits_of_another_task_never_split_an_operation(fs, seed):
    """Core 0 commits (reboot, profile switch, OTP typing) while the card
    thread runs file system operations: every commit holds whole
    operations."""
    fs.h_init()
    made = fs.h_stress(3000, seed)
    assert made > 0
    assert fs.h_commit() == 0
    healthy(fs)


def test_abandoned_transaction_leaves_the_store_as_before(fs):
    """A handler abandons its command (a half-written PIN change): nothing it
    wrote is committed, except what it committed itself on purpose (the
    retry counter), and the file table is the store's again."""
    fs.h_init()
    base = {0xC100 + i: os.urandom(300 + 50 * i) for i in range(6)}
    for fid, data in base.items():
        assert fs.h_put(fid, 0, data, len(data)) == 0
    assert fs.h_commit() == 0
    before = image(fs, 0, STORE)

    fs.h_txn_begin()
    assert fs.h_put(0xC100, 0, b"x" * 50, 50) == 0            # in place
    assert fs.h_put(0xC101, 0, os.urandom(900), 900) == 0     # moved
    assert fs.h_put(0xC200, 0, os.urandom(64), 64) == 0       # new
    assert fs.h_delete(0xC102) == 0
    assert fs.h_txn_abort() == 0
    assert fs.h_txn_end() == 0
    healthy(fs)
    assert image(fs, 0, STORE) == before

    # what the handler committed itself stays
    fs.h_txn_begin()
    assert fs.h_put(0xC103, 0, b"\x02", 1) == 0               # the retry counter
    assert fs.h_txn_commit() == 0
    kept = image(fs, 0, STORE)
    assert fs.h_put(0xC104, 0, os.urandom(1200), 1200) == 0
    assert fs.h_delete(0xC105) == 0
    assert fs.h_txn_abort() == 0
    assert fs.h_txn_end() == 0
    healthy(fs)
    assert image(fs, 0, STORE) == kept

    # the store keeps working afterwards
    for fid, data in base.items():
        assert fs.h_put(fid, 0, data[::-1], len(data)) == 0
    assert fs.h_commit() == 0
    healthy(fs)


def test_transaction_split_by_a_full_cache_cannot_be_abandoned(fs):
    """Once part of the command reached the store unasked (the cache was
    full), abandoning it is refused and nothing is dropped: the command ends
    whole instead of half."""
    fs.h_init()
    fs.h_txn_begin()
    for i in range(24):
        assert fs.h_put(0xC300 + i, 0, os.urandom(3000), 3000) == 0
    assert fs.h_commits() > 1                                 # the cache overflowed
    assert fs.h_txn_abort() != 0
    assert fs.h_txn_end() == 0
    healthy(fs)


def test_copy_from_a_sector_the_cache_gives_away(fs):
    """PIV's MOVE KEY and similar code hand a pointer into the file system
    (possibly into a cached sector) to a write that needs other sectors."""
    fs.h_init()
    # eight dirty sectors in the cache, the source among them
    for i in range(8):
        data = bytes([i]) * 3900
        assert fs.h_put(0xC100 + i, 0, data, len(data)) == 0
    for i in range(8):
        assert fs.h_copy(0xC100 + i, 0xC200 + i, 0) == 0
        healthy(fs)
    assert fs.h_commit() == 0
    healthy(fs)
