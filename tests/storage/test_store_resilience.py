"""Resilient store (pico-keys-sdk/src/fs/lf_store.c) on the host emulator.

Damage is injected directly into the emulator's flash file, power cuts with
LF_FAULT_OPS (the N-th flash erase/write tears and the process dies). The
device must come back with every committed credential intact.

    python -m pytest tests/storage
"""

import os
import random
import re
import shutil
import struct
import time

import pytest

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2

from harness import ctaphid
from harness.emulator import Emulator

# Emulator flash layout (lf_region.c) and store layout (lf_store.c).
SECTOR = 4096
EMU_SYS = 0x800000
EMU_STORE0 = 0x890000
LS = 128
S_A, S_B, S_META_A, S_META_B = 35, 163, 291, 313
META_PER_SECTOR = 6
META_ENTRY = 636

MOUNT_RE = re.compile(
    r"\[lf_store\] profile (\d+) mounted \(region (\d+)\): (\d+) sectors, (\d+) repaired, "
    r"(\d+) ecc-corrected, (\d+) unrecoverable, (\d+) metadata repaired, journal (\w+)")


def mounts(emu, since=0):
    with open(emu.log_path, errors="replace") as f:
        f.seek(since)
        found = MOUNT_RE.findall(f.read())
    keys = ("profile", "region", "sectors", "repaired", "ecc", "unrecoverable", "meta", "journal")
    return [dict(zip(keys, [int(v) for v in m[:7]] + [m[7]])) for m in found]


def last_mount(emu, timeout=10.0):
    """Mount report of the running emulator instance (the HID port opens
    before storage bring-up finishes, so wait for it)."""
    deadline = time.time() + timeout
    while True:
        m = mounts(emu, emu.log_start)
        if m or time.time() > deadline:
            break
        time.sleep(0.05)
    assert m, "no mount line in %s" % emu.log_path
    return m[-1]


@pytest.fixture
def emu(tmp_path):
    ctaphid.install()
    e = Emulator(workdir=str(tmp_path / "dev"))
    e.start()
    yield e
    e.stop()


def ctap2():
    dev = ctaphid.open_device()
    return dev, Ctap2(dev)


def make_rk(user_id, rp="example.com"):
    dev, c = ctap2()
    try:
        return c.make_credential(os.urandom(32), {"id": rp, "name": rp},
                                 {"id": user_id, "name": "u", "displayName": "U"},
                                 [{"type": "public-key", "alg": -7}], options={"rk": True})
    finally:
        dev.close()


def user_ids(rp="example.com"):
    """User IDs of the discoverable credentials of rp."""
    dev, c = ctap2()
    try:
        try:
            first = c.get_assertion(rp, os.urandom(32))
        except CtapError as e:
            if e.code == CtapError.ERR.NO_CREDENTIALS:
                return set()
            raise
        found = {first.user["id"]}
        for _ in range((first.number_of_credentials or 1) - 1):
            found.add(c.get_next_assertion().user["id"])
        return found
    finally:
        dev.close()


def sector_off(region_sector, lsn=0):
    return EMU_STORE0 + (region_sector + lsn) * SECTOR


def read_at(path, off, n):
    with open(path, "rb") as f:
        f.seek(off)
        return f.read(n)


def flip_bytes(path, off, positions, rnd):
    with open(path, "r+b") as f:
        for p in positions:
            f.seek(off + p)
            b = f.read(1)[0]
            f.seek(off + p)
            f.write(bytes([b ^ rnd.randrange(1, 256)]))


def written_sectors(path):
    data = read_at(path, sector_off(S_A), LS * SECTOR)
    return [i for i in range(LS) if data[i * SECTOR:(i + 1) * SECTOR] != b"\xff" * SECTOR]


def test_fresh_device_formats_profile_one(emu):
    m = last_mount(emu)
    assert m["profile"] == 1 and m["region"] == 0 and m["unrecoverable"] == 0
    assert read_at(emu.flash_path, EMU_STORE0, 4) == b"LFST"


def test_credentials_survive_restart(emu):
    make_rk(b"alice")
    emu.restart()
    assert user_ids() == {b"alice"}
    assert last_mount(emu)["journal"] == "clean"


@pytest.mark.parametrize("copy", ["A", "B"])
def test_damaged_copy_is_rebuilt_from_the_other(emu, copy):
    make_rk(b"alice")
    emu.stop()
    secs = written_sectors(emu.flash_path)
    assert secs
    rnd = random.Random(1)
    base = S_A if copy == "A" else S_B
    for lsn in secs:
        flip_bytes(emu.flash_path, sector_off(base, lsn), rnd.sample(range(SECTOR), 50), rnd)
    emu.start()
    m = last_mount(emu)
    assert m["repaired"] == len(secs) and m["unrecoverable"] == 0
    assert user_ids() == {b"alice"}
    emu.restart()
    assert last_mount(emu)["repaired"] == 0


def test_both_copies_damaged_are_corrected_by_ecc(emu):
    make_rk(b"alice")
    emu.stop()
    secs = written_sectors(emu.flash_path)
    rnd = random.Random(2)
    for lsn in secs:
        for base in (S_A, S_B):
            # up to 10 bad bytes in every 223 byte Reed-Solomon block
            for blk in range(0, SECTOR, 223):
                span = range(blk, min(blk + 223, SECTOR))
                flip_bytes(emu.flash_path, sector_off(base, lsn), rnd.sample(span, min(10, len(span))), rnd)
    emu.start()
    m = last_mount(emu)
    assert m["ecc"] == len(secs) and m["unrecoverable"] == 0
    assert user_ids() == {b"alice"}
    emu.restart()
    assert last_mount(emu)["ecc"] == 0


def test_unrecoverable_sector_is_reported_not_hidden(emu):
    make_rk(b"alice")
    emu.stop()
    secs = written_sectors(emu.flash_path)
    rnd = random.Random(3)
    victim = secs[0]
    for base in (S_A, S_B):
        flip_bytes(emu.flash_path, sector_off(base, victim), rnd.sample(range(0, 223), 60), rnd)
    emu.start()
    m = last_mount(emu)
    assert m["unrecoverable"] == 1


def test_damaged_metadata_copy_is_rebuilt(emu):
    make_rk(b"alice")
    emu.stop()
    lsn = written_sectors(emu.flash_path)[0]
    entry = sector_off(S_META_A) + (lsn // META_PER_SECTOR) * SECTOR + (lsn % META_PER_SECTOR) * META_ENTRY
    flip_bytes(emu.flash_path, entry, range(40, 60), random.Random(4))
    emu.start()
    m = last_mount(emu)
    assert m["meta"] >= 1 and m["unrecoverable"] == 0
    assert user_ids() == {b"alice"}
    emu.restart()
    assert last_mount(emu)["meta"] == 0


def sys_generations(path):
    gens = {}
    for slot in range(16):
        head = read_at(path, EMU_SYS + slot * SECTOR, 16)
        if head[:4] == b"LFSY":
            gens[slot] = struct.unpack_from("<Q", head, 8)[0]
    return gens


def test_system_record_falls_back_to_its_twin(emu):
    make_rk(b"alice")
    emu.stop()
    gens = sys_generations(emu.flash_path)
    newest = max(gens.values())
    slots = sorted(s for s, g in gens.items() if g == newest)
    assert len(slots) == 2
    # damage one copy beyond what its Reed-Solomon parity can repair
    flip_bytes(emu.flash_path, EMU_SYS + slots[0] * SECTOR, range(16, 80), random.Random(5))
    emu.start()
    assert user_ids() == {b"alice"}
    assert max(sys_generations(emu.flash_path).values()) == newest + 1  # rewritten twice


def test_power_cut_at_every_flash_operation(tmp_path):
    """makeCredential interrupted at each successive flash operation: after
    the reboot the store is consistent, the old credential is intact, the new
    one exists if (and only if possibly) it was acknowledged, and the device
    keeps working."""
    ctaphid.install()
    base = Emulator(workdir=str(tmp_path / "base"))
    base.start()
    make_rk(b"u1")
    base.stop()

    completed_without_fault = False
    acknowledged_cuts = 0
    for n in range(0, 300):
        wd = tmp_path / ("n%03d" % n)
        shutil.copytree(base.workdir, wd, ignore=shutil.ignore_patterns("emulator.log"))
        e = Emulator(workdir=str(wd))
        try:
            acked = False
            try:
                e.start(LF_FAULT_OPS=n)
                try:
                    make_rk(b"u2")
                    acked = True
                except Exception:
                    pass
            except RuntimeError:
                pass    # the cut hit a boot-time write
            died = e.proc is None or e.proc.poll() is not None or _wait_exit(e)
            e.stop()
            if acked and not died:
                completed_without_fault = True
                cuts = n
                break
            acknowledged_cuts += acked
            e.start()
            m = last_mount(e)
            assert m["unrecoverable"] == 0 and m["journal"] != "corrupt", (n, m)
            ids = user_ids()
            assert b"u1" in ids, (n, ids)
            if acked:
                assert b"u2" in ids, (n, ids)
            make_rk(b"u3")
            assert b"u3" in user_ids(), n
        finally:
            e.stop()
    assert completed_without_fault
    # A one-sector transaction is 14 flash operations: data and metadata
    # image into the journal (2 x erase+write), COMMIT record, copy A, metadata
    # A, copy B, metadata B (4 x erase+write) and the APPLIED record. Every one
    # of them was interrupted once above.
    assert cuts >= 14, cuts
    print("power cut at %d different flash operations, %d after the reply" % (cuts, acknowledged_cuts))


def _wait_exit(e, timeout=0.5):
    try:
        e.proc.wait(timeout)
        return True
    except Exception:
        return False
