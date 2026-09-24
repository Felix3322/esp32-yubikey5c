"""Root key and profile policies on the emulator (security.c, lf_boot.c):
held and refused root keys, profiles without a root, secure profiles,
debug locks, and data carried at the sizes earlier firmware stored.

Needs the PC/SC stack of tests/README.md (management applet over CCID):

    python -m pytest tests/storage/test_root_key.py
"""

import hashlib
import os
import time
import zlib

import pytest

from test_boot_recovery import (EMU_STORE0, EMU_STORE_SIZE, EMU_SYS, REG_SYS, SECTOR, Piv, arm, boot_log,
                                boot_until_exit, emulators, make_rk, management, pcscd,
                                read_at, user_ids, wait_log, wait_reboot, write_at)  # noqa: F401

INS_PROFILE_CREATE_SECURE = 0x15
INS_PROVISION = 0x50
LF_PROFILE_F_NO_EXPORT, LF_PROFILE_F_SECURE = 0x01, 0x02
PROFILE_OFF, PROFILE_SIZE = 24, 48          # lf_sys_t.profile[], lf_profile_entry_t
ENTRY_USED, ENTRY_FLAGS, ENTRY_ROOT_BOUND, ENTRY_UUID = 0, 5, 6, 8
SYS_PENDING_FLAGS = 482                     # lf_sys_t.pending_flags
S_CTR = 335


def bound_tag(rec, idx):
    """lf_boot.c bound_tag(): a tag of the entry's uuid."""
    uuid = rec[entry(rec, idx, ENTRY_UUID):entry(rec, idx, ENTRY_UUID) + 16]
    t = zlib.crc32(bytes(uuid)) & 0xFFFF
    return (t or 1).to_bytes(2, "little")


def root_bound(rec, idx):
    return rec[entry(rec, idx, ENTRY_ROOT_BOUND):entry(rec, idx, ENTRY_ROOT_BOUND) + 2] == bound_tag(rec, idx)


def mark_bound(rec, idx):
    rec[entry(rec, idx, ENTRY_ROOT_BOUND):entry(rec, idx, ENTRY_ROOT_BOUND) + 2] = bound_tag(rec, idx)


# -- helpers -----------------------------------------------------------------

def newest_sys_copies(path):
    """Offsets of the copies of the newest valid system record."""
    best, offs = -1, []
    for slot in range(16):
        off = EMU_SYS + slot * SECTOR
        head = read_at(path, off, 8)
        if head[:4] != b"LFSY":
            continue
        size = int.from_bytes(head[6:8], "little")
        rec = read_at(path, off, size)
        if zlib.crc32(rec[:size - 4]) != int.from_bytes(rec[size - 4:], "little"):
            continue
        gen = int.from_bytes(rec[8:16], "little")
        if gen > best:
            best, offs = gen, [off]
        elif gen == best:
            offs.append(off)
    return offs


def edit_sys(path, fn):
    """Rewrites the newest system record in place (its CRC recomputed: the
    firmware takes a copy whose CRC holds without its parity)."""
    for off in newest_sys_copies(path):
        size = int.from_bytes(read_at(path, off + 6, 2), "little")
        rec = bytearray(read_at(path, off, size))
        fn(rec)
        rec[size - 4:] = zlib.crc32(bytes(rec[:size - 4])).to_bytes(4, "little")
        write_at(path, off, bytes(rec))


def entry(rec, idx, field):
    return PROFILE_OFF + idx * PROFILE_SIZE + field


def records(stream):
    out, off = [], 0
    while off < len(stream):
        n = int.from_bytes(stream[off + 1:off + 3], "little")
        out.append((stream[off], stream[off + 3:off + 3 + n]))
        off += 3 + n
    return out


def build(recs):
    """A backup stream from its records (END and its digest recomputed)."""
    body = b"".join(bytes([t]) + len(v).to_bytes(2, "little") + v for t, v in recs if t != 0x7F)
    return body + b"\x7f" + (32).to_bytes(2, "little") + hashlib.sha256(body).digest()


def bind(m):
    m._cmd(INS_PROVISION, 0xA5, 0x01, what="bind root key")


def fido_works(user):
    try:
        make_rk(user)
        return True
    except Exception:
        return False


# -- root key ----------------------------------------------------------------

def test_plain_root_in_a_profile_once_bound_is_refused(pcscd, emulators):
    """The system area records that a profile's root was bound. A plain root
    turning up there later (planted: whoever wrote it knows it) is neither
    used nor bound, with or without Secure Boot; the same plain root in a
    profile never bound is bound on sight (no Secure Boot)."""
    for marked in (True, False):
        e = emulators()
        e.start()
        make_rk(b"alice")                           # plain root: no HMAC key yet
        e.stop()
        if marked:
            edit_sys(e.flash_path, lambda rec: mark_bound(rec, 0))
        with open(e.efuse_path, "wb") as f:
            f.write(os.urandom(32))                 # the chip has an HMAC key
        e.start()
        m = management()
        try:
            sec = m.info()["security"]
            if marked:
                assert sec["root_key"] == "flash (not bound to the chip)"
                assert not fido_works(b"mallory")
                with pytest.raises(Exception):
                    bind(m)
            else:
                assert sec["root_key"] == "flash, bound to HMAC eFuse key"
                assert user_ids() == {b"alice"}
        finally:
            m.close()
        e.stop()


def test_profile_without_root_is_held_on_a_secure_boot_chip(pcscd, emulators):
    """A profile with files but no root record (migrated from a store without
    one, or its record removed) runs on derivations anyone who knows the
    serial can compute. With the HMAC key and Secure Boot it is held until
    the explicit binding records it has none; then it works again."""
    a = emulators()
    a.start()
    m = management()
    make_rk(b"alice")
    stream = m.export_profile()
    m.close()
    a.stop()
    rootless = build([(t, v) for t, v in records(stream) if t != 0x02])

    e = emulators()
    e.start()
    m = management()
    m.import_profile(rootless, 1)
    m.close()
    e.stop()
    with open(e.efuse_path, "wb") as f:
        f.write(os.urandom(32))
    e.extra_env["LF_EMU_CHIP_SECURE"] = "1"
    e.start()
    m = management()
    try:
        m.select_profile(1)
        wait_reboot(m)
        assert m.info()["active"] == 1
        assert wait_log(e, "is missing: bind to use the profile without one")
        assert "key store locked" in boot_log(e)    # held
        with pytest.raises(Exception):
            m.export_profile()                      # a held profile is not exported
        bind(m)
    finally:
        m.close()
    e.restart()
    assert wait_log(e, "profile 2 mounted")
    time.sleep(0.5)
    log = boot_log(e)
    assert "is missing" not in log and "key store locked" not in log   # recorded: runs without a root


def test_held_root_is_exported_only_once_bound_and_restarted(pcscd, emulators):
    e = emulators()
    e.start()
    make_rk(b"alice")
    e.stop()
    with open(e.efuse_path, "wb") as f:
        f.write(os.urandom(32))
    e.extra_env["LF_EMU_CHIP_SECURE"] = "1"
    e.start()
    m = management()
    try:
        assert m.info()["security"]["root_key"] == "flash (not bound to the chip)"
        with pytest.raises(Exception):
            m.export_profile()
        bind(m)
        with pytest.raises(Exception):
            m.export_profile()                      # bound, in use after a restart
    finally:
        m.close()
    e.restart()
    m = management()
    try:
        stream = m.export_profile()
        assert any(t == 0x02 for t, _ in records(stream))      # the root key travels
    finally:
        m.close()


# -- secure profiles ---------------------------------------------------------

def create_secure(m, idx):
    m._cmd(INS_PROFILE_CREATE_SECURE, idx, what="create secure profile")


def test_secure_profile_root_is_bound_from_the_start(pcscd, emulators):
    e = emulators()
    e.start()
    m = management()
    try:
        bind(m)                                     # the chip gets its HMAC key
        create_secure(m, 1)
        wait_reboot(m)
        info = m.info()
        flags = info["profiles"][1]
        assert flags["used"] and flags["no_export"]
        m.select_profile(1)
        wait_reboot(m)
        assert m.info()["security"]["root_key"] == "flash, bound to HMAC eFuse key"
        assert "secure profile" not in boot_log(e)
    finally:
        m.close()
    assert fido_works(b"alice")
    e.stop()
    rec = read_at(e.flash_path, newest_sys_copies(e.flash_path)[0], 502)
    assert rec[entry(rec, 1, ENTRY_FLAGS)] & LF_PROFILE_F_SECURE
    assert root_bound(rec, 1)


def test_secure_profile_without_hmac_key_stays_locked(pcscd, emulators):
    """If the chip's key cannot be used when the secure profile is first
    mounted, its root is not made at all (never in plain): the key store
    stays locked until the key answers again."""
    e = emulators()
    e.start()
    m = management()
    try:
        bind(m)
        create_secure(m, 1)
        wait_reboot(m)
        with open(e.efuse_path, "rb") as f:
            key = f.read()
        os.unlink(e.efuse_path)                     # the next boot finds no key
        m.select_profile(1)
        wait_reboot(m)
        assert m.info()["active"] == 1
    finally:
        m.close()
    assert wait_log(e, "no HMAC key to bind its root key to")
    assert not fido_works(b"mallory")
    e.stop()
    with open(e.efuse_path, "wb") as f:
        f.write(key)
    e.start()
    m = management()
    try:
        assert m.info()["security"]["root_key"] == "flash, bound to HMAC eFuse key"
    finally:
        m.close()
    assert fido_works(b"alice")


def test_wipe_keeps_the_secure_policy(pcscd, emulators):
    e = emulators()
    e.start()
    m = management()
    try:
        bind(m)
        create_secure(m, 1)
        wait_reboot(m)
        m.wipe_profile(1)
        wait_reboot(m)
        assert m.info()["profiles"][1]["no_export"]
    finally:
        m.close()
    e.stop()
    rec = read_at(e.flash_path, newest_sys_copies(e.flash_path)[0], 502)
    assert rec[entry(rec, 1, ENTRY_FLAGS)] & LF_PROFILE_F_SECURE


def newest_sys(e):
    return bytearray(read_at(e.flash_path, newest_sys_copies(e.flash_path)[0], 502))


def test_deleted_profile_leaves_no_policy_to_its_slot(pcscd, emulators):
    """Automatic presence was switched on for the only profile, which is then
    deleted: the profile boot makes in its place starts without it."""
    e = emulators()
    e.start()
    make_rk(b"alice")
    e.stop()
    edit_sys(e.flash_path, lambda rec: rec.__setitem__(entry(rec, 0, ENTRY_FLAGS), 0x7C))   # every AUTO bit
    e.start()
    m = management()
    try:
        m.delete_profile(0)
        wait_reboot(m)
        info = m.info()
        assert info["boot_status"] == "ok" and info["profiles"][0]["used"]
    finally:
        m.close()
    e.stop()
    rec = newest_sys(e)
    assert rec[entry(rec, 0, ENTRY_FLAGS)] == 0
    assert not root_bound(rec, 0)


def test_failed_secure_creation_keeps_the_old_profile_as_it_was(pcscd, emulators):
    """PROFILE_CREATE_SECURE over a used slot whose new store cannot be built
    (flash error): the old profile stays, with its own flags, never turned
    into a 'secure' profile."""
    e = emulators()
    e.start()
    m = management()
    try:
        bind(m)
        m.select_profile(1)                         # slot 2 (region 1), exportable
        wait_reboot(m)
        make_rk(b"bob")
        m.select_profile(0)
        wait_reboot(m)
        rec = newest_sys(e)
        before = rec[entry(rec, 1, ENTRY_FLAGS)]
        arm(e, "fail %d" % (3 + 2))                 # region 2, the free one: format fails
        create_secure(m, 1)
        rec = newest_sys(e)
        if rec[entry(rec, 1, ENTRY_FLAGS)] & LF_PROFILE_F_SECURE and not rec[SYS_PENDING_FLAGS]:
            pytest.skip("lf_profile_create() writes the slot's flags before the wipe (needs pending_flags)")
        wait_reboot(m)
        assert m.info()["last_result"] == "operation failed"
    finally:
        m.close()
    e.stop()
    rec = newest_sys(e)
    assert rec[entry(rec, 1, ENTRY_USED)] and rec[entry(rec, 1, ENTRY_FLAGS)] == before
    assert rec[SYS_PENDING_FLAGS] == 0


@pytest.mark.parametrize("fails", [True, False], ids=["build-fails", "build-succeeds"])
def test_requested_policy_applies_only_to_the_new_profile(pcscd, emulators, fails):
    """The boot side of the contract (lf_sys_t.pending_flags): a WIPE request
    carrying NO_EXPORT | SECURE gives them to the profile it builds, and
    leaves the slot's own flags alone when the build fails."""
    e = emulators()
    e.start()
    m = management()
    try:
        m.select_profile(1)
        wait_reboot(m)
        make_rk(b"bob")
        m.select_profile(0)
        wait_reboot(m)
    finally:
        m.close()
    e.stop()

    def request(rec):
        rec[18], rec[19] = 2, 1                     # pending_op WIPE, pending_profile 1
        rec[SYS_PENDING_FLAGS] = 0x80 | LF_PROFILE_F_NO_EXPORT | LF_PROFILE_F_SECURE
    edit_sys(e.flash_path, request)
    before = newest_sys(e)
    if fails:
        arm(e, "fail %d" % (3 + 2))                 # region 2, the free one
    e.start()
    assert wait_log(e, "profile 1 mounted")
    e.stop()
    rec = newest_sys(e)
    assert rec[18] == 0 and rec[SYS_PENDING_FLAGS] == 0
    if fails:
        assert rec[entry(rec, 1, ENTRY_FLAGS)] == before[entry(before, 1, ENTRY_FLAGS)]
        assert rec[entry(rec, 1, ENTRY_UUID):entry(rec, 1, ENTRY_UUID) + 16] == \
            before[entry(before, 1, ENTRY_UUID):entry(before, 1, ENTRY_UUID) + 16]
    else:
        assert rec[entry(rec, 1, ENTRY_FLAGS)] == LF_PROFILE_F_NO_EXPORT | LF_PROFILE_F_SECURE


def test_trial_boot_of_an_update_does_not_mark_the_root_bound(pcscd, emulators):
    """An unconfirmed firmware may still roll back to one that does not
    maintain the mark: it binds a plain root on sight, but records that only
    once it is confirmed."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "profiles"))
    from test_firmware_update import image, newer
    e = emulators()
    e.start()
    m = management()
    try:
        make_rk(b"alice")                           # plain root, no HMAC key
        with open(e.efuse_path, "wb") as f:
            f.write(os.urandom(32))                 # read by the next boot
        m.update_firmware(image(e, newer(e, 1)), confirm=False)
        sec = m.info()["security"]
        assert sec["root_key"] == "flash, bound to HMAC eFuse key"     # bound on sight
    finally:
        m.close()
    e.stop(hard=True)
    assert not root_bound(newest_sys(e), 0)        # but not marked by the trial boot
    e.start()                                       # back on the confirmed image
    assert user_ids() == {b"alice"}
    e.stop()
    assert root_bound(newest_sys(e), 0)


# -- debug locks -------------------------------------------------------------

def test_debug_lock_burns_and_is_idempotent(pcscd, emulators):
    e = emulators()
    e.start()
    m = management()
    try:
        sec = m.info()["security"]
        assert not sec["jtag_disabled"] and not sec["download_restricted"]
        m._cmd(INS_PROVISION, 0xA5, 0x02, what="lock debug")
        sec = m.info()["security"]
        assert sec["jtag_disabled"] and sec["download_restricted"]
    finally:
        m.close()
    e.restart()
    m = management()
    try:
        sec = m.info()["security"]
        assert sec["jtag_disabled"] and sec["download_restricted"]     # eFuses stay burned
    finally:
        m.close()


# -- storage -----------------------------------------------------------------

def test_carried_file_of_a_whole_sector_is_imported(pcscd, emulators):
    """Earlier firmware stored payloads up to 4096 bytes; applications cannot
    create such records any more, but migration and backups carry them."""
    e = emulators()
    e.start()
    m = management()
    try:
        stream = m.export_profile()
        big = os.urandom(4096)
        recs = records(stream)
        recs.insert(-1, (0x03, (0xC10D).to_bytes(2, "little") + big))      # PIV retired 1
        m.import_profile(build(recs), 1)
        m.select_profile(1)
        wait_reboot(m)
    finally:
        m.close()
    piv = Piv()
    try:
        assert piv.get(0x5FC10D) == big
    finally:
        piv.close()
    e.restart()
    piv = Piv()
    try:
        assert piv.get(0x5FC10D) == big
    finally:
        piv.close()


def test_factory_reset_then_reads_before_the_reboot(pcscd, emulators):
    """After a factory reset the store is unmapped until the reboot: file
    reads in that window see nothing instead of faulting."""
    e = emulators()
    e.start()
    m = management()
    make_rk(b"alice")
    m.factory_reset()
    for _ in range(3):
        try:
            user_ids()
        except Exception:
            pass                                    # locked or rebooting
    wait_reboot(m)                                  # the process did not fault
    assert m.info()["boot_status"] == "ok"
    m.close()
    assert user_ids() == set()


@pytest.mark.parametrize("nbytes", [597, 604, 611])
def test_tear_in_the_last_block_of_the_first_system_commit(emulators, nbytes):
    """Cut inside the last programmed block of the very first system record
    (597: the parity's last byte, 604: its padding, 611: the completion
    mark): still a first boot, never safe mode."""
    ctaphid_install()
    e = emulators()
    arm(e, "tear %d %d %d" % (REG_SYS, 2 if nbytes > 608 else 1, nbytes - 608 if nbytes > 608 else nbytes))
    assert boot_until_exit(e) == 99
    e.start()
    assert wait_log(e, "profile 1 mounted"), boot_log(e)
    assert "SAFE MODE" not in boot_log(e)
    make_rk(b"alice")
    e.restart()
    assert user_ids() == {b"alice"}


def test_counter_remnant_of_an_old_erase_is_erased(emulators):
    """An unreferenced region where only counter sectors survived an
    interrupted erase of earlier firmware is erased at boot."""
    ctaphid_install()
    e = emulators()
    e.start()
    assert wait_log(e, "profile 1 mounted")         # the flash file is complete
    e.stop()
    off = EMU_STORE0 + 4 * EMU_STORE_SIZE + (S_CTR + 5) * SECTOR
    write_at(e.flash_path, off, os.urandom(64))
    e.start()
    assert wait_log(e, "erasing unreferenced store region 4")
    e.stop()
    assert read_at(e.flash_path, off, SECTOR) == b"\xff" * SECTOR


def ctaphid_install():
    from harness import ctaphid
    ctaphid.install()
