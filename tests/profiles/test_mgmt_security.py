"""Management applet authorization and hygiene on the host emulator: which
commands need a touch, transfers bound to the client that started them, the
staging area never keeping keys after a transfer, profile names, limits on
system area writes, and backups that try to write into non-store files.

    PYTHONPATH=tests:tools/librefido:tests/profiles python -m pytest tests/profiles/test_mgmt_security.py
"""

import hashlib
import os
import struct
import threading

import pytest
from fido2 import cbor
from smartcard.Exceptions import CardConnectionException

from harness.emulator import Button
from librefido.mgmt import (INS_EXPORT_BEGIN, INS_EXPORT_READ, INS_FACTORY_RESET, INS_FW_BEGIN, INS_FW_END,
                            INS_FW_WRITE, INS_IMPORT_BEGIN, INS_IMPORT_END, INS_IMPORT_WRITE, INS_INFO,
                            INS_PROFILE_SET, INS_PROFILE_WIPE, INS_REBOOT, Management)
from librefido.pcsc import ApduError

from test_profiles_backup import device, emulators, make_rk, pcscd, set_pin, wait_reboot  # noqa: F401

MANUAL = {"LF_EMU_UP": "manual", "LF_EMU_UP_TIMEOUT_MS": "1200"}
# Emulator flash file layout (pico-keys-sdk/src/fs/lf_region.c)
SYS_OFF, SYS_SIZE = 0x800000, 0x010000
STAGE_OFF, STAGE_SIZE = 0x810000, 0x080000


def touching(fn):
    """Runs fn while the button is pressed every 0.3 s."""
    done = threading.Event()

    def press():
        b = Button()
        while not done.wait(0.3):
            try:
                b.press(0.05)
            except OSError:
                b.close()       # the emulator restarted: connect again
        b.close()
    t = threading.Thread(target=press)
    t.start()
    try:
        return fn()
    finally:
        done.set()
        t.join()


def region(e, off, size):
    with open(e.flash_path, "rb") as f:
        f.seek(off)
        return f.read(size)


def stage_blank(e):
    return region(e, STAGE_OFF, STAGE_SIZE) == b"\xff" * STAGE_SIZE


def records(stream):
    out, off = [], 0
    while off < len(stream):
        n = int.from_bytes(stream[off + 1:off + 3], "little")
        out.append((stream[off], stream[off + 3:off + 3 + n]))
        off += 3 + n
    return out


def rebuild(recs):
    """Backup stream of records (the END record is recomputed)."""
    body = b"".join(bytes([t]) + len(v).to_bytes(2, "little") + v for t, v in recs if t != 0x7F)
    return body + b"\x7f" + (32).to_bytes(2, "little") + hashlib.sha256(body).digest()


def sw_of(fn):
    with pytest.raises(ApduError) as err:
        fn()
    return err.value.sw


def session_id(resp):
    """ID answered by IMPORT_BEGIN / FW_BEGIN (protocol 3)."""
    return cbor.decode(resp)[1]


def test_switching_and_importing_need_a_touch(pcscd, emulators):
    e = emulators(env=MANUAL)
    m = device(e)
    assert sw_of(lambda: m.select_profile(1)) == 0x6985
    info = m.info()
    assert info["active"] == 0 and not info["profiles"][1]["used"]
    m.select_profile(0)                                 # already active: nothing to confirm

    stream = touching(m.export_profile)
    for p2 in (0, 2, 3):                                # import into an empty slot, restore test
        assert sw_of(lambda: m._cmd(INS_IMPORT_BEGIN, 1, p2)) == 0x6985
    # creating a profile in an empty slot restarts the device: a touch too
    before = region(e, SYS_OFF, SYS_SIZE)
    assert sw_of(lambda: m._cmd(INS_PROFILE_WIPE, 1)) == 0x6985
    assert region(e, SYS_OFF, SYS_SIZE) == before
    assert m.check_backup(stream)["files"] > 0          # a plain check changes nothing
    assert not m.info()["profiles"][1]["used"]

    touching(lambda: m.import_profile(stream, 1))
    assert m.info()["profiles"][1]["used"] and m.info()["active"] == 0
    touching(lambda: m.select_profile(1))
    wait_reboot(m)
    assert m.info()["active"] == 1
    m.close()


def test_restart_needs_a_touch(pcscd, emulators):
    e = emulators(env=MANUAL)
    m = device(e)
    boot_id = m.card.boot_id
    assert sw_of(lambda: m._cmd(INS_REBOOT, 0)) == 0x6985
    assert sw_of(lambda: m._cmd(INS_REBOOT, 1)) == 0x6A81     # no ROM loader to go to
    assert m.card.boot_id == boot_id and m.info()["boot_status"] == "ok"
    touching(lambda: m._cmd(INS_REBOOT, 0))
    wait_reboot(m)
    assert m.card.boot_id != boot_id
    m.close()


def test_only_the_exporting_client_reads_the_stream(pcscd, emulators):
    e = emulators()
    m = device(e)
    make_rk(b"alice")
    ans = cbor.decode(m._cmd(INS_EXPORT_BEGIN))
    export_id = ans[3]
    assert ans[1] > 0 and len(export_id) == 8
    # a protocol 1 read (offset only) gets nothing
    assert sw_of(lambda: m._cmd(INS_EXPORT_READ, data=struct.pack(">I", 0))) == 0x6700
    assert len(m._cmd(INS_EXPORT_READ, data=struct.pack(">I", 0) + export_id)) > 0
    # another client without the ID: refused, and the export is over
    assert sw_of(lambda: m._cmd(INS_EXPORT_READ, data=struct.pack(">I", 0) + bytes(8))) == 0x6982
    assert sw_of(lambda: m._cmd(INS_EXPORT_READ, data=struct.pack(">I", 0) + export_id)) == 0x6985
    assert stage_blank(e)
    # a new export gets another ID
    assert cbor.decode(m._cmd(INS_EXPORT_BEGIN))[3] != export_id
    m._cmd(INS_INFO)                                    # ends it
    assert stage_blank(e)
    m.close()


def test_imports_and_updates_belong_to_their_client(pcscd, emulators):
    e = emulators()
    m = device(e)
    stream = m.export_profile()
    # import: every write and the end carry the ID of the session
    sid = session_id(m._cmd(INS_IMPORT_BEGIN, 1, 0))
    assert len(sid) == 8
    m._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", 0) + sid + stream[:512])
    assert not stage_blank(e)
    assert sw_of(lambda: m._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", 512) + bytes(8) + stream[512:600])) \
        == 0x6982
    assert stage_blank(e)                               # the transfer is over, the stream erased
    assert sw_of(lambda: m._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", 512) + sid + stream[512:600])) \
        == 0x6985
    # an end with another ID schedules nothing
    sid = session_id(m._cmd(INS_IMPORT_BEGIN, 1, 0))
    m._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", 0) + sid + stream)
    assert sw_of(lambda: m._cmd(INS_IMPORT_END, data=bytes(8))) == 0x6982
    info = m.info()
    assert info["pending"] == "none" and stage_blank(e)
    # a chunk out of order ends the transfer too
    sid = session_id(m._cmd(INS_IMPORT_BEGIN, 1, 0))
    assert sw_of(lambda: m._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", 8) + sid + stream[8:16])) == 0x6A80
    assert sw_of(lambda: m._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", 0) + sid + stream)) == 0x6985
    # firmware upload
    with open(e.binary, "rb") as f:
        img = f.read(4096)
    sid = session_id(m._cmd(INS_FW_BEGIN, data=cbor.encode({1: len(img), 2: hashlib.sha256(img).digest()})))
    m._cmd(INS_FW_WRITE, data=struct.pack(">I", 0) + sid + img[:1024])
    assert sw_of(lambda: m._cmd(INS_FW_WRITE, data=struct.pack(">I", 1024) + bytes(8) + img[1024:2048])) == 0x6982
    assert sw_of(lambda: m._cmd(INS_FW_END, data=sid)) == 0x6985
    m.close()


def test_import_into_the_active_slot_asks_for_its_pin(pcscd, emulators):
    e = emulators()
    m = device(e)
    set_pin("123456")
    assert sw_of(lambda: m._cmd(INS_IMPORT_BEGIN, 0, 0)) == 0x6982            # it replaces this profile
    assert sw_of(lambda: m._cmd(INS_IMPORT_BEGIN, 0, 0, data=b"000000")) & 0xFFF0 == 0x63C0
    assert len(session_id(m._cmd(INS_IMPORT_BEGIN, 0, 0, data=b"123456"))) == 8
    m._cmd(INS_INFO)
    assert len(session_id(m._cmd(INS_IMPORT_BEGIN, 1, 0))) == 8               # another slot: a touch only
    m._cmd(INS_INFO)
    m.close()


def test_interrupted_transfers_leave_no_keys_behind(pcscd, emulators):
    e = emulators()
    m = device(e)
    make_rk(b"alice")
    # an export cut off by unplugging the key: root key and files in the stage
    ans = cbor.decode(m._cmd(INS_EXPORT_BEGIN))
    m._cmd(INS_EXPORT_READ, data=struct.pack(">I", 0) + ans[3])
    assert not stage_blank(e)
    m.close()
    e.stop(hard=True)
    e.start()
    m = Management.open(timeout=15)
    assert stage_blank(e)                               # erased by the next boot

    # a long upload cut off, then a short stream: nothing of the first is left
    sid = session_id(m._cmd(INS_IMPORT_BEGIN, 1, 0))
    for off in range(0, 96 * 1024, 1024):
        m._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", off) + sid + os.urandom(1024))
    assert not stage_blank(e)
    m.close()
    e.stop(hard=True)
    e.start()
    m = Management.open(timeout=15)
    assert stage_blank(e)
    stream = m.export_profile()
    assert stream and stage_blank(e)                    # and every session ends with it erased

    # the plain check writes nothing at all, not even the stage
    sid = session_id(m._cmd(INS_IMPORT_BEGIN, 0, 1))
    m._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", 0) + sid + stream[:len(stream) // 2])
    assert stage_blank(e)
    m._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", len(stream) // 2) + sid + stream[len(stream) // 2:])
    assert cbor.decode(m._cmd(INS_IMPORT_END, data=sid))[11] == hashlib.sha256(stream).digest()
    assert stage_blank(e)
    m.close()


def test_no_transfer_while_a_switch_is_pending(pcscd, emulators):
    e = emulators()
    m = device(e)
    m.wipe_profile(1)                                   # creates profile 2
    wait_reboot(m)
    m.set_profile(0, no_export=True)
    m.select_profile(1)                                 # takes effect at the reboot
    info = m.info()
    # profile 1, which may not be exported, is still the mounted one
    assert info["active"] == 1 and not info["export_allowed"]
    assert sw_of(lambda: m._cmd(INS_EXPORT_BEGIN)) == 0x6985
    assert sw_of(lambda: m._cmd(INS_IMPORT_BEGIN, 2, 0)) == 0x6985
    wait_reboot(m)
    assert m.info()["export_allowed"]
    m.close()


def test_factory_reset_leaves_a_blank_system_area(pcscd, emulators):
    e = emulators()
    m = device(e)
    uuid = m.info()["profiles"][0]["uuid"]
    m._cmd(INS_FACTORY_RESET, 0x5A)
    try:
        # before the restart: the record in RAM describes erased stores
        assert sw_of(lambda: m._cmd(INS_PROFILE_SET, 0, data=cbor.encode({1: "x"}))) == 0x6985
    except CardConnectionException:
        pass                                            # it restarted first
    wait_reboot(m)
    info = m.info()
    assert info["boot_status"] == "ok" and info["profiles"][0]["uuid"] != uuid
    assert info["profiles"][0]["name"] != "x"
    m.close()


def set_name_raw(m, raw):
    head = bytes([0x60 + len(raw)]) if len(raw) < 24 else b"\x78" + bytes([len(raw)])
    m._cmd(INS_PROFILE_SET, 0, data=b"\xa1\x01" + head + raw)


def test_profile_names_are_valid_utf8(pcscd, emulators):
    e = emulators()
    m = device(e)
    assert sw_of(lambda: set_name_raw(m, b"x" * 24)) == 0x6700         # the slot holds 23 bytes
    assert sw_of(lambda: set_name_raw(m, "测试测试测试测试".encode())) == 0x6700  # 8 characters, 24 bytes
    for bad in (b"ab\xe6\xb5", b"a\x00b", b"\xc0\x80", b"\xed\xa0\x80", b"\xff"):
        assert sw_of(lambda: set_name_raw(m, bad)) == 0x6A80, bad
    set_name_raw(m, b"y" * 23)
    assert m.info()["profiles"][0]["name"] == "y" * 23
    name = "测试测试测试测"                               # 21 bytes
    set_name_raw(m, name.encode())
    raw = cbor.decode(m._cmd(INS_INFO))                 # the strict decoder
    assert raw[15][0][3] == name
    m.close()


def test_unchanged_settings_are_not_written_and_changes_are_limited(pcscd, emulators):
    e = emulators(env=MANUAL)
    m = device(e)
    info = m.info()
    before = region(e, SYS_OFF, SYS_SIZE)
    m.set_button_slots(info["button_slots"])
    m.set_profile(0, name=info["profiles"][0]["name"], color=info["profiles"][0]["color"], no_export=False)
    assert region(e, SYS_OFF, SYS_SIZE) == before       # nothing was rewritten
    assert cbor.decode(m._cmd(INS_INFO))[18] == 16
    for i in range(16):                                 # changes without a touch, for a while
        m.set_button_slots(3 + i % 2)
    assert sw_of(lambda: m.set_button_slots(2)) == 0x6985
    assert sw_of(lambda: m.set_profile(0, name="again")) == 0x6985
    # a restart (even a power cycle the host causes) does not renew it
    m.close()
    e.restart()
    m = Management.open(timeout=15)
    assert cbor.decode(m._cmd(INS_INFO))[18] == 0
    assert sw_of(lambda: m.set_button_slots(2)) == 0x6985
    touching(lambda: m.set_button_slots(2))             # a touch does
    assert m.info()["button_slots"] == 2
    m.set_button_slots(3)
    m.close()


def test_backups_cannot_write_into_non_store_files(pcscd, emulators):
    e = emulators()
    m = device(e)
    make_rk(b"alice")
    recs = records(m.export_profile())
    assert recs[-1][0] == 0x7F
    assert m.check_backup(rebuild(recs))["files"] > 0
    # EF_CH_DATA (OpenPGP, served by a function) and EF_HIST_BYTES (in RAM)
    for fid in (0x0065, 0x5F52):
        bad = rebuild(recs[:-1] + [(0x03, fid.to_bytes(2, "little") + b"\x00" * 8)])
        assert sw_of(lambda: m.check_backup(bad)) == 0x6984
        assert sw_of(lambda: m.import_profile(bad, 1)) == 0x6984
    assert not m.info()["profiles"][1]["used"] and stage_blank(e)
    m.close()


def test_lock_debug(pcscd, emulators):
    e = emulators(env=MANUAL)
    m = device(e)
    assert sw_of(lambda: m._cmd(0x50, 0xA5, 0x03)) == 0x6A86
    assert sw_of(lambda: m._cmd(0x50, 0x00, 0x02)) == 0x6A86
    assert sw_of(lambda: m._cmd(0x50, 0xA5, 0x02)) == 0x6985                  # irreversible: a touch
    try:
        touching(lambda: m._cmd(0x50, 0xA5, 0x02))
    except ApduError as err:
        assert err.sw == 0x6A81                     # no emulated eFuses (security_lock_debug) yet
        m.close()
        pytest.skip("security_lock_debug() not available in this build")
    sec = m.info()["security"]
    assert sec["jtag_disabled"] and sec["download_restricted"]
    assert sw_of(lambda: m._cmd(0x50, 0xA5, 0x02)) == 0x6A88                  # done once
    m.close()
