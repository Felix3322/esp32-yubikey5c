"""Profiles, management applet, backups and clones on the host emulator.

Needs the user-mode PC/SC stack of tests/README.md (the management applet is
reached over CCID) and tools/librefido on the Python path:

    PYTHONPATH=tests:tools/librefido python -m pytest tests/profiles
"""

import os
import threading
import time

import pytest

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, ClientPin

from harness import ctaphid
from harness.emulator import Button, Emulator, Pcscd

from librefido.backup import BackupError, read_file, write_file
from librefido.mgmt import Management
from librefido.pcsc import ApduError


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    ctaphid.install()
    yield p
    p.stop()


class Devices:
    """Emulated devices of one test (each with its own flash and chip ID)."""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.made = []

    def __call__(self, name="dev", **kw):
        e = Emulator(workdir=str(self.tmp / name), **kw)
        self.made.append(e)
        return e

    def stop_all(self):
        for e in self.made:
            e.stop()


@pytest.fixture
def emulators(tmp_path):
    d = Devices(tmp_path)
    yield d
    d.stop_all()


def device(e):
    e.start()
    return Management.open(timeout=15)


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


def pin_retries():
    dev, c = ctap2()
    try:
        return ClientPin(c).get_pin_retries()[0] if c.info.options.get("clientPin") else None
    finally:
        dev.close()


def set_pin(pin):
    dev, c = ctap2()
    try:
        ClientPin(c).set_pin(pin)
    finally:
        dev.close()


def wait_reboot(m):
    m.reconnect(timeout=20)
    time.sleep(0.3)


def test_fresh_device(pcscd, emulators):
    m = device(emulators())
    info = m.info()
    assert info["boot_status"] == "ok" and info["build_profile"] == "standard"
    assert info["active"] == 0 and info["button_slots"] == 2
    assert info["profiles"][0]["used"] and not any(p["used"] for p in info["profiles"][1:])
    assert info["serial"] == info["chip_serial"]        # profile 1 presents the chip serial
    assert info["security"]["root_key"].startswith("flash")
    m.close()


def test_profiles_are_isolated_authenticators(pcscd, emulators):
    m = device(emulators())
    make_rk(b"alice")
    serial1 = m.info()["serial"]

    m.select_profile(1)
    wait_reboot(m)
    info = m.info()
    assert info["active"] == 1 and info["profiles"][1]["used"]
    assert info["serial"] != serial1                    # another device for the host
    assert user_ids() == set()
    make_rk(b"bob")
    set_pin("1234")

    m.select_profile(0)
    wait_reboot(m)
    assert user_ids() == {b"alice"}
    assert pin_retries() is None                        # the PIN belongs to profile 2
    m.select_profile(1)
    wait_reboot(m)
    assert m.info()["serial"] == info["serial"]
    assert pin_retries() == 8
    m.close()


def test_long_press_switches_profile(pcscd, emulators):
    e = emulators(env={"LF_EMU_UP": "manual", "LF_EMU_LONGPRESS_MS": "400"})
    m = device(e)
    b = Button()
    b.press(0.1)                                        # short press: nothing happens
    time.sleep(1.0)
    assert m.info()["active"] == 0
    b.press(0.8)                                        # long press: next profile
    b.close()
    wait_reboot(m)
    info = m.info()
    assert info["active"] == 1 and info["profiles"][1]["used"]
    b = Button()
    b.press(0.8)                                        # and back (2 button slots)
    b.close()
    wait_reboot(m)
    assert m.info()["active"] == 0
    m.close()


def test_clone_to_another_device(pcscd, emulators, tmp_path):
    m = device(emulators("a"))
    reg = make_rk(b"alice")
    set_pin("1234")
    stream = m.export_profile(pin="1234")
    info_a = m.info()
    m.close()
    path = str(tmp_path / "alice.lfbk")
    write_file(path, stream, passphrase="correct horse battery staple", scrypt_log_n=10)
    emulators.stop_all()

    info, restored = read_file(path, "correct horse battery staple")
    assert restored == stream and info["summary"]["resident_credentials"] == 1
    with pytest.raises(BackupError):
        read_file(path, "wrong passphrase")

    m = device(emulators("b"))                          # another chip
    assert m.info()["chip_serial"] != info_a["chip_serial"]
    m.import_profile(restored, target=0)
    info_b = m.info()
    assert info_b["serial"] == info_a["serial"]         # the clone is the same key
    dev, c = ctap2()
    try:
        # the PIN came along; with it set, pico-fido keeps the device key
        # sealed until the PIN is entered in the power session
        ClientPin(c).get_pin_token("1234")
        cdh = os.urandom(32)
        a = c.get_assertion("example.com", cdh)
        cred = reg.auth_data.credential_data
        assert a.credential["id"] == cred.credential_id
        cred.public_key.verify(bytes(a.auth_data) + cdh, a.signature)
    finally:
        dev.close()
    m.close()


def test_export_asks_for_the_fido_pin(pcscd, emulators):
    m = device(emulators())
    set_pin("1234")
    with pytest.raises(ApduError) as e:
        m.export_profile(pin="9999")
    assert e.value.sw == 0x63C7
    assert pin_retries() == 7                           # same counter as ClientPIN
    m.export_profile(pin="1234")
    assert pin_retries() == 8
    m.close()


def test_no_export_flag(pcscd, emulators):
    m = device(emulators())
    m.set_profile(0, no_export=True)
    with pytest.raises(ApduError) as e:
        m.export_profile()
    assert e.value.sw == 0x6986
    m.close()


def test_backup_verification(pcscd, emulators, tmp_path):
    m = device(emulators())
    make_rk(b"alice")
    stream = m.export_profile()
    # the device checks it without importing
    res = m.check_backup(stream)
    assert res["files"] > 0 and res["root_key"]
    # a full restore into scratch space changes nothing
    res, ok = m.restore_test(stream)
    assert ok
    info = m.info()
    assert info["active"] == 0 and [p["used"] for p in info["profiles"]] == [True, False, False, False]
    assert user_ids() == {b"alice"}
    # damaged streams are refused by the tool and by the firmware
    bad = bytearray(stream)
    bad[len(bad) // 2] ^= 1
    with pytest.raises(BackupError):
        read_file(bytes(write_blob_unchecked(bytes(bad))))
    with pytest.raises(ApduError) as e:
        m.check_backup(bytes(bad))
    assert e.value.sw == 0x6984
    m.close()


def write_blob_unchecked(stream):
    """A backup file around an (invalid) stream, as a corrupted copy would be."""
    import hashlib
    import struct
    head = b"LFBACKUP" + struct.pack("<HH", 1, 0) + bytes(6) + bytes(16) + struct.pack("<I", len(stream))
    return head + hashlib.sha256(stream).digest() + struct.pack("<H", 0) + stream


def test_wipe_and_delete(pcscd, emulators):
    m = device(emulators())
    make_rk(b"alice")
    old_uuid = m.info()["profiles"][0]["uuid"]
    m.wipe_profile(0)
    wait_reboot(m)
    info = m.info()
    assert info["last_result"] == "wiped" and info["profiles"][0]["uuid"] != old_uuid
    assert user_ids() == set()
    m.select_profile(1)
    wait_reboot(m)
    m.select_profile(0)
    wait_reboot(m)
    m.delete_profile(1)
    wait_reboot(m)
    info = m.info()
    assert info["last_result"] == "deleted" and not info["profiles"][1]["used"]
    m.close()


def test_factory_reset(pcscd, emulators):
    m = device(emulators())
    make_rk(b"alice")
    uuid = m.info()["profiles"][0]["uuid"]
    m.factory_reset()
    wait_reboot(m)
    info = m.info()
    assert info["profiles"][0]["uuid"] != uuid and user_ids() == set()
    m.close()


def test_health_report(pcscd, emulators):
    m = device(emulators())
    make_rk(b"alice")
    h = m.health(scrub=True)
    assert h["sectors_written"] > 0 and h["uncorrectable"] == 0 and h["commit_failures"] == 0
    assert h["fs_total_bytes"] > 0
    m.close()


def test_destructive_commands_need_a_touch(pcscd, emulators):
    e = emulators(env={"LF_EMU_UP": "manual", "LF_EMU_UP_TIMEOUT_MS": "1500"})
    m = device(e)
    presser = threading.Thread(target=lambda: (time.sleep(0.3), Button().press()))
    presser.start()
    make_rk(b"alice")                                   # needs presence too
    presser.join()
    with pytest.raises(ApduError) as err:
        m.export_profile()                              # nobody touches
    assert err.value.sw == 0x6985
    with pytest.raises(ApduError) as err:
        m.wipe_profile(0)
    assert err.value.sw == 0x6985
    presser = threading.Thread(target=lambda: (time.sleep(0.4), Button().press()))
    presser.start()
    assert len(m.export_profile()) > 0                  # with a touch
    presser.join()
    assert m.info()["profiles"][0]["used"]              # the refused wipe did nothing
    m.close()
