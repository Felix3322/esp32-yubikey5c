"""Firmware update with A/B slots and rollback, on the host emulator.

The emulator mirrors the ESP-IDF bootloader rules (pico-keys-sdk/src/fs/lf_fw.c):
an installed image boots unconfirmed, and a reset before it is confirmed goes
back to the previous image. Test images are copies of the emulator binary
with another version in their descriptor.

    PYTHONPATH=tests:tools/librefido python -m pytest tests/profiles/test_firmware_update.py
"""

import hashlib
import os
import struct
import threading
import time

import pytest
from fido2 import cbor

from harness.emulator import Button
from librefido import firmware
from librefido.mgmt import INS_FW_BEGIN, INS_FW_END, INS_FW_WRITE
from librefido.pcsc import ApduError

from test_profiles_backup import device, emulators, make_rk, pcscd, set_pin, user_ids  # noqa: F401


def image(e, version=None, patch=None):
    with open(e.binary, "rb") as f:
        img = f.read()
    if version:
        img = firmware.set_version(img, version)
    if patch:
        off = firmware.parse(img)["offset"]
        b = bytearray(img)
        for rel, val in patch.items():
            b[off + rel] = val
        img = bytes(b)
    return img


def upload(m, img, digest=None, p2=0, stop_at=None):
    """Raw transfer; returns the FW_END answer."""
    m._cmd(INS_FW_BEGIN, 0, p2, data=cbor.encode({1: len(img), 2: digest or hashlib.sha256(img).digest()}))
    off = 0
    while off < len(img):
        if stop_at is not None and off >= stop_at:
            return None
        part = img[off:off + 1024]
        m._cmd(INS_FW_WRITE, data=struct.pack(">I", off) + part)
        off += len(part)
    return cbor.decode(m._cmd(INS_FW_END))


def fw(m):
    i = m.info()
    return i["firmware"], i["firmware_slot"]


def test_update_confirm_and_rollback(pcscd, emulators):
    e = emulators()
    m = device(e)
    assert fw(m) == ("2.0.0", {"version": "2.0.0", "platform": "emulation", "board": "emulation",
                               "slot": "factory", "unconfirmed": False, "rollback_possible": False})
    make_rk(b"alice")

    r = m.update_firmware(image(e, (2, 0, 1)))
    assert r["installed"] == "2.0.1"
    version, slot = fw(m)
    assert version == "2.0.1" and slot["slot"] == 0 and not slot["unconfirmed"] and slot["rollback_possible"]
    assert user_ids() == {b"alice"}                     # storage untouched

    e.restart()                                         # power cycle: stays on the confirmed image
    m.reconnect()
    assert fw(m)[0] == "2.0.1"
    make_rk(b"bob")

    # the next update goes to the other slot
    m.update_firmware(image(e, (2, 0, 2)))
    version, slot = fw(m)
    assert version == "2.0.2" and slot["slot"] == 1

    # explicit rollback to the previous image
    assert m.rollback_firmware() == "2.0.1"
    assert fw(m)[1]["slot"] == 0
    assert user_ids() == {b"alice", b"bob"}
    m.close()


def test_unconfirmed_update_rolls_back_on_reset(pcscd, emulators):
    e = emulators()
    m = device(e)
    make_rk(b"alice")
    m.update_firmware(image(e, (2, 1, 0)), confirm=False)
    version, slot = fw(m)
    assert version == "2.1.0" and slot["unconfirmed"]
    make_rk(b"bob")                                     # written by the new image

    e.stop(hard=True)                                   # never confirmed, e.g. the host crashed
    e.start()
    m.reconnect()
    version, slot = fw(m)
    assert version == "2.0.0" and slot["slot"] == "factory" and not slot["unconfirmed"]
    assert user_ids() == {b"alice", b"bob"}             # credentials kept either way
    with open(e.log_path) as f:
        assert "was not confirmed, rolling back" in f.read()
    m.close()


def test_interrupted_upload_changes_nothing(pcscd, emulators):
    e = emulators()
    m = device(e)
    make_rk(b"alice")
    assert upload(m, image(e, (2, 0, 1)), stop_at=200 * 1024) is None
    e.stop(hard=True)                                   # power lost in the middle
    e.start()
    m.reconnect()
    assert fw(m) == ("2.0.0", {"version": "2.0.0", "platform": "emulation", "board": "emulation",
                               "slot": "factory", "unconfirmed": False, "rollback_possible": False})
    assert user_ids() == {b"alice"}
    m.close()


def test_bad_images_are_refused(pcscd, emulators):
    e = emulators()
    m = device(e)
    good = image(e, (2, 0, 1))

    def refused(img, sw, **kw):
        with pytest.raises(ApduError) as err:
            upload(m, img, **kw)
        assert err.value.sw == sw, hex(err.value.sw)
        assert fw(m)[0] == "2.0.0"                      # no restart, nothing selected

    refused(good, 0x6984, digest=hashlib.sha256(b"other").digest())     # transfer corrupted
    refused(os.urandom(64 * 1024), 0x6984)                              # not an image
    refused(good[:len(good) // 2], 0x6984)                              # truncated: no valid image
    refused(image(e, (2, 0, 1), patch={17: 0x01}), 0x6A80)              # other platform
    refused(image(e, (2, 0, 1), patch={23: 2}), 0x6A80)                 # cannot open this storage
    refused(image(e, (1, 9, 9)), 0x6986)                                # downgrade

    # chunks out of order end the transfer
    m._cmd(INS_FW_BEGIN, data=cbor.encode({1: len(good), 2: hashlib.sha256(good).digest()}))
    with pytest.raises(ApduError):
        m._cmd(INS_FW_WRITE, data=struct.pack(">I", 1024) + good[1024:2048])
    with pytest.raises(ApduError) as err:
        m._cmd(INS_FW_END)
    assert err.value.sw == 0x6985

    # an explicit downgrade is possible outside HARDENED builds
    assert upload(m, image(e, (1, 9, 9)), p2=1)[1] == bytes([1, 9, 9])
    m.reconnect()
    assert fw(m)[0] == "1.9.9"
    m.close()


def test_update_needs_touch_and_pin(pcscd, emulators):
    e = emulators(env={"LF_EMU_UP": "manual", "LF_EMU_UP_TIMEOUT_MS": "1500"})
    m = device(e)
    img = image(e, (2, 0, 1))
    with pytest.raises(ApduError) as err:
        m.update_firmware(img)                          # nobody touches
    assert err.value.sw == 0x6985

    presser = threading.Thread(target=lambda: (time.sleep(0.3), Button().press()))
    presser.start()
    set_pin("123456")                                   # (no touch needed, pressed anyway)
    presser.join()
    with pytest.raises(ApduError) as err:
        m.update_firmware(img)                          # PIN missing
    assert err.value.sw & 0xFFF0 == 0x63C0
    presser = threading.Thread(target=lambda: (time.sleep(0.4), Button().press()))
    presser.start()
    assert m.update_firmware(img, pin="123456")["installed"] == "2.0.1"
    presser.join()
    m.close()
