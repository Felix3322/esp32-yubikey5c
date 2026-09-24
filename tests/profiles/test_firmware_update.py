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

from harness.emulator import Button, REPO_ROOT
from librefido import firmware
from librefido.mgmt import INS_FW_BEGIN, INS_FW_END, INS_FW_ROLLBACK, INS_FW_WRITE
from librefido.pcsc import ApduError

from test_profiles_backup import device, emulators, make_rk, pcscd, set_pin, user_ids  # noqa: F401

# Descriptor offsets (pico-keys-sdk/src/fs/lf_fw.h)
PLATFORM, PROFILE, STORE, STORE_MIN = 17, 18, 22, 23


def image(e, version=None, patch=None, binary=None):
    with open(binary or e.binary, "rb") as f:
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


def base(e):
    """Version of the emulator binary."""
    with open(e.binary, "rb") as f:
        return firmware.parse(f.read())["version_tuple"]


def newer(e, k=1):
    b = base(e)
    return (b[0], b[1], b[2] + k)


def vs(version):
    return "%d.%d.%d" % tuple(version)


def begin(m, img, digest=None, p2=0, pin=None):
    """FW_BEGIN; returns the session ID every later command carries."""
    params = {1: len(img), 2: digest or hashlib.sha256(img).digest()}
    if pin is not None:
        params[3] = pin.encode()
    return cbor.decode(m._cmd(INS_FW_BEGIN, 0, p2, data=cbor.encode(params)))[1]


def upload(m, img, digest=None, p2=0, stop_at=None, pin=None):
    """Raw transfer; returns the FW_END answer."""
    sid = begin(m, img, digest, p2, pin)
    off = 0
    while off < len(img):
        if stop_at is not None and off >= stop_at:
            return None
        part = img[off:off + 1024]
        m._cmd(INS_FW_WRITE, data=struct.pack(">I", off) + sid + part)
        off += len(part)
    return cbor.decode(m._cmd(INS_FW_END, data=sid))


def fw(m):
    i = m.info()
    return i["firmware"], i["firmware_slot"]


def factory(e):
    return {"version": vs(base(e)), "platform": "emulation", "board": "emulation",
            "slot": "factory", "unconfirmed": False, "rollback_possible": False}


def test_update_confirm_and_rollback(pcscd, emulators):
    e = emulators()
    m = device(e)
    assert fw(m) == (vs(base(e)), factory(e))
    make_rk(b"alice")

    r = m.update_firmware(image(e, newer(e, 1)))
    assert r["installed"] == vs(newer(e, 1))
    version, slot = fw(m)
    assert version == vs(newer(e, 1)) and slot["slot"] == 0 and not slot["unconfirmed"] and slot["rollback_possible"]
    assert user_ids() == {b"alice"}                     # storage untouched

    e.restart()                                         # power cycle: stays on the confirmed image
    m.reconnect()
    assert fw(m)[0] == vs(newer(e, 1))
    make_rk(b"bob")

    # the next update goes to the other slot
    m.update_firmware(image(e, newer(e, 2)))
    version, slot = fw(m)
    assert version == vs(newer(e, 2)) and slot["slot"] == 1

    # explicit rollback to the previous image
    assert m.rollback_firmware() == vs(newer(e, 1))
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
    assert version == vs(base(e)) and slot["slot"] == "factory" and not slot["unconfirmed"]
    assert user_ids() == {b"alice", b"bob"}             # credentials kept either way
    with open(e.log_path) as f:
        assert "was not confirmed, rolling back" in f.read()
    m.close()


def test_interrupted_upload_changes_nothing(pcscd, emulators):
    e = emulators()
    m = device(e)
    make_rk(b"alice")
    assert upload(m, image(e, newer(e)), stop_at=200 * 1024) is None
    e.stop(hard=True)                                   # power lost in the middle
    e.start()
    m.reconnect()
    assert fw(m) == (vs(base(e)), factory(e))
    assert user_ids() == {b"alice"}
    m.close()


def test_bad_images_are_refused(pcscd, emulators):
    e = emulators()
    m = device(e)
    good = image(e, newer(e))

    def refused(img, sw, **kw):
        with pytest.raises(ApduError) as err:
            upload(m, img, **kw)
        assert err.value.sw == sw, hex(err.value.sw)
        assert fw(m)[0] == vs(base(e))                  # no restart, nothing selected

    refused(good, 0x6984, digest=hashlib.sha256(b"other").digest())     # transfer corrupted
    refused(os.urandom(64 * 1024), 0x6984)                              # not an image
    refused(good[:len(good) // 2], 0x6984)                              # truncated: no valid image
    refused(image(e, newer(e), patch={PLATFORM: 0x01}), 0x6A80)         # other platform
    refused(image(e, newer(e), patch={STORE: 9, STORE_MIN: 9}), 0x6A80) # cannot open this storage
    refused(image(e, (1, 9, 9)), 0x6986)                                # downgrade
    refused(image(e, newer(e), patch={PROFILE: 0}), 0x6986)             # a less restrictive build (development)
    refused(image(e, newer(e), patch={PROFILE: 9}), 0x6A80)             # unknown build profile
    # an image that cannot read the records this firmware writes: never,
    # not even as an explicit downgrade
    refused(image(e, newer(e), patch={STORE: 1, STORE_MIN: 1}), 0x6986, p2=1)
    # a descriptor appended after the image: an image carries exactly one
    d = firmware.parse(good)["offset"]
    forged = firmware.set_version(good, (9, 9, 9))[d:d + firmware.DESC_SIZE]
    refused(good + forged, 0x6984)

    # a HARDENED image only on a chip that has what HARDENED requires: this
    # one would lock the key store for good and refuse every later update
    refused(image(e, newer(e), patch={PROFILE: 2}), 0x6982)

    # chunks out of order end the transfer
    sid = begin(m, good)
    with pytest.raises(ApduError):
        m._cmd(INS_FW_WRITE, data=struct.pack(">I", 1024) + sid + good[1024:2048])
    with pytest.raises(ApduError) as err:
        m._cmd(INS_FW_END, data=sid)
    assert err.value.sw == 0x6985

    # an explicit downgrade is possible outside HARDENED builds
    assert upload(m, image(e, (1, 9, 9)), p2=1)[1] == bytes([1, 9, 9])
    m.reconnect()
    assert fw(m)[0] == "1.9.9"
    m.close()


def test_hardened_image_on_a_hardened_chip(pcscd, emulators):
    e = emulators(env={"LF_EMU_CHIP_SECURE": "1"})
    m = device(e)
    assert upload(m, image(e, newer(e), patch={PROFILE: 2}))[3] == 2
    m.reconnect()
    assert fw(m)[0] == vs(newer(e))
    m.close()


def test_refused_upload_is_no_rollback_target(pcscd, emulators):
    e = emulators()
    m = device(e)
    m.update_firmware(image(e, newer(e, 1)))
    m.update_firmware(image(e, newer(e, 2)))
    assert fw(m)[1]["rollback_possible"]
    # the next upload goes to the slot of the first update: from its first
    # byte on, that slot is no rollback target, and a refused image never
    # becomes one
    with pytest.raises(ApduError) as err:
        upload(m, image(e, (1, 9, 9)))
    assert err.value.sw == 0x6986
    assert not fw(m)[1]["rollback_possible"]
    with pytest.raises(ApduError) as err:
        m._cmd(INS_FW_ROLLBACK)
    assert err.value.sw == 0x6A88
    assert fw(m)[0] == vs(newer(e, 2))
    m.close()


def test_no_update_over_an_unconfirmed_one(pcscd, emulators):
    e = emulators()
    m = device(e)
    m.update_firmware(image(e, newer(e, 1)), confirm=False)
    # the upload would overwrite the image a reset goes back to
    with pytest.raises(ApduError) as err:
        begin(m, image(e, newer(e, 2)))
    assert err.value.sw == 0x6985
    m.confirm_firmware()
    assert m.update_firmware(image(e, newer(e, 2)))["installed"] == vs(newer(e, 2))
    m.close()


def test_no_rollback_past_a_storage_format(pcscd, emulators, tmp_path):
    """Once the new firmware is confirmed the applications seal their
    records, which firmware of an older storage format cannot read: going
    back to it is refused. Before the confirmation it is not (nothing was
    migrated yet), neither explicitly nor by the reset of the bootloader."""
    real = os.environ.get("LF_EMU_BIN") or os.path.join(REPO_ROOT, "build-emu", "pico_fido2")
    old = tmp_path / "pico_fido2_format1"
    with open(real, "rb") as f:
        old_img = f.read()
    old_img = firmware.set_version(old_img, (2, 0, 0))
    off = firmware.parse(old_img)["offset"]
    b = bytearray(old_img)
    b[off + STORE] = b[off + STORE_MIN] = 1             # as LibreFido 2.0.0
    old_img = bytes(b)
    old.write_bytes(old_img)
    old.chmod(0o755)

    e = emulators(binary=str(old))
    m = device(e)
    assert fw(m)[0] == "2.0.0"
    make_rk(b"alice")
    new = image(e, binary=real)
    new_version = firmware.parse(new)["version"]

    m.update_firmware(new, confirm=False)
    assert fw(m)[1]["unconfirmed"]
    assert m.rollback_firmware() == "2.0.0"             # unconfirmed: back is fine

    m.update_firmware(new)                              # confirmed: records get sealed
    version, slot = fw(m)
    assert version == new_version and slot["rollback_possible"]
    with pytest.raises(ApduError) as err:
        m._cmd(INS_FW_ROLLBACK)
    assert err.value.sw == 0x6986
    with pytest.raises(ApduError) as err:
        upload(m, old_img, p2=1)                        # nor as an explicit downgrade
    assert err.value.sw == 0x6986
    assert fw(m)[0] == new_version and user_ids() == {b"alice"}
    m.close()


def test_no_confirmation_while_leaving(pcscd, emulators):
    """After FW_ROLLBACK the running image never boots again: until the
    restart it cannot be confirmed and counts as unconfirmed, so that the
    applications convert no record into its format in that window."""
    from smartcard.Exceptions import CardConnectionException
    from librefido.mgmt import INS_FW_CONFIRM
    from librefido.pcsc import MGMT_AID
    e = emulators()
    m = device(e)
    make_rk(b"alice")
    m.update_firmware(image(e, newer(e)))               # confirmed
    slot = fw(m)[1]
    assert not slot["unconfirmed"] and slot["rollback_possible"]
    try:
        with m.card.transaction(MGMT_AID):              # the next commands follow at once
            m._cmd(INS_FW_ROLLBACK)
            with pytest.raises(ApduError) as err:
                m._cmd(INS_FW_CONFIRM)
            assert err.value.sw == 0x6985
            slot = m.info()["firmware_slot"]
            assert slot["unconfirmed"] and not slot["rollback_possible"]
    except CardConnectionException:
        pytest.skip("the device restarted before the next command arrived")
    m.reconnect()
    assert fw(m)[0] == vs(base(e)) and user_ids() == {b"alice"}
    m.close()


def test_update_needs_touch_and_pin(pcscd, emulators):
    e = emulators(env={"LF_EMU_UP": "manual", "LF_EMU_UP_TIMEOUT_MS": "1500"})
    m = device(e)
    img = image(e, newer(e))
    with pytest.raises(ApduError) as err:
        m.update_firmware(img)                          # nobody touches
    assert err.value.sw == 0x6985

    presser = threading.Thread(target=lambda: (time.sleep(0.3), Button().press()))
    presser.start()
    set_pin("123456")                                   # (no touch needed, pressed anyway)
    presser.join()
    with pytest.raises(ApduError) as err:
        upload(m, img)                                  # PIN missing: the device refuses
    assert err.value.sw == 0x6982                       # (no retry used)
    with pytest.raises(ApduError) as err:
        upload(m, img, pin="000000")                    # wrong PIN
    assert err.value.sw & 0xFFF0 == 0x63C0
    presser = threading.Thread(target=lambda: (time.sleep(0.4), Button().press()))
    presser.start()
    assert m.update_firmware(img, pin="123456")["installed"] == vs(newer(e))
    presser.join()
    m.close()


def test_rollback_needs_touch_and_pin(pcscd, emulators):
    e = emulators(env={"LF_EMU_UP": "manual", "LF_EMU_UP_TIMEOUT_MS": "1500"})
    m = device(e)
    presser = threading.Thread(target=lambda: (time.sleep(0.3), Button().press()))
    presser.start()
    set_pin("123456")
    presser.join()
    presser = threading.Thread(target=lambda: (time.sleep(0.4), Button().press()))
    presser.start()
    assert m.update_firmware(image(e, newer(e)), pin="123456")["installed"] == vs(newer(e))
    presser.join()
    # going back installs another image: the same bar as an update
    with pytest.raises(ApduError) as err:
        m._cmd(INS_FW_ROLLBACK)                         # no PIN
    assert err.value.sw == 0x6982
    with pytest.raises(ApduError) as err:
        m._cmd(INS_FW_ROLLBACK, data=b"000000")         # wrong PIN
    assert err.value.sw & 0xFFF0 == 0x63C0
    with pytest.raises(ApduError) as err:
        m._cmd(INS_FW_ROLLBACK, data=b"123456")         # nobody touches
    assert err.value.sw == 0x6985
    assert fw(m)[0] == vs(newer(e))
    presser = threading.Thread(target=lambda: (time.sleep(0.4), Button().press()))
    presser.start()
    assert m.rollback_firmware(pin="123456") == vs(base(e))
    presser.join()
    e.restart()                                         # for good, not only until the next reset
    m.reconnect()
    assert fw(m)[0] == vs(base(e))
    m.close()
