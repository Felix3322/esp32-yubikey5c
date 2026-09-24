"""HARDENED build on the emulator (LF_EMU_BIN_HARDENED, built with
-DLIBREFIDO_PROFILE=hardened). LF_EMU_CHIP_SECURE=1 makes the emulated chip
report the complete security state the HARDENED key store requires.

    LF_EMU_BIN_HARDENED=~/work/build-emu-hard/pico_fido2 \
    PYTHONPATH=tests:tools/librefido:tests/profiles python -m pytest tests/profiles/test_hardened.py
"""

import os

import pytest

from harness.card import ApduError as CardError, Card
from librefido import firmware
from librefido.pcsc import ApduError
from test_profiles_backup import ctap2, device, emulators, make_rk, pcscd  # noqa: F401

BIN = os.environ.get("LF_EMU_BIN_HARDENED")
pytestmark = pytest.mark.skipif(not BIN or not os.path.exists(BIN), reason="LF_EMU_BIN_HARDENED not built")


def hardened(emulators, secure=True):
    return emulators(binary=BIN, env={"LF_EMU_CHIP_SECURE": "1" if secure else "0"})


def provisioned(emulators, tmp_path):
    """A HARDENED device is usable once its root key is bound to the chip."""
    from librefido import provision
    from test_profiles_backup import wait_reboot
    e = hardened(emulators)
    m = device(e)
    provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path))
    e.restart()
    wait_reboot(m)
    return e, m


def test_hardened_needs_provisioning(pcscd, emulators, tmp_path):
    e = hardened(emulators)
    m = device(e)
    assert m.info()["security"]["root_key"] == "flash (not bound to the chip)"
    dev, c = ctap2()
    try:
        with pytest.raises(Exception):                      # key store locked until then
            c.make_credential(os.urandom(32), {"id": "example.com", "name": "x"},
                              {"id": b"u", "name": "u", "displayName": "U"},
                              [{"type": "public-key", "alg": -7}], options={"rk": True})
    finally:
        dev.close()
    m.close()


def test_hardened_keeps_keys_inside(pcscd, emulators, tmp_path):
    e, m = provisioned(emulators, tmp_path)
    info = m.info()
    assert info["build_profile"] == "hardened" and not info["export_allowed"]
    make_rk(b"alice")
    dev, c = ctap2()
    try:
        assert bytes(c.info.aaguid).hex() == "6c86ea00e57627564e8a6234f544e3fd"
    finally:
        dev.close()
    with pytest.raises(ApduError) as err:
        m.export_profile()
    assert err.value.sw == 0x6986
    # clearing the no-export flag does not help: the build forbids it
    m.set_profile(0, no_export=False)
    with pytest.raises(ApduError):
        m.export_profile()
    # maintenance writes are refused, not merely gated by a touch
    card = Card()
    try:
        card.select(bytes.fromhex("A0583FC19B7E4F21"))
        with pytest.raises(CardError) as err:
            card.transmit(0x80, 0x10, 0x03, 0x00, b"\x30\x03\x02\x01\x00")
        assert err.value.sw == 0x6982
    finally:
        card.close()
    m.close()


def build_profile(img, profile):
    """Copy of img whose descriptor names another build profile."""
    out = bytearray(img)
    out[firmware.parse(img)["offset"] + 18] = profile
    return bytes(out)


def newer(img, k=1):
    """Version k patch releases after the one of img."""
    v = firmware.parse(img)["version_tuple"]
    return (v[0], v[1], v[2] + k)


def test_hardened_firmware_policy(pcscd, emulators, tmp_path):
    e, m = provisioned(emulators, tmp_path)
    with open(BIN, "rb") as f:
        img = f.read()
    older = firmware.set_version(img, (1, 0, 0))
    with pytest.raises(ApduError) as err:
        m.update_firmware(older, allow_downgrade=True)      # never a downgrade
    assert err.value.sw == 0x6986
    # never a build that allows more (STANDARD exports keys), even a newer one
    for profile in (0, 1):
        with pytest.raises(ApduError) as err:
            m.update_firmware(build_profile(firmware.set_version(img, newer(img, 2)), profile),
                              allow_downgrade=True)
        assert err.value.sw == 0x6986
    version = "%d.%d.%d" % newer(img)
    assert m.update_firmware(firmware.set_version(img, newer(img)))["installed"] == version
    # and no way back to the older image either
    assert m.info()["firmware_slot"]["rollback_possible"]
    with pytest.raises(ApduError) as err:
        m.rollback_firmware()
    assert err.value.sw == 0x6986
    assert m.info()["firmware"] == version
    m.close()


def test_hardened_restores_a_backup(pcscd, emulators, tmp_path):
    """HARDENED promises that keys never leave the device, not that they
    were born on it: a backup (from a STANDARD device, since HARDENED never
    exports) can be restored, and then never leaves again."""
    from test_profiles_backup import user_ids, wait_reboot
    std = emulators("std")
    m = device(std)
    make_rk(b"alice")
    stream = m.export_profile()
    m.close()
    std.stop()
    e, m = provisioned(emulators, tmp_path)
    m.import_profile(stream, 1)
    m.select_profile(1)
    wait_reboot(m)
    assert user_ids() == {b"alice"}
    assert not m.info()["export_allowed"]
    with pytest.raises(ApduError) as err:
        m.export_profile()
    assert err.value.sw == 0x6986
    m.close()


def test_locked_key_store_still_asks_for_the_pin(pcscd, emulators, tmp_path):
    """The PIN check of an update does not depend on the key store being
    unlocked (before, a locked store left only the touch)."""
    import hashlib
    from fido2 import cbor
    from librefido.mgmt import INS_FW_BEGIN, Management
    from test_profiles_backup import set_pin
    e, m = provisioned(emulators, tmp_path)
    set_pin("123456")
    m.close()
    e.restart(LF_EMU_CHIP_SECURE="0")                       # chip state incomplete: store locked
    m = Management.open(timeout=15)
    with open(BIN, "rb") as f:
        img = firmware.set_version(f.read(), (2, 0, 1))
    params = {1: len(img), 2: hashlib.sha256(img).digest()}
    with pytest.raises(ApduError) as err:
        m._cmd(INS_FW_BEGIN, data=cbor.encode(params))                  # no PIN
    assert err.value.sw == 0x6982
    with pytest.raises(ApduError) as err:
        m._cmd(INS_FW_BEGIN, data=cbor.encode({**params, 3: b"000000"}))
    assert err.value.sw & 0xFFF0 == 0x63C0
    m._cmd(INS_FW_BEGIN, data=cbor.encode({**params, 3: b"123456"}))    # then the touch
    m.info()                                                            # ends the upload
    m.close()


def test_hardened_without_chip_security_locks_the_store(pcscd, emulators):
    e = hardened(emulators, secure=False)
    m = device(e)
    assert m.info()["security"]["secure_boot"] is False
    dev, c = ctap2()
    try:
        with pytest.raises(Exception):
            c.make_credential(os.urandom(32), {"id": "example.com", "name": "x"},
                              {"id": b"u", "name": "u", "displayName": "U"},
                              [{"type": "public-key", "alg": -7}], options={"rk": True})
    finally:
        dev.close()
    # and no firmware can be installed without Secure Boot
    with open(BIN, "rb") as f:
        img = firmware.set_version(f.read(), (2, 0, 1))
    with pytest.raises(ApduError) as err:
        m.update_firmware(img)
    assert err.value.sw == 0x6986
    m.close()
