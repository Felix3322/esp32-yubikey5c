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


def test_hardened_firmware_policy(pcscd, emulators, tmp_path):
    e, m = provisioned(emulators, tmp_path)
    with open(BIN, "rb") as f:
        img = f.read()
    older = firmware.set_version(img, (1, 0, 0))
    with pytest.raises(ApduError) as err:
        m.update_firmware(older, allow_downgrade=True)      # never a downgrade
    assert err.value.sw == 0x6986
    assert m.update_firmware(firmware.set_version(img, (2, 0, 1)))["installed"] == "2.0.1"
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
