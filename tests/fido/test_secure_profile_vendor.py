"""Secure profiles (and HARDENED builds, where every profile is secure) refuse
every vendor command that moves FIDO key material in or out: sealed device
key export, restore, and AUT_ENABLE (which seals the device key under a host
key). They answer CTAP2_ERR_OPERATION_DENIED.

    LF_EMU_BIN_HARDENED=~/work/build-fix-fido-hard/pico_fido2 \
    PYTHONPATH=tests:pico-fido/tests:tools/librefido:tests/profiles python -m pytest tests/fido
"""

import os
import sys

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Config

from test_profiles_backup import ctap2, device, emulators, pcscd, wait_reboot  # noqa: F401

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "pico-fido", "tests", "pico-fido"))

BIN = os.environ.get("LF_EMU_BIN_HARDENED")
PIN = "12345678"


class _Dev:
    def __init__(self, dev):
        self.dev = dev


def test_no_export_profile_keeps_the_device_key(pcscd, emulators):
    """A profile marked no-export (the flag that blocks profile exports) does
    not hand the FIDO device key out either: AUT_ENABLE (the host picks K)
    and the export of the sealed key are refused; restore is an import."""
    from lf_fido_helpers import CONFIG_AUT_ENABLE, CONFIG_AUT_DISABLE, VENDOR_BACKUP, Mse, raw_vendor, vendor_auth
    m = device(emulators())
    dev, c = ctap2()
    d = _Dev(dev)
    try:
        ClientPin(c).set_pin(PIN)
        proto = ClientPin(c).protocol

        def acfg():
            return ClientPin(c).get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)

        def export():
            tok = acfg()
            return raw_vendor(d, VENDOR_BACKUP, {1: 1, 3: proto.VERSION, 4: vendor_auth(tok, proto, VENDOR_BACKUP, 1)})

        k = os.urandom(32)
        Config(c, proto, acfg())._call(0xFF, {1: CONFIG_AUT_ENABLE, 2: Mse(d).seal(k)})   # allowed so far
        assert export()[0] == 0
        m.set_profile(0, no_export=True)
        assert export()[0] == CtapError.ERR.OPERATION_DENIED
        Config(c, proto, acfg())._call(0xFF, {1: CONFIG_AUT_DISABLE})                    # not an export
        with pytest.raises(CtapError) as err:
            Config(c, proto, acfg())._call(0xFF, {1: CONFIG_AUT_ENABLE, 2: Mse(d).seal(k)})
        assert err.value.code == CtapError.ERR.OPERATION_DENIED
        m.set_profile(0, no_export=False)
        Config(c, proto, acfg())._call(0xFF, {1: CONFIG_AUT_ENABLE, 2: Mse(d).seal(k)})
    finally:
        dev.close()
        m.close()


@pytest.mark.skipif(not BIN or not os.path.exists(BIN), reason="LF_EMU_BIN_HARDENED not built")
def test_no_key_material_moves_in_or_out(pcscd, emulators, tmp_path):
    from librefido import provision
    from lf_fido_helpers import (CONFIG_AUT_ENABLE, VENDOR_BACKUP, Mse, raw_vendor, vendor_auth,
                                 seal_device_key)
    e = emulators(binary=BIN, env={"LF_EMU_CHIP_SECURE": "1"})
    m = device(e)
    provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path))
    e.restart()
    wait_reboot(m)
    m.close()

    dev, c = ctap2()
    d = _Dev(dev)
    try:
        # FIDO itself works (the device key is sealed in sks from the start)
        c.make_credential(os.urandom(32), {"id": "example.com", "name": "x"},
                          {"id": b"u", "name": "u", "displayName": "U"},
                          [{"type": "public-key", "alg": -7}], options={"rk": True})
        ClientPin(c).set_pin(PIN)
        proto = ClientPin(c).protocol
        k = os.urandom(32)

        def acfg():
            return ClientPin(c).get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)

        # AUT_ENABLE: seals the device key under a host key
        kct = Mse(d).seal(k)
        with pytest.raises(CtapError) as err:
            Config(c, proto, acfg())._call(0xFF, {1: CONFIG_AUT_ENABLE, 2: kct})
        assert err.value.code == CtapError.ERR.OPERATION_DENIED

        # restore
        blob = seal_device_key(k, os.urandom(31) + b"\x01")
        kct = Mse(d).seal(k)
        tok = acfg()
        st, _ = raw_vendor(d, VENDOR_BACKUP, {1: 2, 2: {1: blob, 3: kct}, 3: proto.VERSION,
                                              4: vendor_auth(tok, proto, VENDOR_BACKUP, 2, blob, kct)})
        assert st == CtapError.ERR.OPERATION_DENIED

        # export of the sealed key
        tok = acfg()
        st, _ = raw_vendor(d, VENDOR_BACKUP, {1: 1, 3: proto.VERSION, 4: vendor_auth(tok, proto, VENDOR_BACKUP, 1)})
        assert st == CtapError.ERR.OPERATION_DENIED
    finally:
        dev.close()
