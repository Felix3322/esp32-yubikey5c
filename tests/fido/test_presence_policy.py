"""FIDO user presence and the per-profile "automatic presence" policy.

Only the everyday FIDO operations (makeCredential/getAssertion presence, U2F
register/authenticate, authenticatorSelection) may follow the policy
(lf_wait_presence(LF_APP_FIDO) through fido_wait_everyday_presence()).
authenticatorReset and every device key or security-setting command need a
physical press (fido_wait_physical_press()) whatever the policy.

    PYTHONPATH=tests:pico-fido/tests:tools/librefido:tests/profiles python -m pytest tests/fido
"""

import os
import re
import sys
import threading

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Config

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIDO_SRC = os.path.join(REPO, "pico-fido", "src", "fido")
sys.path.insert(0, os.path.join(REPO, "pico-fido", "tests", "pico-fido"))

EVERYDAY = ("fido_wait_everyday_presence", "check_user_presence", "lf_wait_presence")
PHYSICAL = "fido_wait_physical_press"


def source(name):
    with open(os.path.join(FIDO_SRC, name)) as f:
        # without comments
        return re.sub(r"/\*.*?\*/|//[^\n]*", "", f.read(), flags=re.S)


# -- source level: which presence each operation asks for ---------------------

@pytest.mark.parametrize("name", ["cbor_reset.c", "cbor_vendor.c", "cbor_config.c", "cbor_client_pin.c",
                                  "cbor_cred_mgmt.c", "cbor_large_blobs.c"])
def test_destructive_paths_never_reach_the_policy(name):
    """Reset, the device key commands (protect, unprotect, export, restore,
    unlock), authenticatorConfig (PIN policy, EA, board options), PIN and
    credential management never ask for policy-driven presence."""
    text = source(name)
    for fn in EVERYDAY:
        assert fn + "(" not in text, "%s calls %s" % (name, fn)


def test_reset_and_key_commands_ask_for_a_physical_press():
    assert PHYSICAL + "()" in source("cbor_reset.c")
    vendor = source("cbor_vendor.c")
    # protect, unprotect, export, restore
    assert vendor.count(PHYSICAL + "()") >= 4
    assert "wait_button()" not in vendor


@pytest.mark.parametrize("name", ["cbor_make_credential.c", "cbor_get_assertion.c", "cmd_register.c",
                                  "cmd_authenticate.c", "cbor_selection.c"])
def test_everyday_operations_follow_the_policy(name):
    text = source(name)
    assert any(fn + "(" in text for fn in EVERYDAY[:2]), name
    assert PHYSICAL not in text and "wait_button()" not in text, name


def test_policy_is_only_reached_through_one_function():
    for name in os.listdir(FIDO_SRC):
        if not name.endswith(".c") or name in ("oath.c", "otp.c", "management.c"):
            continue
        text = source(name)
        if name == "fido.c":
            assert text.count("lf_wait_presence(") == 1
            body = text[text.index("bool fido_wait_everyday_presence"):]
            assert body[:body.index("}")].count("lf_wait_presence(LF_APP_FIDO)") == 1
            phys = text[text.index("bool fido_wait_physical_press"):]
            phys = phys[:phys.index("}")]
            assert "wait_button()" in phys and "lf_" not in phys
        else:
            assert "lf_wait_presence(" not in text, name


# -- on the emulator, with automatic presence switched on --------------------

MANUAL = {"LF_EMU_UP": "manual", "LF_EMU_UP_TIMEOUT_MS": "1200"}
PIN = "12345678"


def touching(fn):
    from harness.emulator import Button
    done = threading.Event()

    def press():
        b = Button()
        while not done.wait(0.3):
            b.press(0.05)
        b.close()
    t = threading.Thread(target=press)
    t.start()
    try:
        return fn()
    finally:
        done.set()
        t.join()


class _Dev:
    """What lf_fido_helpers expects of a device: .dev (CtapHidDevice)."""

    def __init__(self, dev):
        self.dev = dev


def test_automatic_presence_never_covers_destructive_commands(tmp_path):
    from librefido.mgmt import Management
    if not hasattr(Management, "set_presence"):
        pytest.skip("the management applet cannot switch automatic presence on yet")
    from test_profiles_backup import Devices, Pcscd, ctap2, device
    from lf_fido_helpers import VENDOR_BACKUP, Mse, raw_vendor, vendor_auth, seal_device_key
    from fido2.ctap1 import Ctap1
    from fido2.utils import sha256

    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    devices = Devices(tmp_path)
    try:
        e = devices(env=MANUAL)
        m = device(e)
        touching(lambda: m.set_presence(0, fido=True))
        dev, c = ctap2()
        try:
            # everyday: no press needed now (before the PIN is set: with a
            # PIN, makeCredential needs a pinUvAuthParam, CTAP 2.1 6.1.2)
            c.make_credential(os.urandom(32), {"id": "example.com", "name": "x"},
                              {"id": b"u", "name": "u", "displayName": "U"},
                              [{"type": "public-key", "alg": -7}], options={"rk": True})
            Ctap1(dev).register(os.urandom(32), sha256(b"example.com"))
            c.selection()
            ClientPin(c).set_pin(PIN)

            # authenticatorReset still waits for a physical press
            with pytest.raises(CtapError) as err:
                c.reset()
            assert err.value.code == CtapError.ERR.USER_ACTION_TIMEOUT

            # so does every device key command: here the restore
            d = _Dev(dev)
            k = os.urandom(32)
            blob = seal_device_key(k, os.urandom(31) + b"\x01")
            kct = Mse(d).seal(k)
            proto = ClientPin(c).protocol
            tok = ClientPin(c).get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
            st, _ = raw_vendor(d, VENDOR_BACKUP, {1: 2, 2: {1: blob, 3: kct}, 3: proto.VERSION,
                                                  4: vendor_auth(tok, proto, VENDOR_BACKUP, 2, blob, kct)})
            assert st == CtapError.ERR.USER_ACTION_TIMEOUT
            # and authenticatorConfig AUT_ENABLE (protect)
            from lf_fido_helpers import CONFIG_AUT_ENABLE
            kct = Mse(d).seal(k)
            tok = ClientPin(c).get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
            with pytest.raises(CtapError) as err:
                Config(c, proto, tok)._call(0xFF, {1: CONFIG_AUT_ENABLE, 2: kct})
            assert err.value.code == CtapError.ERR.USER_ACTION_TIMEOUT
        finally:
            dev.close()
        m.close()
    finally:
        devices.stop_all()
        p.stop()
