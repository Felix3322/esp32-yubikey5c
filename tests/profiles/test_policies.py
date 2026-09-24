"""Per-profile policies: automatic presence per application ("my device is
safe"), secure profiles, LED brightness.

    PYTHONPATH=tests:tools/librefido:tests/profiles python -m pytest tests/profiles/test_policies.py
"""

import os
import threading
import time

import pytest
from fido2.ctap import CtapError

from harness.emulator import Button
from librefido import provision
from librefido.pcsc import ApduError
from test_profiles_backup import ctap2, device, emulators, make_rk, pcscd, user_ids, wait_reboot  # noqa: F401

MANUAL = {"LF_EMU_UP": "manual", "LF_EMU_UP_TIMEOUT_MS": "1200"}


def touching(fn):
    """Runs fn while the button is pressed every 0.3 s."""
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


def no_touch_rk(user):
    try:
        make_rk(user)
        return True
    except CtapError as e:
        assert e.code == CtapError.ERR.USER_ACTION_TIMEOUT, e
        return False


def test_automatic_presence_per_application(pcscd, emulators):
    e = emulators(env=MANUAL)
    m = device(e)
    assert m.info()["profiles"][0]["auto_presence"] == []
    assert not no_touch_rk(b"a")                        # a press is needed by default

    with pytest.raises(ApduError) as err:               # switching it on needs a press
        m.set_presence(0, fido=True)
    assert err.value.sw == 0x6985
    touching(lambda: m.set_presence(0, fido=True))
    assert m.info()["profiles"][0]["auto_presence"] == ["fido"]
    assert no_touch_rk(b"b")                            # FIDO without a press now

    # destructive and copying operations still need a physical press
    dev, c = ctap2()
    try:
        with pytest.raises(CtapError) as err:
            c.reset()
        assert err.value.code in (CtapError.ERR.USER_ACTION_TIMEOUT, CtapError.ERR.NOT_ALLOWED)
    finally:
        dev.close()
    with pytest.raises(ApduError) as err:
        m.export_profile()
    assert err.value.sw == 0x6985
    assert user_ids() == {b"b"}                         # nothing was reset

    m.set_presence(0, fido=False)                       # switching off needs no press
    assert not no_touch_rk(b"c")
    m.close()


def test_secure_profile(pcscd, emulators, tmp_path):
    e = emulators(env=MANUAL)
    m = device(e)
    # the root key must be bound to the chip first
    with pytest.raises(ApduError) as err:
        touching(lambda: m.create_secure_profile(1))
    assert err.value.sw == 0x6982
    touching(lambda: provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path)))
    touching(lambda: m.create_secure_profile(1))
    wait_reboot(m)
    info = m.info()
    p = info["profiles"][1]
    assert p["used"] and p["secure"] and p["no_export"]
    touching(lambda: m.select_profile(1))
    wait_reboot(m)
    info = m.info()
    assert info["active"] == 1 and not info["export_allowed"]
    assert info["security"]["root_key"] == "flash, bound to HMAC eFuse key"

    touching(lambda: make_rk(b"secure"))
    with pytest.raises(ApduError) as err:
        touching(m.export_profile)
    assert err.value.sw == 0x6986
    with pytest.raises(ApduError):                      # stays non-exportable
        touching(lambda: m.set_profile(1, no_export=False))
    with pytest.raises(ApduError):                      # no automatic presence
        touching(lambda: m.set_presence(1, fido=True))
    assert not m.info()["profiles"][1]["auto_presence"]
    m.close()


def test_imports_do_not_carry_policies(pcscd, emulators):
    a = emulators("a", env=MANUAL)
    m = device(a)
    touching(lambda: m.set_presence(0, fido=True, oath=True))
    stream = touching(m.export_profile)
    m.close()
    a.stop()

    b = emulators("b", env=MANUAL)
    m = device(b)
    touching(lambda: m.import_profile(stream, 1))
    p = m.info()["profiles"][1]
    assert p["used"] and p["auto_presence"] == [] and not p["secure"]
    m.close()


def test_led_brightness(pcscd, emulators):
    e = emulators()
    m = device(e)
    m.set_led_brightness(40)
    assert m.info()["board"]["led_brightness"] == 40
    e.restart()
    m.reconnect()
    assert m.info()["board"]["led_brightness"] == 40
    with pytest.raises(ApduError):
        m.set_led_brightness(300)
    m.close()


def test_aaguid_custom(pcscd, emulators):
    """A profile's AAGUID is its own file (build default until set), always
    needs a touch, is reported for the mounted profile only, survives a
    restart, travels with a clone, and reaches getInfo/attestation."""
    e = emulators(env=MANUAL)
    m = device(e)
    idx = m.info()["active"]
    default = m.info()["profiles"][idx]["aaguid"]
    assert default == "08c228d97ea02bc8d08e0d22a6d13f7d"   # nothing set yet: the STANDARD build default

    dev, c = ctap2()
    try:
        assert c.info.aaguid.hex() == "08c228d97ea02bc8d08e0d22a6d13f7d"     # STANDARD build default
    finally:
        dev.close()

    custom = "11223344556677889900aabbccddeeff"[:32]
    with pytest.raises(ApduError) as err:
        m.set_aaguid(custom)                    # no touch: refused, nothing changed
    assert err.value.sw == 0x6985
    assert m.info()["profiles"][idx]["aaguid"] == default

    touching(lambda: m.set_aaguid(custom))
    assert m.info()["profiles"][idx]["aaguid"] == custom

    dev, c = ctap2()
    try:
        assert c.info.aaguid.hex() == custom
        cred = touching(lambda: c.make_credential(
            os.urandom(32), {"id": "example.com", "name": "example.com"},
            {"id": b"u", "name": "u", "displayName": "U"}, [{"type": "public-key", "alg": -7}],
            options={"rk": True}))
        assert cred.auth_data.credential_data.aaguid.hex() == custom
    finally:
        dev.close()

    e.restart()                                  # the value is a flash file: it survives a restart
    m.reconnect()
    assert m.info()["profiles"][idx]["aaguid"] == custom

    with pytest.raises(ValueError):
        m.set_aaguid("too short")

    touching(lambda: m.set_aaguid(None))          # back to the build default
    assert m.info()["profiles"][idx]["aaguid"] == default
    m.close()


def test_aaguid_not_reported_for_unmounted_profile(pcscd, emulators):
    """A slot that is not mounted cannot report its AAGUID (its own file is
    only reachable while its store is mounted): the tool sees this as
    'unknown', not 'using the default'."""
    e = emulators()
    m = device(e)
    profiles = m.info()["profiles"]
    other = next(i for i in range(len(profiles)) if i != m.info()["active"])
    assert profiles[other]["aaguid"] is None
    m.close()
