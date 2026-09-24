"""With a PIN set, what needs only user presence keeps working after a power
cycle without the PIN: WebAuthn assertions with userVerification
"discouraged" (CTAP 2.1 allows them) and U2F. The PIN guards user
verification, it does not lock the device key.

    PYTHONPATH=tests:tools/librefido:tests/profiles python -m pytest tests/profiles/test_pin_up_only.py
"""

import hashlib
import os

import pytest
from fido2.ctap import CtapError
from fido2.ctap1 import Ctap1
from fido2.ctap2 import ClientPin

from test_profiles_backup import ctap2, device, emulators, make_rk, pcscd, set_pin  # noqa: F401

RP = "example.com"


def test_up_only_after_power_cycle_with_pin(pcscd, emulators):
    e = emulators()
    m = device(e)
    make_rk(b"alice")                                   # discoverable
    dev, c = ctap2()
    try:
        cred = c.make_credential(os.urandom(32), {"id": RP, "name": RP},
                                 {"id": b"bob", "name": "b", "displayName": "B"},
                                 [{"type": "public-key", "alg": -7}])
        cred_id = cred.auth_data.credential_data.credential_id
        app_id = hashlib.sha256(b"https://u2f.example.com").digest()
        u2f = Ctap1(dev).register(os.urandom(32), app_id)
    finally:
        dev.close()
    set_pin("123456")

    e.stop(hard=True)
    e.start()
    m.reconnect()
    dev, c = ctap2()
    try:
        assert c.info.options["clientPin"]
        # discoverable credential, no allowList, no PIN
        a = c.get_assertion(RP, os.urandom(32))
        assert a.user["id"] == b"alice" and not a.auth_data.is_user_verified()
        # server-side credential through the allowList
        a = c.get_assertion(RP, os.urandom(32), [{"type": "public-key", "id": cred_id}])
        assert a.credential["id"] == cred_id
        # U2F knows nothing about PINs
        sig = Ctap1(dev).authenticate(os.urandom(32), app_id, u2f.key_handle)
        assert sig.counter > 0
        # user verification still needs the PIN
        with pytest.raises(CtapError) as err:
            c.get_assertion(RP, os.urandom(32), options={"uv": True})
        assert err.value.code in (CtapError.ERR.INVALID_OPTION, CtapError.ERR.UNSUPPORTED_OPTION,
                                  CtapError.ERR.PUAT_REQUIRED)
        token = ClientPin(c).get_pin_token("123456")
        assert token
    finally:
        dev.close()
    m.close()
