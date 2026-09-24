"""FIDO while the profile root key is not in use.

A plain root key on a chip that now has the HMAC eFuse key and Secure Boot
is held until `bind-root-key`. Then otp_key_1 is not the root the FIDO
records were made with (format 0x01 would decrypt into a wrong key without
an error, PIN verifiers would not match). So FIDO answers getInfo only:
CTAP2 over HID and CCID NOT_ALLOWED, U2F register/authenticate 6985; no PIN
retry is used, no key is made or rewritten. Bound (and restarted), the
credentials of before work.

    PYTHONPATH=tests:pico-fido/tests:tools/librefido:tests/profiles python -m pytest tests/fido
"""

import os
import sys

import pytest
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError, Ctap1
from fido2.ctap2 import ClientPin, Ctap2
from fido2.utils import sha256

from harness import ctaphid
from harness.card import Card
from harness.emulator import Pcscd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "openpgp"))
from legacy_store import emulator, management, with_management  # noqa: E402

INS_PROVISION = 0x50
FIDO_AID = bytes.fromhex("A0000006472F0001")
U2F_AID = bytes.fromhex("A0000005271002")
PIN = "123456"
RP = {"id": "example.com", "name": "Example"}


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    ctaphid.install()
    yield p
    p.stop()


def ctap2():
    dev = ctaphid.open_device()
    return dev, Ctap2(dev)


def test_held_root_derives_nothing(pcscd, tmp_path):
    e = emulator(tmp_path)
    e.start()
    app = sha256(b"u2f.example")
    try:
        management().close()
        dev, c = ctap2()
        try:
            att = c.make_credential(os.urandom(32), RP, {"id": b"alice", "name": "a", "displayName": "A"},
                                    [{"type": "public-key", "alg": -7}], options={"rk": True})
            reg = Ctap1(dev).register(os.urandom(32), app)
            ClientPin(c).set_pin(PIN)
        finally:
            dev.close()
    finally:
        e.stop()
    with open(e.efuse_path, "wb") as f:
        f.write(os.urandom(32))                         # the chip has an HMAC key
    e.extra_env["LF_EMU_CHIP_SECURE"] = "1"
    e.start()
    try:
        m = management()
        try:
            assert m.info()["security"]["root_key"] == "flash (not bound to the chip)"
        finally:
            m.close()
        cid = att.auth_data.credential_data.credential_id
        dev, c = ctap2()
        try:
            c.get_info()                                # still answered
            for call in (lambda: c.get_assertion(RP["id"], os.urandom(32)),
                         lambda: c.client_pin(2, ClientPin.CMD.GET_PIN_RETRIES),
                         lambda: c.make_credential(os.urandom(32), RP, {"id": b"b", "name": "b", "displayName": "B"},
                                                   [{"type": "public-key", "alg": -7}]),
                         lambda: c.reset()):
                with pytest.raises(CtapError) as err:
                    call()
                assert err.value.code == CtapError.ERR.NOT_ALLOWED
            ctap1 = Ctap1(dev)
            for call in (lambda: ctap1.register(os.urandom(32), app),
                         lambda: ctap1.authenticate(os.urandom(32), app, reg.key_handle)):
                with pytest.raises(ApduError) as err:
                    call()
                assert err.value.code == 0x6985
        finally:
            dev.close()
        card = Card()
        try:
            for aid in (FIDO_AID, U2F_AID):
                card.select(aid)
                _, sw = card.transmit(0x00, 0x01, 0x00, 0x00, os.urandom(64), le=0, check=False)
                assert sw == 0x6985, "%s register: %04X" % (aid.hex(), sw)
                kh = reg.key_handle
                _, sw = card.transmit(0x00, 0x02, 0x03, 0x00, os.urandom(32) + app + bytes([len(kh)]) + kh,
                                      le=0, check=False)
                assert sw == 0x6985, "%s authenticate: %04X" % (aid.hex(), sw)
            card.select(FIDO_AID)
            _, sw = card.transmit(0x80, 0x10, 0x00, 0x00,
                                  bytes([0x02]) + cbor.encode({1: RP["id"], 2: os.urandom(32),
                                                               3: [{"id": cid, "type": "public-key"}]}),
                                  le=0, check=False)
            assert sw == 0x6400 | CtapError.ERR.NOT_ALLOWED
        finally:
            card.close()

        with_management(lambda m: m._cmd(INS_PROVISION, 0xA5, 0x01, what="bind root key"))
        e.restart()
        management().close()
        dev, c = ctap2()
        try:
            assert ClientPin(c).get_pin_retries()[0] == 8        # no retry was used
            cdh = os.urandom(32)
            a = c.get_assertion(RP["id"], cdh)                   # the key of before
            assert a.credential["id"] == cid
            att.auth_data.credential_data.public_key.verify(bytes(a.auth_data) + cdh, a.signature)
            cdh = os.urandom(32)
            Ctap1(dev).authenticate(cdh, app, reg.key_handle).verify(app, cdh, reg.public_key)
            ClientPin(c).get_pin_token(PIN)
        finally:
            dev.close()
    finally:
        e.stop()
