"""FIDO records across a firmware update.

While the running firmware is unconfirmed a reset can roll it back to 2.0.0,
which reads only the earlier formats: the device key stays (or is written) in
format 0x01 (33 bytes) and the pcmr token plain (32 bytes), whatever FIDO
does. Once confirmed, the first use seals them (sks records, 64 bytes).

A HARDENED build keeps reading the device key of a profile written by
earlier firmware (only a profile created secure refuses the earlier formats)
and seals it once confirmed.

The store is inspected through the sizes the store scan logs; selecting the
PIV application runs a scan.

    PYTHONPATH=tests:pico-fido/tests:tools/librefido:tests/profiles python -m pytest tests/fido
"""

import os
import sys

import pytest
from fido2.ctap1 import Ctap1
from fido2.ctap2 import ClientPin, Ctap2
from fido2.ctap2.pin import PinProtocolV2
from fido2.utils import sha256

from harness import ctaphid
from harness.card import Card
from harness.emulator import Emulator, Pcscd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "openpgp"))
from legacy_store import confirm, emulator, management, run_unconfirmed, scanned_len  # noqa: E402

EF_KEY_DEV, EF_PAUTHTOKEN = 0xCC00, 0x1091
F1_LEN, SEALED_KEY_LEN, SEALED_TOKEN_LEN = 33, 64, 64
PIV_AID = bytes.fromhex("A000000308")
PIN = "123456"
RP = {"id": "example.com", "name": "Example"}
HARDENED = os.environ.get("LF_EMU_BIN_HARDENED")


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


def scan():
    """Makes the device scan its store (and log the file sizes)."""
    card = Card()
    try:
        card.select(PIV_AID)
    finally:
        card.close()


def make_rk(c, pin=None):
    kw = {}
    if pin:
        proto = PinProtocolV2()
        tok = ClientPin(c, proto).get_pin_token(pin, ClientPin.PERMISSION.MAKE_CREDENTIAL)
        cdh = os.urandom(32)
        kw = {"pin_uv_param": proto.authenticate(tok, cdh), "pin_uv_protocol": proto.VERSION}
    else:
        cdh = os.urandom(32)
    return c.make_credential(cdh, RP, {"id": b"alice", "name": "a", "displayName": "A"},
                             [{"type": "public-key", "alg": -7}], options={"rk": True}, **kw)


def assert_signs(c, att):
    cdh = os.urandom(32)
    a = c.get_assertion(RP["id"], cdh, allow_list=[{"id": att.auth_data.credential_data.credential_id,
                                                    "type": "public-key"}])
    att.auth_data.credential_data.public_key.verify(bytes(a.auth_data) + cdh, a.signature)


def u2f(dev):
    ctap1, cdh, app = Ctap1(dev), os.urandom(32), sha256(b"u2f.example")
    reg = ctap1.register(cdh, app)
    ctap1.authenticate(cdh, app, reg.key_handle).verify(app, cdh, reg.public_key)


def test_nothing_is_sealed_before_confirmation(pcscd, tmp_path):
    e = emulator(tmp_path)
    e.start()
    try:
        management().close()
        run_unconfirmed(e)
        dev, c = ctap2()
        try:
            c.reset()                                   # a new device key while unconfirmed
            att = make_rk(c)
            u2f(dev)
            ClientPin(c).set_pin(PIN)                   # new pcmr token, PIN verification
            ClientPin(c, PinProtocolV2()).get_pin_token(PIN)
            ClientPin(c).change_pin(PIN, PIN + "7")
            ClientPin(c).change_pin(PIN + "7", PIN)
            assert_signs(c, att)
        finally:
            dev.close()
        scan()
        assert scanned_len(e, EF_KEY_DEV) == F1_LEN
        assert scanned_len(e, EF_PAUTHTOKEN) == 32

        confirm()
        dev, c = ctap2()
        try:
            assert_signs(c, att)                        # the first use seals the key
        finally:
            dev.close()
        scan()
        assert scanned_len(e, EF_KEY_DEV) == SEALED_KEY_LEN

        e.restart()                                     # confirmed: no rollback
        management().close()
        scan()
        assert scanned_len(e, EF_PAUTHTOKEN) == SEALED_TOKEN_LEN
        dev, c = ctap2()
        try:
            assert_signs(c, att)
            u2f(dev)
        finally:
            dev.close()
    finally:
        e.stop()


def test_rollback_keeps_the_key_readable(pcscd, tmp_path):
    """A device key made on unconfirmed firmware (authenticatorReset), used,
    then a reset rolls back: the key is in format 0x01 (checked in the test
    above; the rolled-back process does not log its store scan) and the
    credential made with it still works."""
    e = emulator(tmp_path)
    e.start()
    try:
        management().close()
        run_unconfirmed(e)
        dev, c = ctap2()
        try:
            c.reset()
            att = make_rk(c)
            assert_signs(c, att)
        finally:
            dev.close()
        e.restart()                                     # unconfirmed: rolls back
        management().close()
        dev, c = ctap2()
        try:
            assert_signs(c, att)
        finally:
            dev.close()
    finally:
        e.stop()


@pytest.mark.skipif(not HARDENED or not os.path.exists(HARDENED), reason="LF_EMU_BIN_HARDENED not built")
def test_hardened_build_reads_the_device_key_of_earlier_firmware(pcscd, tmp_path):
    from librefido import provision
    e = emulator(tmp_path)
    e.start()
    try:
        management().close()
        run_unconfirmed(e)
        dev, c = ctap2()
        try:
            c.reset()                                   # a device key in format 0x01, as 2.0.0 writes
            att = make_rk(c)
            ClientPin(c).set_pin(PIN)
        finally:
            dev.close()
        scan()
        assert scanned_len(e, EF_KEY_DEV) == F1_LEN
    finally:
        e.stop()

    h = Emulator(workdir=e.workdir, binary=HARDENED, env={"LF_EMU_CHIP_SECURE": "1"})
    h.start()
    try:
        m = management()
        try:
            provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path))
        finally:
            m.close()
        h.restart()
        management().close()
        try:
            confirm()                                   # in case the image counts as unconfirmed
        except Exception:
            pass
        dev, c = ctap2()
        try:
            ClientPin(c, PinProtocolV2()).get_pin_token(PIN)
            assert_signs(c, att)                        # was WRONG_DATA: key refused
            u2f(dev)
        finally:
            dev.close()
        scan()
        assert scanned_len(h, EF_KEY_DEV) == SEALED_KEY_LEN
        h.restart()
        management().close()
        dev, c = ctap2()
        try:
            assert_signs(c, att)
        finally:
            dev.close()
    finally:
        h.stop()
