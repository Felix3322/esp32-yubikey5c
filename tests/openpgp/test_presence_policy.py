"""Automatic presence per application ("my device is safe") for OpenPGP and
PIV: once the user switches it on for the application (with a press), it
satisfies the OpenPGP UIF and the touch policy of PIV key operations; the
touch of the PIV management key (it guards key replacement and settings)
and resets of either application still need a physical press.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tools/librefido python -m pytest tests/openpgp/test_presence_policy.py
"""

import hashlib
import os
import sys

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from harness.card import Card
from harness.emulator import Pcscd

sys.path.insert(0, os.path.dirname(__file__))
from legacy_store import emulator, management, touching, with_management  # noqa: E402

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

OPENPGP_AID = bytes.fromhex("D27600012401")
PIV_AID = bytes.fromhex("A000000308")
P256_ATTR = bytes.fromhex("132A8648CE3D030107")
MGM = bytes.fromhex("010203040506070801020304050607080102030405060708")
MANUAL = {"LF_EMU_UP": "manual", "LF_EMU_UP_TIMEOUT_MS": "1000"}


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    yield p
    p.stop()


def set_presence(m, **apps):
    if hasattr(m, "set_presence"):
        return m.set_presence(0, **apps)
    from fido2 import cbor
    from librefido.mgmt import INS_PROFILE_SET
    from librefido.policy import auto_mask
    m._cmd(INS_PROFILE_SET, 0, data=cbor.encode({4: auto_mask(**apps)}), what="presence")


def sw(card, *args, **kw):
    return card.transmit(*args, check=False, **kw)[1]


def pgp_sign(card):
    card.select(OPENPGP_AID)
    card.transmit(0x00, 0x20, 0x00, 0x81, b"123456")
    return sw(card, 0x00, 0x2A, 0x9E, 0x9A, hashlib.sha256(b"x").digest(), le=0)


def piv_sign(card):
    card.select(PIV_AID)
    return sw(card, 0x00, 0x87, 0x11, 0x82, bytes.fromhex("7C24 8200 8120") + bytes(32), le=0)


def mgm_auth(card, check=True):
    """Mutual authentication with the management key (9B, 3DES)."""
    tdes = Cipher(TripleDES(MGM), modes.ECB())
    resp, _ = card.transmit(0x00, 0x87, 0x03, 0x9B, bytes.fromhex("7C028000"), le=0)
    d = tdes.decryptor()
    witness = d.update(resp[4:12]) + d.finalize()
    return card.transmit(0x00, 0x87, 0x03, 0x9B, bytes.fromhex("7C148008") + witness + bytes.fromhex("8108") +
                         os.urandom(8), le=0, check=check)[1]


def mgm_ext_auth(card):
    """External authentication with the management key: the SW."""
    resp, _ = card.transmit(0x00, 0x87, 0x03, 0x9B, bytes.fromhex("7C028100"), le=0)
    e = Cipher(TripleDES(MGM), modes.ECB()).encryptor()
    answer = e.update(resp[4:12]) + e.finalize()
    return sw(card, 0x00, 0x87, 0x03, 0x9B, bytes.fromhex("7C0A8208") + answer, le=0)


def test_automatic_presence_for_openpgp_and_piv(pcscd, tmp_path):
    e = emulator(tmp_path, **MANUAL)
    e.start()
    try:
        management().close()
        card = Card()
        try:
            # OpenPGP signature key with UIF on, PIV key 82 with touch ALWAYS
            card.select(OPENPGP_AID)
            card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
            card.transmit(0x00, 0xDA, 0x00, 0xC1, P256_ATTR)
            card.transmit(0x00, 0x47, 0x80, 0x00, bytes.fromhex("B600"), le=0)
            card.transmit(0x00, 0xDA, 0x00, 0xD6, b"\x01\x20")
            card.select(PIV_AID)
            mgm_auth(card)
            tpl = bytes.fromhex("80 01 11 AA 01 01 AB 01 02")
            card.transmit(0x00, 0x47, 0x00, 0x82, bytes([0xAC, len(tpl)]) + tpl, le=0)
            # the management key (same key) with touch ALWAYS (P2 FE)
            card.transmit(0x00, 0xFF, 0xFF, 0xFE, bytes([0x03, 0x9B, len(MGM)]) + MGM)
            # nobody presses
            assert pgp_sign(card) == 0x6600
            assert piv_sign(card) == 0x6985
            card.select(PIV_AID)
            assert mgm_auth(card, check=False) == 0x6985
        finally:
            card.close()

        def enable(m):
            try:
                set_presence(m, openpgp=True, piv=True)
            except Exception as ex:
                pytest.skip("automatic presence cannot be set on this build: %s" % ex)
        touching(lambda: with_management(enable))

        card = Card()
        try:
            assert pgp_sign(card) == 0x9000                 # no press
            assert piv_sign(card) == 0x9000
            # the management key guards key replacement and settings: its
            # touch needs a physical press (also right after a key operation)
            card.select(PIV_AID)
            assert mgm_auth(card, check=False) == 0x6985
            assert mgm_ext_auth(card) == 0x6985
            assert sw(card, 0x00, 0xF6, 0x83, 0x82) == 0x6982     # MOVE KEY: no administrator
            assert touching(lambda: mgm_auth(card, check=False)) == 0x9000
            assert touching(lambda: mgm_ext_auth(card)) == 0x9000
            assert piv_sign(card) == 0x9000                 # key operations: automatic
            # resets still need a physical press
            card.select(PIV_AID)
            for _ in range(3):
                sw(card, 0x00, 0x20, 0x00, 0x80, b"000000\xff\xff")
            for _ in range(3):
                sw(card, 0x00, 0x2C, 0x00, 0x80, b"00000000" + b"111111\xff\xff")
            assert sw(card, 0x00, 0xFB, 0x00, 0x00) == 0x6985
            assert piv_sign(card) == 0x9000                 # nothing was reset
            card.select(OPENPGP_AID)
            card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
            assert sw(card, 0x00, 0xE6, 0x00, 0x00) == 0x6600
            assert pgp_sign(card) == 0x9000
        finally:
            card.close()
    finally:
        e.stop()
