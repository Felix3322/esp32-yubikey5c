"""PIV records of earlier firmware: plaintext key records and metadata
without a version byte (their touch policy was stored but never enforced).
They keep working as they did, and are sealed (and the default management
key switched to 3DES) only once the running firmware is confirmed.

Records are planted through a profile backup (export, edit, import).

    source ~/work/testenv.sh
    PYTHONPATH=tests:tools/librefido python -m pytest tests/piv/test_piv_upgrade.py
"""

import hashlib
import os
import sys

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from harness.card import Card
from harness.emulator import Pcscd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "openpgp"))
from legacy_store import (confirm, emulator, management, meta_file, plant, run_unconfirmed,  # noqa: E402
                          scanned_len, touching)

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    TripleDES = algorithms.TripleDES

PIV_AID = bytes.fromhex("A000000308")
MGM = bytes.fromhex("010203040506070801020304050607080102030405060708")
TDES, AES192, ECCP256 = 0x03, 0x0A, 0x11
PIN = b"123456\xff\xff"
D = bytes.fromhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
EF_META = 0xE010


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    yield p
    p.stop()


HARDENED = os.environ.get("LF_EMU_BIN_HARDENED")
LEGACY = {
    0x009A: b"\x03" + D,                                # group id (secp256r1), scalar
    0x009B: MGM,
    EF_META: meta_file({0x9A: bytes([ECCP256, 2, 2, 1]), 0x9B: bytes([AES192, 3, 2])}),
}


def provision_piv():
    management().close()                                # the card is in the reader
    card = Card()
    try:
        card.select(PIV_AID)                            # provisions the application
    finally:
        card.close()


@pytest.fixture
def legacy_device(pcscd, tmp_path):
    """Presence by the button only. 9A holds a plaintext P-256 key with the
    metadata earlier firmware wrote by default (PIN once, touch ALWAYS stored
    but not enforced, generated); 9B the default key in plaintext, tagged
    AES-192 (PIN and touch ALWAYS stored)."""
    e = emulator(tmp_path, LF_EMU_UP="manual", LF_EMU_UP_TIMEOUT_MS="1000")
    e.start()
    try:
        provision_piv()
        touching(lambda: plant(LEGACY))
        yield e
    finally:
        e.stop()


def mgm_auth(card, algo, key=MGM):
    n = 8 if algo == TDES else 16
    c = Cipher(TripleDES(key) if algo == TDES else algorithms.AES(key), modes.ECB())
    resp, sw = card.transmit(0x00, 0x87, algo, 0x9B, bytes.fromhex("7C028000"), le=0, check=False)
    if sw != 0x9000:
        return sw
    d = c.decryptor()
    witness = d.update(resp[4:4 + n]) + d.finalize()
    data = bytes([0x7C, 2 * n + 4, 0x80, n]) + witness + bytes([0x81, n]) + os.urandom(n)
    return card.transmit(0x00, 0x87, algo, 0x9B, data, le=0, check=False)[1]


def sign_9a(card):
    """No press: the stored touch ALWAYS of earlier firmware was never
    enforced and is not now."""
    pub = ec.derive_private_key(int.from_bytes(D, "big"), ec.SECP256R1()).public_key()
    card.transmit(0x00, 0x20, 0x00, 0x80, PIN)
    digest = hashlib.sha256(b"legacy").digest()
    resp, _ = card.transmit(0x00, 0x87, ECCP256, 0x9A, bytes.fromhex("7C24 8200 8120") + digest, le=0)
    pub.verify(resp[4:], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def metadata_policies(card, ref):
    resp, _ = card.transmit(0x00, 0xF7, 0x00, ref, le=0)
    i = resp.index(b"\x02\x02")
    return resp[i + 2:i + 4]


def select_twice():
    card = Card()
    try:
        card.select(PIV_AID)
        card.select(PIV_AID)
    finally:
        card.close()


def test_legacy_records_work_and_are_sealed_once_confirmed(legacy_device):
    e = legacy_device
    touching(lambda: run_unconfirmed(e))
    card = Card()
    try:
        card.select(PIV_AID)
        sign_9a(card)
        assert metadata_policies(card, 0x9A) == b"\x02\x01"      # PIN once, touch never (as enforced)
        # the default key keeps its tag while a rollback is possible
        assert mgm_auth(card, AES192) == 0x9000
        assert mgm_auth(card, TDES) == 0x6A86
    finally:
        card.close()
    select_twice()
    assert scanned_len(e, 0x9A) == 33 and scanned_len(e, 0x9B) == 24     # still plaintext

    confirm()
    select_twice()                                      # the first one seals
    assert scanned_len(e, 0x9A) == 33 + 32 and scanned_len(e, 0x9B) == 24 + 32
    card = Card()
    try:
        card.select(PIV_AID)
        sign_9a(card)
        assert mgm_auth(card, TDES) == 0x9000
        assert mgm_auth(card, AES192) == 0x6A86
        assert metadata_policies(card, 0x9B)[1] == 1                # no touch
    finally:
        card.close()
    e.restart()
    management().close()
    card = Card()
    try:
        card.select(PIV_AID)
        sign_9a(card)
    finally:
        card.close()


NEW_MGM = bytes(range(1, 25))
NEW_PIN = b"654321\xff\xff"


def generate_p256(card, ref):
    tpl = bytes.fromhex("800111")
    resp, _ = card.transmit(0x00, 0x47, 0x00, ref, bytes([0xAC, len(tpl)]) + tpl, le=0)
    point = resp[resp.index(b"\x86\x41") + 2:][:65]
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)


def sign_with(card, ref, pub, pin):
    card.transmit(0x00, 0x20, 0x00, 0x80, pin)
    digest = hashlib.sha256(b"moved").digest()
    resp, _ = card.transmit(0x00, 0x87, ECCP256, ref, bytes.fromhex("7C24 8200 8120") + digest, le=0)
    pub.verify(resp[4:], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def test_records_written_unconfirmed_keep_the_earlier_format(pcscd, tmp_path):
    """PIV first selected while an update runs unconfirmed: the defaults it
    provisions (management key, PIN, PUK, attestation key) and what is
    generated, set or moved then are written in plaintext, as the previous
    firmware reads them after a rollback; they work, and are sealed once
    the firmware is confirmed. A key moved from a sealed record stays
    sealed, also while a later update runs unconfirmed."""
    e = emulator(tmp_path)
    e.start()
    try:
        management().close()
        run_unconfirmed(e)
        card = Card()
        try:
            card.select(PIV_AID)                        # provisions PIV
            assert mgm_auth(card, TDES) == 0x9000
            pub = generate_p256(card, 0x9A)
            card.transmit(0x00, 0xFF, 0xFF, 0xFF, bytes([TDES, 0x9B, len(NEW_MGM)]) + NEW_MGM)
            card.transmit(0x00, 0xF6, 0x82, 0x9A)       # MOVE KEY 9A -> 82
            card.transmit(0x00, 0x24, 0x00, 0x80, PIN + NEW_PIN)
            sign_with(card, 0x82, pub, NEW_PIN)
        finally:
            card.close()
        select_twice()
        # F9 is stored in 0xFB: group id and the P-384 scalar
        assert scanned_len(e, 0x9B) == 24 and scanned_len(e, 0xFB) == 49 and scanned_len(e, 0x82) == 33
        assert scanned_len(e, 0x1184) == 33 and scanned_len(e, 0x1185) == 33     # PIN, PUK

        confirm()
        select_twice()                                  # the first one seals
        assert scanned_len(e, 0x9B) == 24 + 32 and scanned_len(e, 0xFB) == 49 + 32
        assert scanned_len(e, 0x82) == 33 + 32
        assert scanned_len(e, 0x1184) == 33 + 32 and scanned_len(e, 0x1185) == 33 + 32
        card = Card()
        try:
            card.select(PIV_AID)
            assert mgm_auth(card, TDES, NEW_MGM) == 0x9000
            sign_with(card, 0x82, pub, NEW_PIN)
        finally:
            card.close()

        run_unconfirmed(e, (2, 1, 1))
        card = Card()
        try:
            card.select(PIV_AID)
            assert mgm_auth(card, TDES, NEW_MGM) == 0x9000
            card.transmit(0x00, 0xF6, 0x83, 0x82)       # MOVE KEY 82 -> 83
            sign_with(card, 0x83, pub, NEW_PIN)
        finally:
            card.close()
        select_twice()
        assert scanned_len(e, 0x83) == 33 + 32
    finally:
        e.stop()


@pytest.mark.skipif(not HARDENED or not os.path.exists(HARDENED), reason="LF_EMU_BIN_HARDENED not built")
def test_hardened_build_uses_and_seals_records_of_earlier_firmware(pcscd, tmp_path):
    """A HARDENED build refuses plaintext records only in profiles created
    as secure profiles: a profile written by earlier firmware keeps its PIV
    keys, which are sealed at the next selection."""
    from harness.emulator import Emulator
    from librefido import provision
    e = emulator(tmp_path)                              # a store with records of earlier firmware
    e.start()
    try:
        provision_piv()
        plant(LEGACY)
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
        card = Card()
        try:
            card.select(PIV_AID)                        # seals the records
            sign_9a(card)
            assert mgm_auth(card, TDES) == 0x9000
        finally:
            card.close()
        select_twice()
        assert scanned_len(h, 0x9A) == 33 + 32 and scanned_len(h, 0x9B) == 24 + 32
    finally:
        h.stop()
