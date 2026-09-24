"""OpenPGP data at rest and stores of earlier firmware: the data key file
(EF_DEK) and the PIN verifiers (OpenPGP and PIV) are sealed by the secure
key store; plaintext ones (earlier firmware) keep working and are sealed
only once the running firmware is confirmed; TERMINATE DF shreds the old
sealed records (new epoch); Reset Codes of earlier firmware are dropped;
keys survive a profile export and import to another device; a root key
held until it is bound opens no key and nothing is written with it.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tools/librefido python -m pytest tests/openpgp/test_openpgp_at_rest.py
"""

import hashlib
import os
import sys

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from harness.card import Card
from harness.emulator import Pcscd

sys.path.insert(0, os.path.dirname(__file__))
from legacy_store import (confirm, double_hash_pin, emulator, files_of, management, plant,  # noqa: E402
                          run_unconfirmed, scanned_len, with_management)

OPENPGP_AID = bytes.fromhex("D27600012401")
PIV_AID = bytes.fromhex("A000000308")
P256_ATTR = bytes.fromhex("132A8648CE3D030107")
EF_DEK, EF_RC, EF_PW_PRIV = 0x1099, 0x1082, 0x10C4
EF_PW1, EF_PW3, EF_PIV_PIN, EF_PIV_PUK = 0x1081, 0x1083, 0x1184, 0x1185
VERIFIERS = (EF_PW1, EF_PW3, EF_PIV_PIN, EF_PIV_PUK)
DEK_PLAIN, DEK_SEALED = 16 + 4 * 32, 16 + 4 * 32 + 32      # with the PIV mark
PW_PLAIN, PW_SEALED = 33, 33 + 32                           # length byte, double hash
PIV_PIN = b"123456\xff\xff"
INS_PROVISION = 0x50


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    yield p
    p.stop()


@pytest.fixture
def devices(pcscd, tmp_path):
    made = []

    def make(name="dev"):
        e = emulator(tmp_path, name)
        made.append(e)
        e.start()
        management().close()                    # the card is in the reader
        return e
    yield make
    for e in made:
        e.stop()


def restart(e):
    e.restart()
    management().close()


def select_both():
    """OpenPGP and PIV once each (each selection scans the store)."""
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.select(PIV_AID)
        card.select(OPENPGP_AID)
    finally:
        card.close()


def generate(admin=b"12345678"):
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x20, 0x00, 0x83, admin)
        card.transmit(0x00, 0xDA, 0x00, 0xC1, P256_ATTR)
        resp, _ = card.transmit(0x00, 0x47, 0x80, 0x00, bytes.fromhex("B600"), le=0)
        point = resp[resp.index(b"\x86\x41") + 2:][:65]
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    finally:
        card.close()


def sign(pub, pin=b"123456"):
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x20, 0x00, 0x81, pin)
        digest = hashlib.sha256(b"at rest").digest()
        sig, _ = card.transmit(0x00, 0x2A, 0x9E, 0x9A, digest, le=0)
        der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        pub.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    finally:
        card.close()


def pw_status():
    card = Card()
    try:
        card.select(OPENPGP_AID)
        return card.transmit(0x00, 0xCA, 0x00, 0xC4, le=0)[0]
    finally:
        card.close()


def test_data_key_is_sealed_at_rest(devices):
    e = devices()
    select_both()
    pub = generate()
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x24, 0x00, 0x81, b"123456" + b"a1b2c3d4")
    finally:
        card.close()
    restart(e)
    select_both()
    assert scanned_len(e, EF_DEK) == DEK_SEALED
    sign(pub, b"a1b2c3d4")


def test_plaintext_data_key_is_sealed_once_confirmed(devices):
    """A device that runs a new firmware unconfirmed writes the data key file
    as earlier firmware did (a reset would go back to that firmware), and
    uses it; once the firmware is confirmed, the next selection seals it."""
    e = devices()
    run_unconfirmed(e)
    select_both()
    pub = generate()
    sign(pub)
    select_both()
    assert scanned_len(e, EF_DEK) == DEK_PLAIN              # the format of earlier firmware
    confirm()
    select_both()                                           # seals it
    select_both()
    assert scanned_len(e, EF_DEK) == DEK_SEALED
    sign(pub)
    restart(e)
    sign(pub)


def test_reset_code_of_earlier_firmware_is_dropped(devices):
    """Earlier firmware wrapped the data key for the Reset Code in another
    form: RESET RETRY COUNTER with it would give PW1 a wrong key. It is
    dropped at the next selection; PW1 and the keys are not affected."""
    e = devices()
    select_both()
    pub = generate()
    rc = b"87654321"
    status = bytearray(pw_status() + b"\x03\x03")           # + the PIV PIN and PUK counters
    status[5] = 3
    plant({EF_RC: bytes([len(rc)]) + double_hash_pin(rc), EF_PW_PRIV: bytes(status)})
    assert pw_status()[5] == 0                              # no Reset Code any more
    card = Card()
    try:
        card.select(OPENPGP_AID)
        assert card.transmit(0x00, 0x2C, 0x00, 0x81, rc + b"246810", check=False)[1] == 0x6983
    finally:
        card.close()
    sign(pub)
    # a Reset Code set now works
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
        card.transmit(0x00, 0xDA, 0x00, 0xD3, rc)
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x2C, 0x00, 0x81, rc + b"246810")
    finally:
        card.close()
    sign(pub, b"246810")


def test_keys_travel_with_the_profile(devices):
    """Sealed records open with the profile root key and identity, which the
    backup carries: OpenPGP and PIV keys work on the device it is imported
    into."""
    e = devices("a")
    select_both()
    pub = generate()
    stream = with_management(lambda m: m.export_profile())
    e.stop()
    e2 = devices("b")
    with_management(lambda m: m.import_profile(stream, target=0))
    sign(pub)
    select_both()
    assert scanned_len(e2, EF_DEK) == DEK_SEALED


# -- PIN verifiers -------------------------------------------------------------

def sw(card, *args, **kw):
    return card.transmit(*args, check=False, **kw)[1]


def change_pw1(old, new):
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x24, 0x00, 0x81, old + new)
    finally:
        card.close()


def piv_pin_is_default():
    """GET METADATA of the PIV PIN: its "default value" flag."""
    card = Card()
    try:
        card.select(PIV_AID)
        resp, _ = card.transmit(0x00, 0xF7, 0x00, 0x80, le=0)
        return resp[resp.index(b"\x05\x01") + 2] == 1
    finally:
        card.close()


def test_pin_verifiers_are_sealed_at_rest(devices):
    """The PIN verifiers (the PIN length and an unkeyed hash of the PIN) are
    sealed like the data key file: a flash dump gives no PIN to guess
    offline without the root key. They keep working through changes, the
    Reset Code, a restart, and GET METADATA's default-PIN flag."""
    e = devices()
    select_both()
    for fid in VERIFIERS:
        assert scanned_len(e, fid) == PW_SEALED, hex(fid)
    assert piv_pin_is_default()
    pub = generate()
    change_pw1(b"123456", b"a1b2c3d4")
    rc = b"87654321"
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
        card.transmit(0x00, 0xDA, 0x00, 0xD3, rc)
        card.select(PIV_AID)
        card.transmit(0x00, 0x24, 0x00, 0x80, PIV_PIN + b"654321\xff\xff")
    finally:
        card.close()
    assert not piv_pin_is_default()
    restart(e)
    select_both()
    for fid in VERIFIERS + (EF_RC,):
        assert scanned_len(e, fid) == PW_SEALED, hex(fid)
    sign(pub, b"a1b2c3d4")
    card = Card()
    try:
        card.select(OPENPGP_AID)
        assert sw(card, 0x00, 0x20, 0x00, 0x81, b"123456") == 0x63C2      # the old PW1
        card.transmit(0x00, 0x2C, 0x00, 0x81, rc + b"246810")            # the Reset Code
        card.select(PIV_AID)
        card.transmit(0x00, 0x20, 0x00, 0x80, b"654321\xff\xff")
    finally:
        card.close()
    sign(pub, b"246810")


def test_pin_verifiers_of_earlier_format_are_sealed_once_confirmed(devices):
    """While a new firmware runs unconfirmed, verifiers are written (and
    rewritten) in the plaintext format of earlier firmware, which a rollback
    reads; they work, and are sealed once the firmware is confirmed."""
    e = devices()
    run_unconfirmed(e)
    select_both()
    pub = generate()
    change_pw1(b"123456", b"a1b2c3d4")
    select_both()
    for fid in VERIFIERS:
        assert scanned_len(e, fid) == PW_PLAIN, hex(fid)
    assert scanned_len(e, EF_DEK) == DEK_PLAIN
    assert piv_pin_is_default()
    sign(pub, b"a1b2c3d4")
    confirm()
    select_both()                                           # seals them
    select_both()
    for fid in VERIFIERS:
        assert scanned_len(e, fid) == PW_SEALED, hex(fid)
    assert piv_pin_is_default()
    sign(pub, b"a1b2c3d4")
    card = Card()
    try:
        card.select(OPENPGP_AID)
        assert sw(card, 0x00, 0x20, 0x00, 0x81, b"123456") == 0x63C2
    finally:
        card.close()


def test_terminate_shreds_the_old_sealed_records(devices):
    """TERMINATE DF starts a new epoch of the OpenPGP namespace: the data
    key file and PW1 verifier of before the reset, put back from a copy, no
    longer open. A verifier that does not open matches no PIN, and each try
    is counted (the PW can be blocked, which a reset asks for)."""
    e = devices()
    select_both()
    generate()
    change_pw1(b"123456", b"a1b2c3d4")
    old = with_management(lambda m: files_of(m.export_profile()))
    assert len(old[EF_PW1]) == PW_SEALED and len(old[EF_DEK]) == DEK_SEALED
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
        card.transmit(0x00, 0xE6, 0x00, 0x00)
        card.transmit(0x00, 0x44, 0x00, 0x00)
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x20, 0x00, 0x81, b"123456")                  # the defaults
    finally:
        card.close()
    select_both()
    assert scanned_len(e, EF_DEK) == DEK_SEALED and scanned_len(e, EF_PW1) == PW_SEALED
    plant({EF_DEK: old[EF_DEK], EF_PW1: old[EF_PW1]})
    card = Card()
    try:
        card.select(OPENPGP_AID)
        assert sw(card, 0x00, 0x20, 0x00, 0x81, b"a1b2c3d4") == 0x63C2
        assert sw(card, 0x00, 0x20, 0x00, 0x81, b"123456") == 0x63C1
        card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")               # PW3 of the reset
    finally:
        card.close()


def test_verifiers_that_do_not_open_can_still_be_blocked(devices):
    """A sealed verifier that does not open (damaged, or put there by
    someone) matches no PIN, and every attempt counts: PW3, and the PIV PIN
    and PUK, can be blocked, and the application reset to its defaults."""
    devices()
    select_both()

    def garbage(ns):
        return b"LK\x01" + bytes([ns]) + os.urandom(12 + 33 + 16)
    plant({EF_PW3: garbage(2), EF_PIV_PUK: garbage(3)})
    card = Card()
    try:
        card.select(OPENPGP_AID)
        assert [sw(card, 0x00, 0x20, 0x00, 0x83, b"12345678") for _ in range(3)] == [0x63C2, 0x63C1, 0x6983]
        card.transmit(0x00, 0xE6, 0x00, 0x00)                            # PW3 blocked: TERMINATE
        card.transmit(0x00, 0x44, 0x00, 0x00)
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
        card.select(PIV_AID)
        for _ in range(3):
            sw(card, 0x00, 0x20, 0x00, 0x80, b"000000\xff\xff")
        assert [sw(card, 0x00, 0x2C, 0x00, 0x80, b"12345678" + PIV_PIN) for _ in range(3)] == \
            [0x63C2, 0x63C1, 0x6983]
        card.transmit(0x00, 0xFB, 0x00, 0x00)                            # PIN and PUK blocked: RESET
        card.select(PIV_AID)
        card.transmit(0x00, 0x2C, 0x00, 0x80, b"12345678" + b"654321\xff\xff")
    finally:
        card.close()


# -- a root key held until it is bound --------------------------------------------

def selected(card, aid):
    """SELECT: True if the application answers, False if it is refused
    outright while the key store is locked."""
    s = sw(card, 0x00, 0xA4, 0x04, 0x00, aid, le=0)
    assert s in (0x9000, 0x6A82), hex(s)
    return s == 0x9000


def test_held_root_opens_no_key_and_writes_nothing(pcscd, tmp_path):
    """A plain root key on a chip that now has the HMAC key and Secure Boot
    is held until `bind-root-key`. The OpenPGP data key is bound to it: in
    that state OpenPGP and PIV refuse whatever needs a PIN, a key or writes
    (6985), so no key is used or written with a wrong data key. Bound (and
    restarted), the keys of before work."""
    e = emulator(tmp_path)
    e.start()
    try:
        management().close()
        select_both()
        pub = generate()
    finally:
        e.stop()
    with open(e.efuse_path, "wb") as f:
        f.write(os.urandom(32))                             # the chip has an HMAC key
    e.extra_env["LF_EMU_CHIP_SECURE"] = "1"
    e.start()
    try:
        m = management()
        try:
            assert m.info()["security"]["root_key"] == "flash (not bound to the chip)"
        finally:
            m.close()
        digest = hashlib.sha256(b"held").digest()
        card = Card()
        try:
            if selected(card, OPENPGP_AID):
                assert card.transmit(0x00, 0xCA, 0x00, 0xC4, le=0)[1] == 0x9000   # reading works
                assert sw(card, 0x00, 0x20, 0x00, 0x81, b"123456") == 0x6985
                assert sw(card, 0x00, 0x20, 0x00, 0x83, b"12345678") == 0x6985
                assert sw(card, 0x00, 0x2A, 0x9E, 0x9A, digest, le=0) == 0x6985
                assert sw(card, 0x00, 0x47, 0x80, 0x00, bytes.fromhex("B600"), le=0) == 0x6985
                assert sw(card, 0x00, 0x24, 0x00, 0x81, b"123456" + b"a1b2c3d4") == 0x6985
                assert sw(card, 0x00, 0xE6, 0x00, 0x00) == 0x6985
            if selected(card, PIV_AID):
                assert sw(card, 0x00, 0x20, 0x00, 0x80, PIV_PIN) == 0x6985
                assert sw(card, 0x00, 0x87, 0x03, 0x9B, bytes.fromhex("7C028000"), le=0) == 0x6985
                assert sw(card, 0x00, 0x47, 0x00, 0x9A, bytes.fromhex("AC03800111"), le=0) == 0x6985
                assert sw(card, 0x00, 0xFB, 0x00, 0x00) == 0x6985
        finally:
            card.close()
        with_management(lambda m: m._cmd(INS_PROVISION, 0xA5, 0x01, what="bind root key"))
        e.restart()
        management().close()
        sign(pub)                                           # the key of before, the PWs of before
        card = Card()
        try:
            card.select(PIV_AID)
            card.transmit(0x00, 0x20, 0x00, 0x80, PIV_PIN)
        finally:
            card.close()
    finally:
        e.stop()
