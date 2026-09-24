"""OpenPGP access rules, with plain APDUs against the emulator: only OpenPGP
data objects are reachable (the file table also holds PIV, FIDO and device
files), PW3 guards PUT DATA and key import, authentication ends with the
selection, the Reset Code has no default and works, IMPORT DATA checks its
lengths.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tools/librefido python -m pytest tests/openpgp/test_openpgp_access.py
"""

import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from harness.card import Card
from harness.emulator import Emulator, Pcscd

OPENPGP_AID = bytes.fromhex("D27600012401")
PIV_AID = bytes.fromhex("A000000308")
P256_ATTR = bytes.fromhex("132A8648CE3D030107")


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    yield p
    p.stop()


@pytest.fixture
def card(pcscd, tmp_path):
    from librefido.pcsc import open_device
    e = Emulator(workdir=str(tmp_path / "dev"))
    e.start()
    try:        # a failed setup must not leave the emulator holding the ports
        open_device(timeout=15).close()
        c = Card()
        c.select(OPENPGP_AID)
        yield c
        c.close()
    finally:
        e.stop()


def sw(card, *args, **kw):
    return card.transmit(*args, check=False, **kw)[1]


def pw_status(card):
    return card.transmit(0x00, 0xCA, 0x00, 0xC4, le=0)[0]


def generate_sig_key(card):
    card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
    card.transmit(0x00, 0xDA, 0x00, 0xC1, P256_ATTR)
    resp, _ = card.transmit(0x00, 0x47, 0x80, 0x00, bytes.fromhex("B600"), le=0)
    point = resp[resp.index(b"\x86\x41") + 2:][:65]
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)


def sign(card, pub):
    digest = hashlib.sha256(b"openpgp").digest()
    sig, _ = card.transmit(0x00, 0x2A, 0x9E, 0x9A, digest, le=0)
    der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    pub.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


# device root key and profile, FIDO device key / MKEK / options / PIN / token,
# OpenPGP internals (PW status record, PW1, DEK, private key), PIV keys,
# PIV PIN, PIV printed information
FOREIGN = (0xE021, 0xE022, 0xE023, 0xCC00, 0xCC0F, 0xC001, 0x1080, 0x1090, 0x10A0,
           0x10C4, 0x10C5, 0x1081, 0x1099, 0x10D1, 0x009A, 0x009B, 0x00FB, 0x1184, 0xC109)


def test_only_openpgp_data_objects(card):
    for fid in FOREIGN:
        assert sw(card, 0x00, 0xCA, fid >> 8, fid & 0xFF, le=0) == 0x6A88, "GET DATA %04X" % fid
    card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
    for fid in FOREIGN:
        assert sw(card, 0x00, 0xDA, fid >> 8, fid & 0xFF, bytes(9)) == 0x6A88, "PUT DATA %04X" % fid
    # SELECT DATA / GET NEXT DATA only know the cardholder certificate
    assert sw(card, 0x00, 0xA5, 0x00, 0x04, bytes.fromhex("6004 5C02 10C4")) == 0x6A88
    assert sw(card, 0x00, 0xCC, 0x10, 0xC4, le=0) == 0x6A88
    # nor can SELECT reach another application's files
    for fid in (0xE021, 0xCC00, 0x10C4, 0x009B):
        assert sw(card, 0x00, 0xA4, 0x00, 0x04, fid.to_bytes(2, "big"), le=0) == 0x6A88
    # the public DOs still read
    assert card.transmit(0x00, 0xCA, 0x00, 0x6E, le=0)[0][0] == 0x6E
    assert len(pw_status(card)) == 7


def test_pw_references(card):
    # VERIFY / CHANGE REFERENCE DATA name PW1 (81, 82) and PW3 (83) only
    for p2 in (0x80, 0x84, 0x90, 0x91, 0x99):
        assert sw(card, 0x00, 0x20, 0x00, p2) == 0x6B00
        assert sw(card, 0x00, 0x20, 0x00, p2, b"123456") == 0x6B00
        assert sw(card, 0x00, 0x24, 0x00, p2, b"123456123456") == 0x6B00
    # 82 without data reports PW1, not the Reset Code
    assert sw(card, 0x00, 0x20, 0x00, 0x82) == 0x63C3
    # CHANGE REFERENCE DATA needs old || new of sensible lengths
    assert sw(card, 0x00, 0x24, 0x00, 0x81, b"123456") == 0x6700
    assert sw(card, 0x00, 0x24, 0x00, 0x81, b"12345612") == 0x6700
    assert sw(card, 0x00, 0x24, 0x00, 0x83, b"12345678123") == 0x6700
    assert pw_status(card)[4:7] == bytes([3, 0, 3])      # nothing counted


def test_admin_pin_guards_put_data_and_import(card):
    card.transmit(0x00, 0x20, 0x00, 0x81, b"123456")
    card.transmit(0x00, 0x20, 0x00, 0x82, b"123456")
    for p1, p2, data in ((0x00, 0xC4, b"\x00"), (0x00, 0xD6, b"\x00\x20"), (0x00, 0xC1, P256_ATTR),
                         (0x00, 0x5B, b"Mallory"), (0x00, 0xD3, b"87654321")):
        assert sw(card, 0x00, 0xDA, p1, p2, data) == 0x6982, "PUT DATA %02X%02X" % (p1, p2)
    assert sw(card, 0x00, 0xDB, 0x3F, 0xFF, bytes.fromhex("4D03B60000")) == 0x6982
    # with PW3: C4 changes the PW status byte only, never the retry counters
    card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
    card.transmit(0x00, 0xDA, 0x00, 0xC4, b"\x00")
    assert pw_status(card) == bytes([0x00, 127, 127, 127, 3, 0, 3])
    assert sw(card, 0x00, 0xDA, 0x00, 0xC4, b"\x05") == 0x6700
    assert sw(card, 0x00, 0xDA, 0x00, 0xC4, b"\x01\x7f\x7f\x7f\x09\x09\x09\x09\x09") == 0x6700
    # fixed-size DOs and algorithm attributes are checked
    assert sw(card, 0x00, 0xDA, 0x00, 0xC7, bytes(19)) == 0x6700
    assert sw(card, 0x00, 0xDA, 0x00, 0xC1, bytes.fromhex("132B0601040182")) == 0x6700
    # UIF "permanently enabled" stays
    card.transmit(0x00, 0xDA, 0x00, 0xD6, b"\x02\x20")
    assert sw(card, 0x00, 0xDA, 0x00, 0xD6, b"\x00\x20") == 0x6982


def test_new_algorithm_drops_the_key(card):
    pub = generate_sig_key(card)
    card.transmit(0x00, 0x20, 0x00, 0x81, b"123456")
    sign(card, pub)
    card.transmit(0x00, 0xDA, 0x00, 0xC1, bytes.fromhex("010800002000"))    # RSA-2048
    keyinfo = card.transmit(0x00, 0xCA, 0x00, 0xDE, le=0)[0]
    assert keyinfo[:2] == b"\x00\x00"                     # no signature key any more
    assert sw(card, 0x00, 0x2A, 0x9E, 0x9A, bytes(32), le=0) != 0x9000


def test_authentication_ends_with_the_selection(card):
    card.transmit(0x00, 0x20, 0x00, 0x82, b"123456")
    card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
    assert sw(card, 0x00, 0x20, 0x00, 0x82) == 0x9000
    card.select(PIV_AID)
    card.select(OPENPGP_AID)
    assert sw(card, 0x00, 0x20, 0x00, 0x82) == 0x63C3
    assert sw(card, 0x00, 0x20, 0x00, 0x83) == 0x63C3
    assert sw(card, 0x00, 0x88, 0x00, 0x00, bytes(32), le=0) == 0x6982
    # a card reset too
    card.transmit(0x00, 0x20, 0x00, 0x82, b"123456")
    card.reset()
    card.select(OPENPGP_AID)
    assert sw(card, 0x00, 0x20, 0x00, 0x82) == 0x63C3
    # PW3 does not use the keys
    card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
    assert sw(card, 0x00, 0x2A, 0x9E, 0x9A, bytes(32), le=0) == 0x6982
    assert sw(card, 0x00, 0x88, 0x00, 0x00, bytes(32), le=0) == 0x6982


def test_reset_code(card):
    assert pw_status(card)[5] == 0                        # no Reset Code by default
    assert sw(card, 0x00, 0x2C, 0x00, 0x81, b"12345678" + b"654321") == 0x6983
    pub = generate_sig_key(card)                          # PW3 verified
    assert sw(card, 0x00, 0xDA, 0x00, 0xD3, b"1234567") == 0x6700
    card.transmit(0x00, 0xDA, 0x00, 0xD3, b"87654321")
    assert pw_status(card)[5] == 3
    card.select(OPENPGP_AID)
    for _ in range(3):
        card.transmit(0x00, 0x20, 0x00, 0x81, b"000000", check=False)
    assert sw(card, 0x00, 0x20, 0x00, 0x81, b"123456") == 0x6983
    # a wrong Reset Code counts; the right one sets a new PW1 that opens the key
    assert sw(card, 0x00, 0x2C, 0x00, 0x81, b"00000000" + b"246810") == 0x63C2
    card.transmit(0x00, 0x2C, 0x00, 0x81, b"87654321" + b"246810")
    assert pw_status(card)[4:6] == bytes([3, 3])
    card.transmit(0x00, 0x20, 0x00, 0x81, b"246810")
    sign(card, pub)
    # PUT DATA D3 without data removes it
    card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
    card.transmit(0x00, 0xDA, 0x00, 0xD3)
    assert pw_status(card)[5] == 0
    assert sw(card, 0x00, 0x2C, 0x00, 0x81, b"87654321" + b"135790") == 0x6983


def test_change_pin_keeps_the_keys(card):
    pub = generate_sig_key(card)
    card.transmit(0x00, 0x24, 0x00, 0x81, b"123456" + b"a1b2c3d4")
    card.transmit(0x00, 0x24, 0x00, 0x83, b"12345678" + b"admin-pin-2")
    card.select(OPENPGP_AID)
    card.transmit(0x00, 0x20, 0x00, 0x81, b"a1b2c3d4")
    sign(card, pub)
    # PW3 unblocks PW1 with a new value that opens the same key
    card.transmit(0x00, 0x20, 0x00, 0x83, b"admin-pin-2")
    card.transmit(0x00, 0x2C, 0x02, 0x81, b"999999")
    card.select(OPENPGP_AID)
    card.transmit(0x00, 0x20, 0x00, 0x81, b"999999")
    sign(card, pub)


def test_import_checks_lengths(card):
    card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
    card.transmit(0x00, 0xDA, 0x00, 0xC1, P256_ATTR)

    def imp(body):
        return sw(card, 0x00, 0xDB, 0x3F, 0xFF, bytes([0x4D, len(body)]) + body)

    d = bytes.fromhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
    # lengths past the command, in 7F48 or 5F48, or not adding up
    assert imp(bytes.fromhex("B600 7F48 04 92 82 8000 5F48 20") + d) == 0x6700
    assert imp(bytes.fromhex("B600 7F48 02 92 20 5F48 82 FFFF") + d) == 0x6700
    assert imp(bytes.fromhex("B600 7F48 02 92 20 5F48 21") + d + b"\x00") == 0x6700
    assert imp(bytes.fromhex("B600 7F48 04 92 20 92 20 5F48 40") + d + d) == 0x6700
    assert imp(bytes.fromhex("B6 40 7F48 02 92 20 5F48 20") + d) == 0x6700
    # and a well-formed one goes in
    assert imp(bytes.fromhex("B600 7F48 02 92 20 5F48 20") + d) == 0x9000
    pub = ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1()).public_key()
    card.transmit(0x00, 0x20, 0x00, 0x81, b"123456")
    sign(card, pub)
