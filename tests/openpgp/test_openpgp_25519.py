"""OpenPGP card 3.4 keys on Curve25519, with raw APDUs checked against Python
cryptography: EdDSA ed25519 (signature and authentication keys) and ECDH
cv25519 (decryption key), advertised in the algorithm information DO,
generated on the card or imported (the formats GnuPG uses), used with
PSO:CDS, INTERNAL AUTHENTICATE and PSO:DECIPHER, and kept encrypted at rest.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tools/librefido python -m pytest tests/openpgp/test_openpgp_25519.py
"""

import os

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from harness.card import Card
from harness.emulator import Emulator, Pcscd

OPENPGP_AID = bytes.fromhex("D27600012401")
ADMIN_PIN, USER_PIN = b"12345678", b"123456"
OID_ED25519 = bytes.fromhex("2B06010401DA470F01")
OID_CV25519 = bytes.fromhex("2B060104019755010501")
ED25519_ATTR = b"\x16" + OID_ED25519            # EdDSA
CV25519_ATTR = b"\x12" + OID_CV25519            # ECDH
P256_ATTR = bytes.fromhex("132A8648CE3D030107")
CRT = {"sig": b"\xB6\x00", "dec": b"\xB8\x00", "aut": b"\xA4\x00"}
SW_OK, SW_WRONG_DATA, SW_DATA_INVALID, SW_CONDITIONS = 0x9000, 0x6700, 0x6984, 0x6985


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    yield p
    p.stop()


@pytest.fixture
def device(pcscd, tmp_path):
    e = Emulator(workdir=str(tmp_path / "dev"))
    e.start()
    yield e
    e.stop()


@pytest.fixture
def card(device):
    c = Card()
    c.select(OPENPGP_AID)
    yield c
    c.close()


def raw(key):
    if isinstance(key, (ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey)):
        return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def tlv(tag, value):
    tag = bytes([tag]) if isinstance(tag, int) else tag
    n = len(value)
    ln = bytes([n]) if n < 0x80 else (b"\x81" + bytes([n]) if n < 0x100 else b"\x82" + n.to_bytes(2, "big"))
    return tag + ln + value


def parse_tlv(data):
    """(tag, value) pairs of a flat BER-TLV string (one or two byte tags)."""
    out, i = [], 0
    while i < len(data):
        tag = data[i]
        i += 1
        if tag & 0x1F == 0x1F:
            tag = (tag << 8) | data[i]
            i += 1
        n = data[i]
        i += 1
        if n == 0x81:
            n, i = data[i], i + 1
        elif n == 0x82:
            n, i = int.from_bytes(data[i:i + 2], "big"), i + 2
        out.append((tag, data[i:i + n]))
        i += n
    return out


def public_point(resp):
    """The 32 bytes of 7F49 { 86 20 ... }."""
    [(tag, body)] = parse_tlv(resp)
    assert tag == 0x7F49
    [(t86, point)] = parse_tlv(body)
    assert t86 == 0x86 and len(point) == 32, resp.hex()
    return point


def set_attrs(card, sig=ED25519_ATTR, dec=CV25519_ATTR, aut=ED25519_ATTR):
    card.transmit(0x00, 0x20, 0x00, 0x83, ADMIN_PIN)
    for tag, attr in ((0xC1, sig), (0xC2, dec), (0xC3, aut)):
        if attr is not None:
            card.transmit(0x00, 0xDA, 0x00, tag, attr)


def generate(card, key):
    resp, _ = card.transmit(0x00, 0x47, 0x80, 0x00, CRT[key], le=0)
    return public_point(resp)


def import_key(card, key, secret, pub=None, check=True):
    """IMPORT DATA as GnuPG sends it: 4D { CRT, 7F48 { 92 [99] }, 5F48 }."""
    hdr = b"\x92" + bytes([len(secret)])
    val = secret
    if pub is not None:
        hdr += b"\x99" + bytes([len(pub)])
        val += pub
    body = CRT[key] + tlv(b"\x7F\x48", hdr) + tlv(b"\x5F\x48", val)
    return card.transmit(0x00, 0xDB, 0x3F, 0xFF, tlv(0x4D, body), check=check)[1]


def cds(card, msg, pin=USER_PIN):
    card.transmit(0x00, 0x20, 0x00, 0x81, pin)
    return card.transmit(0x00, 0x2A, 0x9E, 0x9A, msg, le=0)[0]


def decipher(card, point, pin=USER_PIN, check=True):
    card.transmit(0x00, 0x20, 0x00, 0x82, pin)
    data = tlv(0xA6, tlv(b"\x7F\x49", tlv(0x86, point)))
    return card.transmit(0x00, 0x2A, 0x80, 0x86, data, le=0, check=check)


def signature_counter(card):
    for tag, value in parse_tlv(card.transmit(0x00, 0xCA, 0x00, 0x7A, le=0)[0][2:]):
        if tag == 0x93:
            return int.from_bytes(value, "big")
    raise AssertionError("no signature counter")


def test_algorithm_information_lists_curve25519(card):
    fa = card.transmit(0x00, 0xCA, 0x00, 0xFA, le=0)[0]
    [(tag, body)] = parse_tlv(fa)
    assert tag == 0xFA
    entries = parse_tlv(body)
    assert (0xC1, ED25519_ATTR) in entries
    assert (0xC3, ED25519_ATTR) in entries
    assert (0xC2, CV25519_ATTR) in entries
    assert (0xC2, ED25519_ATTR) not in entries
    assert (0xC1, CV25519_ATTR) not in entries


def test_put_data_takes_curve25519_where_it_belongs(card):
    card.transmit(0x00, 0x20, 0x00, 0x83, ADMIN_PIN)
    for tag, attr, sw in ((0xC1, ED25519_ATTR, SW_OK), (0xC3, ED25519_ATTR, SW_OK),
                          (0xC2, CV25519_ATTR, SW_OK), (0xC3, CV25519_ATTR, SW_OK),
                          (0xC1, CV25519_ATTR, SW_WRONG_DATA), (0xC2, ED25519_ATTR, SW_WRONG_DATA),
                          (0xC1, b"\x13" + OID_ED25519, SW_WRONG_DATA),        # ECDSA on ed25519
                          (0xC2, b"\x16" + OID_CV25519, SW_WRONG_DATA),        # EdDSA on cv25519
                          (0xC1, ED25519_ATTR[:-1], SW_WRONG_DATA),            # a truncated OID
                          (0xC1, ED25519_ATTR + b"\xFF", SW_OK)):              # import format
        assert card.transmit(0x00, 0xDA, 0x00, tag, attr, check=False)[1] == sw, (hex(tag), attr.hex())
    assert card.transmit(0x00, 0xCA, 0x00, 0xC1, le=0)[0] == ED25519_ATTR + b"\xFF"


def test_generated_keys_sign_authenticate_and_decipher(card):
    set_attrs(card)
    sig_pub = ed25519.Ed25519PublicKey.from_public_bytes(generate(card, "sig"))
    dec_raw = generate(card, "dec")
    aut_pub = ed25519.Ed25519PublicKey.from_public_bytes(generate(card, "aut"))
    # the public key read back is the one generation answered
    assert public_point(card.transmit(0x00, 0x47, 0x81, 0x00, CRT["sig"], le=0)[0]) == raw(sig_pub)
    assert public_point(card.transmit(0x00, 0x47, 0x81, 0x00, CRT["dec"], le=0)[0]) == dec_raw
    # PSO:CDS signs the data as given (PureEdDSA), up to a long message
    for n in (1, 32, 64, 255, 1000):
        msg = os.urandom(n)
        sig = cds(card, msg)
        assert len(sig) == 64
        sig_pub.verify(sig, msg)
        with pytest.raises(InvalidSignature):
            aut_pub.verify(sig, msg)
    assert signature_counter(card) == 5
    # INTERNAL AUTHENTICATE with the authentication key
    card.transmit(0x00, 0x20, 0x00, 0x82, USER_PIN)
    challenge = os.urandom(48)
    aut_pub.verify(card.transmit(0x00, 0x88, 0x00, 0x00, challenge, le=0)[0], challenge)
    # PSO:DECIPHER: the X25519 shared secret with the host's ephemeral key,
    # the point also with the 40 prefix of the OpenPGP encoding
    dec_pub = x25519.X25519PublicKey.from_public_bytes(dec_raw)
    for prefix in (b"", b"\x40"):
        eph = x25519.X25519PrivateKey.generate()
        secret, _ = decipher(card, prefix + raw(eph.public_key()))
        assert secret == eph.exchange(dec_pub)
    # a point of small order gives no secret; a point of another length is refused
    assert decipher(card, bytes(32), check=False)[1] == SW_DATA_INVALID
    assert decipher(card, os.urandom(31), check=False)[1] == SW_WRONG_DATA
    assert decipher(card, b"\x04" + os.urandom(64), check=False)[1] == SW_WRONG_DATA


def test_keys_of_the_other_kind_are_refused(card):
    """MSE can swap the decryption and authentication keys: an EdDSA key never
    deciphers and an X25519 key never signs."""
    set_attrs(card)
    generate(card, "dec")
    generate(card, "aut")
    card.transmit(0x00, 0x22, 0x41, 0xA4, bytes.fromhex("830103"))      # decipher with the aut key
    eph = x25519.X25519PrivateKey.generate()
    assert decipher(card, raw(eph.public_key()), check=False)[1] == SW_CONDITIONS
    card.transmit(0x00, 0x22, 0x41, 0xB8, bytes.fromhex("830102"))      # authenticate with the dec key
    card.transmit(0x00, 0x20, 0x00, 0x82, USER_PIN)
    assert card.transmit(0x00, 0x88, 0x00, 0x00, b"challenge", check=False)[1] == SW_CONDITIONS


def test_imported_keys_match_cryptography(device, card):
    set_attrs(card)
    # Ed25519: the seed (with the public key, as GnuPG sends it); the card's
    # signatures are the deterministic ones of RFC 8032, byte for byte
    sk = ed25519.Ed25519PrivateKey.generate()
    assert import_key(card, "sig", raw(sk), b"\x40" + raw(sk.public_key())) == SW_OK
    assert public_point(card.transmit(0x00, 0x47, 0x81, 0x00, CRT["sig"], le=0)[0]) == raw(sk.public_key())
    msg = os.urandom(100)
    assert cds(card, msg) == sk.sign(msg)
    # a seed that starts with zero bytes may come without them (an MPI)
    seed = b"\0\0" + os.urandom(30)
    sk2 = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    card.transmit(0x00, 0x20, 0x00, 0x83, ADMIN_PIN)
    assert import_key(card, "aut", seed[2:]) == SW_OK
    card.transmit(0x00, 0x20, 0x00, 0x82, USER_PIN)
    assert card.transmit(0x00, 0x88, 0x00, 0x00, msg, le=0)[0] == sk2.sign(msg)
    # cv25519: GnuPG keeps the scalar as an MPI, big endian
    dk = x25519.X25519PrivateKey.generate()
    card.transmit(0x00, 0x20, 0x00, 0x83, ADMIN_PIN)
    assert import_key(card, "dec", raw(dk)[::-1], raw(dk.public_key())) == SW_OK
    eph = x25519.X25519PrivateKey.generate()
    assert decipher(card, raw(eph.public_key()))[0] == eph.exchange(dk.public_key())
    # a public key that is not the private key's: refused, the key stays
    card.transmit(0x00, 0x20, 0x00, 0x83, ADMIN_PIN)
    other = ed25519.Ed25519PrivateKey.generate()
    assert import_key(card, "sig", raw(other), raw(sk.public_key()), check=False) == SW_WRONG_DATA
    assert import_key(card, "sig", os.urandom(33), check=False) == SW_WRONG_DATA
    assert cds(card, msg) == sk.sign(msg)
    # at rest the private keys are encrypted with the data key
    with open(device.flash_path, "rb") as f:
        image = f.read()
    for secret in (raw(sk), seed[2:], raw(dk), raw(dk)[::-1]):
        assert secret not in image


def test_keys_survive_a_restart_and_attribute_change_drops_them(device, card):
    set_attrs(card)
    pub = ed25519.Ed25519PublicKey.from_public_bytes(generate(card, "sig"))
    card.close()
    device.restart()
    c = Card()
    try:
        c.select(OPENPGP_AID)
        msg = b"after a restart"
        pub.verify(cds(c, msg), msg)
        # new attributes: the key of the slot is gone
        c.transmit(0x00, 0x20, 0x00, 0x83, ADMIN_PIN)
        c.transmit(0x00, 0xDA, 0x00, 0xC1, P256_ATTR)
        assert c.transmit(0x00, 0x47, 0x81, 0x00, CRT["sig"], check=False)[1] == 0x6A88
    finally:
        c.close()
