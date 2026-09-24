"""PIV Ed25519 (E0) and X25519 (E1) keys as on YubiKey 5.7: yubikit's
PivSession (generate, sign, calculate_secret, put_key, metadata, attestation,
move and delete) and plain APDUs, checked with Python cryptography.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tools/librefido python -m pytest tests/piv/test_piv_25519.py
"""

import os

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from harness.card import Card, YkConnection
from harness.emulator import Emulator, Pcscd

piv = pytest.importorskip("yubikit.piv")
from yubikit.core.smartcard import ApduError  # noqa: E402

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

PIV_AID = bytes.fromhex("A000000308")
MGM = bytes.fromhex("010203040506070801020304050607080102030405060708")
PIN = "123456"
ED25519, X25519 = 0xE0, 0xE1
SLOT, KEY_TYPE, PIN_POLICY, TOUCH_POLICY = piv.SLOT, piv.KEY_TYPE, piv.PIN_POLICY, piv.TOUCH_POLICY
YK_VERSION_EXT = x509.ObjectIdentifier("1.3.6.1.4.1.41482.3.3")
YK_POLICY_EXT = x509.ObjectIdentifier("1.3.6.1.4.1.41482.3.8")


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
    from librefido.pcsc import open_device
    e = Emulator(workdir=str(tmp_path / "dev"))
    e.start()
    try:
        open_device(timeout=15).close()
        yield e
    finally:
        e.stop()


@pytest.fixture
def session(device):
    card = Card()
    try:
        s = piv.PivSession(YkConnection(card))
        s.authenticate(MGM)
        yield s
    finally:
        card.close()


def raw(key):
    if isinstance(key, (ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey)):
        return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def check_attestation(s, slot, pub, pin_policy, touch_policy):
    """The attestation certificate: the key (RFC 8410 public key info),
    signed by the attestation key F9, its policies."""
    cert = s.attest_key(slot)
    assert raw(cert.public_key()) == raw(pub)
    assert type(cert.public_key()) is type(pub)
    f9 = s.get_certificate(SLOT.ATTESTATION)
    assert cert.issuer == f9.subject
    f9.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    assert aki == f9.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    assert ski == x509.SubjectKeyIdentifier.from_public_key(pub).digest
    assert cert.extensions.get_extension_for_oid(YK_VERSION_EXT).value.value == bytes([5, 7, 0])
    assert cert.extensions.get_extension_for_oid(YK_POLICY_EXT).value.value == bytes([pin_policy, touch_policy])
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if isinstance(pub, ed25519.Ed25519PublicKey):
        assert usage.digital_signature and not usage.key_agreement
    else:
        assert usage.key_agreement and not usage.digital_signature
    return cert


def test_yubikit_generate_sign_agree_attest(session):
    s = session
    assert s.version >= (5, 7, 0)
    pub_ed = s.generate_key(SLOT.SIGNATURE, KEY_TYPE.ED25519)
    pub_x = s.generate_key(SLOT.KEY_MANAGEMENT, KEY_TYPE.X25519, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
    assert isinstance(pub_ed, ed25519.Ed25519PublicKey) and isinstance(pub_x, x25519.X25519PublicKey)
    # Ed25519 signs the message as given; 9C wants the PIN right before
    for n in (1, 64, 200, 1000):
        msg = os.urandom(n)
        s.verify_pin(PIN)
        pub_ed.verify(s.sign(SLOT.SIGNATURE, KEY_TYPE.ED25519, msg, None), msg)
    with pytest.raises(ApduError):
        s.sign(SLOT.SIGNATURE, KEY_TYPE.ED25519, b"no PIN", None)
    # X25519 key agreement
    s.verify_pin(PIN)
    for _ in range(3):
        eph = x25519.X25519PrivateKey.generate()
        assert s.calculate_secret(SLOT.KEY_MANAGEMENT, eph.public_key()) == eph.exchange(pub_x)
    # metadata
    md = s.get_slot_metadata(SLOT.SIGNATURE)
    assert md.key_type == KEY_TYPE.ED25519 and md.generated
    assert md.pin_policy == PIN_POLICY.ALWAYS and md.touch_policy == TOUCH_POLICY.NEVER
    assert raw(md.public_key) == raw(pub_ed)
    md = s.get_slot_metadata(SLOT.KEY_MANAGEMENT)
    assert md.key_type == KEY_TYPE.X25519 and raw(md.public_key) == raw(pub_x)
    # attestation of both
    check_attestation(s, SLOT.SIGNATURE, pub_ed, PIN_POLICY.ALWAYS, TOUCH_POLICY.NEVER)
    check_attestation(s, SLOT.KEY_MANAGEMENT, pub_x, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
    # the Ed25519 key got a self-signed certificate (as the other keys), the
    # X25519 key none (it cannot sign)
    cert = s.get_certificate(SLOT.SIGNATURE)
    assert raw(cert.public_key()) == raw(pub_ed)
    pub_ed.verify(cert.signature, cert.tbs_certificate_bytes)
    with pytest.raises(Exception):
        s.get_certificate(SLOT.KEY_MANAGEMENT)


def test_yubikit_import_move_delete(device, session):
    s = session
    sk = ed25519.Ed25519PrivateKey.generate()
    xk = x25519.X25519PrivateKey.generate()
    assert s.put_key(SLOT.AUTHENTICATION, sk, PIN_POLICY.ONCE) == KEY_TYPE.ED25519
    assert s.put_key(SLOT.RETIRED1, xk, PIN_POLICY.NEVER) == KEY_TYPE.X25519
    # the card's signatures are RFC 8032's, byte for byte
    s.verify_pin(PIN)
    msg = os.urandom(77)
    assert s.sign(SLOT.AUTHENTICATION, KEY_TYPE.ED25519, msg, None) == sk.sign(msg)
    eph = x25519.X25519PrivateKey.generate()
    assert s.calculate_secret(SLOT.RETIRED1, eph.public_key()) == eph.exchange(xk.public_key())
    md = s.get_slot_metadata(SLOT.AUTHENTICATION)
    assert not md.generated and raw(md.public_key) == raw(sk.public_key())
    assert raw(s.get_slot_metadata(SLOT.RETIRED1).public_key) == raw(xk.public_key())
    # an imported key is not attested
    with pytest.raises(ApduError):
        s.attest_key(SLOT.AUTHENTICATION)
    # MOVE KEY and DELETE KEY
    s.move_key(SLOT.AUTHENTICATION, SLOT.RETIRED5)
    with pytest.raises(ApduError):
        s.get_slot_metadata(SLOT.AUTHENTICATION)
    s.verify_pin(PIN)
    assert s.sign(SLOT.RETIRED5, KEY_TYPE.ED25519, msg, None) == sk.sign(msg)
    s.delete_key(SLOT.RETIRED5)
    with pytest.raises(ApduError):
        s.get_slot_metadata(SLOT.RETIRED5)
    # the private keys are sealed at rest
    with open(device.flash_path, "rb") as f:
        image = f.read()
    assert raw(sk) not in image and raw(xk) not in image


def mutual_auth(card):
    tdes = Cipher(TripleDES(MGM), modes.ECB())
    resp, _ = card.transmit(0x00, 0x87, 0x03, 0x9B, bytes.fromhex("7C028000"), le=0)
    d = tdes.decryptor()
    witness = d.update(resp[4:12]) + d.finalize()
    card.transmit(0x00, 0x87, 0x03, 0x9B, bytes.fromhex("7C148008") + witness + bytes.fromhex("8108") + os.urandom(8),
                  le=0)


def tlvs(data):
    out, i = {}, 0
    while i < len(data):
        t, n = data[i], data[i + 1]
        out[t] = data[i + 2:i + 2 + n]
        i += 2 + n
    return out


def auth(card, algo, slot, tag, data, check=True):
    """GENERAL AUTHENTICATE 7C { 82 00, tag data } -> the 82 value."""
    body = b"\x82\x00" + bytes([tag, len(data)]) + data
    resp, sw = card.transmit(0x00, 0x87, algo, slot, bytes([0x7C, len(body)]) + body, le=0, check=check)
    if sw != 0x9000:
        return sw
    assert resp[0] == 0x7C and resp[1] == len(resp) - 2 and resp[2] == 0x82 and resp[3] == len(resp) - 4
    return resp[4:]


def test_plain_apdus(device):
    card = Card()
    try:
        card.select(PIV_AID)
        mutual_auth(card)
        resp, _ = card.transmit(0x00, 0x47, 0x00, 0x9A, bytes.fromhex("AC03 80 01 E0"), le=0)
        assert resp[:5] == bytes.fromhex("7F49 22 86 20") and len(resp) == 5 + 32
        pub_ed = ed25519.Ed25519PublicKey.from_public_bytes(resp[5:])
        resp, _ = card.transmit(0x00, 0x47, 0x00, 0x82, bytes.fromhex("AC06 80 01 E1 AA 01 01"), le=0)
        pub_x = x25519.X25519PublicKey.from_public_bytes(resp[5:])
        # metadata: algorithm, policies, origin, public key
        meta = tlvs(card.transmit(0x00, 0xF7, 0x00, 0x9A, le=0)[0])
        assert meta[0x01] == b"\xE0" and meta[0x02] == b"\x02\x01" and meta[0x03] == b"\x01"
        assert meta[0x04] == b"\x86\x20" + raw(pub_ed)
        assert tlvs(card.transmit(0x00, 0xF7, 0x00, 0x82, le=0)[0])[0x04] == b"\x86\x20" + raw(pub_x)
        # PIN policy once for 9A: nothing without VERIFY
        assert auth(card, ED25519, 0x9A, 0x81, b"x", check=False) == 0x6982
        card.transmit(0x00, 0x20, 0x00, 0x80, b"123456\xff\xff")
        msg = os.urandom(100)
        sig = auth(card, ED25519, 0x9A, 0x81, msg)
        assert len(sig) == 64
        pub_ed.verify(sig, msg)
        with pytest.raises(InvalidSignature):
            pub_ed.verify(sig, msg + b"\0")
        # the algorithm is the key's own; each key does its own operation
        assert auth(card, X25519, 0x9A, 0x81, msg, check=False) == 0x6A86
        assert auth(card, ED25519, 0x9A, 0x85, raw(pub_x), check=False) == 0x6700
        assert auth(card, X25519, 0x82, 0x81, msg, check=False) == 0x6700
        # X25519 (PIN never): the shared secret; a u of another length, or of
        # small order, gives none
        eph = x25519.X25519PrivateKey.generate()
        assert auth(card, X25519, 0x82, 0x85, raw(eph.public_key())) == eph.exchange(pub_x)
        assert auth(card, X25519, 0x82, 0x85, raw(eph.public_key())[:31], check=False) == 0x6700
        assert auth(card, X25519, 0x82, 0x85, bytes(32), check=False) == 0x6984
        assert auth(card, X25519, 0x82, 0x85, b"\x01" + bytes(31), check=False) == 0x6984
        # import: 07 (seed) and 08 (scalar) of 32 bytes only
        assert card.transmit(0x00, 0xFE, ED25519, 0x9C, bytes([0x07, 31]) + bytes(31), check=False)[1] == 0x6700
        assert card.transmit(0x00, 0xFE, X25519, 0x9D, bytes([0x07, 32]) + bytes(32), check=False)[1] == 0x6700
    finally:
        card.close()
