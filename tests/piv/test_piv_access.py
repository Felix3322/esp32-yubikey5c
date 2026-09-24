"""PIV access rules, with plain APDUs against the emulator: the application
property template, management key authentication (single-use witness and
challenge, no encryption oracle, mutual and external flow), PIN policies and
logout, PIN-protected objects, MOVE KEY, SET MANAGEMENT KEY and GENERATE
input checks, and the touch policy.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tools/librefido python -m pytest tests/piv/test_piv_access.py
"""

import hashlib
import os
import threading

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from harness.card import Card
from harness.emulator import Button, Emulator, Pcscd

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    TripleDES = algorithms.TripleDES

PIV_AID = bytes.fromhex("A000000308")
OPENPGP_AID = bytes.fromhex("D27600012401")
MGM = bytes.fromhex("010203040506070801020304050607080102030405060708")    # default, 3DES
AES_KEY = bytes.fromhex("00112233445566778899aabbccddeeff0011223344556677")
TDES, AES192, ECCP256 = 0x03, 0x0A, 0x11
PIN = b"123456\xff\xff"
CHUID = bytes.fromhex("5C035FC102 5301 00")


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    yield p
    p.stop()


def start(tmp_path, env=None):
    from librefido.pcsc import open_device
    e = Emulator(workdir=str(tmp_path / "dev"), env=env)
    e.start()
    try:
        open_device(timeout=15).close()
    except Exception:
        e.stop()        # a failed setup must not leave the emulator holding the ports
        raise
    return e


@pytest.fixture
def card(pcscd, tmp_path):
    e = start(tmp_path)
    try:
        c = Card()
        c.select(PIV_AID)
        yield c
        c.close()
    finally:
        e.stop()


def sw(card, *args, **kw):
    return card.transmit(*args, check=False, **kw)[1]


def ecb(key, algo, block, encrypt=True):
    c = Cipher(TripleDES(key) if algo == TDES else algorithms.AES(key), modes.ECB())
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(block) + op.finalize()


def mutual_auth(card, key=MGM, algo=TDES):
    n = 8 if algo == TDES else 16
    resp, _ = card.transmit(0x00, 0x87, algo, 0x9B, bytes.fromhex("7C028000"), le=0)
    assert resp[:4] == bytes([0x7C, n + 2, 0x80, n])
    witness, challenge = ecb(key, algo, resp[4:4 + n], False), os.urandom(n)
    resp, _ = card.transmit(0x00, 0x87, algo, 0x9B,
                            bytes([0x7C, 2 * n + 4, 0x80, n]) + witness + bytes([0x81, n]) + challenge, le=0)
    assert resp == bytes([0x7C, n + 2, 0x82, n]) + ecb(key, algo, challenge)
    return witness, challenge


def set_aes_key(card):
    """Replaces the default 3DES management key by an AES-192 one."""
    mutual_auth(card)
    card.transmit(0x00, 0xFF, 0xFF, 0xFF, bytes([AES192, 0x9B, 24]) + AES_KEY)
    card.select(PIV_AID)


def generate(card, slot, pin_policy=None, touch_policy=1):
    tpl = bytes([0x80, 1, ECCP256])
    if pin_policy is not None:
        tpl += bytes([0xAA, 1, pin_policy])
    if touch_policy is not None:
        tpl += bytes([0xAB, 1, touch_policy])
    resp, _ = card.transmit(0x00, 0x47, 0x00, slot, bytes([0xAC, len(tpl)]) + tpl, le=0)
    point = resp[resp.index(b"\x86\x41") + 2:][:65]
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)


def sign(card, slot, pub=None, check=True):
    digest = hashlib.sha256(b"piv").digest()
    resp, s = card.transmit(0x00, 0x87, ECCP256, slot, bytes.fromhex("7C24 8200 8120") + digest, le=0, check=check)
    if s == 0x9000 and pub is not None:
        assert resp[:2] == bytes([0x7C, len(resp) - 2]) and resp[2:4] == bytes([0x82, len(resp) - 4])
        pub.verify(resp[4:], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))   # DER signature
    return s


def tlvs(data):
    out, i = {}, 0
    while i < len(data):
        t, n = data[i], data[i + 1]
        out[t] = data[i + 2:i + 2 + n]
        i += 2 + n
    return out


def test_application_property_template(card):
    apt, _ = card.select(PIV_AID)
    assert apt[0] == 0x61 and apt[1] == len(apt) - 2
    t = tlvs(apt[2:])
    assert t[0x4F] == bytes.fromhex("000010000100")
    assert t[0x79] == bytes.fromhex("4F05A000000308")
    assert t[0x50] == b"LibreFido PIV"
    ac = t[0xAC]
    algos = [ac[i + 2] for i in range(0, len(ac) - 2, 3)]
    assert all(ac[i:i + 2] == b"\x80\x01" for i in range(0, len(ac) - 2, 3))
    assert ac[-2:] == b"\x06\x00"
    assert sorted(algos) == [0x03, 0x06, 0x07, 0x08, 0x0A, 0x0C, 0x11, 0x14, 0xE0, 0xE1]  # E0/E1: Ed25519, X25519
    # also without Le: the template, not 61xx
    data, s = card.raw(bytes.fromhex("00A4040005") + PIV_AID)
    assert s == 0x9000 and data == apt
    # a shorter Le is honoured: that much, the rest with GET RESPONSE
    data, s = card.raw(bytes.fromhex("00A4040005") + PIV_AID + b"\x20")
    assert data == apt[:32] and s == 0x6100 | (len(apt) - 32)
    rest, s = card.raw(bytes([0x00, 0xC0, 0x00, 0x00, len(apt) - 32]))
    assert s == 0x9000 and data + rest == apt


def test_management_key_witness_is_single_use(card):
    # the default key is 3DES and answers only as such (8-byte witness)
    assert sw(card, 0x00, 0x87, AES192, 0x9B, bytes.fromhex("7C028000"), le=0) == 0x6A86
    mutual_auth(card)
    set_aes_key(card)
    card.transmit(0x00, 0x87, AES192, 0x9B, bytes.fromhex("7C028000"), le=0)
    # a one-byte witness was compared over its own length only
    for x in range(32):
        assert sw(card, 0x00, 0x87, AES192, 0x9B, bytes([0x7C, 6, 0x80, 1, x, 0x81, 1, 0]), le=0) == 0x6982
    assert sw(card, 0x00, 0xDB, 0x3F, 0xFF, CHUID) == 0x6982
    # the management key encrypts nothing outside a mutual authentication
    assert sw(card, 0x00, 0x87, AES192, 0x9B, bytes.fromhex("7C128110") + bytes(16), le=0) == 0x6700
    # and only with its own algorithm (a 24-byte key is no 3DES key now)
    assert sw(card, 0x00, 0x87, TDES, 0x9B, bytes.fromhex("7C028000"), le=0) == 0x6A86
    # a replayed witness fails and ends the session
    witness, challenge = mutual_auth(card, AES_KEY, AES192)
    card.transmit(0x00, 0xDB, 0x3F, 0xFF, CHUID)
    replay = bytes.fromhex("7C24 8010") + witness + bytes.fromhex("8110") + challenge
    assert sw(card, 0x00, 0x87, AES192, 0x9B, replay, le=0) == 0x6982
    assert sw(card, 0x00, 0xDB, 0x3F, 0xFF, CHUID) == 0x6982


@pytest.mark.parametrize("algo", [TDES, AES192])
def test_management_key_external_flow(card, algo):
    key, n = MGM, 8
    if algo == AES192:
        set_aes_key(card)
        key, n = AES_KEY, 16
    resp, _ = card.transmit(0x00, 0x87, algo, 0x9B, bytes.fromhex("7C028100"), le=0)
    assert resp[:4] == bytes([0x7C, n + 2, 0x81, n])
    answer = bytes([0x7C, n + 2, 0x82, n]) + ecb(key, algo, resp[4:4 + n])
    card.transmit(0x00, 0x87, algo, 0x9B, answer, le=0)
    card.transmit(0x00, 0xDB, 0x3F, 0xFF, CHUID)
    # the challenge served one attempt
    assert sw(card, 0x00, 0x87, algo, 0x9B, answer, le=0) == 0x6982


def test_pin_policies_and_logout(card):
    mutual_auth(card)
    pub_a = generate(card, 0x9A)                        # PIN once
    pub_c = generate(card, 0x9C)                        # PIN always (default for 9C)
    assert sign(card, 0x9A, check=False) == 0x6982
    card.transmit(0x00, 0x20, 0x00, 0x80, PIN)
    assert sign(card, 0x9A, pub_a) == 0x9000
    assert sign(card, 0x9A, pub_a) == 0x9000
    # the PIN entry was used by 9A: 9C wants its own
    assert sign(card, 0x9C, check=False) == 0x6982
    card.transmit(0x00, 0x20, 0x00, 0x80, PIN)
    assert sign(card, 0x9C, pub_c) == 0x9000
    assert sign(card, 0x9C, check=False) == 0x6982
    assert sign(card, 0x9A, pub_a) == 0x9000            # still verified for PIN-once keys
    # VERIFY FF logs out
    card.transmit(0x00, 0x20, 0xFF, 0x80)
    assert sw(card, 0x00, 0x20, 0x00, 0x80) == 0x63C3
    assert sign(card, 0x9A, check=False) == 0x6982
    assert sw(card, 0x00, 0x20, 0xFF, 0x80, PIN) == 0x6700
    # a signature needs the whole block, and one operation per command
    card.transmit(0x00, 0x20, 0x00, 0x80, PIN)
    two = bytes.fromhex("7C 29 8200 8120") + bytes(32) + bytes.fromhex("8503") + bytes(3)
    assert sw(card, 0x00, 0x87, ECCP256, 0x9A, two, le=0) == 0x6700


def test_pin_always_needs_the_verify_right_before(card):
    mutual_auth(card)
    card.transmit(0x00, 0xDB, 0x3F, 0xFF, bytes.fromhex("5C035FC109 5303 010203"))
    pub_a = generate(card, 0x9A)                        # PIN once
    pub_c = generate(card, 0x9C)                        # PIN always
    # any command between VERIFY and the operation spends the grant
    card.transmit(0x00, 0x20, 0x00, 0x80, PIN)
    card.transmit(0x00, 0xCB, 0x3F, 0xFF, bytes.fromhex("5C035FC109"), le=0)
    assert sign(card, 0x9C, check=False) == 0x6982
    card.transmit(0x00, 0x20, 0x00, 0x80, PIN)
    card.transmit(0x00, 0xF8, 0x00, 0x00, le=0)         # GET SERIAL
    assert sign(card, 0x9C, check=False) == 0x6982
    assert sign(card, 0x9A, pub_a) == 0x9000            # PIN once: verified is enough
    card.transmit(0x00, 0x20, 0x00, 0x80, PIN)
    assert sign(card, 0x9C, pub_c) == 0x9000
    # a PIN status query in between keeps it
    card.transmit(0x00, 0x20, 0x00, 0x80, PIN)
    assert sw(card, 0x00, 0x20, 0x00, 0x80) == 0x9000
    assert sign(card, 0x9C, pub_c) == 0x9000


def test_yubikey_default_policies(card):
    """No AA / AB tag: PIN once (always for 9C, never for 9E), no touch."""
    mutual_auth(card)
    pub_e = generate(card, 0x9E, touch_policy=None)
    meta = tlvs(card.transmit(0x00, 0xF7, 0x00, 0x9E, le=0)[0])
    assert meta[0x02] == b"\x01\x01"                     # PIN never, touch never
    assert sign(card, 0x9E, pub_e) == 0x9000             # no VERIFY
    generate(card, 0x9D, touch_policy=None)
    assert tlvs(card.transmit(0x00, 0xF7, 0x00, 0x9D, le=0)[0])[0x02] == b"\x02\x01"
    generate(card, 0x9C, touch_policy=None)
    assert tlvs(card.transmit(0x00, 0xF7, 0x00, 0x9C, le=0)[0])[0x02] == b"\x03\x01"
    # the default management key: 3DES, no touch
    meta = tlvs(card.transmit(0x00, 0xF7, 0x00, 0x9B, le=0)[0])
    assert meta[0x01] == b"\x03" and meta[0x02][1] == 1 and meta[0x05] == b"\x01"


def test_pin_protected_objects(card):
    mutual_auth(card)
    card.transmit(0x00, 0xDB, 0x3F, 0xFF, bytes.fromhex("5C035FC109 5303 010203"))
    card.select(PIV_AID)
    get = bytes.fromhex("5C035FC109")
    assert sw(card, 0x00, 0xCB, 0x3F, 0xFF, get, le=0) == 0x6982
    card.transmit(0x00, 0x20, 0x00, 0x80, PIN)
    assert card.transmit(0x00, 0xCB, 0x3F, 0xFF, get, le=0)[0] == bytes.fromhex("5303010203")
    # nor through the OpenPGP application
    card.select(OPENPGP_AID)
    assert sw(card, 0x00, 0xCA, 0xC1, 0x09, le=0) == 0x6A88


def test_move_key(card):
    mutual_auth(card)
    pub = generate(card, 0x82, pin_policy=1)            # PIN never
    generate(card, 0x9A)
    for to, frm in ((0x82, 0x82), (0x9A, 0x9B), (0x9B, 0x9A), (0x85, 0x83)):
        assert sw(card, 0x00, 0xF6, to, frm) in (0x6A86, 0x6A88), "%02X <- %02X" % (to, frm)
    assert sign(card, 0x9A, check=False) == 0x6982      # 9A kept its key and policy
    card.transmit(0x00, 0xF6, 0x85, 0x82)
    # the policy went with the key
    assert sw(card, 0x00, 0xF7, 0x00, 0x82, le=0) == 0x6A88
    meta = tlvs(card.transmit(0x00, 0xF7, 0x00, 0x85, le=0)[0])
    assert meta[0x02][0] == 1 and meta[0x03] == b"\x01"
    assert sign(card, 0x85, pub) == 0x9000
    # FF deletes
    card.transmit(0x00, 0xF6, 0xFF, 0x85)
    assert sw(card, 0x00, 0xF7, 0x00, 0x85, le=0) == 0x6A88


def test_set_management_key_and_generate_checks(card):
    mutual_auth(card)
    # SET MANAGEMENT KEY with fewer key bytes than announced
    assert sw(card, 0x00, 0xFF, 0xFF, 0xFF, bytes.fromhex("0A9B18 1122")) == 0x6700
    card.select(PIV_AID)
    mutual_auth(card)                                   # the default key is still the key
    tpl = lambda *b: bytes([0xAC, len(b)]) + bytes(b)
    assert sw(card, 0x00, 0x47, 0x00, 0x9A, tpl(0x80, 1, 0x42), le=0) == 0x6A81          # unknown algorithm
    assert sw(card, 0x00, 0x47, 0x00, 0x9A, tpl(0x80, 1, 0x07, 0x81, 1, 3), le=0) == 0x6700  # e = 3
    assert sw(card, 0x00, 0x47, 0x00, 0x9A, tpl(0x80, 1, 0x11, 0xAA, 1, 7), le=0) == 0x6700  # PIN policy 7
    assert sw(card, 0x00, 0xF7, 0x00, 0x9A, le=0) == 0x6A88  # nothing was stored


def test_keys_are_sealed_at_rest(pcscd, tmp_path):
    d = bytes.fromhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
    e = start(tmp_path)
    try:
        card = Card()
        try:
            card.select(PIV_AID)
            mutual_auth(card)
            card.transmit(0x00, 0xFE, ECCP256, 0x9A, bytes([0x06, len(d)]) + d)
            card.transmit(0x00, 0x20, 0x00, 0x80, PIN)
            pub = ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1()).public_key()
            assert sign(card, 0x9A, pub) == 0x9000
        finally:
            card.close()
    finally:
        e.stop()
    with open(e.flash_path, "rb") as f:
        assert d not in f.read()


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


def test_touch_policy_is_enforced(pcscd, tmp_path):
    e = start(tmp_path, env={"LF_EMU_UP": "manual", "LF_EMU_UP_TIMEOUT_MS": "1000"})
    card = Card()
    try:
        card.select(PIV_AID)
        # nobody touches: the default management key and keys generated
        # without a touch policy need none (as on YubiKey)
        mutual_auth(card)
        pub_default = generate(card, 0x9E, touch_policy=None)
        pub_touch = generate(card, 0x82, pin_policy=1, touch_policy=2)
        assert sign(card, 0x9E, pub_default) == 0x9000
        # the ALWAYS key refuses without a press, signs with one
        assert sign(card, 0x82, check=False) == 0x6985
        assert touching(lambda: sign(card, 0x82, pub_touch)) == 0x9000
        # a management key set with the touch flag (P2 FE) needs one
        card.transmit(0x00, 0xFF, 0xFF, 0xFE, bytes([AES192, 0x9B, 24]) + AES_KEY)
        card.select(PIV_AID)
        resp, _ = card.transmit(0x00, 0x87, AES192, 0x9B, bytes.fromhex("7C028000"), le=0)
        witness = ecb(AES_KEY, AES192, resp[4:20], False)
        auth = bytes.fromhex("7C24 8010") + witness + bytes.fromhex("8110") + os.urandom(16)
        assert sw(card, 0x00, 0x87, AES192, 0x9B, auth, le=0) == 0x6985
        touching(lambda: mutual_auth(card, AES_KEY, AES192))
    finally:
        card.close()
        e.stop()
