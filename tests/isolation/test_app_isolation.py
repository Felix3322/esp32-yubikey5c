"""Application isolation: resetting one application (FIDO, OpenPGP, PIV)
leaves the others, and the device identity, untouched; PIV administration
needs the management key; PIV and OpenPGP never reach each other's data.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tools/librefido:tests/profiles python -m pytest tests/isolation
"""

import hashlib
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fido2.ctap2 import Ctap2

from harness import ctaphid
from harness.card import ApduError, Card, YkConnection
from harness.emulator import Emulator, Pcscd
from librefido.mgmt import Management

yubikit_piv = pytest.importorskip("yubikit.piv")
yubikit_oath = pytest.importorskip("yubikit.oath")

OPENPGP_AID = bytes.fromhex("D27600012401")
PIV_AID = bytes.fromhex("A000000308")
P256_ATTR = bytes.fromhex("132A8648CE3D030107")


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    ctaphid.install()
    yield p
    p.stop()


@pytest.fixture
def device(pcscd, tmp_path):
    e = Emulator(workdir=str(tmp_path / "dev"))
    e.start()
    Management.open(timeout=15).close()
    yield e
    e.stop()


# -- FIDO ---------------------------------------------------------------------
def fido_make(user):
    dev = ctaphid.open_device()
    try:
        Ctap2(dev).make_credential(os.urandom(32), {"id": "example.com", "name": "x"},
                                   {"id": user, "name": "u", "displayName": "U"},
                                   [{"type": "public-key", "alg": -7}], options={"rk": True})
    finally:
        dev.close()


def fido_users():
    dev = ctaphid.open_device()
    try:
        c = Ctap2(dev)
        try:
            a = c.get_assertion("example.com", os.urandom(32))
        except Exception:
            return set()
        users = {a.user["id"]}
        for _ in range((a.number_of_credentials or 1) - 1):
            users.add(c.get_next_assertion().user["id"])
        return users
    finally:
        dev.close()


def fido_reset():
    dev = ctaphid.open_device()
    try:
        Ctap2(dev).reset()
    finally:
        dev.close()


# -- OATH ---------------------------------------------------------------------
def oath_put():
    card = Card()
    try:
        s = yubikit_oath.OathSession(YkConnection(card))
        s.put_credential(yubikit_oath.CredentialData(
            name="alice", oath_type=yubikit_oath.OATH_TYPE.TOTP, hash_algorithm=yubikit_oath.HASH_ALGORITHM.SHA1,
            secret=b"12345678901234567890", digits=8))
    finally:
        card.close()


def oath_code():
    card = Card()
    try:
        s = yubikit_oath.OathSession(YkConnection(card))
        creds = [c for c in s.list_credentials() if c.name == "alice"]
        return s.calculate_code(creds[0], timestamp=59).value if creds else None
    finally:
        card.close()


# -- OpenPGP (plain APDUs) ----------------------------------------------------
def pgp_generate():
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
        card.transmit(0x00, 0xDA, 0x00, 0xC1, P256_ATTR)
        resp, _ = card.transmit(0x00, 0x47, 0x80, 0x00, bytes.fromhex("B600"), le=0)
        point = resp[resp.index(b"\x86\x41") + 2:][:65]
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    finally:
        card.close()


def pgp_sign(pub):
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x20, 0x00, 0x81, b"123456")
        digest = hashlib.sha256(b"pgp").digest()
        sig, _ = card.transmit(0x00, 0x2A, 0x9E, 0x9A, digest, le=0)
        der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        pub.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    finally:
        card.close()


def pgp_sig_count():
    card = Card()
    try:
        card.select(OPENPGP_AID)
        resp, _ = card.transmit(0x00, 0xCA, 0x00, 0x93, le=0)
        return int.from_bytes(resp[-3:], "big")
    finally:
        card.close()


def pgp_factory_reset():
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
        card.transmit(0x00, 0xE6, 0x00, 0x00)
        card.transmit(0x00, 0x44, 0x00, 0x00)
    finally:
        card.close()


# -- PIV (yubikit) ------------------------------------------------------------
def piv_session():
    card = Card()
    return yubikit_piv.PivSession(YkConnection(card)), card


def piv_generate(slot=yubikit_piv.SLOT.AUTHENTICATION):
    s, card = piv_session()
    try:
        s.authenticate(s.management_key_type, yubikit_piv.DEFAULT_MANAGEMENT_KEY)
        return s.generate_key(slot, yubikit_piv.KEY_TYPE.ECCP256)
    finally:
        card.close()


def piv_sign(pub, slot=yubikit_piv.SLOT.AUTHENTICATION, pin="123456"):
    s, card = piv_session()
    try:
        s.verify_pin(pin)
        sig = s.sign(slot, yubikit_piv.KEY_TYPE.ECCP256, b"piv", hashes.SHA256())
        pub.verify(sig, b"piv", ec.ECDSA(hashes.SHA256()))
    finally:
        card.close()


def piv_has_key(slot=yubikit_piv.SLOT.AUTHENTICATION):
    s, card = piv_session()
    try:
        s.get_slot_metadata(slot)
        return True
    except Exception:
        return False
    finally:
        card.close()


def piv_block_and_reset():
    s, card = piv_session()
    try:
        for _ in range(3):
            try:
                s.verify_pin("000000")
            except Exception:
                pass
        for _ in range(3):
            try:
                s.change_puk("00000000", "11111111")
            except Exception:
                pass
        s.reset()
    finally:
        card.close()


def identity():
    m = Management.open(timeout=10)
    try:
        i = m.info()
        return i["serial"], i["profiles"][i["active"]]["uuid"]
    finally:
        m.close()


def everything(e):
    fido_make(b"alice")
    oath_put()
    pgp_pub = pgp_generate()
    piv_pub = piv_generate()
    return pgp_pub, piv_pub, identity(), oath_code()


def test_fido_reset_is_fido_only(device):
    pgp_pub, piv_pub, ident, code = everything(device)
    fido_reset()
    assert fido_users() == set()
    assert oath_code() == code
    pgp_sign(pgp_pub)
    piv_sign(piv_pub)
    assert identity() == ident


def test_openpgp_reset_is_openpgp_only(device):
    pgp_pub, piv_pub, ident, code = everything(device)
    pgp_factory_reset()
    with pytest.raises(ApduError):
        pgp_sign(pgp_pub)                               # key gone, default PINs again
    piv_sign(piv_pub)                                   # PIV data key still decrypts
    assert fido_users() == {b"alice"}
    assert oath_code() == code
    assert identity() == ident


def test_piv_reset_is_piv_only(device):
    pgp_pub, piv_pub, ident, code = everything(device)
    piv_block_and_reset()
    assert not piv_has_key()
    piv_sign(piv_generate())                            # default PIN and management key
    pgp_sign(pgp_pub)                                   # OpenPGP data key still decrypts
    assert fido_users() == {b"alice"}
    assert oath_code() == code
    assert identity() == ident


def test_piv_administration_needs_the_management_key(device):
    card = Card()
    try:
        card.select(PIV_AID)
        checks = [
            (0xFF, 0xFF, 0xFF, bytes.fromhex("03 9B 18") + bytes(24)),      # SET MANAGEMENT KEY
            (0xDB, 0x3F, 0xFF, bytes.fromhex("5C 03 5F C1 02 53 01 00")),   # PUT DATA (CHUID)
            (0xFE, 0x11, 0x9A, bytes.fromhex("06 20") + bytes(32)),         # IMPORT KEY
            (0xF6, 0x9C, 0x9A, b""),                                        # MOVE KEY
            (0xFA, 0x05, 0x05, b""),                                        # SET RETRIES
        ]
        for ins, p1, p2, data in checks:
            with pytest.raises(ApduError) as err:
                card.transmit(0x00, ins, p1, p2, data)
            assert err.value.sw == 0x6982, "INS %02X: %04X" % (ins, err.value.sw)
    finally:
        card.close()

    # a management key session ends with the selection
    s, card = piv_session()
    try:
        s.authenticate(s.management_key_type, yubikit_piv.DEFAULT_MANAGEMENT_KEY)
        card.select(OPENPGP_AID)
        card.select(PIV_AID)
        with pytest.raises(ApduError) as err:
            card.transmit(0x00, 0xDB, 0x3F, 0xFF, bytes.fromhex("5C 03 5F C1 02 53 01 00"))
        assert err.value.sw == 0x6982
    finally:
        card.close()


def test_piv_and_openpgp_do_not_share_files(device):
    pgp_pub = pgp_generate()
    pgp_sign(pgp_pub)
    count = pgp_sig_count()
    assert count == 1
    # PIV retired key 18 has reference 93, the tag of the OpenPGP signature counter
    piv_pub = piv_generate(yubikit_piv.SLOT.RETIRED18)
    piv_sign(piv_pub, yubikit_piv.SLOT.RETIRED18)
    assert pgp_sig_count() == count
    s, card = piv_session()
    try:
        assert s.get_slot_metadata(yubikit_piv.SLOT.RETIRED18).key_type == yubikit_piv.KEY_TYPE.ECCP256
        # references that are no PIV keys (here: OpenPGP algorithm attributes)
        card.select(PIV_AID)
        for ref in (0xC1, 0xC4, 0x6E):
            with pytest.raises(ApduError) as err:
                card.transmit(0x00, 0xF7, 0x00, ref, le=0)
            assert err.value.sw == 0x6A88
    finally:
        card.close()
    pgp_sign(pgp_pub)
