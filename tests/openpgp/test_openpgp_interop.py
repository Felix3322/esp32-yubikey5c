"""OpenPGP card interoperability with real clients: yubikit (parses the
constructed DOs strictly) and GnuPG's scdaemon, against the emulator.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tools/librefido python -m pytest tests/openpgp
"""

import hashlib
import os
import shutil
import subprocess

import pytest

from harness.emulator import Emulator, Pcscd

yubikit_openpgp = pytest.importorskip("yubikit.openpgp")


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


def open_session():
    from harness.card import Card, YkConnection
    card = Card()
    return yubikit_openpgp.OpenPgpSession(YkConnection(card)), card


def raw_get_data(tag):
    from harness.card import Card
    card = Card()
    try:
        card.select(bytes.fromhex("D27600012401"))
        resp, _ = card.transmit(0x00, 0xCA, tag >> 8, tag & 0xFF, le=0)
        return resp
    finally:
        card.close()


def test_data_objects_are_encoded_like_iso7816(device):
    # constructed DOs carry their own tag, simple DOs are just the value
    assert raw_get_data(0x006E)[0] == 0x6E
    assert raw_get_data(0x0065)[0] == 0x65
    assert raw_get_data(0x007A)[0] == 0x7A
    assert len(raw_get_data(0x00C4)) == 7                   # PW status bytes, no tag
    # the same answer whichever applet a client selected before
    from harness.card import Card
    card = Card()
    try:
        card.select(bytes.fromhex("A000000527471117"))      # management
    except Exception:
        pass
    finally:
        card.close()
    assert raw_get_data(0x006E)[0] == 0x6E
    assert len(raw_get_data(0x00C4)) == 7


P256_ATTR = bytes.fromhex("132A8648CE3D030107")         # ECDSA, secp256r1


def test_yubikit_parses_the_card(device):
    """yubikit unpacks 6E, 65, 7A and the PW status strictly. It gates key
    generation on YubiKey firmware versions, which this card does not claim
    to have, so keys are generated and used with plain APDUs."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    s, card = open_session()
    try:
        ard = s.get_application_related_data()
        assert ard.aid.serial and ard.aid.version
        assert ard.discretionary.pw_status.attempts_user == 3
        assert s.get_pin_status().attempts_admin == 3
        s.verify_admin("12345678")
        card.transmit(0x00, 0xDA, 0x00, 0xC1, P256_ATTR)
        resp, _ = card.transmit(0x00, 0x47, 0x80, 0x00, bytes.fromhex("B600"), le=0)
        point = resp[resp.index(b"\x86\x41") + 2:][:65]
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        s.verify_pin("123456")
        digest = hashlib.sha256(b"signed").digest()
        sig, _ = card.transmit(0x00, 0x2A, 0x9E, 0x9A, digest, le=0)
        der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        pub.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        # the new key and the signature counter are visible through yubikit
        ard = s.get_application_related_data()
        assert ard.discretionary.attributes_sig.oid == yubikit_openpgp.OID.SECP256R1
        assert s.get_signature_counter() == 1
    finally:
        card.close()


@pytest.mark.skipif(not shutil.which("gpg"), reason="GnuPG not installed")
def test_gnupg_card_status(device):
    home = os.environ.get("GNUPGHOME")
    if not home or not os.environ.get("SCDAEMON_PROGRAM"):
        pytest.skip("GnuPG test home not configured (source testenv.sh)")
    # the card is present in the reader (librefido connects without powering
    # it down on disconnect)
    from librefido.pcsc import open_device
    open_device(timeout=10).close()
    # pcsc-shared: scdaemon would otherwise want the reader exclusively
    subprocess.run(["bash", "-c", "source ~/work/testenv.sh >/dev/null && GPG_TEST_PCSC_SHARED=1 gpg_test_reset"],
                   check=True, capture_output=True)
    out = subprocess.run(["gpg", "--batch", "--card-status"], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert "Application ID" in out.stdout
    assert "PIN retry counter : 3 0 3" in out.stdout or "PIN retry counter : 3 3 3" in out.stdout
    subprocess.run(["gpgconf", "--kill", "all"], check=False)
