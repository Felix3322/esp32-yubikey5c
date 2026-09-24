"""Migration of stores written by firmware before LibreFido 2.

An emulator built from the unmodified upstream sources (LF_EMU_BASELINE_BIN)
creates credentials in the legacy layout; the current firmware then boots on
the same flash file and must migrate everything, bit for bit usable, without
ever writing to the legacy store.

Needs vpcd (the baseline emulator refuses to run without it): run with the
test environment of tests/README.md, e.g.
    source testenv.sh && python -m pytest tests/storage/test_migration.py
"""

import hashlib
import os

import pytest

from fido2.ctap2 import Ctap2, ClientPin
from fido2.ctap2.pin import PinProtocolV2

from harness import ctaphid
from harness.emulator import Emulator, Pcscd

BASELINE = os.environ.get("LF_EMU_BASELINE_BIN") or os.path.expanduser("~/work/build-emu-baseline/pico_fido2")
LEGACY_SPAN = 0x800000          # emulator legacy store region [0, 8 MiB)
PIN = "314159"

# The baseline binary (upstream sources) listens on the fixed default ports:
# it cannot run in a test slot with its own ports next to other runs.
pytestmark = pytest.mark.skipif(bool(os.environ.get("LF_TEST_PORT_BASE")),
                                reason="the baseline emulator has fixed ports: run without a test slot "
                                       "(LF_TEST_PORT_BASE unset, the global lock)")


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    yield p
    p.stop()


def ctap2():
    dev = ctaphid.open_device()
    return dev, Ctap2(dev)


def legacy_digest(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read(LEGACY_SPAN)).hexdigest()


def smartcard():
    from harness.card import Card, YkConnection
    return YkConnection(Card())


def oath_code():
    """TOTP of RFC 6238's SHA-1 test secret at t=59 (the credential is
    created on first use)."""
    from yubikit.oath import OathSession, CredentialData, OATH_TYPE, HASH_ALGORITHM
    conn = smartcard()
    try:
        s = OathSession(conn)
        creds = [c for c in s.list_credentials() if c.name == "alice"]
        if not creds:
            creds = [s.put_credential(CredentialData(name="alice", oath_type=OATH_TYPE.TOTP,
                                                     hash_algorithm=HASH_ALGORITHM.SHA1,
                                                     secret=b"12345678901234567890", digits=8))]
        return s.calculate_code(creds[0], timestamp=59).value
    finally:
        conn.card.close()


# OpenPGP card with raw APDUs (the legacy firmware answers GET DATA 6E
# without the outer tag, which yubikit cannot parse).
OPENPGP_AID = bytes.fromhex("D27600012401")
P256_ATTR = bytes.fromhex("132A8648CE3D030107")     # ECDSA, secp256r1


def openpgp_generate():
    from cryptography.hazmat.primitives.asymmetric import ec
    from harness.card import Card
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x20, 0x00, 0x83, b"12345678")
        card.transmit(0x00, 0xDA, 0x00, 0xC1, P256_ATTR)
        resp, _ = card.transmit(0x00, 0x47, 0x80, 0x00, bytes.fromhex("B600"), le=0)
        point = resp[resp.index(b"\x86\x41") + 2:][:65]     # 7F49 { 86 41 04 X Y }
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    finally:
        card.close()


def openpgp_sign_and_verify(public_key):
    import hashlib as hl
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from harness.card import Card
    card = Card()
    try:
        card.select(OPENPGP_AID)
        card.transmit(0x00, 0x20, 0x00, 0x81, b"123456")
        digest = hl.sha256(b"migrated").digest()
        sig, _ = card.transmit(0x00, 0x2A, 0x9E, 0x9A, digest, le=0)
        der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        public_key.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    finally:
        card.close()


@pytest.fixture
def emulators():
    """Emulator instances created by a test, always stopped afterwards."""
    made = []

    def make(**kw):
        e = Emulator(**kw)
        made.append(e)
        return e
    yield make
    for e in made:
        e.stop()


def test_legacy_store_is_migrated(tmp_path, pcscd, emulators):
    if not os.path.exists(BASELINE):
        pytest.skip("baseline emulator not built")
    ctaphid.install()
    wd = str(tmp_path / "dev")
    # The silicon ID of earlier emulator builds is all zeros; the new firmware
    # must see the same chip.
    legacy = emulators(binary=BASELINE, workdir=wd, chip_id=b"\0" * 8)
    legacy.start()
    dev, c = ctap2()
    try:
        rk = c.make_credential(os.urandom(32), {"id": "example.com", "name": "Example"},
                               {"id": b"alice", "name": "alice", "displayName": "Alice"},
                               [{"type": "public-key", "alg": -7}], options={"rk": True})
        nr = c.make_credential(os.urandom(32), {"id": "example.org", "name": "Example"},
                               {"id": b"bob", "name": "bob", "displayName": "Bob"},
                               [{"type": "public-key", "alg": -7}])
        ClientPin(c).set_pin(PIN)
    finally:
        dev.close()
    oath_before = oath_code()
    pgp_key = openpgp_generate()
    legacy.stop()
    before = legacy_digest(legacy.flash_path)

    new = emulators(workdir=wd)
    new.start()
    dev, c = ctap2()
    try:
        # PIN, retries and the device secrets came along
        pin = ClientPin(c, PinProtocolV2())
        assert pin.get_pin_retries()[0] == 8
        pin.get_pin_token(PIN)

        # discoverable credential: same ID, same key
        cdh = os.urandom(32)
        a = c.get_assertion("example.com", cdh)
        cred = rk.auth_data.credential_data
        assert a.credential["id"] == cred.credential_id
        assert a.user["id"] == b"alice"
        cred.public_key.verify(bytes(a.auth_data) + cdh, a.signature)

        # server-side credential (key derived from the migrated device key)
        cdh = os.urandom(32)
        ncred = nr.auth_data.credential_data
        a = c.get_assertion("example.org", cdh, allow_list=[{"type": "public-key", "id": ncred.credential_id}])
        ncred.public_key.verify(bytes(a.auth_data) + cdh, a.signature)
        # signature counter continued from the legacy value
        assert a.auth_data.counter > rk.auth_data.counter
    finally:
        dev.close()

    # OATH secret and OpenPGP key moved too
    assert oath_code() == oath_before
    openpgp_sign_and_verify(pgp_key)

    with open(new.log_path) as f:
        log = f.read()
    assert "migrating the legacy store into profile 1" in log
    # earlier emulator builds bound their store to a fixed stand-in eFuse key
    assert "legacy root key" in log
    new.restart()
    # The legacy firmware had locked the device key with the PIN (format
    # 0x02); verifying the PIN above converted it, so after a restart an
    # assertion that needs only user presence works without the PIN.
    dev, c = ctap2()
    try:
        cdh = os.urandom(32)
        a = c.get_assertion("example.com", cdh)
        rk.auth_data.credential_data.public_key.verify(bytes(a.auth_data) + cdh, a.signature)
        assert not a.auth_data.is_user_verified()
    finally:
        dev.close()
    new.stop()
    with open(new.log_path) as f:
        assert f.read().count("migrating the legacy store") == 1
    # the legacy store was only read
    assert legacy_digest(new.flash_path) == before
