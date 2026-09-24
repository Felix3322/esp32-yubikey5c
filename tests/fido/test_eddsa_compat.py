"""Ed25519 credentials on firmware without EdDSA.

Discoverable Ed25519 credentials made by this firmware, then the same flash
under a build without EdDSA: credential management lists them without a
public key and can delete them, getAssertion does not offer them. Back on
this firmware, the credential left keeps its key and signs.

The build without EdDSA: LF_EMU_NOEDDSA_BIN, this tree configured with
-DCMAKE_C_FLAGS=-ULF_HAVE_25519 (as ~/work/build-ed-fido-noed), else an
earlier build (LF_EMU_PREVIOUS_BIN, ~/work/build-emu/pico_fido2). Skipped
when it lists EdDSA, or cannot read this firmware's store at all (an
earlier build with an older store format).

Earlier binaries have fixed ports: run with the global lock, not in a
parallel slot (LF_TEST_PORT_BASE unset).
"""

import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement
from fido2.ctap2.pin import PinProtocolV2
from fido2.utils import sha256

from harness import ctaphid
from harness.emulator import HID_PORT, Emulator, Pcscd

NO_EDDSA = (os.environ.get("LF_EMU_NOEDDSA_BIN") or os.environ.get("LF_EMU_PREVIOUS_BIN") or
            os.path.expanduser("~/work/build-ed-fido-noed/pico_fido2"))
if not os.path.exists(NO_EDDSA):
    NO_EDDSA = os.path.expanduser("~/work/build-emu/pico_fido2")
PIN = "314159"
RP = {"id": "ed.example", "name": "Ed"}
R = CredentialManagement.RESULT

pytestmark = pytest.mark.skipif(HID_PORT != 35962,
                                reason="the earlier builds have fixed ports: run without a test slot")


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
def emulators():
    made = []

    def make(**kw):
        e = Emulator(**kw)
        made.append(e)
        return e
    yield make
    for e in made:
        e.stop()


def open_ctap2():
    from fido2.ctap2 import Ctap2
    dev = ctaphid.open_device()
    return dev, Ctap2(dev)


def has_eddsa(c):
    return any(a["alg"] == -8 for a in c.get_info().algorithms)


def pin_token(c, permission, rp_id=None):
    proto = PinProtocolV2()
    return proto, ClientPin(c, proto).get_pin_token(PIN, permission, rp_id)


def make_rk(c, alg, uid):
    proto, tok = pin_token(c, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP["id"])
    cdh = os.urandom(32)
    return c.make_credential(cdh, RP, {"id": uid, "name": uid.decode(), "displayName": uid.decode()},
                             [{"type": "public-key", "alg": alg}], options={"rk": True},
                             pin_uv_param=proto.authenticate(tok, cdh), pin_uv_protocol=proto.VERSION)


def cred_mgmt(c):
    proto, tok = pin_token(c, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    return CredentialManagement(c, proto, tok)


def listed(c):
    cm = cred_mgmt(c)
    return cm, {cr[R.USER]["id"]: cr for cr in cm.enumerate_creds(sha256(RP["id"].encode()))}


def test_eddsa_credentials_on_a_firmware_without_eddsa(tmp_path, pcscd, emulators):
    if not os.path.exists(NO_EDDSA):
        pytest.skip("no build without EdDSA (LF_EMU_NOEDDSA_BIN)")
    wd = str(tmp_path / "dev")
    cur = emulators(workdir=wd)
    cur.start()
    dev, c = open_ctap2()
    try:
        if not has_eddsa(c):
            pytest.skip("this build has no EdDSA")
        ClientPin(c).set_pin(PIN)
        made = {uid: make_rk(c, alg, uid) for uid, alg in ((b"ed1", -8), (b"ed2", -8), (b"p256", -7))}
    finally:
        dev.close()
    cur.stop()

    old = emulators(binary=NO_EDDSA, workdir=wd)
    old.start()
    dev, c = open_ctap2()
    try:
        if has_eddsa(c):
            pytest.skip("%s has EdDSA" % NO_EDDSA)
        # only the P-256 credential is offered
        cdh = os.urandom(32)
        try:
            a = c.get_assertion(RP["id"], cdh)
        except CtapError as e:
            pytest.skip("%s does not read this firmware's store (%s)" % (NO_EDDSA, e))
        assert a.user["id"] == b"p256" and not a.number_of_credentials
        with pytest.raises(CtapError) as e:
            c.get_assertion(RP["id"], cdh, allow_list=[{"type": "public-key",
                                                       "id": made[b"ed1"].auth_data.credential_data.credential_id}])
        assert e.value.code == CtapError.ERR.NO_CREDENTIALS
        cm, creds = listed(c)
        assert cm.get_metadata()[R.EXISTING_CRED_COUNT] == 3
        assert sorted(creds) == [b"ed1", b"ed2", b"p256"]
        assert R.PUBLIC_KEY not in creds[b"ed1"] and R.PUBLIC_KEY not in creds[b"ed2"]
        assert dict(creds[b"p256"][R.PUBLIC_KEY]) == dict(made[b"p256"].auth_data.credential_data.public_key)
        assert creds[b"ed1"][R.CREDENTIAL_ID]["id"] == made[b"ed1"].auth_data.credential_data.credential_id
        # deletable
        cm.delete_cred(creds[b"ed1"][R.CREDENTIAL_ID])
        cm, creds = listed(c)
        assert cm.get_metadata()[R.EXISTING_CRED_COUNT] == 2 and sorted(creds) == [b"ed2", b"p256"]
    finally:
        dev.close()
    old.stop()

    cur = emulators(workdir=wd)
    cur.start()
    dev, c = open_ctap2()
    try:
        cm, creds = listed(c)
        assert sorted(creds) == [b"ed2", b"p256"]
        key = made[b"ed2"].auth_data.credential_data.public_key
        assert dict(creds[b"ed2"][R.PUBLIC_KEY]) == dict(key)
        cdh = os.urandom(32)
        a = c.get_assertion(RP["id"], cdh, allow_list=[creds[b"ed2"][R.CREDENTIAL_ID]])
        ed25519.Ed25519PublicKey.from_public_bytes(key[-2]).verify(a.signature, bytes(a.auth_data) + cdh)
    finally:
        dev.close()
