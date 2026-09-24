"""FIDO state written by earlier firmware, read by this one.

An earlier emulator build creates the state: the upstream baseline
(LF_EMU_BASELINE_BIN, unmodified upstream sources, as in
tests/storage/test_migration.py) or a LibreFido build from before this
change (LF_EMU_PREVIOUS_BIN). The current firmware then boots on the same
flash:

- a discoverable credential on a brainpool curve (makeCredential no longer
  accepts ESB*) stays listed, with a proper COSE key, signs, and can be
  deleted;
- a device key restored without a PIN (the upstream restore needed none) is
  locked until UNLOCK, which needs a PIN: setPIN works while locked;
- credentials made with the replaced key are listed by ID only and can be
  deleted; the counts agree.

The earlier binaries have fixed ports: run with the global lock, not in a
parallel slot (LF_TEST_PORT_BASE unset).
"""

import os
import sys

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement
from fido2.ctap2.pin import PinProtocolV2
from fido2.utils import sha256

from harness import ctaphid
from harness.emulator import HID_PORT, Emulator, Pcscd

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "pico-fido", "tests", "pico-fido"))

BASELINE = os.environ.get("LF_EMU_BASELINE_BIN") or os.path.expanduser("~/work/build-emu-baseline/pico_fido2")
# LibreFido development firmware from before this change (it still made
# brainpool credentials; the upstream baseline cannot)
PREVIOUS = os.environ.get("LF_EMU_PREVIOUS_BIN") or os.path.expanduser("~/work/build-emu/pico_fido2")
PIN = "314159"

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


class _Dev:
    def __init__(self, dev):
        self.dev = dev


def open_ctap2():
    from fido2.ctap2 import Ctap2
    dev = ctaphid.open_device()
    return dev, Ctap2(dev)


def cred_mgmt(c):
    proto = PinProtocolV2()
    tok = ClientPin(c, proto).get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    return CredentialManagement(c, proto, tok)


BP_CURVES = {256: ec.BrainpoolP256R1(), 258: ec.BrainpoolP384R1(), 259: ec.BrainpoolP512R1()}


def test_brainpool_credential_of_the_previous_firmware(tmp_path, pcscd, emulators):
    if not os.path.exists(PREVIOUS):
        pytest.skip("no previous firmware build (LF_EMU_PREVIOUS_BIN)")
    wd = str(tmp_path / "dev")
    legacy = emulators(binary=PREVIOUS, workdir=wd)
    legacy.start()
    dev, c = open_ctap2()
    try:
        rp = {"id": "bp.example", "name": "BP"}
        # That firmware did not reduce the derived scalar modulo n: about a
        # third of its brainpool registrations failed (OTHER). Retried.
        made = "no"
        for _ in range(12):
            try:
                c.make_credential(os.urandom(32), rp, {"id": b"bp", "name": "bp", "displayName": "BP"},
                                  [{"type": "public-key", "alg": -265}], options={"rk": True})
                made = "yes"
            except CtapError as e:
                made = "no: %s" % e
            except (ValueError, KeyError, TypeError):   # its public key was not valid COSE
                made = "yes"
            if made == "yes":
                break
        c.make_credential(os.urandom(32), rp, {"id": b"p256", "name": "p", "displayName": "P"},
                          [{"type": "public-key", "alg": -7}], options={"rk": True})
    finally:
        dev.close()
    legacy.stop()

    new = emulators(workdir=wd)
    new.start()
    dev, c = open_ctap2()
    try:
        ClientPin(c).set_pin(PIN)
        cm = cred_mgmt(c)
        creds = cm.enumerate_creds(sha256(b"bp.example"))
        if made != "yes":
            pytest.skip("the previous firmware build did not create the brainpool credential (%s)" % made)
        assert len(creds) == 2
        assert cm.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 2
        bp = [cr for cr in creds if cr[CredentialManagement.RESULT.USER]["id"] == b"bp"][0]
        key = bp[CredentialManagement.RESULT.PUBLIC_KEY]
        assert key[1] == 2 and key[3] == -265 and key[-1] == 256
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big"),
                                            BP_CURVES[key[-1]]).public_key()
        cid = bp[CredentialManagement.RESULT.CREDENTIAL_ID]
        cdh = os.urandom(32)
        a = c.get_assertion("bp.example", cdh, allow_list=[cid])
        pub.verify(a.signature, bytes(a.auth_data) + cdh, ec.ECDSA(hashes.SHA256()))

        cm = cred_mgmt(c)
        cm.delete_cred(cid)
        assert cm.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 1
        left = cm.enumerate_creds(sha256(b"bp.example"))
        assert [cr[CredentialManagement.RESULT.USER]["id"] for cr in left] == [b"p256"]
    finally:
        dev.close()


HARDENED = os.environ.get("LF_EMU_BIN_HARDENED")


@pytest.mark.skipif(not HARDENED or not os.path.exists(HARDENED), reason="LF_EMU_BIN_HARDENED not built")
def test_hardened_build_reads_a_pin_bound_device_key(tmp_path, pcscd, emulators):
    """The upstream firmware binds the device key to the PIN (format 0x02,
    61 bytes). A HARDENED build migrating that store keeps it usable: the
    PIN verification converts it."""
    from librefido import provision
    from librefido.mgmt import Management
    if not os.path.exists(BASELINE):
        pytest.skip("baseline emulator not built")
    wd = str(tmp_path / "dev")
    legacy = emulators(binary=BASELINE, workdir=wd, chip_id=b"\0" * 8)
    legacy.start()
    dev, c = open_ctap2()
    try:
        rk = c.make_credential(os.urandom(32), {"id": "example.com", "name": "Example"},
                               {"id": b"alice", "name": "alice", "displayName": "Alice"},
                               [{"type": "public-key", "alg": -7}], options={"rk": True})
        ClientPin(c).set_pin(PIN)
    finally:
        dev.close()
    legacy.stop()

    h = emulators(workdir=wd, binary=HARDENED, env={"LF_EMU_CHIP_SECURE": "1"})
    h.start()
    m = Management.open(timeout=15)
    try:
        provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path))
    finally:
        m.close()
    h.restart()
    Management.open(timeout=15).close()
    dev, c = open_ctap2()
    try:
        ClientPin(c, PinProtocolV2()).get_pin_token(PIN)       # converts the 0x02 key
        cdh = os.urandom(32)
        a = c.get_assertion("example.com", cdh)
        assert a.credential["id"] == rk.auth_data.credential_data.credential_id
        rk.auth_data.credential_data.public_key.verify(bytes(a.auth_data) + cdh, a.signature)
    finally:
        dev.close()
    h.restart()                                                 # without the PIN now
    Management.open(timeout=15).close()
    dev, c = open_ctap2()
    try:
        cdh = os.urandom(32)
        a = c.get_assertion("example.com", cdh)
        rk.auth_data.credential_data.public_key.verify(bytes(a.auth_data) + cdh, a.signature)
    finally:
        dev.close()


def test_key_restored_without_pin_by_the_previous_firmware(tmp_path, pcscd, emulators):
    from lf_fido_helpers import VENDOR_BACKUP, VENDOR_UNLOCK, Mse, raw_vendor, vendor_auth, seal_device_key
    if not os.path.exists(BASELINE):
        pytest.skip("baseline emulator not built")
    wd = str(tmp_path / "dev")
    legacy = emulators(binary=BASELINE, workdir=wd, chip_id=b"\0" * 8)
    legacy.start()
    new_key = ec.generate_private_key(ec.SECP256R1())
    k = os.urandom(32)
    dev, c = open_ctap2()
    try:
        c.make_credential(os.urandom(32), {"id": "old.example", "name": "Old"},
                          {"id": b"old", "name": "old", "displayName": "Old"},
                          [{"type": "public-key", "alg": -7}], options={"rk": True})
        # upstream restore: no PIN, no token
        blob = seal_device_key(k, new_key.private_numbers().private_value.to_bytes(32, "big"))
        Mse(_Dev(dev))
        st, _ = raw_vendor(_Dev(dev), VENDOR_BACKUP, {1: 2, 2: {1: blob}})
        assert st == 0
    finally:
        dev.close()
    legacy.stop()

    new = emulators(workdir=wd)
    new.start()
    dev, c = open_ctap2()
    d = _Dev(dev)
    try:
        # locked, and UNLOCK needs a PIN
        with pytest.raises(CtapError):
            c.make_credential(os.urandom(32), {"id": "x.example", "name": "x"},
                              {"id": b"x", "name": "x", "displayName": "X"}, [{"type": "public-key", "alg": -7}])
        kct = Mse(d).seal(k)
        st, _ = raw_vendor(d, VENDOR_UNLOCK, {1: 1, 2: {1: kct}})
        assert st == CtapError.ERR.PIN_NOT_SET
        # the documented recovery: setPIN (works while locked), acfg token, UNLOCK
        ClientPin(c).set_pin(PIN)
        proto = PinProtocolV2()
        tok = ClientPin(c, proto).get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
        kct = Mse(d).seal(k)
        st, _ = raw_vendor(d, VENDOR_UNLOCK, {1: 1, 2: {1: kct}, 3: proto.VERSION,
                                              4: vendor_auth(tok, proto, VENDOR_UNLOCK, 1, kct)})
        assert st == 0

        # the credential made with the replaced key: ID only, deletable
        cm = cred_mgmt(c)
        assert cm.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 1
        rps = cm.enumerate_rps()
        assert [r[CredentialManagement.RESULT.RP]["id"] for r in rps] == ["old.example"]
        creds = cm.enumerate_creds(sha256(b"old.example"))
        assert len(creds) == 1
        assert creds[0][CredentialManagement.RESULT.USER] == {}
        assert CredentialManagement.RESULT.PUBLIC_KEY not in creds[0]
        cm.delete_cred(creds[0][CredentialManagement.RESULT.CREDENTIAL_ID])
        assert cm.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 0
        assert cm.enumerate_rps() == []

        # the restored key works
        tok = ClientPin(c, proto).get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL)
        cdh = os.urandom(32)
        att = c.make_credential(cdh, {"id": "new.example", "name": "New"},
                                {"id": b"new", "name": "new", "displayName": "New"},
                                [{"type": "public-key", "alg": -7}], options={"rk": True},
                                pin_uv_param=proto.authenticate(tok, cdh), pin_uv_protocol=proto.VERSION)
        cdh = os.urandom(32)
        a = c.get_assertion("new.example", cdh)
        att.auth_data.credential_data.public_key.verify(bytes(a.auth_data) + cdh, a.signature)
    finally:
        dev.close()
