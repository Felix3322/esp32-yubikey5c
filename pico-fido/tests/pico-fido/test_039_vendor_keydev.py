"""
Device key protection through the vendor commands: authenticatorConfig
AUT_ENABLE / AUT_DISABLE and CTAPHID 0xC1 MSE / UNLOCK / BACKUP.

Every key management command needs the PIN (a pinUvAuthToken with acfg),
the destructive ones a touch; blobs and host keys are length checked and
proven to open before anything is replaced; malformed input never crashes.
"""

import os
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from fido2 import cbor
from fido2.client import ClientError
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Config
from fido2.utils import sha256

from utils import verify
from lf_fido_helpers import (PIN, CONFIG_AUT_ENABLE, CONFIG_AUT_DISABLE, CONFIG_EA_UPLOAD, VENDOR_BACKUP,
                             VENDOR_UNLOCK, Mse, ctap2, fresh, token, raw_vendor, vendor_auth, seal_device_key)

ACFG = ClientPin.PERMISSION.AUTHENTICATOR_CFG
DENIED = (CtapError, ClientError)


def config(device):
    t, p = token(device, ACFG)
    return Config(ctap2(device), p, t)


def unlock(device, k, with_token=True):
    m = Mse(device)
    kct = m.seal(k)
    req = {1: 1, 2: {1: kct}}
    if with_token:
        t, p = token(device, ACFG)
        req[3] = p.VERSION
        req[4] = vendor_auth(t, p, VENDOR_UNLOCK, 1, kct)
    return raw_vendor(device, VENDOR_UNLOCK, req)[0]


def restore(device, blob, kct):
    t, p = token(device, ACFG)
    return raw_vendor(device, VENDOR_BACKUP, {1: 2, 2: {1: blob, 3: kct}, 3: p.VERSION,
                                              4: vendor_auth(t, p, VENDOR_BACKUP, 2, blob, kct)})[0]


def assert_signs(device, reg):
    res = device.doGA(allow_list=[{"id": reg.auth_data.credential_data.credential_id, "type": "public-key"}])
    for a in res['res'].get_assertions():
        verify(reg, a, res['req']['client_data'].hash)


def new_device_key():
    k = ec.generate_private_key(ec.SECP256R1())
    return k.private_numbers().private_value.to_bytes(32, "big"), k.public_key()


def test_aut_enable_rejects_malformed_host_key(device):
    fresh(device)
    Mse(device)
    # 5 bytes: the MSE decryption used to compute a length of 5 - 16
    with pytest.raises(CtapError) as e:
        config(device)._call(0xFF, {1: CONFIG_AUT_ENABLE, 2: b"12345"})
    assert e.value.code == CtapError.ERR.INVALID_PARAMETER
    with pytest.raises(CtapError) as e:
        config(device)._call(0xFF, {1: CONFIG_AUT_ENABLE})
    assert e.value.code == CtapError.ERR.INVALID_PARAMETER
    # not encrypted with the session key: refused, and the session is spent
    with pytest.raises(CtapError) as e:
        config(device)._call(0xFF, {1: CONFIG_AUT_ENABLE, 2: os.urandom(48)})
    assert e.value.code == CtapError.ERR.INVALID_PARAMETER
    with pytest.raises(CtapError) as e:
        config(device)._call(0xFF, {1: CONFIG_AUT_ENABLE, 2: os.urandom(48)})
    assert e.value.code == CtapError.ERR.NOT_ALLOWED
    ctap2(device).get_info()                        # still alive
    # the device key is untouched
    reg = device.doMC()['res'].attestation_object
    assert_signs(device, reg)


def test_protect_unlock_disable(device):
    fresh(device)
    reg = device.doMC()['res'].attestation_object
    k = os.urandom(32)
    m = Mse(device)
    config(device)._call(0xFF, {1: CONFIG_AUT_ENABLE, 2: m.seal(k)})
    assert_signs(device, reg)                       # usable until the power cycle

    device.reboot()
    with pytest.raises(DENIED):                     # locked
        assert_signs(device, reg)

    # malformed UNLOCK requests (used to underflow / read past the input)
    Mse(device)
    st, _ = raw_vendor(device, VENDOR_UNLOCK, {1: 1})
    assert st == CtapError.ERR.MISSING_PARAMETER
    Mse(device)
    st, _ = raw_vendor(device, VENDOR_UNLOCK, {1: 1, 2: {1: b"12345"}})
    assert st == CtapError.ERR.INVALID_PARAMETER

    # no unauthenticated UNLOCK
    assert unlock(device, k, with_token=False) == CtapError.ERR.PUAT_REQUIRED
    # a wrong host key is a status byte (not a CTAPHID error) and changes nothing
    assert unlock(device, os.urandom(32)) == CtapError.ERR.INVALID_PARAMETER
    with pytest.raises(DENIED):
        assert_signs(device, reg)
    assert unlock(device, k) == 0
    assert_signs(device, reg)                       # the same device key

    # export of the sealed key: PIN needed, 60 bytes
    st, _ = raw_vendor(device, VENDOR_BACKUP, {1: 1})
    assert st == CtapError.ERR.PUAT_REQUIRED
    t, p = token(device, ACFG)
    st, out = raw_vendor(device, VENDOR_BACKUP, {1: 1, 3: p.VERSION, 4: vendor_auth(t, p, VENDOR_BACKUP, 1)})
    assert st == 0 and len(out[1]) == 60

    # back to normal storage: the real key, in the format load_keydev reads
    config(device)._call(0xFF, {1: CONFIG_AUT_DISABLE})
    assert_signs(device, reg)                       # no all-zero RAM key
    device.reboot()
    assert_signs(device, reg)                       # no UNLOCK needed, same key
    device.reset()


def test_restore_needs_pin(device):
    fresh(device, pin=None)
    key, _ = new_device_key()
    k = os.urandom(32)
    m = Mse(device)
    st, _ = raw_vendor(device, VENDOR_BACKUP, {1: 2, 2: {1: seal_device_key(k, key), 3: m.seal(k)}})
    assert st == CtapError.ERR.PIN_NOT_SET


def test_restore(device):
    fresh(device)
    reg = device.doMC()['res'].attestation_object
    key, pub = new_device_key()
    k = os.urandom(32)
    blob = seal_device_key(k, key)

    # the blob must open with the host key before anything is replaced
    m = Mse(device)
    assert restore(device, blob, m.seal(os.urandom(32))) == CtapError.ERR.INVALID_PARAMETER
    m = Mse(device)
    assert restore(device, blob[:59], m.seal(k)) == CtapError.ERR.INVALID_PARAMETER
    m = Mse(device)
    assert restore(device, blob, m.seal(k)[:47]) == CtapError.ERR.INVALID_PARAMETER
    assert_signs(device, reg)                       # device key unchanged

    m = Mse(device)
    assert restore(device, blob, m.seal(k)) == 0
    with pytest.raises(DENIED):                     # made with the old key
        assert_signs(device, reg)

    # U2F attests with a device certificate of the restored key
    cdh, rih = os.urandom(32), sha256(b"example.com")
    r = device.ctap1.register(cdh, rih)
    r.verify(rih, cdh)
    cert_pub = x509.load_der_x509_certificate(r.certificate).public_key()
    fmt = (serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    assert cert_pub.public_bytes(*fmt) == pub.public_bytes(*fmt)

    # sealed from now on: locked after a power cycle until unlocked
    device.reboot()
    with pytest.raises(Exception):
        device.ctap1.register(cdh, rih)
    assert unlock(device, k) == 0
    device.ctap1.register(cdh, rih).verify(rih, cdh)
    device.reset()


def test_pin_change_keeps_the_sealing(device):
    """changePIN used to write the device key back in the normal format next
    to the sealed blob: after the next power up it worked without K. On a
    locked key a correct PIN was reported as PIN_INVALID."""
    fresh(device)
    reg = device.doMC()['res'].attestation_object
    k = os.urandom(32)
    m = Mse(device)
    config(device)._call(0xFF, {1: CONFIG_AUT_ENABLE, 2: m.seal(k)})
    ClientPin(ctap2(device)).change_pin(PIN, "87654321")     # while unlocked
    assert_signs(device, reg)
    device.reboot()
    with pytest.raises(DENIED):                     # still locked
        assert_signs(device, reg)
    ClientPin(ctap2(device)).change_pin("87654321", PIN)     # while locked
    with pytest.raises(DENIED):
        assert_signs(device, reg)
    assert unlock(device, k) == 0
    assert_signs(device, reg)
    device.reset()


P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def test_restore_rejects_an_invalid_key(device):
    """32 bytes that are no P-256 private key used to be installed, then the
    certificate step failed: an error was reported for a restore that had
    happened, U2F registration broke."""
    fresh(device)
    reg = device.doMC()['res'].attestation_object
    k = os.urandom(32)
    for bad in (bytes(32), P256_N.to_bytes(32, "big")):
        m = Mse(device)
        assert restore(device, seal_device_key(k, bad), m.seal(k)) == CtapError.ERR.INVALID_PARAMETER
    assert_signs(device, reg)                       # nothing was replaced
    cdh, rih = os.urandom(32), sha256(b"example.com")
    device.ctap1.register(cdh, rih).verify(rih, cdh)
    device.reset()


def ea_make_credential(device):
    t, p = token(device, ClientPin.PERMISSION.MAKE_CREDENTIAL)
    cdh = os.urandom(32)
    att = ctap2(device).make_credential(cdh, {"id": "example.com", "name": "Example"},
                                        {"id": os.urandom(8), "name": "u", "displayName": "U"},
                                        [{"type": "public-key", "alg": -7}], enterprise_attestation=2,
                                        pin_uv_param=p.authenticate(t, cdh), pin_uv_protocol=p.VERSION)
    return att, cdh


def test_restore_drops_the_ea_certificate_of_the_old_key(device):
    fresh(device)
    config(device).enable_enterprise_attestation()
    config(device)._call(0xFF, {1: CONFIG_EA_UPLOAD, 2: b"certificate of the old key"})
    att, _ = ea_make_credential(device)
    assert att.att_stmt["x5c"][0] == b"certificate of the old key"

    key, pub = new_device_key()
    k = os.urandom(32)
    m = Mse(device)
    assert restore(device, seal_device_key(k, key), m.seal(k)) == 0
    att, cdh = ea_make_credential(device)
    cert = x509.load_der_x509_certificate(att.att_stmt["x5c"][0])
    fmt = (serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    assert cert.public_key().public_bytes(*fmt) == pub.public_bytes(*fmt)
    cert.public_key().verify(att.att_stmt["sig"], bytes(att.auth_data) + cdh, ec.ECDSA(hashes.SHA256()))
    device.reset()


FIDO_AID = bytes.fromhex("A0000006472F0001")


def ccid_vendor(card, vcmd, params):
    card.select(FIDO_AID)
    _, sw = card.transmit(0x80, 0x41, 0x00, 0x00, bytes([vcmd]) + cbor.encode(params), le=0, check=False)
    return sw


def test_expired_token_refused_over_ccid(device, card):
    """The FIDO applet's vendor command (INS 0x41) skipped the token expiry:
    an expired acfg token was accepted there, and even revived."""
    fresh(device)
    blob, kct = os.urandom(60), os.urandom(48)

    def restore_params(t, p):
        return {1: 2, 2: {1: blob, 3: kct}, 3: p.VERSION, 4: vendor_auth(t, p, VENDOR_BACKUP, 2, blob, kct)}

    t, p = token(device, ACFG)
    # a live token passes (the command then stops: no MSE session)
    assert ccid_vendor(card, VENDOR_BACKUP, restore_params(t, p)) == 0x6400 | CtapError.ERR.NOT_ALLOWED
    t, p = token(device, ACFG)
    time.sleep(31)                                  # unused past the initial limit
    assert ccid_vendor(card, VENDOR_BACKUP, restore_params(t, p)) == 0x6400 | CtapError.ERR.PIN_AUTH_INVALID
    with pytest.raises(CtapError) as e:             # and it was not revived
        Config(ctap2(device), p, t).set_min_pin_length(6)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_reset_from_the_management_applet_drops_command_state(device, card):
    """authenticatorReset through the management applet (CCID) left the
    getNextAssertion state (decrypted user entities) of the wiped profile."""
    fresh(device, pin=None)
    for u in (b"a", b"b", b"c"):
        device.doMC(rk=True, user={"id": u, "name": "u", "displayName": "U"})
    ga = ctap2(device).get_assertion("example.com", os.urandom(32))
    assert ga.number_of_credentials == 3
    card.select(bytes.fromhex("A000000527471117"))
    _, sw = card.transmit(0x00, 0x1E, 0x00, 0x00, b"", check=False)
    assert sw == 0x9000
    with pytest.raises(CtapError) as e:
        ctap2(device).get_next_assertion()
    assert e.value.code == CtapError.ERR.NOT_ALLOWED
