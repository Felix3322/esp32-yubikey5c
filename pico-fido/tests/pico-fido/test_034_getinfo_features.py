"""
Everything authenticatorGetInfo advertises is implemented; this module covers
what the upstream suite did not: FIDO_2_2's hmac-secret-mc and
thirdPartyPayment, maxCredBlobLength itself, enterprise attestation ("ep"),
PIN/UV auth protocol 1, the pinUvAuthToken lifetime.
"""

import os
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Config, CredentialManagement
from fido2.ctap2.pin import PinProtocolV1
from fido2.utils import sha256

from utils import generate_random_user
from lf_fido_helpers import CONFIG_AUT_ENABLE, CONFIG_AUT_DISABLE, CONFIG_EA_UPLOAD, ctap2, fresh, token

RP = {"id": "example.com", "name": "Example RP"}
ES256_PARAMS = [{"type": "public-key", "alg": -7}]


def test_getinfo_contents(device):
    info = ctap2(device).get_info()
    assert info.versions == ["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_2"]
    assert sorted(info.extensions) == sorted(["credBlob", "credProtect", "hmac-secret", "largeBlobKey",
                                              "minPinLength", "hmac-secret-mc", "thirdPartyPayment"])
    assert set(info.options) == {"ep", "rk", "credMgmt", "authnrCfg", "clientPin", "largeBlobs",
                                 "pinUvAuthToken", "setMinPINLength"}
    assert "alwaysUv" not in info.options           # toggleAlwaysUv is not implemented
    assert info.pin_complexity_policy is None       # no complexity rule is enforced
    assert info.pin_uv_protocols == [1, 2]
    assert info.max_cred_blob_length == 128
    assert info.vendor_prototype_config_commands == [CONFIG_AUT_ENABLE, CONFIG_AUT_DISABLE, CONFIG_EA_UPLOAD]


def test_hmac_secret_mc(device):
    """CTAP 2.2 hmac-secret-mc: the PRF output at creation equals the one
    getAssertion (hmac-secret) gives later with the same UV state."""
    fresh(device)
    salt = os.urandom(32)
    mc = device.doMC(rk=True, user=generate_random_user(), user_verification=True,
                     extensions={"prf": {"eval": {"first": salt}}})
    ext = mc['res'].attestation_object.auth_data.extensions
    assert ext["hmac-secret"] is True
    assert "hmac-secret-mc" in ext
    first = mc['client_extension_results']["prf"]["results"]["first"]
    cid = mc['res'].attestation_object.auth_data.credential_data.credential_id
    ga = device.doGA(allow_list=[{"id": cid, "type": "public-key"}], user_verification=True,
                     extensions={"prf": {"eval": {"first": salt}}})['res'].get_response(0)
    assert ga.client_extension_results["prf"]["results"]["first"] == first
    ga = device.doGA(allow_list=[{"id": cid, "type": "public-key"}], user_verification=True,
                     extensions={"prf": {"eval": {"first": os.urandom(32)}}})['res'].get_response(0)
    assert ga.client_extension_results["prf"]["results"]["first"] != first


def test_hmac_secret_mc_needs_hmac_secret(device):
    fresh(device, pin=None)
    with pytest.raises(CtapError) as e:
        ctap2(device).make_credential(os.urandom(32), RP, generate_random_user(), ES256_PARAMS,
                                      extensions={"hmac-secret-mc": {1: {1: 2, 3: -25, -1: 1, -2: bytes(32), -3: bytes(32)},
                                                                     2: bytes(48), 3: bytes(32), 4: 2}})
    assert e.value.code == CtapError.ERR.MISSING_PARAMETER


def test_third_party_payment(device):
    fresh(device)
    c = ctap2(device)
    t, p = token(device, ClientPin.PERMISSION.MAKE_CREDENTIAL)
    cdh = os.urandom(32)
    paid = c.make_credential(cdh, RP, generate_random_user(), ES256_PARAMS, options={"rk": True},
                             extensions={"thirdPartyPayment": True},
                             pin_uv_param=p.authenticate(t, cdh), pin_uv_protocol=p.VERSION)
    assert "thirdPartyPayment" not in (paid.auth_data.extensions or {})    # no makeCredential output
    t, p = token(device, ClientPin.PERMISSION.MAKE_CREDENTIAL)
    cdh = os.urandom(32)
    plain = c.make_credential(cdh, RP, generate_random_user(), ES256_PARAMS, options={"rk": True},
                              pin_uv_param=p.authenticate(t, cdh), pin_uv_protocol=p.VERSION)
    for att, expected in ((paid, True), (plain, False)):
        cid = att.auth_data.credential_data.credential_id
        ga = c.get_assertion(RP["id"], os.urandom(32), allow_list=[{"id": cid, "type": "public-key"}],
                             extensions={"thirdPartyPayment": True})
        assert ga.auth_data.extensions == {"thirdPartyPayment": expected}
        ga = c.get_assertion(RP["id"], os.urandom(32), allow_list=[{"id": cid, "type": "public-key"}])
        assert not ga.auth_data.extensions
    t, p = token(device, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    creds = CredentialManagement(c, p, t).enumerate_creds(sha256(RP["id"].encode()))
    flags = {cr[CredentialManagement.RESULT.CREDENTIAL_ID]["id"]: cr[CredentialManagement.RESULT.THIRD_PARTY_PAYMENT] for cr in creds}
    assert flags == {paid.auth_data.credential_data.credential_id: True,
                     plain.auth_data.credential_data.credential_id: False}


def test_cred_blob_max_length(device, info):
    """maxCredBlobLength bytes are stored (one byte less used to be the limit)."""
    fresh(device, pin=None)
    blob = os.urandom(info.max_cred_blob_length)
    c = ctap2(device)
    att = c.make_credential(os.urandom(32), RP, generate_random_user(), ES256_PARAMS, options={"rk": True},
                            extensions={"credBlob": blob})
    assert att.auth_data.extensions["credBlob"] is True
    cid = att.auth_data.credential_data.credential_id
    ga = c.get_assertion(RP["id"], os.urandom(32), allow_list=[{"id": cid, "type": "public-key"}],
                         extensions={"credBlob": True})
    assert ga.auth_data.extensions["credBlob"] == blob


def test_enterprise_attestation(device):
    fresh(device)
    assert ctap2(device).get_info().options["ep"] is False
    with pytest.raises(CtapError) as e:
        device.MC(enterprise_attestation=2)
    assert e.value.code in (CtapError.ERR.INVALID_PARAMETER, CtapError.ERR.PUAT_REQUIRED)
    t, p = token(device, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    Config(ctap2(device), p, t).enable_enterprise_attestation()
    assert ctap2(device).get_info().options["ep"] is True
    for alg in (-7, -35):
        t, p = token(device, ClientPin.PERMISSION.MAKE_CREDENTIAL)
        cdh = os.urandom(32)
        att = ctap2(device).make_credential(cdh, RP, generate_random_user(), [{"type": "public-key", "alg": alg}],
                                            enterprise_attestation=2,
                                            pin_uv_param=p.authenticate(t, cdh), pin_uv_protocol=p.VERSION)
        assert att.ep_att is True
        assert att.att_stmt["alg"] == -7
        # signed by the attestation key over SHA-256, whatever the credential's curve
        cert = x509.load_der_x509_certificate(att.att_stmt["x5c"][0])
        cert.public_key().verify(att.att_stmt["sig"], bytes(att.auth_data) + cdh, ec.ECDSA(hashes.SHA256()))


def test_pin_protocol_1(device):
    fresh(device)
    t, p = token(device, ClientPin.PERMISSION.MAKE_CREDENTIAL, protocol=PinProtocolV1())
    cdh = os.urandom(32)
    att = ctap2(device).make_credential(cdh, RP, generate_random_user(), ES256_PARAMS,
                                        pin_uv_param=p.authenticate(t, cdh), pin_uv_protocol=p.VERSION)
    assert att.auth_data.flags & 0x04


def test_token_expires_unused(device):
    """A pinUvAuthToken not used within 30 s of being issued expires."""
    fresh(device)
    t, p = token(device, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    time.sleep(31)
    with pytest.raises(CtapError) as e:
        CredentialManagement(ctap2(device), p, t).get_metadata()
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID
    t, p = token(device, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    cm = CredentialManagement(ctap2(device), p, t)
    cm.get_metadata()                               # used in time: stays valid
    time.sleep(31)
    cm.get_metadata()
