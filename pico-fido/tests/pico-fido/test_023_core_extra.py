"""
makeCredential / getAssertion core regressions: credProtect filtering (double
free), pinUvAuthToken consumption and RP binding, unknown keys, fully
specified algorithms, silent probes after a reset.
"""

import os

import pytest
from fido2 import cbor
from fido2.cose import ES256, CoseKey
from fido2.ctap import CtapError
from fido2.ctap2 import AttestationResponse, ClientPin, Ctap2
from fido2.ctap2.extensions import CredProtectExtension
from fido2.utils import sha256

from utils import generate_random_user
from lf_fido_helpers import ctap2, fresh, token, raw_cbor, status

MC = ClientPin.PERMISSION.MAKE_CREDENTIAL
GA = ClientPin.PERMISSION.GET_ASSERTION
RP = {"id": "example.com", "name": "Example RP"}
ES256_PARAMS = [{"type": "public-key", "alg": -7}]
REQUIRED = CredProtectExtension.POLICY.REQUIRED
OPTIONAL_WITH_LIST = CredProtectExtension.POLICY.OPTIONAL_WITH_LIST


def desc(att):
    return {"id": att.auth_data.credential_data.credential_id, "type": "public-key"}


def test_protected_credential_first_in_allow_list(device):
    """Dropping a credProtect=3 credential and moving the next one down left
    both slots with the same buffers: freed twice when only one remained."""
    fresh(device, pin=None)
    a = device.doMC(user=generate_random_user(), extensions={'credentialProtectionPolicy': REQUIRED})['res'].attestation_object
    b = device.doMC(user=generate_random_user())['res'].attestation_object
    for _ in range(3):
        ga = ctap2(device).get_assertion(RP["id"], os.urandom(32), allow_list=[desc(a), desc(b)])
        assert ga.credential["id"] == desc(b)["id"]
        assert ga.number_of_credentials is None
    ctap2(device).get_info()


def test_protected_discoverable_credential_first(device):
    fresh(device, pin=None)
    device.doMC(rk=True, user=generate_random_user(), extensions={'credentialProtectionPolicy': OPTIONAL_WITH_LIST})
    b = device.doMC(rk=True, user=generate_random_user())['res'].attestation_object
    for _ in range(3):
        ga = ctap2(device).get_assertion(RP["id"], os.urandom(32))
        assert ga.credential["id"] == desc(b)["id"]
    # two usable ones after a protected one: getNextAssertion walks them
    c = device.doMC(rk=True, user=generate_random_user())['res'].attestation_object
    ga = ctap2(device).get_assertion(RP["id"], os.urandom(32))
    assert ga.number_of_credentials == 2
    ids = {ga.credential["id"], ctap2(device).get_next_assertion().credential["id"]}
    assert ids == {desc(b)["id"], desc(c)["id"]}
    ctap2(device).get_info()


def test_make_credential_consumes_the_token(device):
    fresh(device)
    t, p = token(device, MC | GA)
    cdh = os.urandom(32)
    att = ctap2(device).make_credential(cdh, RP, generate_random_user(), ES256_PARAMS,
                                        pin_uv_param=p.authenticate(t, cdh), pin_uv_protocol=p.VERSION)
    assert att.auth_data.flags & 0x04
    # the same token cannot make (or assert) anything else
    for _ in range(2):
        cdh = os.urandom(32)
        with pytest.raises(CtapError) as e:
            ctap2(device).make_credential(cdh, RP, generate_random_user(), ES256_PARAMS,
                                          pin_uv_param=p.authenticate(t, cdh), pin_uv_protocol=p.VERSION)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID
    cdh = os.urandom(32)
    with pytest.raises(CtapError) as e:
        ctap2(device).get_assertion(RP["id"], cdh, allow_list=[desc(att)],
                                    pin_uv_param=p.authenticate(t, cdh), pin_uv_protocol=p.VERSION)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_no_uv_flag_from_a_stale_token(device):
    """A token obtained before authenticatorReset gave UV to makeCredential
    requests without any pinUvAuthParam."""
    fresh(device)
    token(device, MC)
    device.reset()
    att = ctap2(device).make_credential(os.urandom(32), RP, generate_random_user(), ES256_PARAMS)
    assert not att.auth_data.flags & 0x04


def test_make_credential_up_option(device):
    """CTAP 2.1, 6.1.2 step 5: "up" true is the default, false is invalid."""
    fresh(device, pin=None)
    att = ctap2(device).make_credential(os.urandom(32), RP, generate_random_user(), ES256_PARAMS, options={"up": True})
    assert att.auth_data.flags & 0x01
    with pytest.raises(CtapError) as e:
        ctap2(device).make_credential(os.urandom(32), RP, generate_random_user(), ES256_PARAMS, options={"up": False})
    assert e.value.code == CtapError.ERR.INVALID_OPTION


def test_assertion_binds_token_to_rp(device):
    fresh(device)
    a = device.doMC(rp={"id": "a.example", "name": "A"})['res'].attestation_object
    b = device.doMC(rp={"id": "b.example", "name": "B"})['res'].attestation_object
    t, p = token(device, GA)
    cdh = os.urandom(32)
    # up=false does not consume the token
    ctap2(device).get_assertion("a.example", cdh, allow_list=[desc(a)], options={"up": False},
                                pin_uv_param=p.authenticate(t, cdh), pin_uv_protocol=p.VERSION)
    cdh = os.urandom(32)
    with pytest.raises(CtapError) as e:
        ctap2(device).get_assertion("b.example", cdh, allow_list=[desc(b)], options={"up": False},
                                    pin_uv_param=p.authenticate(t, cdh), pin_uv_protocol=p.VERSION)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_unknown_top_level_keys_are_ignored(device):
    fresh(device, pin=None)
    req = {1: os.urandom(32), 2: RP, 3: generate_random_user(), 4: ES256_PARAMS,
           0x0B: ["packed", "none"], 0x0E: {"future": [1, 2, 3]}}
    att = AttestationResponse.from_dict(ctap2(device).send_cbor(Ctap2.CMD.MAKE_CREDENTIAL, req))
    ga = ctap2(device).send_cbor(Ctap2.CMD.GET_ASSERTION, {1: RP["id"], 2: os.urandom(32),
                                                           3: [desc(att)], 0x08: b"x", 0x10: {"a": 1}})
    assert ga[1]["id"] == desc(att)["id"]
    res = ctap2(device).send_cbor(Ctap2.CMD.CLIENT_PIN, {1: 2, 2: 1, 0x0B: [1, 2]})
    assert res[3] == 8


def test_overlong_extension_name(device):
    """A key longer than the parse buffer used to end in an empty CTAP2_OK."""
    fresh(device, pin=None)
    att = ctap2(device).make_credential(os.urandom(32), RP, generate_random_user(), ES256_PARAMS,
                                        extensions={"x" * 100: True, "credProtect": 1})
    assert att.auth_data.extensions == {"credProtect": 1}


def test_too_long_user_fields(device):
    """More than a credential ID can hold: an error, not an empty CTAP2_OK."""
    fresh(device, pin=None)
    user = {"id": b"u", "name": "n" * 470, "displayName": "d" * 470}
    with pytest.raises(CtapError) as e:
        ctap2(device).make_credential(os.urandom(32), RP, user, ES256_PARAMS)
    assert e.value.code in (CtapError.ERR.REQUEST_TOO_LARGE, CtapError.ERR.INVALID_LENGTH)
    ctap2(device).get_info()


def test_fully_specified_esp256(device):
    """The credential key carries the negotiated algorithm (-9), the same as
    the attestation statement."""
    fresh(device, pin=None)
    cdh = os.urandom(32)
    att = ctap2(device).make_credential(cdh, RP, generate_random_user(), [{"type": "public-key", "alg": -9}])
    key = att.auth_data.credential_data.public_key
    assert key[3] == -9
    assert att.att_stmt["alg"] == -9
    ES256(dict(key)).verify(bytes(att.auth_data) + cdh, att.att_stmt["sig"])


def test_brainpool_not_accepted(device):
    fresh(device, pin=None)
    for alg in (-265, -267, -268):
        with pytest.raises(CtapError) as e:
            ctap2(device).make_credential(os.urandom(32), RP, generate_random_user(), [{"type": "public-key", "alg": alg}])
        assert e.value.code == CtapError.ERR.UNSUPPORTED_ALGORITHM


def test_silent_probe_after_reset(device):
    """A credential ID from before authenticatorReset is unknown afterwards,
    also to an up=false probe (it used to get a success with a dummy
    signature)."""
    fresh(device, pin=None)
    att = device.doMC()['res'].attestation_object
    ctap2(device).get_assertion(RP["id"], os.urandom(32), allow_list=[desc(att)], options={"up": False})
    device.reset()
    with pytest.raises(CtapError) as e:
        ctap2(device).get_assertion(RP["id"], os.urandom(32), allow_list=[desc(att)], options={"up": False})
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS


def test_get_pin_retries_without_pin(device):
    """Used to dereference the missing PIN record."""
    fresh(device, pin=None)
    assert ClientPin(ctap2(device)).get_pin_retries()[0] == 8
    ctap2(device).get_info()


def test_unknown_command_is_a_status_byte(device):
    """An unknown authenticator command is CTAP1_ERR_INVALID_COMMAND in the
    CBOR status byte; an empty CBOR message stays a CTAPHID error."""
    assert raw_cbor(device, 0x55) == b"\x01"
