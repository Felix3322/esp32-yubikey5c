"""
Credential management: the CTAP 2.1-PRE command byte 0x41 gets the same
checks as 0x0A, the persistent (pcmr) token survives a power cycle,
resident credential IDs keep their ID and share no constant bytes.
"""

import pytest
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement
from fido2.utils import sha256

from lf_fido_helpers import PIN, ctap2, fresh, token

MC = ClientPin.PERMISSION.MAKE_CREDENTIAL
GA = ClientPin.PERMISSION.GET_ASSERTION
CM = ClientPin.PERMISSION.CREDENTIAL_MGMT
PCMR = ClientPin.PERMISSION.PERSISTENT_CREDENTIAL_MGMT


def prototype_call(device, tok, protocol, sub, params=None):
    """credentialManagement through the prototype command byte 0x41."""
    msg = bytes([sub]) + (cbor.encode(params) if params is not None else b"")
    req = {1: sub, 3: protocol.VERSION, 4: protocol.authenticate(tok, msg)}
    if params is not None:
        req[2] = params
    return ctap2(device).send_cbor(0x41, req)


@pytest.fixture(scope="module")
def two_rps(device):
    fresh(device)
    a = device.doMC(rp={"id": "a.example", "name": "A"}, rk=True)['res'].attestation_object
    b = device.doMC(rp={"id": "b.example", "name": "B"}, rk=True)['res'].attestation_object
    return a, b


def test_prototype_needs_cm_permission(device, two_rps):
    a, b = two_rps
    t, p = token(device, GA)
    for sub, params in ((0x01, None), (0x02, None), (0x06, {2: {"id": b.auth_data.credential_data.credential_id, "type": "public-key"}})):
        with pytest.raises(CtapError) as e:
            prototype_call(device, t, p, sub, params)
        assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_prototype_honours_rp_binding(device, two_rps):
    a, b = two_rps
    t, p = token(device, CM, rp_id="a.example")
    with pytest.raises(CtapError) as e:
        prototype_call(device, t, p, 0x06, {2: {"id": b.auth_data.credential_data.credential_id, "type": "public-key"}})
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID
    with pytest.raises(CtapError) as e:
        prototype_call(device, t, p, 0x02)
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID
    # still a working alias with a proper token
    t, p = token(device, CM)
    assert prototype_call(device, t, p, 0x01)[1] == 2


def test_resident_ids(device, two_rps):
    """New resident IDs share no per-device constant (the first 4 bytes used
    to be HMAC(0, serial)); getAssertion and credMgmt report the ID the
    credential was created with."""
    a, b = two_rps
    ida = a.auth_data.credential_data.credential_id
    idb = b.auth_data.credential_data.credential_id
    assert len(ida) == len(idb) == 42
    assert ida[:4] != idb[:4]
    assert ida[4:10] == idb[4:10]               # format marker only
    for rp, cid in (("a.example", ida), ("b.example", idb)):
        ga = ctap2(device).get_assertion(rp, bytes(32))
        assert ga.credential["id"] == cid
        ga = ctap2(device).get_assertion(rp, bytes(32), allow_list=[{"id": cid, "type": "public-key"}])
        assert ga.credential["id"] == cid
    t, p = token(device, CM)
    cm = CredentialManagement(ctap2(device), p, t)
    creds = cm.enumerate_creds(sha256(b"a.example"))
    assert [c[CredentialManagement.RESULT.CREDENTIAL_ID]["id"] for c in creds] == [ida]
    # user update keeps the ID and is read back
    cm.update_user_info({"id": ida, "type": "public-key"}, {"id": device.user()["id"], "name": "renamed"})
    creds = cm.enumerate_creds(sha256(b"a.example"))
    assert creds[0][CredentialManagement.RESULT.CREDENTIAL_ID]["id"] == ida
    assert creds[0][CredentialManagement.RESULT.USER]["name"] == "renamed"
    cm.delete_cred({"id": ida, "type": "public-key"})
    assert cm.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 1


def test_persistent_token_survives_power_cycle(device):
    fresh(device)
    device.doMC(rk=True)
    t, p = token(device, PCMR)
    cm = CredentialManagement(ctap2(device), p, t)
    assert cm.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 1
    device.reboot()
    cm = CredentialManagement(ctap2(device), p, t)
    assert cm.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 1
    assert len(cm.enumerate_rps()) == 1
    # read only
    with pytest.raises(CtapError) as e:
        cm.delete_cred({"id": b"\x00" * 42, "type": "public-key"})
    assert e.value.code in (CtapError.ERR.PIN_AUTH_INVALID, CtapError.ERR.NO_CREDENTIALS)
    # a PIN change revokes it
    ClientPin(ctap2(device)).change_pin(PIN, "87654321")
    with pytest.raises(CtapError) as e:
        CredentialManagement(ctap2(device), p, t).get_metadata()
    assert e.value.code == CtapError.ERR.PIN_AUTH_INVALID
    device.reset()
