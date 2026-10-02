"""
U2F (CTAP1) edge cases: exact key handle length, validation before the
touch, CTAP2 credentials that demand UV, dummy registrations.
"""

import os
import struct

import pytest
from fido2.ctap1 import APDU, ApduError, Ctap1
from fido2.ctap2.extensions import CredProtectExtension
from fido2.utils import sha256

from lf_fido_helpers import fresh

CHAL, APP = os.urandom(32), sha256(b"example.com")
SW_WRONG_LENGTH = 0x6700


def auth_apdu(device, p1, data):
    return device.ctap1.send_apdu(ins=Ctap1.INS.AUTHENTICATE, p1=p1, data=data)


def test_key_handle_length_must_match(device):
    reg = device.ctap1.register(CHAL, APP)
    kh = reg.key_handle
    # announces 64 bytes, carries 1: the rest used to come from old buffer contents
    for p1 in (0x03, 0x07, 0x08):
        with pytest.raises(ApduError) as e:
            auth_apdu(device, p1, CHAL + APP + bytes([len(kh)]) + kh[:1])
        assert e.value.code == SW_WRONG_LENGTH
    with pytest.raises(ApduError) as e:
        auth_apdu(device, 0x03, CHAL + APP + bytes([len(kh)]) + kh + b"\x00")
    assert e.value.code == SW_WRONG_LENGTH
    # the exact message still works
    sig = auth_apdu(device, 0x03, CHAL + APP + bytes([len(kh)]) + kh)
    assert sig[0] & 0x01


def test_unknown_control_byte(device):
    reg = device.ctap1.register(CHAL, APP)
    kh = reg.key_handle
    for p1 in (0x00, 0x01, 0x09):
        with pytest.raises(ApduError) as e:
            auth_apdu(device, p1, CHAL + APP + bytes([len(kh)]) + kh)
        assert e.value.code == 0x6A86


def test_dont_enforce_presence(device):
    reg = device.ctap1.register(CHAL, APP)
    kh = reg.key_handle
    resp = auth_apdu(device, 0x08, CHAL + APP + bytes([len(kh)]) + kh)
    assert resp[0] & 0x01 == 0                  # TUP not set


@pytest.mark.parametrize("app", [b"\x00" * 32, b"A" * 32])
def test_dummy_registration(device, app):
    """Browsers' dummy registrations (wait for a touch) get a normal answer;
    they used to get a CTAPHID error frame sent from the card thread."""
    reg = device.ctap1.register(CHAL, app)
    reg.verify(app, CHAL)


def test_ctap2_credential_with_uv_required(device):
    """A CTAP2 credential ID also works as a U2F key handle, but U2F has no
    UV: a credential with credProtect userVerificationRequired is refused."""
    fresh(device, pin=None)
    protected = device.doMC(extensions={'credentialProtectionPolicy': CredProtectExtension.POLICY.REQUIRED})['res'].attestation_object
    assert protected.auth_data.extensions['credProtect'] == 3
    cid = protected.auth_data.credential_data.credential_id
    rih = protected.auth_data.rp_id_hash
    for check_only in (False, True):
        with pytest.raises(ApduError) as e:
            device.ctap1.authenticate(CHAL, rih, cid, check_only=check_only)
        assert e.value.code == APDU.WRONG_DATA

    plain = device.doMC()['res'].attestation_object
    cid = plain.auth_data.credential_data.credential_id
    auth = device.ctap1.authenticate(CHAL, rih, cid)
    pub = plain.auth_data.credential_data.public_key
    pub.verify(rih + struct.pack(">BI", auth.user_presence, auth.counter) + CHAL, auth.signature)
