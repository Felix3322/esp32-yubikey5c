"""
authenticatorLargeBlobs status codes and integrity check, and the CBOR status
byte for codes below 0x0B (INVALID_PARAMETER, INVALID_SEQ, ...), which used
to be sent as CTAPHID_ERROR frames.
"""

import os
import struct

import pytest
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2
from fido2.utils import sha256

from lf_fido_helpers import fresh, token, raw_cbor, status, ctap2

LBW = ClientPin.PERMISSION.LARGE_BLOB_WRITE
GA = ClientPin.PERMISSION.GET_ASSERTION
EMPTY_ARRAY = bytes.fromhex("8076be8b528d0075f7aae98d6fa57a6d3c")


def write(device, data, offset, length=None, tok=None, protocol=None):
    params = {2: data, 3: offset}
    if length is not None:
        params[4] = length
    if tok is not None:
        msg = b"\xff" * 32 + b"\x0c\x00" + struct.pack("<I", offset) + sha256(data)
        params[5] = protocol.authenticate(tok, msg)
        params[6] = protocol.VERSION
    return raw_cbor(device, Ctap2.CMD.LARGE_BLOBS, cbor.encode(params))


def test_status_codes_are_kept(device):
    fresh(device)
    # no token: PUAT_REQUIRED (0x36), not 0xEE for every error
    assert status(write(device, EMPTY_ARRAY, 0, len(EMPTY_ARRAY))) == CtapError.ERR.PUAT_REQUIRED
    t, p = token(device, LBW)
    assert status(write(device, EMPTY_ARRAY, 0, len(EMPTY_ARRAY), os.urandom(32), p)) == CtapError.ERR.PIN_AUTH_INVALID
    # codes below 0x0B are the CBOR status byte too
    assert status(write(device, EMPTY_ARRAY, 5, None, t, p)) == CtapError.ERR.INVALID_SEQ
    assert status(write(device, EMPTY_ARRAY, 0, 16, t, p)) == CtapError.ERR.INVALID_PARAMETER
    assert status(write(device, EMPTY_ARRAY, 0, 4096, t, p)) == CtapError.ERR.LARGE_BLOB_STORAGE_FULL


def test_get_status_byte(device):
    resp = raw_cbor(device, Ctap2.CMD.LARGE_BLOBS, cbor.encode({1: 10, 3: 100000}))
    assert status(resp) == CtapError.ERR.INVALID_PARAMETER
    resp = raw_cbor(device, Ctap2.CMD.LARGE_BLOBS, cbor.encode({1: 4096, 3: 0}))
    assert status(resp) == CtapError.ERR.INVALID_LENGTH


def test_17_byte_array_integrity(device):
    """The smallest array was stored without checking its hash."""
    fresh(device)
    t, p = token(device, LBW)
    bad = b"\x80" + bytes(16)
    assert status(write(device, bad, 0, len(bad), t, p)) == CtapError.ERR.INTEGRITY_FAILURE
    t, p = token(device, LBW)
    assert status(write(device, EMPTY_ARRAY, 0, len(EMPTY_ARRAY), t, p)) == 0
    assert ctap2(device).large_blobs(offset=0, get=100)[1] == EMPTY_ARRAY


def test_assertion_does_not_grant_lbw(device):
    """Clearing a token's permissions "except lbw" used to set lbw."""
    fresh(device)
    reg = device.doMC()['res'].attestation_object
    t, p = token(device, GA)
    cdh = os.urandom(32)
    ctap2(device).get_assertion("example.com", cdh,
                                allow_list=[{"id": reg.auth_data.credential_data.credential_id, "type": "public-key"}],
                                pin_uv_param=p.authenticate(t, cdh), pin_uv_protocol=p.VERSION)
    assert status(write(device, EMPTY_ARRAY, 0, len(EMPTY_ARRAY), t, p)) == CtapError.ERR.PIN_AUTH_INVALID
