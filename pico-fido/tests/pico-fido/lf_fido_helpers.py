"""
Helpers for the LibreFido regression tests of this directory (raw CTAP
messages, PIN tokens, the MSE channel of the vendor commands).
"""

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.ctap2.pin import PinProtocolV2
from fido2.hid import CTAPHID

PIN = "12345678"

# authenticatorConfig vendorCommandId values (ctap.h)
CONFIG_AUT_ENABLE = 0x03e43f56b34285e2
CONFIG_AUT_DISABLE = 0x1831a40f04a25ed9
CONFIG_EA_UPLOAD = 0x66f2a674c29a8dcf
CONFIG_PIN_POLICY = 0x6c07d70fe96c3897

# CTAPHID vendor command 0xC1 (CBOR vendor commands) and its first byte
CTAPHID_VENDOR_CBOR = 0x41
VENDOR_BACKUP, VENDOR_MSE, VENDOR_UNLOCK = 0x01, 0x02, 0x03


def ctap2(device):
    return device.client()._backend.ctap2


def fresh(device, pin=PIN):
    """authenticatorReset, then a PIN (unless pin is None)."""
    device.reset()
    if pin:
        ClientPin(ctap2(device)).set_pin(pin)


def token(device, permissions, rp_id=None, pin=PIN, protocol=None):
    """A pinUvAuthToken and the PIN protocol it was obtained with."""
    protocol = protocol or PinProtocolV2()
    t = ClientPin(ctap2(device), protocol).get_pin_token(pin, permissions, rp_id)
    return t, protocol


def raw_cbor(device, cmd, payload=b""):
    """CTAPHID_CBOR message; returns the raw response, status byte first.
    A CTAPHID_ERROR frame raises CtapError."""
    return device.dev.call(CTAPHID.CBOR, bytes([cmd]) + payload)


def status(resp):
    return resp[0]


def raw_vendor(device, vcmd, params):
    """CTAPHID vendor command 0xC1: returns (status, decoded map or None)."""
    resp = device.dev.call(CTAPHID_VENDOR_CBOR, bytes([vcmd]) + cbor.encode(params))
    return resp[0], (cbor.decode(resp[1:]) if len(resp) > 1 else None)


def vendor_auth(tok, protocol, vcmd, sub, *fields):
    """pinUvAuthParam of the key management vendor commands:
    32 x 0xFF || 0xC1 || cmd || vendorCmd || vendorParam || vendorKey."""
    msg = b"\xff" * 32 + bytes([0xC1, vcmd, sub]) + b"".join(fields)
    return protocol.authenticate(tok, msg)


class Mse:
    """Host side of the vendor MSE channel (ECDH P-256, HKDF-SHA256 with the
    host public key as info, ChaCha20-Poly1305). One secret per session."""

    def __init__(self, device):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        pub = self.priv.public_key()
        self.qpt = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        cose = {1: 2, 3: -25, -1: 1, -2: self.qpt[1:33], -3: self.qpt[33:65]}
        st, m = raw_vendor(device, VENDOR_MSE, {1: 1, 2: {2: cose}})
        assert st == 0, "MSE key agreement failed: %02X" % st
        dk = m[1]
        dev_pub = ec.EllipticCurvePublicNumbers(int.from_bytes(dk[-2], "big"), int.from_bytes(dk[-3], "big"),
                                                ec.SECP256R1()).public_key()
        z = self.priv.exchange(ec.ECDH(), dev_pub)
        k = HKDF(algorithm=hashes.SHA256(), length=44, salt=None, info=self.qpt).derive(z)
        self.nonce, self.key = k[:12], k[12:]

    def seal(self, secret):
        return ChaCha20Poly1305(self.key).encrypt(self.nonce, secret, self.qpt)


def seal_device_key(k, device_key):
    """A device key blob as the firmware stores it: iv || ChaCha20-Poly1305_k(key) || tag."""
    iv = os.urandom(12)
    return iv + ChaCha20Poly1305(k).encrypt(iv, device_key, None)


def expect_ctap(code, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except CtapError as e:
        assert e.code == code, "expected %s, got %s" % (code, e.code)
        return
    raise AssertionError("expected CtapError %s" % code)
