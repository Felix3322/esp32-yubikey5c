"""
EdDSA (COSE -8, Ed25519) credentials.

getInfo lists {"alg": -8, "type": "public-key"} only when the build can make
and use Ed25519 keys (the mbedTLS EdDSA fork, or lf_25519); without it -8 is
refused, and the other tests are skipped.

With it: makeCredential with -8 alone and in a list (the first supported
entry wins), packed self attestation (alg -8, pure EdDSA over
authenticatorData || clientDataHash), the OKP COSE key, getAssertion,
discoverable credentials in credential management, hmac-secret, excludeList,
enterprise attestation (still ES256 with the device certificate), U2F (P-256
only: refused), and the key derivation: the seed of an Ed25519 credential is
derived from its credential ID and the device key exactly like the other
credential keys (the first 32 bytes of the same key material), which is also
the key the mbedTLS EdDSA fork derives, so credentials of firmware built with
it keep working.
"""

import os

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fido2.attestation import AttestationType, PackedAttestation
from fido2.ctap import CtapError
from fido2.ctap1 import APDU, ApduError
from fido2.ctap2 import ClientPin, Config, CredentialManagement
from fido2.utils import sha256

from lf_fido_helpers import (PIN, VENDOR_BACKUP, Mse, ctap2, fresh, token, raw_vendor, vendor_auth,
                             seal_device_key)

EDDSA = {"type": "public-key", "alg": -8}
ED25519 = {"type": "public-key", "alg": -19}
ES256 = {"type": "public-key", "alg": -7}
RP = {"id": "eddsa.example", "name": "EdDSA RP"}
RP_ID_HASH = sha256(RP["id"].encode())
MC = ClientPin.PERMISSION.MAKE_CREDENTIAL
CM = ClientPin.PERMISSION.CREDENTIAL_MGMT
ACFG = ClientPin.PERMISSION.AUTHENTICATOR_CFG
R = CredentialManagement.RESULT


def has_eddsa(info):
    return {"alg": -8, "type": "public-key"} in info.algorithms


@pytest.fixture
def eddsa(info):
    if not has_eddsa(info):
        pytest.skip("EdDSA is not in this build (getInfo does not list -8)")


def user(uid=None):
    uid = uid or os.urandom(16)
    return {"id": uid, "name": "ed", "displayName": "Ed User"}


def mc(device, key_params, rp=RP, usr=None, **kw):
    """makeCredential with a fresh mc token (PIN set by fresh())."""
    t, p = token(device, MC, rp["id"])
    cdh = os.urandom(32)
    att = ctap2(device).make_credential(cdh, rp, usr or user(), key_params,
                                        pin_uv_param=p.authenticate(t, cdh), pin_uv_protocol=p.VERSION, **kw)
    return att, cdh


def ga(device, allow=None, rp_id=RP["id"], **kw):
    cdh = os.urandom(32)
    allow_list = [{"type": "public-key", "id": i} for i in allow] if allow else None
    return ctap2(device).get_assertion(rp_id, cdh, allow_list=allow_list, **kw), cdh


def okp(key, alg=-8):
    """The Ed25519 public key of an OKP COSE key {1: 1, 3: alg, -1: 6, -2: x}."""
    assert dict(key) == {1: 1, 3: alg, -1: 6, -2: key[-2]}
    assert isinstance(key[-2], bytes) and len(key[-2]) == 32
    return ed25519.Ed25519PublicKey.from_public_bytes(key[-2])


def cred_mgmt(device):
    t, p = token(device, CM)
    return CredentialManagement(ctap2(device), p, t)


def test_getinfo_and_refusal(device, info):
    algs = [a["alg"] for a in info.algorithms]
    assert all(a["type"] == "public-key" for a in info.algorithms)
    assert algs[0] == -7 and -35 in algs and -36 in algs
    assert algs.count(-8) <= 1 and -19 not in algs and -53 not in algs
    if not has_eddsa(info):
        fresh(device, pin=None)
        for params in ([EDDSA], [ED25519]):
            with pytest.raises(CtapError) as e:
                ctap2(device).make_credential(os.urandom(32), RP, user(), params)
            assert e.value.code == CtapError.ERR.UNSUPPORTED_ALGORITHM


def test_register_eddsa_only(device, eddsa):
    fresh(device)
    att, cdh = mc(device, [EDDSA])
    assert att.fmt == "packed"
    assert att.auth_data.flags & 0x45 == 0x45           # UP, UV, AT
    st = att.att_stmt
    assert set(st) == {"alg", "sig"}                    # self attestation, no x5c
    assert st["alg"] == -8 and len(st["sig"]) == 64
    pub = okp(att.auth_data.credential_data.public_key)
    # pure EdDSA, no prehash: over authenticatorData || clientDataHash
    pub.verify(st["sig"], bytes(att.auth_data) + cdh)
    with pytest.raises(InvalidSignature):
        pub.verify(st["sig"], bytes(att.auth_data) + os.urandom(32))
    res = PackedAttestation().verify(st, att.auth_data, cdh)
    assert res.attestation_type == AttestationType.SELF


def test_register_picks_the_first_supported(device, eddsa):
    fresh(device)
    att, _ = mc(device, [EDDSA, ES256])
    okp(att.auth_data.credential_data.public_key)
    assert att.att_stmt["alg"] == -8
    att, _ = mc(device, [ES256, EDDSA])
    key = att.auth_data.credential_data.public_key
    assert key[1] == 2 and key[3] == -7 and att.att_stmt["alg"] == -7
    # an algorithm the authenticator does not have is skipped
    att, _ = mc(device, [{"type": "public-key", "alg": -257}, EDDSA, ES256])
    okp(att.auth_data.credential_data.public_key)


def test_register_ed25519_alg(device, eddsa):
    """-19 (fully specified Ed25519) is the same key and signature; the
    credential keeps the algorithm it was created for."""
    fresh(device)
    att, cdh = mc(device, [ED25519])
    pub = okp(att.auth_data.credential_data.public_key, alg=-19)
    assert att.att_stmt["alg"] == -19
    pub.verify(att.att_stmt["sig"], bytes(att.auth_data) + cdh)
    a, cdh = ga(device, [att.auth_data.credential_data.credential_id])
    pub.verify(a.signature, bytes(a.auth_data) + cdh)


def test_authenticate(device, eddsa):
    fresh(device)
    att, _ = mc(device, [EDDSA])
    cd = att.auth_data.credential_data
    pub = okp(cd.public_key)
    counter = att.auth_data.counter
    for _ in range(3):
        a, cdh = ga(device, [cd.credential_id])
        assert len(a.signature) == 64
        assert a.auth_data.rp_id_hash == RP_ID_HASH and a.auth_data.counter > counter
        counter = a.auth_data.counter
        pub.verify(a.signature, bytes(a.auth_data) + cdh)
        a.verify(cdh, cd.public_key)                    # python-fido2's own check
    with pytest.raises(InvalidSignature):
        pub.verify(a.signature, bytes(a.auth_data) + os.urandom(32))
    # silent probe (up=false) of the same credential
    a, cdh = ga(device, [cd.credential_id], options={"up": False})
    assert a.auth_data.flags & 0x01 == 0
    pub.verify(a.signature, bytes(a.auth_data) + cdh)


def test_resident_credential_and_credential_management(device, eddsa):
    fresh(device)
    ed_user, p_user = user(b"ed-user"), user(b"p256-user")
    ed, _ = mc(device, [EDDSA], usr=ed_user, options={"rk": True})
    p256, _ = mc(device, [ES256], usr=p_user, options={"rk": True})
    ed_key, p_key = ed.auth_data.credential_data.public_key, p256.auth_data.credential_data.public_key
    ed_id = ed.auth_data.credential_data.credential_id

    # discoverable: both, each signs with its own algorithm
    a, cdh = ga(device)
    assertions = [(a, cdh)]
    assert a.number_of_credentials == 2
    assertions.append((ctap2(device).get_next_assertion(), cdh))
    seen = set()
    for x, h in assertions:
        uid = x.user["id"]
        seen.add(uid)
        if uid == ed_user["id"]:
            assert x.credential["id"] == ed_id
            okp(ed_key).verify(x.signature, bytes(x.auth_data) + h)
        else:
            x.verify(h, p_key)
    assert seen == {ed_user["id"], p_user["id"]}

    # listed with the OKP public key it was created with
    cm = cred_mgmt(device)
    assert cm.get_metadata()[R.EXISTING_CRED_COUNT] == 2
    creds = cm.enumerate_creds(RP_ID_HASH)
    assert len(creds) == 2
    by_user = {c[R.USER]["id"]: c for c in creds}
    listed = by_user[ed_user["id"]]
    assert listed[R.CREDENTIAL_ID]["id"] == ed_id
    assert dict(listed[R.PUBLIC_KEY]) == dict(ed_key)
    okp(listed[R.PUBLIC_KEY])
    assert dict(by_user[p_user["id"]][R.PUBLIC_KEY]) == dict(p_key)

    # deleted: the P-256 one remains
    cm.delete_cred(listed[R.CREDENTIAL_ID])
    cm = cred_mgmt(device)
    assert cm.get_metadata()[R.EXISTING_CRED_COUNT] == 1
    with pytest.raises(CtapError) as e:
        ga(device, [ed_id])
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS
    a, cdh = ga(device)
    assert a.user["id"] == p_user["id"]


def test_hmac_secret(device, eddsa):
    fresh(device)
    salt1, salt2 = b"\x11" * 32, b"\x22" * 32

    def secrets(att):
        cd = att.auth_data.credential_data
        r = device.doGA(allow_list=[{"id": cd.credential_id, "type": "public-key"}],
                        extensions={"hmacGetSecret": {"salt1": salt1, "salt2": salt2}})
        resp = r['res'].get_response(0)
        ad = resp.response.authenticator_data
        cd.public_key.verify(bytes(ad) + resp.response.client_data.hash, resp.response.signature)
        out = resp.client_extension_results.hmac_get_secret
        return out.output1, out.output2

    ed = device.doMC(key_params=[EDDSA], extensions={"hmacCreateSecret": True})['res'].attestation_object
    assert ed.auth_data.extensions["hmac-secret"] is True
    okp(ed.auth_data.credential_data.public_key)
    first = secrets(ed)
    assert len(first[0]) == 32 and len(first[1]) == 32 and first[0] != first[1]
    assert secrets(ed) == first                         # stable
    p256 = device.doMC(key_params=[ES256], extensions={"hmacCreateSecret": True})['res'].attestation_object
    assert secrets(p256)[0] != first[0]                 # per credential


def test_exclude_list(device, eddsa):
    fresh(device)
    att, _ = mc(device, [EDDSA])
    cid = att.auth_data.credential_data.credential_id
    with pytest.raises(CtapError) as e:
        mc(device, [EDDSA], exclude_list=[{"type": "public-key", "id": cid}])
    assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED
    # whatever algorithm the new credential would have
    with pytest.raises(CtapError) as e:
        mc(device, [ES256], exclude_list=[{"type": "public-key", "id": cid}])
    assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED
    # a discoverable one, by its resident ID
    rk, _ = mc(device, [EDDSA], usr=user(b"rk"), options={"rk": True})
    rid = rk.auth_data.credential_data.credential_id
    with pytest.raises(CtapError) as e:
        mc(device, [EDDSA], exclude_list=[{"type": "public-key", "id": rid}])
    assert e.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED
    # another RP is not excluded
    mc(device, [EDDSA], rp={"id": "other.example", "name": "Other"},
       exclude_list=[{"type": "public-key", "id": cid}])


def test_enterprise_attestation(device, eddsa):
    """An enterprise attestation is made with the device key (ES256 and its
    certificate), whatever the credential's algorithm."""
    fresh(device)
    t, p = token(device, ACFG)
    Config(ctap2(device), p, t).enable_enterprise_attestation()
    att, cdh = mc(device, [EDDSA], enterprise_attestation=2)
    st = att.att_stmt
    assert st["alg"] == -7 and len(st["x5c"]) == 1 and att.ep_att is True
    cert = x509.load_der_x509_certificate(st["x5c"][0])
    cert.public_key().verify(st["sig"], bytes(att.auth_data) + cdh, ec.ECDSA(hashes.SHA256()))
    pub = okp(att.auth_data.credential_data.public_key)
    a, cdh = ga(device, [att.auth_data.credential_data.credential_id])
    pub.verify(a.signature, bytes(a.auth_data) + cdh)
    device.reset()


def test_u2f_refuses_an_eddsa_credential(device, eddsa):
    fresh(device, pin=None)
    att = ctap2(device).make_credential(os.urandom(32), RP, user(), [EDDSA])
    cid = att.auth_data.credential_data.credential_id
    for check_only in (False, True):
        with pytest.raises(ApduError) as e:
            device.ctap1.authenticate(os.urandom(32), RP_ID_HASH, cid, check_only=check_only)
        assert e.value.code == APDU.WRONG_DATA
    # still a working FIDO2 credential
    a, cdh = ga(device, [cid])
    okp(att.auth_data.credential_data.public_key).verify(a.signature, bytes(a.auth_data) + cdh)


def key_material(device_key, cred_id):
    """What derive_key() computes for a credential: the hardened key path of
    the credential ID, one HKDF-SHA512 step per entry from the device key.
    (Only the first 64 bytes feed the next step or a 256-bit key.)"""
    path = bytearray(cred_id[:32])
    path[0:4] = (0x80000000 | 10022).to_bytes(4, "little")
    for i in range(1, 8):
        path[4 * i + 3] |= 0x80
    k = device_key + bytes(32)
    for i in range(8):
        k = HKDF(algorithm=hashes.SHA512(), length=64, salt=bytes(path[4 * i:4 * i + 4]),
                 info=k[32:64]).derive(k[:32])
    return k


@pytest.mark.parametrize("alg", [-7, -8])
def test_key_derivation(device, info, alg):
    """With a known device key (vendor restore), the credential's public key
    is recomputed from its credential ID. P-256: the first 32 bytes of the
    key material, big endian. Ed25519: the same 32 bytes are the seed, as the
    mbedTLS EdDSA fork reads them (a little-endian d, hashed as written)."""
    if alg == -8 and not has_eddsa(info):
        pytest.skip("EdDSA is not in this build")
    fresh(device)
    k = ec.generate_private_key(ec.SECP256R1())
    device_key = k.private_numbers().private_value.to_bytes(32, "big")
    hk = os.urandom(32)
    blob = seal_device_key(hk, device_key)
    kct = Mse(device).seal(hk)
    t, p = token(device, ACFG)
    st, _ = raw_vendor(device, VENDOR_BACKUP, {1: 2, 2: {1: blob, 3: kct}, 3: p.VERSION,
                                               4: vendor_auth(t, p, VENDOR_BACKUP, 2, blob, kct)})
    assert st == 0
    try:
        for _ in range(3):
            att, _ = mc(device, [{"type": "public-key", "alg": alg}])
            cd = att.auth_data.credential_data
            m = key_material(device_key, cd.credential_id)
            if alg == -7:
                pub = ec.derive_private_key(int.from_bytes(m[:32], "big"), ec.SECP256R1()).public_key()
                n = pub.public_numbers()
                assert (cd.public_key[-2], cd.public_key[-3]) == (n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big"))
            else:
                pub = ed25519.Ed25519PrivateKey.from_private_bytes(m[:32]).public_key()
                raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                assert cd.public_key[-2] == raw
    finally:
        device.reset()
