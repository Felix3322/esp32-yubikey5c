"""Single-key transfer of FIDO passkeys (discoverable credentials) between
emulated devices (docs/KEY_TRANSFER.md).

A passkey made on device A is exported with the host library (keyio, which
drives KEY_LIST / KEY_EXPORT of the management applet), passed through a
.lfkey file and added to device B, where relying parties must see the
credential they registered: the same credential ID and user, signatures
that verify with the public key A attested, the same hmac-secret outputs
and largeBlobKey, and the same credential in credential management. Records
the host makes up (their keys known here) test what the firmware refuses,
and what a full backup and the profiles do with an imported credential.
A, B and C have their own flash and chip ID and share the ports, so only one
of them runs at a time.

    bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/keys
"""

import hashlib
import hmac
import os
import time

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2, CredentialManagement
from fido2.ctap2.pin import PinProtocolV2

from harness import ctaphid
from librefido import keyio
from librefido.mgmt import INS_KEY_IMPORT

from test_app_transfer import FILE_PW, Mgmt, power, run_cli, through_file, wait_card
from test_mgmt_security import sw_of
from test_profiles_backup import emulators, pcscd, pin_retries, set_pin, wait_reboot  # noqa: F401  (fixtures)

PIN = "314159"
RP, RP_ED = "transfer.example", "eddsa.example"
SALTS = bytes(range(64))            # salt1 || salt2 of hmac-secret
CM = CredentialManagement.RESULT
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
# the manual button, and a short wait for it
NO_TOUCH = {"LF_EMU_UP": "manual", "LF_EMU_UP_TIMEOUT_MS": "1000"}


# -- CTAP ------------------------------------------------------------------------

class Ctap:
    """A CTAPHID connection to the running device, closed on exit."""

    def __enter__(self):
        self.dev = ctaphid.open_device()
        return Ctap2(self.dev)

    def __exit__(self, *a):
        self.dev.close()


def uv(c, pin, permission, rp, cdh):
    """pinUvAuthParam and protocol of a request over cdh, with a PIN token."""
    cp = ClientPin(c, PinProtocolV2())
    tok = cp.get_pin_token(pin, permission, rp)
    return {"pin_uv_param": cp.protocol.authenticate(tok, cdh), "pin_uv_protocol": cp.protocol.VERSION}


def make(c, rp, user, alg=-7, ext=None, pin=None, rk=True, exclude=None):
    """makeCredential for user (id, name, displayName); exclude: credential
    IDs of its excludeList."""
    cdh = os.urandom(32)
    kw = uv(c, pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, rp, cdh) if pin else {}
    return c.make_credential(cdh, {"id": rp, "name": rp}, {"id": user[0], "name": user[1], "displayName": user[2]},
                             [{"type": "public-key", "alg": alg}],
                             exclude_list=[{"type": "public-key", "id": i} for i in exclude] if exclude else None,
                             extensions=ext, options={"rk": rk}, **kw)


def get(c, rp, cred_id=None, ext=None, pin=None):
    """getAssertion (with an allowList of cred_id, or discoverable) and its
    client data hash; with pin, user verification by a PIN token."""
    cdh = os.urandom(32)
    kw = uv(c, pin, ClientPin.PERMISSION.GET_ASSERTION, rp, cdh) if pin else {}
    allow = [{"type": "public-key", "id": cred_id}] if cred_id else None
    return c.get_assertion(rp, cdh, allow, extensions=ext, **kw), cdh


def check_signature(pub, r, cdh):
    """The assertion's signature verifies with pub (a COSE key)."""
    pub.verify(bytes(r.auth_data) + cdh, r.signature)


def no_credentials(c, rp, cred_id=None):
    with pytest.raises(CtapError) as err:
        get(c, rp, cred_id)
    assert err.value.code == CtapError.ERR.NO_CREDENTIALS


def hmac_secret(c, rp, cred_id, pin=None):
    """hmac-secret output of cred_id for SALTS, with user verification (the
    PIN) or without."""
    proto = PinProtocolV2()
    cp = ClientPin(c, proto)
    cdh = os.urandom(32)
    kw = uv(c, pin, ClientPin.PERMISSION.GET_ASSERTION, rp, cdh) if pin else {}
    ka, ss = cp._get_shared_secret()
    enc = proto.encrypt(ss, SALTS)
    ext = {"hmac-secret": {1: ka, 2: enc, 3: proto.authenticate(ss, enc), 4: proto.VERSION}}
    r = c.get_assertion(rp, cdh, [{"type": "public-key", "id": cred_id}], extensions=ext, **kw)
    assert r.auth_data.is_user_verified() is bool(pin)
    return proto.decrypt(ss, r.auth_data.extensions["hmac-secret"])


def host_hmac(cred_random):
    """What hmac-secret answers for SALTS with the CredRandom half of a
    record's key 10 (CredRandomWithoutUV || CredRandomWithUV)."""
    return b"".join(hmac.new(cred_random, SALTS[i:i + 32], "sha256").digest() for i in (0, 32))


def credman(c, pin=PIN):
    cp = ClientPin(c, PinProtocolV2())
    return CredentialManagement(c, cp.protocol, cp.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT))


def rp_hash(rp):
    return hashlib.sha256(rp.encode()).digest()


# -- records -----------------------------------------------------------------------

def fido_ids(m, pin=None):
    """Credential IDs KEY_LIST gives, in its order."""
    return [e[1] for e in m.list_keys("fido", pin=pin)[0]]


def without(rec, *keys):
    return {k: v for k, v in rec.items() if k not in keys}


def resident_id():
    """A credential ID of the resident form (bytes 4..7 F1 D0 02 03)."""
    return os.urandom(4) + b"\xf1\xd0\x02\x03\x00\x00" + os.urandom(32)


def synthetic(rp=RP, user=None, extra=None):
    """A P-256 / ES256 record made up by the host."""
    d = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
    rec = {1: rp, 2: resident_id(), 3: user or os.urandom(16), 4: "made-up", 6: -7, 7: 1, 8: d.to_bytes(32, "big"),
           9: 1, 13: True, 14: 0}
    rec.update(extra or {})
    return rec


def synthetic_ed25519(rp=RP_ED, user=None):
    """An Ed25519 / EdDSA record made up by the host."""
    return {**synthetic(rp, user), 6: -8, 7: 6, 8: os.urandom(32)}


def pub_of(rec):
    """Public key of a record's private key, computed here: {-2: x or the
    Ed25519 key, -3: y}."""
    if rec[7] == 6:
        return {-2: ed25519.Ed25519PrivateKey.from_private_bytes(rec[8]).public_key().public_bytes_raw()}
    n = ec.derive_private_key(int.from_bytes(rec[8], "big"), ec.SECP256R1()).public_key().public_numbers()
    return {-2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def check_record_signature(rec, r, cdh):
    """The assertion's signature verifies with the public key of rec."""
    msg = bytes(r.auth_data) + cdh
    p = pub_of(rec)
    if rec[7] == 6:
        ed25519.Ed25519PublicKey.from_public_bytes(p[-2]).verify(r.signature, msg)
    else:
        ec.EllipticCurvePublicNumbers(int.from_bytes(p[-2], "big"), int.from_bytes(p[-3], "big"), ec.SECP256R1()) \
            .public_key().verify(r.signature, msg, ec.ECDSA(hashes.SHA256()))


def raw_import(m, data):
    """KEY_IMPORT with data as sent (CBOR the host library would not make)."""
    return m._cmd(INS_KEY_IMPORT, data=data, what="key import")


# -- A to B --------------------------------------------------------------------------

USER_X = (b"user-x-" + bytes(range(9)), "alice@transfer.example", "Alice")
USER_Y = (b"user-y", "bob", "Bob Ed")


def test_passkeys_move_to_another_device(pcscd, emulators, tmp_path):
    a, b = emulators("a"), emulators("b")

    # A (with a PIN): an ES256 passkey with hmac-secret, largeBlobKey and
    # credProtect 2, an EdDSA one, and a server-side (non-resident) credential
    power(emulators, a)
    with Ctap() as c:
        ClientPin(c).set_pin(PIN)
        att = make(c, RP, USER_X, -7, {"hmac-secret": True, "largeBlobKey": True, "credProtect": 2}, pin=PIN)
        assert att.auth_data.extensions == {"hmac-secret": True, "credProtect": 2}
        cid_x, pub_x, lbk = att.auth_data.credential_data.credential_id, att.auth_data.credential_data.public_key, \
            att.large_blob_key
        att = make(c, RP_ED, USER_Y, -8, {"hmac-secret": True}, pin=PIN)
        cid_y, pub_y = att.auth_data.credential_data.credential_id, att.auth_data.credential_data.public_key
        assert pub_y[3] == -8 and len(cid_x) == len(cid_y) == 42
        att = make(c, RP, (b"server-side", "s", "S"), pin=PIN, rk=False)
        cid_z, pub_z = att.auth_data.credential_data.credential_id, att.auth_data.credential_data.public_key
        r, cdh = get(c, RP, cid_z)
        check_signature(pub_z, r, cdh)
        r, cdh = get(c, RP, cid_x, {"largeBlobKey": True})
        check_signature(pub_x, r, cdh)
        assert r.large_blob_key == lbk and len(lbk) == 32
        counter_a = r.auth_data.counter
        hx, hx_uv, hy = hmac_secret(c, RP, cid_x), hmac_secret(c, RP, cid_x, pin=PIN), hmac_secret(c, RP_ED, cid_y)
        assert hx != hx_uv
        no_credentials(c, RP)               # credProtect 2: not discoverable without UV

    with Mgmt() as m:
        entries, exportable = m.list_keys("fido", pin=PIN)
        assert exportable
        listed = {e[1]: e for e in entries}
        # the server-side credential is not on the device: not listed
        assert set(listed) == {cid_x, cid_y} and cid_z not in listed
        assert listed[cid_x] == {1: cid_x, 2: RP, 3: -7, 4: USER_X[1], 5: USER_X[2], 6: USER_X[0], 7: False}
        assert listed[cid_y] == {1: cid_y, 2: RP_ED, 3: -8, 4: USER_Y[1], 5: USER_Y[2], 6: USER_Y[0], 7: False}
        key_x = through_file(tmp_path, keyio.export_single(m, "fido", cid_x, pin=PIN), "x")
        key_y = through_file(tmp_path, keyio.export_single(m, "fido", cid_y, pin=PIN), "y")
    rec_x, rec_y = key_x.record, key_y.record
    assert without(rec_x, 8, 10, 11, 14, 15) == {1: RP, 2: cid_x, 3: USER_X[0], 4: USER_X[1], 5: USER_X[2], 6: -7,
                                                  7: 1, 9: 2, 13: True}
    assert pub_of(rec_x) == {-2: pub_x[-2], -3: pub_x[-3]}
    assert rec_x[11] == lbk and rec_x[14] >= counter_a
    assert hx == host_hmac(rec_x[10][:32]) and hx_uv == host_hmac(rec_x[10][32:])
    assert without(rec_y, 8, 10, 14, 15) == {1: RP_ED, 2: cid_y, 3: USER_Y[0], 4: USER_Y[1], 5: USER_Y[2], 6: -8,
                                             7: 6, 9: 1, 13: True}
    assert pub_of(rec_y) == {-2: pub_y[-2]} and hy == host_hmac(rec_y[10][:32])

    # B (no PIN yet): the relying parties see the credentials A made
    power(emulators, b)
    with Mgmt() as m:
        for key in (key_x, key_y):
            assert "imported (credential ID %s)" % key.record[2].hex() in keyio.import_single(m, key)
        # without a PIN (a touch): what a getAssertion with user presence
        # alone gives, the credProtect 1 passkey without its user's names
        entries, _ = m.list_keys("fido")
        assert {e[1]: e for e in entries} == {cid_y: {**without(listed[cid_y], 4, 5), 7: True}}
    with Ctap() as c:
        r, cdh = get(c, RP, cid_x, {"largeBlobKey": True})
        assert r.credential["id"] == cid_x and r.user["id"] == USER_X[0]
        check_signature(pub_x, r, cdh)
        # never below the counter of A at the export
        assert r.auth_data.counter > rec_x[14] >= counter_a
        assert r.large_blob_key == lbk
        assert hmac_secret(c, RP, cid_x) == hx
        no_credentials(c, RP)               # credProtect 2 came along
        r, cdh = get(c, RP_ED)
        assert r.credential["id"] == cid_y and r.user["id"] == USER_Y[0]
        check_signature(pub_y, r, cdh)
        r, cdh = get(c, RP_ED, cid_y)
        assert r.credential["id"] == cid_y
        check_signature(pub_y, r, cdh)
        assert hmac_secret(c, RP_ED, cid_y) == hy

        ClientPin(c).set_pin(PIN)
        r, cdh = get(c, RP, pin=PIN)        # with UV: discoverable
        assert r.credential["id"] == cid_x and r.user["id"] == USER_X[0]
        check_signature(pub_x, r, cdh)
        assert hmac_secret(c, RP, cid_x, pin=PIN) == hx_uv
        # a relying party excluding it finds it
        with pytest.raises(CtapError) as err:
            make(c, RP, (b"someone-else", "e", "E"), pin=PIN, exclude=[cid_x])
        assert err.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED

        # credential management: the same credentials, which it updates and deletes
        cm = credman(c)
        assert cm.get_metadata()[CM.EXISTING_CRED_COUNT] == 2
        assert {rp[CM.RP]["id"] for rp in cm.enumerate_rps()} == {RP, RP_ED}
        for rp, cid, user, pub, protect in ((RP, cid_x, USER_X, pub_x, 2), (RP_ED, cid_y, USER_Y, pub_y, 1)):
            [cr] = cm.enumerate_creds(rp_hash(rp))
            assert cr[CM.CREDENTIAL_ID]["id"] == cid and cr[CM.PUBLIC_KEY] == pub
            assert (cr[CM.USER]["id"], cr[CM.USER]["name"], cr[CM.USER]["displayName"]) == user
            assert cr[CM.CRED_PROTECT] == protect
            assert cr.get(CM.LARGE_BLOB_KEY) == (lbk if cid == cid_x else None)
        cm.update_user_info({"type": "public-key", "id": cid_x},
                            {"id": USER_X[0], "name": "carol@transfer.example", "displayName": "Carol"})
        [cr] = credman(c).enumerate_creds(rp_hash(RP))
        assert (cr[CM.USER]["name"], cr[CM.USER]["displayName"]) == ("carol@transfer.example", "Carol")
        assert cr[CM.CREDENTIAL_ID]["id"] == cid_x and cr[CM.PUBLIC_KEY] == pub_x
        r, cdh = get(c, RP, cid_x)
        check_signature(pub_x, r, cdh)
        assert hmac_secret(c, RP, cid_x) == hx

    # exported again from B: A's record, but for the new names and the counter
    with Mgmt() as m:
        again = m.export_key("fido", cid_x, pin=PIN)
        assert without(again, 4, 5, 14) == without(rec_x, 4, 5, 14)
        assert (again[4], again[5]) == ("carol@transfer.example", "Carol") and again[14] > rec_x[14]
        again = m.export_key("fido", cid_y, pin=PIN)
        assert without(again, 14) == without(rec_y, 14) and again[14] >= rec_y[14]
    with Ctap() as c:
        credman(c).delete_cred({"type": "public-key", "id": cid_y})
        no_credentials(c, RP_ED)
        no_credentials(c, RP_ED, cid_y)
        assert credman(c).get_metadata()[CM.EXISTING_CRED_COUNT] == 1
    with Mgmt() as m:
        assert fido_ids(m, PIN) == [cid_x]


# -- what an import refuses ----------------------------------------------------------

def invalid_records(base):
    """{name: record} the firmware refuses as invalid (6A80). Each brings a
    high sign counter, which must not reach the device either."""
    rid, d = base[2], base[8]
    bad = {
        # the curve does not go with the algorithm
        "p384-es256": {7: 2}, "p256-eddsa": {6: -8}, "ed25519-es256": {7: 6, 8: os.urandom(32)},
        # EC scalars outside [1, n-1], keys of the wrong length
        "scalar-0": {8: bytes(32)}, "scalar-n": {8: P256_N.to_bytes(32, "big")},
        "scalar-ff": {8: b"\xff" * 32}, "scalar-31": {8: d[1:]}, "scalar-33": {8: b"\0" + d},
        "seed-31": {6: -8, 7: 6, 8: os.urandom(31)}, "seed-33": {6: -8, 7: 6, 8: os.urandom(33)},
        # credential IDs of the wrong length or not of the resident form
        "id-41": {2: rid[:41]}, "id-43": {2: rid + b"\0"}, "id-64": {2: rid + bytes(22)},
        "id-form": {2: rid[:4] + b"\xf1\xd0\x02\x04" + rid[8:]},
        # other fields
        "rpid-empty": {1: ""}, "rpid-256": {1: "a" * 256}, "user-empty": {3: b""}, "user-65": {3: bytes(65)},
        "name-nul": {4: "a\0b"}, "credprotect-0": {9: 0}, "credprotect-4": {9: 4}, "hmac-63": {10: bytes(63)},
        "lbk-33": {11: bytes(33)}, "blob-129": {12: bytes(129)}, "counter-max": {14: 0xFFFFFFFF},
        # values of the wrong type, keys that are not unsigned integers
        "alg-text": {6: "-7"}, "curve-text": {7: "1"}, "key-text": {8: d.hex()}, "use-counter-int": {13: 1},
        "text-key": {"1": RP}, "negative-key": {-1: 1},
    }
    out = {name: {**base, 14: 5000, **fields} for name, fields in bad.items()}
    for k in (1, 2, 3, 6, 7, 8):            # a required field missing
        out["missing-%d" % k] = without({**base, 14: 5000}, k)
    return out


def test_import_refusals(pcscd, emulators):
    b = emulators("b")
    power(emulators, b)
    native_user = (b"native-user", "native", "Native")
    with Ctap() as c:
        att = make(c, RP, native_user)
        native, native_pub = att.auth_data.credential_data.credential_id, att.auth_data.credential_data.public_key
    good = synthetic(user=b"good-user")
    with Mgmt() as m:
        assert m.import_key("fido", good) == good[2]
        stored = fido_ids(m)
        assert stored == [native, good[2]]

        # invalid: 6A80, nothing stored, the device counter untouched
        for name, rec in invalid_records(good).items():
            assert sw_of(lambda: m.import_key("fido", rec, replace=True)) == 0x6A80, name
        # a curve this firmware has no key format for (Ed448, unknown): 6A81
        for curve in (7, 99):
            assert sw_of(lambda: m.import_key("fido", {**good, 6: -8, 7: curve, 14: 5000})) == 0x6A81, curve
        # damaged requests: truncated, trailing bytes, a repeated record key,
        # an unknown request key, a target (FIDO has one store)
        req = cbor.encode({1: 0, 2: {**good, 14: 5000}, 5: True})
        for data in (req[:-1], req[:len(req) // 2], req[:5], req + b"\0"):
            assert sw_of(lambda: raw_import(m, data)) == 0x6A80, data.hex()
        rec = cbor.encode({**good, 14: 5000})
        assert rec[0] < 0xB7                # a map of fewer than 23 pairs: its size in the first byte
        twice = bytes([rec[0] + 1]) + rec[1:] + cbor.encode(1) + cbor.encode("other.example")
        assert sw_of(lambda: raw_import(m, b"\xa3\x01\x00\x02" + twice + b"\x05\xf5")) == 0x6A80
        assert sw_of(lambda: raw_import(m, cbor.encode({1: 0, 2: {**good, 14: 5000}, 7: 1}))) == 0x6A80
        assert sw_of(lambda: m.import_key("fido", {**good, 14: 5000}, replace=True, target=1)) == 0x6A80
        assert fido_ids(m) == stored

        # a field of a later version is skipped; it does not come back out
        later = synthetic(user=b"later-user", extra={17: "a later field", 99: {1: b"x"}})
        assert m.import_key("fido", later) == later[2]
        assert without(m.export_key("fido", later[2]), 14) == without(later, 17, 99, 14)

        # the same credential again: only with replace
        assert sw_of(lambda: m.import_key("fido", good)) == 0x6A89
        assert m.import_key("fido", {**good, 4: "replaced"}, replace=True) == good[2]
        # another credential ID for the same rpId and user: only with replace,
        # which removes the credential it conflicts with
        twin = synthetic(user=good[3])
        assert sw_of(lambda: m.import_key("fido", twin)) == 0x6A89
        assert set(fido_ids(m)) == {native, good[2], later[2]}
        assert m.import_key("fido", twin, replace=True) == twin[2]
        # the same with a credential made on this device
        over_native = synthetic(user=native_user[0])
        assert sw_of(lambda: m.import_key("fido", over_native)) == 0x6A89
        assert m.import_key("fido", over_native, replace=True) == over_native[2]
        assert set(fido_ids(m)) == {twin[2], later[2], over_native[2]}
        [e] = [e for e in m.list_keys("fido")[0] if e[1] == over_native[2]]
        assert e[6] == native_user[0] and e[7] is True
    with Ctap() as c:
        no_credentials(c, RP, good[2])
        no_credentials(c, RP, native)
        r, cdh = get(c, RP, twin[2])
        check_record_signature(twin, r, cdh)
        assert r.auth_data.counter < 5000   # no refused record raised it
        r, cdh = get(c, RP, over_native[2])
        check_record_signature(over_native, r, cdh)
        with pytest.raises(InvalidSignature):
            check_signature(native_pub, r, cdh)

    # no touch: 6985 after the wait for it, nothing stored; refused records
    # and conflicts are answered before the touch is asked for
    other = synthetic(user=b"other-user")
    power(emulators, b, **NO_TOUCH)
    with Mgmt() as m:
        t = time.time()
        assert sw_of(lambda: m.import_key("fido", other)) == 0x6985
        assert time.time() - t >= 0.9
        assert sw_of(lambda: m.export_key("fido", twin[2])) == 0x6985
        t = time.time()
        assert sw_of(lambda: m.import_key("fido", twin)) == 0x6A89
        assert sw_of(lambda: m.import_key("fido", {**other, 8: bytes(32)})) == 0x6A80
        assert time.time() - t < 0.9
    b.restart()
    wait_card()
    with Mgmt() as m:
        assert other[2] not in fido_ids(m)

    # a wrong FIDO PIN: 63Cx, one retry used, nothing stored
    set_pin(PIN)
    with Mgmt() as m:
        assert sw_of(lambda: m.import_key("fido", other, pin="000000")) == 0x63C7
        assert pin_retries() == 7
        assert sw_of(lambda: m.export_key("fido", twin[2], pin="000000")) == 0x63C6
        assert pin_retries() == 6
        assert m.import_key("fido", other, pin=PIN) == other[2]
        assert pin_retries() == 8
        assert other[2] in fido_ids(m, PIN)


# -- backups and profiles ------------------------------------------------------------

def test_imported_passkeys_in_backups_and_profiles(pcscd, emulators, tmp_path, capsys):
    """A full backup of B (librefido export / import) brings the imported
    credentials to C; each profile keeps its own."""
    b, c = emulators("b"), emulators("c")
    p256 = synthetic(user=b"p256-user", extra={9: 2, 10: os.urandom(64), 11: os.urandom(32), 14: 777})
    ed = synthetic_ed25519(user=b"ed-user")
    pw, pin = tmp_path / "pw", tmp_path / "pin"
    pw.write_text(FILE_PW + "\n", encoding="utf-8")
    pin.write_text(PIN + "\n", encoding="utf-8")
    backup = str(tmp_path / "b.lfbk")

    power(emulators, b)
    set_pin(PIN)
    with Mgmt() as m:
        for rec in (p256, ed):
            assert m.import_key("fido", rec, pin=PIN) == rec[2]
    with Ctap() as cc:
        r, cdh = get(cc, RP, p256[2])
        check_record_signature(p256, r, cdh)
        assert r.auth_data.counter > 777
    assert "encrypted" in run_cli(capsys, "export", backup, "--passphrase-file", str(pw), "--pin-file", str(pin)).out

    # C: a credential of its own in profile 1, the backup into profile 2
    power(emulators, c)
    own = synthetic(user=b"own-user")
    with Mgmt() as m:
        assert m.import_key("fido", own) == own[2]
    assert "imported" in run_cli(capsys, "import", backup, "--profile", "2", "--passphrase-file", str(pw)).out
    with Mgmt() as m:
        assert fido_ids(m) == [own[2]]
        m.select_profile(1)
        wait_reboot(m)
        entries, _ = m.list_keys("fido", pin=PIN)
        assert {e[1]: e[7] for e in entries} == {p256[2]: True, ed[2]: True}
    with Ctap() as cc:
        r, cdh = get(cc, RP, p256[2], {"largeBlobKey": True}, pin=PIN)
        assert r.user["id"] == p256[3]
        check_record_signature(p256, r, cdh)
        assert r.large_blob_key == p256[11]
        assert hmac_secret(cc, RP, p256[2]) == host_hmac(p256[10][:32])
        assert hmac_secret(cc, RP, p256[2], pin=PIN) == host_hmac(p256[10][32:])
        no_credentials(cc, RP)              # credProtect 2
        r, cdh = get(cc, RP_ED)
        assert r.credential["id"] == ed[2]
        check_record_signature(ed, r, cdh)
        no_credentials(cc, RP, own[2])
    with Mgmt() as m:
        assert without(m.export_key("fido", p256[2], pin=PIN), 14) == without(p256, 14)
        m.select_profile(0)
        wait_reboot(m)
        assert fido_ids(m) == [own[2]]
    with Ctap() as cc:
        no_credentials(cc, RP, p256[2])
        no_credentials(cc, RP_ED)
        r, cdh = get(cc, RP)
        assert r.credential["id"] == own[2]
        check_record_signature(own, r, cdh)
