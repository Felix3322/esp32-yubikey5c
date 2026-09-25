"""librefido.keyfile (single-key files), the single-key commands of
librefido.mgmt against a simulated device, and what librefido.keyio decides
before it reaches an application (the application paths themselves need
the emulator)."""

import hashlib
import os
import stat
import struct
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
from fido2 import cbor

import fakedev as F
from librefido import backup, keyfile, keyio, mgmt, stdformats
from librefido.keyfile import KeyFileError, SingleKey, read_key_file, write_key_file
from librefido.keyio import KeyTransferError
from librefido.mgmt import PinRequired
from librefido.pcsc import ApduError, MGMT_AID

PW = "correct horse battery staple"
LOG_N = 10                      # fast scrypt for tests

_ed = ed25519.Ed25519PrivateKey.generate()
_raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
SEED = _ed.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
_p256 = ec.generate_private_key(ec.SECP256R1())
P256_D = _p256.private_numbers().private_value.to_bytes(32, "big")
P256_Q = _p256.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

RECORDS = {
    "fido": {1: "example.com", 2: bytes(range(42)), 3: b"user-1", 4: "alice", 5: "Alice", 6: -7, 7: 1,
             8: bytes(range(32)), 9: 2, 10: bytes(64), 11: bytes(32), 13: True, 14: 5, 15: 1700000000},
    "oath": {1: b"Example:alice", 2: 0x21, 3: 6, 4: b"12345678901234567890", 6: False},
    "otp": {1: 2, 2: bytes(range(52)), 3: bytes(8), 4: "chal-hmac"},
    "openpgp": {1: 1, 2: bytes.fromhex("162b06010401da470f01"), 3: {6: SEED, 7: _ed.public_key().public_bytes(*_raw)},
                4: bytes(range(20)), 5: 1700000000, 6: b"\x01\x20"},
    "piv": {1: 0x9A, 2: 0x11, 3: {6: P256_D, 7: P256_Q}, 4: 2, 5: 1},
}


def key(app, **meta):
    return SingleKey(app, dict(RECORDS[app]), meta or {"label": "a %s key" % app, "firmware": "2.1.0"})


def blob_of(k, passphrase=PW):
    out = []

    class Sink:
        def write(self, b):
            out.append(b)
    write_key_file(Sink(), k, passphrase, scrypt_log_n=LOG_N)
    return b"".join(out)


def plain_file(payload, version=1, flags=0, params=b""):
    """A key file in the clear with any payload (bytes or a map)."""
    if not isinstance(payload, bytes):
        payload = cbor.encode(payload)
    return (keyfile.MAGIC + struct.pack("<HHI", version, flags, len(payload)) + hashlib.sha256(payload).digest() +
            struct.pack("<H", len(params)) + params + payload)


# -- key files -----------------------------------------------------------------------

@pytest.mark.parametrize("app", list(RECORDS))
def test_round_trip(tmp_path, app):
    path = str(tmp_path / ("k" + keyfile.SUFFIX))
    size = write_key_file(path, key(app), PW, scrypt_log_n=LOG_N)
    assert os.path.getsize(path) == size
    info, k = read_key_file(path)
    assert info["encrypted"] and k is None
    info, k = read_key_file(path, PW, require_encryption=True)
    assert k.app == app and k.record == RECORDS[app]
    assert k.meta["label"] == "a %s key" % app and k.meta["firmware"] == "2.1.0"
    assert k.meta["tool"] and abs(k.meta["created"] - time.time()) < 60
    assert info["app"] == app and info["label"] == k.meta["label"]


def test_wrong_passphrase_and_candidates():
    blob = blob_of(key("oath"))
    with pytest.raises(KeyFileError, match="wrong passphrase"):
        read_key_file(blob, "other")
    assert read_key_file(blob, ["other", PW])[1].record == RECORDS["oath"]
    decomposed = "café"                   # typed decomposed, stored as NFC
    assert read_key_file(blob_of(key("oath"), decomposed), "café")[1].app == "oath"


def test_tampering_is_detected():
    blob = bytearray(blob_of(key("piv")))
    b = bytearray(blob)
    b[-1] ^= 1
    with pytest.raises(KeyFileError, match="SHA-256"):
        read_key_file(bytes(b), PW)
    # a changed ciphertext with a matching digest: the authentication fails
    plen = struct.unpack_from("<H", blob, 48)[0]
    b[16:48] = hashlib.sha256(bytes(b[50 + plen:])).digest()
    with pytest.raises(KeyFileError, match="wrong passphrase, or the key file was modified"):
        read_key_file(bytes(b), PW)
    # the parameters are authenticated (salt changed: another key, no match)
    b = bytearray(blob)
    salt_at = bytes(b).index(cbor.decode(bytes(b[50:50 + plen]))[2])
    b[salt_at] ^= 1
    with pytest.raises(KeyFileError, match="wrong passphrase"):
        read_key_file(bytes(b), PW)


def test_plaintext_only_when_asked(tmp_path):
    path = str(tmp_path / "k.lfkey")
    with pytest.raises(KeyFileError, match="empty passphrase"):
        write_key_file(path, key("fido"), "")
    assert not os.listdir(str(tmp_path))
    with pytest.raises(TypeError):
        write_key_file(path, key("fido"), b"bytes")
    write_key_file(path, key("fido"), None)                         # explicit: in the clear
    info, k = read_key_file(path)
    assert not info["encrypted"] and k.record == RECORDS["fido"]
    for pw in (None, PW):
        with pytest.raises(KeyFileError, match="NOT encrypted"):
            read_key_file(path, pw, require_encryption=True)


@pytest.mark.parametrize("blob, match", [
    (b"LFBACKUP" + bytes(60), "not a LibreFido key file"),
    (keyfile.MAGIC + bytes(10), "not a LibreFido key file"),
    (plain_file(b"x", version=2), "newer than this tool"),
    (plain_file(b"x", version=0), "version 0"),
    (plain_file(b"x", flags=2), "flags"),
    (plain_file(b"x")[:-1], "truncated"),
    (plain_file(b"x", params=b"\xa0"), "parameters without encryption"),
    (plain_file(b"\xff"), "malformed|unknown content"),
    (plain_file(b"\xa1\x01"), "malformed"),
    (plain_file(b"\x81" * 3000 + b"\x00"), "malformed"),
    (plain_file([1, 2]), "unknown content"),
    (plain_file({1: "librefido-key", 2: 2, 3: "oath", 4: RECORDS["oath"]}), "newer than this tool"),
    (plain_file({1: "other", 2: 1, 3: "oath", 4: RECORDS["oath"]}), "unknown content"),
    (plain_file({1: "librefido-key", 2: 1, 3: "ssh", 4: {}}), "unknown application"),
    (plain_file({1: "librefido-key", 2: 1, 3: "oath", 4: RECORDS["piv"]}), "not a oath key"),
    (plain_file({1: "librefido-key", 2: 1, 3: "piv", 4: RECORDS["oath"]}), "not a piv key"),
    (plain_file({1: "librefido-key", 2: 1, 3: "fido", 4: RECORDS["fido"], 5: [1]}), "metadata"),
])
def test_format_checks(blob, match):
    with pytest.raises(KeyFileError, match=match):
        read_key_file(blob)


def test_encrypted_parameters_are_checked_first():
    blob = blob_of(key("otp"))
    plen = struct.unpack_from("<H", blob, 48)[0]
    params = cbor.decode(blob[50:50 + plen])
    params[3] = 25                                                  # 32 GiB of scrypt
    raw = cbor.encode(params)
    bad = blob[:48] + struct.pack("<H", len(raw)) + raw + blob[50 + plen:]
    with pytest.raises(KeyFileError, match="unsupported encryption parameters"):
        read_key_file(bad, PW)
    assert isinstance(KeyFileError("x"), backup.BackupError)


def test_file_size_limit(tmp_path):
    p = tmp_path / "big.lfkey"
    p.write_bytes(keyfile.MAGIC + bytes(keyfile.MAX_FILE))
    with pytest.raises(KeyFileError, match="larger than"):
        read_key_file(str(p))


@pytest.mark.parametrize("app, bad", [
    ("oath", RECORDS["piv"]),
    ("piv", RECORDS["oath"]),
    ("fido", {**RECORDS["fido"], 1: b"example.com"}),              # rpId must be text
    ("oath", {**RECORDS["oath"], 1: b"x" * 65}),
    ("oath", {**RECORDS["oath"], 2: 0x121}),                        # type/algorithm is one byte
    ("oath", {**RECORDS["oath"], 3: 0x106}),
    ("oath", {**RECORDS["oath"], 2: 0x11, 5: 1 << 64}),             # HOTP counter: 8 bytes
    ("otp", {**RECORDS["otp"], 2: bytes(51)}),
    ("otp", {**RECORDS["otp"], 1: 3}),
    ("openpgp", {**RECORDS["openpgp"], 4: bytes(19)}),
    ("openpgp", {**RECORDS["openpgp"], 3: {2: b"\1"}}),
    ("piv", {**RECORDS["piv"], 3: {7: P256_Q}}),
    ("piv", {**RECORDS["piv"], 2: True}),
    ("piv", {**RECORDS["piv"], "x": 1}),
    ("fido", [1, 2]),
])
def test_records_must_match_the_application(app, bad):
    with pytest.raises(KeyFileError):
        write_key_file(_Null(), SingleKey(app, bad), PW, scrypt_log_n=LOG_N)


class _Null:
    def write(self, b):
        pass


def test_single_key_object():
    k = SingleKey(4, RECORDS["piv"], {3: "from the file", 1: 5, 9: "ignored", "label": None})
    assert k.app == "piv" and k.meta == {"label": None, "created": 5}
    assert "piv" in repr(k) and P256_D.hex() not in repr(k) and str(P256_D) not in repr(k)
    with pytest.raises(KeyFileError):
        SingleKey("ssh", {})
    assert keyfile.is_key_file(blob_of(key("fido"))) and not keyfile.is_key_file(b"LFBACKUP")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_key_file_is_private(tmp_path):
    path = str(tmp_path / "k.lfkey")
    old = os.umask(0o022)
    try:
        write_key_file(path, key("fido"), None)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        write_key_file(path, key("fido"), PW, scrypt_log_n=LOG_N)
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600 and os.listdir(str(tmp_path)) == ["k.lfkey"]


# -- management applet: KEY_LIST / KEY_EXPORT / KEY_IMPORT ------------------------------

def test_indefinite_cbor():
    assert mgmt.decode(bytes.fromhex("9f0102ff")) == [1, 2]
    assert mgmt.decode(bytes.fromhex("bf0102ff")) == {1: 2}
    assert mgmt.decode(bytes.fromhex("a1019f9f01ff80ff")) == {1: [[1], []]}
    assert mgmt.decode(bytes.fromhex("a201020103")) == {1: 3}      # a repeated key counts as an item
    for bad in ("9f01", "9f", "ff", "bf01ff", "9f01ff00", "5f41ff", "bf" * 40 + "ff" * 40):
        with pytest.raises(ValueError):
            mgmt.decode(bytes.fromhex(bad))


def _cbor_page(entries, exportable, nxt):
    items = [(1, b"\x9f" + b"".join(cbor.encode(e) for e in entries) + b"\xff"), (2, cbor.encode(exportable))]
    if nxt is not None:
        items.append((3, cbor.encode(nxt)))
    return bytes([0xA0 | len(items)]) + b"".join(cbor.encode(k) + v for k, v in items)


class KeyDevice(F.FakeDevice):
    """FakeDevice with the single-key commands (lf_mgmt.c KEY_LIST, KEY_EXPORT,
    KEY_IMPORT; FIDO PIN checked like EXPORT_BEGIN)."""

    def __init__(self, **kw):
        kw.setdefault("protocol", 3)
        super().__init__(**kw)
        self.masks = {1: 0b11111, 2: 0b00101}           # export: all, import: FIDO and OTP
        self.entries = {0: [{1: bytes([i]) * 42, 2: "rp%d.example" % i, 3: -7, 6: b"u", 7: False}
                            for i in range(5)],
                        2: [{1: b"\x01", 2: "hotp", 3: True}]}
        self.page_size = 2
        self.exportable = True
        self.export_sw = 0x9000
        self.import_sw = 0x9000
        self.bad_cursor = False
        self.requests = []

    def _info(self):
        m = cbor.decode(super()._info())
        if self.masks is not None:
            m[19] = self.masks
        return cbor.encode(m)

    def handle(self, app, ins, p1, p2, data):
        if app != MGMT_AID or ins not in (mgmt.INS_KEY_LIST, mgmt.INS_KEY_EXPORT, mgmt.INS_KEY_IMPORT):
            return super().handle(app, ins, p1, p2, data)
        if self.masks is None:
            return b"", 0x6D00
        req = cbor.decode(data)
        self.requests.append((ins, req))
        sw = self._pin_check(req.get(2 if ins == mgmt.INS_KEY_LIST else 3, b""))
        if sw:
            return b"", sw
        if ins == mgmt.INS_KEY_LIST:
            all_ = self.entries.get(req[1], [])
            cur = req.get(3, 0)
            nxt = cur + self.page_size if cur + self.page_size < len(all_) else None
            if self.bad_cursor and nxt:
                nxt = cur
            return _cbor_page(all_[cur:cur + self.page_size], self.exportable, nxt), 0x9000
        if ins == mgmt.INS_KEY_EXPORT:
            if self.export_sw != 0x9000:
                return b"", self.export_sw
            return cbor.encode({1: req[1], 2: dict(RECORDS[mgmt.APPS[req[1]]])}), 0x9000
        if self.import_sw != 0x9000:
            return b"", self.import_sw
        return cbor.encode({1: req[1], 2: b"\x42" * 42}), 0x9000


def dev_and_m(monkeypatch, **kw):
    dev = KeyDevice(**kw)
    return dev, F.management(dev, monkeypatch)


def test_key_transfer_support(monkeypatch):
    dev, m = dev_and_m(monkeypatch)
    assert m.key_transfer() == {"export": set(mgmt.APPS), "import": {"fido", "otp"}}
    dev.masks = None
    assert m.key_transfer() == {"export": set(), "import": set()}    # before 2.1.0: no INFO key 19


def test_list_keys_takes_every_page(monkeypatch):
    dev, m = dev_and_m(monkeypatch, pin="1234")
    with pytest.raises(PinRequired):
        m.list_keys("fido")
    assert not dev.requests and dev.retries == 8                    # nothing sent without the PIN
    entries, exportable = m.list_keys("fido", pin="1234")
    assert [e[2] for e in entries] == ["rp%d.example" % i for i in range(5)] and exportable
    assert [r[1].get(3, 0) for r in dev.requests] == [0, 2, 4]
    assert all(r[1][1] == 0 and r[1][2] == b"1234" for r in dev.requests)
    dev.exportable = False
    assert m.list_keys(2, pin="1234") == ([{1: b"\x01", 2: "hotp", 3: True}], False)
    dev.bad_cursor = True
    with pytest.raises(ApduError, match="malformed"):
        m.list_keys("fido", pin="1234")
    with pytest.raises(ValueError):
        m.list_keys("ssh", pin="1234")


def test_list_keys_without_pin(monkeypatch):
    dev, m = dev_and_m(monkeypatch)
    m.list_keys("oath")
    assert dev.requests == [(mgmt.INS_KEY_LIST, {1: 1})]


def test_export_key(monkeypatch):
    dev, m = dev_and_m(monkeypatch, pin="1234")
    assert m.export_key("piv", b"\x9a", pin="1234") == RECORDS["piv"]
    assert dev.requests[-1] == (mgmt.INS_KEY_EXPORT, {1: 4, 2: b"\x9a", 3: b"1234"})
    with pytest.raises(ApduError, match="Admin PIN"):
        m.export_key("openpgp", b"\x01", pin="1234")                # refused before the touch
    assert len(dev.requests) == 1
    m.export_key("openpgp", b"\x01", pin="1234", secret="12345678")
    assert dev.requests[-1][1][4] == b"12345678"
    with pytest.raises(ValueError):
        m.export_key("fido", b"", pin="1234")
    dev.export_sw = 0x6986
    with pytest.raises(ApduError) as e:
        m.export_key("fido", bytes(42), pin="1234")
    assert e.value.sw == 0x6986
    with pytest.raises(ApduError) as e:
        m.export_key("fido", bytes(42), pin="4321")                 # wrong FIDO PIN: a retry used
    assert e.value.sw & 0xFFF0 == 0x63C0


def test_import_key(monkeypatch):
    dev, m = dev_and_m(monkeypatch)
    assert m.import_key("otp", RECORDS["otp"], secret=bytes(6), target=1, replace=True) == b"\x42" * 42
    assert dev.requests[-1] == (mgmt.INS_KEY_IMPORT, {1: 2, 2: RECORDS["otp"], 4: bytes(6), 5: True, 6: b"\x01"})
    m.import_key("fido", RECORDS["fido"])
    assert dev.requests[-1][1] == {1: 0, 2: RECORDS["fido"]}
    dev.import_sw = 0x6A89
    with pytest.raises(ApduError) as e:
        m.import_key("fido", RECORDS["fido"])
    assert e.value.sw == 0x6A89
    dev.import_sw = 0x6982                                          # a wrong access code
    with pytest.raises(ApduError, match="access code") as e:
        m.import_key("otp", RECORDS["otp"], secret=bytes(6))
    assert not isinstance(e.value, PinRequired)
    with pytest.raises(TypeError):
        m.import_key("otp", [1])


# -- keyio, up to the applications -----------------------------------------------------

def test_export_single(monkeypatch):
    dev, m = dev_and_m(monkeypatch, pin="1234")
    k = keyio.export_single(m, "fido", bytes(42), pin="1234")
    assert k.app == "fido" and k.record == RECORDS["fido"]
    assert k.meta["firmware"] == "2.0.0" and k.meta["label"] == "FIDO passkey for example.com (alice)"
    with pytest.raises(KeyTransferError, match="Admin PIN"):
        keyio.export_single(m, "openpgp", b"\x01", pin="1234")
    dev.export_sw = 0x6986
    with pytest.raises(KeyTransferError, match="not allowed by this profile") as e:
        keyio.export_single(m, 0, bytes(42), pin="1234")
    assert e.value.sw == 0x6986
    with pytest.raises(PinRequired):
        keyio.export_single(m, "fido", bytes(42))                  # the caller asks for the PIN


def test_import_single_checks_the_record_first(monkeypatch):
    dev, m = dev_and_m(monkeypatch)
    for app, rec in (("fido", RECORDS["oath"]), ("piv", RECORDS["openpgp"]), ("oath", RECORDS["otp"]),
                     # out of range for YKOATH PUT: refused, not a ValueError / OverflowError
                     ("oath", {**RECORDS["oath"], 2: 0x121}), ("oath", {**RECORDS["oath"], 2: 0x11, 5: 1 << 64})):
        with pytest.raises(KeyTransferError, match="not a %s key" % app):
            keyio.import_single(m, SingleKey(app, rec))
    assert not F.commands(dev)                                      # nothing reached the device
    with pytest.raises(TypeError):
        keyio.import_single(m, RECORDS["fido"])


def test_import_single_fido(monkeypatch):
    dev, m = dev_and_m(monkeypatch)
    text = keyio.import_single(m, key("fido"))
    assert "example.com" in text and dev.requests[-1][1] == {1: 0, 2: RECORDS["fido"]}
    dev.import_sw = 0x6A89
    with pytest.raises(KeyTransferError, match="already on the device"):
        keyio.import_single(m, key("fido"))
    dev.import_sw = 0x6986
    with pytest.raises(KeyTransferError, match="secure profile or a HARDENED build"):
        keyio.import_single(m, key("fido"), replace=True)
    assert dev.requests[-1][1][5] is True
    dev.masks = {1: 0, 2: 0}
    n = len(dev.requests)
    with pytest.raises(KeyTransferError, match="2.1.0"):
        keyio.import_single(m, key("fido"))
    assert len(dev.requests) == n


def test_import_single_otp_never_overwrites_silently(monkeypatch):
    dev, m = dev_and_m(monkeypatch)
    otp = SingleKey("otp", {**RECORDS["otp"], 1: 1})                # slot 1 is configured, with an access code
    with pytest.raises(KeyTransferError, match="slot 1 is configured"):
        keyio.import_single(m, otp)
    with pytest.raises(KeyTransferError, match="access code"):
        keyio.import_single(m, otp, replace=True)
    assert not [r for r in dev.requests if r[0] == mgmt.INS_KEY_IMPORT]
    with pytest.raises(KeyTransferError, match="6 bytes"):
        keyio.import_single(m, otp, replace=True, otp_access_code="0102")
    keyio.import_single(m, otp, replace=True, otp_access_code="010203040506")
    assert dev.requests[-1] == (mgmt.INS_KEY_IMPORT, {1: 2, 2: otp.record, 4: bytes(range(1, 7)), 5: True,
                                                      6: b"\x01"})
    text = keyio.import_single(m, otp, target="2")                  # slot 2 is free
    assert dev.requests[-1][1][6] == b"\x02" and "slot 2" in text
    with pytest.raises(KeyTransferError, match="slot"):
        keyio.import_single(m, otp, target=3)


def _firmware_import_data(data):
    """cmd_import_data.c, in Python: {tag: value} of an extended header list,
    the CRT tag and its length checks."""
    assert data[0] == 0x4D
    body, rest = _ber(data[1:])
    assert rest == b""
    crt = body[0]
    assert body[1] == 0 and body[2:4] == b"\x7f\x48"
    header, rest = _ber(body[4:])
    assert rest[:2] == b"\x5f\x48"
    values, rest = _ber(rest[2:])
    assert rest == b""
    out, i, pos = {}, 0, 0
    while i < len(header):
        tag = header[i]
        n, tail = _ber_len(header[i + 1:])
        i = len(header) - len(tail)
        out[tag] = values[pos:pos + n]
        pos += n
    assert pos == len(values)
    return crt, out


def _ber_len(b):
    if b[0] < 0x80:
        return b[0], b[1:]
    k = b[0] & 0x7F
    return int.from_bytes(b[1:1 + k], "big"), b[1 + k:]


def _ber(b):
    n, rest = _ber_len(b)
    return rest[:n], rest[n:]


def test_openpgp_import_data():
    r = RECORDS["openpgp"]
    crt, tags = _firmware_import_data(keyio._pgp_import_data(1, r[2], r[3]))
    assert crt == 0xB6 and tags == {0x92: SEED, 0x99: r[3][7]}
    x = x25519.X25519PrivateKey.generate()
    native = x.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    crt, tags = _firmware_import_data(keyio._pgp_import_data(2, bytes.fromhex("122b060104019755010501"),
                                                             {6: native, 7: x.public_key().public_bytes(*_raw)}))
    assert crt == 0xB8 and tags[0x92] == native[::-1]               # big endian, as GnuPG sends it
    k = rsa.generate_private_key(65537, 2048)
    n = k.private_numbers()
    priv = {1: b"\x01\x00\x01", 2: n.p.to_bytes(128, "big"), 3: n.q.to_bytes(128, "big")}
    crt, tags = _firmware_import_data(keyio._pgp_import_data(3, bytes.fromhex("010800002000"), priv))
    assert crt == 0xA4 and tags == {0x91: priv[1], 0x92: priv[2], 0x93: priv[3]}
    with pytest.raises(KeyTransferError, match="attributes"):
        keyio._pgp_import_data(3, bytes.fromhex("010c00002000"), priv)
    with pytest.raises(KeyTransferError, match="exponent"):
        keyio._pgp_import_data(3, bytes.fromhex("010800002000"), {**priv, 1: b"\x03"})


def test_piv_import_data():
    k = rsa.generate_private_key(65537, 1024)
    rec = stdformats.piv_record(k)
    rec.update({4: 3, 5: 2})
    tags = dict(keyio._tlvs(keyio._piv_import_data(rec, stdformats.piv_private_key(rec)), "t"))
    n = k.private_numbers()
    assert tags == {1: n.p.to_bytes(64, "big"), 2: n.q.to_bytes(64, "big"), 3: n.dmp1.to_bytes(64, "big"),
                    4: n.dmq1.to_bytes(64, "big"), 5: n.iqmp.to_bytes(64, "big"), 0xAA: b"\x03", 0xAB: b"\x02"}
    rec = dict(RECORDS["piv"])
    assert dict(keyio._tlvs(keyio._piv_import_data(rec, None), "t")) == {6: P256_D, 0xAA: b"\x02", 0xAB: b"\x01"}
    x = stdformats.piv_record(x25519.X25519PrivateKey.generate())
    assert list(dict(keyio._tlvs(keyio._piv_import_data(x, None), "t"))) == [8]
    with pytest.raises(KeyTransferError, match="policy"):
        keyio._piv_import_data({**rec, 4: 7}, None)


def test_piv_objects_and_slots():
    assert [keyio.piv_object_id(s) for s in (0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x95)] == \
        [0x5FC105, 0x5FC10A, 0x5FC10B, 0x5FC101, 0x5FC10D, 0x5FC120]
    for bad in (0x9B, 0xF9, 0x81, 0x96):
        with pytest.raises(KeyTransferError):
            keyio.piv_object_id(bad)
    assert keyio._piv_slot("9c") == 0x9C and keyio._piv_slot(0x82) == 0x82
    for bad in ("9b", "f9", None, True):
        with pytest.raises(KeyTransferError):
            keyio._piv_slot(bad)
    assert keyio._pgp_key_ref("AUT") == 3 and keyio._pgp_key_ref(1) == 1
    with pytest.raises(KeyTransferError):
        keyio._pgp_key_ref(4)


def test_tlv():
    assert keyio._tlv(0x7F48, bytes(200))[:5] == b"\x7f\x48\x81\xc8\x00"
    assert keyio._tlv(0x53, bytes(300))[:4] == b"\x53\x82\x01\x2c"
    assert keyio._tlvs(b"\x7f\x49\x02\x86\x00\x71\x00", "t") == [(0x7F49, b"\x86\x00"), (0x71, b"")]
    for bad in (b"\x71\x05ab", b"\x71", b"\x71\x83\x00\x00\x01\x00"):
        with pytest.raises(KeyTransferError, match="malformed"):
            keyio._tlvs(bad, "t")


def test_describe():
    assert keyio.describe(key("fido")) == "FIDO passkey for example.com (alice)"
    assert keyio.describe(key("oath")) == "OATH TOTP account Example:alice (SHA1, 6 digits)"
    assert keyio.describe(key("otp")) == "OTP slot 2 configuration (chal-hmac)"
    assert keyio.describe(key("openpgp")).startswith("OpenPGP signature key EdDSA ed25519, fingerprint 0001 0203")
    assert keyio.describe(key("piv")) == "PIV ECC P-256 key of slot 9A"
    evil = SingleKey("fido", {**RECORDS["fido"], 1: "a\x1b[31m‮.com"})
    assert "\x1b" not in keyio.describe(evil) and "‮" not in keyio.describe(evil)
    assert keyio.describe(SingleKey("oath", {})) == "oath key"
