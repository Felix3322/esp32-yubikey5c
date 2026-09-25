"""librefido.stdformats: otpauth / Google Authenticator links, QR images, PIV
key files and OpenPGP secret keys (made with gpg), read into the records of
the single-key transfer. No device."""

import base64
import datetime
import hashlib
import hmac
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import urllib.parse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from librefido import stdformats as S
from librefido.stdformats import FormatError, PassphraseRequired, WrongPassphrase

SECRET = b"12345678901234567890"                # RFC 4226 / 6238 test secret
B32 = base64.b32encode(SECRET).decode()         # GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ (no padding needed)


def hotp(key, counter, digits=6, alg="sha1"):
    h = hmac.new(key, struct.pack(">Q", counter), alg).digest()
    o = h[-1] & 15
    return (int.from_bytes(h[o:o + 4], "big") & 0x7FFFFFFF) % 10 ** digits


# -- otpauth:// ------------------------------------------------------------------

def test_totp_link():
    [r] = S.parse_otpauth("otpauth://totp/ACME%%20Co:john.doe@email.com?secret=%s&issuer=ACME%%20Co"
                          "&algorithm=SHA1&digits=6&period=30" % B32)
    assert r == {1: b"ACME Co:john.doe@email.com", 2: 0x21, 3: 6, 4: SECRET}


def test_secret_forms_and_normalization():
    short = base64.b32encode(b"0123456789").decode()                    # 10 bytes: padded to 14
    for text in (short, short.lower(), short + "======", " ".join(short[i:i + 4] for i in range(0, 16, 4))):
        [r] = S.parse_otpauth("otpauth://totp/a?secret=" + urllib.parse.quote(text))
        assert r[4] == b"0123456789" + bytes(4)
        assert hotp(r[4], 7) == hotp(b"0123456789", 7)                 # the same codes
    padded = base64.b32encode(b"x" * 11).decode()                       # needs "=" padding
    assert "=" in padded and S.parse_otpauth("otpauth://totp/a?secret=" + padded.rstrip("="))[0][4][:11] == b"x" * 11
    long_key = os.urandom(80)                                           # longer than the SHA-1 block: hashed
    [r] = S.parse_otpauth("otpauth://totp/a?secret=" + base64.b32encode(long_key).decode())
    assert r[4] == hashlib.sha1(long_key).digest().ljust(14, b"\0") and hotp(r[4], 1) == hotp(long_key, 1)
    long_key = os.urandom(100)                                          # SHA-512 block: 128, kept
    [r] = S.parse_otpauth("otpauth://totp/a?algorithm=SHA512&secret=" + base64.b32encode(long_key).decode())
    assert r[4] == long_key and r[2] == 0x23


def test_issuer_period_algorithm_digits():
    [r] = S.parse_otpauth("otpauth://totp/alice?secret=%s&issuer=Example&period=60&digits=8&algorithm=sha256" % B32)
    assert r[1] == b"60/Example:alice" and r[2] == 0x22 and r[3] == 8
    [r] = S.parse_otpauth("otpauth://totp/Label:alice?secret=%s" % B32)       # issuer from the label only
    assert r[1] == b"Label:alice"
    [r] = S.parse_otpauth("otpauth://totp/Label:%%20alice?secret=%s&issuer=Param" % B32)
    assert r[1] == b"Param:alice"                                             # the parameter wins
    [r] = S.parse_otpauth("  OTPAUTH://TOTP/bob?SECRET=%s&Period=30  " % B32)
    assert r[1] == b"bob"


def test_hotp_counter():
    [r] = S.parse_otpauth("otpauth://hotp/Example:alice?secret=%s&counter=42&period=60" % B32)
    assert r == {1: b"Example:alice", 2: 0x11, 3: 6, 4: SECRET, 5: 42}          # no period for HOTP
    assert S.parse_otpauth("otpauth://hotp/a?secret=%s" % B32)[0][5] == 0


@pytest.mark.parametrize("uri, match", [
    ("https://example.com/?secret=AAAA", "otpauth"),
    ("otpauth://steam/a?secret=%s" % B32, "type"),
    ("otpauth://totp/a?issuer=x", "no secret"),
    ("otpauth://totp/a?secret=1189!!", "base32"),
    ("otpauth://totp/a?secret=%s&algorithm=MD5" % B32, "algorithm"),
    ("otpauth://totp/a?secret=%s&digits=5" % B32, "digits"),
    ("otpauth://totp/a?secret=%s&digits=9" % B32, "digits"),
    ("otpauth://totp/a?secret=%s&digits=six" % B32, "digits"),
    ("otpauth://totp/a?secret=%s&period=0" % B32, "period"),
    ("otpauth://hotp/a?secret=%s&counter=-1" % B32, "counter"),
    ("otpauth://totp/?secret=%s" % B32, "account"),
    ("otpauth://totp/%s?secret=%s" % ("x" * 65, B32), "65 bytes"),
    ("otpauth://totp/a?secret=", "secret"),
])
def test_bad_links(uri, match):
    with pytest.raises(FormatError, match=match):
        S.parse_otpauth(uri)


@pytest.mark.parametrize("uri", [
    "otpauth://totp/Example:alice@example.com?secret=%s&issuer=Example" % B32,
    "otpauth://totp/Big%%20Corp%%20%%C3%%A9:%%C3%%BCser?secret=%s&period=45&digits=7&algorithm=SHA512" % B32,
    "otpauth://hotp/Bank:bob?secret=%s&counter=123456789012&algorithm=SHA256&digits=8" % B32,
    "otpauth://totp/solo?secret=%s" % B32,
])
def test_record_to_uri_round_trip(uri):
    [r] = S.parse_otpauth(uri)
    again = S.oath_record_to_uri(r)
    assert again.startswith("otpauth://") and S.parse_otpauth(again) == [r]


def test_uri_of_a_record_with_period():
    [r] = S.parse_otpauth("otpauth://totp/Ex:al?secret=%s&period=60" % B32)
    uri = S.oath_record_to_uri(r)
    assert "period=60" in uri and "/Ex:al?" in uri and "issuer=Ex" in uri
    with pytest.raises(FormatError):
        S.oath_record_to_uri({1: b"\xff\xfe", 2: 0x21, 3: 6, 4: SECRET})


def test_names_that_look_like_a_period():
    """A 30 s TOTP account named "12/alice" gets its period written out
    ("30/12/alice"): YKOATH readers take a leading "<digits>/" for the
    period, 12 s here (the rule of mgr_oath.build_name). HOTP names have no
    period. A stored TOTP name "0/x" (no period is 0 s) is a 30 s account
    named "0/x", and its link says so instead of period=0."""
    for label, raw in (("12%2Falice", b"30/12/alice"), ("12/x:a", b"30/12/x:a"), ("Site:12%2Fa", b"Site:12/a"),
                       ("0%2Fwork", b"30/0/work")):
        [r] = S.parse_otpauth("otpauth://totp/%s?secret=%s" % (label, B32))
        assert r[1] == raw, label
        assert S.parse_otpauth(S.oath_record_to_uri(r)) == [r]
    [r] = S.parse_otpauth("otpauth://totp/12%%2Falice?secret=%s&period=60" % B32)
    assert r[1] == b"60/12/alice"
    [r] = S.parse_otpauth("otpauth://hotp/12%%2Falice?secret=%s&counter=3" % B32)
    assert r[1] == b"12/alice"
    uri = migration([_otp_params(SECRET, "12/alice"), _otp_params(SECRET, "7/bob", kind=1, counter=5),
                     _otp_params(SECRET, "12/x", alg=4)])
    assert [r[1] for r in S.parse_otpauth(uri, skip_unsupported=True)] == [b"30/12/alice", b"7/bob"]
    with pytest.raises(FormatError, match=r"accounts the device cannot hold: 12/x \(algorithm MD5\)"):
        S.parse_otpauth(uri)
    uri = S.oath_record_to_uri({1: b"0/x", 2: 0x21, 3: 6, 4: SECRET})
    assert "period=30" in uri and "period=0" not in uri and "/0%2Fx?" in uri
    assert S.parse_otpauth(uri)[0][1] == b"30/0/x"
    assert S.split_ykoath_name("0/x") == ("0/x", None, 30) and S.split_ykoath_name("00/a:b") == ("b", "00/a", 30)


# -- otpauth-migration:// ----------------------------------------------------------

def _varint(v):
    out = b""
    v &= (1 << 64) - 1
    while True:
        b, v = v & 0x7F, v >> 7
        if v:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def _field(n, v):
    if isinstance(v, int):
        return _varint(n << 3) + _varint(v)
    if isinstance(v, str):
        v = v.encode()
    return _varint(n << 3 | 2) + _varint(len(v)) + v


def _otp_params(secret, name, issuer="", alg=1, digits=1, kind=2, counter=None):
    m = _field(1, secret) + _field(2, name) + (_field(3, issuer) if issuer else b"")
    m += _field(4, alg) + _field(5, digits) + _field(6, kind)
    return m + (_field(7, counter) if counter is not None else b"")


def migration(accounts, version=1, size=1, index=0, batch_id=-123456 & 0xFFFFFFFF, quote=True):
    payload = b"".join(_field(1, a) for a in accounts)
    payload += _field(2, version) + _field(3, size) + _field(4, index) + _field(5, batch_id)
    data = base64.b64encode(payload).decode()
    return "otpauth-migration://offline?data=" + (urllib.parse.quote(data, safe="") if quote else data)


def test_migration_accounts_and_batch():
    uri = migration([_otp_params(SECRET, "alice@example.com", "Example"),
                     _otp_params(b"\x01" * 20, "Bank:bob", "Bank", alg=2, digits=2, kind=1, counter=42),
                     _otp_params(b"\x02" * 32, "carol", "", alg=3)], size=2, index=1, batch_id=77)
    records, batch = S.parse_migration(uri)
    assert batch == {"version": 1, "batch_size": 2, "batch_index": 1, "batch_id": 77}
    assert records == [{1: b"Example:alice@example.com", 2: 0x21, 3: 6, 4: SECRET},
                       {1: b"Bank:bob", 2: 0x12, 3: 8, 4: b"\x01" * 20, 5: 42},
                       {1: b"carol", 2: 0x23, 3: 6, 4: b"\x02" * 32}]
    assert S.parse_otpauth(uri) == records
    # "+" not escaped, and the URL-safe alphabet, read alike
    raw = migration([_otp_params(b"\xfb\xff" * 10, "x")], quote=False)
    assert S.parse_otpauth(raw)[0][4][:20] == b"\xfb\xff" * 10
    head, data = raw.split("data=")
    urlsafe = head + "data=" + data.replace("+", "-").replace("/", "_").rstrip("=")
    assert S.parse_otpauth(urlsafe)[0][4][:20] == b"\xfb\xff" * 10


def test_migration_unknown_fields_are_skipped():
    extra = _field(15, 7) + _varint(16 << 3 | 5) + b"abcd" + _varint(17 << 3 | 1) + b"12345678"
    [r] = S.parse_otpauth(migration([_otp_params(SECRET, "a") + extra]))
    assert r[1] == b"a"


def test_migration_unsupported_accounts():
    uri = migration([_otp_params(SECRET, "good"), _otp_params(SECRET, "old", alg=4), _otp_params(SECRET, "odd",
                                                                                               digits=3)])
    with pytest.raises(FormatError, match="old .algorithm MD5.*odd"):
        S.parse_otpauth(uri)
    assert [r[1] for r in S.parse_otpauth(uri, skip_unsupported=True)] == [b"good"]


def test_missing_batches():
    parts = [migration([_otp_params(SECRET, "a%d" % i)], size=3, index=i, batch_id=9) for i in (0, 2)]
    assert S.missing_batches(parts + ["otpauth://totp/x?secret=%s" % B32]) == {9: [1]}
    parts.append(migration([_otp_params(SECRET, "a1")], size=3, index=1, batch_id=9))
    assert S.missing_batches(parts) == {}


@pytest.mark.parametrize("size,index", [(10 ** 7, 0), (1 << 40, 0), ((1 << 64) - 1, 0), (0, 0), (3, 3),
                                        (S.MIGRATION_BATCHES_MAX + 1, 0)])
def test_migration_batch_bounds(size, index):
    """The batch fields come from the link: a short link claiming billions of
    QR codes is refused, before missing_batches would list their indexes."""
    uri = migration([_otp_params(SECRET, "a")], size=size, index=index)
    assert len(uri) < 200
    with pytest.raises(FormatError, match="malformed migration data"):
        S.missing_batches([uri])
    with pytest.raises(FormatError, match="malformed migration data"):
        S.parse_otpauth(uri)
    edge = migration([_otp_params(SECRET, "a")], size=S.MIGRATION_BATCHES_MAX, index=S.MIGRATION_BATCHES_MAX - 1)
    assert len(S.missing_batches([edge])[-123456 & 0xFFFFFFFF]) == S.MIGRATION_BATCHES_MAX - 1


@pytest.mark.parametrize("data", [
    b"\x0a\x05abc",                         # truncated field
    b"\x0a\x03\x0a\x80",                    # truncated varint inside
    b"\x0b",                                # wire type 3 (groups)
    b"\xff" * 11,                           # varint too long
])
def test_malformed_migration(data):
    with pytest.raises(FormatError):
        S.parse_otpauth("otpauth-migration://offline?data=" + urllib.parse.quote(base64.b64encode(data)))


def test_migration_errors():
    with pytest.raises(FormatError, match="no data"):
        S.parse_otpauth("otpauth-migration://offline?x=1")
    with pytest.raises(FormatError, match="base64"):
        S.parse_otpauth("otpauth-migration://offline?data=%%%21%21")
    with pytest.raises(FormatError, match="negative"):
        S.parse_otpauth(migration([_otp_params(SECRET, "h", kind=1, counter=-5)]))


# -- QR images ---------------------------------------------------------------------

def test_qr_decoding_with_opencv(tmp_path):
    cv2 = pytest.importorskip("cv2", reason="no QR decoder installed (opencv-python-headless)")
    uri = "otpauth://totp/Example:alice?secret=%s&issuer=Example" % B32
    img = cv2.QRCodeEncoder.create().encode(uri)
    img = cv2.resize(img, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    img = cv2.copyMakeBorder(img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    path = str(tmp_path / "qr code ä.png")
    ok, png = cv2.imencode(".png", img)
    with open(path, "wb") as f:
        f.write(png.tobytes())
    assert S.decode_qr_image(path) == [uri]


def _no_modules(monkeypatch, *names):
    for n in names:
        monkeypatch.setitem(sys.modules, n, None)       # import raises ImportError


def test_qr_without_decoder_names_what_to_install(monkeypatch, tmp_path):
    _no_modules(monkeypatch, "cv2", "PIL", "zxingcpp", "pyzbar")
    with pytest.raises(FormatError, match="opencv-python-headless"):
        S.decode_qr_image(str(tmp_path / "x.png"))


def test_qr_opencv_path(monkeypatch, tmp_path):
    """OpenCV reads the file itself (bytes), the detector's texts are
    returned, the single-code detector is the fallback."""
    uri = "otpauth://totp/a?secret=%s" % B32
    seen = {}

    class Detector:
        multi = (True, (uri, ""), None, None)

        def detectAndDecodeMulti(self, img):
            seen["img"] = img
            return self.multi

        def detectAndDecode(self, img):
            return uri, None, None
    cv2 = types.SimpleNamespace(IMREAD_COLOR=1, error=RuntimeError, QRCodeDetector=Detector,
                                imdecode=lambda buf, flag: None if buf == b"junk" else ("decoded", buf))
    monkeypatch.setitem(sys.modules, "cv2", cv2)
    monkeypatch.setitem(sys.modules, "numpy", types.SimpleNamespace(uint8="u8", frombuffer=lambda b, dtype: b))
    p = tmp_path / "q.png"
    p.write_bytes(b"PNG data")
    assert S.decode_qr_image(str(p)) == [uri] and seen["img"] == ("decoded", b"PNG data")
    Detector.multi = (False, (), None, None)
    assert S.decode_qr_image(str(p)) == [uri]
    p.write_bytes(b"junk")
    with pytest.raises(FormatError, match="not an image"):
        S.decode_qr_image(str(p))
    with pytest.raises(FormatError, match="cannot read"):
        S.decode_qr_image(str(tmp_path / "missing.png"))


def test_qr_pyzbar_path(monkeypatch, tmp_path):
    _no_modules(monkeypatch, "cv2", "zxingcpp")

    class Img:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def convert(self, mode):
            return "rgb"
    pil = types.ModuleType("PIL")
    pil.Image = types.SimpleNamespace(open=lambda path: Img())
    monkeypatch.setitem(sys.modules, "PIL", pil)
    monkeypatch.setitem(sys.modules, "PIL.Image", pil.Image)
    sym = types.SimpleNamespace(type="QRCODE", data=b"otpauth://totp/z?secret=AAAA")
    bar = types.SimpleNamespace(type="EAN13", data=b"123")
    pz = types.ModuleType("pyzbar")
    pz.pyzbar = types.SimpleNamespace(decode=lambda img: [bar, sym] if img == "rgb" else [])
    monkeypatch.setitem(sys.modules, "pyzbar", pz)
    monkeypatch.setitem(sys.modules, "pyzbar.pyzbar", pz.pyzbar)
    assert S.decode_qr_image(str(tmp_path / "x.png")) == ["otpauth://totp/z?secret=AAAA"]
    pz.pyzbar.decode = lambda img: [bar]
    with pytest.raises(FormatError, match="no QR code"):
        S.decode_qr_image(str(tmp_path / "x.png"))


# -- PIV key files -------------------------------------------------------------------

def _cert(key, cn="LibreFido test"):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2026, 1, 1)
    signer = ec.generate_private_key(ec.SECP256R1())            # X25519 cannot sign its own certificate
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30)).sign(signer, hashes.SHA256()))


def _pub(key):
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture(scope="module")
def piv_keys():
    return {S.PIV_RSA1024: rsa.generate_private_key(65537, 1024), S.PIV_RSA2048: rsa.generate_private_key(65537, 2048),
            S.PIV_P256: ec.generate_private_key(ec.SECP256R1()), S.PIV_P384: ec.generate_private_key(ec.SECP384R1()),
            S.PIV_ED25519: ed25519.Ed25519PrivateKey.generate(), S.PIV_X25519: x25519.X25519PrivateKey.generate()}


PEM, DER = serialization.Encoding.PEM, serialization.Encoding.DER
PKCS8, TRAD = serialization.PrivateFormat.PKCS8, serialization.PrivateFormat.TraditionalOpenSSL
NOENC = serialization.NoEncryption()


def _check(result, key, algo, cert=None):
    [(rec, cert_der)] = result
    assert rec[2] == algo and 1 not in rec
    assert _pub(S.piv_private_key(rec)) == _pub(key)            # the record is the same key
    assert cert_der == (cert.public_bytes(DER) if cert else None)
    return rec


def test_piv_formats(piv_keys):
    for algo, key in piv_keys.items():
        _check(S.load_piv_key(key.private_bytes(PEM, PKCS8, NOENC)), key, algo)
        _check(S.load_piv_key(key.private_bytes(DER, PKCS8, NOENC)), key, algo)
        enc = key.private_bytes(PEM, PKCS8, serialization.BestAvailableEncryption(b"pw"))
        _check(S.load_piv_key(enc, "pw"), key, algo)
        _check(S.load_piv_key(key.private_bytes(DER, PKCS8, serialization.BestAvailableEncryption(b"pw")), b"pw"),
               key, algo)
        if algo not in (S.PIV_ED25519, S.PIV_X25519):             # no traditional form for these
            _check(S.load_piv_key(key.private_bytes(PEM, TRAD, NOENC)), key, algo)
            _check(S.load_piv_key(key.private_bytes(DER, TRAD, NOENC)), key, algo)
            _check(S.load_piv_key(key.private_bytes(PEM, TRAD, serialization.BestAvailableEncryption(b"pw")), "pw"),
                   key, algo)


def test_piv_record_contents(piv_keys):
    rec = _check(S.load_piv_key(piv_keys[S.PIV_RSA2048].private_bytes(PEM, PKCS8, NOENC)), piv_keys[S.PIV_RSA2048],
                 S.PIV_RSA2048)
    n = piv_keys[S.PIV_RSA2048].private_numbers()
    assert rec[3] == {1: b"\x01\x00\x01", 2: n.p.to_bytes(128, "big"), 3: n.q.to_bytes(128, "big")}
    k = piv_keys[S.PIV_P256]
    rec = _check(S.load_piv_key(k.private_bytes(PEM, PKCS8, NOENC)), k, S.PIV_P256)
    assert rec[3][6] == k.private_numbers().private_value.to_bytes(32, "big") and rec[3][7][0] == 4
    k = piv_keys[S.PIV_X25519]
    rec = _check(S.load_piv_key(k.private_bytes(PEM, PKCS8, NOENC)), k, S.PIV_X25519)
    raw = serialization.Encoding.Raw
    assert rec[3][6] == k.private_bytes(raw, serialization.PrivateFormat.Raw, NOENC)      # native order


def test_piv_certificates(piv_keys):
    key, other = piv_keys[S.PIV_P256], piv_keys[S.PIV_P384]
    cert, other_cert = _cert(key), _cert(other, "other")
    pem = other_cert.public_bytes(PEM) + key.private_bytes(PEM, PKCS8, NOENC) + cert.public_bytes(PEM)
    _check(S.load_piv_key(pem), key, S.PIV_P256, cert)                        # the key's own certificate
    _check(S.load_piv_key(key.private_bytes(PEM, PKCS8, NOENC) + other_cert.public_bytes(PEM)), key, S.PIV_P256)
    for algo, k in piv_keys.items():
        if algo == S.PIV_X25519:
            continue                        # (cryptography does not put X25519 keys into PKCS#12)
        c = _cert(k)
        p12 = pkcs12.serialize_key_and_certificates(b"n", k, c, [other_cert],
                                                    serialization.BestAvailableEncryption(b"pw"))
        _check(S.load_piv_key(p12, "pw"), k, algo, c)
    p12 = pkcs12.serialize_key_and_certificates(b"n", key, cert, None, NOENC)
    _check(S.load_piv_key(p12), key, S.PIV_P256, cert)                        # without a password


def test_piv_passwords(piv_keys):
    key = piv_keys[S.PIV_P256]
    enc = key.private_bytes(PEM, PKCS8, serialization.BestAvailableEncryption(b"right"))
    with pytest.raises(PassphraseRequired):
        S.load_piv_key(enc)
    with pytest.raises(WrongPassphrase):
        S.load_piv_key(enc, "wrong")
    _check(S.load_piv_key(key.private_bytes(PEM, PKCS8, NOENC), "unneeded"), key, S.PIV_P256)
    p12 = pkcs12.serialize_key_and_certificates(b"n", key, None, None, serialization.BestAvailableEncryption(b"right"))
    with pytest.raises(PassphraseRequired):
        S.load_piv_key(p12)
    with pytest.raises(WrongPassphrase):
        S.load_piv_key(p12, "wrong")


def test_piv_unsupported_keys():
    for key, match in ((rsa.generate_private_key(3, 1024), "exponent"),
                       (rsa.generate_private_key(65537, 1536), "RSA 1536"),
                       (ec.generate_private_key(ec.SECP521R1()), "secp521r1"),
                       (ec.generate_private_key(ec.SECP256K1()), "secp256k1")):
        with pytest.raises(FormatError, match=match):
            S.load_piv_key(key.private_bytes(PEM, PKCS8, NOENC))
    for junk in (b"", b"hello", b"\x30\x03\x02\x01\x05", b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"):
        with pytest.raises(FormatError):
            S.load_piv_key(junk)
    with pytest.raises(FormatError, match="OpenSSH"):
        k = ed25519.Ed25519PrivateKey.generate()
        S.load_piv_key(k.private_bytes(PEM, serialization.PrivateFormat.OpenSSH, NOENC))


def test_piv_record_to_pem(piv_keys):
    key = piv_keys[S.PIV_ED25519]
    cert = _cert(key)
    [(rec, _)] = S.load_piv_key(key.private_bytes(PEM, PKCS8, NOENC))
    rec = {**rec, 1: 0x9A, 4: 2, 5: 1, 8: cert.public_bytes(DER)}
    pem = S.piv_record_to_pem(rec, "secret")
    assert b"ENCRYPTED PRIVATE KEY" in pem and b"BEGIN CERTIFICATE" in pem
    [(again, c)] = S.load_piv_key(pem, "secret")
    assert again == {2: rec[2], 3: rec[3]} and c == rec[8]
    plain = S.piv_record_to_pem({2: rec[2], 3: rec[3]}, None)
    assert b"BEGIN PRIVATE KEY" in plain and b"CERTIFICATE" not in plain
    with pytest.raises(FormatError, match="empty passphrase"):
        S.piv_record_to_pem(rec, "")
    for bad in ({2: rec[2], 3: {6: rec[3][6], 7: bytes(32)}},           # public key of another key
                {2: S.PIV_P256, 3: {6: bytes(31)}},
                {2: S.PIV_RSA2048, 3: {1: b"\x01\x00\x01", 2: b"\x05", 3: b"\x07"}},
                {2: 0x99, 3: {6: bytes(32)}}):
        with pytest.raises(FormatError):
            S.piv_private_key(bad)


# -- OpenPGP secret keys (gpg) ---------------------------------------------------------

GPG = shutil.which("gpg")
PGP_PW = "pgp passphrase"


class Gpg:
    """gpg with its own short-lived GNUPGHOME (short path: the agent socket)."""

    def __init__(self):
        self.home = tempfile.mkdtemp(prefix="lfgpg", dir="/tmp" if os.path.isdir("/tmp") else None)
        os.chmod(self.home, 0o700)
        self.env = dict(os.environ, GNUPGHOME=self.home, LC_ALL="C")

    def run(self, *args, passphrase=PGP_PW, stdin=None):
        cmd = [GPG, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", passphrase] + list(args)
        r = subprocess.run(cmd, env=self.env, input=stdin, capture_output=True, timeout=180)
        assert r.returncode == 0, r.stderr.decode(errors="replace")
        return r.stdout

    def make(self, primary, subkeys, passphrase=PGP_PW, uid="Test <test@example.org>"):
        self.run("--quick-gen-key", uid, primary[0], primary[1], "0", passphrase=passphrase)
        fpr = self.keys(uid)[0]["fpr"]
        for algo, use in subkeys:
            self.run("--quick-add-key", fpr, algo, use, "0", passphrase=passphrase)
        return fpr

    def keys(self, which):
        """[{fpr, created, caps, pkd: [ints/bytes]}] from --with-colons --with-key-data."""
        out, cur = [], None
        for line in self.run("--with-colons", "--with-key-data", "--list-keys", which).decode().splitlines():
            f = line.split(":")
            if f[0] in ("pub", "sub"):
                cur = {"created": int(f[5]), "caps": set(f[11]) & set("scea"), "pkd": [], "algo": int(f[3])}
                out.append(cur)
            elif f[0] == "fpr" and cur is not None and "fpr" not in cur:
                cur["fpr"] = f[9]
            elif f[0] == "pkd" and cur is not None:
                cur["pkd"].append(bytes.fromhex(f[3]))
        return out

    def close(self):
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=self.env, capture_output=True)
        shutil.rmtree(self.home, ignore_errors=True)


KEYSETS = {
    "rsa2048": (("rsa2048", "sign,cert"), [("rsa2048", "encr"), ("rsa2048", "auth")]),
    "nistp256": (("nistp256", "sign,cert"), [("nistp256", "encr"), ("nistp256/ecdsa", "auth")]),
    "25519": (("ed25519", "sign,cert"), [("cv25519", "encr"), ("ed25519", "auth")]),
}
CAPS = {"s": "sig", "c": "cert", "e": "dec", "a": "aut"}


@pytest.fixture(scope="module")
def gpg_keys():
    if GPG is None:
        pytest.skip("gpg is not installed")
    g = Gpg()
    try:
        made = {}
        for name, (primary, subs) in KEYSETS.items():
            uid = "Test %s <%s@example.org>" % (name, name)
            fpr = g.make(primary, subs, uid=uid)
            made[name] = {"fpr": fpr, "info": g.keys(fpr), "armored": g.run("--armor", "--export-secret-keys", fpr),
                          "binary": g.run("--export-secret-keys", fpr), "uid": uid}
        uid = "Plain <plain@example.org>"
        fpr = g.make(("ed25519", "sign,cert"), [("cv25519", "encr")], passphrase="", uid=uid)
        made["plain"] = {"fpr": fpr, "info": g.keys(fpr), "uid": uid,
                         "armored": g.run("--armor", "--export-secret-keys", fpr, passphrase="")}
        yield made
    finally:
        g.close()


def _public_of(entry):
    """The public key (as gpg's key data shows it) derived from the parsed
    private key of an entry."""
    rec = entry["record"]
    attr, k = rec[2], rec[3]
    raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if attr[0] == 1:
        return [(int.from_bytes(k[2], "big") * int.from_bytes(k[3], "big")).to_bytes(256, "big"), k[1]]
    name = S.pgp_attr_name(attr)
    if name.endswith("ed25519"):
        return [b"\x40" + ed25519.Ed25519PrivateKey.from_private_bytes(k[6]).public_key().public_bytes(*raw)]
    if name.endswith("cv25519"):
        return [b"\x40" + x25519.X25519PrivateKey.from_private_bytes(k[6]).public_key().public_bytes(*raw)]
    key = ec.derive_private_key(int.from_bytes(k[6], "big"), ec.SECP256R1())
    return [key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)]


ATTRS = {
    "rsa2048": [bytes.fromhex("010800002000")] * 3,
    "nistp256": [bytes.fromhex("132a8648ce3d030107"), bytes.fromhex("122a8648ce3d030107"),
                 bytes.fromhex("132a8648ce3d030107")],
    "25519": [bytes.fromhex("162b06010401da470f01"), bytes.fromhex("122b060104019755010501"),
              bytes.fromhex("162b06010401da470f01")],
}


@pytest.mark.parametrize("name", list(KEYSETS))
@pytest.mark.parametrize("form", ["armored", "binary"])
def test_openpgp_keys_from_gpg(gpg_keys, name, form):
    made = gpg_keys[name]
    keys = S.parse_openpgp_secret(made[form], PGP_PW)
    assert [k["fingerprint"].hex().upper() for k in keys] == [i["fpr"] for i in made["info"]]
    for k, info, attr in zip(keys, made["info"], ATTRS[name]):
        assert k["unsupported"] is None and k["record"] is not None
        assert k["usage"] == {CAPS[c] for c in info["caps"]}
        assert k["created"] == info["created"] and k["record"][5] == info["created"]
        assert k["record"][4] == k["fingerprint"] and k["key_id"] == info["fpr"][-16:]
        assert k["user_ids"] == [made["uid"]] and not k["revoked"]
        assert k["record"][2] == attr and 1 not in k["record"]
        # the private key gives the public key gpg lists (RSA: n, e; EC: the point)
        want = info["pkd"][:2] if name == "rsa2048" else [info["pkd"][1]]
        if name == "rsa2048":
            want = [want[0].rjust(256, b"\0"), want[1]]
        assert _public_of(k) == want
    assert [k["primary"] for k in keys] == [True, False, False]


def test_openpgp_x25519_is_native(gpg_keys):
    """cv25519: GnuPG keeps the scalar big endian; the record has the card's
    (native) order, which gives the public key only that way round."""
    enc = [k for k in S.parse_openpgp_secret(gpg_keys["25519"]["armored"], PGP_PW) if "dec" in k["usage"]][0]
    native = enc["record"][3][6]
    raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert x25519.X25519PrivateKey.from_private_bytes(native).public_key().public_bytes(*raw) == enc["record"][3][7]
    assert x25519.X25519PrivateKey.from_private_bytes(native[::-1]).public_key().public_bytes(*raw) != \
        enc["record"][3][7]


def test_openpgp_passphrases(gpg_keys):
    armored = gpg_keys["25519"]["armored"]
    with pytest.raises(PassphraseRequired):
        S.parse_openpgp_secret(armored)
    with pytest.raises(WrongPassphrase):
        S.parse_openpgp_secret(armored, "not it")
    keys = S.parse_openpgp_secret(gpg_keys["plain"]["armored"])          # unprotected: no passphrase needed
    assert [k["fingerprint"].hex().upper() for k in keys] == [i["fpr"] for i in gpg_keys["plain"]["info"]]
    assert all(k["record"] for k in keys)
    assert S.parse_openpgp_secret(gpg_keys["plain"]["armored"], "ignored")[0]["record"] == keys[0]["record"]


def test_openpgp_damaged_files(gpg_keys):
    armored = gpg_keys["rsa2048"]["armored"]
    lines = armored.split(b"\n")
    i = next(n for n, line in enumerate(lines) if len(line) > 60 and n > 3)
    lines[i] = lines[i][:10] + (b"A" if lines[i][10:11] != b"A" else b"B") + lines[i][11:]
    with pytest.raises(FormatError, match="checksum"):
        S.parse_openpgp_secret(b"\n".join(lines), PGP_PW)
    binary = gpg_keys["rsa2048"]["binary"]
    with pytest.raises(FormatError):
        S.parse_openpgp_secret(binary[:len(binary) // 2], PGP_PW)
    for junk in (b"", b"hello", b"-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----\n"):
        with pytest.raises(FormatError):
            S.parse_openpgp_secret(junk, PGP_PW)


def test_openpgp_parser_on_damaged_input(gpg_keys):
    """Cut or changed anywhere, a key file gives FormatError, nothing else
    (unprotected keys: the checks after the decryption run too)."""
    [blob] = S._pgp_binary(gpg_keys["plain"]["armored"])
    rnd = random.Random(7)
    outcomes = set()
    for i in range(400):
        b = bytearray(blob)
        if i % 2:
            b = b[:rnd.randrange(len(b))]
        else:
            for _ in range(rnd.randrange(1, 4)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
        try:
            S.parse_openpgp_secret(bytes(b))
            outcomes.add("parsed")
        except FormatError:
            outcomes.add("refused")
    assert "refused" in outcomes


def test_openpgp_public_key_is_refused(gpg_keys):
    g = Gpg()
    try:
        g.run("--import", stdin=gpg_keys["25519"]["armored"])
        pub = g.run("--armor", "--export", gpg_keys["25519"]["fpr"])
    finally:
        g.close()
    with pytest.raises(FormatError, match="no secret key"):
        S.parse_openpgp_secret(pub)


def test_openpgp_stub_and_unsupported_keys(gpg_keys):
    """A GnuPG stub (secret primary key removed) is listed as unsupported,
    its subkeys still come out; so does a key size the card lacks."""
    g = Gpg()
    try:
        g.run("--import", stdin=gpg_keys["25519"]["armored"])
        fpr = gpg_keys["25519"]["fpr"]
        subs = g.run("--export-secret-subkeys", fpr)
        keys = S.parse_openpgp_secret(subs, PGP_PW)
        assert keys[0]["record"] is None and "stub" in keys[0]["unsupported"] and keys[0]["primary"]
        assert all(k["record"] for k in keys[1:]) and len(keys) == 3
        fpr = g.make(("rsa1536", "sign,cert"), [], uid="Odd <odd@example.org>")
        [odd] = S.parse_openpgp_secret(g.run("--export-secret-keys", fpr), PGP_PW)
        assert odd["record"] is None and "RSA 1536" in odd["unsupported"] and odd["algorithm"] == "RSA 1536"
    finally:
        g.close()


def _pgp_mpi(b):
    b = b.lstrip(b"\0")
    return struct.pack(">H", len(b) * 8 - (8 - b[0].bit_length()) if b else 0) + b


def test_openpgp_aead_protection():
    """S2K usage 253 (RFC 9580 5.5.3): HKDF from the S2K output, AES-OCB with
    the packet type and public key as associated data."""
    from cryptography.hazmat.primitives.ciphers.aead import AESOCB3
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    k = ed25519.Ed25519PrivateKey.generate()
    raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    seed = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, NOENC)
    oid = bytes.fromhex("2b06010401da470f01")
    pub = b"\x04" + struct.pack(">I", 1700000000) + bytes([22, len(oid)]) + oid + \
        _pgp_mpi(b"\x40" + k.public_key().public_bytes(*raw))
    salt, count_byte = os.urandom(8), 0x10
    count = (16 + (count_byte & 15)) << ((count_byte >> 4) + 6)
    data = salt + PGP_PW.encode()
    stream = (data * (count // len(data) + 1))[:max(count, len(data))]
    s2k = hashlib.sha256(stream).digest()
    kek = HKDF(hashes.SHA256(), 32, None, bytes([0xC5, 4, 9, 2])).derive(s2k)
    iv = os.urandom(15)
    enc = AESOCB3(kek).encrypt(iv, _pgp_mpi(seed), b"\xc5" + pub)
    body = pub + bytes([253, 9, 2, 3, 8]) + salt + bytes([count_byte]) + iv + enc
    packet = b"\xc5\xff" + struct.pack(">I", len(body)) + body
    [key] = S.parse_openpgp_secret(packet, PGP_PW)
    assert key["record"][3][6] == seed.lstrip(b"\0").rjust(32, b"\0")
    assert key["record"][2] == bytes.fromhex("162b06010401da470f01") and key["usage"] == {"sig", "aut", "cert"}
    with pytest.raises(WrongPassphrase):
        S.parse_openpgp_secret(packet, "wrong")


def test_pgp_attribute_names():
    assert S.pgp_attr_name(bytes.fromhex("010800002000")) == "RSA 2048"
    assert S.pgp_attr_name(bytes.fromhex("132a8648ce3d030107")) == "ECDSA nistp256"
    assert S.pgp_attr_name(bytes.fromhex("122b060104019755010501ff")) == "ECDH cv25519"
    assert S.pgp_attr_name(bytes.fromhex("162b06010401da470f01")) == "EdDSA ed25519"
    assert S.pgp_attr_name(b"") == "none"
