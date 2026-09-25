"""Standard key formats for single-key transfer (docs/KEY_TRANSFER.md), pure
functions without a device: otpauth:// links and QR code images of them,
Google Authenticator export links (otpauth-migration://), PIV private keys
(PEM, DER, PKCS#12) and OpenPGP secret key files, read into the records of
the key transfer, and written back where a standard format exists.

Records are maps with integer keys, as the management applet encodes them:
OATH {1: name, 2: type|algorithm, 3: digits, 4: secret, 5: HOTP counter};
PIV {2: algorithm, 3: private key, 4/5: policies}; OpenPGP {2: algorithm
attributes, 3: private key, 4: fingerprint, 5: generation time}. Private
keys are RSA {1: e, 2: p, 3: q} or {6: private, 7: public} with the EC
scalar big endian (curve length), the Ed25519 seed, or the X25519 scalar in
its native (RFC 7748, little endian) byte order, the order the card keeps.
"""

import base64
import binascii
import hashlib
import re
import struct
import urllib.parse


class FormatError(Exception):
    """Input that is not (or not a supported kind of) the expected format."""


class PassphraseRequired(FormatError):
    """The key is protected: ask for its passphrase / password."""


class WrongPassphrase(FormatError):
    """The passphrase / password does not open the key."""


# ----------------------------------------------------------------------------
# OATH: otpauth:// and otpauth-migration://
# ----------------------------------------------------------------------------

OATH_HOTP, OATH_TOTP = 0x10, 0x20
OATH_ALGORITHMS = {"SHA1": 1, "SHA256": 2, "SHA512": 3}
OATH_ALGORITHM_NAMES = {v: k for k, v in OATH_ALGORITHMS.items()}
OATH_NAME_MAX = 64          # oath.c OATH_NAME_MAX
OATH_SECRET_MAX = 128       # oath.c OATH_SECRET_MAX
OATH_KEY_MIN = 14           # YKOATH clients pad shorter HMAC keys to this
DEFAULT_PERIOD = 30

# Google Authenticator MigrationPayload enums
_MIG_ALGORITHMS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
_MIG_DIGITS = {0: 6, 1: 6, 2: 8}
_MIG_TYPES = {0: OATH_TOTP, 1: OATH_HOTP, 2: OATH_TOTP}
# QR codes of one export: Google Authenticator puts about ten accounts in
# each, and a device holds a few hundred at most
MIGRATION_BATCHES_MAX = 1000


def _oath_key(secret, alg):
    """The secret as YKOATH clients store it: longer than the HMAC block, it
    is hashed (as HMAC itself would), shorter than OATH_KEY_MIN bytes it is
    padded with zeros (HMAC pads anyway): the codes stay the same."""
    name = OATH_ALGORITHM_NAMES[alg].lower()
    if len(secret) > (128 if alg == 3 else 64):
        secret = hashlib.new(name, secret).digest()
    return secret.ljust(OATH_KEY_MIN, b"\0")


_PERIOD_PREFIX = re.compile(r"\d+/")        # what split_ykoath_name reads as a period


def ykoath_name(account, issuer=None, period=DEFAULT_PERIOD, totp=True):
    """YKOATH credential name: [period/][issuer:]account. The period is
    written for TOTP other than 30 s, and for a 30 s TOTP name that would
    start with "<digits>/" ("30/12/alice"): every YKOATH reader would take
    that number for its period."""
    name = "%s:%s" % (issuer, account) if issuer else account
    if totp and (period != DEFAULT_PERIOD or _PERIOD_PREFIX.match(name)):
        name = "%d/%s" % (period, name)
    return name


def split_ykoath_name(name, totp=True):
    """(account, issuer or None, period) of a YKOATH name (text). A TOTP name
    that starts with "0/" has no period prefix (no period is 0 s: another
    tool stored the name without one): the whole name, the default period."""
    period = DEFAULT_PERIOD
    m = re.match(r"^(\d+)/(.+)$", name) if totp else None
    if m and int(m.group(1)) >= 1:
        period, name = int(m.group(1)), m.group(2)
    issuer, sep, account = name.partition(":")
    return (account, issuer, period) if sep else (name, None, period)


def _oath_record(kind, alg, digits, secret, name, counter=0):
    if not 6 <= digits <= 8:
        raise FormatError("%s: %d digits (the device shows 6 to 8)" % (name, digits))
    raw = name.encode("utf-8")
    if not 1 <= len(raw) <= OATH_NAME_MAX:
        raise FormatError("%s: the name has %d bytes (1 to %d)" % (name, len(raw), OATH_NAME_MAX))
    if not secret:
        raise FormatError("%s: no secret" % name)
    rec = {1: raw, 2: kind | alg, 3: digits, 4: _oath_key(secret, alg)}
    if len(rec[4]) > OATH_SECRET_MAX:
        raise FormatError("%s: secret of %d bytes (at most %d)" % (name, len(rec[4]), OATH_SECRET_MAX))
    if kind == OATH_HOTP:
        if not 0 <= counter < 1 << 64:
            raise FormatError("%s: HOTP counter out of range" % name)
        rec[5] = counter
    return rec


def _query(query):
    """Parameters of a URI query, names in lower case, values percent-decoded
    (RFC 3986: "+" is a plus sign, as base64 data needs it). The first of a
    repeated parameter counts."""
    out = {}
    for pair in query.split("&"):
        if pair:
            k, _, v = pair.partition("=")
            out.setdefault(urllib.parse.unquote(k).lower(), urllib.parse.unquote(v))
    return out


def _b32(text):
    s = re.sub(r"[\s-]", "", text).upper().rstrip("=")
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8))
    except (binascii.Error, ValueError):
        raise FormatError("the secret is not base32")


def _uint(text, what, lo=0, hi=None):
    try:
        v = int(text, 10)
    except (TypeError, ValueError):
        raise FormatError("%s %r is not a number" % (what, text))
    if v < lo or (hi is not None and v > hi):
        raise FormatError("%s %d out of range" % (what, v))
    return v


def parse_otpauth(uri, skip_unsupported=False):
    """OATH records of an otpauth:// link (one) or an otpauth-migration://
    link of Google Authenticator (all of its accounts; see parse_migration).
    Raises FormatError; with skip_unsupported, accounts of a migration link
    that the device cannot hold (MD5, 7 digits) are left out instead."""
    uri = uri.strip()
    scheme = uri.partition(":")[0].lower()
    if scheme == "otpauth-migration":
        return parse_migration(uri, skip_unsupported)[0]
    if scheme != "otpauth":
        raise FormatError("not an otpauth:// link")
    parts = urllib.parse.urlsplit(uri)
    kind = {"totp": OATH_TOTP, "hotp": OATH_HOTP}.get(parts.netloc.lower())
    if kind is None:
        raise FormatError("otpauth type %r (totp or hotp)" % parts.netloc)
    label = urllib.parse.unquote(parts.path[1:] if parts.path.startswith("/") else parts.path)
    issuer, sep, account = label.partition(":")
    if not sep:
        issuer, account = "", label
    account = account.strip()
    p = _query(parts.query)
    issuer = (p.get("issuer") or issuer).strip()
    if not account:
        raise FormatError("the otpauth link names no account")
    if "secret" not in p:
        raise FormatError("the otpauth link has no secret")
    alg = OATH_ALGORITHMS.get(p.get("algorithm", "SHA1").upper())
    if alg is None:
        raise FormatError("algorithm %r (SHA1, SHA256 or SHA512)" % p["algorithm"])
    digits = _uint(p.get("digits", "6"), "digits")
    period = _uint(p.get("period", str(DEFAULT_PERIOD)), "period", 1, 0xFFFFFFFF) if kind == OATH_TOTP \
        else DEFAULT_PERIOD
    counter = _uint(p.get("counter", "0"), "counter", 0, (1 << 64) - 1) if kind == OATH_HOTP else 0
    name = ykoath_name(account, issuer or None, period, kind == OATH_TOTP)
    return [_oath_record(kind, alg, digits, _b32(p["secret"]), name, counter)]


def _varint(buf, pos):
    v = shift = 0
    while True:
        if pos >= len(buf) or shift > 63:
            raise FormatError("malformed migration data")
        b = buf[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v & ((1 << 64) - 1), pos
        shift += 7


def _protobuf(buf):
    """{field number: [values]} of a protobuf message: varints and fixed
    fields as integers, length-delimited fields as bytes."""
    out, pos = {}, 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        field, wire = key >> 3, key & 7
        if wire == 0:
            v, pos = _varint(buf, pos)
        elif wire in (1, 5):
            n = 8 if wire == 1 else 4
            if pos + n > len(buf):
                raise FormatError("malformed migration data")
            v, pos = int.from_bytes(buf[pos:pos + n], "little"), pos + n
        elif wire == 2:
            n, pos = _varint(buf, pos)
            if pos + n > len(buf):
                raise FormatError("malformed migration data")
            v, pos = buf[pos:pos + n], pos + n
        else:
            raise FormatError("malformed migration data (wire type %d)" % wire)
        if field == 0:
            raise FormatError("malformed migration data")
        out.setdefault(field, []).append(v)
    return out


def _pb_last(msg, field, default, kind):
    """The last value of a field (protobuf: the last one counts), of kind
    int, bytes or str."""
    v = msg.get(field, [default])[-1]
    if kind is int:
        if not isinstance(v, int):
            raise FormatError("malformed migration data")
        return v
    if not isinstance(v, bytes):
        raise FormatError("malformed migration data")
    if kind is str:
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            raise FormatError("malformed migration data (text not UTF-8)")
    return v


def parse_migration(uri, skip_unsupported=False):
    """(records, batch) of a Google Authenticator export link
    otpauth-migration://offline?data=...: the OATH records of its accounts
    and batch = {"version", "batch_size", "batch_index", "batch_id"} (an
    export of many accounts is split over several QR codes, each a batch
    of the same batch_id; see missing_batches). Accounts the device cannot
    hold (MD5, 7 digits) raise FormatError, or with skip_unsupported are
    left out."""
    parts = urllib.parse.urlsplit(uri.strip())
    if parts.scheme.lower() != "otpauth-migration" or parts.netloc.lower() != "offline":
        raise FormatError("not an otpauth-migration://offline link")
    data = _query(parts.query).get("data")
    if not data:
        raise FormatError("the migration link has no data")
    # base64 whose "+" may have become a space, or in the URL-safe alphabet
    s = re.sub(r"\s", "+", data.strip()).replace("-", "+").replace("_", "/").rstrip("=")
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        raise FormatError("the migration data is not base64")
    msg = _protobuf(raw)
    batch = {"version": _pb_last(msg, 2, 0, int), "batch_size": _pb_last(msg, 3, 1, int),
             "batch_index": _pb_last(msg, 4, 0, int), "batch_id": _pb_last(msg, 5, 0, int)}
    # missing_batches lists the indexes up to batch_size: a link of a few
    # bytes must not be able to ask for billions of them
    if not 1 <= batch["batch_size"] <= MIGRATION_BATCHES_MAX or batch["batch_index"] >= batch["batch_size"]:
        raise FormatError("malformed migration data (QR code %d of %d)" % (batch["batch_index"] + 1,
                                                                           batch["batch_size"]))
    records, unsupported = [], []
    for entry in msg.get(1, []):
        if not isinstance(entry, bytes):
            raise FormatError("malformed migration data")
        e = _protobuf(entry)
        secret = _pb_last(e, 1, b"", bytes)
        label = _pb_last(e, 2, b"", str).strip()
        issuer = _pb_last(e, 3, b"", str).strip()
        alg = _MIG_ALGORITHMS.get(_pb_last(e, 4, 0, int))
        digits = _MIG_DIGITS.get(_pb_last(e, 5, 0, int))
        kind = _MIG_TYPES.get(_pb_last(e, 6, 0, int))
        counter = _pb_last(e, 7, 0, int)
        if counter >= 1 << 63:
            raise FormatError("%s: negative HOTP counter" % label)
        # the name may carry the issuer already ("issuer:account")
        account = label[len(issuer) + 1:].strip() if issuer and label.startswith(issuer + ":") else label
        why = None
        if alg not in OATH_ALGORITHMS:
            why = "algorithm %s" % (alg or "unknown")
        elif digits is None or kind is None:
            why = "unknown number of digits or type"
        if why:
            unsupported.append("%s (%s)" % (ykoath_name(account, issuer or None, totp=False), why))
            continue
        # (Google Authenticator exports TOTP accounts of 30 s only)
        records.append(_oath_record(kind, OATH_ALGORITHMS[alg], digits, secret,
                                    ykoath_name(account, issuer or None, totp=kind == OATH_TOTP), counter))
    if unsupported and not skip_unsupported:
        raise FormatError("accounts the device cannot hold: %s" % ", ".join(unsupported))
    return records, batch


def missing_batches(uris):
    """For the Google Authenticator export links among uris: {batch_id:
    [missing batch indexes]} of each export not complete in them."""
    seen = {}
    for uri in uris:
        if uri.strip().lower().startswith("otpauth-migration:"):
            b = parse_migration(uri, skip_unsupported=True)[1]
            size, idx = seen.setdefault(b["batch_id"], (b["batch_size"], set()))
            idx.add(b["batch_index"])
    return {bid: sorted(set(range(size)) - idx) for bid, (size, idx) in seen.items() if set(range(size)) - idx}


def oath_record_to_uri(record):
    """otpauth:// link of an OATH record (period and issuer from its YKOATH
    name). The secret is the stored one (zero padding included: the same
    codes)."""
    try:
        name = record[1].decode("utf-8")
    except UnicodeDecodeError:
        raise FormatError("the OATH name is not UTF-8 text")
    kind, alg = record[2] & 0xF0, record[2] & 0x0F
    if kind not in (OATH_TOTP, OATH_HOTP) or alg not in OATH_ALGORITHM_NAMES:
        raise FormatError("OATH type/algorithm %02X has no otpauth form" % record[2])
    account, issuer, period = split_ykoath_name(name, kind == OATH_TOTP)
    label = urllib.parse.quote(account, safe="@")
    if issuer:
        label = urllib.parse.quote(issuer, safe="") + ":" + label
    params = [("secret", base64.b32encode(record[4]).decode("ascii").rstrip("="))]
    if issuer:
        params.append(("issuer", issuer))
    params += [("algorithm", OATH_ALGORITHM_NAMES[alg]), ("digits", str(record[3]))]
    params.append(("period", str(period)) if kind == OATH_TOTP else ("counter", str(record.get(5, 0))))
    return "otpauth://%s/%s?%s" % ("totp" if kind == OATH_TOTP else "hotp", label,
                                   "&".join("%s=%s" % (k, urllib.parse.quote(v, safe="")) for k, v in params))


def decode_qr_image(path):
    """Texts of the QR codes in an image file (PNG, JPEG, ...), with OpenCV
    when it is installed, else zxing-cpp or pyzbar (each with Pillow).
    Raises FormatError when no decoder is installed (naming what to
    install), the image cannot be read or holds no QR code."""
    try:
        import cv2
    except ImportError:
        cv2 = None
    if cv2 is not None:
        texts = _qr_opencv(cv2, path)
    else:
        texts = _qr_pillow(path)
    if not texts:
        raise FormatError("no QR code found in %s" % path)
    return texts


def _qr_opencv(cv2, path):
    import numpy
    try:
        # (cv2.imread cannot open every path on Windows: non-ASCII names)
        with open(path, "rb") as f:
            img = cv2.imdecode(numpy.frombuffer(f.read(), dtype=numpy.uint8), cv2.IMREAD_COLOR)
    except OSError as e:
        raise FormatError("cannot read %s (%s)" % (path, e))
    if img is None:
        raise FormatError("%s is not an image OpenCV can read" % path)
    det = cv2.QRCodeDetector()
    texts = []
    try:
        ok, decoded, _, _ = det.detectAndDecodeMulti(img)
        texts = [t for t in decoded if t] if ok else []
    except cv2.error:
        pass
    if not texts:
        text, _, _ = det.detectAndDecode(img)
        texts = [text] if text else []
    return texts


def _qr_pillow(path):
    try:
        from PIL import Image
    except ImportError:
        Image = None
    decoders = []
    if Image is not None:
        try:
            import zxingcpp
            decoders.append(lambda img: [r.text for r in zxingcpp.read_barcodes(img)
                                         if "QR" in str(getattr(r, "format", "QR")) and r.text])
        except ImportError:
            pass
        try:
            from pyzbar import pyzbar
            decoders.append(lambda img: [s.data.decode("utf-8", "replace") for s in pyzbar.decode(img)
                                         if s.type == "QRCODE"])
        except ImportError:
            pass
    if not decoders:
        raise FormatError("reading QR code images needs OpenCV: pip install opencv-python-headless "
                          "(or zxing-cpp or pyzbar, each with Pillow)")
    try:
        with Image.open(path) as im:
            img = im.convert("RGB")
    except OSError as e:
        raise FormatError("cannot read the image %s (%s)" % (path, e))
    return decoders[0](img)


# ----------------------------------------------------------------------------
# PIV: PEM, DER, PKCS#12
# ----------------------------------------------------------------------------

PIV_RSA1024, PIV_RSA2048, PIV_RSA3072, PIV_RSA4096 = 0x06, 0x07, 0x05, 0x16
PIV_P256, PIV_P384, PIV_ED25519, PIV_X25519 = 0x11, 0x14, 0xE0, 0xE1
PIV_ALGORITHMS = {PIV_RSA1024: "RSA 1024", PIV_RSA2048: "RSA 2048", PIV_RSA3072: "RSA 3072",
                  PIV_RSA4096: "RSA 4096", PIV_P256: "ECC P-256", PIV_P384: "ECC P-384",
                  PIV_ED25519: "Ed25519", PIV_X25519: "X25519"}
PIV_RSA_BITS = {PIV_RSA1024: 1024, PIV_RSA2048: 2048, PIV_RSA3072: 3072, PIV_RSA4096: 4096}
PIV_EC_CURVES = {PIV_P256: ("secp256r1", 32), PIV_P384: ("secp384r1", 48)}
RSA_EXPONENT = 65537        # the only one the card uses (piv.c, cmd_import_data.c)


def _int_bytes(v, size=0):
    return v.to_bytes(max(size, (v.bit_length() + 7) // 8, 1), "big")


def _spki(public_key):
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _rsa_map(p, q, e, bits):
    half = bits // 16
    return {1: _int_bytes(e), 2: _int_bytes(p, half), 3: _int_bytes(q, half)}


def piv_record(key):
    """PIV record (without slot and policies) of a private key object of
    the cryptography package."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
    raw = (serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    if isinstance(key, rsa.RSAPrivateKey):
        nums = key.private_numbers()
        algo = {v: k for k, v in PIV_RSA_BITS.items()}.get(key.key_size)
        if algo is None:
            raise FormatError("RSA %d: PIV keys are RSA 1024, 2048, 3072 or 4096" % key.key_size)
        if nums.public_numbers.e != RSA_EXPONENT:
            raise FormatError("RSA public exponent %d: the device uses %d only" % (nums.public_numbers.e,
                                                                                  RSA_EXPONENT))
        return {2: algo, 3: _rsa_map(nums.p, nums.q, nums.public_numbers.e, key.key_size)}
    if isinstance(key, ec.EllipticCurvePrivateKey):
        algo = {c[0]: a for a, c in PIV_EC_CURVES.items()}.get(key.curve.name)
        if algo is None:
            raise FormatError("EC curve %s: PIV keys use P-256 or P-384" % key.curve.name)
        pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return {2: algo, 3: {6: _int_bytes(key.private_numbers().private_value, PIV_EC_CURVES[algo][1]), 7: pub}}
    for cls, algo in ((ed25519.Ed25519PrivateKey, PIV_ED25519), (x25519.X25519PrivateKey, PIV_X25519)):
        if isinstance(key, cls):
            pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return {2: algo, 3: {6: key.private_bytes(*raw), 7: pub}}
    raise FormatError("%s keys cannot go into PIV (RSA, P-256, P-384, Ed25519, X25519)" % type(key).__name__)


def piv_private_key(record):
    """Private key object (cryptography) of a PIV or OpenPGP-style record:
    algorithm record[2] (a PIV algorithm), key map record[3]. Checks that
    the key is complete and matches the public key the map carries."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
    algo, k = record.get(2), record.get(3)
    if not isinstance(k, dict):
        raise FormatError("no private key in the record")
    try:
        if algo in PIV_RSA_BITS:
            e, p, q = (int.from_bytes(k[i], "big") for i in (1, 2, 3))
            if p < 2 or q < 2 or p == q or e != RSA_EXPONENT:
                raise ValueError("bad RSA parameters")
            d = pow(e, -1, (p - 1) * (q - 1))
            key = rsa.RSAPrivateNumbers(p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q),
                                        rsa.rsa_crt_iqmp(p, q), rsa.RSAPublicNumbers(e, p * q)).private_key()
            if key.key_size != PIV_RSA_BITS[algo]:
                raise ValueError("RSA %d key for %s" % (key.key_size, PIV_ALGORITHMS[algo]))
            return key
        if algo in PIV_EC_CURVES:
            name, size = PIV_EC_CURVES[algo]
            if len(k[6]) != size:
                raise ValueError("EC scalar of %d bytes" % len(k[6]))
            curve = ec.SECP256R1() if name == "secp256r1" else ec.SECP384R1()
            key = ec.derive_private_key(int.from_bytes(k[6], "big"), curve)
            pub = key.public_key().public_bytes(serialization.Encoding.X962,
                                                serialization.PublicFormat.UncompressedPoint)
        elif algo in (PIV_ED25519, PIV_X25519):
            cls = ed25519.Ed25519PrivateKey if algo == PIV_ED25519 else x25519.X25519PrivateKey
            key = cls.from_private_bytes(k[6])
            pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        else:
            raise FormatError("unknown PIV algorithm %r" % (algo,))
    except (KeyError, TypeError, ValueError) as e:
        raise FormatError("invalid private key in the record (%s)" % e)
    if 7 in k and k[7] != pub:
        raise FormatError("the private key does not match its public key")
    return key


_PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.S)


def _load_private(loader, data, password, what):
    from cryptography.exceptions import UnsupportedAlgorithm
    try:
        return loader(data, password)
    except TypeError:
        if password is None:
            raise PassphraseRequired("the %s is encrypted: give its password" % what)
        return loader(data, None)       # not encrypted: the password is not needed
    except ValueError as e:
        if password is not None and ("decrypt" in str(e).lower() or "password" in str(e).lower()):
            raise WrongPassphrase("wrong password for the %s" % what)
        raise FormatError("unreadable %s (%s)" % (what, e))
    except UnsupportedAlgorithm as e:
        raise FormatError("unsupported %s (%s)" % (what, e))


def _is_pkcs12(data):
    """A DER SEQUENCE starting with INTEGER 3: a PFX (RFC 7292)."""
    if len(data) < 8 or data[0] != 0x30:
        return False
    n = data[1]
    pos = 2 + (n & 0x7F if n & 0x80 else 0)
    return data[pos:pos + 3] == b"\x02\x01\x03"


def load_piv_key(data, password=None):
    """PIV keys of a file: [(record without slot, certificate DER or
    None)], the certificate being the one of the file that belongs to the
    key. Takes PEM (PKCS#8, traditional RSA / EC, encrypted, with
    certificates), DER (PKCS#8 or traditional) and PKCS#12. password
    (bytes or text) opens an encrypted key; PassphraseRequired /
    WrongPassphrase otherwise."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    data = bytes(data)
    if isinstance(password, str):
        password = password.encode("utf-8")
    keys, certs = [], []
    if b"-----BEGIN" in data:
        for m in _PEM.finditer(data):
            label = m.group(1).decode("ascii")
            if label.endswith("PRIVATE KEY"):
                if label == "OPENSSH PRIVATE KEY":
                    raise FormatError("OpenSSH private keys are not read: convert it with "
                                      "ssh-keygen -p -m PKCS8 -f FILE")
                keys.append(_load_private(serialization.load_pem_private_key, m.group(0), password,
                                          "private key"))
            elif label in ("CERTIFICATE", "X509 CERTIFICATE"):
                try:
                    certs.append(x509.load_pem_x509_certificate(m.group(0)))
                except ValueError as e:
                    raise FormatError("unreadable certificate (%s)" % e)
    elif _is_pkcs12(data):
        loaded = None
        for pw in ([password] if password is not None else [None, b""]):
            try:
                loaded = pkcs12.load_key_and_certificates(data, pw)
                break
            except ValueError:
                continue
        if loaded is None:
            if password is None:
                raise PassphraseRequired("the PKCS#12 file is protected: give its password")
            raise WrongPassphrase("wrong password for the PKCS#12 file (or it is damaged)")
        if loaded[0] is not None:
            keys.append(loaded[0])
        certs = [c for c in [loaded[1]] + list(loaded[2] or []) if c is not None]
    else:
        keys.append(_load_private(serialization.load_der_private_key, data, password, "private key"))
    if not keys:
        raise FormatError("no private key in the file")
    out = []
    for key in keys:
        rec = piv_record(key)
        pub = _spki(key.public_key())
        cert = next((c for c in certs if _spki(c.public_key()) == pub), None)
        out.append((rec, cert.public_bytes(serialization.Encoding.DER) if cert is not None else None))
    return out


def piv_record_to_pem(record, passphrase):
    """PEM of a PIV record: the private key as PKCS#8, encrypted with
    passphrase (None: in the clear, which must be the user's explicit choice;
    an empty passphrase is refused), then the certificate (record key 8)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    if passphrase is not None and len(passphrase) == 0:
        raise FormatError("empty passphrase (a key in the clear must be asked for explicitly)")
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    enc = serialization.NoEncryption() if passphrase is None else \
        serialization.BestAvailableEncryption(passphrase)
    out = piv_private_key(record).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    if record.get(8):
        try:
            out += x509.load_der_x509_certificate(record[8]).public_bytes(serialization.Encoding.PEM)
        except ValueError as e:
            raise FormatError("unreadable certificate in the record (%s)" % e)
    return out


# ----------------------------------------------------------------------------
# OpenPGP secret keys (RFC 4880 / RFC 9580, version 4 keys)
# ----------------------------------------------------------------------------

PGP_RSA, PGP_RSA_E, PGP_RSA_S = 1, 2, 3
PGP_ELGAMAL_E, PGP_DSA, PGP_ECDH, PGP_ECDSA, PGP_ELGAMAL, PGP_EDDSA = 16, 17, 18, 19, 20, 22
PGP_X25519, PGP_X448, PGP_ED25519, PGP_ED448 = 25, 26, 27, 28
PGP_KEY_REFS = {"sig": 1, "dec": 2, "aut": 3}

# Card algorithm ids (OpenPGP card 3.4, 4.4.3.9; openpgp.h ALGO_*)
CARD_RSA, CARD_ECDH, CARD_ECDSA, CARD_EDDSA = 0x01, 0x12, 0x13, 0x16
_CARD_ALG_NAMES = {CARD_RSA: "RSA", CARD_ECDH: "ECDH", CARD_ECDSA: "ECDSA", CARD_EDDSA: "EdDSA"}

# Curve OIDs (DER value) -> (name, cryptography curve class). The card's own
# OIDs of Ed25519 / Curve25519 are the first of each (do.c).
_PGP_CURVES = {
    "2a8648ce3d030107": ("nistp256", "SECP256R1"),
    "2b81040022": ("nistp384", "SECP384R1"),
    "2b81040023": ("nistp521", "SECP521R1"),
    "2b8104000a": ("secp256k1", "SECP256K1"),
    "2b2403030208010107": ("brainpoolP256r1", "BrainpoolP256R1"),
    "2b240303020801010b": ("brainpoolP384r1", "BrainpoolP384R1"),
    "2b240303020801010d": ("brainpoolP512r1", "BrainpoolP512R1"),
    "2b06010401da470f01": ("ed25519", None),
    "2b6570": ("ed25519", None),
    "2b060104019755010501": ("cv25519", None),
    "2b656e": ("cv25519", None),
}
_CARD_OID = {"ed25519": bytes.fromhex("2b06010401da470f01"), "cv25519": bytes.fromhex("2b060104019755010501")}

_PGP_HASHES = {1: "md5", 2: "sha1", 3: "ripemd160", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224",
               12: "sha3_256", 14: "sha3_512"}
_PGP_AES = {7: 16, 8: 24, 9: 32}                # key sizes of AES-128/192/256
_PGP_AEAD_IV = {2: 15, 3: 12}                   # OCB, GCM


def pgp_attr_name(attr):
    """Readable name of card algorithm attributes (DO C1..C3 value)."""
    attr = bytes(attr)
    if not attr:
        return "none"
    if attr[0] == CARD_RSA and len(attr) >= 3:
        return "RSA %d" % int.from_bytes(attr[1:3], "big")
    oid = attr[1:-1] if attr[-1:] == b"\xff" else attr[1:]
    name = _PGP_CURVES.get(oid.hex(), ("curve %s" % oid.hex(),))[0]
    return "%s %s" % (_CARD_ALG_NAMES.get(attr[0], "algorithm %d" % attr[0]), name)


class _Unsupported(Exception):
    """A key of the file that cannot go onto the card (the others can)."""


def _crc24(data):
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


_ARMOR = re.compile(rb"-----BEGIN PGP (PRIVATE|SECRET|PUBLIC) KEY BLOCK-----[^\n]*\n(.*?)"
                    rb"-----END PGP \1 KEY BLOCK-----", re.S)


def _pgp_binary(data):
    """The binary packet streams of an armored or binary key file."""
    data = bytes(data)
    if data[:1] and data[0] & 0x80:
        return [data]
    blocks = []
    for _, text in _ARMOR.findall(data):
        lines = [line.strip() for line in text.replace(b"\r", b"").split(b"\n")]
        if b"" in lines:                # armor headers ("Key: value") end with an empty line
            i = lines.index(b"")
            if all(b": " in line for line in lines[:i]):
                lines = lines[i + 1:]
        lines = [line for line in lines if line]
        crc = None
        if lines and lines[-1].startswith(b"=") and len(lines[-1]) == 5:
            crc = lines.pop()[1:]
        try:
            raw = base64.b64decode(b"".join(lines), validate=True)
            if crc is not None and _crc24(raw) != int.from_bytes(base64.b64decode(crc, validate=True), "big"):
                raise FormatError("OpenPGP armor checksum mismatch: the file is damaged")
        except (binascii.Error, ValueError):
            raise FormatError("malformed OpenPGP armor")
        blocks.append(raw)
    if not blocks:
        raise FormatError("not an OpenPGP key file")
    return blocks


def _pgp_packets(data):
    """(tag, body) of each packet (old and new format headers)."""
    pos = 0
    try:
        while pos < len(data):
            hdr = data[pos]
            if not hdr & 0x80:
                raise FormatError("not an OpenPGP packet stream")
            if hdr & 0x40:
                tag, first = hdr & 0x3F, data[pos + 1]
                if first < 192:
                    length, pos = first, pos + 2
                elif first < 224:
                    length, pos = ((first - 192) << 8) + data[pos + 2] + 192, pos + 3
                elif first == 255:
                    length, pos = int.from_bytes(data[pos + 2:pos + 6], "big"), pos + 6
                else:
                    raise FormatError("partial packet lengths in a key file")
            else:
                tag, lt = (hdr >> 2) & 0x0F, hdr & 3
                if lt == 3:
                    length, pos = len(data) - pos - 1, pos + 1
                else:
                    n = 1 << lt
                    length, pos = int.from_bytes(data[pos + 1:pos + 1 + n], "big"), pos + 1 + n
            body = data[pos:pos + length]
            if len(body) != length:
                raise FormatError("truncated OpenPGP packet")
            pos += length
            yield tag, body
    except IndexError:
        raise FormatError("truncated OpenPGP packet")


def _mpi(buf, pos):
    if pos + 2 > len(buf):
        raise FormatError("truncated OpenPGP key")
    n = (struct.unpack_from(">H", buf, pos)[0] + 7) // 8
    v = buf[pos + 2:pos + 2 + n]
    if len(v) != n:
        raise FormatError("truncated OpenPGP key")
    return v, pos + 2 + n


def _pgp_subpackets(area):
    """(type, data) of the subpackets of a signature area."""
    pos = 0
    while pos < len(area):
        first = area[pos]
        if first < 192:
            n, pos = first, pos + 1
        elif first < 255:
            if pos + 1 >= len(area):
                break
            n, pos = ((first - 192) << 8) + area[pos + 1] + 192, pos + 2
        else:
            n, pos = int.from_bytes(area[pos + 1:pos + 5], "big"), pos + 5
        if n < 1 or pos + n > len(area):
            break
        yield area[pos] & 0x7F, area[pos + 1:pos + n]
        pos += n


def _pgp_signature(body):
    """(signature type, creation time, key flags or None, issuers) of a v4
    (or v5) signature; None for others (they carry no key flags)."""
    if len(body) < 6 or body[0] not in (4, 5):
        return None
    sigtype = body[1]
    n = struct.unpack_from(">H", body, 4)[0]
    hashed = body[6:6 + n]
    pos = 6 + n
    unhashed = b""
    if pos + 2 <= len(body):
        m = struct.unpack_from(">H", body, pos)[0]
        unhashed = body[pos + 2:pos + 2 + m]
    created, flags, issuers = 0, None, set()
    for t, d in _pgp_subpackets(hashed):
        if t == 2 and len(d) == 4:
            created = int.from_bytes(d, "big")
        elif t == 27:
            flags = d[0] if d else 0
        elif t == 16:
            issuers.add(d)
        elif t == 33 and len(d) > 1:
            issuers.add(d[1:])
    for t, d in _pgp_subpackets(unhashed):       # only who issued it, never what it says
        if t == 16:
            issuers.add(d)
        elif t == 33 and len(d) > 1:
            issuers.add(d[1:])
    return sigtype, created, flags, issuers


class _PgpKey:
    def __init__(self, tag, body, primary):
        self.tag, self.body, self.primary = tag, body, primary
        self.user_ids = primary.user_ids if primary else []
        self.flags = None               # (creation time of the self-signature, key flags)
        self.revoked = False
        self.fingerprint = self.secret = None
        self.created, self.algo, self.pub, self.unsupported = 0, 0, {}, None
        try:
            self._parse_public()
        except _Unsupported as e:
            self.unsupported = str(e)

    def _parse_public(self):
        b = self.body
        if len(b) < 6:
            raise FormatError("truncated OpenPGP key")
        if b[0] != 4:
            raise _Unsupported("version %d key (the card holds version 4 keys)" % b[0])
        self.created, self.algo = struct.unpack_from(">I", b, 1)[0], b[5]
        pos, pub = 6, self.pub
        if self.algo in (PGP_RSA, PGP_RSA_E, PGP_RSA_S):
            pub["n"], pos = _mpi(b, pos)
            pub["e"], pos = _mpi(b, pos)
        elif self.algo in (PGP_DSA, PGP_ELGAMAL_E, PGP_ELGAMAL):
            for _ in range(4 if self.algo == PGP_DSA else 3):
                _, pos = _mpi(b, pos)
        elif self.algo in (PGP_ECDH, PGP_ECDSA, PGP_EDDSA):
            n = b[pos] if pos < len(b) else 0
            if n in (0, 0xFF) or pos + 1 + n > len(b):
                raise FormatError("malformed OpenPGP curve")
            pub["oid"], pos = b[pos + 1:pos + 1 + n], pos + 1 + n
            pub["q"], pos = _mpi(b, pos)
            if self.algo == PGP_ECDH:
                n = b[pos] if pos < len(b) else 0
                if pos + 1 + n > len(b):
                    raise FormatError("truncated OpenPGP key")
                pos += 1 + n
        elif self.algo in (PGP_X25519, PGP_X448, PGP_ED25519, PGP_ED448):
            n = {PGP_X25519: 32, PGP_X448: 56, PGP_ED25519: 32, PGP_ED448: 57}[self.algo]
            pub["q"], pos = b[pos:pos + n], pos + n
            if len(pub["q"]) != n:
                raise FormatError("truncated OpenPGP key")
        else:
            raise _Unsupported("public key algorithm %d" % self.algo)
        self.fingerprint = hashlib.sha1(b"\x99" + struct.pack(">H", pos) + b[:pos]).digest()
        self.pub_len = pos
        if self.tag in (5, 7):
            self.secret = b[pos:]

    @property
    def key_id(self):
        return self.fingerprint[-8:] if self.fingerprint else None

    def algorithm_name(self):
        if self.algo in (PGP_RSA, PGP_RSA_E, PGP_RSA_S) and "n" in self.pub:
            return "RSA %d" % int.from_bytes(self.pub["n"], "big").bit_length()
        if "oid" in self.pub:
            curve = _PGP_CURVES.get(self.pub["oid"].hex(), ("curve %s" % self.pub["oid"].hex(),))[0]
            return "%s %s" % ({PGP_ECDH: "ECDH", PGP_ECDSA: "ECDSA", PGP_EDDSA: "EdDSA"}[self.algo], curve)
        return {PGP_X25519: "X25519", PGP_X448: "X448", PGP_ED25519: "Ed25519", PGP_ED448: "Ed448",
                PGP_DSA: "DSA", PGP_ELGAMAL_E: "ElGamal", PGP_ELGAMAL: "ElGamal"}.get(self.algo,
                                                                                     "algorithm %d" % self.algo)

    def usage(self):
        if self.flags is not None:
            f = self.flags[1]
            use = {name for bit, name in ((0x01, "cert"), (0x02, "sig"), (0x04, "dec"), (0x08, "dec"),
                                          (0x20, "aut")) if f & bit}
        elif self.algo in (PGP_RSA,):
            use = {"sig", "dec", "aut"}
        elif self.algo in (PGP_RSA_E, PGP_ECDH, PGP_X25519, PGP_X448, PGP_ELGAMAL_E):
            use = {"dec"}
        else:
            use = {"sig", "aut"}
        if self.primary is None and self.flags is None:
            use.add("cert")
        return use

    def self_signed(self, issuers):
        top = self.primary or self
        return not issuers or top.key_id in issuers or top.fingerprint in issuers


def _pgp_apply_signature(target, body):
    sig = _pgp_signature(body)
    if sig is None:
        return
    sigtype, created, flags, issuers = sig
    kind, key = target
    if not key.self_signed(issuers):
        return                          # a certification by someone else
    if (kind == "subkey" and sigtype == 0x18) or (kind == "primary" and sigtype == 0x1F) or \
            (kind == "uid" and 0x10 <= sigtype <= 0x13):
        if flags is not None and (key.flags is None or created >= key.flags[0]):
            key.flags = (created, flags)
    elif (kind == "subkey" and sigtype == 0x28) or (kind == "primary" and sigtype == 0x20):
        key.revoked = True


def _s2k(buf, pos):
    """(S2K specifier, position after it)."""
    try:
        t = buf[pos]
        if t == 0:
            return ("simple", buf[pos + 1], b"", 0), pos + 2
        if t == 1:
            return ("salted", buf[pos + 1], buf[pos + 2:pos + 10], 0), pos + 10
        if t == 3:
            c = buf[pos + 10]
            return ("iterated", buf[pos + 1], buf[pos + 2:pos + 10], (16 + (c & 15)) << ((c >> 4) + 6)), pos + 11
        if t == 101 and buf[pos + 2:pos + 5] == b"GNU":
            return ("gnu", buf[pos + 5], b"", 0), len(buf)
    except IndexError:
        raise FormatError("truncated OpenPGP key protection")
    raise _Unsupported("key protection with S2K specifier %d" % t)


def _s2k_key(spec, passphrase, size):
    kind, halg, salt, count = spec
    name = _PGP_HASHES.get(halg)
    if name is None or name not in hashlib.algorithms_available:
        raise _Unsupported("key protection with hash algorithm %d" % halg)
    data = salt + passphrase
    out, i = b"", 0
    while len(out) < size:
        h = hashlib.new(name)
        h.update(b"\0" * i)
        if kind == "iterated":
            total = max(count, len(data))
            block = data * (1 + 65536 // max(len(data), 1))     # whole repetitions of data
            while total >= len(block):
                h.update(block)
                total -= len(block)
            h.update(block[:total])
        else:
            h.update(data)
        out += h.digest()
        i += 1
    return out[:size]


def _pgp_decrypt(key, passphrase):
    """The secret key material (MPIs, or the native 25519 key) of key, its
    protection removed and its checksum verified."""
    sec = key.secret
    if not sec:
        raise FormatError("truncated OpenPGP secret key")
    usage, pos = sec[0], 1
    if usage == 0:
        plain, check = sec[1:], "sum"
    elif usage in (253, 254, 255):
        if pos >= len(sec):
            raise FormatError("truncated OpenPGP secret key")
        sym, pos = sec[pos], pos + 1
        aead = None
        if usage == 253:
            aead, pos = sec[pos], pos + 1
        spec, pos = _s2k(sec, pos)
        if spec[0] == "gnu":
            raise _Unsupported("no secret key in the file (a GnuPG stub: the key is offline or on a card)")
        size = _PGP_AES.get(sym)
        if size is None:
            raise _Unsupported("key protection with cipher %d (AES is supported)" % sym)
        ivlen = 16 if usage != 253 else _PGP_AEAD_IV.get(aead)
        if ivlen is None:
            raise _Unsupported("key protection with AEAD mode %d (OCB and GCM are supported)" % aead)
        iv, enc = sec[pos:pos + ivlen], sec[pos + ivlen:]
        if len(iv) != ivlen or not enc:
            raise FormatError("truncated OpenPGP secret key")
        if passphrase is None:
            raise PassphraseRequired("the OpenPGP secret key is protected: give its passphrase")
        s2k = _s2k_key(spec, passphrase if isinstance(passphrase, bytes) else passphrase.encode("utf-8"), size)
        if usage == 253:
            plain, check = _pgp_aead(key, sym, aead, s2k, iv, enc), None
        else:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
            try:
                from cryptography.hazmat.decrepit.ciphers.modes import CFB
            except ImportError:             # cryptography before CFB moved there
                from cryptography.hazmat.primitives.ciphers.modes import CFB
            d = Cipher(algorithms.AES(s2k), CFB(iv)).decryptor()
            plain, check = d.update(enc) + d.finalize(), "sha1" if usage == 254 else "sum"
    else:
        raise _Unsupported("legacy key protection (re-export the key with a current GnuPG)")
    if check == "sha1":
        plain, digest = plain[:-20], plain[-20:]
        ok = len(digest) == 20 and hashlib.sha1(plain).digest() == digest
    elif check == "sum":
        plain, digest = plain[:-2], plain[-2:]
        ok = len(digest) == 2 and sum(plain) & 0xFFFF == int.from_bytes(digest, "big")
    else:
        ok = True
    if not ok:
        if usage == 0:
            raise FormatError("the OpenPGP secret key is damaged (checksum mismatch)")
        raise WrongPassphrase("wrong passphrase for the OpenPGP secret key")
    return plain


def _pgp_aead(key, sym, aead, s2k, iv, enc):
    """RFC 9580 5.5.3: the key encryption key from the S2K output by HKDF,
    the packet type and public key as associated data."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESOCB3
    except ImportError:
        raise _Unsupported("key protection with AEAD (needs a newer cryptography package)")
    ptag = 0xC0 | key.tag
    kek = HKDF(hashes.SHA256(), len(s2k), None, bytes([ptag, 4, sym, aead])).derive(s2k)
    try:
        return (AESOCB3 if aead == 2 else AESGCM)(kek).decrypt(iv, enc, bytes([ptag]) + key.body[:key.pub_len])
    except InvalidTag:
        raise WrongPassphrase("wrong passphrase for the OpenPGP secret key")


def _pgp_record(key, plain):
    """Card record (without key reference) of a decrypted key: algorithm
    attributes, private key map, fingerprint, generation time. The private
    key is checked against the public one."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
    algo, pub = key.algo, key.pub
    if algo in (PGP_RSA, PGP_RSA_E, PGP_RSA_S):
        pos = 0
        vals = []
        for _ in range(4):              # d, p, q, u
            v, pos = _mpi(plain, pos)
            vals.append(int.from_bytes(v, "big"))
        n, e = int.from_bytes(pub["n"], "big"), int.from_bytes(pub["e"], "big")
        p, q = vals[1], vals[2]
        if pos != len(plain) or p * q != n:
            raise FormatError("the RSA secret key does not match its public key")
        bits = n.bit_length()
        if bits not in (1024, 2048, 3072, 4096):
            raise _Unsupported("RSA %d (the card takes 1024, 2048, 3072 and 4096 bits)" % bits)
        if e != RSA_EXPONENT:
            raise _Unsupported("RSA public exponent %d (the card uses %d)" % (e, RSA_EXPONENT))
        attr = bytes([CARD_RSA]) + bits.to_bytes(2, "big") + b"\x00\x20\x00"
        priv = _rsa_map(p, q, e, bits)
    else:
        raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if algo in (PGP_X25519, PGP_ED25519):
            if len(plain) != 32:
                raise FormatError("malformed OpenPGP secret key")
            secret, curve, q = plain, "cv25519" if algo == PGP_X25519 else "ed25519", pub["q"]
        elif algo in (PGP_ECDH, PGP_ECDSA, PGP_EDDSA):
            s, pos = _mpi(plain, 0)
            if pos != len(plain):
                raise FormatError("malformed OpenPGP secret key")
            curve, cls = _PGP_CURVES.get(pub["oid"].hex(), (None, None))
            if curve is None:
                raise _Unsupported("curve %s" % pub["oid"].hex())
            q = pub["q"]
            if curve in ("ed25519", "cv25519"):
                if len(s) > 32 or q[:1] != b"\x40":
                    raise FormatError("malformed %s key" % curve)
                q = q[1:]
                # GnuPG keeps the Curve25519 scalar as an MPI: big endian, the
                # native order reversed. The card keeps it native.
                secret = s.rjust(32, b"\0")[::-1] if curve == "cv25519" else s.rjust(32, b"\0")
            else:
                secret = s
        else:
            raise _Unsupported("%s keys cannot go onto the card" % key.algorithm_name())
        want = {PGP_ECDH: ("cv25519", CARD_ECDH), PGP_X25519: ("cv25519", CARD_ECDH),
                PGP_EDDSA: ("ed25519", CARD_EDDSA), PGP_ED25519: ("ed25519", CARD_EDDSA)}.get(algo)
        if curve in ("ed25519", "cv25519"):
            if want is None or want[0] != curve:
                raise _Unsupported("%s on %s" % (key.algorithm_name(), curve))
            k = (x25519.X25519PrivateKey if curve == "cv25519" else ed25519.Ed25519PrivateKey).from_private_bytes(
                secret)
            if k.public_key().public_bytes(*raw) != q:
                raise FormatError("the %s secret key does not match its public key" % curve)
            attr = bytes([want[1]]) + _CARD_OID[curve]
        else:
            if algo == PGP_EDDSA:
                raise _Unsupported("EdDSA on %s" % curve)
            ec_curve = getattr(ec, cls)()
            size = (ec_curve.key_size + 7) // 8
            try:
                k = ec.derive_private_key(int.from_bytes(secret, "big"), ec_curve)
            except ValueError:
                raise FormatError("invalid %s secret key" % curve)
            if k.public_key().public_bytes(serialization.Encoding.X962,
                                           serialization.PublicFormat.UncompressedPoint) != q:
                raise FormatError("the %s secret key does not match its public key" % curve)
            secret = secret.rjust(size, b"\0")
            attr = bytes([CARD_ECDH if algo == PGP_ECDH else CARD_ECDSA]) + pub["oid"]
        priv = {6: secret, 7: q}
    return {2: attr, 3: priv, 4: key.fingerprint, 5: key.created}


def parse_openpgp_secret(data, passphrase=None):
    """The secret keys of an OpenPGP key file (armored or binary, as `gpg
    --export-secret-keys` writes it), in file order: dicts with
    record (the card record without key reference, None when the key cannot
    go onto the card), usage (subset of {"sig", "dec", "aut", "cert"}, from
    the key flags of the self-signatures), fingerprint (v4, 20 bytes),
    key_id (hex), created (unix time), user_ids, primary (bool), algorithm
    (text), revoked (bool), unsupported (None or why record is None).
    passphrase opens protected keys (PassphraseRequired / WrongPassphrase)."""
    keys, primary, target = [], None, None
    for blob in _pgp_binary(data):
        for tag, body in _pgp_packets(blob):
            if tag in (5, 6):
                primary = _PgpKey(tag, body, None)
                keys.append(primary)
                target = ("primary", primary)
            elif tag in (7, 14):
                if primary is None:
                    raise FormatError("OpenPGP subkey without a primary key")
                k = _PgpKey(tag, body, primary)
                keys.append(k)
                target = ("subkey", k)
            elif tag == 13 and primary is not None:
                primary.user_ids.append(body.decode("utf-8", "replace"))
                target = ("uid", primary)
            elif tag == 17 and primary is not None:
                target = ("uid", primary)           # user attribute: certified like a user ID
            elif tag == 2 and target is not None:
                _pgp_apply_signature(target, body)
    out = []
    for k in keys:
        if k.tag not in (5, 7):
            continue
        record, why = None, k.unsupported
        if why is None:
            try:
                record = _pgp_record(k, _pgp_decrypt(k, passphrase))
            except _Unsupported as e:
                why = str(e)
            except IndexError:
                raise FormatError("truncated OpenPGP secret key")
        out.append({"record": record, "usage": k.usage(), "fingerprint": k.fingerprint,
                    "key_id": k.key_id.hex().upper() if k.key_id else None, "created": k.created,
                    "user_ids": list(k.user_ids), "primary": k.primary is None,
                    "algorithm": k.algorithm_name(), "revoked": k.revoked, "unsupported": why})
    if not out:
        raise FormatError("no secret key in the file (a public key?)")
    return out


__all__ = ["FormatError", "PassphraseRequired", "WrongPassphrase", "parse_otpauth", "parse_migration",
           "missing_batches", "oath_record_to_uri", "decode_qr_image", "load_piv_key", "piv_record",
           "piv_private_key", "piv_record_to_pem", "parse_openpgp_secret", "pgp_attr_name", "ykoath_name",
           "split_ykoath_name"]
