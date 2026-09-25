"""OpenPGP application of the device for the key manager (OpenPGP card 3.4,
pico-openpgp/src/openpgp): status, key generation on the card, PINs, Reset
Code, touch policies (UIF), cardholder name, deleting a key and resetting the
application.

A key generated here gets what GnuPG gives a key it generates on a card: its
OpenPGP v4 fingerprint, computed from the card's public key and the
generation time (with GnuPG's KDF parameters for ECDH keys), and the
generation time are written to the card (DOs C7-C9 and CE-D0), so that `gpg
--card-status` shows them and a key GnuPG makes from the card key at that
time ("Existing key from card") has the same fingerprint.

PINs go to the card as typed (UTF-8), or through the card's KDF when its
KDF-DO asks for one (KDF_ITERSALTED_S2K, as GnuPG sends them). Nothing here
keeps a PIN: each operation takes the one it needs, and the Admin PIN
session ends with the operation (VERIFY FF, and the management applet
selected again).
"""

import hashlib
import struct
import time
from contextlib import contextmanager

from smartcard.Exceptions import CardConnectionException

from . import stdformats
from .mgmt import display_name
from .mgr_common import (AuthRequired, ManagerError, NotSupported, SecretBlocked, WrongSecret, applet, parse_tlvs,
                         send, sw_error, sw_text, wipe)

OPENPGP_AID = bytes.fromhex("D27600012401")

KEY_REFS = {"sig": 1, "dec": 2, "aut": 3}
KEY_NAMES = {1: "sig", 2: "dec", 3: "aut"}
KEY_LABELS = {"sig": ("Signature key", "签名密钥"), "dec": ("Encryption key", "加密密钥"),
              "aut": ("Authentication key", "认证密钥")}

INS_VERIFY, INS_CHANGE_REFERENCE, INS_RESET_RETRY = 0x20, 0x24, 0x2C
INS_GET_DATA, INS_PUT_DATA, INS_GENERATE = 0xCA, 0xDA, 0x47
INS_TERMINATE, INS_ACTIVATE = 0xE6, 0x44
PW1, PW3 = 0x81, 0x83
RC = "rc"                   # the Reset Code (no VERIFY reference of its own)

_CRT = {1: 0xB6, 2: 0xB8, 3: 0xA4}          # control reference templates of the keys
_DO_ALGO, _DO_FP, _DO_TIME, _DO_UIF = 0xC0, 0xC6, 0xCD, 0xD5      # + key reference
DO_AID, DO_NAME, DO_URL, DO_APP_DATA, DO_CH_DATA = 0x4F, 0x5B, 0x5F50, 0x6E, 0x65
DO_SEC_TPL, DO_SIG_COUNT, DO_PW_STATUS, DO_FPS, DO_TIMES = 0x7A, 0x93, 0xC4, 0xC5, 0xCD
DO_RESET_CODE, DO_KEY_INFO, DO_KDF, DO_ALGO_INFO = 0xD3, 0xDE, 0xF9, 0xFA

PW1_MIN, PW3_MIN, RC_MIN, PW_MAX = 6, 8, 8, 127     # cmd_change_pin.c, cmd_put_data.c
NAME_MAX = 39                                       # cmd_put_data.c do_len_ok

# Card algorithm ids (OpenPGP card 3.4, 4.4.3.9) and OpenPGP public key
# algorithms (RFC 4880 9.1, RFC 6637, RFC 9580 legacy EdDSA).
CARD_RSA, CARD_ECDH, CARD_ECDSA, CARD_EDDSA = 0x01, 0x12, 0x13, 0x16
_PGP_ALGO = {CARD_RSA: 1, CARD_ECDH: 18, CARD_ECDSA: 19, CARD_EDDSA: 22}

# Curves the card offers: name -> (OID, cryptography curve, KDF hash and
# cipher of an ECDH key). The KDF parameters are GnuPG's for a key it makes
# (pk_ecdh_default_params, g10/ecdh.c: SHA-256 / AES-128 up to 256 bits,
# SHA-384 / AES-256 up to 384, SHA-512 / AES-256 above); they are part of
# the public key packet, and so of the fingerprint.
_KDF_256, _KDF_384, _KDF_512 = (8, 7), (9, 9), (10, 9)
_CURVES = {
    "nistp256": ("2a8648ce3d030107", "SECP256R1", _KDF_256),
    "nistp384": ("2b81040022", "SECP384R1", _KDF_384),
    "nistp521": ("2b81040023", "SECP521R1", _KDF_512),
    "brainpoolP256r1": ("2b2403030208010107", "BrainpoolP256R1", _KDF_256),
    "brainpoolP384r1": ("2b240303020801010b", "BrainpoolP384R1", _KDF_384),
    "brainpoolP512r1": ("2b240303020801010d", "BrainpoolP512R1", _KDF_512),
    "secp256k1": ("2b8104000a", "SECP256K1", _KDF_256),
    "ed25519": ("2b06010401da470f01", None, None),
    "cv25519": ("2b060104019755010501", None, _KDF_256),
}

# What generate() offers, in the order a list shows them (RSA 1024 is left
# out: too weak for a new key).
ALGORITHMS = ("rsa2048", "rsa3072", "rsa4096", "nistp256", "nistp384", "nistp521", "ed25519", "cv25519",
              "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "secp256k1")
ALGORITHM_LABELS = {"rsa2048": "RSA 2048", "rsa3072": "RSA 3072", "rsa4096": "RSA 4096",
                    "nistp256": "ECC NIST P-256", "nistp384": "ECC NIST P-384", "nistp521": "ECC NIST P-521",
                    "ed25519": "Ed25519", "cv25519": "Curve25519 (cv25519)",
                    "brainpoolP256r1": "ECC brainpool P-256", "brainpoolP384r1": "ECC brainpool P-384",
                    "brainpoolP512r1": "ECC brainpool P-512", "secp256k1": "ECC secp256k1"}

# Touch policy (User Interaction Flag, DOs D6-D8): 2 and 4 cannot be
# switched off again but by a reset of the application.
UIF_VALUES = {"off": 0, "on": 1, "fixed": 2, "cached": 3, "cached-fixed": 4}
UIF_NAMES = {v: k for k, v in UIF_VALUES.items()}
UIF_PERMANENT = (2, 4)
_UIF_BUTTON = 0x20

_PIN_NAMES = {PW1: ("OpenPGP PIN", "OpenPGP 用户 PIN"), PW3: ("OpenPGP Admin PIN", "OpenPGP 管理员 PIN"),
              RC: ("OpenPGP Reset Code", "OpenPGP 重置码")}
_KDF_HASHES = {0x08: "sha256", 0x0A: "sha512"}
_KDF_SALT = {PW1: 0x84, RC: 0x85, PW3: 0x86}
_KDF_COUNT_MAX = 1 << 32


class OpenPgpError(ManagerError):
    """An OpenPGP operation failed (ManagerError: English and Chinese
    message, the status word)."""


def _err(en, zh, sw=None, cls=OpenPgpError):
    return cls("OpenPGP: " + en, sw, "OpenPGP：" + zh)


# ----------------------------------------------------------------------------
# Algorithms, public keys, fingerprints (pure)
# ----------------------------------------------------------------------------

def key_ref(value):
    """Key reference 1, 2 or 3 of "sig", "dec", "aut" (or the number)."""
    if isinstance(value, str):
        value = KEY_REFS.get(value.strip().lower(), value)
    if type(value) is not int or value not in KEY_NAMES:
        raise _err("key slot %r (sig, dec or aut)" % (value,), "密钥槽 %r（sig、dec 或 aut）" % (value,))
    return value


def algorithm_attributes(algorithm, ref):
    """Card algorithm attributes (DO C1, C2 or C3 value) of algorithm (a
    name of ALGORITHMS) for key slot ref. RSA keys get a 32-bit exponent
    field and format 0 (e, p, q), like the card's default."""
    ref = key_ref(ref)
    name = str(algorithm)
    if name.startswith("rsa") and name[3:].isdigit() and int(name[3:]) in (1024, 2048, 3072, 4096):
        return bytes([CARD_RSA]) + int(name[3:]).to_bytes(2, "big") + b"\x00\x20\x00"
    if name not in _CURVES:
        raise _err("unknown algorithm %r" % (algorithm,), "未知算法 %r" % (algorithm,))
    oid = bytes.fromhex(_CURVES[name][0])
    slot = KEY_LABELS[KEY_NAMES[ref]]
    if name == "ed25519":
        if ref == 2:
            raise _err("an Ed25519 key cannot decrypt: choose cv25519 for the %s" % slot[0].lower(),
                       "Ed25519 密钥不能解密：%s请选择 cv25519" % slot[1])
        return bytes([CARD_EDDSA]) + oid
    if name == "cv25519":
        if ref != 2:
            raise _err("a cv25519 key can only decrypt: choose Ed25519 for the %s" % slot[0].lower(),
                       "cv25519 密钥只能用于解密：%s请选择 Ed25519" % slot[1])
        return bytes([CARD_ECDH]) + oid
    return bytes([CARD_ECDH if ref == 2 else CARD_ECDSA]) + oid


def _attr_oid(attr):
    return attr[1:-1] if attr[-1:] == b"\xff" else attr[1:]


def _curve_of(attr):
    """Name of the curve of EC attributes (None for RSA or unknown)."""
    attr = bytes(attr)
    if not attr or attr[0] == CARD_RSA:
        return None
    name = stdformats._PGP_CURVES.get(_attr_oid(attr).hex(), (None,))[0]
    return name if name in _CURVES else None


def algorithm_name(attr):
    """Name (as in ALGORITHMS, e.g. "rsa2048", "nistp256", "ed25519") of card
    algorithm attributes; a description for anything else."""
    attr = bytes(attr or b"")
    if attr[:1] == bytes([CARD_RSA]) and len(attr) >= 3:
        return "rsa%d" % int.from_bytes(attr[1:3], "big")
    return _curve_of(attr) or stdformats.pgp_attr_name(attr)


def parse_public_key(data):
    """Fields of a public key answered by the card (7F49 { 81 n, 82 e } or
    { 86 point }, with or without the 7F49 tag): {0x81: n, 0x82: e} or
    {0x86: point}."""
    items = parse_tlvs(data, "OpenPGP public key", "OpenPGP 公钥")
    if len(items) == 1 and items[0][0] == 0x7F49:
        items = parse_tlvs(items[0][1], "OpenPGP public key", "OpenPGP 公钥")
    fields = dict(items)
    if not (0x86 in fields or (0x81 in fields and 0x82 in fields)):
        raise _err("malformed public key from the card", "卡返回的公钥格式错误")
    return fields


def public_key_object(attr, fields):
    """Public key (cryptography) of card attributes attr and the public key
    fields (parse_public_key)."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
    attr = bytes(attr)
    try:
        if attr[:1] == bytes([CARD_RSA]):
            return rsa.RSAPublicNumbers(int.from_bytes(fields[0x82], "big"),
                                        int.from_bytes(fields[0x81], "big")).public_key()
        curve = _curve_of(attr)
        point = fields[0x86]
        if curve in ("ed25519", "cv25519"):
            if len(point) == 33 and point[0] == 0x40:
                point = point[1:]
            cls = ed25519.Ed25519PublicKey if curve == "ed25519" else x25519.X25519PublicKey
            return cls.from_public_bytes(point)
        if curve is None:
            raise ValueError("unknown curve")
        return ec.EllipticCurvePublicKey.from_encoded_point(getattr(ec, _CURVES[curve][1])(), point)
    except (KeyError, ValueError, TypeError) as e:
        raise _err("the card's public key cannot be read (%s)" % e, "无法读取卡上的公钥（%s）" % e) from None


def public_key_pem(attr, fields):
    from cryptography.hazmat.primitives import serialization
    return public_key_object(attr, fields).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def _mpi(value):
    value = bytes(value).lstrip(b"\x00")
    bits = (len(value) - 1) * 8 + value[0].bit_length() if value else 0
    return struct.pack(">H", bits) + value


def public_key_packet(attr, fields, created):
    """Body of the OpenPGP v4 public key packet (RFC 4880 5.5.2) of a card
    key: algorithm attributes attr, public key fields (parse_public_key),
    creation time created (Unix time). RSA keys are algorithm 1; ECDSA 19;
    EdDSA 22 (Ed25519, legacy form: 0x40 || key); ECDH 18 with GnuPG's KDF
    parameters (cv25519: 0x40 || key, as stored natively)."""
    attr = bytes(attr)
    if not 0 <= int(created) < 1 << 32:
        raise _err("creation time out of range", "创建时间超出范围")
    head = b"\x04" + struct.pack(">I", int(created))
    if attr[:1] == bytes([CARD_RSA]):
        return head + bytes([_PGP_ALGO[CARD_RSA]]) + _mpi(fields[0x81]) + _mpi(fields[0x82])
    curve = _curve_of(attr)
    if curve is None or attr[0] not in (CARD_ECDH, CARD_ECDSA, CARD_EDDSA):
        raise _err("no OpenPGP key for algorithm %s" % stdformats.pgp_attr_name(attr),
                   "算法 %s 无法构成 OpenPGP 密钥" % stdformats.pgp_attr_name(attr))
    oid = bytes.fromhex(_CURVES[curve][0])      # the OpenPGP OID (also for RFC 8410 ones on the card)
    point = bytes(fields[0x86])
    if curve in ("ed25519", "cv25519") and len(point) == 32:
        point = b"\x40" + point
    body = head + bytes([_PGP_ALGO[attr[0]], len(oid)]) + oid + _mpi(point)
    if attr[0] == CARD_ECDH:
        body += b"\x03\x01" + bytes(_CURVES[curve][2])
    return body


def fingerprint(packet):
    """OpenPGP v4 fingerprint (20 bytes) of a public key packet body, as
    stdformats computes it for key files (the packet is parsed back, so a
    malformed one is caught here)."""
    k = stdformats._PgpKey(6, bytes(packet), None)
    if k.unsupported or k.fingerprint is None or k.pub_len != len(packet):
        raise _err("cannot compute the fingerprint of the key", "无法计算密钥指纹")
    return k.fingerprint


def kdf_pin(kdf_do, pin, which):
    """The PIN bytes sent to the card: pin as is, or when the KDF-DO (F9)
    asks for KDF_ITERSALTED_S2K (OpenPGP card 3.4, 4.3.2) its S2K hash with
    the salt of which (PW1, RC or PW3), as GnuPG sends it."""
    fields = _kdf_fields(kdf_do)
    if fields.get(0x81, b"\x00")[:1] != b"\x03":
        return bytes(pin)
    hname = _KDF_HASHES.get((fields.get(0x82) or b"\x00")[0])
    count = int.from_bytes(fields.get(0x83, b""), "big")
    salt = fields.get(_KDF_SALT[which]) or fields.get(0x84)
    if hname is None or not 0 < count < _KDF_COUNT_MAX or not salt:
        raise _err("the card asks for a PIN KDF this tool does not know (KDF-DO %s)" % bytes(kdf_do[:3]).hex(),
                   "卡要求使用本工具不支持的 PIN KDF", cls=NotSupported)
    return s2k_iterated(hname, salt, pin, count)


def s2k_iterated(hname, salt, secret, count):
    """Iterated and salted S2K (RFC 4880 3.7.1.3): the hash of salt ||
    secret repeated to count bytes (at least once)."""
    h = hashlib.new(hname)
    unit = bytes(salt) + bytes(secret)
    count = max(int(count), len(unit))
    block = unit * max(1, 65536 // len(unit))
    while count >= len(block):
        h.update(block)
        count -= len(block)
    full, rest = divmod(count, len(unit))
    h.update(unit * full + unit[:rest])
    return h.digest()


def _kdf_fields(kdf_do):
    """Fields of the KDF-DO, with or without its F9 tag (GET DATA F9 of this
    firmware answers it tagged, and a lone 81 01 00 as F9 01 00); {} when it
    is absent or says "none"."""
    kdf_do = bytes(kdf_do or b"")
    try:
        items = parse_tlvs(kdf_do, "OpenPGP KDF", "OpenPGP KDF") if len(kdf_do) >= 3 else []
        if len(items) == 1 and items[0][0] == DO_KDF:
            value = items[0][1]
            items = parse_tlvs(value, "OpenPGP KDF", "OpenPGP KDF") if len(value) >= 3 else []
        return dict(items)
    except ManagerError:
        return {}


# ----------------------------------------------------------------------------
# Card access
# ----------------------------------------------------------------------------

def _get(card, tag):
    return send(card, INS_GET_DATA, tag >> 8, tag & 0xFF)


def _flatten(data, out, depth=0):
    """Simple data objects of a (constructed) DO answer, by tag."""
    for tag, value in parse_tlvs(data, "OpenPGP data", "OpenPGP 数据"):
        first = tag >> 8 if tag > 0xFF else tag
        if first & 0x20 and depth < 4:
            _flatten(value, out, depth + 1)
        else:
            out.setdefault(tag, value)
    return out


def _constructed(card, tag):
    """Simple DOs inside the constructed DO tag ({} when the card has none)."""
    resp, sw = _get(card, tag)
    if sw != 0x9000:
        if sw in (0x6A88, 0x6A82):
            return {}
        raise sw_error("OpenPGP: reading data object %X" % tag, sw, "OpenPGP：读取数据对象 %X" % tag)
    return _flatten(resp, {}) if resp else {}


def _app_data(card):
    """Application related data (6E): AID, algorithm attributes, PW status,
    fingerprints, generation times, UIF and key information."""
    return _constructed(card, DO_APP_DATA)


def _kdf_do(card):
    resp, sw = _get(card, DO_KDF)
    return resp if sw == 0x9000 else b""


def _present(app, ref):
    """Whether key slot ref holds a key: the key information DE, else the
    fingerprint; None when the card says neither."""
    info = app.get(DO_KEY_INFO)
    if info and len(info) >= 2:
        status = {info[i]: info[i + 1] for i in range(0, len(info) - 1, 2)}
        if ref - 1 in status:
            return status[ref - 1] != 0
    fps = app.get(DO_FPS, b"")
    if len(fps) >= 60:
        return any(fps[(ref - 1) * 20:ref * 20])
    return None


def _supported(card):
    """{key ref: [attributes]} the card lists in its algorithm information
    (FA); None when it has none."""
    resp, sw = _get(card, DO_ALGO_INFO)
    if sw != 0x9000 or not resp:
        return None
    items = parse_tlvs(resp, "OpenPGP algorithm information", "OpenPGP 算法信息")
    if len(items) == 1 and items[0][0] == DO_ALGO_INFO:
        items = parse_tlvs(items[0][1], "OpenPGP algorithm information", "OpenPGP 算法信息")
    out = {1: [], 2: [], 3: []}
    for tag, value in items:
        if _DO_ALGO + 1 <= tag <= _DO_ALGO + 3 and value:
            out[tag - _DO_ALGO].append(bytes(value))
    return out


def _offered(attr, listed):
    """Whether attributes attr are among those the card lists for a slot:
    RSA by modulus size, EC by curve (the list names a curve with one
    algorithm id, e.g. ECDSA also for the decryption slot, where the key is
    ECDH)."""
    if attr[0] == CARD_RSA:
        return any(a[0] == CARD_RSA and a[1:3] == attr[1:3] for a in listed)
    return any(a[0] != CARD_RSA and _attr_oid(a) == _attr_oid(attr) for a in listed)


def _pin_bytes(pin, which, new=False):
    """A PIN as sent (UTF-8). A new one is checked against the lengths the
    card takes (PW1 6, PW3 and Reset Code 8, at most 127 bytes)."""
    en, zh = _PIN_NAMES[which]
    if pin is None:
        raise _err("the %s is needed" % en, "需要%s" % zh, cls=AuthRequired)
    b = pin.encode("utf-8") if isinstance(pin, str) else bytes(pin)
    lo = {PW1: PW1_MIN, PW3: PW3_MIN, RC: RC_MIN}[which] if new else 1
    if not lo <= len(b) <= PW_MAX:
        if new:
            raise _err("the new %s must have %d to %d characters" % (en, lo, PW_MAX),
                       "新的%s长度须为 %d 到 %d 个字符" % (zh, lo, PW_MAX))
        raise _err("the %s is empty or too long (it was not sent)" % en, "%s为空或过长（未发送）" % zh)
    return b


def _pin_error(which, sw, what_en=None, what_zh=None):
    """ManagerError for a PIN check the card refused."""
    en, zh = _PIN_NAMES[which]
    if sw & 0xFFF0 == 0x63C0:
        n = sw & 0xF
        return WrongSecret("OpenPGP: wrong %s, %d tries left (SW %04X)" % (en, n, sw), sw,
                           "OpenPGP：%s错误，还剩 %d 次（SW %04X）" % (zh, n, sw), retries=n)
    if sw == 0x6983:
        hint = {PW1: (" (unblock it with the Reset Code or the Admin PIN)", "（可用重置码或管理员 PIN 解锁）"),
                PW3: (" (only a reset of the OpenPGP application helps)", "（只能重置 OpenPGP 应用）"),
                RC: (" or not set (set one with the Admin PIN)", "或未设置（请用管理员 PIN 设置）")}[which]
        return SecretBlocked("OpenPGP: the %s is blocked%s (SW %04X)" % (en, hint[0], sw), sw,
                             "OpenPGP：%s已锁定%s（SW %04X）" % (zh, hint[1], sw))
    if sw == 0x6700:
        return OpenPgpError("OpenPGP: %s: wrong length (SW %04X)" % (what_en or en, sw), sw,
                            "OpenPGP：%s：长度错误（SW %04X）" % (what_zh or zh, sw))
    return sw_error("OpenPGP: %s" % (what_en or en), sw, "OpenPGP：%s" % (what_zh or zh))


def _check(sw, en, zh, texts=None):
    if sw != 0x9000:
        texts = dict(texts or {})
        texts.setdefault(0x6600, ("not confirmed: touch the key when it blinks", "未确认：请在按键闪烁时触摸它"))
        texts.setdefault(0x6982, ("the Admin PIN is not verified", "管理员 PIN 未验证"))
        raise sw_error("OpenPGP: " + en, sw, "OpenPGP：" + zh, texts)


def _verify(card, which, pin, kdf):
    data = bytearray(kdf_pin(kdf, _pin_bytes(pin, which), which))
    try:
        _, sw = send(card, INS_VERIFY, 0x00, which, bytes(data))
    finally:
        wipe(data)
    if sw != 0x9000:
        raise _pin_error(which, sw)


def _logout(card, which):
    try:
        send(card, INS_VERIFY, 0xFF, which)
    except CardConnectionException:
        pass


def _put(card, tag, value, en, zh):
    _, sw = send(card, INS_PUT_DATA, tag >> 8, tag & 0xFF, bytes(value))
    _check(sw, en, zh)


# ----------------------------------------------------------------------------
# Manager
# ----------------------------------------------------------------------------

class OpenPgpManager:
    """The OpenPGP application of the device of m (a Management). Every
    method is one operation (its own PC/SC transaction); secrets are taken
    per call and not kept. Errors: ManagerError subclasses (OpenPgpError,
    WrongSecret with .retries, SecretBlocked, AuthRequired, NotSupported)."""

    def __init__(self, m):
        self.m = m

    @contextmanager
    def _session(self):
        try:
            with applet(self.m, OPENPGP_AID, "OpenPGP") as answer:
                yield self.m.card, answer
        except CardConnectionException as e:
            raise _err("the device cannot be reached (%s)" % e, "无法访问设备（%s）" % e) from None

    # -- information ---------------------------------------------------------
    def status(self):
        """{version ("3.4"), serial (8 hex digits, as GnuPG shows it),
        manufacturer (int), name (cardholder name as stored, "Surname<<Given
        names" by convention), url, keys: {"sig"|"dec"|"aut": {algorithm
        (name, see algorithm_name), label, attributes (bytes), present
        (bool|None), fingerprint (40 hex digits|None), created (Unix
        time|None), uif (int|None), uif_name}}, pin_retries (pw1, rc, pw3),
        pin_max_lengths (pw1, rc, pw3), pw1_multiple_signatures (bool),
        signature_counter, kdf (bool)}."""
        with self._session() as (card, _):
            app = _app_data(card)
            holder = _constructed(card, DO_CH_DATA)
            security = _constructed(card, DO_SEC_TPL)
            url, sw = _get(card, DO_URL)
            kdf = _kdf_do(card)
        aid = app.get(DO_AID, b"")
        fps, times, pw = app.get(DO_FPS, b""), app.get(DO_TIMES, b""), app.get(DO_PW_STATUS, b"")
        keys = {}
        for ref, name in KEY_NAMES.items():
            attr = bytes(app.get(_DO_ALGO + ref, b""))
            fp = bytes(fps[(ref - 1) * 20:ref * 20])
            ts = bytes(times[(ref - 1) * 4:ref * 4])
            uif = app.get(_DO_UIF + ref)
            keys[name] = {
                "algorithm": algorithm_name(attr) if attr else None,
                "label": stdformats.pgp_attr_name(attr) if attr else None,
                "attributes": attr,
                "present": _present(app, ref),
                "fingerprint": fp.hex().upper() if len(fp) == 20 and any(fp) else None,
                "created": int.from_bytes(ts, "big") if len(ts) == 4 and any(ts) else None,
                "uif": uif[0] if uif else None,
                "uif_name": UIF_NAMES.get(uif[0]) if uif else None,
            }
        counter = security.get(DO_SIG_COUNT, b"")
        return {
            "version": "%d.%d" % (aid[6], aid[7]) if len(aid) >= 8 else None,
            "serial": aid[10:14].hex().upper() if len(aid) >= 14 else None,
            "manufacturer": int.from_bytes(aid[8:10], "big") if len(aid) >= 10 else None,
            "name": _text(holder.get(DO_NAME, b"")),
            "url": _text(url) if sw == 0x9000 else "",
            "keys": keys,
            "pin_retries": (pw[4], pw[5], pw[6]) if len(pw) >= 7 else (None, None, None),
            "pin_max_lengths": (pw[1], pw[2], pw[3]) if len(pw) >= 7 else (None, None, None),
            "pw1_multiple_signatures": bool(pw[0]) if pw else None,
            "signature_counter": int.from_bytes(counter, "big") if counter else 0,
            "kdf": _kdf_fields(kdf).get(0x81, b"\x00")[:1] == b"\x03",
        }

    def supported_algorithms(self, ref):
        """Names (ALGORITHMS order) of the algorithms the card offers for key
        slot ref (its algorithm information FA; without one, ALGORITHMS as
        they fit the slot)."""
        ref = key_ref(ref)
        with self._session() as (card, _):
            listed = _supported(card)
        out = []
        for name in ALGORITHMS:
            try:
                attr = algorithm_attributes(name, ref)
            except ManagerError:
                continue
            if listed is None or _offered(attr, listed[ref]):
                out.append(name)
        return out

    def public_key(self, ref):
        """Public key (PEM) of key slot ref, None when it holds none."""
        ref = key_ref(ref)
        with self._session() as (card, _):
            attr = _app_data(card).get(_DO_ALGO + ref, b"")
            resp, sw = send(card, INS_GENERATE, 0x81, 0x00, bytes([_CRT[ref], 0x00]))
        if sw in (0x6A88, 0x6A82):
            return None
        _check(sw, "reading the public key", "读取公钥")
        return public_key_pem(attr, parse_public_key(resp))

    # -- keys ----------------------------------------------------------------
    def generate(self, ref, algorithm, admin_pin, replace=False, created=None):
        """Generates a key of algorithm (ALGORITHMS) in key slot ref ("sig",
        "dec", "aut") on the card: sets the slot's algorithm attributes if
        they differ, generates, and writes the fingerprint and generation
        time (created, default now). A key already in the slot is replaced
        only with replace=True. Returns {key_ref, algorithm, fingerprint
        (hex), created, public_key (PEM)}."""
        ref = key_ref(ref)
        attr = algorithm_attributes(algorithm, ref)
        created = int(time.time()) if created is None else int(created)
        slot = KEY_LABELS[KEY_NAMES[ref]]
        with self._session() as (card, _):
            app = _app_data(card)
            listed = _supported(card)
            if listed is not None and not _offered(attr, listed[ref]):
                raise _err("the card does not offer %s for the %s" % (ALGORITHM_LABELS.get(algorithm, algorithm),
                                                                      slot[0].lower()),
                           "卡的%s不支持 %s" % (slot[1], ALGORITHM_LABELS.get(algorithm, algorithm)), 0x6A81,
                           NotSupported)
            if _present(app, ref) is not False and not replace:
                raise _err("the %s slot holds a key; replace it explicitly" % slot[0].lower(),
                           "%s槽中已有密钥；如需替换请明确确认" % slot[1], 0x6A89)
            kdf = _kdf_do(card)
            _verify(card, PW3, admin_pin, kdf)
            try:
                if bytes(app.get(_DO_ALGO + ref, b"")) != attr:
                    # (a new algorithm removes the slot's key: cmd_put_data.c)
                    _put(card, _DO_ALGO + ref, attr, "algorithm attributes", "算法属性")
                resp, sw = send(card, INS_GENERATE, 0x80, 0x00, bytes([_CRT[ref], 0x00]))
                _check(sw, "key generation", "密钥生成")
                fields = parse_public_key(resp)
                fp = fingerprint(public_key_packet(attr, fields, created))
                _put(card, _DO_FP + ref, fp, "fingerprint", "指纹")
                _put(card, _DO_TIME + ref, struct.pack(">I", created), "generation time", "生成时间")
            finally:
                _logout(card, PW3)
        return {"key_ref": KEY_NAMES[ref], "algorithm": algorithm, "fingerprint": fp.hex().upper(),
                "created": created, "public_key": public_key_pem(attr, fields)}

    def delete_key(self, ref, admin_pin):
        """Deletes the key of slot ref (with its fingerprint and generation
        time): the card has no delete command, but a change of the slot's
        algorithm attributes removes its key, so they are changed and set
        back. The algorithm and touch policy of the slot stay."""
        ref = key_ref(ref)
        slot = KEY_LABELS[KEY_NAMES[ref]]
        with self._session() as (card, _):
            app = _app_data(card)
            if _present(app, ref) is False:
                raise _err("the %s slot holds no key" % slot[0].lower(), "%s槽中没有密钥" % slot[1], 0x6A88)
            current = bytes(app.get(_DO_ALGO + ref) or algorithm_attributes("rsa2048", ref))
            other = algorithm_attributes("rsa3072" if current == algorithm_attributes("rsa2048", ref) else "rsa2048",
                                         ref)
            _verify(card, PW3, admin_pin, _kdf_do(card))
            try:
                _put(card, _DO_ALGO + ref, other, "deleting the key", "删除密钥")
                _put(card, _DO_ALGO + ref, current, "restoring the algorithm attributes", "恢复算法属性")
            finally:
                _logout(card, PW3)
            if _present(_app_data(card), ref):
                raise _err("the key of the %s slot is still there" % slot[0].lower(), "%s槽中的密钥仍然存在" % slot[1])

    # -- PINs ------------------------------------------------------------------
    def change_pin(self, old, new):
        """Changes the PIN (PW1, 6 to 127 characters)."""
        self._change(PW1, old, new)

    def change_admin_pin(self, old, new):
        """Changes the Admin PIN (PW3, 8 to 127 characters)."""
        self._change(PW3, old, new)

    def _change(self, which, old, new):
        new_b = _pin_bytes(new, which, new=True)
        old_b = _pin_bytes(old, which)
        with self._session() as (card, _):
            kdf = _kdf_do(card)
            data = bytearray(kdf_pin(kdf, old_b, which) + kdf_pin(kdf, new_b, which))
            try:
                _, sw = send(card, INS_CHANGE_REFERENCE, 0x00, which, bytes(data))
            finally:
                wipe(data)
        if sw != 0x9000:
            raise _pin_error(which, sw, "changing the %s" % _PIN_NAMES[which][0], "更改%s" % _PIN_NAMES[which][1])

    def set_reset_code(self, admin_pin, code):
        """Sets the Reset Code (8 to 127 characters), which unblocks the PIN
        without the Admin PIN; None removes it."""
        code_b = None if code is None else _pin_bytes(code, RC, new=True)
        with self._session() as (card, _):
            kdf = _kdf_do(card)
            _verify(card, PW3, admin_pin, kdf)
            data = bytearray(b"" if code_b is None else kdf_pin(kdf, code_b, RC))
            try:
                _, sw = send(card, INS_PUT_DATA, 0x00, DO_RESET_CODE, bytes(data))
            finally:
                wipe(data)
                _logout(card, PW3)
        _check(sw, "setting the Reset Code", "设置重置码")

    def unblock_pin(self, new_pin, admin_pin=None, reset_code=None):
        """Sets a new PIN and its retry counter back, with the Reset Code or
        the Admin PIN (exactly one of them)."""
        if (admin_pin is None) == (reset_code is None):
            raise _err("unblocking the PIN needs the Reset Code or the Admin PIN", "解锁 PIN 需要重置码或管理员 PIN")
        new_b = _pin_bytes(new_pin, PW1, new=True)
        with self._session() as (card, _):
            kdf = _kdf_do(card)
            if reset_code is not None:
                data = bytearray(kdf_pin(kdf, _pin_bytes(reset_code, RC), RC) + kdf_pin(kdf, new_b, PW1))
                try:
                    _, sw = send(card, INS_RESET_RETRY, 0x00, PW1, bytes(data))
                finally:
                    wipe(data)
                if sw != 0x9000:
                    raise _pin_error(RC, sw, "unblocking the PIN", "解锁 PIN")
                return
            _verify(card, PW3, admin_pin, kdf)
            data = bytearray(kdf_pin(kdf, new_b, PW1))
            try:
                _, sw = send(card, INS_RESET_RETRY, 0x02, PW1, bytes(data))
            finally:
                wipe(data)
                _logout(card, PW3)
        if sw != 0x9000:
            raise _pin_error(PW1, sw, "unblocking the PIN", "解锁 PIN")

    # -- settings --------------------------------------------------------------
    def set_uif(self, ref, value, admin_pin, permanent=False):
        """Touch policy of key slot ref: value a name of UIF_VALUES or its
        number. "fixed" and "cached-fixed" cannot be changed again but by a
        reset of the application: permanent=True confirms that."""
        ref = key_ref(ref)
        v = UIF_VALUES.get(value.strip().lower(), value) if isinstance(value, str) else value
        if type(v) is not int or v not in UIF_NAMES:
            raise _err("unknown touch policy %r (%s)" % (value, ", ".join(UIF_VALUES)),
                       "未知的触摸策略 %r（%s）" % (value, "、".join(UIF_VALUES)))
        if v in UIF_PERMANENT and not permanent:
            raise _err("the touch policy %r cannot be switched off again (only a reset of the OpenPGP application "
                       "removes it): confirm it explicitly" % UIF_NAMES[v],
                       "触摸策略 %r 设置后无法关闭（只有重置 OpenPGP 应用才能清除）：请明确确认" % UIF_NAMES[v])
        slot = KEY_LABELS[KEY_NAMES[ref]]
        with self._session() as (card, _):
            cur = _app_data(card).get(_DO_UIF + ref)
            if cur and cur[0] in UIF_PERMANENT and cur[0] != v:
                raise _err("the touch policy of the %s is fixed (only a reset of the OpenPGP application changes it)"
                           % slot[0].lower(), "%s的触摸策略已固定（只有重置 OpenPGP 应用才能更改）" % slot[1], 0x6982)
            _verify(card, PW3, admin_pin, _kdf_do(card))
            try:
                _put(card, _DO_UIF + ref, bytes([v, _UIF_BUTTON]), "touch policy", "触摸策略")
            finally:
                _logout(card, PW3)

    def set_cardholder(self, name, admin_pin):
        """Cardholder name (DO 5B), stored as given: by convention
        "Surname<<Given names" (GnuPG shows "Given names Surname"). Printable
        ASCII, at most 39 characters, as GnuPG takes it; "" removes it."""
        name = "" if name is None else str(name)
        if any(not " " <= c <= "~" for c in name):
            raise _err("the cardholder name may only have plain ASCII letters, digits and signs (GnuPG reads "
                       "nothing else)", "持卡人姓名只能包含普通 ASCII 字母、数字和符号（GnuPG 不支持其他字符）")
        raw = name.encode("ascii")
        if len(raw) > NAME_MAX:
            raise _err("the cardholder name has at most %d characters" % NAME_MAX,
                       "持卡人姓名最多 %d 个字符" % NAME_MAX)
        with self._session() as (card, _):
            _verify(card, PW3, admin_pin, _kdf_do(card))
            try:
                _put(card, DO_NAME, raw, "cardholder name", "持卡人姓名")
            finally:
                _logout(card, PW3)

    def set_url(self, url, admin_pin):
        """URL of the public key (DO 5F50, GnuPG's `fetch`); "" removes it."""
        raw = ("" if url is None else str(url)).encode("utf-8")
        if len(raw) > 255:
            raise _err("the URL has at most 255 bytes", "URL 最多 255 字节")
        with self._session() as (card, _):
            _verify(card, PW3, admin_pin, _kdf_do(card))
            try:
                _put(card, DO_URL, raw, "URL", "URL")
            finally:
                _logout(card, PW3)

    # -- reset -------------------------------------------------------------------
    def reset(self, admin_pin=None):
        """Factory state of the OpenPGP application (TERMINATE DF, ACTIVATE
        FILE; a touch): every OpenPGP key, the PINs (back to 123456 and
        12345678), the Reset Code, the touch policies and the cardholder data
        go. The card allows it with the Admin PIN verified or blocked:
        without admin_pin it is blocked first by wrong attempts (if the
        touch is then missing, it stays blocked until a reset succeeds)."""
        with self._session() as (card, _):
            if admin_pin is not None:
                _verify(card, PW3, admin_pin, _kdf_do(card))
            else:
                _block_admin_pin(card)
            _, sw = send(card, INS_TERMINATE, 0x00, 0x00)
            _check(sw, "reset", "重置")
            _, sw = send(card, INS_ACTIVATE, 0x00, 0x00)
            if sw not in (0x9000, 0x6D00):
                _check(sw, "reset (activation)", "重置（激活）")


def _block_admin_pin(card):
    """Wrong Admin PIN attempts until the card reports it blocked (the value
    tried is shorter than any Admin PIN can be: never the right one)."""
    for _ in range(32):
        _, sw = send(card, INS_VERIFY, 0x00, PW3, b"\x00")
        if sw in (0x6983, 0x9000):
            return
        if sw & 0xFFF0 != 0x63C0:
            raise _err("the Admin PIN could not be blocked for the reset (%s, SW %04X)" % (sw_text(sw), sw),
                       "无法为重置锁定管理员 PIN（%s，SW %04X）" % (sw_text(sw, True), sw), sw)
    raise _err("the Admin PIN is not blocked after 32 wrong attempts", "32 次错误尝试后管理员 PIN 仍未锁定")


def _text(raw):
    """Text of the card (UTF-8, else Latin-1), made safe to show."""
    raw = bytes(raw or b"")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return display_name(text)


__all__ = ["OpenPgpManager", "OpenPgpError", "ALGORITHMS", "ALGORITHM_LABELS", "KEY_REFS", "KEY_NAMES", "KEY_LABELS",
           "UIF_VALUES", "UIF_NAMES", "algorithm_attributes", "algorithm_name", "key_ref", "parse_public_key",
           "public_key_object", "public_key_packet", "fingerprint", "kdf_pin", "s2k_iterated"]
