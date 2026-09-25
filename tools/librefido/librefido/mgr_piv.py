"""PIV application of the device for the key manager (SP 800-73-4 with the
YubiKey extensions the firmware implements, pico-openpgp/src/openpgp/piv.c):
status with the key metadata, management key authentication, key
generation, self-signed certificates and certificate signing requests made
with the card's key, certificate import / export / deletion, deleting and
moving keys, PIN / PUK / management key changes and resetting the
application.

Certificates and requests: the to-be-signed part is built with the
cryptography package around the slot's public key (a throwaway key of the
same type only supplies the signature algorithm), the card signs it
(GENERAL AUTHENTICATE after VERIFY PIN) and the DER is assembled here; it is
checked against the slot's public key before it is stored or returned.

The management key given to authenticate() is kept (in a bytearray, wiped by
forget() and reset()) for the manager's lifetime, since every administrative
command needs a fresh authentication (it ends with the application's
selection); without one, the default key is used when the device says it
still has it, otherwise AuthRequired is raised. PINs and PUKs are taken per
call and not kept.
"""

import datetime
import hashlib
import hmac
import os
import threading
from contextlib import contextmanager

from smartcard.Exceptions import CardConnectionException

from . import keyio, stdformats
from .mgmt import display_name
from .mgr_common import (AuthRequired, ManagerError, NotSupported, SecretBlocked, WrongSecret, applet, parse_tlvs,
                         send, sw_error, sw_text, tlv, wipe)

PIV_AID = keyio.PIV_AID
SLOTS = keyio.PIV_SLOTS
MGMT_SLOT = 0x9B
PIN_REF, PUK_REF = 0x80, 0x81
DEFAULT_MGMT_KEY = keyio.PIV_DEFAULT_MGMT_KEY

INS_VERIFY, INS_CHANGE_REFERENCE, INS_RESET_RETRY = 0x20, 0x24, 0x2C
INS_AUTHENTICATE, INS_GENERATE, INS_GET_DATA, INS_PUT_DATA = 0x87, 0x47, 0xCB, 0xDB
INS_ATTEST, INS_SERIAL, INS_METADATA, INS_MOVE_KEY = 0xF9, 0xF8, 0xF7, 0xF6
INS_RESET, INS_SET_MGMT_KEY, INS_VERSION = 0xFB, 0xFF, 0xFD

# Names of the algorithms (and the PIV identifiers, SP 800-78-4; E0 / E1 as
# on YubiKey 5.7).
ALGORITHMS = {"rsa1024": 0x06, "rsa2048": 0x07, "rsa3072": 0x05, "rsa4096": 0x16, "eccp256": 0x11,
              "eccp384": 0x14, "ed25519": 0xE0, "x25519": 0xE1}
ALGORITHM_NAMES = {v: k for k, v in ALGORITHMS.items()}
ALGORITHM_LABELS = {k: stdformats.PIV_ALGORITHMS[v] for k, v in ALGORITHMS.items()}
MGMT_ALGORITHMS = {"3des": 0x03, "aes128": 0x08, "aes192": 0x0A, "aes256": 0x0C}
MGMT_ALGORITHM_NAMES = {v: k for k, v in MGMT_ALGORITHMS.items()}
MGMT_KEY_SIZES = {0x03: 24, 0x08: 16, 0x0A: 24, 0x0C: 32}
PIN_POLICIES = {"default": 0, "never": 1, "once": 2, "always": 3}
TOUCH_POLICIES = {"default": 0, "never": 1, "always": 2, "cached": 3}
PIN_POLICY_NAMES = {v: k for k, v in PIN_POLICIES.items() if v}
TOUCH_POLICY_NAMES = {v: k for k, v in TOUCH_POLICIES.items() if v}
ORIGINS = {1: "generated", 2: "imported"}

SLOT_NAMES = {0x9A: ("Authentication", "身份认证"), 0x9C: ("Digital Signature", "数字签名"),
              0x9D: ("Key Management", "密钥管理"), 0x9E: ("Card Authentication", "卡认证")}

PIN_LEN = 8                 # PIN and PUK: 6 to 8 bytes, padded with FF to 8 (piv.c piv_new_pin_ok)
PIN_MIN = 6
_RSA = (0x06, 0x07, 0x05, 0x16)
_EC = {0x11: "SECP256R1", 0x14: "SECP384R1"}
_ED25519, _X25519 = 0xE0, 0xE1
_SHA256_INFO = bytes.fromhex("3031300d060960864801650304020105000420")     # DigestInfo prefix (RFC 8017)
_PIN_NAMES = {PIN_REF: ("PIV PIN", "PIV PIN"), PUK_REF: ("PIV PUK", "PIV PUK")}
DAYS_MAX = 36500


class PivError(ManagerError):
    """A PIV operation failed (ManagerError: English and Chinese message, the
    status word)."""


def _err(en, zh, sw=None, cls=PivError):
    return cls("PIV: " + en, sw, "PIV：" + zh)


def slot_name(slot, zh=False):
    """Name of a key slot ("Authentication", "Retired key 5", ...)."""
    if slot in SLOT_NAMES:
        return SLOT_NAMES[slot][1 if zh else 0]
    if 0x82 <= slot <= 0x95:
        return ("历史密钥 %d" if zh else "Retired key %d") % (slot - 0x81)
    return "%02X" % slot


def slot_ref(value):
    """Slot number of 0x9A, "9a", "9A", "0x82", ..."""
    if isinstance(value, str):
        try:
            value = int(value.strip(), 16)
        except ValueError:
            pass
    if type(value) is not int or value not in SLOTS:
        raise _err("slot %r (9A, 9C, 9D, 9E or 82 to 95)" % (value,), "槽位 %r（9A、9C、9D、9E 或 82 到 95）" % (value,))
    return value


def _algorithm(value):
    if isinstance(value, str) and value.strip().lower() in ALGORITHMS:
        return ALGORITHMS[value.strip().lower()]
    if type(value) is int and value in ALGORITHM_NAMES:
        return value
    raise _err("unknown algorithm %r (%s)" % (value, ", ".join(ALGORITHMS)),
               "未知算法 %r（%s）" % (value, "、".join(ALGORITHMS)))


def _policy(value, table, what, what_zh):
    v = table.get(value.strip().lower()) if isinstance(value, str) else value
    if type(v) is not int or v not in table.values():
        raise _err("unknown %s %r (%s)" % (what, value, ", ".join(table)),
                   "未知的%s %r（%s）" % (what_zh, value, "、".join(table)))
    return v


# ----------------------------------------------------------------------------
# Secrets (pure)
# ----------------------------------------------------------------------------

def pin_block(pin, ref=PIN_REF, new=False):
    """A PIN or PUK as the card takes it: its UTF-8 bytes padded with FF to 8
    (a bytearray: wipe it). A new one has 6 to 8 bytes; another one longer
    than 8 cannot be right and is refused before it costs a retry."""
    en, zh = _PIN_NAMES[ref]
    if pin is None:
        raise _err("the %s is needed" % en, "需要%s" % zh, cls=AuthRequired)
    b = pin.encode("utf-8") if isinstance(pin, str) else bytes(pin)
    lo = PIN_MIN if new else 1
    if not lo <= len(b) <= PIN_LEN or 0xFF in b:
        if new:
            raise _err("the new %s must have %d to %d characters (bytes of UTF-8)" % (en, PIN_MIN, PIN_LEN),
                       "新的%s须为 %d 到 %d 个字符（UTF-8 字节）" % (zh, PIN_MIN, PIN_LEN))
        raise _err("a %s has 1 to %d characters: this one cannot be right (it was not sent)" % (en, PIN_LEN),
                   "%s为 1 到 %d 个字符：此值不可能正确（未发送）" % (zh, PIN_LEN))
    return bytearray(b + b"\xff" * (PIN_LEN - len(b)))


def parse_management_key(key, algorithm=None):
    """A management key (bytes, or hexadecimal text with optional spaces or
    colons) as a bytearray, checked against the size of algorithm (a name of
    MGMT_ALGORITHMS or its number) when given."""
    if isinstance(key, str):
        text = "".join(c for c in key if c not in " :-\t\r\n")
        try:
            raw = bytearray.fromhex(text)
        except ValueError:
            raise _err("the management key must be hexadecimal", "管理密钥必须是十六进制") from None
    elif isinstance(key, (bytes, bytearray)):
        raw = bytearray(key)
    else:
        raise _err("the management key must be bytes or hexadecimal text", "管理密钥必须是字节或十六进制文本")
    if algorithm is not None:
        algo = _mgmt_algorithm(algorithm)
        if len(raw) != MGMT_KEY_SIZES[algo]:
            n = len(raw)
            wipe(raw)
            raise _err("a %s management key has %d bytes (%d hex digits), not %d" % (
                MGMT_ALGORITHM_NAMES[algo].upper(), MGMT_KEY_SIZES[algo], 2 * MGMT_KEY_SIZES[algo], n),
                "%s 管理密钥应为 %d 字节（%d 个十六进制数字），而不是 %d 字节" % (
                MGMT_ALGORITHM_NAMES[algo].upper(), MGMT_KEY_SIZES[algo], 2 * MGMT_KEY_SIZES[algo], n))
    elif len(raw) not in (16, 24, 32):
        n = len(raw)
        wipe(raw)
        raise _err("a management key has 16, 24 or 32 bytes (32, 48 or 64 hex digits), not %d" % n,
                   "管理密钥应为 16、24 或 32 字节（32、48 或 64 个十六进制数字），而不是 %d 字节" % n)
    return raw


def _mgmt_algorithm(value):
    v = MGMT_ALGORITHMS.get(value.strip().lower()) if isinstance(value, str) else value
    if type(v) is not int or v not in MGMT_KEY_SIZES:
        raise _err("unknown management key algorithm %r (%s)" % (value, ", ".join(MGMT_ALGORITHMS)),
                   "未知的管理密钥算法 %r（%s）" % (value, "、".join(MGMT_ALGORITHMS)))
    return v


def generate_management_key(algorithm="aes192"):
    """A new random management key of algorithm, as hexadecimal text (to
    show to the user, who must keep it)."""
    return os.urandom(MGMT_KEY_SIZES[_mgmt_algorithm(algorithm)]).hex().upper()


# ----------------------------------------------------------------------------
# Public keys, certificates, requests (pure)
# ----------------------------------------------------------------------------

def public_key_object(algo, fields):
    """Public key (cryptography) of PIV algorithm algo from the fields of a
    public key template (81 modulus, 82 exponent; 86 point or key)."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
    try:
        if algo in _RSA:
            return rsa.RSAPublicNumbers(int.from_bytes(fields[0x82], "big"),
                                        int.from_bytes(fields[0x81], "big")).public_key()
        if algo in _EC:
            return ec.EllipticCurvePublicKey.from_encoded_point(getattr(ec, _EC[algo])(), fields[0x86])
        if algo == _ED25519:
            return ed25519.Ed25519PublicKey.from_public_bytes(fields[0x86])
        if algo == _X25519:
            return x25519.X25519PublicKey.from_public_bytes(fields[0x86])
    except (KeyError, ValueError, TypeError) as e:
        raise _err("the public key from the device cannot be read (%s)" % e,
                   "无法读取设备返回的公钥（%s）" % e) from None
    raise _err("unknown algorithm %02X" % algo, "未知算法 %02X" % algo, cls=NotSupported)


def _pem(public_key):
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def _spki(public_key):
    return stdformats._spki(public_key)


def _public_fields(data, what, what_zh):
    items = parse_tlvs(data, what, what_zh)
    if len(items) == 1 and items[0][0] == 0x7F49:
        items = parse_tlvs(items[0][1], what, what_zh)
    return dict(items)


def parse_subject(subject):
    """x509.Name of a subject: an x509.Name, an RFC 4514 string ("CN=Alice,
    O=Example"), or a plain name (the common name)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    if isinstance(subject, x509.Name):
        name = subject
    else:
        text = str(subject or "").strip()
        try:
            if "=" in text:
                name = x509.Name.from_rfc4514_string(text)
            else:
                name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)]) if text else x509.Name([])
        except ValueError as e:
            raise _err("the subject %r cannot be used (%s)" % (display_name(text), e),
                       "主题 %r 无法使用（%s）" % (display_name(text), e)) from None
    if not list(name):
        raise _err("the subject is empty", "主题为空")
    return name


def _hash(algo):
    from cryptography.hazmat.primitives import hashes
    if algo in _RSA or algo == 0x11:
        return hashes.SHA256()
    if algo == 0x14:
        return hashes.SHA384()
    return None                 # Ed25519 signs the message itself


_dummies = {}
_dummy_lock = threading.Lock()


def _dummy_key(algo):
    """A throwaway private key of the type of algo: it signs nothing that is
    kept, it only gives cryptography's builders the signature algorithm."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    kind = "rsa" if algo in _RSA else algo
    with _dummy_lock:
        key = _dummies.get(kind)
        if key is None:
            if kind == "rsa":
                key = rsa.generate_private_key(65537, 2048)
            elif algo in _EC:
                key = ec.generate_private_key(getattr(ec, _EC[algo])())
            elif algo == _ED25519:
                key = ed25519.Ed25519PrivateKey.generate()
            else:
                raise _err("an %s key cannot sign" % ALGORITHM_LABELS.get(ALGORITHM_NAMES.get(algo), "%02X" % algo),
                           "%s 密钥不能签名" % ALGORITHM_LABELS.get(ALGORITHM_NAMES.get(algo), "%02X" % algo),
                           cls=NotSupported)
            _dummies[kind] = key
        return key


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(tag, value):
    return bytes([tag]) + _der_len(len(value)) + bytes(value)


def _der_read(buf, pos):
    """(tag, start of the value, end of the value) of the DER item at pos."""
    if pos + 2 > len(buf):
        raise ValueError("truncated DER")
    tag, n = buf[pos], buf[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        if not 1 <= k <= 4 or pos + k > len(buf):
            raise ValueError("bad DER length")
        n, pos = int.from_bytes(buf[pos:pos + k], "big"), pos + k
    if pos + n > len(buf):
        raise ValueError("truncated DER")
    return tag, pos, pos + n


def der_sequence_items(der):
    """The encoded items of a DER SEQUENCE (the whole of der)."""
    der = bytes(der)
    tag, start, end = _der_read(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("not one DER SEQUENCE")
    out, pos = [], start
    while pos < end:
        _, _, e = _der_read(der, pos)
        out.append(der[pos:e])
        pos = e
    return out


def signature_payload(algo, message):
    """What the card signs for message with a key of PIV algorithm algo
    (GENERAL AUTHENTICATE 81): RSA: the EMSA-PKCS1-v1_5 block of the SHA-256
    digest (the card does the raw RSA operation); ECC: the SHA-256 (P-256) or
    SHA-384 (P-384) digest (the card answers a DER ECDSA signature);
    Ed25519: the message itself."""
    message = bytes(message)
    if algo in _RSA:
        k = stdformats.PIV_RSA_BITS[algo] // 8
        info = _SHA256_INFO + hashlib.sha256(message).digest()
        return b"\x00\x01" + b"\xff" * (k - len(info) - 3) + b"\x00" + info
    if algo in _EC:
        return hashlib.new("sha256" if algo == 0x11 else "sha384", message).digest()
    if algo == _ED25519:
        return message
    raise _err("an %s key cannot sign" % ALGORITHM_LABELS.get(ALGORITHM_NAMES.get(algo), "%02X" % algo),
               "%s 密钥不能签名" % ALGORITHM_LABELS.get(ALGORITHM_NAMES.get(algo), "%02X" % algo), cls=NotSupported)


def verify_signature(public_key, algo, message, signature):
    """Whether signature (as the card answered it) is right for message."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    try:
        if algo in _RSA:
            public_key.verify(signature, message, padding.PKCS1v15(), _hash(algo))
        elif algo in _EC:
            public_key.verify(signature, message, ec.ECDSA(_hash(algo)))
        else:
            public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _check_days(days):
    if type(days) is not int or not 1 <= days <= DAYS_MAX:
        raise _err("the validity must be 1 to %d days" % DAYS_MAX, "有效期须为 1 到 %d 天" % DAYS_MAX)


def certificate_tbs(public_key, algo, subject, days, now=None, serial=None):
    """(to-be-signed certificate, signature AlgorithmIdentifier) of a
    self-signed certificate for public_key (of PIV algorithm algo): subject
    and issuer subject (parse_subject), valid from now for days days, a
    random serial number, no extensions (as ykman makes them)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    _check_days(days)
    name = parse_subject(subject)
    now = now or datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(public_key)
               .serial_number(serial or x509.random_serial_number())
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=days)))
    cert = builder.sign(_dummy_key(algo), _hash(algo))
    return cert.tbs_certificate_bytes, der_sequence_items(cert.public_bytes(serialization.Encoding.DER))[1]


def csr_info(public_key, algo, subject):
    """(CertificationRequestInfo, signature AlgorithmIdentifier) of a
    certificate signing request for public_key (RFC 2986: version 0, subject,
    the key, no attributes)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    name = parse_subject(subject)
    info = _der(0x30, b"\x02\x01\x00" + name.public_bytes() + _spki(public_key) + b"\xa0\x00")
    dummy = x509.CertificateSigningRequestBuilder().subject_name(name).sign(_dummy_key(algo), _hash(algo))
    return info, der_sequence_items(dummy.public_bytes(serialization.Encoding.DER))[1]


def assemble_signed(tbs, sig_alg, signature):
    """SEQUENCE { tbs, signature algorithm, BIT STRING signature }: a
    certificate (RFC 5280) or a request (RFC 2986)."""
    return _der(0x30, bytes(tbs) + bytes(sig_alg) + _der(0x03, b"\x00" + bytes(signature)))


def certificate_info(der, public_key=None):
    """{subject, issuer, serial (hex), not_before, not_after (aware
    datetimes), pem, matches_key (bool, None without public_key), error
    (None, or why the certificate cannot be read)} of a DER certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    try:
        c = x509.load_der_x509_certificate(bytes(der))
        info = {"subject": display_name(c.subject.rfc4514_string()),
                "issuer": display_name(c.issuer.rfc4514_string()),
                "serial": "%X" % c.serial_number,
                "not_before": c.not_valid_before_utc, "not_after": c.not_valid_after_utc,
                "pem": c.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                "matches_key": None, "error": None}
        if public_key is not None:
            info["matches_key"] = _spki(c.public_key()) == _spki(public_key)
        return info
    except (ValueError, TypeError) as e:
        return {"subject": None, "issuer": None, "serial": None, "not_before": None, "not_after": None, "pem": None,
                "matches_key": None, "error": "unreadable certificate (%s)" % e}


def load_certificates(data):
    """Certificates (cryptography) of PEM (one or more) or DER data."""
    from cryptography import x509
    data = data.encode("ascii", "replace") if isinstance(data, str) else bytes(data)
    try:
        if b"-----BEGIN" in data:
            certs = x509.load_pem_x509_certificates(data)
        else:
            certs = [x509.load_der_x509_certificate(data)]
    except ValueError as e:
        raise _err("not a certificate (PEM or DER): %s" % e, "不是证书（PEM 或 DER）：%s" % e) from None
    if not certs:
        raise _err("no certificate in the data", "数据中没有证书")
    return certs


# ----------------------------------------------------------------------------
# Card access
# ----------------------------------------------------------------------------

def _check(sw, en, zh, texts=None):
    if sw != 0x9000:
        texts = dict(texts or {})
        texts.setdefault(0x6982, ("not authenticated (management key or PIN)", "未认证（管理密钥或 PIN）"))
        raise sw_error("PIV: " + en, sw, "PIV：" + zh, texts)


def _metadata(card, ref):
    """GET METADATA of a key, the PIN, the PUK or the management key: {tag:
    value}, None when there is no such key."""
    resp, sw = send(card, INS_METADATA, 0x00, ref)
    if sw in (0x6A88, 0x6A82):
        return None
    _check(sw, "metadata of %02X" % ref, "%02X 的元数据" % ref)
    return dict(parse_tlvs(resp, "PIV metadata", "PIV 元数据"))


def _byte(meta, tag, default=0, index=0):
    """Byte index of the value of tag in a metadata map, default when absent."""
    value = (meta or {}).get(tag) or b""
    return value[index] if len(value) > index else default


def _key_public(meta, slot):
    algo = _byte(meta, 0x01)
    if 0x04 not in meta:
        raise _err("the device gives no public key for slot %02X" % slot, "设备未提供槽位 %02X 的公钥" % slot)
    return algo, public_key_object(algo, _public_fields(meta[0x04], "PIV public key", "PIV 公钥"))


def _read_certificate(card, slot):
    try:
        return keyio._piv_certificate(card, slot)
    except keyio.KeyTransferError as e:
        raise _err(str(e).replace("PIV certificate: ", "certificate of slot %02X: " % slot),
                   "槽位 %02X 的证书无法读取" % slot, getattr(e, "sw", None)) from None


def _write_certificate(card, slot, der):
    obj = tlv(0x5C, keyio.piv_object_id(slot).to_bytes(3, "big"))
    body = tlv(0x53, tlv(0x70, der) + tlv(0x71, b"\x00") + tlv(0xFE)) if der else tlv(0x53)
    _, sw = send(card, INS_PUT_DATA, 0x3F, 0xFF, obj + body)
    _check(sw, "writing the certificate of slot %02X" % slot if der else
           "deleting the certificate of slot %02X" % slot,
           "写入槽位 %02X 的证书" % slot if der else "删除槽位 %02X 的证书" % slot)


def _pin_error(ref, sw, what_en=None, what_zh=None):
    en, zh = _PIN_NAMES[ref]
    if sw & 0xFFF0 == 0x63C0:
        n = sw & 0xF
        return WrongSecret("PIV: wrong %s, %d tries left (SW %04X)" % (en, n, sw), sw,
                           "PIV：%s错误，还剩 %d 次（SW %04X）" % (zh, n, sw), retries=n)
    if sw == 0x6983:
        hint = ((" (unblock it with the PUK)", "（请用 PUK 解锁）") if ref == PIN_REF else
                (" (only a reset of the PIV application helps once the PIN is blocked too)",
                 "（PIN 也锁定时只能重置 PIV 应用）"))
        return SecretBlocked("PIV: the %s is blocked%s (SW %04X)" % (en, hint[0], sw), sw,
                             "PIV：%s已锁定%s（SW %04X）" % (zh, hint[1], sw))
    return sw_error("PIV: %s" % (what_en or en), sw, "PIV：%s" % (what_zh or zh))


def _verify_pin(card, pin):
    data = pin_block(pin, PIN_REF)
    try:
        _, sw = send(card, INS_VERIFY, 0x00, PIN_REF, bytes(data))
    finally:
        wipe(data)
    if sw != 0x9000:
        raise _pin_error(PIN_REF, sw)


def _mutual_auth(card, algo, key):
    """Mutual authentication with the management key (SP 800-73-4 part 2,
    appendix A): the card proves it knows the key too."""
    if MGMT_KEY_SIZES.get(algo) != len(key):
        raise _err("the device's management key is %s (%d bytes); the key given has %d bytes" % (
            MGMT_ALGORITHM_NAMES.get(algo, "%02X" % algo).upper(), MGMT_KEY_SIZES.get(algo, 0), len(key)),
            "设备的管理密钥为 %s（%d 字节）；给出的密钥为 %d 字节" % (
            MGMT_ALGORITHM_NAMES.get(algo, "%02X" % algo).upper(), MGMT_KEY_SIZES.get(algo, 0), len(key)),
            cls=WrongSecret)
    size = 8 if algo == 0x03 else 16
    resp, sw = send(card, INS_AUTHENTICATE, algo, MGMT_SLOT, tlv(0x7C, tlv(0x80)))
    _check(sw, "management key", "管理密钥")
    witness = dict(parse_tlvs(dict(parse_tlvs(resp, "PIV", "PIV")).get(0x7C, b""), "PIV", "PIV")).get(0x80, b"")
    if len(witness) != size:
        raise _err("malformed answer to the management key authentication", "管理密钥认证的应答格式错误")
    challenge = os.urandom(size)
    k = bytes(key)
    resp, sw = send(card, INS_AUTHENTICATE, algo, MGMT_SLOT,
                    tlv(0x7C, tlv(0x80, keyio._piv_crypt(algo, k, witness, False)) + tlv(0x81, challenge)))
    if sw == 0x6982:
        raise _err("wrong management key", "管理密钥错误", sw, WrongSecret)
    _check(sw, "management key", "管理密钥")
    theirs = dict(parse_tlvs(dict(parse_tlvs(resp, "PIV", "PIV")).get(0x7C, b""), "PIV", "PIV")).get(0x82, b"")
    if not hmac.compare_digest(theirs, keyio._piv_crypt(algo, k, challenge, True)):
        raise _err("the device's answer does not prove it holds this management key",
                   "设备的应答无法证明其持有此管理密钥")


def _card_sign(card, slot, algo, pin_policy, payload, pin):
    """The card's signature of payload (signature_payload) with the key of
    slot: VERIFY PIN right before (a PIN-always key needs it so; a key with
    PIN policy never is used without, whatever pin is), GENERAL
    AUTHENTICATE."""
    if pin_policy != PIN_POLICIES["never"]:
        if pin is None:
            raise _err("signing with the key of slot %02X needs the PIV PIN" % slot,
                       "使用槽位 %02X 的密钥签名需要 PIV PIN" % slot, cls=AuthRequired)
        _verify_pin(card, pin)
    resp, sw = send(card, INS_AUTHENTICATE, algo, slot, tlv(0x7C, tlv(0x82) + tlv(0x81, payload)))
    _check(sw, "signing with the key of slot %02X" % slot, "用槽位 %02X 的密钥签名" % slot,
           {0x6982: ("the PIN is not verified", "PIN 未验证")})
    sig = dict(parse_tlvs(dict(parse_tlvs(resp, "PIV", "PIV")).get(0x7C, b""), "PIV", "PIV")).get(0x82)
    if not sig:
        raise _err("the device answered no signature", "设备没有返回签名")
    return sig


def _supported(answer):
    """PIV algorithms of the application property template (SELECT answer
    61 { AC { 80 algorithm ... } }); None when it lists none."""
    try:
        top = dict(parse_tlvs(answer, "PIV", "PIV"))
        tpl = dict(parse_tlvs(top.get(0x61, b""), "PIV", "PIV"))
        algos = [v[0] for t, v in parse_tlvs(tpl.get(0xAC, b""), "PIV", "PIV") if t == 0x80 and v]
    except ManagerError:
        return None
    return algos or None


# ----------------------------------------------------------------------------
# Manager
# ----------------------------------------------------------------------------

class PivManager:
    """The PIV application of the device of m (a Management). Every method is
    one operation (its own PC/SC transaction). Errors: ManagerError
    subclasses (PivError, WrongSecret with .retries, SecretBlocked,
    AuthRequired, NotSupported)."""

    def __init__(self, m):
        self.m = m
        self._key = None            # bytearray: the management key authenticate() checked

    @contextmanager
    def _session(self):
        try:
            with applet(self.m, PIV_AID, "PIV") as answer:
                yield self.m.card, answer
        except CardConnectionException as e:
            raise _err("the device cannot be reached (%s)" % e, "无法访问设备（%s）" % e) from None

    # -- management key ------------------------------------------------------
    @property
    def authenticated(self):
        """Whether a management key was given (authenticate()) and is kept."""
        return self._key is not None

    def forget(self):
        """Wipes the kept management key."""
        if self._key is not None:
            wipe(self._key)
        self._key = None

    def authenticate(self, mgmt_key=None):
        """Checks the management key (bytes or hexadecimal text; None: the
        default one, when the device says it still has it) with the device
        and keeps it for the administrative operations of this manager.
        WrongSecret when it is wrong, AuthRequired when None was given and
        the device's key is not the default one."""
        key = None if mgmt_key is None else parse_management_key(mgmt_key)
        try:
            with self._session() as (card, _):
                algo, default = self._mgmt_state(card)
                if key is None:
                    if default is False:
                        raise _err("the management key is not the default one: enter it", "管理密钥不是默认值：请输入",
                                   cls=AuthRequired)
                    key = bytearray(DEFAULT_MGMT_KEY)
                _mutual_auth(card, algo, key)
        except BaseException:
            if key is not None:
                wipe(key)
            raise
        self.forget()
        self._key = key

    def _mgmt_state(self, card):
        """(algorithm, default: bool or None) of the device's management
        key; without metadata (older firmware) 3DES, default unknown."""
        meta = _metadata(card, MGMT_SLOT)
        if meta is None:
            return 0x03, None
        return _byte(meta, 0x01, 0x03), (_byte(meta, 0x05) == 1) if 0x05 in meta else None

    def _admin(self, card):
        """Authenticates with the kept management key, else the default one
        when the device still has it (AuthRequired otherwise). A kept key the
        device refuses is forgotten."""
        algo, default = self._mgmt_state(card)
        if self._key is not None:
            try:
                _mutual_auth(card, algo, self._key)
            except WrongSecret:
                self.forget()
                raise
            return
        if default is False:
            raise _err("this needs the management key (it is not the default one)",
                       "此操作需要管理密钥（它不是默认值）", cls=AuthRequired)
        key = bytearray(DEFAULT_MGMT_KEY)
        try:
            _mutual_auth(card, algo, key)
        finally:
            wipe(key)

    def set_management_key(self, new_key, algorithm="aes192", touch=False):
        """Replaces the management key (after authenticating with the current
        one) by new_key (bytes or hexadecimal text) of algorithm (3des,
        aes128, aes192, aes256); touch: every authentication with it then
        needs a physical touch. The new key is kept for this manager."""
        algo = _mgmt_algorithm(algorithm)
        key = parse_management_key(new_key, algo)
        data = bytearray([algo, MGMT_SLOT, len(key)]) + key
        try:
            with self._session() as (card, _):
                self._admin(card)
                _, sw = send(card, INS_SET_MGMT_KEY, 0xFF, 0xFE if touch else 0xFF, bytes(data))
            _check(sw, "setting the management key", "设置管理密钥")
        except BaseException:
            wipe(key)
            raise
        finally:
            wipe(data)
        self.forget()
        self._key = key

    # -- information ---------------------------------------------------------
    def status(self):
        """{version ("5.7.0"), serial (int), pin_retries, pin_attempts,
        pin_default, puk_retries, puk_attempts, puk_default,
        mgmt_key_algorithm ("3des", "aes128", ...), mgmt_key_default (bool or
        None), mgmt_key_touch (bool), algorithms (names the device generates),
        slots: {slot: {name, has_key, algorithm (ALGORITHMS name), pin_policy
        ("never" / "once" / "always"), touch_policy ("never" / "always" /
        "cached"), origin ("generated" / "imported" / None), public_key (PEM),
        certificate (certificate_info) or None}} for 9A 9C 9D 9E 82-95}; the
        fields of an empty slot are None."""
        with self._session() as (card, answer):
            ver, sw = send(card, INS_VERSION)
            ser, sw2 = send(card, INS_SERIAL)
            pin, puk, mgmt = (_metadata(card, r) for r in (PIN_REF, PUK_REF, MGMT_SLOT))
            raw = {slot: (_metadata(card, slot), _read_certificate(card, slot)) for slot in SLOTS}
        slots = {slot: self._slot_info(slot, meta, cert) for slot, (meta, cert) in raw.items()}
        supported = _supported(answer) or []

        def flag(meta):
            return (_byte(meta, 0x05) == 1) if meta and 0x05 in meta else None

        def tries(meta, index):
            return _byte(meta, 0x06, None, index) if meta and len(meta.get(0x06) or b"") >= 2 else None
        return {
            "version": ".".join(str(b) for b in ver[:3]) if sw == 0x9000 and len(ver) >= 3 else None,
            "serial": int.from_bytes(ser[:4], "big") if sw2 == 0x9000 and len(ser) >= 4 else None,
            "pin_retries": tries(pin, 1), "pin_attempts": tries(pin, 0), "pin_default": flag(pin),
            "puk_retries": tries(puk, 1), "puk_attempts": tries(puk, 0), "puk_default": flag(puk),
            "mgmt_key_algorithm": MGMT_ALGORITHM_NAMES.get(_byte(mgmt, 0x01, 0x03)),
            "mgmt_key_default": flag(mgmt),
            "mgmt_key_touch": _byte(mgmt, 0x02, 1, 1) not in (0, 1),
            "algorithms": [ALGORITHM_NAMES[a] for a in supported if a in ALGORITHM_NAMES],
            "slots": slots,
        }

    @staticmethod
    def _slot_info(slot, meta, cert):
        info = {"name": slot_name(slot), "name_zh": slot_name(slot, True), "has_key": meta is not None,
                "algorithm": None, "pin_policy": None, "touch_policy": None, "origin": None, "public_key": None,
                "certificate": None}
        pub = None
        if meta is not None:
            algo = _byte(meta, 0x01)
            info.update({"algorithm": ALGORITHM_NAMES.get(algo, "%02X" % algo),
                         "pin_policy": PIN_POLICY_NAMES.get(_byte(meta, 0x02, None)),
                         "touch_policy": TOUCH_POLICY_NAMES.get(_byte(meta, 0x02, None, 1)),
                         "origin": ORIGINS.get(_byte(meta, 0x03))})
            if 0x04 in meta:
                try:
                    pub = _key_public(meta, slot)[1]
                    info["public_key"] = _pem(pub)
                except ManagerError:
                    pub = None
        if cert:
            info["certificate"] = certificate_info(cert, pub)
        return info

    def supported_algorithms(self):
        """Names of the algorithms the device generates (its application
        property template; without one, those this firmware generates)."""
        with self._session() as (_, answer):
            listed = _supported(answer)
        if listed is None:
            listed = [ALGORITHMS[n] for n in ("rsa1024", "rsa2048", "eccp256", "eccp384")]
        return [ALGORITHM_NAMES[a] for a in listed if a in ALGORITHM_NAMES]

    # -- keys ------------------------------------------------------------------
    def generate(self, slot, algorithm, pin_policy="default", touch_policy="default", replace=False):
        """Generates a key of algorithm (ALGORITHMS name) in slot, with a PIN
        and touch policy (names of PIN_POLICIES / TOUCH_POLICIES; default:
        the slot's usual one). A key or certificate already in the slot is
        replaced only with replace=True (the device then also makes a new
        certificate of its own for the slot, none for X25519). Returns the
        public key (PEM)."""
        slot = slot_ref(slot)
        algo = _algorithm(algorithm)
        pp = _policy(pin_policy, PIN_POLICIES, "PIN policy", "PIN 策略")
        tp = _policy(touch_policy, TOUCH_POLICIES, "touch policy", "触摸策略")
        with self._session() as (card, answer):
            listed = _supported(answer)
            if listed is not None and algo not in listed:
                raise _err("the device does not generate %s keys" % ALGORITHM_LABELS[ALGORITHM_NAMES[algo]],
                           "设备不能生成 %s 密钥" % ALGORITHM_LABELS[ALGORITHM_NAMES[algo]], 0x6A81, NotSupported)
            if (_metadata(card, slot) is not None or _read_certificate(card, slot)) and not replace:
                raise _err("slot %02X holds a key or certificate; replace it explicitly" % slot,
                           "槽位 %02X 中已有密钥或证书；如需替换请明确确认" % slot, 0x6A89)
            self._admin(card)
            spec = tlv(0x80, bytes([algo]))
            if pp:
                spec += tlv(0xAA, bytes([pp]))
            if tp:
                spec += tlv(0xAB, bytes([tp]))
            resp, sw = send(card, INS_GENERATE, 0x00, slot, tlv(0xAC, spec))
            _check(sw, "key generation in slot %02X" % slot, "在槽位 %02X 生成密钥" % slot,
                   {0x6A81: ("the device does not generate this algorithm", "设备不能生成此算法的密钥")})
        return _pem(public_key_object(algo, _public_fields(resp, "PIV public key", "PIV 公钥")))

    def _slot_key(self, card, slot):
        """(algorithm, PIN policy, public key) of the key of slot."""
        meta = _metadata(card, slot)
        if meta is None:
            raise _err("slot %02X holds no key" % slot, "槽位 %02X 中没有密钥" % slot, 0x6A88)
        algo, pub = _key_public(meta, slot)
        return algo, _byte(meta, 0x02, PIN_POLICIES["once"]), pub

    def _signed(self, slot, pin, make, store=None, replace=False):
        """Something the card signs with the key of slot: make(public key,
        algo) gives (to-be-signed, signature algorithm), built outside the
        card transaction (a first one reads the key); the second checks that
        the key is still the same, signs (store: the DER is stored as the
        slot's certificate, after the management key), and the result is
        checked against the key."""
        with self._session() as (card, _):
            algo, _, pub = self._slot_key(card, slot)
        if algo == _X25519:
            raise _err("the X25519 key of slot %02X cannot sign" % slot, "槽位 %02X 的 X25519 密钥不能签名" % slot,
                       cls=NotSupported)
        tbs, sig_alg = make(pub, algo)
        payload = signature_payload(algo, tbs)
        with self._session() as (card, _):
            algo2, policy, pub2 = self._slot_key(card, slot)
            if algo2 != algo or _spki(pub2) != _spki(pub):
                raise _err("the key of slot %02X changed meanwhile; try again" % slot,
                           "槽位 %02X 的密钥已被更改；请重试" % slot)
            if store and _read_certificate(card, slot) and not replace:
                raise _err("slot %02X holds a certificate; replace it explicitly" % slot,
                           "槽位 %02X 中已有证书；如需替换请明确确认" % slot, 0x6A89)
            if store:
                self._admin(card)       # before the PIN: a PIN-always key needs VERIFY right before signing
            sig = _card_sign(card, slot, algo, policy, payload, pin)
            if not verify_signature(pub, algo, tbs, sig):
                raise _err("the signature of the device does not verify with the key of slot %02X" % slot,
                           "设备的签名无法用槽位 %02X 的公钥验证" % slot)
            der = assemble_signed(tbs, sig_alg, sig)
            if store:
                store(card, der)
        return der

    def self_sign(self, slot, subject, days, pin, replace=False):
        """A self-signed certificate for the key of slot, signed by the card
        (subject: RFC 4514 text or a plain name; valid days days from now),
        stored as the slot's certificate; a certificate already there is
        replaced only with replace=True (the device makes one of its own when
        it generates a key). Returns it as PEM."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        slot = slot_ref(slot)
        parse_subject(subject)
        _check_days(days)

        def make(pub, algo):
            return certificate_tbs(pub, algo, subject, days)

        der = self._signed(slot, pin, make, store=lambda card, d: _write_certificate(card, slot, d), replace=replace)
        return x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode("ascii")

    def csr(self, slot, subject, pin):
        """A certificate signing request (PKCS#10) for the key of slot, signed
        by the card. Returns it as PEM."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        slot = slot_ref(slot)
        parse_subject(subject)
        der = self._signed(slot, pin, lambda pub, algo: csr_info(pub, algo, subject))
        try:
            req = x509.load_der_x509_csr(der)
            ok = req.is_signature_valid
        except ValueError:
            ok = False
        if not ok:
            raise _err("the request made with the key of slot %02X is not valid" % slot,
                       "用槽位 %02X 的密钥生成的请求无效" % slot)
        return req.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def attest(self, slot):
        """Attestation certificate (PEM) of a key generated on the device,
        signed by the device's attestation key (F9)."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        slot = slot_ref(slot)
        with self._session() as (card, _):
            resp, sw = send(card, INS_ATTEST, slot, 0x00)
        _check(sw, "attestation of slot %02X" % slot, "槽位 %02X 的证明" % slot,
               {0x6A80: ("only a key generated on the device can be attested", "只有在设备上生成的密钥才能被证明"),
                0x6A88: ("the slot holds no key", "该槽位中没有密钥")})
        try:
            cert = x509.load_der_x509_certificate(resp)
        except ValueError as e:
            raise _err("malformed attestation certificate (%s)" % e, "证明证书格式错误（%s）" % e) from None
        return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def delete_key(self, slot, with_certificate=False):
        """Deletes the key of slot (MOVE KEY to FF); with_certificate: its
        certificate too."""
        slot = slot_ref(slot)
        with self._session() as (card, _):
            self._slot_key(card, slot)
            cert = _read_certificate(card, slot) if with_certificate else None
            self._admin(card)
            _, sw = send(card, INS_MOVE_KEY, 0xFF, slot)
            _check(sw, "deleting the key of slot %02X" % slot, "删除槽位 %02X 的密钥" % slot)
            if cert:
                _write_certificate(card, slot, None)

    def move_key(self, src, dst, replace=False, with_certificate=True):
        """Moves the key of slot src to slot dst (with its PIN and touch
        policy and origin); with_certificate: src's certificate goes with it
        (a certificate in dst is removed). A key (or, with_certificate, a
        certificate) in dst is replaced only with replace=True."""
        src, dst = slot_ref(src), slot_ref(dst)
        if src == dst:
            raise _err("the source and destination slots are the same", "源槽位和目标槽位相同")
        with self._session() as (card, _):
            self._slot_key(card, src)
            there = _metadata(card, dst) is not None
            cert_src = _read_certificate(card, src) if with_certificate else None
            cert_dst = _read_certificate(card, dst) if with_certificate else None
            if (there or cert_dst) and not replace:
                raise _err("slot %02X holds a key or certificate; replace it explicitly" % dst,
                           "槽位 %02X 中已有密钥或证书；如需替换请明确确认" % dst, 0x6A89)
            self._admin(card)
            _, sw = send(card, INS_MOVE_KEY, dst, src)
            _check(sw, "moving the key of slot %02X to %02X" % (src, dst), "将槽位 %02X 的密钥移到 %02X" % (src, dst))
            if cert_src:
                _write_certificate(card, dst, cert_src)
                _write_certificate(card, src, None)
            elif cert_dst:
                _write_certificate(card, dst, None)

    # -- certificates ------------------------------------------------------------
    def import_certificate(self, slot, data, replace=False, verify=True):
        """Stores a certificate (PEM or DER; of several, the one for the
        slot's key) as the certificate of slot. verify: refused when the slot
        holds a key the certificate is not for. A certificate already there
        is replaced only with replace=True. Returns certificate_info."""
        from cryptography.hazmat.primitives import serialization
        slot = slot_ref(slot)
        certs = load_certificates(data)
        with self._session() as (card, _):
            meta = _metadata(card, slot)
            pub = _key_public(meta, slot)[1] if meta is not None else None
            cert = certs[0]
            if pub is not None:
                cert = next((c for c in certs if _spki(c.public_key()) == _spki(pub)), None)
                if cert is None:
                    if verify:
                        raise _err("the certificate is not for the key in slot %02X" % slot,
                                   "该证书与槽位 %02X 中的密钥不匹配" % slot)
                    cert = certs[0]
            if _read_certificate(card, slot) and not replace:
                raise _err("slot %02X holds a certificate; replace it explicitly" % slot,
                           "槽位 %02X 中已有证书；如需替换请明确确认" % slot, 0x6A89)
            der = cert.public_bytes(serialization.Encoding.DER)
            self._admin(card)
            _write_certificate(card, slot, der)
        return certificate_info(der, pub)

    def export_certificate(self, slot):
        """The certificate of slot as PEM (PivError 6A82 when it has none)."""
        slot = slot_ref(slot)
        with self._session() as (card, _):
            der = _read_certificate(card, slot)
        if not der:
            raise _err("slot %02X holds no certificate" % slot, "槽位 %02X 中没有证书" % slot, 0x6A82)
        info = certificate_info(der)
        if info["pem"] is None:
            raise _err("the certificate of slot %02X cannot be read (%s)" % (slot, info["error"]),
                       "槽位 %02X 的证书无法读取" % slot)
        return info["pem"]

    def delete_certificate(self, slot):
        """Deletes the certificate of slot (PivError 6A82 when it has none)."""
        slot = slot_ref(slot)
        with self._session() as (card, _):
            if not _read_certificate(card, slot):
                raise _err("slot %02X holds no certificate" % slot, "槽位 %02X 中没有证书" % slot, 0x6A82)
            self._admin(card)
            _write_certificate(card, slot, None)

    # -- PIN, PUK ----------------------------------------------------------------
    def change_pin(self, old, new):
        """Changes the PIN (6 to 8 characters)."""
        self._change(PIN_REF, INS_CHANGE_REFERENCE, old, new, PIN_REF)

    def change_puk(self, old, new):
        """Changes the PUK (6 to 8 characters)."""
        self._change(PUK_REF, INS_CHANGE_REFERENCE, old, new, PUK_REF)

    def unblock_pin(self, puk, new_pin):
        """Sets a new PIN with the PUK (and the PIN's retry counter back)."""
        self._change(PUK_REF, INS_RESET_RETRY, puk, new_pin, PIN_REF)

    def _change(self, ref, ins, old, new, new_ref):
        new_b = pin_block(new, new_ref, new=True)
        old_b = pin_block(old, ref)
        data = old_b + new_b
        try:
            with self._session() as (card, _):
                _, sw = send(card, ins, 0x00, PIN_REF if ins == INS_RESET_RETRY else ref, bytes(data))
        finally:
            wipe(old_b)
            wipe(new_b)
            wipe(data)
        if sw != 0x9000:
            what = {PIN_REF: ("changing the PIN", "更改 PIN"), PUK_REF: ("changing the PUK", "更改 PUK")}[ref] \
                if ins == INS_CHANGE_REFERENCE else ("unblocking the PIN", "解锁 PIN")
            raise _pin_error(ref, sw, *what)

    # -- reset -------------------------------------------------------------------
    def reset(self):
        """Factory state of the PIV application (a touch): every PIV key and
        certificate, the PIN (123456), PUK (12345678) and management key
        (the default 3DES key) are reset; the attestation key stays. The
        device allows it once the PIN and the PUK are blocked: they are
        blocked first by wrong attempts (if the touch is then missing they
        stay blocked until a reset succeeds)."""
        with self._session() as (card, _):
            _block(card, INS_VERIFY, PIN_REF)
            _block(card, INS_RESET_RETRY, PUK_REF)
            _, sw = send(card, INS_RESET, 0x00, 0x00)
            _check(sw, "reset", "重置", {0x6A80: ("the PIN and the PUK are not both blocked", "PIN 和 PUK 未同时锁定")})
        self.forget()               # the device has the default key again


def _block(card, ins, ref):
    """Wrong PIN (VERIFY) or PUK (RESET RETRY COUNTER) attempts until the
    device reports it blocked. The value tried is all FF, which no PIN or PUK
    can be (at least 6 other bytes)."""
    wrong = b"\xff" * PIN_LEN + (b"000000\xff\xff" if ins == INS_RESET_RETRY else b"")
    for _ in range(32):
        _, sw = send(card, ins, 0x00, PIN_REF, wrong)
        if sw == 0x6983:
            return
        if sw & 0xFFF0 != 0x63C0:
            en, zh = _PIN_NAMES[ref]
            raise _err("the %s could not be blocked for the reset (%s, SW %04X)" % (en, sw_text(sw), sw),
                       "无法为重置锁定%s（%s，SW %04X）" % (zh, sw_text(sw, True), sw), sw)
    raise _err("the %s is not blocked after 32 wrong attempts" % _PIN_NAMES[ref][0],
               "32 次错误尝试后%s仍未锁定" % _PIN_NAMES[ref][1])


__all__ = ["PivManager", "PivError", "ALGORITHMS", "ALGORITHM_NAMES", "ALGORITHM_LABELS", "MGMT_ALGORITHMS",
           "PIN_POLICIES", "TOUCH_POLICIES", "SLOTS", "SLOT_NAMES", "slot_name", "slot_ref", "pin_block",
           "parse_management_key", "generate_management_key", "parse_subject", "signature_payload",
           "verify_signature", "certificate_tbs", "csr_info", "assemble_signed", "certificate_info",
           "load_certificates", "public_key_object", "der_sequence_items"]
