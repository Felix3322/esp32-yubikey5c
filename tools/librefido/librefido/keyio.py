"""Single-key transfer with a device (docs/KEY_TRANSFER.md), for the command
line and the GUI: one key of one application out to a SingleKey, and one
key onto a device.

FIDO credentials and OTP slots go through the management applet
(Management.export_key / import_key: a touch and the FIDO PIN). OATH
accounts, OpenPGP keys and PIV keys are added through their own
applications with their own authentication, as on any card of the kind:
YKOATH PUT (after VALIDATE with the OATH password), OpenPGP PUT DATA and
IMPORT DATA (Admin PIN), PIV IMPORT ASYMMETRIC KEY and PUT DATA (management
key). A key already on the device is never replaced unless the caller says
so: the device is asked first.
"""

import gzip
import hashlib
import hmac
import io
import os
import time
from contextlib import contextmanager

from smartcard.Exceptions import CardConnectionException

from . import __version__, stdformats
from .keyfile import KeyFileError, SingleKey, check_record
from .mgmt import APPS, PinRequired, display_name
from .pcsc import MGMT_AID, ApduError

OATH_AID = bytes.fromhex("A0000005272101")
OPENPGP_AID = bytes.fromhex("D27600012401")
PIV_AID = bytes.fromhex("A000000308")

# YKOATH (pico-fido/src/fido/oath.c)
OATH_PUT, OATH_LIST, OATH_VALIDATE, OATH_SEND_REMAINING = 0x01, 0xA1, 0xA3, 0xA5
TAG_NAME, TAG_NAME_LIST, TAG_KEY, TAG_CHALLENGE, TAG_RESPONSE = 0x71, 0x72, 0x73, 0x74, 0x75
TAG_PROPERTY, TAG_IMF, TAG_ALGORITHM = 0x78, 0x7A, 0x7B
OATH_PROP_TOUCH = 0x02
OATH_ANSWER_MAX = 255 * 70      # a LIST of every account oath.c can hold (255 of names up to 64 bytes)
_OATH_HASHES = {1: "sha1", 2: "sha256", 3: "sha512"}

# OpenPGP card 3.4 (pico-openpgp: cmd_import_data.c, cmd_put_data.c, do.c)
PGP_KEY_REFS = stdformats.PGP_KEY_REFS
PGP_SLOT_NAMES = {1: "signature", 2: "decryption", 3: "authentication"}
_PGP_CRT = {1: 0xB6, 2: 0xB8, 3: 0xA4}
_PGP_DO_ALGO, _PGP_DO_FP, _PGP_DO_TIME, _PGP_DO_UIF = 0xC0, 0xC6, 0xCD, 0xD5      # + key ref
_PGP_DO_FPS, _PGP_DO_KEY_INFO, _PGP_DO_KDF = 0xC5, 0xDE, 0xF9

# PIV (SP 800-73-4; pico-openpgp/src/openpgp/piv.c)
PIV_INS_GET_DATA, PIV_INS_PUT_DATA, PIV_INS_AUTHENTICATE = 0xCB, 0xDB, 0x87
PIV_INS_METADATA, PIV_INS_IMPORT = 0xF7, 0xFE
PIV_MGMT_SLOT = 0x9B
PIV_3DES, PIV_AES128, PIV_AES192, PIV_AES256 = 0x03, 0x08, 0x0A, 0x0C
_PIV_MGMT_SIZES = {PIV_3DES: 24, PIV_AES128: 16, PIV_AES192: 24, PIV_AES256: 32}
PIV_DEFAULT_MGMT_KEY = bytes.fromhex("010203040506070801020304050607080102030405060708")
PIV_SLOTS = (0x9A, 0x9C, 0x9D, 0x9E) + tuple(range(0x82, 0x96))
PIV_CERT_MAX = 16 * 1024        # a decompressed certificate larger than this is refused

_SW_TEXT = {
    0x6700: "wrong length",
    0x6982: "a PIN, password or key is missing or wrong, or the device cannot check it now",
    0x6983: "blocked after too many wrong attempts",
    0x6984: "wrong password or data",
    0x6985: "not confirmed: touch the key when it blinks (or the key store is locked, or an operation is "
            "pending)",
    0x6986: "not allowed by this profile or build",
    0x6A80: "the device refused the data as invalid",
    0x6A81: "not supported by this device or firmware",
    0x6A82: "not found",
    0x6A84: "no space left on the device",
    0x6A86: "incorrect parameters",
    0x6A88: "no such key on the device",
    0x6A89: "a key is already there (replace it explicitly)",
    0x6D00: "the firmware does not support this command",
}


class KeyTransferError(Exception):
    """A key could not be exported or imported; sw: the device's status
    word, when it answered one."""

    def __init__(self, message, sw=None):
        super().__init__(message)
        self.sw = sw


def _sw_error(what, sw, text=None):
    if text is None:
        text = ("wrong PIN, %d tries left" % (sw & 0xF)) if sw & 0xFFF0 == 0x63C0 else _SW_TEXT.get(sw, "error")
    return KeyTransferError("%s: %s (SW %04X)" % (what, text, sw), sw)


def _app_name(app):
    if type(app) is int and 0 <= app < len(APPS):
        return APPS[app]
    if app in APPS:
        return app
    raise KeyTransferError("unknown application %r (one of %s)" % (app, ", ".join(APPS)))


# -- TLV -----------------------------------------------------------------------

def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82]) + n.to_bytes(2, "big")


def _tlv(tag, value=b""):
    value = bytes(value)
    return (tag.to_bytes(2, "big") if tag > 0xFF else bytes([tag])) + _ber_len(len(value)) + value


def _tlvs(data, what):
    """[(tag, value)] of BER-TLV data (tags of one or two bytes)."""
    out, i = [], 0
    try:
        while i < len(data):
            tag = data[i]
            i += 1
            if tag & 0x1F == 0x1F:
                tag, i = (tag << 8) | data[i], i + 1
            n = data[i]
            i += 1
            if n in (0x81, 0x82):
                k = n & 0x7F
                n, i = int.from_bytes(data[i:i + k], "big"), i + k
            elif n > 0x82:
                raise IndexError
            value = data[i:i + n]
            if len(value) != n:
                raise IndexError
            out.append((tag, bytes(value)))
            i += n
    except IndexError:
        raise KeyTransferError("%s: malformed answer from the device" % what)
    return out


# -- applications ----------------------------------------------------------------

@contextmanager
def _applet(m, aid, name):
    """The application aid of the device, selected inside one PC/SC
    transaction (no other program's commands in between). The management
    applet is selected again afterwards, which also ends what was
    authenticated in the application."""
    card = m.card
    with card.transaction():
        try:
            answer, _ = card.select(aid)
        except ApduError as e:
            raise KeyTransferError("the device has no %s application (SW %04X)" % (name, e.sw), e.sw)
        try:
            yield answer
        finally:
            try:
                card.select(MGMT_AID)
            except (ApduError, CardConnectionException):
                pass


def _send(card, ins, p1=0, p2=0, data=b""):
    """ISO command: (answer, status word), no exception for a status."""
    return card.transmit(0x00, ins, p1, p2, data, le=0, check=False)


def _oath_send(card, ins, p1=0, p2=0, data=b""):
    """YKOATH command: (answer, status word). A long answer continues with
    SEND REMAINING (61xx), which YKOATH pages itself: pcsc.Card would ask
    with GET RESPONSE, so this goes to the reader directly."""
    data = bytes(data)
    if len(data) > 255:
        raise KeyTransferError("OATH: command too long")
    resp, sw1, sw2 = card.conn.transmit([0x00, ins, p1, p2] + ([len(data)] + list(data) if data else []) + [0])
    out = bytes(resp)
    while sw1 == 0x61:
        if len(out) > OATH_ANSWER_MAX:
            raise KeyTransferError("OATH: the device answers without end")
        resp, sw1, sw2 = card.conn.transmit([0x00, OATH_SEND_REMAINING, 0x00, 0x00, 0x00])
        out += bytes(resp)
    return out, (sw1 << 8) | sw2


def _secret_bytes(value, what, hex_ok=False):
    if isinstance(value, str):
        if hex_ok:
            try:
                return bytes.fromhex(value)
            except ValueError:
                raise KeyTransferError("%s: not hexadecimal" % what)
        return value.encode("utf-8")
    return bytes(value)


# -- export ----------------------------------------------------------------------

def export_single(m, app, key_id, pin=None, no_pin=False, secret=None):
    """One key of the device (m, a Management) as a SingleKey: touch, the
    FIDO PIN when the profile has one (PinRequired otherwise, see
    Management.export_key) and for an OpenPGP key its Admin PIN (secret).
    A PIV key gets the certificate of its slot (record key 8)."""
    name = _app_name(app)
    if name == "openpgp" and not secret:
        raise KeyTransferError("exporting an OpenPGP key needs the OpenPGP Admin PIN")
    if name == "openpgp":
        # KEY_EXPORT checks the Admin PIN as VERIFY does
        with _applet(m, OPENPGP_AID, "OpenPGP"):
            secret = _pgp_admin_pin(m.card, secret)
    try:
        firmware = m.info().get("firmware")
        record = m.export_key(name, key_id, pin=pin, no_pin=no_pin, secret=secret)
    except PinRequired:
        raise
    except ApduError as e:
        texts = {0x6986: "exporting secret keys is not allowed by this profile or build (a secure or no-export "
                         "profile, or a HARDENED build)",
                 0x6A88: "no such key on the device (list the keys again)",
                 0x6A81: "this key cannot be exported (not supported by the firmware)",
                 0x6D00: "the firmware cannot export single keys (LibreFido 2.1.0 or newer)"}
        if name == "openpgp":
            # the FIDO PIN is checked first, then the Admin PIN: both answer alike
            texts[0x6983] = "a PIN is blocked (the FIDO PIN or the OpenPGP Admin PIN)"
            if e.sw & 0xFFF0 == 0x63C0:
                texts[e.sw] = "wrong PIN (the FIDO PIN or the OpenPGP Admin PIN), %d tries left" % (e.sw & 0xF)
        raise _sw_error("key export", e.sw, texts.get(e.sw)) from e
    try:
        check_record(name, record)
    except KeyFileError as e:
        raise KeyTransferError("key export: the device answered a record this tool cannot read (%s)" % e)
    if name == "piv":
        with _applet(m, PIV_AID, "PIV"):
            cert = _piv_certificate(m.card, record.get(1))
        if cert:
            record[8] = cert
    key = SingleKey(name, record, {"created": int(time.time()), "firmware": firmware, "tool": __version__})
    key.meta["label"] = describe(key)
    return key


# -- import ----------------------------------------------------------------------

def import_single(m, key, pin=None, no_pin=False, replace=False, target=None, oath_password=None,
                  otp_access_code=None, pgp_admin_pin=None, piv_mgmt_key=None, piv_slot=None, pgp_key_ref=None):
    """Adds key (a SingleKey) to the device of m (a Management); returns what
    was done, as text. replace: a key already where this one goes may be
    replaced (otherwise KeyTransferError, and nothing changes).
      fido:    the management applet (touch, FIDO PIN); refused by secure
               profiles and HARDENED builds.
      otp:     the management applet (touch, FIDO PIN); target: slot 1 or 2
               (default the record's), otp_access_code: of that slot when it
               has one.
      oath:    YKOATH PUT; oath_password when the application has one.
      openpgp: PUT DATA / IMPORT DATA with pgp_admin_pin; pgp_key_ref: "sig",
               "dec" or "aut" (default the record's).
      piv:     IMPORT ASYMMETRIC KEY with the management key piv_mgmt_key
               (bytes or hex; default: the default key, when the device says
               it has that one); piv_slot (default the record's); the
               certificate (record key 8) goes with it.
    PinRequired (FIDO PIN) is raised as by Management; everything else as
    KeyTransferError."""
    if not isinstance(key, SingleKey):
        raise TypeError("key must be a SingleKey")
    try:
        check_record(key.app, key.record)
    except KeyFileError as e:
        raise KeyTransferError("not a %s key: %s" % (key.app, e))
    if key.app in ("fido", "otp"):
        return _import_mgmt(m, key, pin, no_pin, replace, target, otp_access_code)
    if key.app == "oath":
        return _import_oath(m, key, replace, oath_password)
    if key.app == "openpgp":
        return _import_openpgp(m, key, replace, pgp_admin_pin, pgp_key_ref)
    return _import_piv(m, key, replace, piv_mgmt_key, piv_slot)


def _otp_slot(value):
    if isinstance(value, (bytes, bytearray)) and len(value) == 1:
        value = value[0]
    elif isinstance(value, str) and value.strip() in ("1", "2"):
        value = int(value)
    if value not in (1, 2) or type(value) is bool:
        raise KeyTransferError("OTP slot %r (1 or 2)" % (value,))
    return value


def _import_mgmt(m, key, pin, no_pin, replace, target, access_code):
    what = "%s import" % key.app.upper()
    texts = {0x6A80: "the device refused the key as invalid"}
    slot = None
    try:
        if key.app not in m.key_transfer()["import"]:
            raise KeyTransferError("%s: the firmware of this device cannot import %s keys (LibreFido 2.1.0 or "
                                   "newer)" % (what, key.app.upper()))
        if key.app == "fido":
            texts[0x6986] = "FIDO credentials cannot be imported into a secure profile or a HARDENED build " \
                            "(there they are always made on the device)"
            texts[0x6A89] = "a passkey with this credential ID, or for the same account of this site, is " \
                            "already on the device (replace it explicitly)"
            texts[0x6A81] = "the device does not support this credential's algorithm"
            ident = m.import_key("fido", key.record, pin=pin, no_pin=no_pin, replace=replace)
        else:
            slot = _otp_slot(target if target is not None else key.record[1])
            code = None
            if access_code is not None:
                code = _secret_bytes(access_code, "OTP access code", hex_ok=True)
                if len(code) != 6:
                    raise KeyTransferError("an OTP access code has 6 bytes (12 hex digits)")
            # The device refuses to overwrite (6A89) and checks the access
            # code, but a missing code only shows after the FIDO PIN: asked
            # here first, with clear answers.
            entries, _ = m.list_keys("otp", pin=pin, no_pin=no_pin)
            there = next((e for e in entries if e.get(1) in (bytes([slot]), slot)), None)
            if there is not None and not replace:
                raise KeyTransferError("%s: OTP slot %d is configured (%s); replace it explicitly"
                                       % (what, slot, display_name(str(there.get(2, "?")))), 0x6A89)
            if there is not None and there.get(3) and code is None:
                raise KeyTransferError("%s: OTP slot %d is protected by an access code; give it" % (what, slot))
            texts[0x6A89] = "OTP slot %d is configured (replace it explicitly)" % slot
            texts[0x6982] = "the access code of OTP slot %d is wrong (or the device cannot check the FIDO PIN " \
                            "now)" % slot
            ident = m.import_key("otp", key.record, pin=pin, no_pin=no_pin, secret=code, target=slot,
                                 replace=replace)
    except PinRequired:
        raise
    except ApduError as e:
        raise _sw_error(what, e.sw, texts.get(e.sw)) from e
    if key.app == "otp":
        return "OTP slot %d written (from slot %d of the file)" % (slot, key.record[1])
    return "%s imported (credential ID %s)" % (describe(key), ident.hex())


# -- OATH --------------------------------------------------------------------------

def _oath_validate(card, select, password):
    """VALIDATE: the OATH password proves itself, and the device proves it
    knows the same key (YKOATH mutual authentication)."""
    alg = (select.get(TAG_ALGORITHM) or b"\x01")[0]
    hname = _OATH_HASHES.get(alg)
    salt, challenge = select.get(TAG_NAME), select.get(TAG_CHALLENGE)
    if hname is None or not salt or not challenge:
        raise KeyTransferError("OATH: malformed SELECT answer")
    k = hashlib.pbkdf2_hmac("sha1", _secret_bytes(password, "OATH password"), salt, 1000, 16)
    mine = os.urandom(8)
    out, sw = _oath_send(card, OATH_VALIDATE, data=_tlv(TAG_RESPONSE, hmac.new(k, challenge, hname).digest()) +
                         _tlv(TAG_CHALLENGE, mine))
    if sw == 0x6984:
        raise KeyTransferError("wrong OATH password", sw)
    if sw == 0x6983:
        raise KeyTransferError("OATH: too many wrong passwords; unplug the key and try again", sw)
    if sw != 0x9000:
        raise _sw_error("OATH password", sw)
    theirs = dict(_tlvs(out, "OATH")).get(TAG_RESPONSE, b"")
    if not hmac.compare_digest(theirs, hmac.new(k, mine, hname).digest()):
        raise KeyTransferError("OATH: the device's answer does not prove it knows this password")


def _oath_names(card):
    out, sw = _oath_send(card, OATH_LIST)
    if sw != 0x9000:
        raise _sw_error("OATH list", sw)
    return {v[1:] for t, v in _tlvs(out, "OATH list") if t == TAG_NAME_LIST and v}


def _import_oath(m, key, replace, password):
    r = key.record
    kind, alg = r[2] & 0xF0, r[2] & 0x0F
    if kind not in (stdformats.OATH_HOTP, stdformats.OATH_TOTP) or alg not in _OATH_HASHES or \
            not 6 <= r[3] <= 8 or len(r[4]) > stdformats.OATH_SECRET_MAX:
        raise KeyTransferError("OATH: the device cannot hold this account (type, algorithm, digits or "
                               "secret length)")
    data = _tlv(TAG_NAME, r[1]) + _tlv(TAG_KEY, bytes([r[2], r[3]]) + r[4])
    if r.get(6):
        data += bytes([TAG_PROPERTY, OATH_PROP_TOUCH])     # YKOATH: property without length
    if kind == stdformats.OATH_HOTP and r.get(5):
        data += _tlv(TAG_IMF, r[5].to_bytes(4 if r[5] < 1 << 32 else 8, "big"))
    with _applet(m, OATH_AID, "OATH") as answer:
        select = dict(_tlvs(answer, "OATH select"))
        if TAG_CHALLENGE in select:
            if password is None:
                raise KeyTransferError("the OATH application is protected by a password; give it")
            _oath_validate(m.card, select, password)
        there = r[1] in _oath_names(m.card)
        if there and not replace:
            raise KeyTransferError("an OATH account named %s is already on the device; replace it explicitly"
                                   % display_name(r[1].decode("utf-8", "replace")), 0x6A89)
        _, sw = _oath_send(m.card, OATH_PUT, data=data)
        if sw != 0x9000:
            raise _sw_error("OATH account", sw, {0x6A84: "no space left for OATH accounts"}.get(sw))
    return "%s %s" % (describe(key), "replaced" if there else "added")


# -- OpenPGP ---------------------------------------------------------------------

def _pgp_key_ref(value):
    if isinstance(value, str):
        value = PGP_KEY_REFS.get(value.strip().lower(), value)
    if value not in (1, 2, 3) or type(value) is bool:
        raise KeyTransferError("choose the OpenPGP key slot: sig, dec or aut")
    return value


def _pgp_import_data(ref, attr, priv):
    """IMPORT DATA (PUT DATA 3FFF) body: extended header list 4D { CRT,
    7F48 { tag / length list }, 5F48 { values } } (OpenPGP card 3.4,
    4.4.3.12). RSA: 91 e, 92 p, 93 q. EC: 92 the private key (the X25519
    scalar big endian, as GnuPG sends it: the card reverses it), 99 the
    public key, which the card checks against it (25519)."""
    if attr[0] == stdformats.CARD_RSA:
        e, p, q = (int.from_bytes(priv[i], "big") for i in (1, 2, 3))
        if e != stdformats.RSA_EXPONENT:
            raise KeyTransferError("OpenPGP: RSA public exponent %d (the card uses %d)" % (e, stdformats.RSA_EXPONENT))
        if len(attr) < 3 or (p * q).bit_length() != int.from_bytes(attr[1:3], "big"):
            raise KeyTransferError("OpenPGP: the RSA key does not match its algorithm attributes")
        parts = [(0x91, priv[1]), (0x92, priv[2]), (0x93, priv[3])]
    else:
        d = priv[6]
        if stdformats.pgp_attr_name(attr).endswith("cv25519"):
            d = d[::-1]
        parts = [(0x92, d)] + ([(0x99, priv[7])] if priv.get(7) else [])
    header = b"".join(bytes([t]) + _ber_len(len(v)) for t, v in parts)
    body = bytes([_PGP_CRT[ref], 0x00]) + _tlv(0x7F48, header) + _tlv(0x5F48, b"".join(v for _, v in parts))
    return _tlv(0x4D, body)


def _pgp_key_present(card, ref):
    """Whether the slot holds a key: key information DE, else the
    fingerprints C5; None when the card tells neither."""
    info, sw = _send(card, 0xCA, 0x00, _PGP_DO_KEY_INFO)
    if sw == 0x9000 and len(info) >= 2:
        status = {info[i]: info[i + 1] for i in range(0, len(info) - 1, 2)}
        if ref - 1 in status:
            return status[ref - 1] != 0
    fps, sw = _send(card, 0xCA, 0x00, _PGP_DO_FPS)
    if sw == 0x9000 and len(fps) >= 60:
        return any(fps[(ref - 1) * 20:ref * 20])
    return None


def _pgp_admin_pin(card, admin_pin):
    """The Admin PIN as the OpenPGP application (selected on card) checks
    it: as typed, or when its KDF-DO asks for a PIN KDF (`gpg --card-edit`
    kdf-setup) the S2K hash GnuPG sends instead. The raw PIN would be
    refused there, each time at the cost of a PW3 retry."""
    # imported here: mgr_common imports this module
    from .mgr_common import ManagerError
    from .mgr_pgp import PW3, kdf_pin
    kdf, sw = _send(card, 0xCA, 0x00, _PGP_DO_KDF)
    try:
        return kdf_pin(kdf if sw == 0x9000 else b"", _secret_bytes(admin_pin, "OpenPGP Admin PIN"), PW3)
    except ManagerError as e:
        raise KeyTransferError(str(e))


def _import_openpgp(m, key, replace, admin_pin, key_ref):
    r = key.record
    ref = _pgp_key_ref(key_ref if key_ref is not None else r.get(1))
    attr, slot = bytes(r[2]), PGP_SLOT_NAMES[ref]
    if not attr or attr[0] not in (stdformats.CARD_RSA, stdformats.CARD_ECDH, stdformats.CARD_ECDSA,
                                   stdformats.CARD_EDDSA):
        raise KeyTransferError("OpenPGP: unknown algorithm attributes %s" % attr.hex())
    if (attr[0] == stdformats.CARD_ECDH and ref == 1) or (attr[0] in (stdformats.CARD_ECDSA, stdformats.CARD_EDDSA)
                                                          and ref == 2):
        raise KeyTransferError("OpenPGP: a %s key cannot go into the %s slot" % (stdformats.pgp_attr_name(attr), slot))
    if not 0 <= r[5] < 1 << 32:
        raise KeyTransferError("OpenPGP: generation time out of range")
    uif = r.get(6)
    if uif is not None and (len(uif) != 2 or uif[0] > 4):
        raise KeyTransferError("OpenPGP: malformed touch policy (UIF) in the record")
    body = _pgp_import_data(ref, attr, r[3])
    if admin_pin is None:
        raise KeyTransferError("adding an OpenPGP key needs the OpenPGP Admin PIN")
    with _applet(m, OPENPGP_AID, "OpenPGP"):
        card = m.card
        pw3 = _pgp_admin_pin(card, admin_pin)
        there = _pgp_key_present(card, ref)
        if there is not False and not replace:
            raise KeyTransferError("the OpenPGP %s slot %s; replace it explicitly"
                                   % (slot, "holds a key" if there else "may hold a key (the card does not say)"),
                                   0x6A89)
        if uif is not None:
            cur, sw = _send(card, 0xCA, 0x00, _PGP_DO_UIF + ref)
            if sw == 0x9000 and cur[:1] in (b"\x02", b"\x04") and cur[:1] != uif[:1]:
                raise KeyTransferError("OpenPGP: the %s slot's touch policy is fixed (permanently on) and "
                                       "differs from the key's" % slot)
        _, sw = _send(card, 0x20, 0x00, 0x83, pw3)
        if sw != 0x9000:
            raise _sw_error("OpenPGP Admin PIN", sw, {0x6983: "blocked", 0x6982: "wrong",
                                                      0x6A88: "not set (OpenPGP not initialized)"}.get(sw) or
                            ("wrong, %d tries left" % (sw & 0xF) if sw & 0xFFF0 == 0x63C0 else None))
        try:
            steps = [("algorithm attributes", 0xDA, 0x00, _PGP_DO_ALGO + ref, attr),
                     ("key", 0xDB, 0x3F, 0xFF, body),
                     ("fingerprint", 0xDA, 0x00, _PGP_DO_FP + ref, r[4]),
                     ("generation time", 0xDA, 0x00, _PGP_DO_TIME + ref, r[5].to_bytes(4, "big"))]
            if uif is not None:
                steps.append(("touch policy", 0xDA, 0x00, _PGP_DO_UIF + ref, uif))
            for i, (what, ins, p1, p2, data) in enumerate(steps):
                _, sw = _send(card, ins, p1, p2, data)
                if sw != 0x9000:
                    # a new algorithm removes the slot's old key (cmd_put_data.c)
                    raise _sw_error("OpenPGP %s" % what, sw, "%s%s" % (
                        _SW_TEXT.get(sw, "error"), "; the %s slot may now be without a usable key" % slot if i else ""))
        finally:
            try:
                _send(card, 0x20, 0xFF, 0x83)           # the Admin PIN session ends
            except (ApduError, CardConnectionException):
                pass
    return "%s %s in the %s slot" % (describe(key), "replaced the key" if there else "added", slot)


# -- PIV ---------------------------------------------------------------------------

def piv_object_id(slot):
    """Data object of the certificate of a PIV key slot (SP 800-73-4)."""
    fixed = {0x9A: 0x5FC105, 0x9C: 0x5FC10A, 0x9D: 0x5FC10B, 0x9E: 0x5FC101}
    if slot in fixed:
        return fixed[slot]
    if 0x82 <= slot <= 0x95:
        return 0x5FC10D + slot - 0x82
    raise KeyTransferError("PIV slot %r (9A, 9C, 9D, 9E or 82 to 95)" % (slot,))


def _piv_slot(value):
    if isinstance(value, str):
        try:
            value = int(value, 16)
        except ValueError:
            pass
    if value not in PIV_SLOTS or type(value) is bool:
        raise KeyTransferError("choose the PIV slot: 9A, 9C, 9D, 9E or 82 to 95")
    return value


def _piv_certificate(card, slot):
    """DER certificate of a slot (GET DATA), None when there is none."""
    resp, sw = _send(card, PIV_INS_GET_DATA, 0x3F, 0xFF, _tlv(0x5C, piv_object_id(slot).to_bytes(3, "big")))
    if sw in (0x6A82, 0x6A88):
        return None
    if sw != 0x9000:
        raise _sw_error("PIV certificate", sw)
    obj = dict(_tlvs(dict(_tlvs(resp, "PIV certificate")).get(0x53, b""), "PIV certificate"))
    cert = obj.get(0x70)
    if cert and (obj.get(0x71) or b"\0")[0] & 0x01:
        # compressed (CertInfo bit 0): gzip, read with a size limit
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(cert)) as g:
                cert = g.read(PIV_CERT_MAX + 1)
        except (OSError, EOFError):
            raise KeyTransferError("PIV certificate: malformed compressed certificate")
        if len(cert) > PIV_CERT_MAX:
            raise KeyTransferError("PIV certificate: larger than %d bytes" % PIV_CERT_MAX)
    return cert or None


def _piv_crypt(algo, key, block, encrypt):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if algo == PIV_3DES:
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:                 # cryptography before 43
            TripleDES = algorithms.TripleDES
        c = Cipher(TripleDES(key), modes.ECB())
    else:
        c = Cipher(algorithms.AES(key), modes.ECB())
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(block) + op.finalize()


def _piv_authenticate(card, mgmt_key):
    """Mutual authentication with the management key (9B; SP 800-73-4 part
    2, appendix A): the card proves it knows the key too."""
    meta, sw = _send(card, PIV_INS_METADATA, 0x00, PIV_MGMT_SLOT)
    fields = dict(_tlvs(meta, "PIV metadata")) if sw == 0x9000 else {}
    algo = fields.get(0x01, b"")[:1]
    algo = algo[0] if algo else None
    if mgmt_key is None:
        if fields.get(0x05, b"\x01")[:1] == b"\x00":
            raise KeyTransferError("the PIV management key is not the default one; give it")
        key = PIV_DEFAULT_MGMT_KEY
    else:
        key = _secret_bytes(mgmt_key, "PIV management key", hex_ok=True)
    if algo is None:            # no metadata: the size tells (24 bytes: 3DES, the default)
        algo = {16: PIV_AES128, 24: PIV_3DES, 32: PIV_AES256}.get(len(key))
    if _PIV_MGMT_SIZES.get(algo) != len(key):
        raise KeyTransferError("the PIV management key has %d bytes; the device's key needs %s"
                               % (len(key), _PIV_MGMT_SIZES.get(algo, "another algorithm")))
    size = 8 if algo == PIV_3DES else 16
    resp, sw = _send(card, PIV_INS_AUTHENTICATE, algo, PIV_MGMT_SLOT, _tlv(0x7C, _tlv(0x80)))
    if sw != 0x9000:
        raise _sw_error("PIV management key", sw)
    witness = dict(_tlvs(dict(_tlvs(resp, "PIV")).get(0x7C, b""), "PIV")).get(0x80, b"")
    if len(witness) != size:
        raise KeyTransferError("PIV management key: malformed answer from the device")
    challenge = os.urandom(size)
    resp, sw = _send(card, PIV_INS_AUTHENTICATE, algo, PIV_MGMT_SLOT,
                     _tlv(0x7C, _tlv(0x80, _piv_crypt(algo, key, witness, False)) + _tlv(0x81, challenge)))
    if sw == 0x6982:
        raise KeyTransferError("wrong PIV management key", sw)
    if sw != 0x9000:
        raise _sw_error("PIV management key", sw)
    theirs = dict(_tlvs(dict(_tlvs(resp, "PIV")).get(0x7C, b""), "PIV")).get(0x82, b"")
    if not hmac.compare_digest(theirs, _piv_crypt(algo, key, challenge, True)):
        raise KeyTransferError("PIV: the device's answer does not prove it holds this management key")


def _piv_import_data(record, key):
    """IMPORT ASYMMETRIC KEY data: RSA 01 p, 02 q, 03 dp, 04 dq, 05 qinv;
    EC 06 the scalar; Ed25519 07 the seed; X25519 08 the scalar (native);
    then AA PIN and AB touch policy."""
    algo, k = record[2], record[3]
    if algo in stdformats.PIV_RSA_BITS:
        n = key.private_numbers()
        half = key.key_size // 16
        data = b"".join(_tlv(t, stdformats._int_bytes(v, half))
                        for t, v in ((1, n.p), (2, n.q), (3, n.dmp1), (4, n.dmq1), (5, n.iqmp)))
    else:
        data = _tlv({stdformats.PIV_ED25519: 0x07, stdformats.PIV_X25519: 0x08}.get(algo, 0x06), k[6])
    for field, tag in ((4, 0xAA), (5, 0xAB)):
        if field in record:
            if not 0 <= record[field] <= 3:
                raise KeyTransferError("PIV: %s policy %d out of range" % ("PIN" if tag == 0xAA else "touch",
                                                                           record[field]))
            data += _tlv(tag, bytes([record[field]]))
    return data


def _import_piv(m, key, replace, mgmt_key, slot):
    r = key.record
    slot = _piv_slot(slot if slot is not None else r.get(1))
    try:
        priv = stdformats.piv_private_key(r)
    except stdformats.FormatError as e:
        raise KeyTransferError("PIV: %s" % e)
    cert = r.get(8)
    if cert:
        from cryptography import x509
        try:
            cert_pub = x509.load_der_x509_certificate(cert).public_key()
        except ValueError as e:
            raise KeyTransferError("PIV: unreadable certificate (%s)" % e)
        if stdformats._spki(cert_pub) != stdformats._spki(priv.public_key()):
            raise KeyTransferError("PIV: the certificate does not belong to the key")
    data = _piv_import_data(r, priv)
    notes = []
    with _applet(m, PIV_AID, "PIV"):
        card = m.card
        _, sw = _send(card, PIV_INS_METADATA, 0x00, slot)
        old_cert = _piv_certificate(card, slot)
        there = True if sw == 0x9000 or old_cert else (False if sw == 0x6A88 else None)
        if there is not False and not replace:
            raise KeyTransferError("PIV slot %02X %s; replace it explicitly"
                                   % (slot, "holds a key or certificate" if there else
                                      "may hold a key (the device does not say)"), 0x6A89)
        _piv_authenticate(card, mgmt_key)
        _, sw = _send(card, PIV_INS_IMPORT, r[2], slot, data)
        if sw != 0x9000:
            raise _sw_error("PIV key", sw)
        obj = _tlv(0x5C, piv_object_id(slot).to_bytes(3, "big"))
        if cert:
            _, sw = _send(card, PIV_INS_PUT_DATA, 0x3F, 0xFF,
                          obj + _tlv(0x53, _tlv(0x70, cert) + _tlv(0x71, b"\x00") + _tlv(0xFE)))
            if sw != 0x9000:
                raise _sw_error("PIV certificate (the key was imported)", sw)
        elif old_cert:
            # the old certificate is for the key just replaced
            _, sw = _send(card, PIV_INS_PUT_DATA, 0x3F, 0xFF, obj + _tlv(0x53))
            notes.append("the slot's old certificate was %s" % ("removed" if sw == 0x9000 else
                                                                 "NOT removed (SW %04X)" % sw))
    text = "%s %s in slot %02X" % (describe(key), "replaced the key" if there else "added", slot)
    return text + ("; " + "; ".join(notes) if notes else "")


# -- description -------------------------------------------------------------------

def describe(key):
    """One line about a key (no secrets), texts from the device made safe
    to show (mgmt.display_name)."""
    r = key.record
    try:
        if key.app == "fido":
            user = r.get(4) or r.get(5) or r[3].hex()
            return "FIDO passkey for %s (%s)" % (display_name(r[1]), display_name(user))
        if key.app == "oath":
            kind = "HOTP" if r[2] & 0xF0 == stdformats.OATH_HOTP else "TOTP"
            return "OATH %s account %s (%s, %d digits%s)" % (
                kind, display_name(r[1].decode("utf-8", "replace")),
                stdformats.OATH_ALGORITHM_NAMES.get(r[2] & 0x0F, "?"), r[3], ", touch" if r.get(6) else "")
        if key.app == "otp":
            return "OTP slot %d configuration (%s)" % (r[1], display_name(r.get(4) or "?"))
        if key.app == "openpgp":
            fp = r[4].hex().upper()
            slot = PGP_SLOT_NAMES.get(r.get(1))
            return "OpenPGP %skey %s, fingerprint %s" % (slot + " " if slot else "", stdformats.pgp_attr_name(r[2]),
                                                         " ".join(fp[i:i + 4] for i in range(0, len(fp), 4)))
        if key.app == "piv":
            text = "PIV %s key%s" % (stdformats.PIV_ALGORITHMS.get(r[2], "?"),
                                     " of slot %02X" % r[1] if isinstance(r.get(1), int) else "")
            if r.get(8):
                text += " with certificate"
                try:
                    from cryptography import x509
                    text += " %s" % display_name(x509.load_der_x509_certificate(r[8]).subject.rfc4514_string())
                except ValueError:
                    pass
            return text
    except (KeyError, TypeError, AttributeError, ValueError):
        pass
    return "%s key" % key.app


__all__ = ["KeyTransferError", "export_single", "import_single", "describe", "piv_object_id"]
