"""Key manager: OATH accounts (the YKOATH application, AID A0000005272101;
pico-fido/src/fido/oath.c) - list, codes, add, rename, delete, the OATH
password and a reset, as an authenticator app does.

The OATH password never stays: unlock() derives the access key from it
(PBKDF2-HMAC-SHA1, salt = the device ID of the SELECT answer, 1000
iterations, 16 bytes; YKOATH) and keeps that key for the life of the
OathManager (or until lock()). Every operation selects the application
again (one PC/SC transaction) and proves the key with VALIDATE, which also
checks that the device knows the same key.

Account names follow YKOATH: [period/][issuer:]account, the period only for
TOTP other than 30 s, or when the name would start with "<digits>/" and read
back with that number as its period ("30/0/work"; stdformats.ykoath_name,
which otpauth links go through too). Names are identified by their bytes as
stored (raw).
"""

import base64
import hashlib
import hmac
import os
import struct
import time
from contextlib import contextmanager

from . import stdformats
from .mgmt import display_name
from .mgr_common import (AuthRequired, ManagerError, SecretBlocked, WrongSecret, applet, parse_tlvs, sw_error, tlv,
                         wipe)

OATH_AID = bytes.fromhex("A0000005272101")

INS_PUT, INS_DELETE, INS_SET_CODE, INS_RESET, INS_RENAME = 0x01, 0x02, 0x03, 0x04, 0x05
INS_LIST, INS_CALCULATE, INS_VALIDATE, INS_CALCULATE_ALL, INS_SEND_REMAINING = 0xA1, 0xA2, 0xA3, 0xA4, 0xA5
TAG_NAME, TAG_NAME_LIST, TAG_KEY, TAG_CHALLENGE, TAG_RESPONSE = 0x71, 0x72, 0x73, 0x74, 0x75
TAG_TRUNCATED, TAG_NO_RESPONSE, TAG_PROPERTY, TAG_VERSION, TAG_IMF = 0x76, 0x77, 0x78, 0x79, 0x7A
TAG_ALGORITHM, TAG_TOUCH = 0x7B, 0x7C
PROP_TOUCH = 0x02
LIST_PROP_TOUCH = 0x01          # LIST with data 01 (extended): property byte after the name

HOTP, TOTP = stdformats.OATH_HOTP, stdformats.OATH_TOTP
TYPES = {"hotp": HOTP, "totp": TOTP}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
ALGORITHMS = dict(stdformats.OATH_ALGORITHMS)           # "SHA1": 1, "SHA256": 2, "SHA512": 3
ALGORITHM_NAMES = dict(stdformats.OATH_ALGORITHM_NAMES)
_HASHES = {1: "sha1", 2: "sha256", 3: "sha512"}
DEFAULT_PERIOD = stdformats.DEFAULT_PERIOD
NAME_MAX = stdformats.OATH_NAME_MAX
SECRET_MAX = stdformats.OATH_SECRET_MAX
KEY_ITERATIONS, KEY_LENGTH = 1000, 16
ANSWER_MAX = 255 * 96           # LIST / CALCULATE ALL of every account oath.c can hold, with margin


class OathPasswordRequired(AuthRequired):
    """The OATH application has a password and this manager holds no (or
    no longer the right) key: ask for the password, unlock(), try again."""


# ----------------------------------------------------------------------------
# Pure helpers
# ----------------------------------------------------------------------------

def derive_key(password, salt):
    """YKOATH access key of a password: PBKDF2-HMAC-SHA1(UTF-8 password,
    salt, 1000 iterations, 16 bytes)."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha1", bytes(password), bytes(salt), KEY_ITERATIONS, KEY_LENGTH)


def device_id(salt):
    """The device ID YKOATH clients show and remember passwords by: base64
    (no padding) of the first 16 bytes of SHA-256 of the salt."""
    return base64.b64encode(hashlib.sha256(bytes(salt)).digest()[:16]).replace(b"=", b"").decode()


def format_code(value, digits):
    """The code of a dynamically truncated value (31 bits), zero-padded."""
    return str((value & 0x7FFFFFFF) % 10 ** digits).rjust(digits, "0")


def hotp(secret, counter, digits=6, algorithm="SHA1"):
    """RFC 4226 (RFC 6238 with counter = time step) code, host-side."""
    h = hmac.new(bytes(secret), struct.pack(">Q", counter), _HASHES[ALGORITHMS[algorithm.upper()]]).digest()
    off = h[-1] & 0x0F
    return format_code(int.from_bytes(h[off:off + 4], "big"), digits)


def totp(secret, timestamp, period=DEFAULT_PERIOD, digits=6, algorithm="SHA1"):
    """RFC 6238 code at timestamp (seconds), host-side."""
    return hotp(secret, int(timestamp) // period, digits, algorithm)


def totp_window(period, timestamp=None):
    """(start, end) in seconds of the TOTP time step holding timestamp."""
    now = int(time.time() if timestamp is None else timestamp)
    start = now - now % period
    return start, start + period


def secret_from_base32(text):
    """Secret bytes of base32 text as authenticator sites show it (spaces,
    dashes, lower case and missing padding allowed)."""
    try:
        return stdformats._b32(text or "")
    except stdformats.FormatError:
        raise ManagerError("the secret is not base32 (letters A-Z and digits 2-7)", None,
                           "密钥不是 base32 格式（字母 A-Z 和数字 2-7）") from None


def parse_name(raw, kind):
    """(issuer or None, account, period or None) of a stored name; period is
    None for HOTP. A TOTP name that starts with "0/" (no period can be 0 s:
    a name stored without its period prefix, "0/work") is an account of the
    default period (stdformats.split_ykoath_name)."""
    text = bytes(raw).decode("utf-8", "replace")
    account, issuer, period = stdformats.split_ykoath_name(text, kind == TOTP)
    return (issuer or None), account, (period if kind == TOTP else None)


def build_name(issuer, account, kind=TOTP, period=DEFAULT_PERIOD):
    """Stored name (bytes) of an account; ManagerError when it cannot be
    stored or read back as given. A TOTP name that would start with
    "<digits>/" gets its period written out even when it is the default
    one ("30/12/alice"), or it would read back with that number as its
    period (YKOATH clients read it so too; stdformats.ykoath_name)."""
    account = (account or "").strip()
    issuer = (issuer or "").strip() or None
    if not account:
        raise ManagerError("OATH: the account name is empty", None, "OATH：账户名为空")
    if issuer and ":" in issuer:
        raise ManagerError("OATH: the issuer cannot contain a colon (:)", None, "OATH：发行方不能包含冒号（:）")
    if not issuer and ":" in account:
        raise ManagerError("OATH: without an issuer, the account name cannot contain a colon (:); the part before "
                           "it would read back as the issuer", None,
                           "OATH：没有发行方时，账户名不能包含冒号（:）；冒号前的部分会被读作发行方")
    if kind == TOTP and (type(period) is not int or not 1 <= period <= 0xFFFFFFFF):
        raise ManagerError("OATH: the period must be a whole number of seconds (1 or more)", None,
                           "OATH：周期必须是整数秒（至少 1）")
    raw = stdformats.ykoath_name(account, issuer, period, kind == TOTP).encode("utf-8")
    if len(raw) > NAME_MAX:
        raise ManagerError("OATH: the name is too long (%d bytes, at most %d with issuer and period)"
                           % (len(raw), NAME_MAX), None,
                           "OATH：名称太长（%d 字节，含发行方和周期最多 %d 字节）" % (len(raw), NAME_MAX))
    if parse_name(raw, kind) != (issuer, account, period if kind == TOTP else None):
        raise ManagerError("OATH: this issuer and account name would not read back as given", None,
                           "OATH：此发行方和账户名存储后无法按原样读回")
    return raw


def _show(raw):
    return display_name(bytes(raw).decode("utf-8", "replace"))


# ----------------------------------------------------------------------------
# Device
# ----------------------------------------------------------------------------

def oath_send(card, ins, p1=0, p2=0, data=b""):
    """YKOATH command: (answer, status word). A long answer continues with
    SEND REMAINING (61xx), which YKOATH pages itself: pcsc.Card would ask
    with GET RESPONSE, so this goes to the reader directly."""
    data = bytes(data)
    if len(data) > 255:
        raise ManagerError("OATH: command too long", None, "OATH：命令过长")
    resp, sw1, sw2 = card.conn.transmit([0x00, ins, p1, p2] + ([len(data)] + list(data) if data else []) + [0])
    out = bytes(resp)
    while sw1 == 0x61:
        if len(out) > ANSWER_MAX:
            raise ManagerError("OATH: the device answers without end", None, "OATH：设备应答没有结束")
        resp, sw1, sw2 = card.conn.transmit([0x00, INS_SEND_REMAINING, 0x00, 0x00, 0x00])
        out += bytes(resp)
    return out, (sw1 << 8) | sw2


def _sw(what, what_zh, sw, texts=None):
    return sw_error("OATH " + what, sw, "OATH " + what_zh, texts)


class OathManager:
    """The OATH application of the device of m (a Management)."""

    def __init__(self, m):
        self.m = m
        self._key = None        # bytearray: access key of unlock(), never the password
        self._salt = None       # the salt (device ID) it belongs to

    # -- session ---------------------------------------------------------------
    @staticmethod
    def _select_info(answer):
        sel = dict(parse_tlvs(answer, "OATH select", "OATH 选择"))
        salt = sel.get(TAG_NAME)
        if not salt:
            raise ManagerError("OATH: malformed SELECT answer", None, "OATH：SELECT 应答格式错误")
        version = sel.get(TAG_VERSION) or b""
        return {"salt": salt, "challenge": sel.get(TAG_CHALLENGE), "algorithm": (sel.get(TAG_ALGORITHM) or b"\x01")[0],
                "version": ".".join(str(b) for b in version) if version else None}

    def _prove(self, card, sel, key):
        """VALIDATE with key: the key proves itself, and the device proves it
        knows it too. Returns the status word (9000, 6984 wrong, 6983 too
        many attempts); ManagerError when the device's proof is wrong."""
        hname = _HASHES.get(sel["algorithm"])
        if hname is None or not sel["challenge"]:
            raise ManagerError("OATH: malformed SELECT answer", None, "OATH：SELECT 应答格式错误")
        mine = os.urandom(8)
        out, sw = oath_send(card, INS_VALIDATE, data=tlv(TAG_RESPONSE, hmac.new(bytes(key), sel["challenge"],
                                                                               hname).digest()) +
                            tlv(TAG_CHALLENGE, mine))
        if sw == 0x9000:
            theirs = dict(parse_tlvs(out, "OATH validate", "OATH 验证")).get(TAG_RESPONSE, b"")
            if not hmac.compare_digest(theirs, hmac.new(bytes(key), mine, hname).digest()):
                raise ManagerError("OATH: the device's answer does not prove it knows this password", None,
                                   "OATH：设备的应答不能证明它知道此密码")
        return sw

    def _validate(self, card, sel):
        if self._key is not None and self._salt != sel["salt"]:
            self.lock()                 # another device (or application instance): not its key
        if self._key is None:
            raise OathPasswordRequired("OATH: the accounts are protected by a password; enter it", None,
                                       "OATH：账户受密码保护；请输入密码")
        sw = self._prove(card, sel, self._key)
        if sw == 0x9000:
            return
        if sw == 0x6983:
            raise SecretBlocked("OATH password: too many wrong passwords; unplug the key and plug it in again",
                                sw, "OATH 密码：错误次数过多；请拔出按键并重新插入")
        if sw == 0x6984:
            self.lock()
            raise OathPasswordRequired("OATH: the password was changed; enter the new one", sw,
                                       "OATH：密码已被修改；请输入新密码")
        raise _sw("password", "密码", sw)

    @contextmanager
    def _session(self, auth=True):
        """The application selected (one transaction), VALIDATE done when it
        has a password and auth; yields (card, select info)."""
        with applet(self.m, OATH_AID, "OATH") as answer:
            sel = self._select_info(answer)
            if sel["challenge"] is None:
                self.lock()             # no password (any more): no key to keep
            elif auth:
                self._validate(self.m.card, sel)
            yield self.m.card, sel

    def lock(self):
        """Forgets the access key."""
        wipe(self._key)
        self._key = self._salt = None

    @property
    def unlocked(self):
        return self._key is not None

    # -- state -----------------------------------------------------------------
    def status(self):
        """{password_set, locked (a password is set and this manager does not
        hold its key), device_id, version}. A held key is checked (VALIDATE);
        one that no longer works is forgotten."""
        with self._session(auth=False) as (card, sel):
            locked = False
            if sel["challenge"] is not None:
                try:
                    self._validate(card, sel)
                except OathPasswordRequired:
                    locked = True
            return {"password_set": sel["challenge"] is not None, "locked": locked,
                    "device_id": device_id(sel["salt"]), "version": sel["version"]}

    def unlock(self, password):
        """Checks the password (VALIDATE) and keeps its key. Returns False
        when the application has no password (nothing kept). WrongSecret,
        SecretBlocked."""
        if not password:
            raise WrongSecret("OATH password: enter the password", None, "OATH 密码：请输入密码")
        self.lock()
        with self._session(auth=False) as (card, sel):
            if sel["challenge"] is None:
                return False
            key = bytearray(derive_key(password, sel["salt"]))
            try:
                sw = self._prove(card, sel, key)
            except BaseException:
                wipe(key)
                raise
            if sw != 0x9000:
                wipe(key)
                if sw == 0x6984:
                    raise WrongSecret("wrong OATH password", sw, "OATH 密码错误")
                if sw == 0x6983:
                    raise SecretBlocked("OATH password: too many wrong passwords; unplug the key and plug it in "
                                        "again", sw, "OATH 密码：错误次数过多；请拔出按键并重新插入")
                raise _sw("password", "密码", sw)
            self._key, self._salt = key, sel["salt"]
            return True

    # -- accounts ----------------------------------------------------------------
    def _entries(self, card):
        """[(type|algorithm, raw name, touch or None)] from LIST (extended:
        with the touch property; plain LIST on firmware without it)."""
        out, sw = oath_send(card, INS_LIST, data=b"\x01")
        ext = sw == 0x9000
        if not ext:
            out, sw = oath_send(card, INS_LIST)
            if sw != 0x9000:
                raise _sw("list", "列表", sw)
        entries = []
        for tag, v in parse_tlvs(out, "OATH list", "OATH 列表"):
            if tag != TAG_NAME_LIST or len(v) < (3 if ext else 2):
                continue
            if ext:
                entries.append((v[0], v[1:-1], bool(v[-1] & LIST_PROP_TOUCH)))
            else:
                entries.append((v[0], v[1:], None))
        return entries

    @staticmethod
    def _calculate_all(card, timestamp):
        """[(raw name, response tag, value)] of CALCULATE ALL (truncated
        codes) for the 30 s time step of timestamp."""
        out, sw = oath_send(card, INS_CALCULATE_ALL, 0, 1, tlv(TAG_CHALLENGE, struct.pack(">Q", timestamp //
                                                                                          DEFAULT_PERIOD)))
        if sw != 0x9000:
            raise _sw("codes", "验证码", sw)
        items = parse_tlvs(out, "OATH codes", "OATH 验证码")
        result = []
        for i in range(0, len(items) - 1, 2):
            (t1, name), (t2, value) = items[i], items[i + 1]
            if t1 == TAG_NAME and value:
                result.append((name, t2, value))
        return result

    def list(self):
        """The accounts, sorted by issuer and account: dicts {raw (bytes),
        name (text), issuer (text or None), account, type ("totp"/"hotp"),
        algorithm ("SHA1"/"SHA256"/"SHA512"), digits, period (seconds; None
        for HOTP), touch (bool)}. Texts come from the device: show them
        through mgmt.display_name."""
        with self._session() as (card, _):
            entries = self._entries(card)
            codes = self._calculate_all(card, int(time.time()))
        digits = {name: value[0] for name, _, value in codes}
        touch_tag = {name for name, tag, _ in codes if tag == TAG_TOUCH}
        out = []
        for type_alg, raw, touch in entries:
            kind, alg = type_alg & 0xF0, type_alg & 0x0F
            if kind not in TYPE_NAMES or alg not in ALGORITHM_NAMES:
                continue        # not an OATH account (password safe entry, unknown algorithm)
            issuer, account, period = parse_name(raw, kind)
            out.append({"raw": bytes(raw), "name": bytes(raw).decode("utf-8", "replace"), "issuer": issuer,
                        "account": account, "type": TYPE_NAMES[kind], "algorithm": ALGORITHM_NAMES[alg],
                        "digits": digits.get(raw, 6), "period": period,
                        "touch": bool(touch) if touch is not None else raw in touch_tag})
        out.sort(key=lambda e: ((e["issuer"] or "").lower(), e["account"].lower(), e["raw"]))
        return out

    def calculate_all(self, timestamp=None):
        """{raw name: code} of every account at timestamp (seconds, default
        now); None for HOTP accounts and accounts that need a touch (compute
        those one by one with calculate()). TOTP accounts with another period
        than 30 s are computed for their own period."""
        ts = int(time.time() if timestamp is None else timestamp)
        result = {}
        with self._session() as (card, _):
            for raw, tag, value in self._calculate_all(card, ts):
                code = None
                if tag == TAG_TRUNCATED and len(value) >= 5:
                    _, _, period = parse_name(raw, TOTP)
                    if period == DEFAULT_PERIOD:
                        code = format_code(int.from_bytes(value[1:5], "big"), value[0])
                    else:
                        code = self._calculate(card, raw, struct.pack(">Q", ts // period))
                result[bytes(raw)] = code
        return result

    @staticmethod
    def _calculate(card, raw, challenge):
        out, sw = oath_send(card, INS_CALCULATE, 0, 1, tlv(TAG_NAME, raw) + tlv(TAG_CHALLENGE, challenge))
        if sw != 0x9000:
            raise _sw("code of %s" % _show(raw), "%s 的验证码" % _show(raw), sw, {
                0x6984: ("no such account (list them again)", "没有该账户（请重新列出）"),
                0x6985: ("not confirmed: touch the key when it blinks", "未确认：请在按键闪烁时触摸它")})
        value = dict(parse_tlvs(out, "OATH code", "OATH 验证码")).get(TAG_TRUNCATED, b"")
        if len(value) < 5:
            raise ManagerError("OATH: malformed code from the device", None, "OATH：设备返回的验证码格式错误")
        return format_code(int.from_bytes(value[1:5], "big"), value[0])

    def calculate(self, raw, timestamp=None):
        """The code of one account at timestamp (default now). A HOTP account
        moves on to its next counter; an account that needs a touch waits
        for it (the key blinks)."""
        raw = bytes(raw)
        ts = int(time.time() if timestamp is None else timestamp)
        with self._session() as (card, _):
            entry = next((e for e in self._entries(card) if e[1] == raw), None)
            if entry is None:
                raise ManagerError("OATH: no account %s (list them again)" % _show(raw), 0x6984,
                                   "OATH：没有账户 %s（请重新列出）" % _show(raw))
            kind = entry[0] & 0xF0
            if kind == HOTP:
                challenge = b""
            else:
                _, _, period = parse_name(raw, TOTP)
                challenge = struct.pack(">Q", ts // period)
            return self._calculate(card, raw, challenge)

    # -- changes -------------------------------------------------------------------
    def add(self, issuer, account, secret, type="totp", algorithm="SHA1", digits=6, period=DEFAULT_PERIOD, counter=0,
            touch=False, replace=False):
        """Adds an account (secret: the key bytes, see secret_from_base32);
        returns its raw name. An account with the same name is replaced only
        with replace (otherwise ManagerError SW 6A89)."""
        kind = TYPES.get(str(type).lower())
        if kind is None:
            raise ManagerError("OATH: the type is TOTP or HOTP", None, "OATH：类型只能是 TOTP 或 HOTP")
        alg = ALGORITHMS.get(str(algorithm).upper())
        if alg is None:
            raise ManagerError("OATH: the algorithm is SHA1, SHA256 or SHA512", None,
                               "OATH：算法只能是 SHA1、SHA256 或 SHA512")
        if not type_ok(digits) or not 6 <= digits <= 8:
            raise ManagerError("OATH: 6, 7 or 8 digits", None, "OATH：位数只能是 6、7 或 8")
        if kind == HOTP and (not type_ok(counter) or not 0 <= counter < 1 << 64):
            raise ManagerError("OATH: the HOTP counter is a whole number from 0 to 2^64-1", None,
                               "OATH：HOTP 计数器必须是 0 到 2^64-1 的整数")
        if not isinstance(secret, (bytes, bytearray)) or not secret:
            raise ManagerError("OATH: the secret is empty", None, "OATH：密钥为空")
        name = build_name(issuer, account, kind, period if kind == TOTP else DEFAULT_PERIOD)
        record = {1: name, 2: kind | alg, 3: digits, 4: stdformats._oath_key(bytes(secret), alg), 6: bool(touch)}
        if kind == HOTP:
            record[5] = counter
        return self._put(record, replace)

    def add_record(self, record, replace=False):
        """Adds an account given as an OATH record (stdformats.parse_otpauth,
        a key file's): {1: name, 2: type|algorithm, 3: digits, 4: secret as
        stored, 5: HOTP counter, 6: touch}. Returns its raw name. The type /
        algorithm byte, digits and counter go to the device as a byte, a byte
        and at most 8 bytes: out of range, ManagerError (as keyfile.check_record)."""
        try:
            if not isinstance(record, dict) or not all(isinstance(record[k], (bytes, bytearray, memoryview))
                                                       for k in (1, 4)):
                raise TypeError             # (bytes(int) would make that many zero bytes)
            name, type_alg, digits, secret = bytes(record[1]), record[2], record[3], bytes(record[4])
        except (KeyError, TypeError, ValueError):
            raise ManagerError("OATH: not an OATH account record", None, "OATH：不是 OATH 账户记录") from None
        byte = type_ok(type_alg) and 0 <= type_alg <= 0xFF
        kind = type_alg & 0xF0 if byte else None
        alg = type_alg & 0x0F if byte else None
        counter = record.get(5, 0) or 0
        if kind not in TYPE_NAMES or alg not in ALGORITHM_NAMES or not type_ok(digits) or not 6 <= digits <= 8 or \
                not 1 <= len(name) <= NAME_MAX or not secret or len(secret) > SECRET_MAX or \
                not type_ok(counter) or not 0 <= counter < 1 << 64:
            raise ManagerError("OATH: the device cannot hold this account (type, algorithm, digits, name or secret "
                               "length)", None, "OATH：设备无法保存此账户（类型、算法、位数、名称或密钥长度）")
        rec = {1: name, 2: kind | alg, 3: digits, 4: secret, 6: bool(record.get(6))}
        if kind == HOTP:
            rec[5] = counter
        return self._put(rec, replace)

    def _put(self, r, replace):
        data = tlv(TAG_NAME, r[1]) + tlv(TAG_KEY, bytes([r[2], r[3]]) + r[4])
        if r.get(6):
            data += bytes([TAG_PROPERTY, PROP_TOUCH])       # YKOATH: property without length
        if r[2] & 0xF0 == HOTP and r.get(5):
            data += tlv(TAG_IMF, r[5].to_bytes(4 if r[5] < 1 << 32 else 8, "big"))
        with self._session() as (card, _):
            there = any(e[1] == r[1] for e in self._entries(card))
            if there and not replace:
                raise ManagerError("OATH: an account named %s is already on the device; replace it explicitly"
                                   % _show(r[1]), 0x6A89, "OATH：设备上已有名为 %s 的账户；需明确选择替换" % _show(r[1]))
            _, sw = oath_send(card, INS_PUT, data=data)
            if sw != 0x9000:
                raise _sw("add %s" % _show(r[1]), "添加 %s" % _show(r[1]), sw, {
                    0x6A84: ("no space left for OATH accounts", "OATH 账户空间已满"),
                    0x6700: ("the device refused the account (name or secret too long?)",
                             "设备拒绝了该账户（名称或密钥太长？）")})
        return bytes(r[1])

    def rename(self, raw, issuer, account):
        """Gives an account a new issuer and account name (type and period
        stay); returns the new raw name. ManagerError (SW 6A89) when another
        account has that name."""
        raw = bytes(raw)
        with self._session() as (card, _):
            entries = self._entries(card)
            entry = next((e for e in entries if e[1] == raw), None)
            if entry is None:
                raise ManagerError("OATH: no account %s (list them again)" % _show(raw), 0x6984,
                                   "OATH：没有账户 %s（请重新列出）" % _show(raw))
            kind = entry[0] & 0xF0
            _, _, period = parse_name(raw, kind)
            new = build_name(issuer, account, kind, period if kind == TOTP else DEFAULT_PERIOD)
            if new == raw:
                return raw
            if any(e[1] == new for e in entries):
                raise ManagerError("OATH: an account named %s is already on the device" % _show(new), 0x6A89,
                                   "OATH：设备上已有名为 %s 的账户" % _show(new))
            _, sw = oath_send(card, INS_RENAME, data=tlv(TAG_NAME, raw) + tlv(TAG_NAME, new))
            if sw != 0x9000:
                raise _sw("rename %s" % _show(raw), "重命名 %s" % _show(raw), sw, {
                    0x6984: ("no such account (list them again)", "没有该账户（请重新列出）"),
                    0x6985: ("an account with the new name exists", "已有同名账户")})
        return new

    def delete(self, raw):
        """Deletes an account for good (the caller confirmed)."""
        raw = bytes(raw)
        with self._session() as (card, _):
            _, sw = oath_send(card, INS_DELETE, data=tlv(TAG_NAME, raw))
            if sw != 0x9000:
                raise _sw("delete %s" % _show(raw), "删除 %s" % _show(raw), sw, {
                    0x6984: ("no such account (list them again)", "没有该账户（请重新列出）")})

    def set_password(self, new):
        """Sets or changes the OATH password (new), or removes it (None or
        ""). Needs the current one unlocked when one is set. The manager then
        holds the new key."""
        with self._session() as (card, sel):
            if not new:
                _, sw = oath_send(card, INS_SET_CODE, data=tlv(TAG_KEY))
                if sw != 0x9000:
                    raise _sw("remove password", "删除密码", sw)
                self.lock()
                return
            key = bytearray(derive_key(new, sel["salt"]))
            try:
                challenge = os.urandom(8)
                data = tlv(TAG_KEY, bytes([TOTP | ALGORITHMS["SHA1"]]) + bytes(key)) + tlv(TAG_CHALLENGE, challenge) + \
                    tlv(TAG_RESPONSE, hmac.new(bytes(key), challenge, "sha1").digest())
                _, sw = oath_send(card, INS_SET_CODE, data=data)
                if sw != 0x9000:
                    raise _sw("set password", "设置密码", sw)
            except BaseException:
                wipe(key)
                raise
            self.lock()
            self._key, self._salt = key, sel["salt"]

    def reset(self):
        """Erases every OATH account and the password (the caller confirmed
        twice). The device asks for a touch, whatever the presence policy."""
        self.lock()
        with self._session(auth=False) as (card, _):
            _, sw = oath_send(card, INS_RESET, 0xDE, 0xAD)
            if sw != 0x9000:
                raise _sw("reset", "重置", sw, {
                    0x6985: ("not confirmed: touch the key when it blinks", "未确认：请在按键闪烁时触摸它")})


def type_ok(value):
    """value is an int (not a bool)."""
    return type(value) is int


__all__ = ["OathManager", "OathPasswordRequired", "derive_key", "device_id", "format_code", "hotp", "totp",
           "totp_window", "secret_from_base32", "parse_name", "build_name"]
