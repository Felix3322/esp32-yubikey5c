"""OTP slots of the device, for the key manager (pico-fido/src/fido/otp.c).

The YubiKey OTP application over the smart card interface (AID
A0000005272001): INS 01 with the slot command in P1, as yubikit's
YubiOtpSession sends it over CCID. A slot write carries a 52-byte
configuration (fixed part, UID, key, access code, length and flags, RFU, CRC)
followed by the slot's current access code. The frames are byte for byte the
ones yubikit builds (tests/tools/test_mgr_otp_units.py compares them): a slot
programmed here is the slot ykman would have programmed, and the other way
round. The device answers a write with its status, whose programming sequence
moves on when the write was stored; a write it did not store is an error.

Slots 1 and 2. An access code (6 bytes) protects a slot: programming,
updating, deleting and swapping it need that code (the device does not tell
whether a slot has one; a refusal does). Nothing is overwritten silently:
programming a slot that holds a configuration needs replace=True.

Secrets (keys, access codes, passwords) are never logged, never put into
messages, and not kept by the manager.
"""

import base64
import hashlib
import os
import secrets
import struct
from contextlib import contextmanager
from datetime import datetime

from .mgr_common import AuthRequired, ManagerError, WrongSecret, applet, parse_tlvs, sw_error, wipe

OTP_AID = bytes.fromhex("A0000005272001")
INS_CONFIG = 0x01
SLOTS = (1, 2)

# Slot commands (P1 of INS 01; yubikit CONFIG_SLOT)
CMD_CONFIG = {1: 0x01, 2: 0x03}
CMD_UPDATE = {1: 0x04, 2: 0x05}
CMD_SWAP = 0x06
CMD_DEVICE_SERIAL = 0x10
CMD_STATUS_EXT = 0x14           # LibreFido: the flags (and public ID) of every programmed slot
CMD_CHAL_HMAC = {1: 0x30, 2: 0x38}

# Sizes (ykdef.h)
FIXED_SIZE, UID_SIZE, KEY_SIZE, ACC_CODE_SIZE, CONFIG_SIZE = 16, 6, 16, 6, 52
HMAC_KEY_SIZE, HMAC_CHALLENGE_SIZE, HMAC_RESPONSE_SIZE = 20, 64, 20
SCAN_CODES_SIZE = FIXED_SIZE + UID_SIZE + KEY_SIZE        # characters of a static password
SHA1_BLOCK_SIZE = 64
PUBLIC_ID_SIZE = 6              # the device types a 6-byte public ID
HOTP_IMF_MAX = 0xFFFF0          # the initial moving factor is stored divided by 16 (16 bits)
CRC_OK_RESIDUAL = 0xF0B8

# Ticket flags
TKT_TAB_FIRST, TKT_APPEND_TAB1, TKT_APPEND_TAB2 = 0x01, 0x02, 0x04
TKT_APPEND_DELAY1, TKT_APPEND_DELAY2, TKT_APPEND_CR = 0x08, 0x10, 0x20
TKT_OATH_HOTP = TKT_CHAL_RESP = 0x40
TKT_PROTECT_CFG2 = 0x80
TKT_UPDATE_MASK = TKT_TAB_FIRST | TKT_APPEND_TAB1 | TKT_APPEND_TAB2 | TKT_APPEND_DELAY1 | TKT_APPEND_DELAY2 | \
    TKT_APPEND_CR
# Configuration flags (their meaning depends on the mode)
CFG_SEND_REF, CFG_SHORT_TICKET, CFG_PACING_10MS, CFG_PACING_20MS = 0x01, 0x02, 0x04, 0x08
CFG_STATIC_TICKET = 0x20
CFG_OATH_HOTP8, CFG_OATH_FIXED_MODHEX2 = 0x02, 0x40
CFG_HMAC_LT64, CFG_CHAL_BTN_TRIG, CFG_CHAL_YUBICO, CFG_CHAL_HMAC = 0x04, 0x08, 0x20, 0x22
CFG_UPDATE_MASK = CFG_PACING_10MS | CFG_PACING_20MS
# Extended flags
EXT_SERIAL_API_VISIBLE, EXT_FAST_TRIG, EXT_ALLOW_UPDATE = 0x04, 0x10, 0x20
# yubikit's defaults: every configuration (SlotConfiguration), and the ones
# that type (KeyboardSlotConfiguration)
EXT_DEFAULT = EXT_SERIAL_API_VISIBLE | EXT_ALLOW_UPDATE
EXT_KEYBOARD = EXT_DEFAULT | EXT_FAST_TRIG

# Configuration state (the "touch level" of the status)
STATE_VALID = {1: 0x01, 2: 0x02}
STATE_TOUCH = {1: 0x04, 2: 0x08}
STATE_MASK = 0x1F

MODES = ("yubico-otp", "chal-hmac", "chal-yubico", "hotp", "static")

MODHEX = "cbdefghijklnrtuv"


# ----------------------------------------------------------------------------
# Values
# ----------------------------------------------------------------------------

def _error(en, zh, sw=None, cls=ManagerError):
    return cls(en, sw, zh)


def _slot(slot):
    if type(slot) is not int or slot not in SLOTS:
        raise _error("OTP slot %r: choose slot 1 or 2" % (slot,), "OTP 槽位 %r：请选择槽位 1 或 2" % (slot,))
    return slot


def _bytes(value, what, what_zh, fmt="hex"):
    """bytes of a secret or identifier: bytes as they are, text as fmt ("hex",
    "modhex" or "base32"; white space ignored). The value is never part of
    a message."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if not isinstance(value, str):
        raise _error("%s: bytes or text expected" % what, "%s：应为字节或文本" % what_zh)
    text = "".join(value.split())
    try:
        if fmt == "modhex":
            return modhex_decode(text)
        if fmt == "base32":
            text = text.upper().rstrip("=")
            return base64.b32decode(text + "=" * (-len(text) % 8))
        return bytes.fromhex(text)
    except (ValueError, TypeError):
        names = {"hex": ("hexadecimal", "十六进制"), "modhex": ("modhex (%s)" % MODHEX, "modhex（%s）" % MODHEX),
                 "base32": ("base32", "base32")}[fmt]
        raise _error("%s: not valid %s" % (what, names[0]), "%s：不是有效的%s" % (what_zh, names[1])) from None


def access_code_bytes(value, what="access code", what_zh="访问码"):
    """An access code as the device takes it: 6 bytes, or text of 12
    hexadecimal digits. None, "" and six zero bytes mean no access code
    (None)."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    code = _bytes(value, what, what_zh)
    if len(code) != ACC_CODE_SIZE:
        raise _error("%s: an OTP access code has 6 bytes (12 hexadecimal digits)" % what,
                     "%s：OTP 访问码为 6 字节（12 位十六进制数字）" % what_zh)
    return code if any(code) else None


def modhex_encode(data):
    """Modhex text of data (the alphabet cbdefghijklnrtuv)."""
    return "".join(MODHEX[b >> 4] + MODHEX[b & 0x0F] for b in bytes(data))


def modhex_decode(text):
    """bytes of modhex text (either case); ValueError when it is not modhex."""
    text = text.lower()
    if len(text) % 2 or any(c not in MODHEX for c in text):
        raise ValueError("not modhex")
    return bytes(MODHEX.index(text[i]) << 4 | MODHEX.index(text[i + 1]) for i in range(0, len(text), 2))


# ----------------------------------------------------------------------------
# Static passwords: keyboard scan codes (USB HID usage IDs, 0x80: shift)
# ----------------------------------------------------------------------------

_SHIFT = 0x80


def _us_layout():
    codes = {}
    for i, c in enumerate("abcdefghijklmnopqrstuvwxyz"):
        codes[c] = 0x04 + i
        codes[c.upper()] = (0x04 + i) | _SHIFT
    for i, (c, shifted) in enumerate(zip("1234567890", "!@#$%^&*()")):
        codes[c] = 0x1E + i
        codes[shifted] = (0x1E + i) | _SHIFT
    for c, shifted, code in (("-", "_", 0x2D), ("=", "+", 0x2E), ("[", "{", 0x2F), ("]", "}", 0x30),
                             ("\\", "|", 0x32), (";", ":", 0x33), ("'", '"', 0x34), ("`", "~", 0x35),
                             (",", "<", 0x36), (".", ">", 0x37), ("/", "?", 0x38)):
        codes[c] = code
        codes[shifted] = code | _SHIFT
    codes.update({"\t": 0x2B, "\n": 0x28, " ": 0x2C})
    return codes


_US = _us_layout()
# "us": a US English keyboard layout (as ykman's); "modhex": only the modhex
# letters, which type alike on the common Latin layouts (QWERTY, QWERTZ, AZERTY)
KEYBOARD_LAYOUTS = {
    "us": _US,
    "modhex": {c: _US[c] for c in MODHEX + MODHEX.upper()},
}
_PASSWORD_GEN_EXCLUDED = "\t\n "


def encode_scan_codes(password, layout="us"):
    """The keyboard scan codes that type password with the keyboard layout
    ("us" or "modhex"), at most 38 characters."""
    table = KEYBOARD_LAYOUTS.get(layout)
    if table is None:
        raise _error("unknown keyboard layout %r (one of %s)" % (layout, ", ".join(KEYBOARD_LAYOUTS)),
                     "未知的键盘布局 %r（可选：%s）" % (layout, "、".join(KEYBOARD_LAYOUTS)))
    if not isinstance(password, str) or not password:
        raise _error("the static password is empty", "静态密码为空")
    if len(password) > SCAN_CODES_SIZE:
        raise _error("a static password has at most %d characters" % SCAN_CODES_SIZE,
                     "静态密码最多 %d 个字符" % SCAN_CODES_SIZE)
    for i, c in enumerate(password):
        if c not in table:
            # the character itself is part of the password: its position only
            raise _error("the static password cannot be typed with the %s keyboard layout (character %d)"
                         % (layout, i + 1), "静态密码无法用 %s 键盘布局输入（第 %d 个字符）" % (layout, i + 1))
    return bytes(table[c] for c in password)


def random_static_password(length=SCAN_CODES_SIZE, layout="modhex"):
    """A random password of length characters that the keyboard layout
    types (no tab, line break or space)."""
    table = KEYBOARD_LAYOUTS.get(layout)
    if table is None or not 1 <= length <= SCAN_CODES_SIZE:
        raise _error("random password: layout %r, length %r (1 to %d)" % (layout, length, SCAN_CODES_SIZE),
                     "随机密码：布局 %r，长度 %r（1 到 %d）" % (layout, length, SCAN_CODES_SIZE))
    chars = sorted(c for c in table if c not in _PASSWORD_GEN_EXCLUDED)
    return "".join(secrets.choice(chars) for _ in range(length))


# ----------------------------------------------------------------------------
# Frames (yubikit.yubiotp: _build_config and the SlotConfiguration classes)
# ----------------------------------------------------------------------------

def calculate_crc(data):
    """CRC of the OTP frames (ISO 13239, as ykcore's yubikey_crc16)."""
    crc = 0xFFFF
    for b in bytes(data):
        crc ^= b
        for _ in range(8):
            j = crc & 1
            crc >>= 1
            if j:
                crc ^= 0x8408
    return crc & 0xFFFF


def check_crc(data):
    """Whether data ends with the (complemented) CRC of what precedes it."""
    return calculate_crc(data) == CRC_OK_RESIDUAL


def build_config(fixed, uid, key, ext, tkt, cfg, access_code=None):
    """The 52-byte slot configuration: fixed part (padded to 16), UID (6),
    key (16), access code (6, zeros for none), length of the fixed part,
    ext / tkt / cfg flags, 2 RFU bytes, the complemented CRC (little
    endian)."""
    fixed, uid, key = bytes(fixed), bytes(uid), bytes(key)
    if len(fixed) > FIXED_SIZE or len(uid) != UID_SIZE or len(key) != KEY_SIZE:
        raise ValueError("OTP configuration: field sizes")
    code = access_code_bytes(access_code, "new access code", "新访问码")
    buf = fixed.ljust(FIXED_SIZE, b"\0") + uid + key + (code or bytes(ACC_CODE_SIZE)) + \
        struct.pack(">BBBB", len(fixed), ext, tkt, cfg) + b"\0\0"
    return buf + struct.pack("<H", 0xFFFF & ~calculate_crc(buf))


def _hmac_key(key, what, what_zh):
    """A key for HMAC-SHA1 of at most 20 bytes, packed into the key and UID
    fields. A key longer than the SHA-1 block is hashed first (HMAC does the
    same), as yubikit does."""
    if len(key) > SHA1_BLOCK_SIZE:
        key = hashlib.sha1(key).digest()
    elif len(key) > HMAC_KEY_SIZE:
        raise _error("%s: at most %d bytes (or more than %d)" % (what, HMAC_KEY_SIZE, SHA1_BLOCK_SIZE),
                     "%s：最多 %d 字节（或多于 %d 字节）" % (what_zh, HMAC_KEY_SIZE, SHA1_BLOCK_SIZE))
    if not key:
        raise _error("%s: empty" % what, "%s：为空" % what_zh)
    return key[:KEY_SIZE].ljust(KEY_SIZE, b"\0"), key[KEY_SIZE:].ljust(UID_SIZE, b"\0")


def yubico_otp_config(public_id, private_id, key, append_cr=True, access_code=None):
    """Yubico OTP (YubiOtpSlotConfiguration(public_id, private_id,
    key).append_cr(append_cr)). public_id: 6 bytes or 12 modhex characters;
    private_id: 6 bytes or 12 hexadecimal digits; key: 16 bytes (AES-128) or
    32 hexadecimal digits; access_code: the one that protects the slot from
    now on (None: none)."""
    public_id = _bytes(public_id, "public ID", "公共 ID", "modhex")
    private_id = _bytes(private_id, "private ID", "私有 ID")
    key = _bytes(key, "Yubico OTP key", "Yubico OTP 密钥")
    if len(public_id) != PUBLIC_ID_SIZE:
        raise _error("the public ID has 6 bytes (12 modhex characters)", "公共 ID 为 6 字节（12 个 modhex 字符）")
    if len(private_id) != UID_SIZE:
        raise _error("the private ID has 6 bytes (12 hexadecimal digits)", "私有 ID 为 6 字节（12 位十六进制数字）")
    if len(key) != KEY_SIZE:
        raise _error("the Yubico OTP key has 16 bytes (32 hexadecimal digits)",
                     "Yubico OTP 密钥为 16 字节（32 位十六进制数字）")
    tkt = TKT_APPEND_CR if append_cr else 0
    return build_config(public_id, private_id, key, EXT_KEYBOARD, tkt, 0, access_code)


def hmac_sha1_config(key, touch=False, access_code=None):
    """HMAC-SHA1 challenge-response (HmacSha1SlotConfiguration(key)
    .require_touch(touch)). key: up to 20 bytes (40 hexadecimal digits)."""
    k, uid = _hmac_key(_bytes(key, "challenge-response key", "挑战-响应密钥"), "challenge-response key",
                       "挑战-响应密钥")
    cfg = CFG_CHAL_HMAC | CFG_HMAC_LT64 | (CFG_CHAL_BTN_TRIG if touch else 0)
    return build_config(b"", uid, k, EXT_DEFAULT, TKT_CHAL_RESP, cfg, access_code)


def static_password_config(scan_codes, append_cr=True, access_code=None):
    """Static password (StaticPasswordSlotConfiguration(scan_codes)
    .append_cr(append_cr)): up to 38 scan codes (encode_scan_codes())."""
    scan_codes = bytes(scan_codes)
    if not scan_codes or len(scan_codes) > SCAN_CODES_SIZE:
        raise _error("a static password has 1 to %d characters" % SCAN_CODES_SIZE,
                     "静态密码为 1 到 %d 个字符" % SCAN_CODES_SIZE)
    padded = scan_codes.ljust(SCAN_CODES_SIZE, b"\0")
    tkt = TKT_APPEND_CR if append_cr else 0
    return build_config(padded[:FIXED_SIZE], padded[FIXED_SIZE:FIXED_SIZE + UID_SIZE],
                        padded[FIXED_SIZE + UID_SIZE:], EXT_KEYBOARD, tkt, CFG_SHORT_TICKET, access_code)


def hotp_config(secret, digits=6, counter=0, append_cr=True, access_code=None):
    """OATH-HOTP (HotpSlotConfiguration(secret).imf(counter).digits8(digits
    == 8).append_cr(append_cr)): HMAC-SHA1, 6 or 8 digits, the initial
    counter a multiple of 16 up to 1048560. secret: up to 20 bytes, or base32
    text (as sites show it)."""
    if digits not in (6, 8) or type(digits) is not int:
        raise _error("an OTP slot's HOTP code has 6 or 8 digits", "OTP 槽位的 HOTP 验证码为 6 或 8 位")
    if type(counter) is not int or not 0 <= counter <= HOTP_IMF_MAX or counter % 16:
        raise _error("the initial HOTP counter is a multiple of 16 from 0 to %d" % HOTP_IMF_MAX,
                     "HOTP 初始计数器应为 0 到 %d 之间 16 的倍数" % HOTP_IMF_MAX)
    k, uid = _hmac_key(_bytes(secret, "HOTP secret", "HOTP 密钥", "base32"), "HOTP secret", "HOTP 密钥")
    uid = uid[:4] + struct.pack(">H", counter >> 4)
    tkt = TKT_OATH_HOTP | (TKT_APPEND_CR if append_cr else 0)
    cfg = CFG_OATH_FIXED_MODHEX2 | (CFG_OATH_HOTP8 if digits == 8 else 0)
    return build_config(b"", uid, k, EXT_KEYBOARD, tkt, cfg, access_code)


def update_config(tkt=TKT_APPEND_CR, cfg=0, keyboard=True, access_code=None):
    """A slot update (UpdateConfiguration(), with .fast_trigger(False) for a
    challenge-response slot): the flags that may change (tkt: tabs, delays,
    Enter; cfg: pacing) and the new access code; the device keeps the
    secrets."""
    if tkt & ~TKT_UPDATE_MASK or cfg & ~CFG_UPDATE_MASK:
        raise ValueError("OTP update: flags that cannot be updated")
    return build_config(bytes(FIXED_SIZE), bytes(UID_SIZE), bytes(KEY_SIZE), EXT_KEYBOARD if keyboard else EXT_DEFAULT,
                        tkt, cfg, access_code)


DELETE_CONFIG = bytes(CONFIG_SIZE)


def pad_challenge(challenge):
    """An HMAC challenge as yubikit sends it: padded to 64 bytes with a byte
    other than its last, which the device strips (HMAC_LT64)."""
    challenge = bytes(challenge)
    return challenge.ljust(HMAC_CHALLENGE_SIZE, b"\1" if challenge.endswith(b"\0") else b"\0")


def slot_mode(tkt, cfg):
    """Mode of a configuration from its flags, told apart as the device does
    (otp.c otp_mode_name): one of MODES."""
    if tkt & TKT_CHAL_RESP and cfg & CFG_CHAL_YUBICO:
        return "chal-hmac" if cfg & CFG_CHAL_HMAC == CFG_CHAL_HMAC else "chal-yubico"
    if tkt & TKT_OATH_HOTP:
        return "hotp"
    if cfg & (CFG_SHORT_TICKET | CFG_STATIC_TICKET):
        return "static"
    return "yubico-otp"


def random_yubico_otp():
    """A new Yubico OTP credential (public_id, private_id, key): a 6-byte
    public ID starting with 0xFF (modhex "vv", the prefix YubiCloud keeps for
    credentials their owners program), a random 6-byte private ID and a
    random 16-byte AES key."""
    return b"\xff" + os.urandom(PUBLIC_ID_SIZE - 1), os.urandom(UID_SIZE), os.urandom(KEY_SIZE)


def format_csv(serial, public_id, private_id, key, access_code=None, timestamp=None):
    """One line in the "Yubico" CSV format of YubiCloud's upload (as ykman
    writes it): serial, public ID (modhex), private ID (hex), key (hex),
    access code (hex, empty for none), time; a trailing comma. serial None
    (unknown) leaves its field empty. It holds the secret key: shown or
    saved only at the user's request."""
    code = access_code_bytes(access_code)
    ts = timestamp or datetime.now()
    return ",".join(["" if serial is None else str(serial), modhex_encode(public_id), bytes(private_id).hex(),
                     bytes(key).hex(), code.hex() if code else "", ts.isoformat(timespec="seconds"), ""])


# ----------------------------------------------------------------------------
# The application
# ----------------------------------------------------------------------------

# Status words of slot writes (otp.c)
_WRITE_TEXTS = {
    0x6400: ("the slot's stored configuration cannot be opened", "无法打开槽位中保存的配置"),
    0x6581: ("the device could not store the slot", "设备无法保存该槽位"),
    0x6700: ("the device refused the configuration", "设备拒绝了该配置"),
    0x6985: ("refused now (the key store is locked)", "当前被拒绝（密钥存储已锁定）"),
    0x6A86: ("no such slot", "没有这个槽位"),
}


class _State:
    """The status the OTP application answers (SELECT and every write):
    version (3 bytes), programming sequence, configuration state (2 bytes,
    little endian), status flags."""

    def __init__(self, answer):
        self._read(answer, "OTP status", "OTP 状态")

    def _read(self, answer, what, what_zh):
        if len(answer) < 6:
            raise _error("%s: malformed answer from the device" % what, "%s：设备的应答格式错误" % what_zh)
        self.version = tuple(answer[:3])
        self.seq = answer[3]
        self.touch_level = answer[4] | answer[5] << 8

    def configured(self, slot):
        return bool(self.touch_level & STATE_VALID[slot])

    def touch_triggered(self, slot):
        return bool(self.touch_level & STATE_TOUCH[slot])

    def written(self, answer, what, what_zh):
        """The status after a write: stored when the programming sequence
        moved on (or went to 0 with every slot empty, as some YubiKeys do)."""
        prev = self.seq
        self._read(answer, what, what_zh)
        if self.seq == (prev + 1) & 0xFF or (self.seq == 0 and prev > 0 and not self.touch_level & STATE_MASK):
            return
        raise _error("%s: the device did not store it" % what, "%s：设备没有保存" % what_zh)


class OtpManager:
    """The OTP slots of the device of m (a librefido.mgmt.Management). Every
    operation is one PC/SC transaction (the OTP application selected, the
    management applet selected again afterwards). Errors: ManagerError
    (AuthRequired: a slot is protected by an access code and none was given;
    WrongSecret: the access code given is wrong; NotSupported: no OTP
    application)."""

    random_yubico_otp = staticmethod(random_yubico_otp)

    def __init__(self, m):
        self.m = m

    @contextmanager
    def _session(self):
        with applet(self.m, OTP_AID, "OTP") as answer:
            yield self.m.card, _State(answer)

    # -- reading ---------------------------------------------------------------

    @staticmethod
    def _ext_status(card):
        """{slot: (tkt, cfg, public ID or None)} of the programmed slots, from
        the extended status; {} when the device does not answer it (older
        firmware, key store locked)."""
        data, sw = card.transmit(0x00, INS_CONFIG, CMD_STATUS_EXT, 0x00, b"", le=0, check=False)
        if sw != 0x9000:
            return {}
        out = {}
        try:
            for tag, value in parse_tlvs(data, "OTP status", "OTP 状态"):
                slot = tag - 0xB0 + 1
                if slot not in SLOTS:
                    continue
                inner = dict(parse_tlvs(value, "OTP status", "OTP 状态"))
                flags, fixed = inner.get(0xA0, b""), inner.get(0xC0)
                if len(flags) == 2:
                    out[slot] = (flags[0], flags[1], fixed)
        except ManagerError:
            return {}
        return out

    @staticmethod
    def _serial(card):
        data, sw = card.transmit(0x00, INS_CONFIG, CMD_DEVICE_SERIAL, 0x00, b"", le=0, check=False)
        return int.from_bytes(data[:4], "big") if sw == 0x9000 and len(data) >= 4 else None

    def status(self):
        """{"version": "x.y.z" (of the OTP application), "serial": int or
        None, "slots": {1: {...}, 2: {...}}} with, for each slot:
          configured (bool): from the configuration state;
          touch_triggered (bool): a press makes the slot type (never a
          challenge-response slot, even one that needs a touch: see touch);
          from the slot's flags when the device reports them, else from the
          configuration state;
          mode: one of MODES (None when empty or the device does not say);
          public_id: modhex (Yubico OTP); digits: 6 or 8 (HOTP);
          append_cr: whether Enter follows (the modes that type);
          touch: whether a challenge-response needs a touch (challenge-
          response modes); None where not applicable or unknown.
        Whether a slot has an access code cannot be read."""
        with self._session() as (card, st):
            ext = self._ext_status(card)
            serial = self._serial(card)
        slots = {}
        for slot in SLOTS:
            info = {"configured": st.configured(slot), "touch_triggered": st.touch_triggered(slot), "mode": None,
                    "public_id": None, "digits": None, "append_cr": None, "touch": None}
            if info["configured"] and slot in ext:
                tkt, cfg, fixed = ext[slot]
                mode = info["mode"] = slot_mode(tkt, cfg)
                if mode.startswith("chal-"):
                    info["touch"] = bool(cfg & CFG_CHAL_BTN_TRIG)
                else:
                    info["append_cr"] = bool(tkt & TKT_APPEND_CR)
                # from the flags, as a YubiKey reports it (yubikit: "triggered
                # by touch (not challenge-response)"): the state of the 2.0.x
                # firmware takes an OATH-HOTP slot (its HOTP flag is the
                # challenge-response flag) for one that needs no touch, and a
                # challenge-response slot that waits for the button for one
                # that types on a press; 2.1.0 reports the same as the flags
                info["touch_triggered"] = not mode.startswith("chal-")
                if mode == "hotp":
                    info["digits"] = 8 if cfg & CFG_OATH_HOTP8 else 6
                if mode == "yubico-otp" and fixed:
                    info["public_id"] = modhex_encode(fixed)
            slots[slot] = info
        return {"version": "%d.%d.%d" % st.version, "serial": serial, "slots": slots}

    def serial(self):
        """The device's serial number as the OTP application reports it (for
        a YubiCloud upload), None when it does not."""
        with self._session() as (card, _):
            return self._serial(card)

    # -- writing ---------------------------------------------------------------

    @staticmethod
    def _write(card, st, cmd, config, current, what, what_zh, texts=None, note=("", "")):
        """Sends a slot command: config followed by the current access code
        (zeros for none), and checks that the device stored it. note: added
        to the access code messages."""
        data = bytearray(config) + bytearray(current or bytes(ACC_CODE_SIZE))
        try:
            # without Le, as yubikit sends it: the device answers its status
            answer, sw = card.transmit(0x00, INS_CONFIG, cmd, 0x00, bytes(data), le=None, check=False)
        finally:
            wipe(data)
        if sw == 0x6982:
            if current is None:
                raise _error("%s: protected by an access code; enter it%s" % (what, note[0]),
                             "%s：受访问码保护，请输入访问码%s" % (what_zh, note[1]), sw, AuthRequired)
            raise _error("%s: wrong access code%s" % (what, note[0]), "%s：访问码错误%s" % (what_zh, note[1]), sw,
                         WrongSecret)
        if sw != 0x9000:
            raise sw_error(what, sw, what_zh, dict(_WRITE_TEXTS, **(texts or {})))
        st.written(answer, what, what_zh)

    def _program(self, slot, config, access_code, replace, what, what_zh):
        slot = _slot(slot)
        current = access_code_bytes(access_code, "current access code", "当前访问码")
        what, what_zh = "OTP slot %d: %s" % (slot, what), "OTP 槽位 %d：%s" % (slot, what_zh)
        with self._session() as (card, st):
            if st.configured(slot) and not replace:
                raise _error("%s: the slot is programmed; replace it explicitly" % what,
                             "%s：槽位已有配置，需明确选择替换" % what_zh, 0x6A89)
            self._write(card, st, CMD_CONFIG[slot], config, current, what, what_zh)

    def program_yubico_otp(self, slot, public_id, private_id, key, access_code=None, new_access_code=None,
                           append_cr=True, replace=False):
        """Programs a Yubico OTP credential (see yubico_otp_config and
        random_yubico_otp). access_code: the slot's current one;
        new_access_code: the one that protects it from now on (None: none);
        replace: a configuration in the slot may be replaced."""
        config = yubico_otp_config(public_id, private_id, key, append_cr, new_access_code)
        self._program(slot, config, access_code, replace, "Yubico OTP", "Yubico OTP")

    def program_chalresp(self, slot, key, touch=False, access_code=None, new_access_code=None, replace=False):
        """Programs HMAC-SHA1 challenge-response: key up to 20 bytes; touch:
        each response needs a touch."""
        config = hmac_sha1_config(key, touch, new_access_code)
        self._program(slot, config, access_code, replace, "challenge-response", "挑战-响应")

    def program_static(self, slot, password, layout="us", append_cr=True, access_code=None, new_access_code=None,
                       replace=False):
        """Programs a static password (at most 38 characters the keyboard
        layout "us" or "modhex" types)."""
        config = static_password_config(encode_scan_codes(password, layout), append_cr, new_access_code)
        self._program(slot, config, access_code, replace, "static password", "静态密码")

    def program_hotp(self, slot, secret, digits=6, counter=0, append_cr=True, access_code=None,
                     new_access_code=None, replace=False):
        """Programs OATH-HOTP (see hotp_config): secret bytes, or base32."""
        config = hotp_config(secret, digits, counter, append_cr, new_access_code)
        self._program(slot, config, access_code, replace, "OATH-HOTP", "OATH-HOTP")

    def set_access_code(self, slot, new_access_code, access_code=None):
        """Sets, changes or (new_access_code None) removes the access code
        of a programmed slot with a slot update, which keeps the secrets and
        the counter: access_code is the current one. The update keeps the
        slot's settings the device reports (Enter, tabs, delays, pacing) and
        sets yubikit's extended flags. Refused for a configuration without
        the update flag (programmed elsewhere): program the slot again."""
        slot = _slot(slot)
        current = access_code_bytes(access_code, "current access code", "当前访问码")
        new = access_code_bytes(new_access_code, "new access code", "新访问码")
        what, what_zh = "OTP slot %d: access code" % slot, "OTP 槽位 %d：访问码" % slot
        with self._session() as (card, st):
            if not st.configured(slot):
                raise _error("%s: the slot is not programmed" % what, "%s：槽位没有配置" % what_zh)
            flags = self._ext_status(card).get(slot)
            if flags is None:
                config = update_config(access_code=new)         # yubikit's defaults, as ykman
            elif slot_mode(flags[0], flags[1]).startswith("chal-"):
                config = update_config(0, 0, keyboard=False, access_code=new)
            else:
                # (the pacing bits only mean pacing in the modes that type)
                config = update_config(flags[0] & TKT_UPDATE_MASK, flags[1] & CFG_UPDATE_MASK, access_code=new)
            self._write(card, st, CMD_UPDATE[slot], config, current, what, what_zh, texts={
                0x6985: ("the slot's configuration does not allow updates (program the slot again), or the key "
                         "store is locked", "槽位的配置不允许更新（请重新配置槽位），或密钥存储已锁定")})

    def delete(self, slot, access_code=None):
        """Deletes the configuration of a slot (its secrets are gone)."""
        slot = _slot(slot)
        current = access_code_bytes(access_code, "current access code", "当前访问码")
        what, what_zh = "OTP slot %d: delete" % slot, "OTP 槽位 %d：删除" % slot
        with self._session() as (card, st):
            if not st.configured(slot):
                raise _error("%s: the slot is not programmed" % what, "%s：槽位没有配置" % what_zh)
            self._write(card, st, CMD_CONFIG[slot], DELETE_CONFIG, current, what, what_zh)

    def swap(self, access_code=None):
        """Swaps the configurations of slots 1 and 2. A protected slot only
        moves with its access code: one code is sent, so two protected slots
        swap only when they have the same one."""
        current = access_code_bytes(access_code, "current access code", "当前访问码")
        what, what_zh = "OTP slots: swap", "OTP 槽位：交换"
        with self._session() as (card, st):
            if not st.configured(1) and not st.configured(2):
                raise _error("%s: both slots are empty" % what, "%s：两个槽位都是空的" % what_zh)
            self._write(card, st, CMD_SWAP, b"", current, what, what_zh,
                        note=(" (two protected slots swap only when they have the same access code)",
                              "（两个槽位都受保护时，只有访问码相同才能交换）"))

    # -- using -----------------------------------------------------------------

    def calculate_hmac(self, slot, challenge):
        """The HMAC-SHA1 response (20 bytes) of a challenge-response slot to
        challenge (up to 64 bytes; of a 64-byte one the device, like a
        YubiKey, takes the last byte and the equal bytes before it for
        padding, as yubikit leaves it). For a slot that needs a touch this
        returns after the touch (ManagerError 6985 when none came)."""
        slot = _slot(slot)
        challenge = bytes(challenge)
        what, what_zh = "OTP slot %d: challenge-response" % slot, "OTP 槽位 %d：挑战-响应" % slot
        if len(challenge) > HMAC_CHALLENGE_SIZE:
            raise _error("%s: a challenge has at most %d bytes" % (what, HMAC_CHALLENGE_SIZE),
                         "%s：挑战最多 %d 字节" % (what_zh, HMAC_CHALLENGE_SIZE))
        with self._session() as (card, st):
            if not st.configured(slot):
                raise _error("%s: the slot is not programmed" % what, "%s：槽位没有配置" % what_zh)
            answer, sw = card.transmit(0x00, INS_CONFIG, CMD_CHAL_HMAC[slot], 0x00, pad_challenge(challenge),
                                       le=None, check=False)
        if sw != 0x9000:
            raise sw_error(what, sw, what_zh, {
                0x6700: ("the slot is not programmed for HMAC-SHA1 challenge-response",
                         "槽位没有配置为 HMAC-SHA1 挑战-响应"),
                0x6985: ("not confirmed: touch the key when it blinks (or the key store is locked)",
                         "未确认：请在按键闪烁时触摸它（或密钥存储已锁定）"),
                0x6400: _WRITE_TEXTS[0x6400]})
        if len(answer) != HMAC_RESPONSE_SIZE:
            raise _error("%s: malformed answer from the device" % what, "%s：设备的应答格式错误" % what_zh)
        return answer


__all__ = ["OtpManager", "OTP_AID", "SLOTS", "MODES", "KEYBOARD_LAYOUTS", "access_code_bytes", "modhex_encode",
           "modhex_decode", "encode_scan_codes", "random_static_password", "random_yubico_otp", "format_csv",
           "calculate_crc", "check_crc", "build_config", "yubico_otp_config", "hmac_sha1_config",
           "static_password_config", "hotp_config", "update_config", "pad_challenge", "slot_mode", "DELETE_CONFIG"]
