"""Helpers for the OATH / OTP / management regression tests: emulators the
tests own (they may need a manual button or a fresh flash) and raw APDUs.

Works with and without the harness plugin (starting an own emulator or
pcscd suspends the plugin's session ones).
"""

import hmac
import os
import threading
import time

import pytest

from harness import ctaphid
from harness.card import Card
from harness.emulator import Button, Emulator, Pcscd, ensure_session

OATH_AID = bytes.fromhex("A0000005272101")
OTP_AID = bytes.fromhex("A0000005272001")
MGMT_AID = bytes.fromhex("A000000527471117")

# YKOATH
INS_PUT, INS_DELETE, INS_SET_CODE, INS_RESET, INS_RENAME = 0x01, 0x02, 0x03, 0x04, 0x05
INS_LIST, INS_CALCULATE, INS_VALIDATE, INS_CALC_ALL, INS_SEND_REMAINING = 0xA1, 0xA2, 0xA3, 0xA4, 0xA5
INS_VERIFY_CODE, INS_VERIFY_PIN, INS_CHANGE_PIN, INS_SET_PIN, INS_GET_CREDENTIAL = 0xB1, 0xB2, 0xB3, 0xB4, 0xB5
TAG_NAME, TAG_NAME_LIST, TAG_KEY, TAG_CHALLENGE, TAG_RESPONSE = 0x71, 0x72, 0x73, 0x74, 0x75
TAG_T_RESPONSE, TAG_NO_RESPONSE, TAG_PROPERTY, TAG_IMF, TAG_TOUCH_RESPONSE = 0x76, 0x77, 0x78, 0x7A, 0x7C
TAG_PASSWORD, TAG_NEW_PASSWORD, TAG_PWS_LOGIN, TAG_PWS_PASSWORD = 0x80, 0x81, 0x83, 0x84
TOTP, HOTP, SHA1 = 0x20, 0x10, 0x01

RFC4226_SECRET = b"12345678901234567890"
RFC4226_CODES = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489]

SW_OK = 0x9000
SW_WRONG_DATA = 0x6700
SW_SECURITY = 0x6982
SW_BLOCKED = 0x6983
SW_DATA_INVALID = 0x6984
SW_CONDITIONS = 0x6985
SW_INCORRECT_PARAMS = 0x6A80
SW_P1P2 = 0x6A86


@pytest.fixture(scope="module")
def pcscd():
    """The PC/SC daemon: the harness plugin's one when the plugin is loaded,
    else an own one. With the plugin, the session emulator the tests here
    suspend is brought back afterwards: the upstream suites' class-scoped
    fixtures connect before any function-scoped fixture could restart it."""
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    plugin = ensure_session() is not None
    if not plugin:
        p.start()
    ctaphid.install()
    yield p
    if plugin:
        ensure_session()
    else:
        p.stop()


@pytest.fixture
def device(pcscd, tmp_path):
    """device(**env) starts an emulator on a fresh flash (restart() keeps it)."""
    made = []

    def make(binary=None, chip_id=None, **env):
        e = Emulator(binary=binary, workdir=str(tmp_path / "dev"), env=env, chip_id=chip_id)
        e.start()
        made.append(e)
        return e
    yield make
    for e in made:
        e.stop()


def tlv(tag, value):
    value = bytes(value)
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    if len(value) < 0x100:
        return bytes([tag, 0x81, len(value)]) + value
    return bytes([tag, 0x82]) + len(value).to_bytes(2, "big") + value


def parse_tlvs(data):
    """[(tag, value)] of a response (1-byte tags, BER lengths)."""
    out, i = [], 0
    while i < len(data):
        tag, n = data[i], data[i + 1]
        i += 2
        if n == 0x81:
            n, i = data[i], i + 1
        elif n == 0x82:
            n, i = int.from_bytes(data[i:i + 2], "big"), i + 2
        out.append((tag, bytes(data[i:i + n])))
        i += n
    return out


def open_card(timeout=15.0):
    """A card connection to a device that answers (right after an emulator
    start the reader may still hold the previous card)."""
    deadline = time.time() + timeout
    while True:
        card = None
        try:
            card = Card()
            card.raw(bytes([0x00, 0xA4, 0x04, 0x00, len(MGMT_AID)]) + MGMT_AID)
            return card
        except Exception:
            if card is not None:
                card.close()
            if time.time() > deadline:
                raise
            time.sleep(0.3)


def apdu(card, ins, p1=0, p2=0, data=b"", cla=0x00, le=True):
    """One command, no GET RESPONSE: (data, sw). Extended length above 255."""
    data = bytes(data)
    if len(data) > 255:
        cmd = bytes([cla, ins, p1, p2, 0]) + len(data).to_bytes(2, "big") + data + (b"\0\0" if le else b"")
    else:
        cmd = bytes([cla, ins, p1, p2]) + (bytes([len(data)]) + data if data else b"") + (b"\0" if le else b"")
    return card.raw(cmd)


def select(card, aid=OATH_AID):
    data, sw = apdu(card, 0xA4, 0x04, 0x00, aid)
    assert sw == SW_OK, "select %s: %04X" % (aid.hex(), sw)
    return data


def oath_select(card):
    """SELECT OATH; returns the challenge (None without access code)."""
    return dict(parse_tlvs(select(card))).get(TAG_CHALLENGE)


def oath_reset(card):
    _, sw = apdu(card, INS_RESET, 0xDE, 0xAD)
    assert sw == SW_OK


def put(card, name, secret, kind=TOTP, digits=6, touch=False, imf=None, extra=b""):
    """PUT as yubikit sends it: name, key, IMF, bare property (no length)."""
    data = tlv(TAG_NAME, name) + tlv(TAG_KEY, bytes([kind | SHA1, digits]) + secret)
    if imf is not None:
        data += tlv(TAG_IMF, imf.to_bytes(4, "big"))
    data += extra
    if touch:
        data += bytes([TAG_PROPERTY, 0x02])
    return apdu(card, INS_PUT, data=data)[1]


def hmac_sha1(key, msg):
    return hmac.new(key, msg, "sha1").digest()


def set_code(card, key, resp=None):
    chal = os.urandom(8)
    if resp is None:
        resp = hmac_sha1(key, chal)
    data = tlv(TAG_KEY, bytes([TOTP | SHA1]) + key) + tlv(TAG_CHALLENGE, chal) + tlv(TAG_RESPONSE, resp)
    return apdu(card, INS_SET_CODE, data=data)[1]


def validate(card, key, challenge, resp=None):
    if resp is None:
        resp = hmac_sha1(key, challenge)
    mine = os.urandom(8)
    data, sw = apdu(card, INS_VALIDATE, data=tlv(TAG_RESPONSE, resp) + tlv(TAG_CHALLENGE, mine))
    if sw == SW_OK:
        assert dict(parse_tlvs(data))[TAG_RESPONSE] == hmac_sha1(key, mine)
    return sw


def truncated(value, digits=6):
    return (int.from_bytes(value[1:5], "big") & 0x7FFFFFFF) % (10 ** digits)


def calculate(card, name, challenge=b"", truncate=True):
    """(code or response bytes, sw)"""
    data, sw = apdu(card, INS_CALCULATE, 0, 1 if truncate else 0,
                    tlv(TAG_NAME, name) + tlv(TAG_CHALLENGE, challenge))
    if sw != SW_OK:
        return None, sw
    tag, value = parse_tlvs(data)[0]
    return (truncated(value, value[0]) if truncate else value[1:]), sw


def totp(secret, challenge, digits=6):
    h = hmac_sha1(secret, challenge)
    off = h[-1] & 0x0F
    return (int.from_bytes(h[off:off + 4], "big") & 0x7FFFFFFF) % (10 ** digits)


def pressing(fn, delay=0.3):
    """Runs fn() while the button is pressed once, delay seconds after the start."""
    def press():
        time.sleep(delay)
        b = Button()
        b.press(0.15)
        b.close()
    t = threading.Thread(target=press)
    t.start()
    try:
        return fn()
    finally:
        t.join()


def press_idle(times=1):
    """Presses while idle (OTP slot event: 1 press slot 1, 2 presses slot 2)."""
    b = Button()
    for i in range(times):
        b.press(0.1)
        time.sleep(0.2)
    b.close()


def hid_otp(raw, cid, cmd):
    """One APDU over the HID vendor command (CTAPHID_OTP, Nitrokey): (data, sw)."""
    from harness.ctaphid import CMD_OTP
    rcmd, data = raw.call(cid, CMD_OTP, bytes(cmd))
    assert rcmd == CMD_OTP, "CTAPHID error %s" % data.hex()
    return data[2:], int.from_bytes(data[:2], "big")


def hid_apdu(raw, cid, ins, p1=0, p2=0, data=b""):
    data = bytes(data)
    return hid_otp(raw, cid, bytes([0x00, ins, p1, p2]) + (bytes([len(data)]) + data if data else b""))


def flash_has(emu, needle):
    """The needle is somewhere in the emulator's flash file (stopped device)."""
    with open(emu.flash_path, "rb") as f:
        return bytes(needle) in f.read()


def log_since(emu, offset):
    with open(emu.log_path, errors="replace") as f:
        f.seek(offset)
        return f.read()


def log_size(emu):
    return os.path.getsize(emu.log_path)
