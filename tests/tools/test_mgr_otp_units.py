"""OTP slot manager (librefido.mgr_otp) without a device: the frames are byte
for byte yubikit's (flags, CRC, access code layout), whole command sequences
included (yubikit's YubiOtpSession and the manager against the same
simulated OTP application); the keyboard layouts and the upload CSV are
ykman's; checks and messages of the manager. yubikit / ykman are references
only (tests skip without them), not dependencies of librefido.

    PYTHONPATH=tools/librefido python -m pytest -q tests/tools/test_mgr_otp_units.py
"""

import hmac
import os
import types
from contextlib import contextmanager
from datetime import datetime

import pytest

from librefido import mgr_otp as O
from librefido.mgr_common import AuthRequired, ManagerError, NotSupported, WrongSecret
from librefido.pcsc import MGMT_AID, Card

KEY20 = bytes(range(1, 21))
CODE = bytes.fromhex("0102030405ff")
CODE2 = bytes.fromhex("a1a2a3a4a5a6")


@pytest.fixture
def yk():
    return pytest.importorskip("yubikit.yubiotp")


# -- a simulated OTP application (pico-fido/src/fido/otp.c over CCID) ------------

def _decode(apdu):
    """(cla, ins, p1, p2, data) of a short or extended command APDU."""
    apdu = bytes(apdu)
    head, body = apdu[:4], apdu[4:]
    if len(body) <= 1:
        data = b""
    elif body[0] == 0 and len(body) >= 3:
        data = body[3:3 + int.from_bytes(body[1:3], "big")]
    else:
        data = body[1:1 + body[0]]
    return head[0], head[1], head[2], head[3], data


class FakeOtp:
    """The OTP application: slots 1 and 2, access codes, the programming
    sequence, the extended status, HMAC challenge-response. Records every
    command (ins, p1, p2, data)."""

    AID = O.OTP_AID

    def __init__(self, version=(7, 2, 0), ext_status=True, store=True, old_state=False):
        self.version = version
        self.slots = {}                 # slot -> 52-byte configuration
        self.seq = 0
        self.selected = None
        self.log = []
        self.ext_status = ext_status    # answers P1 14
        self.store = store              # False: answers writes without storing (sequence stays)
        # True: the configuration state of the 2.0.x firmware (an HOTP slot not
        # touch triggered, a challenge-response slot that waits for the button
        # touch triggered)
        self.old_state = old_state

    # configuration fields: fixed 0-15, UID 16-21, key 22-37, access code
    # 38-43, fixed size 44, ext 45, tkt 46, cfg 47, RFU 48-49, CRC 50-51

    def status(self):
        level = 0
        for s, c in self.slots.items():
            level |= O.STATE_VALID[s]
            chal = c[46] & O.TKT_CHAL_RESP and (c[47] & O.CFG_CHAL_YUBICO or self.old_state)
            if not chal or (self.old_state and c[47] & O.CFG_CHAL_BTN_TRIG):
                level |= O.STATE_TOUCH[s]
        return bytes(self.version) + bytes([self.seq, level, 0, 0])

    def apdu(self, apdu):
        cla, ins, p1, p2, data = _decode(apdu)
        if ins == 0xA4:
            if data == self.AID:
                self.selected = data
                self.seq = 1 if self.slots else 0
                return self.status(), 0x9000
            if data == MGMT_AID:
                self.selected = data
                return b"LF\x03", 0x9000
            return b"", 0x6A82
        if self.selected != self.AID:
            return b"", 0x6D00
        self.log.append((ins, p1, p2, data))
        if ins != 0x01:
            return b"", 0x6D00
        return self.command(p1, data)

    @staticmethod
    def _code(cfg):
        return cfg[38:44]

    def _stored(self):
        if self.store:
            self.seq = (self.seq + 1) & 0xFF
        return self.status(), 0x9000

    def command(self, p1, data):
        if p1 in (0x01, 0x03):
            slot = 1 if p1 == 0x01 else 2
            if len(data) < 58:
                return b"", 0x6700
            cur = self.slots.get(slot)
            if cur is not None and self._code(cur) != data[52:58]:
                return b"", 0x6982
            if not any(data[:52]):
                self.slots.pop(slot, None)
                return self._stored()
            if data[48:50] != b"\0\0" or not O.check_crc(data[:52]):
                return b"", 0x6700
            self.slots[slot] = data[:52]
            return self._stored()
        if p1 in (0x04, 0x05):
            slot = 1 if p1 == 0x04 else 2
            cur = self.slots.get(slot)
            if cur is None:
                return self.status(), 0x9000        # not stored: the sequence stays
            if self._code(cur) != data[52:58]:
                return b"", 0x6982
            if not cur[45] & O.EXT_ALLOW_UPDATE:
                return b"", 0x6985
            new = bytearray(cur)
            new[38:44] = data[38:44]
            new[45] = data[45]
            new[46] = (cur[46] & ~O.TKT_UPDATE_MASK) | (data[46] & O.TKT_UPDATE_MASK)
            if not cur[46] & O.TKT_CHAL_RESP:
                new[47] = (cur[47] & ~O.CFG_UPDATE_MASK) | (data[47] & O.CFG_UPDATE_MASK)
            new[50:52] = struct_crc(bytes(new[:50]))
            self.slots[slot] = bytes(new)
            return self._stored()
        if p1 == 0x06:
            given = data[:6] if len(data) == 6 else None
            for c in self.slots.values():
                if any(self._code(c)) and self._code(c) != given:
                    return b"", 0x6982
            a, b = self.slots.pop(1, None), self.slots.pop(2, None)
            if b is not None:
                self.slots[1] = b
            if a is not None:
                self.slots[2] = a
            return self._stored()
        if p1 == 0x10:
            return (123456).to_bytes(4, "big"), 0x9000
        if p1 == 0x14:
            if not self.ext_status:
                return b"", 0x6985
            out = b""
            for s in sorted(self.slots):
                c = self.slots[s]
                inner = bytes([0xA0, 2, c[46], c[47]])
                if O.slot_mode(c[46], c[47]) == "yubico-otp":
                    inner += bytes([0xC0, 6]) + c[:6]
                out += bytes([0xB0 + s - 1, len(inner)]) + inner
            return out, 0x9000
        if p1 in (0x30, 0x38):
            c = self.slots.get(1 if p1 == 0x30 else 2)
            if c is None:
                return b"", 0x9000
            if not c[46] & O.TKT_CHAL_RESP or c[47] & O.CFG_CHAL_HMAC != O.CFG_CHAL_HMAC:
                return b"", 0x6700
            chal = data
            if len(chal) == 64 and c[47] & O.CFG_HMAC_LT64:
                chal = chal.rstrip(chal[-1:])
            return hmac.new(c[22:38] + c[16:22], chal, "sha1").digest(), 0x9000
        return b"", 0x9000

    def writes(self):
        """The slot commands (not the queries 10 and 14)."""
        return [e for e in self.log if e[1] not in (0x10, 0x14)]


def struct_crc(buf):
    return (0xFFFF & ~O.calculate_crc(buf)).to_bytes(2, "little")


class _Conn:
    """pyscard connection stand-in in front of a FakeOtp."""

    def __init__(self, dev):
        self.dev = dev

    def transmit(self, apdu):
        data, sw = self.dev.apdu(bytes(apdu))
        return list(data), sw >> 8, sw & 0xFF


class FakeCard(Card):
    """librefido.pcsc.Card (its own APDU encoding) without PC/SC transactions."""

    def __init__(self, dev):
        super().__init__(_Conn(dev), "fake")
        self.transactions = 0

    @contextmanager
    def transaction(self, aid=None):
        self.transactions += 1
        if aid is not None:
            self.select(aid)
        yield self


def manager(dev):
    return O.OtpManager(types.SimpleNamespace(card=FakeCard(dev)))


def yk_session(yk, dev):
    from yubikit.core import TRANSPORT
    from yubikit.core.smartcard import SmartCardConnection

    class Conn(SmartCardConnection):
        @property
        def transport(self):
            return TRANSPORT.USB

        def send_and_receive(self, apdu):
            return dev.apdu(apdu)

        def close(self):
            pass
    return yk.YubiOtpSession(Conn())


# -- frames --------------------------------------------------------------------------

def test_crc_is_yubikits():
    core = pytest.importorskip("yubikit.core.otp")
    for n in (0, 1, 7, 50, 64, 70):
        data = os.urandom(n)
        assert O.calculate_crc(data) == core.calculate_crc(data)
    frame = O.hmac_sha1_config(KEY20)
    assert O.check_crc(frame) and core.check_crc(frame)


PUB, PRIV, AES = b"\xff\x01\x02\x03\x04\x05", bytes.fromhex("a0a1a2a3a4a5"), bytes(range(16))


@pytest.mark.parametrize("append_cr", [True, False])
@pytest.mark.parametrize("code", [None, CODE])
def test_yubico_otp_frame(yk, append_cr, code):
    ref = yk.YubiOtpSlotConfiguration(PUB, PRIV, AES).append_cr(append_cr).get_config(code)
    assert O.yubico_otp_config(PUB, PRIV, AES, append_cr, code) == ref
    # the same from text: modhex public ID, hexadecimal private ID and key
    assert O.yubico_otp_config(O.modhex_encode(PUB).upper(), PRIV.hex(), " ".join(AES.hex()[i:i + 4]
                                                                                for i in range(0, 32, 4)),
                               append_cr, code.hex() if code else None) == ref


@pytest.mark.parametrize("key", [KEY20, KEY20[:16], KEY20[:5], bytes(range(65)), bytes(range(200))])
@pytest.mark.parametrize("touch", [False, True])
@pytest.mark.parametrize("code", [None, CODE])
def test_hmac_frame(yk, key, touch, code):
    ref = yk.HmacSha1SlotConfiguration(key).require_touch(touch).get_config(code)
    assert O.hmac_sha1_config(key, touch, code) == ref
    assert O.hmac_sha1_config(key.hex(), touch, code) == ref


@pytest.mark.parametrize("password", ["Passw0rd!", "x", "ab" * 19, "~`!@#$%^&*()_+-={}[]|\\:;\"'<>,.?/ Zz"])
@pytest.mark.parametrize("append_cr", [True, False])
def test_static_frame(yk, password, append_cr):
    scancodes = pytest.importorskip("ykman.scancodes")
    codes = O.encode_scan_codes(password, "us")
    assert codes == scancodes.encode(password, scancodes.KEYBOARD_LAYOUT.US)
    ref = yk.StaticPasswordSlotConfiguration(codes).append_cr(append_cr).get_config(CODE)
    assert O.static_password_config(codes, append_cr, CODE) == ref


@pytest.mark.parametrize("key", [KEY20, KEY20[:10], bytes(range(100))])
@pytest.mark.parametrize("digits,counter", [(6, 0), (8, 16), (6, O.HOTP_IMF_MAX), (8, 4096)])
@pytest.mark.parametrize("append_cr", [True, False])
def test_hotp_frame(yk, key, digits, counter, append_cr):
    ref = yk.HotpSlotConfiguration(key).imf(counter).digits8(digits == 8).append_cr(append_cr).get_config(CODE2)
    assert O.hotp_config(key, digits, counter, append_cr, CODE2) == ref


def test_hotp_secret_as_base32(yk):
    import base64
    text = base64.b32encode(KEY20).decode().lower().rstrip("=")
    text = " ".join(text[i:i + 4] for i in range(0, len(text), 4))
    assert O.hotp_config(text) == yk.HotpSlotConfiguration(KEY20).get_config()


@pytest.mark.parametrize("tkt", [0, O.TKT_APPEND_CR, O.TKT_TAB_FIRST | O.TKT_APPEND_TAB2 | O.TKT_APPEND_DELAY1,
                                 O.TKT_UPDATE_MASK])
@pytest.mark.parametrize("cfg", [0, O.CFG_PACING_10MS, O.CFG_PACING_10MS | O.CFG_PACING_20MS])
@pytest.mark.parametrize("keyboard", [True, False])
@pytest.mark.parametrize("code", [None, CODE])
def test_update_frame(yk, tkt, cfg, keyboard, code):
    ref = yk.UpdateConfiguration().append_cr(bool(tkt & O.TKT_APPEND_CR)).tabs(
        bool(tkt & O.TKT_TAB_FIRST), bool(tkt & O.TKT_APPEND_TAB1), bool(tkt & O.TKT_APPEND_TAB2)).delay(
        bool(tkt & O.TKT_APPEND_DELAY1), bool(tkt & O.TKT_APPEND_DELAY2)).pacing(
        bool(cfg & O.CFG_PACING_10MS), bool(cfg & O.CFG_PACING_20MS)).fast_trigger(keyboard).get_config(code)
    assert O.update_config(tkt, cfg, keyboard, code) == ref


def test_frames_are_told_apart_as_the_device_does():
    assert O.slot_mode(*O.yubico_otp_config(PUB, PRIV, AES)[46:48]) == "yubico-otp"
    assert O.slot_mode(*O.hmac_sha1_config(KEY20, True)[46:48]) == "chal-hmac"
    assert O.slot_mode(*O.hotp_config(KEY20, 8)[46:48]) == "hotp"
    assert O.slot_mode(*O.static_password_config(b"\x04\x05")[46:48]) == "static"
    assert O.slot_mode(O.TKT_CHAL_RESP, O.CFG_CHAL_YUBICO) == "chal-yubico"
    for frame in (O.yubico_otp_config(PUB, PRIV, AES, access_code=CODE), O.hotp_config(KEY20), O.update_config()):
        assert len(frame) == O.CONFIG_SIZE and O.check_crc(frame)


def test_challenge_padding_is_yubikits(yk):
    for chal in (b"", b"\0", b"abc", b"abc\0", os.urandom(63), os.urandom(64)):
        expected = chal.ljust(64, b"\1" if chal.endswith(b"\0") else b"\0")
        assert O.pad_challenge(chal) == expected


# -- whole command sequences: yubikit's session and the manager ----------------------

def _both(yk, run_yk, run_mgr, setup=None):
    a, b = FakeOtp(), FakeOtp()
    for dev in (a, b):
        if setup:
            setup(dev)
    run_yk(yk_session(yk, a))
    run_mgr(manager(b))
    assert a.writes() and a.writes() == b.writes()
    assert a.slots == b.slots
    return a, b


def test_programming_sends_what_yubikit_sends(yk):
    S = yk.SLOT

    def with_yk(s):
        s.put_configuration(S.ONE, yk.YubiOtpSlotConfiguration(PUB, PRIV, AES), acc_code=CODE)
        s.put_configuration(S.TWO, yk.HmacSha1SlotConfiguration(KEY20).require_touch(True))
        s.put_configuration(S.ONE, yk.HotpSlotConfiguration(KEY20).imf(32).digits8(True).append_cr(False),
                            acc_code=CODE2, cur_acc_code=CODE)
        s.put_configuration(S.TWO, yk.StaticPasswordSlotConfiguration(bytes([4, 5, 0x86])), cur_acc_code=None)

    def with_mgr(m):
        m.program_yubico_otp(1, PUB, PRIV, AES, new_access_code=CODE)
        m.program_chalresp(2, KEY20, touch=True)
        m.program_hotp(1, KEY20, digits=8, counter=32, append_cr=False, access_code=CODE, new_access_code=CODE2,
                       replace=True)
        m.program_static(2, "abC", replace=True)
    _both(yk, with_yk, with_mgr)


def test_delete_update_and_hmac_send_what_yubikit_sends(yk):
    S = yk.SLOT

    def setup(dev):
        dev.slots[1] = O.yubico_otp_config(PUB, PRIV, AES, access_code=CODE)
        dev.slots[2] = O.hmac_sha1_config(KEY20)
    out = {}

    def with_yk(s):
        out["yk"] = s.calculate_hmac_sha1(S.TWO, b"challenge")
        s.update_configuration(S.ONE, yk.UpdateConfiguration(), acc_code=CODE2, cur_acc_code=CODE)
        s.update_configuration(S.TWO, yk.UpdateConfiguration().append_cr(False).fast_trigger(False), acc_code=CODE)
        s.delete_slot(S.ONE, cur_acc_code=CODE2)

    def with_mgr(m):
        out["mgr"] = m.calculate_hmac(2, b"challenge")
        m.set_access_code(1, CODE2, access_code=CODE)
        m.set_access_code(2, CODE)
        m.delete(1, access_code=CODE2)
    a, b = _both(yk, with_yk, with_mgr, setup)
    assert out["mgr"] == out["yk"] == hmac.new(KEY20, b"challenge", "sha1").digest()
    assert b.slots == {2: O.hmac_sha1_config(KEY20, access_code=CODE)}


def test_protected_swap():
    """yubikit's swap sends no access code (6 zero bytes), which the device
    refuses for a protected slot; the manager sends the code in that field."""
    dev = FakeOtp()
    dev.slots[2] = O.hmac_sha1_config(KEY20, access_code=CODE)
    manager(dev).swap(access_code=CODE)
    assert dev.writes() == [(0x01, 0x06, 0x00, CODE)]
    assert dev.slots == {1: O.hmac_sha1_config(KEY20, access_code=CODE)}


def test_unprotected_swap_is_yubikits(yk):
    def setup(dev):
        dev.slots[1] = O.hmac_sha1_config(KEY20)
    _both(yk, lambda s: s.swap_slots(), lambda m: m.swap(), setup)


# -- the manager ------------------------------------------------------------------------

def test_status():
    dev = FakeOtp(version=(7, 2, 0))
    dev.slots[1] = O.yubico_otp_config(PUB, PRIV, AES, append_cr=False)
    dev.slots[2] = O.hmac_sha1_config(KEY20, touch=False)
    st = manager(dev).status()
    assert st["version"] == "7.2.0" and st["serial"] == 123456
    assert st["slots"][1] == {"configured": True, "touch_triggered": True, "mode": "yubico-otp",
                              "public_id": O.modhex_encode(PUB), "digits": None, "append_cr": False, "touch": None}
    assert st["slots"][2] == {"configured": True, "touch_triggered": False, "mode": "chal-hmac", "public_id": None,
                              "digits": None, "append_cr": None, "touch": False}
    # an HOTP slot is touch triggered; the state of the 2.0.x firmware took it
    # for one without touch (its HOTP flag is the challenge-response flag):
    # the flags tell
    dev.slots[2] = O.hotp_config(KEY20, 8)
    assert dev.status()[4] & O.STATE_TOUCH[2]
    s = manager(dev).status()["slots"][2]
    assert s["digits"] == 8 and s["touch_triggered"] is True and s["mode"] == "hotp"
    old = FakeOtp(old_state=True)
    old.slots[2] = O.hotp_config(KEY20, 8)
    assert not old.status()[4] & O.STATE_TOUCH[2]
    assert manager(old).status()["slots"][2] == s
    # a challenge-response slot that waits for the button types nothing on a
    # press: not touch triggered (yubikit: "not challenge-response"), though
    # the state of the 2.0.x firmware says it is
    for d in (dev, old):
        d.slots[2] = O.hmac_sha1_config(KEY20, touch=True)
    assert not dev.status()[4] & O.STATE_TOUCH[2] and old.status()[4] & O.STATE_TOUCH[2]
    for d in (dev, old):
        assert manager(d).status()["slots"][2] == {"configured": True, "touch_triggered": False, "mode": "chal-hmac",
                                                   "public_id": None, "digits": None, "append_cr": None, "touch": True}
    # older firmware (no extended status): the configuration state only
    dev.ext_status = False
    del dev.slots[2]
    st = manager(dev).status()
    assert st["slots"][1]["configured"] and st["slots"][1]["mode"] is None
    assert st["slots"][2] == {"configured": False, "touch_triggered": False, "mode": None, "public_id": None,
                              "digits": None, "append_cr": None, "touch": None}


def test_nothing_is_overwritten_silently():
    dev = FakeOtp()
    dev.slots[1] = O.hmac_sha1_config(KEY20)
    m = manager(dev)
    with pytest.raises(ManagerError) as e:
        m.program_chalresp(1, KEY20[:16])
    assert e.value.sw == 0x6A89 and "replace it explicitly" in str(e.value) and e.value.zh
    assert dev.writes() == [] and dev.slots[1] == O.hmac_sha1_config(KEY20)
    m.program_chalresp(1, KEY20[:16], replace=True)
    assert dev.slots[1] == O.hmac_sha1_config(KEY20[:16])
    m.program_chalresp(2, KEY20)            # an empty slot needs no confirmation


def test_access_code_missing_or_wrong():
    dev = FakeOtp()
    dev.slots[1] = O.hmac_sha1_config(KEY20, access_code=CODE)
    m = manager(dev)
    with pytest.raises(AuthRequired) as e:
        m.delete(1)
    assert e.value.sw == 0x6982 and "access code" in str(e.value) and e.value.zh
    with pytest.raises(WrongSecret):
        m.delete(1, access_code=CODE2)
    with pytest.raises(WrongSecret):
        m.program_static(1, "abc", access_code=CODE2.hex(), replace=True)
    with pytest.raises(AuthRequired) as e:
        m.swap()
    assert "same access code" in str(e.value)
    assert dev.slots[1] == O.hmac_sha1_config(KEY20, access_code=CODE)
    m.delete(1, access_code=CODE.hex().upper())
    assert dev.slots == {}


def test_access_code_set_and_removed_keeps_the_settings():
    dev = FakeOtp()
    dev.slots[1] = O.hotp_config(KEY20, 8, append_cr=False)
    m = manager(dev)
    m.set_access_code(1, CODE)
    assert dev.slots[1][38:44] == CODE and dev.slots[1][46] == O.TKT_OATH_HOTP      # still no Enter
    assert dev.log[-1] == (0x01, 0x04, 0x00, O.update_config(0, 0, True, CODE) + bytes(6))
    with pytest.raises(AuthRequired):
        m.set_access_code(1, None)
    m.set_access_code(1, None, access_code=CODE)
    assert dev.slots[1] == O.hotp_config(KEY20, 8, append_cr=False)
    with pytest.raises(ManagerError, match="not programmed"):
        m.set_access_code(2, CODE)


def test_a_write_the_device_did_not_store_is_an_error():
    dev = FakeOtp(store=False)
    with pytest.raises(ManagerError, match="did not store"):
        manager(dev).program_chalresp(1, KEY20)


def test_empty_slots():
    dev = FakeOtp()
    m = manager(dev)
    with pytest.raises(ManagerError, match="not programmed"):
        m.delete(2)
    with pytest.raises(ManagerError, match="both slots are empty"):
        m.swap()
    with pytest.raises(ManagerError, match="not programmed"):
        m.calculate_hmac(1, b"x")
    assert dev.writes() == []
    dev.slots[1] = O.hotp_config(KEY20)
    with pytest.raises(ManagerError, match="not programmed for HMAC-SHA1") as e:
        m.calculate_hmac(1, b"x")
    assert e.value.sw == 0x6700


def test_no_otp_application():
    dev = FakeOtp()
    dev.AID = b"other"
    with pytest.raises(NotSupported):
        manager(dev).status()


def test_every_operation_is_one_transaction_and_reselects_management():
    dev = FakeOtp()
    m = manager(dev)
    m.program_chalresp(1, KEY20)
    m.calculate_hmac(1, b"abc")
    m.status()
    assert m.m.card.transactions == 3
    assert dev.selected == b"\xF0LIBREFIDO"


# -- values, layouts, helpers -------------------------------------------------------------

@pytest.mark.parametrize("call", [
    lambda: O.yubico_otp_config(PUB[:5], PRIV, AES),
    lambda: O.yubico_otp_config("vvcc", PRIV, AES),
    lambda: O.yubico_otp_config("vvccbbddeeff" + "x", PRIV, AES),
    lambda: O.yubico_otp_config(PUB, PRIV[:5], AES),
    lambda: O.yubico_otp_config(PUB, PRIV, AES + b"\0"),
    lambda: O.yubico_otp_config(PUB, "zz" * 6, AES),
    lambda: O.hmac_sha1_config(bytes(21)),
    lambda: O.hmac_sha1_config(bytes(64)),
    lambda: O.hmac_sha1_config(b""),
    lambda: O.hotp_config(KEY20, digits=7),
    lambda: O.hotp_config(KEY20, counter=15),
    lambda: O.hotp_config(KEY20, counter=O.HOTP_IMF_MAX + 16),
    lambda: O.hotp_config("not base32!"),
    lambda: O.static_password_config(b""),
    lambda: O.static_password_config(bytes(39)),
    lambda: O.encode_scan_codes("x" * 39),
    lambda: O.encode_scan_codes("abc", "dvorak"),
    lambda: O.access_code_bytes("0102"),
    lambda: O.access_code_bytes(bytes(7)),
    lambda: O.access_code_bytes("zz" * 6),
    lambda: O.yubico_otp_config(PUB, PRIV, AES, access_code="12"),
])
def test_invalid_values_are_refused(call):
    with pytest.raises(ManagerError) as e:
        call()
    assert e.value.zh and str(e.value)


def test_messages_hold_no_secrets():
    secret = "S3cr€t"
    with pytest.raises(ManagerError) as e:
        O.encode_scan_codes(secret)
    assert "€" not in str(e.value) and "€" not in e.value.zh and "character 5" in str(e.value)
    with pytest.raises(ManagerError) as e:
        O.encode_scan_codes("hunter2", "modhex")
    assert "hunter" not in str(e.value)
    with pytest.raises(ManagerError) as e:
        O.access_code_bytes("abcdef0123")
    assert "abcdef" not in str(e.value)


def test_access_codes():
    assert O.access_code_bytes(None) is None and O.access_code_bytes("") is None and O.access_code_bytes("  ") is None
    assert O.access_code_bytes(bytes(6)) is None
    assert O.access_code_bytes("01 02 03 04 05 FF") == CODE and O.access_code_bytes(bytearray(CODE)) == CODE


def test_keyboard_layouts_are_ykmans():
    scancodes = pytest.importorskip("ykman.scancodes")
    assert O.KEYBOARD_LAYOUTS["us"] == scancodes.KEYBOARD_LAYOUT.US.value
    assert O.KEYBOARD_LAYOUTS["modhex"] == scancodes.KEYBOARD_LAYOUT.MODHEX.value


def test_modhex():
    data = bytes(range(256))
    assert O.modhex_decode(O.modhex_encode(data)) == data
    assert O.modhex_encode(b"\xff\x00") == "vvcc"
    for bad in ("abc", "vva", "vvcc0a"):
        with pytest.raises(ValueError):
            O.modhex_decode(bad)


def test_random_values():
    pub, priv, key = O.random_yubico_otp()
    assert O.OtpManager.random_yubico_otp is O.random_yubico_otp
    assert len(pub) == 6 and O.modhex_encode(pub).startswith("vv") and len(priv) == 6 and len(key) == 16
    assert len({O.random_yubico_otp() for _ in range(20)}) == 20
    pw = O.random_static_password()
    assert len(pw) == 38 and set(pw) <= set(O.MODHEX + O.MODHEX.upper())
    pw = O.random_static_password(20, "us")
    assert len(pw) == 20 and not set(pw) & set("\t\n ")
    O.encode_scan_codes(pw, "us")


def test_upload_csv_is_ykmans():
    otp = pytest.importorskip("ykman.otp")
    ts = datetime(2026, 9, 24, 12, 30, 5)
    for code in (None, CODE):
        assert O.format_csv(123456, PUB, PRIV, AES, code, ts) == otp.format_csv(123456, PUB, PRIV, AES, code, ts)
    assert O.format_csv(None, PUB, PRIV, AES, None, ts).startswith(",vv")
