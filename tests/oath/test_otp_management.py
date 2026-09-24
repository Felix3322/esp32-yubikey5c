"""OTP slots (pico-fido/src/fido/otp.c) over the smart card interface, the
YubiKey management applet (management.c) and OATH records written by older
firmware.

The emulator has no keyboard: LF_EMU_KEYBOARD_LOG=1 makes it log what a slot
types, which these tests read back.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tests/oath python -m pytest tests/oath
"""

import os
import time

import pytest

from oathlib import *   # noqa: F401,F403
from oathlib import pcscd, device   # noqa: F401  (fixtures)

BASELINE = os.environ.get("LF_EMU_BASELINE_BIN") or os.path.expanduser("~/work/build-emu-baseline/pico_fido2")
KEY20 = bytes(range(1, 21))


def otp(card, p1, data=b"", p2=0):
    return apdu(card, 0x01, p1, p2, data)


def typed(emu, presses=1, timeout=6.0):
    """Presses the button while idle and returns what the slot typed."""
    off = log_size(emu)
    press_idle(presses)
    deadline = time.time() + timeout

    def lines():
        return [l.split("[otp] keyboard: ", 1)[1] for l in log_since(emu, off).splitlines()
                if "[otp] keyboard: " in l]
    while not lines() and time.time() < deadline:
        time.sleep(0.1)
    time.sleep(0.3)
    return lines()


def slots_ext(card):
    """{slot index: (tkt flags, cfg flags)} from the extended status (P1 0x14)."""
    data, sw = otp(card, 0x14)
    assert sw == SW_OK
    out = {}
    for tag, value in parse_tlvs(data):
        inner = dict(parse_tlvs(value))
        out[tag - 0xB0] = tuple(inner[0xA0])
    return out


def test_hotp_slot_types_rfc4226_codes(device):
    yubiotp = pytest.importorskip("yubikit.yubiotp")
    e = device(LF_EMU_UP="manual", LF_EMU_KEYBOARD_LOG="1")
    card = open_card()
    try:
        select(card, OTP_AID)
        cfg = yubiotp.HotpSlotConfiguration(RFC4226_SECRET).append_cr(False).get_config()
        assert otp(card, 0x01, cfg + bytes(6))[1] == SW_OK
    finally:
        card.close()
    time.sleep(1.2)
    assert typed(e) == [str(RFC4226_CODES[0])]
    assert typed(e) == [str(RFC4226_CODES[1])]

    # a settings update keeps the moving factor
    card = open_card()
    try:
        select(card, OTP_AID)
        upd = yubiotp.UpdateConfiguration().append_cr(True).get_config()
        assert otp(card, 0x04, upd + bytes(6))[1] == SW_OK
    finally:
        card.close()
    assert typed(e) == [str(RFC4226_CODES[2]), "<0d>"]

    # so does a swap, and a power cycle
    card = open_card()
    try:
        select(card, OTP_AID)
        assert otp(card, 0x06)[1] == SW_OK
    finally:
        card.close()
    assert typed(e, presses=2) == [str(RFC4226_CODES[3]), "<0d>"]
    assert typed(e, presses=1, timeout=2.5) == []
    e.restart()
    time.sleep(1.2)
    assert typed(e, presses=2) == [str(RFC4226_CODES[4]), "<0d>"]


def test_slot_commands_are_bounded(device):
    yubiotp = pytest.importorskip("yubikit.yubiotp")
    device()
    card = open_card()
    try:
        select(card, OTP_AID)
        cfg = yubiotp.HmacSha1SlotConfiguration(KEY20).get_config()
        for p2 in (4, 0x10, 0xFF):
            assert otp(card, 0x01, cfg + bytes(6), p2=p2)[1] == SW_P1P2
            assert otp(card, 0x04, cfg + bytes(6), p2=p2)[1] == SW_P1P2
            assert otp(card, 0x30, bytes(64), p2=p2)[1] == SW_P1P2
        assert otp(card, 0x03, cfg + bytes(6), p2=1)[1] == SW_P1P2
        # the current access code must be sent, never read from stale buffer bytes
        assert otp(card, 0x01, cfg)[1] == SW_WRONG_DATA
        protected = yubiotp.HmacSha1SlotConfiguration(KEY20).get_config(b"secret")
        assert otp(card, 0x01, protected + bytes(6), p2=3)[1] == SW_OK      # slot 4
        assert otp(card, 0x01, protected + bytes(6), p2=3)[1] == SW_SECURITY
        assert otp(card, 0x01, protected, p2=3)[1] == SW_WRONG_DATA
        assert set(slots_ext(card)) == {3}
        # swap: offsets from slot 1 and 2, inside the four slots, distinct
        assert otp(card, 0x06, b"\x00")[1] == SW_WRONG_DATA
        assert otp(card, 0x06, bytes(3))[1] == SW_WRONG_DATA
        assert otp(card, 0x06, b"\x00\x03")[1] == SW_WRONG_DATA
        assert otp(card, 0x06, b"\x01\x00")[1] == SW_WRONG_DATA
        # a protected slot only moves with its access code
        assert otp(card, 0x06, b"\x03\x00")[1] == SW_SECURITY
        assert otp(card, 0x06, b"\x03\x00" + b"wrong!")[1] == SW_SECURITY
        assert set(slots_ext(card)) == {3}
        assert otp(card, 0x06, b"\x03\x00" + b"secret")[1] == SW_OK         # slot 4 <-> slot 2
        assert set(slots_ext(card)) == {1}
        # Le without data: the default swap (slots 1 and 2), not offsets from
        # old buffer bytes; refused without the code
        _, sw = card.raw(bytes([0x00, 0x01, 0x06, 0x00, 0x02]))
        assert sw == SW_SECURITY
        # the yubikit framing: the 6-byte access code field
        assert otp(card, 0x06, b"secret")[1] == SW_OK
        assert set(slots_ext(card)) == {0}
    finally:
        card.close()


def test_yubikit_swap_over_the_smart_card_interface(device):
    yubiotp = pytest.importorskip("yubikit.yubiotp")
    from harness.card import YkConnection
    device()
    card = open_card()
    try:
        s = yubiotp.YubiOtpSession(YkConnection(card))
        s.put_configuration(yubiotp.SLOT.ONE, yubiotp.HmacSha1SlotConfiguration(KEY20))
        state = s.get_config_state()
        assert state.is_configured(yubiotp.SLOT.ONE) and not state.is_configured(yubiotp.SLOT.TWO)
        s.swap_slots()                          # checks the programming sequence moved on
        state = s.get_config_state()
        assert state.is_configured(yubiotp.SLOT.TWO) and not state.is_configured(yubiotp.SLOT.ONE)
        resp = s.calculate_hmac_sha1(yubiotp.SLOT.TWO, b"swap")
        assert resp == hmac_sha1(KEY20, b"swap")
        # protected: yubikit's swap (no code) is refused, nothing moves
        s.put_configuration(yubiotp.SLOT.ONE, yubiotp.HmacSha1SlotConfiguration(KEY20), acc_code=b"secret")
        with pytest.raises(Exception):
            s.swap_slots()
        state = s.get_config_state()
        assert state.is_configured(yubiotp.SLOT.ONE) and state.is_configured(yubiotp.SLOT.TWO)
    finally:
        card.close()


def test_challenge_response(device):
    yubiotp = pytest.importorskip("yubikit.yubiotp")
    device(LF_EMU_UP="manual", LF_EMU_UP_TIMEOUT_MS="1000")
    card = open_card()
    try:
        select(card, OTP_AID)
        cfg = yubiotp.HmacSha1SlotConfiguration(KEY20).require_touch(True).get_config()
        assert otp(card, 0x03, cfg + bytes(6))[1] == SW_OK                  # slot 2
        chal = os.urandom(31) + b"\x07"
        padded = chal.ljust(64, b"\0")
        assert otp(card, 0x38, padded)[1] == SW_CONDITIONS                  # nobody touches
        resp, sw = pressing(lambda: otp(card, 0x38, padded))
        assert sw == SW_OK and resp == hmac_sha1(KEY20, chal)
        # over CCID Lc gives the challenge length
        resp, sw = pressing(lambda: otp(card, 0x38, chal))
        assert sw == SW_OK and resp == hmac_sha1(KEY20, chal)
        # the Yubico OTP challenge command does not use an HMAC slot
        assert otp(card, 0x28, bytes(6))[1] == SW_WRONG_DATA
        assert otp(card, 0x38, b"")[1] != SW_OK
    finally:
        card.close()


def test_management_reset_reports_a_refusal(device):
    device(LF_EMU_UP="manual", LF_EMU_UP_TIMEOUT_MS="800")
    card = open_card()
    try:
        select(card, MGMT_AID)
        assert apdu(card, 0x1E)[1] == SW_CONDITIONS
        assert pressing(lambda: apdu(card, 0x1E))[1] == SW_OK
    finally:
        card.close()


def test_write_config_is_validated_and_merged(device):
    device()
    card = open_card()
    try:
        select(card, MGMT_AID)

        def write(tlvs):
            return apdu(card, 0x1C, data=bytes([len(tlvs)]) + tlvs)[1]

        def read():
            data, sw = apdu(card, 0x1D)
            assert sw == SW_OK and data[0] == len(data) - 1
            return data, dict(parse_tlvs(data[1:]))
        assert write(b"\x55\x01\x00") == SW_WRONG_DATA                      # unknown setting
        assert write(b"\x03\x02\x02") == SW_WRONG_DATA                      # runs past the data
        assert write(b"\x08\x01\x80" * 60 + b"\x55" * 20) == SW_WRONG_DATA
        assert write(b"\x03\x02\x02\x3b\x03\x02\x02\x3b") == SW_WRONG_DATA  # twice
        assert write(b"\x0a\x10" + b"\x01" * 16) == SW_CONDITIONS          # lock codes are not supported
        assert write(b"\x0a\x10" + bytes(16)) == SW_OK
        assert write(b"\x03\x02\x02\x3b\x08\x01\x80") == SW_OK
        _, conf = read()
        assert conf[0x03] == b"\x02\x3b" and conf[0x08] == b"\x80"
        assert write(b"\x07\x01\x0f\x0c\x00") == SW_OK                      # one setting (+ reboot)
        raw, conf = read()
        assert conf[0x03] == b"\x02\x3b" and conf[0x08] == b"\x80" and conf[0x07] == b"\x0f"
        # the OTP applet reports the same device information
        select(card, OTP_AID)
        data, sw = otp(card, 0x13)
        assert sw == SW_OK and data == raw
    finally:
        card.close()


def test_write_config_and_the_board_settings_allowance(device):
    """WRITE CONFIG only goes through the guarded board settings write for a
    real change of them: it never uses the free changes when the board
    settings stay as they are, and still works once they are used up. (The
    refusal itself needs recorded USB interfaces, which the emulator's board
    settings never hold: its rescue PHY write is compiled out.)"""
    from fido2 import cbor
    from librefido.mgmt import INS_INFO, Management
    device(LF_EMU_UP="manual", LF_EMU_UP_TIMEOUT_MS="800")
    card = open_card()
    m = Management.open(timeout=15)
    try:
        free = lambda: cbor.decode(m._cmd(INS_INFO))[18]

        def write_config(tlvs):
            select(card, MGMT_AID)
            return apdu(card, 0x1C, data=bytes([len(tlvs)]) + tlvs)[1]
        assert free() == 16
        for i in range(3):
            assert write_config(bytes([0x07, 0x01, 10 + i])) == SW_OK
        assert free() == 16
        for i in range(16):
            m.set_button_slots(3 + i % 2)
        assert free() == 0
        assert write_config(bytes([0x07, 0x01, 0x2A])) == SW_OK
        data, sw = apdu(card, 0x1D)
        assert sw == SW_OK and dict(parse_tlvs(data[1:]))[0x07] == b"\x2a"
    finally:
        m.close()
        card.close()


def test_oath_records_of_older_firmware(device):
    """Records the previous firmware stored verbatim (bare YKOATH property,
    Nitrokey field order) keep working, touch included."""
    if not os.path.exists(BASELINE):
        pytest.skip("baseline emulator not built")
    from harness.emulator import HID_PORT
    with open(BASELINE, "rb") as f:
        if HID_PORT != 35962 and b"LF_EMU_VPCD_PORT" not in f.read():
            pytest.skip("the baseline emulator has fixed ports: run this test on the default ports")
    legacy = device(binary=BASELINE, chip_id=b"\0" * 8)
    chal = (1234).to_bytes(8, "big")
    card = open_card()
    try:
        oath_select(card)
        assert put(card, b"plain", RFC4226_SECRET) == SW_OK
        assert put(card, b"touchy", RFC4226_SECRET, touch=True) == SW_OK
        assert put(card, b"hotp-touch", RFC4226_SECRET, kind=HOTP, touch=True) == SW_OK
        # the old firmware padded a short IMF in place over the property that
        # followed it: this record has no touch flag left
        assert put(card, b"hotp-imf", RFC4226_SECRET, kind=HOTP, imf=5, touch=True) == SW_OK
        nk = (tlv(TAG_NAME, b"nk") + tlv(TAG_KEY, bytes([HOTP | SHA1, 6]) + RFC4226_SECRET) +
              bytes([TAG_PROPERTY, 0x02]) + tlv(TAG_IMF, (7).to_bytes(4, "big")) +
              tlv(TAG_PWS_LOGIN, b"alice") + tlv(TAG_PWS_PASSWORD, b"hunter2"))
        assert apdu(card, INS_PUT, data=nk)[1] == SW_OK
        # clients that sent the property with a length (78 01 02)
        key = bytes([TOTP | SHA1, 6]) + RFC4226_SECRET
        lt = tlv(TAG_NAME, b"len-touch") + tlv(TAG_KEY, key) + b"\x78\x01\x02"
        assert apdu(card, INS_PUT, data=lt)[1] == SW_OK
        key = bytes([HOTP | SHA1, 6]) + RFC4226_SECRET
        lh = tlv(TAG_NAME, b"len-hotp") + tlv(TAG_KEY, key) + b"\x78\x01\x02" + tlv(TAG_IMF, (3).to_bytes(4, "big"))
        assert apdu(card, INS_PUT, data=lh)[1] == SW_OK
        # one-byte lengths of 128..255 (tlv8, the Nitrokey client)
        long_pw = bytes(range(0x30, 0x30 + 64)) * 2
        t8 = tlv(TAG_NAME, b"tlv8") + tlv(TAG_KEY, bytes([TOTP | SHA1, 6]) + RFC4226_SECRET) + \
            tlv(TAG_PWS_LOGIN, b"bob") + bytes([TAG_PWS_PASSWORD, len(long_pw)]) + long_pw
        assert apdu(card, INS_PUT, data=t8)[1] == SW_OK
        before, sw = calculate(card, b"plain", chal)
        assert sw == SW_OK
        # an OTP challenge-response slot in the old (plaintext) format
        yubiotp = pytest.importorskip("yubikit.yubiotp")
        select(card, OTP_AID)
        cfg = yubiotp.HmacSha1SlotConfiguration(KEY20).get_config()
        assert otp(card, 0x01, cfg + bytes(6))[1] == SW_OK
    finally:
        card.close()
    legacy.stop()

    e = device(LF_EMU_UP="manual", LF_EMU_UP_TIMEOUT_MS="1000")
    card = open_card()
    try:
        oath_select(card)
        entries = parse_tlvs(apdu(card, INS_LIST, data=b"\x01")[0])
        props = {v[1:-1]: v[-1] for t, v in entries}
        assert props == {b"plain": 0, b"touchy": 1, b"hotp-touch": 1, b"hotp-imf": 0, b"nk": 5,
                         b"len-touch": 1, b"len-hotp": 1, b"tlv8": 4}
        assert calculate(card, b"plain", chal) == (before, SW_OK)
        assert calculate(card, b"touchy", chal)[1] == SW_CONDITIONS
        assert pressing(lambda: calculate(card, b"touchy", chal)) == (totp(RFC4226_SECRET, chal), SW_OK)
        assert calculate(card, b"hotp-touch")[1] == SW_CONDITIONS
        assert pressing(lambda: calculate(card, b"hotp-touch")) == (RFC4226_CODES[0], SW_OK)
        assert pressing(lambda: calculate(card, b"hotp-touch")) == (RFC4226_CODES[1], SW_OK)
        assert calculate(card, b"hotp-imf") == (RFC4226_CODES[5], SW_OK)
        assert calculate(card, b"hotp-imf") == (RFC4226_CODES[6], SW_OK)
        assert pressing(lambda: calculate(card, b"nk")) == (RFC4226_CODES[7], SW_OK)
        get_nk = (INS_GET_CREDENTIAL, 0, 0, tlv(TAG_NAME, b"nk"))
        assert apdu(card, *get_nk)[1] == SW_CONDITIONS         # a touch entry
        fields = dict(parse_tlvs(pressing(lambda: apdu(card, *get_nk))[0]))
        assert fields[TAG_PWS_LOGIN] == b"alice" and fields[TAG_PWS_PASSWORD] == b"hunter2"
        assert fields[TAG_PROPERTY] == b"\x02"
        assert pressing(lambda: calculate(card, b"nk")) == (RFC4226_CODES[8], SW_OK)
        # the length-form property: touch kept, the HOTP counter continues
        assert calculate(card, b"len-touch", chal)[1] == SW_CONDITIONS
        assert pressing(lambda: calculate(card, b"len-touch", chal)) == (totp(RFC4226_SECRET, chal), SW_OK)
        assert calculate(card, b"len-hotp")[1] == SW_CONDITIONS
        assert pressing(lambda: calculate(card, b"len-hotp")) == (RFC4226_CODES[3], SW_OK)
        assert pressing(lambda: calculate(card, b"len-hotp")) == (RFC4226_CODES[4], SW_OK)
        # the 128-byte field is read and returned with a one-byte length
        data, sw = apdu(card, INS_GET_CREDENTIAL, data=tlv(TAG_NAME, b"tlv8"))
        assert sw == SW_OK and bytes([TAG_PWS_PASSWORD, 0x80]) + long_pw in data
    finally:
        card.close()

    # the records were sealed on the way (the running firmware is confirmed)
    # and still work after a power cycle
    e.restart()
    card = open_card()
    try:
        oath_select(card)
        assert calculate(card, b"plain", chal) == (before, SW_OK)
        assert pressing(lambda: calculate(card, b"len-hotp")) == (RFC4226_CODES[5], SW_OK)
        assert pressing(lambda: calculate(card, b"hotp-touch")) == (RFC4226_CODES[2], SW_OK)
        data, sw = apdu(card, INS_GET_CREDENTIAL, data=tlv(TAG_NAME, b"tlv8"))
        assert sw == SW_OK and long_pw in data
        select(card, OTP_AID)
        resp, sw = otp(card, 0x30, b"legacy")
        assert sw == SW_OK and resp == hmac_sha1(KEY20, b"legacy")
    finally:
        card.close()
