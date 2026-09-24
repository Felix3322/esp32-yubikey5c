"""OATH sessions per transport (smart card vs. the HID vendor command
CTAPHID_OTP), touch over HID, and OATH / OTP records sealed at rest.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tests/oath python -m pytest tests/oath
"""

import os
import threading
import time

import pytest

from harness.ctaphid import CID_BROADCAST, CMD_INIT, CMD_MSG, RawCtapHid
from oathlib import *   # noqa: F401,F403
from oathlib import pcscd, device   # noqa: F401  (fixtures)

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
SELECT_OATH = bytes([0x00, 0xA4, 0x04, 0x00, len(OATH_AID)]) + OATH_AID


def test_hid_otp_as_the_first_command_after_power_up(device):
    """The transport selects OATH before the command: nothing may be written
    through a response pointer that is not set yet (it crashed)."""
    device()
    raw = RawCtapHid()
    try:
        cid = raw.init()
        assert hid_apdu(raw, cid, INS_LIST) == (b"", SW_OK)
        data, sw = hid_otp(raw, cid, SELECT_OATH)
        tags = dict(parse_tlvs(data))
        assert sw == SW_OK and len(tags[0x79]) == 3 and len(tags[TAG_NAME]) == 8
    finally:
        raw.close()


def test_hid_authorization_ends_when_idle(device):
    device(LF_EMU_OATH_IDLE_MS="1500")
    raw = RawCtapHid()
    try:
        cid = raw.init()
        entry = tlv(TAG_NAME, b"mail") + tlv(TAG_KEY, b"\x21\x06" + RFC4226_SECRET) + \
            tlv(TAG_PWS_LOGIN, b"alice") + tlv(TAG_PWS_PASSWORD, b"hunter2")
        assert hid_apdu(raw, cid, INS_PUT, data=entry)[1] == SW_OK
        assert hid_apdu(raw, cid, INS_SET_PIN, data=tlv(TAG_PASSWORD, b"1234"))[1] == SW_OK
        get = (INS_GET_CREDENTIAL, 0, 0, tlv(TAG_NAME, b"mail"))
        assert hid_apdu(raw, cid, *get)[1] == SW_SECURITY
        assert hid_apdu(raw, cid, INS_VERIFY_PIN, data=tlv(TAG_PASSWORD, b"1234"))[1] == SW_OK
        # back to back: fine
        for _ in range(3):
            data, sw = hid_apdu(raw, cid, *get)
            assert sw == SW_OK and dict(parse_tlvs(data))[TAG_PWS_PASSWORD] == b"hunter2"
            time.sleep(0.5)
        # the client went away: nobody inherits its authorization
        time.sleep(2.0)
        assert hid_apdu(raw, cid, *get)[1] == SW_SECURITY
        assert hid_apdu(raw, cid, INS_LIST)[1] == SW_SECURITY
    finally:
        raw.close()


def test_smart_card_and_hid_sessions_are_separate(device):
    device()
    card = open_card()
    raw = RawCtapHid()
    try:
        oath_select(card)
        assert put(card, b"alice", RFC4226_SECRET) == SW_OK
        assert set_code(card, KEY) == SW_OK
        chal = oath_select(card)
        assert validate(card, KEY, chal) == SW_OK
        calc_all = (INS_CALC_ALL, 0, 1, tlv(TAG_CHALLENGE, bytes(8)))
        assert apdu(card, *calc_all)[1] == SW_OK

        # HID: first selection, a wrong VALIDATE, locked commands, U2F traffic
        cid = raw.init()
        assert hid_apdu(raw, cid, INS_LIST)[1] == SW_SECURITY
        data, sw = hid_otp(raw, cid, SELECT_OATH)
        hid_chal = dict(parse_tlvs(data))[TAG_CHALLENGE]
        assert hid_chal != chal
        bad = tlv(TAG_RESPONSE, bytes(20)) + tlv(TAG_CHALLENGE, bytes(8))
        assert hid_apdu(raw, cid, INS_VALIDATE, data=bad)[1] == SW_DATA_INVALID
        raw.call(cid, CMD_MSG, bytes([0x00, 0x03, 0x00, 0x00]))      # U2F VERSION
        # the smart card session is untouched ...
        assert apdu(card, *calc_all)[1] == SW_OK
        # ... and gives HID nothing
        assert hid_apdu(raw, cid, *calc_all)[1] == SW_SECURITY
        # HID validates on its own
        data, sw = hid_otp(raw, cid, SELECT_OATH)
        hid_chal = dict(parse_tlvs(data))[TAG_CHALLENGE]
        mine = os.urandom(8)
        resp = tlv(TAG_RESPONSE, hmac_sha1(KEY, hid_chal)) + tlv(TAG_CHALLENGE, mine)
        data, sw = hid_apdu(raw, cid, INS_VALIDATE, data=resp)
        assert sw == SW_OK and dict(parse_tlvs(data))[TAG_RESPONSE] == hmac_sha1(KEY, mine)
        assert hid_apdu(raw, cid, *calc_all)[1] == SW_OK
        # a smart card SELECT ends the smart card session only
        oath_select(card)
        assert apdu(card, *calc_all)[1] == SW_SECURITY
        assert hid_apdu(raw, cid, *calc_all)[1] == SW_OK
    finally:
        raw.close()
        card.close()


def test_hid_touch_uses_the_command_it_was_asked_for(device):
    """Frames arriving while the command waits for the touch (a browser's
    INIT, another client) must not change what is computed."""
    device(LF_EMU_UP="manual", LF_EMU_UP_TIMEOUT_MS="3000")
    raw = RawCtapHid(timeout=15)
    try:
        cid = raw.init()
        assert hid_apdu(raw, cid, INS_PUT, data=tlv(TAG_NAME, b"aaaa") +
                        tlv(TAG_KEY, b"\x21\x06" + RFC4226_SECRET) + bytes([TAG_PROPERTY, 0x02]))[1] == SW_OK
        other = os.urandom(20)
        assert hid_apdu(raw, cid, INS_PUT, data=tlv(TAG_NAME, b"bbbb") +
                        tlv(TAG_KEY, b"\x11\x06" + other))[1] == SW_OK
        chal = (1234).to_bytes(8, "big")
        cmd = bytes([0x00, INS_CALCULATE, 0x00, 0x01])
        body = tlv(TAG_NAME, b"aaaa") + tlv(TAG_CHALLENGE, chal)
        from harness.ctaphid import CMD_OTP
        raw.send(cid, CMD_OTP, cmd + bytes([len(body)]) + body)
        time.sleep(0.4)
        # a frame that overlays the waiting command with another name and counter
        evil = cmd + bytes([len(body)]) + tlv(TAG_NAME, b"bbbb") + tlv(TAG_CHALLENGE, bytes(8))
        raw.send_frame(cid, bytes([CMD_OTP, 0, len(evil)]) + evil)
        raw.send(CID_BROADCAST, CMD_INIT, os.urandom(8))
        time.sleep(0.3)
        press_idle(1)
        answer = None
        deadline = time.time() + 10
        while answer is None and time.time() < deadline:
            rcid, rcmd, data, _ = raw.recv()
            if rcid == cid and rcmd == CMD_OTP and len(data) > 2 and data[:2] == b"\x90\x00":
                answer = data[2:]
        assert answer is not None
        value = dict(parse_tlvs(answer))[TAG_T_RESPONSE]
        assert truncated(value) == totp(RFC4226_SECRET, chal)
    finally:
        raw.close()


def stored_records(emu, name):
    """Plaintext records in the flash file that start with this name, as
    lists of (tag, value) the way the previous firmware walks them (0x78 is
    tag, length, value there)."""
    with open(emu.flash_path, "rb") as f:
        flash = f.read()
    head = tlv(TAG_NAME, name)
    out, i = [], flash.find(head)
    while i >= 0:
        elems, p = [], i
        for _ in range(8):
            if p + 2 > len(flash) or flash[p] in (0x00, 0xFF):
                break
            t, n = flash[p], flash[p + 1]
            elems.append((t, flash[p + 2:p + 2 + n]))
            p += 2 + n
        out.append(elems)
        i = flash.find(head, i + 1)
    return out


def test_unconfirmed_update_keeps_the_previous_format(device):
    """While a firmware update is not confirmed, the previous firmware may
    come back: records it can read stay in its format (plaintext, the property
    as the client stored it, never the new private tag), also when a counter
    moves or a credential is renamed. Once confirmed, they are sealed."""
    from librefido import firmware
    from librefido.mgmt import Management
    e = device()
    with open(e.binary, "rb") as f:
        img = f.read()
    v = firmware.parse(img)["version_tuple"]
    newer = firmware.set_version(img, (v[0], v[1], v[2] + 1))
    m = Management.open(timeout=15)
    try:
        m.update_firmware(newer, confirm=False)
        assert m.info()["firmware_slot"]["unconfirmed"]
    finally:
        m.close()
    card = open_card()
    try:
        oath_select(card)
        # the property sent in the length form, which the previous firmware reads
        hotp = tlv(TAG_NAME, b"touch-hotp") + tlv(TAG_KEY, b"\x11\x06" + RFC4226_SECRET) + \
            b"\x78\x01\x02" + tlv(TAG_IMF, (5).to_bytes(4, "big"))
        assert apdu(card, INS_PUT, data=hotp)[1] == SW_OK
        assert put(card, b"old-name", RFC4226_SECRET, touch=True) == SW_OK
        assert calculate(card, b"touch-hotp") == (RFC4226_CODES[5], SW_OK)
        assert calculate(card, b"touch-hotp") == (RFC4226_CODES[6], SW_OK)
        assert apdu(card, INS_RENAME, data=tlv(TAG_NAME, b"old-name") + tlv(TAG_NAME, b"new-name"))[1] == SW_OK
    finally:
        card.close()
    e.stop()
    recs = [r for r in stored_records(e, b"touch-hotp") if (TAG_IMF, (7).to_bytes(8, "big")) in r]
    assert recs, "the rewritten HOTP record is in plaintext"
    for r in recs:
        assert (TAG_PROPERTY, b"\x02") in r and 0x8E not in [t for t, _ in r]
    recs = stored_records(e, b"new-name")
    assert recs, "the renamed record is in plaintext"
    for r in recs:
        # the bare property as the client (yubikit) sent it, right after the key
        assert [t for t, _ in r[:3]] == [TAG_NAME, TAG_KEY, TAG_PROPERTY]
        assert 0x8E not in [t for t, _ in r]
    # the reset goes back to the previous image (here: the same code); the
    # records work there, touch included
    e.start()
    card = open_card()
    try:
        oath_select(card)
        props = {v[1:-1]: v[-1] for t, v in parse_tlvs(apdu(card, INS_LIST, data=b"\x01")[0])}
        assert props == {b"touch-hotp": 1, b"new-name": 1}
        assert calculate(card, b"touch-hotp") == (RFC4226_CODES[7], SW_OK)
    finally:
        card.close()
    # confirmed firmware: the records are sealed at the first OATH command
    m = Management.open(timeout=15)
    try:
        m.update_firmware(newer)
        assert not m.info()["firmware_slot"]["unconfirmed"]
    finally:
        m.close()
    card = open_card()
    try:
        oath_select(card)
        assert calculate(card, b"touch-hotp") == (RFC4226_CODES[8], SW_OK)
        props = {v[1:-1]: v[-1] for t, v in parse_tlvs(apdu(card, INS_LIST, data=b"\x01")[0])}
        assert props == {b"touch-hotp": 1, b"new-name": 1}
    finally:
        card.close()
    e.restart()
    card = open_card()
    try:
        oath_select(card)
        assert calculate(card, b"touch-hotp") == (RFC4226_CODES[9], SW_OK)
    finally:
        card.close()


def test_locked_key_store_uses_no_record(device):
    """A plain root key on a chip that now has the HMAC key and Secure Boot is
    held (key store locked) until it is bound. Then OATH and OTP use no
    record, not even plaintext ones of earlier firmware (they cannot be
    sealed then): SELECT answers, everything else is 6985, and the button
    types nothing. Bound, everything works as before."""
    yubiotp = pytest.importorskip("yubikit.yubiotp")
    from librefido import firmware
    from librefido.mgmt import Management
    e = device()
    # records in plaintext: written while a firmware update is unconfirmed
    with open(e.binary, "rb") as f:
        img = f.read()
    v = firmware.parse(img)["version_tuple"]
    m = Management.open(timeout=15)
    try:
        m.update_firmware(firmware.set_version(img, (v[0], v[1], v[2] + 1)), confirm=False)
    finally:
        m.close()
    secret = os.urandom(20)
    card = open_card()
    try:
        oath_select(card)
        assert put(card, b"plain", secret) == SW_OK
        select(card, OTP_AID)
        cfg = yubiotp.HotpSlotConfiguration(RFC4226_SECRET).append_cr(False).get_config()
        assert apdu(card, 0x01, 0x01, 0x00, cfg + bytes(6))[1] == SW_OK
        cfg = yubiotp.HmacSha1SlotConfiguration(os.urandom(20)).get_config()
        assert apdu(card, 0x01, 0x03, 0x00, cfg + bytes(6))[1] == SW_OK
    finally:
        card.close()
    e.stop()
    assert flash_has(e, secret)                         # plaintext
    with open(e.efuse_path, "wb") as f:
        f.write(os.urandom(32))                         # the chip has an HMAC key
    e.extra_env.update(LF_EMU_CHIP_SECURE="1", LF_EMU_UP="manual", LF_EMU_UP_TIMEOUT_MS="1500",
                       LF_EMU_KEYBOARD_LOG="1")
    e.start()
    m = Management.open(timeout=15)
    try:
        assert m.info()["security"]["root_key"] == "flash (not bound to the chip)"
    finally:
        m.close()
    card = open_card()
    raw = RawCtapHid()
    try:
        c = bytes(8)
        oath_select(card)
        for ins, p1, p2, data in ((INS_LIST, 0, 0, b""), (INS_CALCULATE, 0, 1, tlv(TAG_NAME, b"plain") + tlv(TAG_CHALLENGE, c)),
                                  (INS_CALC_ALL, 0, 1, tlv(TAG_CHALLENGE, c)),
                                  (INS_PUT, 0, 0, tlv(TAG_NAME, b"new") + tlv(TAG_KEY, b"\x21\x06" + secret)),
                                  (INS_DELETE, 0, 0, tlv(TAG_NAME, b"plain")),
                                  (INS_GET_CREDENTIAL, 0, 0, tlv(TAG_NAME, b"plain"))):
            assert apdu(card, ins, p1, p2, data)[1] == SW_CONDITIONS, "INS %02X" % ins
        cid = raw.init()
        assert hid_apdu(raw, cid, INS_LIST)[1] == SW_CONDITIONS
        assert hid_otp(raw, cid, SELECT_OATH)[1] == SW_OK
        status = select(card, OTP_AID)
        assert status[4] & 0x03 == 0x03                 # the slots are listed as programmed
        assert apdu(card, 0x01, 0x38, 0x00, b"chal")[1] == SW_CONDITIONS
        assert apdu(card, 0x01, 0x01, 0x00, bytes(58))[1] == SW_CONDITIONS
        assert apdu(card, 0x01, 0x06, 0x00)[1] == SW_CONDITIONS
    finally:
        raw.close()
        card.close()
    off = log_size(e)
    press_idle(1)
    time.sleep(1.5)
    assert "[otp] keyboard:" not in log_since(e, off)   # the HOTP slot types nothing

    def bind(m):
        return m._cmd(0x50, 0xA5, 0x01, what="bind root key")
    m = Management.open(timeout=15)
    try:
        pressing(lambda: bind(m))
    finally:
        m.close()
    e.restart()
    card = open_card()
    try:
        oath_select(card)
        assert calculate(card, b"plain", c) == (totp(secret, c), SW_OK)
    finally:
        card.close()
    time.sleep(1.2)
    off = log_size(e)
    press_idle(1)
    deadline = time.time() + 5
    while "[otp] keyboard:" not in log_since(e, off) and time.time() < deadline:
        time.sleep(0.1)
    assert "[otp] keyboard: %d" % RFC4226_CODES[0] in log_since(e, off)   # the counter did not move


def test_records_are_sealed_at_rest(device):
    yubiotp = pytest.importorskip("yubikit.yubiotp")
    secret = os.urandom(20)
    password = os.urandom(12).hex().encode()
    code_key = os.urandom(16)
    hmac_key = os.urandom(20)
    static_pw = os.urandom(16)
    e = device()
    card = open_card()
    try:
        oath_select(card)
        assert put(card, b"sealed-name", secret,
                   extra=tlv(TAG_PWS_LOGIN, b"alice") + tlv(TAG_PWS_PASSWORD, password)) == SW_OK
        assert put(card, b"hotp", secret, kind=HOTP, imf=7) == SW_OK
        assert set_code(card, code_key) == SW_OK
        assert apdu(card, INS_SET_PIN, data=tlv(TAG_PASSWORD, b"4321"))[1] == SW_OK
        select(card, OTP_AID)
        cfg = yubiotp.HmacSha1SlotConfiguration(hmac_key).get_config()
        assert apdu(card, 0x01, 0x01, 0x00, cfg + bytes(6))[1] == SW_OK
        cfg = yubiotp.StaticPasswordSlotConfiguration(static_pw + bytes(22)).get_config()
        assert apdu(card, 0x01, 0x03, 0x00, cfg + bytes(6))[1] == SW_OK
    finally:
        card.close()
    e.stop()
    for needle in (secret, password, code_key, hmac_key[:16], static_pw, b"sealed-name"):
        assert not flash_has(e, needle), needle
    e.start()
    card = open_card()
    try:
        chal = oath_select(card)
        assert validate(card, code_key, chal) == SW_OK
        assert apdu(card, INS_VERIFY_PIN, data=tlv(TAG_PASSWORD, b"4321"))[1] == SW_OK
        c = bytes(8)
        assert calculate(card, b"sealed-name", c) == (totp(secret, c), SW_OK)
        fields = dict(parse_tlvs(apdu(card, INS_GET_CREDENTIAL, data=tlv(TAG_NAME, b"sealed-name"))[0]))
        assert fields[TAG_PWS_PASSWORD] == password
        select(card, OTP_AID)
        resp, sw = apdu(card, 0x01, 0x30, 0x00, b"abc")
        assert sw == SW_OK and resp == hmac_sha1(hmac_key, b"abc")
    finally:
        card.close()
