"""OATH applet (YKOATH, pico-fido/src/fido/oath.c): access code, touch,
HOTP verification, password safe, OTP PIN, bounds and paging.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tests/oath python -m pytest tests/oath
"""

import os
import time

import pytest

from harness.card import YkConnection
from oathlib import *   # noqa: F401,F403
from oathlib import pcscd, device   # noqa: F401  (fixtures)

KEY = bytes.fromhex("0123456789abcdef0123456789abcdef")


def locked_commands():
    return [
        (INS_LIST, 0, 0, b""),
        (INS_CALCULATE, 0, 1, tlv(TAG_NAME, b"alice") + tlv(TAG_CHALLENGE, bytes(8))),
        (INS_CALC_ALL, 0, 1, tlv(TAG_CHALLENGE, bytes(8))),
        (INS_PUT, 0, 0, tlv(TAG_NAME, b"eve") + tlv(TAG_KEY, b"\x21\x06" + bytes(16))),
        (INS_DELETE, 0, 0, tlv(TAG_NAME, b"alice")),
        (INS_RENAME, 0, 0, tlv(TAG_NAME, b"alice") + tlv(TAG_NAME, b"eve")),
        (INS_SET_CODE, 0, 0, b""),
        (INS_GET_CREDENTIAL, 0, 0, tlv(TAG_NAME, b"alice")),
        (INS_VERIFY_CODE, 0, 0, tlv(TAG_NAME, b"alice") + tlv(TAG_RESPONSE, bytes(4))),
        (INS_SET_PIN, 0, 0, tlv(TAG_PASSWORD, b"1234")),
    ]


def test_access_code_is_enforced_after_a_power_cycle(device):
    e = device()
    card = open_card()
    try:
        oath_select(card)
        oath_reset(card)
        assert put(card, b"alice", RFC4226_SECRET,
                   extra=tlv(TAG_PWS_LOGIN, b"alice") + tlv(TAG_PWS_PASSWORD, b"hunter2")) == SW_OK
        assert set_code(card, KEY) == SW_OK
    finally:
        card.close()

    e.restart()
    card = open_card()
    try:
        chal = oath_select(card)
        assert chal is not None and len(chal) == 8
        for ins, p1, p2, data in locked_commands():
            _, sw = apdu(card, ins, p1, p2, data)
            assert sw == SW_SECURITY, "INS %02X: %04X" % (ins, sw)
        assert validate(card, KEY, chal) == SW_OK
        names = [v[1:] for t, v in parse_tlvs(apdu(card, INS_LIST)[0])]
        assert names == [b"alice"]
        # a new SELECT starts a new session
        oath_select(card)
        assert apdu(card, INS_LIST)[1] == SW_SECURITY
        # and so does a card reset
        chal = oath_select(card)
        assert validate(card, KEY, chal) == SW_OK
        card.reset()
        card.select(OATH_AID)
        assert apdu(card, INS_LIST)[1] == SW_SECURITY
    finally:
        card.close()


def test_validate_needs_the_exact_response(device):
    device()
    card = open_card()
    try:
        oath_select(card)
        oath_reset(card)
        assert put(card, b"alice", RFC4226_SECRET) == SW_OK
        # SET CODE checks the host's proof the same way
        assert set_code(card, KEY, resp=b"") == SW_DATA_INVALID
        assert set_code(card, KEY, resp=hmac_sha1(KEY, b"x")[:1]) == SW_DATA_INVALID
        assert oath_select(card) is None                    # no code was set
        assert set_code(card, KEY) == SW_OK

        chal = oath_select(card)
        good = hmac_sha1(KEY, chal)
        for bad in (b"", good[:1], good[:19], good + b"\0", bytes(20)):
            assert validate(card, KEY, chal, resp=bad) == SW_DATA_INVALID, bad.hex()
            assert apdu(card, INS_LIST)[1] == SW_SECURITY
        assert validate(card, KEY, chal) == SW_OK
        assert apdu(card, INS_LIST)[1] == SW_OK
        # the challenge answers once
        assert validate(card, KEY, chal) == SW_DATA_INVALID
        assert apdu(card, INS_LIST)[1] == SW_SECURITY
    finally:
        card.close()


def test_yubikit_session_with_access_code(device):
    oath = pytest.importorskip("yubikit.oath")
    device()
    card = open_card()
    try:
        s = oath.OathSession(YkConnection(card))
        s.reset()
        s.put_credential(oath.CredentialData(name="alice", oath_type=oath.OATH_TYPE.TOTP,
                                             hash_algorithm=oath.HASH_ALGORITHM.SHA1,
                                             secret=RFC4226_SECRET, digits=8))
        key = s.derive_key("correct horse")
        s.set_key(key)
        # the session that set the password stays unlocked (as on a YubiKey)
        assert [c.name for c in s.list_credentials()] == ["alice"]
        s = oath.OathSession(YkConnection(card))
        assert s.locked
        with pytest.raises(Exception):
            s.list_credentials()
        s = oath.OathSession(YkConnection(card))
        s.validate(key)
        creds = s.list_credentials()
        assert [c.name for c in creds] == ["alice"]
        assert s.calculate_code(creds[0], timestamp=59).value == "94287082"
        # a password change keeps the session too; the old password is gone
        new_key = s.derive_key("battery staple")
        s.set_key(new_key)
        assert len(s.list_credentials()) == 1
        s = oath.OathSession(YkConnection(card))
        with pytest.raises(Exception):
            s.validate(key)
        s = oath.OathSession(YkConnection(card))
        s.validate(new_key)
        s.unset_key()
    finally:
        card.close()


def test_validate_attempts_are_limited(device):
    e = device()
    card = open_card()
    try:
        oath_select(card)
        assert put(card, b"alice", RFC4226_SECRET) == SW_OK
        assert set_code(card, KEY) == SW_OK
        chal = oath_select(card)
        for i in range(10):
            assert validate(card, KEY, chal, resp=bytes(20)) == SW_DATA_INVALID
        # the right answer does not help any more until a power cycle
        assert validate(card, KEY, chal) == SW_BLOCKED
        assert apdu(card, INS_LIST)[1] == SW_SECURITY
    finally:
        card.close()
    e.restart()
    card = open_card()
    try:
        chal = oath_select(card)
        assert validate(card, KEY, chal, resp=bytes(20)) == SW_DATA_INVALID
        assert validate(card, KEY, chal) == SW_OK            # a success starts the count again
        assert apdu(card, INS_LIST)[1] == SW_OK
    finally:
        card.close()


def test_reset_needs_a_touch(device):
    device(LF_EMU_UP="manual", LF_EMU_UP_TIMEOUT_MS="800")
    card = open_card()
    try:
        oath_select(card)
        assert put(card, b"alice", RFC4226_SECRET) == SW_OK
        assert apdu(card, INS_RESET, 0xDE, 0xAD)[1] == SW_CONDITIONS
        assert [v[1:] for t, v in parse_tlvs(apdu(card, INS_LIST)[0])] == [b"alice"]
        assert pressing(lambda: apdu(card, INS_RESET, 0xDE, 0xAD))[1] == SW_OK
        assert apdu(card, INS_LIST) == (b"", SW_OK)
    finally:
        card.close()


def test_touch_property_is_enforced(device):
    device(LF_EMU_UP="manual", LF_EMU_UP_TIMEOUT_MS="1000")
    card = open_card()
    try:
        oath_select(card)
        assert put(card, b"touchy", RFC4226_SECRET, touch=True) == SW_OK
        assert put(card, b"hotp-touch", RFC4226_SECRET, kind=HOTP, imf=5, touch=True) == SW_OK
        assert put(card, b"plain", RFC4226_SECRET) == SW_OK

        entries = parse_tlvs(apdu(card, INS_LIST, data=b"\x01")[0])
        props = {v[1:-1]: v[-1] for t, v in entries}
        assert props == {b"touchy": 1, b"hotp-touch": 1, b"plain": 0}

        chal = (1).to_bytes(8, "big")
        all_ = parse_tlvs(apdu(card, INS_CALC_ALL, 0, 1, tlv(TAG_CHALLENGE, chal))[0])
        tags = {all_[i][1]: all_[i + 1][0] for i in range(0, len(all_), 2)}
        assert tags == {b"touchy": TAG_TOUCH_RESPONSE, b"hotp-touch": TAG_NO_RESPONSE, b"plain": TAG_T_RESPONSE}

        # nobody touches: refused, and the HOTP counter did not move
        assert calculate(card, b"touchy", chal)[1] == SW_CONDITIONS
        assert calculate(card, b"hotp-touch")[1] == SW_CONDITIONS
        code, sw = pressing(lambda: calculate(card, b"touchy", chal))
        assert sw == SW_OK and code == totp(RFC4226_SECRET, chal)
        code, sw = pressing(lambda: calculate(card, b"hotp-touch"))
        assert sw == SW_OK and code == RFC4226_CODES[5]
        # no touch needed for the other one
        code, sw = calculate(card, b"plain", chal)
        assert sw == SW_OK and code == totp(RFC4226_SECRET, chal)

        # a password-safe entry with touch: its fields need the press too
        assert put(card, b"vault", RFC4226_SECRET, touch=True,
                   extra=tlv(TAG_PWS_LOGIN, b"alice") + tlv(TAG_PWS_PASSWORD, b"hunter2")) == SW_OK
        get = (INS_GET_CREDENTIAL, 0, 0, tlv(TAG_NAME, b"vault"))
        assert apdu(card, *get) == (b"", SW_CONDITIONS)
        data, sw = pressing(lambda: apdu(card, *get))
        assert sw == SW_OK and dict(parse_tlvs(data))[TAG_PWS_PASSWORD] == b"hunter2"
    finally:
        card.close()


def test_verify_code_accepts_a_hotp_code_once(device):
    device()
    card = open_card()
    try:
        oath_select(card)
        oath_reset(card)
        assert put(card, b"heads", RFC4226_SECRET, kind=HOTP) == SW_OK

        def verify(code, raw=None):
            value = raw if raw is not None else code.to_bytes(4, "big")
            return apdu(card, INS_VERIFY_CODE, data=tlv(TAG_NAME, b"heads") + tlv(TAG_RESPONSE, value))[1]
        assert verify(0, raw=b"\0\0\0") == SW_INCORRECT_PARAMS
        assert apdu(card, INS_VERIFY_CODE, data=tlv(TAG_NAME, b"heads"))[1] == SW_INCORRECT_PARAMS
        assert verify(RFC4226_CODES[0]) == SW_OK
        assert verify(RFC4226_CODES[0]) == SW_WRONG_DATA        # replay
        assert verify(RFC4226_CODES[1]) == SW_OK
        assert verify(RFC4226_CODES[5]) == SW_OK                # within the look-ahead window
        assert verify(RFC4226_CODES[3]) == SW_WRONG_DATA        # behind the counter now
        # CALCULATE continues after the last verified counter
        code, sw = calculate(card, b"heads")
        assert sw == SW_OK and code == RFC4226_CODES[6]
        # misses are limited (a match starts the count again)
        assert verify(RFC4226_CODES[7]) == SW_OK
        for _ in range(10):
            assert verify(123) == SW_WRONG_DATA
        assert verify(RFC4226_CODES[8]) == SW_BLOCKED
        oath_reset(card)
        assert put(card, b"heads", RFC4226_SECRET, kind=HOTP) == SW_OK
        assert verify(RFC4226_CODES[0]) == SW_OK
    finally:
        card.close()


def test_password_safe_needs_access_code_and_pin(device):
    device()
    card = open_card()
    try:
        oath_select(card)
        oath_reset(card)
        assert put(card, b"mail", RFC4226_SECRET,
                   extra=tlv(TAG_PWS_LOGIN, b"alice") + tlv(TAG_PWS_PASSWORD, b"hunter2")) == SW_OK
        get = (INS_GET_CREDENTIAL, 0, 0, tlv(TAG_NAME, b"mail"))
        fields = dict(parse_tlvs(apdu(card, *get)[0]))
        assert fields[TAG_PWS_PASSWORD] == b"hunter2"

        assert apdu(card, INS_SET_PIN, data=tlv(TAG_PASSWORD, b"1234"))[1] == SW_OK
        assert apdu(card, *get)[1] == SW_SECURITY
        assert apdu(card, INS_LIST)[1] == SW_SECURITY
        assert apdu(card, INS_VERIFY_PIN, data=tlv(TAG_PASSWORD, b"0000"))[1] == SW_SECURITY
        assert apdu(card, INS_VERIFY_PIN, data=tlv(TAG_PASSWORD, b"1234"))[1] == SW_OK
        assert dict(parse_tlvs(apdu(card, *get)[0]))[TAG_PWS_LOGIN] == b"alice"

        # the PIN does not stand in for the access code
        assert set_code(card, KEY) == SW_OK
        chal = oath_select(card)
        assert apdu(card, INS_VERIFY_PIN, data=tlv(TAG_PASSWORD, b"1234"))[1] == SW_OK
        assert apdu(card, *get)[1] == SW_SECURITY
        assert validate(card, KEY, chal) == SW_OK
        assert apdu(card, *get)[1] == SW_OK
        # and the access code not for the PIN
        chal = oath_select(card)
        assert validate(card, KEY, chal) == SW_OK
        assert apdu(card, *get)[1] == SW_SECURITY
    finally:
        card.close()


def test_otp_pin_tries_are_shared_by_change_and_verify(device):
    device()
    card = open_card()
    try:
        oath_select(card)
        oath_reset(card)
        assert apdu(card, INS_SET_PIN, data=tlv(TAG_PASSWORD, b""))[1] != SW_OK
        assert apdu(card, INS_SET_PIN, data=tlv(TAG_PASSWORD, b"1234"))[1] == SW_OK
        assert apdu(card, INS_SET_PIN, data=tlv(TAG_PASSWORD, b"9999"))[1] == SW_CONDITIONS
        change = lambda old: apdu(card, INS_CHANGE_PIN,
                                  data=tlv(TAG_PASSWORD, old) + tlv(TAG_NEW_PASSWORD, b"5678"))[1]
        # a right PIN restores the tries
        assert change(b"0000") == SW_SECURITY
        assert apdu(card, INS_VERIFY_PIN, data=tlv(TAG_PASSWORD, b"1234"))[1] == SW_OK
        for _ in range(3):
            assert change(b"0000") == SW_SECURITY
        assert change(b"1234") == SW_BLOCKED
        assert apdu(card, INS_VERIFY_PIN, data=tlv(TAG_PASSWORD, b"1234"))[1] == SW_BLOCKED
        assert apdu(card, INS_LIST)[1] == SW_SECURITY
        oath_reset(card)
        assert apdu(card, INS_LIST)[1] == SW_OK
    finally:
        card.close()


def test_put_and_rename_are_bounded(device):
    device()
    card = open_card()
    try:
        oath_select(card)
        oath_reset(card)
        assert put(card, b"n" * 65, RFC4226_SECRET) == SW_WRONG_DATA
        assert put(card, b"", RFC4226_SECRET) == SW_WRONG_DATA
        short_key = tlv(TAG_NAME, b"k") + tlv(TAG_KEY, b"\x21")
        assert apdu(card, INS_PUT, data=short_key)[1] == SW_WRONG_DATA
        assert apdu(card, INS_PUT, data=tlv(TAG_NAME, b"k") + tlv(TAG_KEY, b""))[1] == SW_WRONG_DATA
        assert put(card, b"k", RFC4226_SECRET, digits=9) == SW_WRONG_DATA
        assert apdu(card, INS_PUT, data=tlv(TAG_NAME, b"k") + tlv(TAG_KEY, b"\x2f\x06abc"))[1] == SW_WRONG_DATA
        # a length running past the data
        assert apdu(card, INS_PUT, data=tlv(TAG_NAME, b"k") + b"\x73\x40\x21\x06")[1] == SW_INCORRECT_PARAMS
        # 3000 byte name through command chaining
        big = tlv(TAG_NAME, b"x" * 3000) + tlv(TAG_KEY, b"\x21\x06" + RFC4226_SECRET)
        _, sw = card.transmit(0x00, INS_PUT, 0, 0, big, check=False)
        assert sw == SW_WRONG_DATA
        assert apdu(card, INS_LIST) == (b"", SW_OK)

        assert put(card, b"abc", RFC4226_SECRET) == SW_OK
        assert put(card, b"other", RFC4226_SECRET) == SW_OK
        rename = lambda a, b: apdu(card, INS_RENAME, data=tlv(TAG_NAME, a) + tlv(TAG_NAME, b))[1]
        assert rename(b"abc", b"abcd") == SW_OK             # a longer name starting with the old one
        assert rename(b"abcd", b"other") == SW_CONDITIONS   # taken
        assert rename(b"other", b"o" * 65) == SW_WRONG_DATA
        assert rename(b"other", b"o" * 129) == SW_WRONG_DATA
        assert rename(b"missing", b"new") == SW_DATA_INVALID
        names = sorted(v[1:] for t, v in parse_tlvs(apdu(card, INS_LIST)[0]))
        assert names == [b"abcd", b"other"]
        chal = bytes(8)
        assert calculate(card, b"abcd", chal) == (totp(RFC4226_SECRET, chal), SW_OK)
    finally:
        card.close()


def test_long_answers_are_paged(device):
    oath = pytest.importorskip("yubikit.oath")
    device()
    card = open_card()
    try:
        oath_select(card)
        oath_reset(card)
        names = [("cred-%03d-" % i).encode() + b"n" * 52 for i in range(100)]
        for n in names:
            assert put(card, n, RFC4226_SECRET, digits=8) == SW_OK
        # LIST: 100 x 67 bytes do not fit one answer
        out, pages = b"", 0
        data, sw = apdu(card, INS_LIST)
        while True:
            pages += 1
            assert len(data) <= 2048
            out += data
            if sw == SW_OK:
                break
            assert sw >> 8 == 0x61
            data, sw = apdu(card, INS_SEND_REMAINING)
        assert pages > 1
        assert [v[1:] for t, v in parse_tlvs(out)] == names
        # a different command drops the rest
        data, sw = apdu(card, INS_LIST)
        assert sw >> 8 == 0x61
        apdu(card, INS_CALCULATE, 0, 1, tlv(TAG_NAME, names[0]) + tlv(TAG_CHALLENGE, bytes(8)))
        assert apdu(card, INS_SEND_REMAINING)[1] == SW_CONDITIONS

        # yubikit follows the pages
        s = oath.OathSession(YkConnection(card))
        assert len(s.list_credentials()) == 100
        codes = s.calculate_all(timestamp=59)
        assert len(codes) == 100
        assert {c.value for c in codes.values()} == {"94287082"}
    finally:
        card.close()
