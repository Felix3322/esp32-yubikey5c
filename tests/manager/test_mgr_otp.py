"""Key manager, OTP slots (librefido.mgr_otp) against the emulator: each mode
programmed and then used (what a slot types is read from the emulator log,
LF_EMU_KEYBOARD_LOG=1; the Yubico OTP typed is decrypted with its key),
challenge-response with and without touch, access codes set / required /
changed / removed, delete, swap, status, the slots after a power cycle, and a
slot yubikit programmed.

    bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/manager/test_mgr_otp.py
"""

import hmac
import os
import time

import pytest

from harness.emulator import Button

from librefido import mgr_otp as O
from librefido.mgr_common import AuthRequired, ManagerError, WrongSecret
from librefido.mgr_otp import OtpManager

KEY20 = bytes(range(1, 21))
RFC4226_SECRET = b"12345678901234567890"
RFC4226_CODES = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489]
CODE = bytes.fromhex("0102030405ff")
CODE2 = bytes.fromhex("a1a2a3a4a5a6")
KEYBOARD = {"LF_EMU_UP": "manual", "LF_EMU_KEYBOARD_LOG": "1"}


def hotp(secret, counter, digits=6):
    h = hmac.new(secret, counter.to_bytes(8, "big"), "sha1").digest()
    off = h[-1] & 0x0F
    return "%0*d" % (digits, (int.from_bytes(h[off:off + 4], "big") & 0x7FFFFFFF) % 10 ** digits)


def typed(e, presses=1, timeout=6.0):
    """Presses the button presses times while the device is idle (1: slot 1,
    2: slot 2) and returns the lines the slot typed (emulator log)."""
    off = os.path.getsize(e.log_path)
    b = Button()
    try:
        for _ in range(presses):
            b.press(0.1)
            time.sleep(0.2)
    finally:
        b.close()

    def lines():
        with open(e.log_path, errors="replace") as f:
            f.seek(off)
            return [ln.split("[otp] keyboard: ", 1)[1] for ln in f.read().splitlines() if "[otp] keyboard: " in ln]
    deadline = time.time() + timeout
    while not lines() and time.time() < deadline:
        time.sleep(0.1)
    time.sleep(0.4)
    return lines()


def yubico_otp_fields(text, key):
    """(public ID, private ID, usage counter, session counter) of a typed
    Yubico OTP, after checking its CRC."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    raw = O.modhex_decode(text)
    assert len(raw) == 22
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    token = d.update(raw[6:]) + d.finalize()
    assert O.check_crc(token)
    return raw[:6], token[:6], int.from_bytes(token[6:8], "little"), token[11]


@pytest.fixture
def otp_device(device, connect):
    """(emulator with the manual button and the keyboard log, OtpManager)."""
    e = device(**KEYBOARD)
    time.sleep(1.2)         # button events count from one second after the start
    return e, OtpManager(connect())


def test_status_of_a_new_device(mgmt):
    st = OtpManager(mgmt).status()
    assert st["version"].count(".") == 2 and isinstance(st["serial"], int)
    for slot in (1, 2):
        assert st["slots"][slot] == {"configured": False, "touch_triggered": False, "mode": None, "public_id": None,
                                     "digits": None, "append_cr": None, "touch": None}
    # the management applet answers again afterwards
    assert mgmt.info()["boot_status"] == "ok"
    assert OtpManager(mgmt).serial() == st["serial"]


def test_yubico_otp_is_typed_and_decrypts(otp_device):
    e, o = otp_device
    pub, priv, key = o.random_yubico_otp()
    o.program_yubico_otp(1, pub, priv, key)
    s = o.status()["slots"][1]
    assert s["configured"] and s["touch_triggered"] and s["mode"] == "yubico-otp"
    assert s["public_id"] == O.modhex_encode(pub) and s["public_id"].startswith("vv") and s["append_cr"] is True
    first = typed(e)
    assert len(first) == 2 and first[1] == "<0d>" and len(first[0]) == 44
    got_pub, got_priv, usage, session = yubico_otp_fields(first[0], key)
    assert got_pub == pub and got_priv == priv and usage >= 1
    second = typed(e)
    assert second[0] != first[0]
    _, got_priv2, usage2, session2 = yubico_otp_fields(second[0], key)
    assert got_priv2 == priv and (usage2, session2) == (usage, session + 1)
    # from text (as the GUI has it), without Enter, into slot 2
    o.program_yubico_otp(2, O.modhex_encode(pub), priv.hex(), key.hex(), append_cr=False)
    lines = typed(e, presses=2)
    assert len(lines) == 1 and yubico_otp_fields(lines[0], key)[:2] == (pub, priv)


def test_chalresp(device, connect, button):
    device(LF_EMU_UP="manual", LF_EMU_UP_TIMEOUT_MS="1000")
    o = OtpManager(connect())
    o.program_chalresp(2, KEY20)
    s = o.status()["slots"]
    assert not s[1]["configured"]
    assert s[2]["configured"] and not s[2]["touch_triggered"] and s[2]["mode"] == "chal-hmac" and \
        s[2]["touch"] is False
    challenges = (b"", b"x", os.urandom(32), os.urandom(62) + b"\0", os.urandom(63), b"\0" * 10)
    wrong = [c.hex() for c in challenges if o.calculate_hmac(2, c) != hmac.new(KEY20, c, "sha1").digest()]
    assert wrong == []
    # a 64-byte challenge goes as it is, and the device, like a YubiKey
    # (HMAC_LT64), takes its last byte and the equal ones before it for padding
    chal = bytes(range(62)) + b"\x07\x07"
    assert o.calculate_hmac(2, chal) == hmac.new(KEY20, chal[:62], "sha1").digest()
    with pytest.raises(ManagerError, match="at most 64"):
        o.calculate_hmac(2, bytes(65))
    # a key longer than 20 bytes, and a touch for every response
    long_key = os.urandom(100)
    o.program_chalresp(1, long_key, touch=True)
    s = o.status()["slots"][1]
    assert not s["touch_triggered"] and s["touch"] is True     # (a press types nothing)
    with pytest.raises(ManagerError) as ex:
        o.calculate_hmac(1, b"no touch")
    assert ex.value.sw == 0x6985 and "touch" in str(ex.value) and ex.value.zh
    resp = button.pressing(lambda: o.calculate_hmac(1, b"touched"))
    assert resp == hmac.new(long_key, b"touched", "sha1").digest()


def test_hotp_is_typed(otp_device):
    e, o = otp_device
    o.program_hotp(1, RFC4226_SECRET)
    s = o.status()["slots"][1]
    assert s["mode"] == "hotp" and s["digits"] == 6 and s["append_cr"] is True and s["touch_triggered"]
    assert typed(e) == [str(RFC4226_CODES[0]), "<0d>"]
    assert typed(e) == [str(RFC4226_CODES[1]), "<0d>"]
    # 8 digits, an initial counter, base32 text, no Enter
    import base64
    o.program_hotp(2, base64.b32encode(RFC4226_SECRET).decode().lower(), digits=8, counter=32, append_cr=False)
    assert o.status()["slots"][2]["digits"] == 8
    assert typed(e, presses=2) == [hotp(RFC4226_SECRET, 32, 8)]
    assert typed(e, presses=2) == [hotp(RFC4226_SECRET, 33, 8)]
    # an HOTP slot is no challenge-response slot
    with pytest.raises(ManagerError, match="not programmed for HMAC-SHA1"):
        o.calculate_hmac(1, b"x")


def test_static_password_is_typed(otp_device):
    e, o = otp_device
    password = "Hello, World! 42"
    o.program_static(1, password)
    s = o.status()["slots"][1]
    assert s["mode"] == "static" and s["append_cr"] is True and s["public_id"] is None
    codes = O.encode_scan_codes(password, "us").ljust(O.SCAN_CODES_SIZE, b"\0")
    assert typed(e) == ["".join("<%02x>" % c for c in codes), "<28>"]
    generated = O.random_static_password()
    o.program_static(2, generated, layout="modhex", append_cr=False)
    codes = O.encode_scan_codes(generated, "modhex").ljust(O.SCAN_CODES_SIZE, b"\0")
    assert typed(e, presses=2) == ["".join("<%02x>" % c for c in codes)]


def test_nothing_is_overwritten_silently(mgmt):
    o = OtpManager(mgmt)
    o.program_chalresp(1, KEY20)
    with pytest.raises(ManagerError) as ex:
        o.program_hotp(1, RFC4226_SECRET)
    assert ex.value.sw == 0x6A89 and "replace it explicitly" in str(ex.value)
    assert o.status()["slots"][1]["mode"] == "chal-hmac"
    assert o.calculate_hmac(1, b"kept") == hmac.new(KEY20, b"kept", "sha1").digest()
    o.program_hotp(1, RFC4226_SECRET, replace=True)
    assert o.status()["slots"][1]["mode"] == "hotp"


def test_access_code_set_required_changed_removed(mgmt):
    o = OtpManager(mgmt)
    o.program_chalresp(1, KEY20, new_access_code=CODE)

    def works():
        return o.calculate_hmac(1, b"still") == hmac.new(KEY20, b"still", "sha1").digest()
    # required: nothing changes the slot without it
    with pytest.raises(AuthRequired) as ex:
        o.program_hotp(1, RFC4226_SECRET, replace=True)
    assert ex.value.sw == 0x6982 and ex.value.zh
    with pytest.raises(WrongSecret):
        o.program_hotp(1, RFC4226_SECRET, access_code=CODE2, replace=True)
    with pytest.raises(AuthRequired):
        o.delete(1)
    with pytest.raises(WrongSecret):
        o.delete(1, access_code=CODE2.hex())
    with pytest.raises(AuthRequired):
        o.swap()
    with pytest.raises(AuthRequired):
        o.set_access_code(1, None)
    s = o.status()["slots"]
    assert s[1]["mode"] == "chal-hmac" and not s[2]["configured"] and works()
    # changed (the secret and the settings stay)
    o.set_access_code(1, CODE2, access_code=CODE)
    with pytest.raises(WrongSecret):
        o.delete(1, access_code=CODE)
    assert works() and o.status()["slots"][1]["touch"] is False
    # a protected slot swaps with its code
    o.swap(access_code=CODE2)
    assert o.status()["slots"][2]["mode"] == "chal-hmac" and not o.status()["slots"][1]["configured"]
    assert o.calculate_hmac(2, b"x") == hmac.new(KEY20, b"x", "sha1").digest()
    o.swap(access_code=CODE2.hex())
    assert works()
    # removed
    o.set_access_code(1, None, access_code=CODE2)
    assert works()
    o.set_access_code(1, CODE)         # set on a slot without one: no current code needed
    with pytest.raises(AuthRequired):
        o.delete(1)
    o.set_access_code(1, "", access_code=CODE)
    # reprogramming a protected slot with its code, keeping a code
    o.set_access_code(1, CODE)
    o.program_hotp(1, RFC4226_SECRET, access_code=CODE, new_access_code=CODE2, replace=True)
    with pytest.raises(WrongSecret):
        o.delete(1, access_code=CODE)
    o.delete(1, access_code=CODE2)
    assert not o.status()["slots"][1]["configured"]


def test_delete_and_swap(mgmt):
    o = OtpManager(mgmt)
    with pytest.raises(ManagerError, match="both slots are empty"):
        o.swap()
    with pytest.raises(ManagerError, match="not programmed"):
        o.delete(1)
    o.program_chalresp(1, KEY20)
    o.program_hotp(2, RFC4226_SECRET, digits=8)
    o.swap()
    s = o.status()["slots"]
    assert (s[1]["mode"], s[1]["digits"], s[2]["mode"]) == ("hotp", 8, "chal-hmac")
    assert o.calculate_hmac(2, b"swapped") == hmac.new(KEY20, b"swapped", "sha1").digest()
    o.delete(2)
    s = o.status()["slots"]
    assert s[1]["mode"] == "hotp" and not s[2]["configured"]
    with pytest.raises(ManagerError, match="not programmed"):
        o.calculate_hmac(2, b"gone")
    o.swap()                            # one slot empty: it moves
    s = o.status()["slots"]
    assert not s[1]["configured"] and s[2]["mode"] == "hotp"
    o.delete(2)
    assert not any(s["configured"] for s in o.status()["slots"].values())


def test_slots_survive_a_power_cycle(device, connect):
    e = device()
    o = OtpManager(connect())
    o.program_chalresp(2, KEY20, new_access_code=CODE)
    o.program_hotp(1, RFC4226_SECRET)
    e.restart()
    o = OtpManager(connect())
    s = o.status()["slots"]
    assert s[1]["mode"] == "hotp" and s[2]["mode"] == "chal-hmac"
    assert o.calculate_hmac(2, b"again") == hmac.new(KEY20, b"again", "sha1").digest()
    with pytest.raises(AuthRequired):
        o.delete(2)


def test_a_slot_yubikit_programmed(mgmt):
    """The manager takes over a slot ykman / yubikit programmed (access code
    and all), and yubikit reads what the manager programmed."""
    yubiotp = pytest.importorskip("yubikit.yubiotp")
    from harness.card import Card, YkConnection
    # yubikit on the manager's own connection (another connection would reset
    # the card when it closes)
    yk = YkConnection(Card(conn=mgmt.card.conn))
    s = yubiotp.YubiOtpSession(yk)
    s.put_configuration(yubiotp.SLOT.TWO, yubiotp.HmacSha1SlotConfiguration(KEY20), acc_code=CODE)
    o = OtpManager(mgmt)
    assert o.status()["slots"][2]["mode"] == "chal-hmac"
    o.set_access_code(2, None, access_code=CODE)
    assert o.calculate_hmac(2, b"yk") == hmac.new(KEY20, b"yk", "sha1").digest()
    o.program_chalresp(1, KEY20[:16], touch=False)
    s = yubiotp.YubiOtpSession(yk)
    state = s.get_config_state()
    assert state.is_configured(yubiotp.SLOT.ONE) and state.is_configured(yubiotp.SLOT.TWO)
    assert s.calculate_hmac_sha1(yubiotp.SLOT.ONE, b"mgr") == hmac.new(KEY20[:16], b"mgr", "sha1").digest()
    s.delete_slot(yubiotp.SLOT.TWO)             # no access code any more
    assert not o.status()["slots"][2]["configured"]
    assert mgmt.info()["boot_status"] == "ok"
