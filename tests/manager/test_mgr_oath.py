"""Key manager, OATH (librefido.mgr_oath) against the emulator: accounts of
every type, algorithm, digit count and period with the RFC 4226 / RFC 6238
test vectors, touch accounts, CALCULATE ALL, rename, delete, replace, the
OATH password (checked against yubikit, the reference client, too), reset,
and accounts from otpauth:// links.

    bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/manager/test_mgr_oath.py
"""

import hmac
import struct

import pytest

from librefido import stdformats
from librefido.mgr_common import ManagerError, SecretBlocked, WrongSecret
from librefido.mgr_oath import OathManager, OathPasswordRequired

# RFC 4226 appendix D: HOTP-SHA1 of this secret, counters 0..9, before the
# modulo (so every digit count can be checked).
RFC4226_SECRET = b"12345678901234567890"
RFC4226_VALUES = [1284755224, 1094287082, 137359152, 1726969429, 1640338314, 868254676, 1918287922, 82162583,
                  673399871, 645520489]

# RFC 6238 appendix B: TOTP, 30 s, 8 digits.
RFC6238 = {
    "SHA1": (b"12345678901234567890",
             {59: "94287082", 1111111109: "07081804", 1111111111: "14050471", 1234567890: "89005924",
              2000000000: "69279037", 20000000000: "65353130"}),
    "SHA256": (b"12345678901234567890123456789012",
               {59: "46119246", 1111111109: "68084774", 1111111111: "67062674", 1234567890: "91819424",
                2000000000: "90698825", 20000000000: "77737706"}),
    "SHA512": (b"1234567890123456789012345678901234567890123456789012345678901234",
               {59: "90693936", 1111111109: "25091201", 1111111111: "99943326", 1234567890: "93441116",
                2000000000: "38618901", 20000000000: "47863826"}),
}


def hotp_value(secret, counter, hname="sha1"):
    """Reference HOTP (RFC 4226 section 5.3), independent of the tool."""
    h = hmac.new(secret, struct.pack(">Q", counter), hname).digest()
    off = h[-1] & 0x0F
    return int.from_bytes(h[off:off + 4], "big") & 0x7FFFFFFF


def code(value, digits):
    return str(value % 10 ** digits).rjust(digits, "0")


def test_totp_all_algorithms_and_digits(mgmt):
    o = OathManager(mgmt)
    raws = {}
    for alg, (secret, _) in RFC6238.items():
        for digits in (6, 7, 8):
            raws[alg, digits] = o.add("RFC6238 " + alg, "d%d" % digits, secret, algorithm=alg, digits=digits)
    assert raws["SHA256", 7] == b"RFC6238 SHA256:d7"
    listed = {e["raw"]: e for e in o.list()}
    for (alg, digits), raw in raws.items():
        e = listed[raw]
        assert (e["type"], e["algorithm"], e["digits"], e["period"], e["touch"]) == ("totp", alg, digits, 30, False)
        assert (e["issuer"], e["account"], e["name"]) == ("RFC6238 " + alg, "d%d" % digits, raw.decode())
    for t in RFC6238["SHA1"][1]:
        codes = o.calculate_all(t)
        for (alg, digits), raw in raws.items():
            assert codes[raw] == RFC6238[alg][1][t][-digits:], (alg, digits, t)
    assert o.calculate(raws["SHA512", 8], 1234567890) == "93441116"
    assert o.calculate(raws["SHA1", 6], 59) == "287082"


def test_hotp_counters(mgmt):
    o = OathManager(mgmt)
    h6 = o.add("RFC4226", "six", RFC4226_SECRET, type="hotp")
    h8 = o.add("RFC4226", "eight", RFC4226_SECRET, type="hotp", digits=8, counter=5)
    h7 = o.add(None, "seven", RFC4226_SECRET, type="HOTP", digits=7, counter=1 << 33)
    e = {x["raw"]: x for x in o.list()}
    assert (e[h6]["type"], e[h6]["period"], e[h6]["digits"]) == ("hotp", None, 6)
    assert e[h7]["issuer"] is None and e[h7]["account"] == "seven"
    # CALCULATE ALL leaves HOTP accounts alone (no counter moves)
    codes = o.calculate_all(59)
    assert codes[h6] is None and codes[h8] is None and codes[h7] is None
    assert [o.calculate(h6) for _ in range(3)] == [code(v, 6) for v in RFC4226_VALUES[:3]]
    assert [o.calculate(h8) for _ in range(2)] == [code(v, 8) for v in RFC4226_VALUES[5:7]]
    assert o.calculate(h7) == code(hotp_value(RFC4226_SECRET, 1 << 33), 7)
    assert o.calculate(h7) == code(hotp_value(RFC4226_SECRET, (1 << 33) + 1), 7)
    # other hash algorithms (no RFC vector: the reference implementation above)
    s256, s512 = RFC6238["SHA256"][0], RFC6238["SHA512"][0]
    a = o.add("H", "sha256", s256, type="hotp", algorithm="sha256", counter=7)
    b = o.add("H", "sha512", s512, type="hotp", algorithm="SHA512", digits=8)
    assert o.calculate(a) == code(hotp_value(s256, 7, "sha256"), 6)
    assert o.calculate(b) == code(hotp_value(s512, 0, "sha512"), 8)


def test_periods(mgmt):
    o = OathManager(mgmt)
    secret = RFC6238["SHA1"][0]
    p15 = o.add("P", "fifteen", secret, period=15)
    p60 = o.add("P", "sixty", secret, period=60, digits=8, algorithm="SHA256")
    p30 = o.add("P", "thirty", secret)
    assert (p15, p60, p30) == (b"15/P:fifteen", b"60/P:sixty", b"P:thirty")
    e = {x["raw"]: x for x in o.list()}
    assert (e[p15]["period"], e[p60]["period"], e[p30]["period"]) == (15, 60, 30)
    assert (e[p15]["issuer"], e[p15]["account"]) == ("P", "fifteen")
    for t in (59, 1111111111, 20000000000):
        codes = o.calculate_all(t)
        assert codes[p15] == code(hotp_value(secret, t // 15), 6)
        assert codes[p60] == code(hotp_value(secret, t // 60, "sha256"), 8)
        assert codes[p30] == code(hotp_value(secret, t // 30), 6)
        assert o.calculate(p15, t) == codes[p15]
        assert o.calculate(p60, t) == codes[p60]


def test_names_that_look_like_a_period(mgmt):
    """Accounts named "0/work" or "12/alice" (30 s) are stored with their
    period written out and read back as typed, with 30 s codes; a name that
    another tool stored as "0/x" lists as a 30 s account instead of making
    every code calculation fail."""
    o = OathManager(mgmt)
    secret = RFC6238["SHA1"][0]
    zero = o.add(None, "0/work", secret)
    twelve = o.add("", "12/alice", secret, digits=8)
    assert (zero, twelve) == (b"30/0/work", b"30/12/alice")
    legacy = o.add_record({1: b"0/x", 2: stdformats.OATH_TOTP | 1, 3: 6, 4: secret})
    e = {x["raw"]: x for x in o.list()}
    assert (e[zero]["issuer"], e[zero]["account"], e[zero]["period"]) == (None, "0/work", 30)
    assert (e[twelve]["issuer"], e[twelve]["account"], e[twelve]["period"]) == (None, "12/alice", 30)
    assert (e[legacy]["account"], e[legacy]["period"]) == ("0/x", 30)
    assert o.calculate_all(1111111109) == {zero: "081804", twelve: "07081804", legacy: "081804"}
    assert o.calculate(twelve, 1111111109) == "07081804"
    assert o.calculate(legacy, 59) == o.calculate(zero, 59) == "287082"
    assert o.rename(legacy, None, "0/y") == b"30/0/y"
    assert o.rename(twelve, "12/x", "a") == b"30/12/x:a"
    assert {x["raw"]: (x["issuer"], x["account"], x["period"]) for x in o.list()} == {
        zero: (None, "0/work", 30), b"30/0/y": (None, "0/y", 30), b"30/12/x:a": ("12/x", "a", 30)}


def test_touch_accounts(device, connect, button):
    device(LF_EMU_UP="manual")
    o = OathManager(connect())
    secret = RFC6238["SHA1"][0]
    t_raw = o.add("T", "totp", secret, touch=True)
    h_raw = o.add("T", "hotp", RFC4226_SECRET, type="hotp", touch=True)
    plain = o.add("T", "plain", secret)
    e = {x["raw"]: x for x in o.list()}
    assert e[t_raw]["touch"] and e[h_raw]["touch"] and not e[plain]["touch"]
    # CALCULATE ALL never waits: touch accounts come back without a code
    codes = o.calculate_all(59)
    assert codes == {t_raw: None, h_raw: None, plain: "287082"}
    # one by one they wait for the press
    assert button.pressing(lambda: o.calculate(t_raw, 59)) == "287082"
    assert button.pressing(lambda: o.calculate(h_raw)) == code(RFC4226_VALUES[0], 6)
    assert button.pressing(lambda: o.calculate(h_raw)) == code(RFC4226_VALUES[1], 6)


def test_touch_account_with_automatic_press(mgmt):
    o = OathManager(mgmt)
    raw = o.add("T", "auto", RFC6238["SHA1"][0], touch=True, digits=8)
    assert o.calculate_all(1234567890)[raw] is None
    assert o.calculate(raw, 1234567890) == "89005924"


def test_rename_delete_replace(mgmt):
    o = OathManager(mgmt)
    secret = RFC6238["SHA1"][0]
    a = o.add("Old", "alice", secret, period=60)
    b = o.add("Other", "bob", secret)
    with pytest.raises(ManagerError) as e:
        o.add("Other", "bob", RFC4226_SECRET)               # never replaced silently
    assert e.value.sw == 0x6A89 and o.calculate(b, 59) == "287082"
    assert o.add("Other", "bob", RFC4226_SECRET, replace=True) == b
    assert o.calculate(b, 59) == code(hotp_value(RFC4226_SECRET, 1), 6)

    new = o.rename(a, "New", "alice2")
    assert new == b"60/New:alice2"                          # the period stays
    names = [x["raw"] for x in o.list()]
    assert a not in names and new in names
    assert o.calculate(new, 59) == code(hotp_value(secret, 0), 6)
    assert o.rename(new, "New", "alice2") == new            # nothing to change
    taken = o.add("Taken", "name", secret, period=60)
    with pytest.raises(ManagerError) as e:
        o.rename(new, "Taken", "name")                       # the name of another account
    assert e.value.sw == 0x6A89
    assert o.rename(new, "Other", "bob") == b"60/Other:bob"  # another period: another name
    new = b"60/Other:bob"
    o.delete(taken)
    with pytest.raises(ManagerError):
        o.rename(a, "X", "y")                                # gone
    o.delete(new)
    assert [x["raw"] for x in o.list()] == [b]
    with pytest.raises(ManagerError) as e:
        o.delete(new)
    assert e.value.sw == 0x6984
    with pytest.raises(ManagerError):
        o.calculate(new, 59)


def test_invalid_accounts_are_refused(mgmt):
    o = OathManager(mgmt)
    s = RFC4226_SECRET
    bad = [dict(digits=5), dict(digits=9), dict(algorithm="MD5"), dict(type="steam"), dict(period=0),
           dict(type="hotp", counter=-1), dict(type="hotp", counter=1 << 64)]
    for kw in bad:
        with pytest.raises(ManagerError) as e:
            o.add("I", "x", s, **kw)
        assert e.value.zh, kw
    for issuer, account in (("I", ""), ("a:b", "x"), ("I" * 40, "y" * 30)):
        with pytest.raises(ManagerError):
            o.add(issuer, account, s)
    with pytest.raises(ManagerError):
        o.add("I", "x", b"")
    assert o.list() == []
    # a long secret is shortened as YKOATH clients do: the codes stay the same
    long_secret = bytes(range(100))
    raw = o.add("L", "long", long_secret)
    assert o.calculate(raw, 59) == code(hotp_value(long_secret, 1), 6)


def test_password(mgmt):
    o = OathManager(mgmt)
    st = o.status()
    assert st["password_set"] is False and st["locked"] is False and st["device_id"] and st["version"]
    assert o.unlock("anything") is False                    # nothing to unlock
    raw = o.add("P", "acct", RFC6238["SHA1"][0])
    o.set_password("correct horse")
    st = o.status()
    assert st["password_set"] and not st["locked"] and o.unlocked
    assert o.calculate_all(59) == {raw: "287082"}           # this manager holds the key

    other = OathManager(mgmt)
    assert other.status()["locked"] is True
    for op in (other.list, lambda: other.calculate_all(59), lambda: other.add("x", "y", b"secret"),
               lambda: other.delete(raw), lambda: other.set_password("x")):
        with pytest.raises(OathPasswordRequired):
            op()
    with pytest.raises(WrongSecret):
        other.unlock("wrong horse")
    with pytest.raises(WrongSecret):
        other.unlock("")
    assert other.unlock("correct horse") is True
    assert [x["raw"] for x in other.list()] == [raw]

    # changed through one manager: the other one's key no longer opens it
    o.set_password("battery staple")
    with pytest.raises(OathPasswordRequired):
        other.list()
    assert not other.unlocked and other.status()["locked"]
    assert other.unlock("battery staple")
    assert other.calculate(raw, 59) == "287082"
    # removed: no password needed any more
    other.set_password(None)
    assert not other.unlocked
    assert o.unlocked and [x["raw"] for x in o.list()] == [raw]
    assert not o.unlocked                                    # no password any more: its key is dropped
    fresh = OathManager(mgmt)
    assert fresh.status() == dict(st, password_set=False, locked=False)
    assert [x["raw"] for x in fresh.list()] == [raw]


def test_password_attempts_are_limited(device, connect):
    e = device()
    o = OathManager(connect())
    o.set_password("right")
    o.lock()
    for _ in range(10):
        with pytest.raises(WrongSecret):
            o.unlock("wrong")
    with pytest.raises(SecretBlocked) as b:
        o.unlock("right")                                    # refused until a power cycle
    assert "unplug" in str(b.value) and b.value.zh
    e.restart()
    o = OathManager(connect())
    assert o.unlock("right") and not o.status()["locked"]


def test_password_interoperates_with_yubikit(mgmt):
    """The key derivation and VALIDATE are YKOATH's: yubikit (Yubico's own
    client, test-only reference) opens what this tool locked, and the other
    way round."""
    oath = pytest.importorskip("yubikit.oath")
    from harness.card import Card, YkConnection
    o = OathManager(mgmt)
    raw = o.add("Y", "k", RFC6238["SHA1"][0], digits=8)
    o.set_password("s3cret")
    device_id = o.status()["device_id"]
    card = Card()
    try:
        s = oath.OathSession(YkConnection(card))
        assert s.locked and s.device_id == device_id
        s.validate(s.derive_key("s3cret"))
        assert [c.id for c in s.list_credentials()] == [raw]
        yk_codes = {c.id: v.value for c, v in s.calculate_all(1111111109).items()}
        assert yk_codes[raw] == "07081804"
        s.set_key(s.derive_key("from yubikit"))
    finally:
        card.close()
    o2 = OathManager(mgmt)
    with pytest.raises(WrongSecret):
        o2.unlock("s3cret")
    assert o2.unlock("from yubikit")
    assert o2.calculate_all(1111111109) == {raw: "07081804"}


def test_reset(mgmt):
    o = OathManager(mgmt)
    o.add("R", "one", RFC4226_SECRET)
    o.add("R", "two", RFC4226_SECRET, type="hotp")
    o.set_password("pw")
    o.reset()
    assert not o.unlocked
    st = o.status()
    assert st["password_set"] is False and st["locked"] is False
    assert o.list() == [] and o.calculate_all() == {}


def test_add_record_from_otpauth(mgmt):
    o = OathManager(mgmt)
    b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"                  # RFC 4226 secret
    [totp] = stdformats.parse_otpauth("otpauth://totp/ACME%20Co:john@example.com?secret=" + b32 +
                                      "&issuer=ACME%20Co&algorithm=SHA1&digits=8&period=30")
    [hotp] = stdformats.parse_otpauth("otpauth://hotp/Bank:jane?secret=" + b32 + "&counter=3")
    [slow] = stdformats.parse_otpauth("otpauth://totp/Slow:joe?secret=" + b32 + "&period=60&algorithm=SHA256")
    raws = [o.add_record(r) for r in (totp, hotp, slow)]
    assert raws == [b"ACME Co:john@example.com", b"Bank:jane", b"60/Slow:joe"]
    e = {x["raw"]: x for x in o.list()}
    assert (e[raws[0]]["issuer"], e[raws[0]]["account"], e[raws[0]]["digits"]) == ("ACME Co", "john@example.com", 8)
    assert (e[raws[2]]["period"], e[raws[2]]["algorithm"]) == (60, "SHA256")
    assert o.calculate_all(59)[raws[0]] == "94287082"
    assert o.calculate(raws[1]) == code(RFC4226_VALUES[3], 6)
    assert o.calculate(raws[2], 59) == code(hotp_value(RFC4226_SECRET, 0, "sha256"), 6)
    with pytest.raises(ManagerError) as err:
        o.add_record(totp)
    assert err.value.sw == 0x6A89
    def changed(rec, key, value):
        rec = dict(rec)
        rec[key] = value
        return rec
    assert o.add_record(changed(totp, 6, True), replace=True) == raws[0]
    assert next(x for x in o.list() if x["raw"] == raws[0])["touch"] is True
    for broken in ({}, {1: b"x", 2: 0x31, 3: 6, 4: b"k"}, changed(totp, 3, 9), changed(totp, 4, b""),
                   changed(totp, 1, b"n" * 65), "x"):
        with pytest.raises(ManagerError):
            o.add_record(broken)


def test_out_of_range_records_and_arguments_are_refused(mgmt):
    """A type / algorithm byte, digits or HOTP counter the YKOATH PUT cannot
    carry (a byte, a byte, 8 bytes), and a name or secret that is not bytes,
    are refused with a ManagerError (keyfile.check_record alike), not stored
    wrapped around nor raised as ValueError / OverflowError."""
    o = OathManager(mgmt)
    b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    [totp] = stdformats.parse_otpauth("otpauth://totp/A:b?secret=" + b32)
    [hotp] = stdformats.parse_otpauth("otpauth://hotp/C:d?secret=" + b32)
    before = o.list()

    def changed(rec, key, value):
        return {**rec, key: value}
    for broken in (changed(totp, 2, 0x121), changed(totp, 2, -0xDF), changed(totp, 2, 1 << 70),
                   changed(totp, 3, 1 << 70), changed(hotp, 5, 1 << 64), changed(hotp, 5, -1),
                   changed(totp, 1, 1 << 70), changed(totp, 4, 10 ** 30), changed(totp, 1, 5), changed(totp, 4, 20)):
        with pytest.raises(ManagerError) as err:
            o.add_record(broken)
        assert err.value.zh
    for kw in ({"digits": 1 << 70}, {"type": "hotp", "counter": 1 << 64}, {"type": "hotp", "counter": -1},
               {"period": 10 ** 30}, {"period": 0}):
        with pytest.raises(ManagerError):
            o.add("I", "x", RFC4226_SECRET, **kw)
    assert o.list() == before


def test_one_transaction_per_operation_and_management_after(mgmt):
    """Every operation leaves the management applet selected."""
    o = OathManager(mgmt)
    o.add("M", "x", RFC4226_SECRET)
    o.set_password("pw")
    assert mgmt.info()["boot_status"] == "ok"
    o.list()
    assert mgmt.info()["boot_status"] == "ok"
