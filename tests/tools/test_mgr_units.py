"""Offline unit tests of the key manager's pure parts (librefido.mgr_common,
mgr_fido, mgr_oath): errors, the CTAP over CCID adapter on a simulated card,
the OATH key derivation, codes and names. No emulator.

    PYTHONPATH=tools/librefido python -m pytest -q tests/tools/test_mgr_units.py
"""

import base64
import hashlib
from contextlib import contextmanager

import pytest

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2
from fido2.hid import CTAPHID

from librefido.mgmt import FIDO_AID
from librefido.mgr_common import (AuthRequired, CcidCtapDevice, CtapTransportError, ManagerError, NotSupported,
                                  SecretBlocked, WrongSecret, error_text, sw_error, sw_text, wipe)
from librefido.mgr_fido import FidoManager, FidoPinNotSet, FidoPinRequired, ctap_error
from librefido import mgr_oath
from librefido.mgr_oath import (build_name, derive_key, device_id, format_code, hotp, parse_name, secret_from_base32,
                                totp, totp_window)
from librefido.pcsc import MGMT_AID, ApduError


# ----------------------------------------------------------------------------
# A simulated card
# ----------------------------------------------------------------------------

class FakeCard:
    """pcsc.Card as the managers use it: transaction(), select(), transmit().
    answers: (data, sw) for each transmit, in order."""

    def __init__(self, answers=(), missing=()):
        self.answers = list(answers)
        self.missing = {bytes(a) for a in missing}
        self.log = []
        self.depth = 0

    @contextmanager
    def transaction(self, aid=None):
        self.depth += 1
        self.log.append("begin")
        try:
            if aid is not None:
                self.select(aid)
            yield self
        finally:
            self.depth -= 1
            self.log.append("end")

    def select(self, aid):
        self.log.append(("select", bytes(aid), self.depth))
        if bytes(aid) in self.missing:
            raise ApduError(0x6A82)
        return b"", 0x9000

    def transmit(self, cla, ins, p1, p2, data=b"", le=0, check=True, what=""):
        self.log.append(("apdu", cla, ins, p1, p2, bytes(data), self.depth))
        return self.answers.pop(0)


def info_answer(**options):
    """getInfo of a simulated authenticator (with the fields python-fido2 1.1
    requires as well: versions, extensions, aaguid)."""
    opts = {"rk": True, "clientPin": False, "credMgmt": True, "pinUvAuthToken": True}
    opts.update(options)
    return b"\x00" + cbor.encode({1: ["FIDO_2_0", "FIDO_2_1"], 2: ["credProtect"], 3: bytes(range(16)), 4: opts,
                                  6: [2, 1]}), 0x9000


# ----------------------------------------------------------------------------
# mgr_common
# ----------------------------------------------------------------------------

def test_errors_carry_both_languages_and_the_status_word():
    e = ManagerError("broken", 0x6A80, "坏了")
    assert str(e) == "broken" and e.sw == 0x6A80 and e.text() == "broken" and e.text(zh=True) == "坏了"
    assert ManagerError("only English").text(zh=True) == "only English"
    assert error_text(e, True) == "坏了" and error_text(ValueError("x"), True) == "x"
    w = sw_error("verify", 0x63C2, "验证")
    assert isinstance(w, WrongSecret) and w.retries == 2 and "2 tries left" in str(w) and "还剩 2 次" in w.text(True)
    assert isinstance(sw_error("verify", 0x6983), SecretBlocked)
    assert isinstance(sw_error("x", 0x6A81), NotSupported) and isinstance(sw_error("x", 0x6D00), NotSupported)
    plain = sw_error("delete", 0x6A88, "删除", {0x6A88: ("no such key", "没有该密钥")})
    assert type(plain) is ManagerError and str(plain) == "delete: no such key (SW 6A88)"
    assert plain.text(True) == "删除：没有该密钥（SW 6A88）"
    assert "SW 1234" in str(sw_error("odd", 0x1234)) and sw_text(0x1234) == "error"
    assert issubclass(FidoPinRequired, AuthRequired) and issubclass(mgr_oath.OathPasswordRequired, AuthRequired)


def test_wipe():
    b = bytearray(b"secret")
    wipe(b)
    assert b == bytearray(6)
    wipe(None)          # nothing to do


def test_ccid_ctap_command_selects_and_restores():
    card = FakeCard([(b"\x00\xa1\x01\x02", 0x9000)])
    dev = CcidCtapDevice(card)
    assert dev.call(CTAPHID.CBOR, b"\x06\xa0") == b"\x00\xa1\x01\x02"
    assert card.log == ["begin", ("select", FIDO_AID, 1), ("apdu", 0x80, 0x10, 0, 0, b"\x06\xa0", 1),
                        ("select", MGMT_AID, 1), "end"]


def test_ccid_ctap_status_words():
    # SW 64xx: the CTAP status in xx, as python-fido2 expects it (first byte)
    card = FakeCard([info_answer(clientPin=True), (b"", 0x6431)])
    ctap = Ctap2(CcidCtapDevice(card))
    assert ctap.info.options["clientPin"] is True
    with pytest.raises(CtapError) as e:
        ctap.client_pin(2, ClientPin.CMD.GET_PIN_RETRIES)
    assert e.value.code == CtapError.ERR.PIN_INVALID
    # any other status word: CtapTransportError with the word
    card = FakeCard([(b"", 0x6985)])
    with pytest.raises(CtapTransportError) as e:
        CcidCtapDevice(card).call(CTAPHID.CBOR, b"\x04")
    assert e.value.sw == 0x6985 and e.value.code == CtapError.ERR.OTHER
    with pytest.raises(CtapError):
        CcidCtapDevice(FakeCard()).call(CTAPHID.INIT, b"")


def test_ccid_ctap_u2f_passthrough():
    card = FakeCard([(b"resp", 0x9000), (b"", 0x6985)])
    dev = CcidCtapDevice(card)
    extended = bytes([0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02]) + b"ab" + b"\x00\x00"
    assert dev.call(CTAPHID.MSG, extended) == b"resp\x90\x00"
    assert card.log[2] == ("apdu", 0x00, 0x01, 0x03, 0x00, b"ab", 1)
    short = bytes([0x00, 0x02, 0x07, 0x00, 0x01]) + b"z" + b"\x00"
    assert dev.call(CTAPHID.MSG, short) == b"\x69\x85"
    assert card.log[-3] == ("apdu", 0x00, 0x02, 0x07, 0x00, b"z", 1)


def test_ccid_ctap_without_fido_application():
    card = FakeCard(missing=[FIDO_AID])
    with pytest.raises(NotSupported) as e:
        CcidCtapDevice(card).call(CTAPHID.CBOR, b"\x04")
    assert e.value.sw == 0x6A82 and e.value.zh
    assert card.log[-2] == ("select", MGMT_AID, 1)        # the management applet selected again


def test_ccid_ctap_management_not_selected_again():
    # the command went through: said so, not taken for a failure of the command
    card = FakeCard([(b"\x00", 0x9000)], missing=[MGMT_AID])
    with pytest.raises(ManagerError) as e:
        CcidCtapDevice(card).call(CTAPHID.CBOR, b"\x04")
    assert "was sent" in str(e.value) and e.value.zh
    # a failing command is reported as itself
    class Broken(FakeCard):
        def transmit(self, *a, **kw):
            raise OSError("reader gone")
    with pytest.raises(OSError):
        CcidCtapDevice(Broken(missing=[MGMT_AID])).call(CTAPHID.CBOR, b"\x04")


def test_ccid_ctap_follows_the_managements_card():
    class M:
        card = FakeCard([(b"\x00", 0x9000)])
    m = M()
    dev = CcidCtapDevice(m)
    dev.call(CTAPHID.CBOR, b"\x04")
    m.card = FakeCard([(b"\x00", 0x9000)])                 # Management.reconnect() replaces its card
    dev.call(CTAPHID.CBOR, b"\x04")
    assert m.card.log and dev.card is m.card


# ----------------------------------------------------------------------------
# mgr_fido
# ----------------------------------------------------------------------------

def test_ctap_errors():
    assert isinstance(ctap_error("x", "x", CtapError(CtapError.ERR.PIN_BLOCKED)), SecretBlocked)
    blocked = ctap_error("unlock", "解锁", CtapError(CtapError.ERR.PIN_AUTH_BLOCKED))
    assert isinstance(blocked, SecretBlocked) and "unplug" in str(blocked) and "拔出" in blocked.text(True)
    assert isinstance(ctap_error("x", "x", CtapError(CtapError.ERR.INVALID_SUBCOMMAND)), NotSupported)
    t = ctap_error("list", "列出", CtapTransportError(0x6985))
    assert t.sw == 0x6985 and "SW 6985" in str(t)
    odd = ctap_error("x", "x", CtapError(0xF5))
    assert type(odd) is ManagerError and "CTAP" in str(odd)


class FakeManagement:
    def __init__(self, answers):
        self.card = FakeCard(answers)


def test_fido_operations_need_a_token_or_a_pin():
    f = FidoManager(FakeManagement([info_answer(clientPin=True)]))
    with pytest.raises(FidoPinRequired) as e:
        f.list_credentials()
    assert e.value.zh
    f = FidoManager(FakeManagement([info_answer(clientPin=False)]))
    with pytest.raises(FidoPinNotSet):
        f.delete_credential(b"id")
    f = FidoManager(FakeManagement([info_answer(clientPin=True, credMgmt=False)]))
    with pytest.raises(NotSupported):
        f.metadata()


def test_fido_pins_that_cannot_be_right_are_not_sent():
    m = FakeManagement([])
    f = FidoManager(m)
    for pin in ("123", "x" * 64, "é" * 32, None):     # too short, 64 bytes, 64 bytes of UTF-8, none
        with pytest.raises(WrongSecret):
            f.unlock(pin)
        with pytest.raises(WrongSecret):
            f.change_pin(pin, "123456")
    assert m.card.log == []
    m = FakeManagement([info_answer()])
    with pytest.raises(ManagerError) as e:
        FidoManager(m).set_pin("abc")                   # checked before anything is sent but getInfo
    assert "at least 4" in str(e.value) and [x for x in m.card.log if x[0] == "apdu"] == [
        ("apdu", 0x80, 0x10, 0, 0, b"\x04", 2)]


# ----------------------------------------------------------------------------
# mgr_oath
# ----------------------------------------------------------------------------

RFC6238 = {"SHA1": b"12345678901234567890", "SHA256": b"12345678901234567890123456789012",
           "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234"}
RFC6238_CODES = {59: ("94287082", "46119246", "90693936"), 1111111109: ("07081804", "68084774", "25091201"),
                 1111111111: ("14050471", "67062674", "99943326"), 1234567890: ("89005924", "91819424", "93441116"),
                 2000000000: ("69279037", "90698825", "38618901"), 20000000000: ("65353130", "77737706", "47863826")}


def test_rfc_vectors():
    s = RFC6238["SHA1"]
    assert [hotp(s, c) for c in range(10)] == ["755224", "287082", "359152", "969429", "338314", "254676", "287922",
                                               "162583", "399871", "520489"]
    for t, codes in RFC6238_CODES.items():
        for alg, want in zip(("SHA1", "SHA256", "SHA512"), codes):
            assert totp(RFC6238[alg], t, digits=8, algorithm=alg) == want
            assert totp(RFC6238[alg], t, digits=6, algorithm=alg.lower()) == want[2:]


def test_codes_and_windows():
    assert format_code(123, 6) == "000123" and format_code(0x80000000 + 7, 8) == "00000007"
    assert totp_window(30, 59) == (30, 60) and totp_window(60, 60) == (60, 120)


def test_key_derivation_and_device_id():
    salt = bytes.fromhex("0102030405060708")
    assert derive_key("pw", salt) == hashlib.pbkdf2_hmac("sha1", b"pw", salt, 1000, 16)
    assert derive_key("pässwörd", salt) == derive_key("pässwörd".encode("utf-8"), salt)
    assert device_id(salt) == base64.b64encode(hashlib.sha256(salt).digest()[:16]).decode().rstrip("=")
    oath = pytest.importorskip("yubikit.oath")      # the reference YKOATH client (tests only)
    assert derive_key("correct horse", salt) == oath._derive_key(salt, "correct horse")
    assert device_id(salt) == oath._get_device_id(salt)


def test_names():
    T, H = mgr_oath.TOTP, mgr_oath.HOTP
    assert build_name("ACME", "joe") == b"ACME:joe"
    assert build_name("  ", " joe ") == b"joe"
    assert build_name("ACME", "joe", T, 60) == b"60/ACME:joe"
    assert build_name("ACME", "joe", H, 60) == b"ACME:joe"               # HOTP has no period
    assert parse_name(b"60/ACME:joe", T) == ("ACME", "joe", 60)
    assert parse_name(b"60/ACME:joe", H) == ("60/ACME", "joe", None)
    assert parse_name(b"joe", T) == (None, "joe", 30)
    assert parse_name("日本:山田".encode(), T) == ("日本", "山田", 30)
    for issuer, account, period in (("A", "", 30), ("a:b", "c", 30), ("A", "b", 0), ("A", "b", 1.5),
                                    ("I" * 40, "a" * 30, 30), (None, "a:b", 30), ("", "a:b", 60)):
        with pytest.raises(ManagerError) as e:
            build_name(issuer, account, T, period)
        assert e.value.zh
    with pytest.raises(ManagerError):
        build_name(None, "a:b", H)                                       # would read back as issuer "a"
    assert build_name("A", "b:c", T) == b"A:b:c" and parse_name(b"A:b:c", T) == ("A", "b:c", 30)


def test_names_that_look_like_a_period():
    """A TOTP name starting with "<digits>/" reads back with that number as
    its period (YKOATH): build_name writes the default period out, and a name
    with period 0 (stored so by another tool) is read as a 30 s account
    instead of making every code calculation divide by zero."""
    T, H = mgr_oath.TOTP, mgr_oath.HOTP
    for issuer, account, raw in ((None, "0/work", b"30/0/work"), ("", "12/alice", b"30/12/alice"),
                                 ("12/x", "a", b"30/12/x:a"), (None, "007/bond", b"30/007/bond"),
                                 ("Site", "12/alice", b"Site:12/alice")):
        assert build_name(issuer, account, T) == raw, (issuer, account)
        assert parse_name(raw, T) == ((issuer or None), account, 30), raw
    assert build_name(None, "12/alice", T, 60) == b"60/12/alice"
    assert parse_name(b"60/12/alice", T) == (None, "12/alice", 60)
    assert build_name(None, "12/alice", H) == b"12/alice"             # HOTP names have no period
    assert parse_name(b"12/alice", H) == (None, "12/alice", None)
    for raw, parsed in ((b"0/x", (None, "0/x", 30)), (b"00/a:b", ("00/a", "b", 30)),
                        (b"12/alice", (None, "alice", 12))):
        assert parse_name(raw, T) == parsed, raw
    oath = pytest.importorskip("yubikit.oath")      # the reference YKOATH client (tests only) reads them alike
    for raw in (b"30/0/work", b"30/12/x:a", b"60/12/alice"):
        yk = oath._parse_cred_id(raw, oath.OATH_TYPE.TOTP)
        assert (yk[0], yk[1], yk[2]) == parse_name(raw, T), raw


def test_base32_secrets():
    assert secret_from_base32("GEZD GNBV-gy3tqojq") == b"1234567890"
    assert secret_from_base32("MZXW6===") == b"foo"
    with pytest.raises(ManagerError) as e:
        secret_from_base32("not base32!")
    assert e.value.zh
