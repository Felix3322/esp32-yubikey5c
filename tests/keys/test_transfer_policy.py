"""What the single-key transfer (docs/KEY_TRANSFER.md) lets a host see and
take, on emulated devices.

KEY_LIST never reveals more than the application itself does with the same
credentials: FIDO lists its passkeys as credential management does (with a
verified FIDO PIN), or else after a touch what a getAssertion with user
presence alone gives (credProtect 1 passkeys, RP and user ID, no names);
OATH its accounts only after a touch while an OATH password or OTP PIN is
set. The pages after the first follow with the list session ID the first
answered, no touch or PIN again: forward only, for a few seconds.
OTP, OpenPGP and PIV list metadata their applets give any host. Exports and
imports follow the device policies: the export policy of the profile and
the build, the FIDO PIN as for EXPORT_BEGIN, a physical touch (never
automatic presence).

    bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/keys/test_transfer_policy.py
    LF_EMU_BIN_HARDENED=~/work/build-<name>-hard/pico_fido2 ...   # the HARDENED case too
"""

import hashlib
import os
import struct
import threading
import time

import pytest
from fido2 import cbor

from harness.card import YkConnection
from harness.emulator import Button
from librefido import policy, provision
from librefido.mgmt import (APPS, INS_EXPORT_BEGIN, INS_EXPORT_READ, INS_FW_BEGIN, INS_FW_WRITE, INS_IMPORT_BEGIN,
                            INS_IMPORT_WRITE, INS_INFO, INS_KEY_EXPORT, INS_KEY_IMPORT, INS_KEY_LIST)

from test_app_transfer import ATTR, CRT, PW3, OPENPGP_AID, Mgmt, Session, pgp, power, yoath, yotp, ypiv
from test_fido_transfer import synthetic
from test_mgmt_security import session_id, sw_of
from test_profiles_backup import emulators, pcscd, pin_retries, set_pin, wait_reboot  # noqa: F401  (fixtures)

HARDENED = os.environ.get("LF_EMU_BIN_HARDENED")
# the manual button, and a short wait for it
MANUAL = {"LF_EMU_UP": "manual", "LF_EMU_UP_TIMEOUT_MS": "1000"}
PIN = "271828"
FIDO, OATH, OTP, OPENPGP, PIV = range(5)


def key_list(m, app, pin=None, cursor=None, sid=None):
    """One KEY_LIST page as sent (list_keys pages by itself)."""
    req = {1: app}
    if pin is not None:
        req[2] = pin.encode()
    if cursor is not None:
        req[3] = cursor
    if sid is not None:
        req[4] = sid
    # (the host library's decoder: the entries are an indefinite-length array)
    return m._map(m._cmd(INS_KEY_LIST, data=cbor.encode(req), what="key list"), "key list")


def key_export(m, app, key_id, pin=None):
    req = {1: app, 2: key_id}
    if pin is not None:
        req[3] = pin.encode()
    return m._map(m._cmd(INS_KEY_EXPORT, data=cbor.encode(req), what="key export"), "key export")


def pressing(fn, delay=0.3):
    """fn() with one press of the button (LF_EMU_UP=manual) after delay."""
    def press():
        time.sleep(delay)
        b = Button()
        b.press()
        b.close()
    t = threading.Thread(target=press)
    t.start()
    try:
        return fn()
    finally:
        t.join()


def no_touch(fn):
    """fn() is refused with 6985 once the device waited for a touch."""
    t = time.time()
    assert sw_of(fn) == 0x6985
    assert time.time() - t >= 0.9


def otp_record(slot=1):
    """An OTP record (challenge-response HMAC-SHA1) as KEY_EXPORT gives it."""
    cfg = yotp.HmacSha1SlotConfiguration(os.urandom(20)).get_config(None)
    return {1: slot, 2: cfg, 3: bytes(8), 4: "chal-hmac"}


def refuses_exports(m):
    """No key of any application leaves the device; KEY_LIST says so."""
    for app in range(len(APPS)):
        assert sw_of(lambda: key_export(m, app, b"\x01")) == 0x6986, APPS[app]
    assert m.list_keys("otp", no_pin=True)[1] is False


# -- KEY_LIST ------------------------------------------------------------------------

def test_fido_list_needs_the_pin_or_a_touch(pcscd, emulators):
    a = emulators("a")
    # long texts and user IDs: listings of several pages; credProtect 1
    # (4 in 5), 2 and 3
    recs = [synthetic(rp="rp%02d.%s.example" % (i, "x" * 100), user=b"user-%02d-" % i + bytes(52),
                      extra={4: "u%02d-%s" % (i, "n" * 56), 5: "User %02d %s" % (i, "d" * 54),
                             9: 1 if i % 5 else 2 + i // 5 % 2})
            for i in range(40)]
    power(emulators, a)
    with Mgmt() as m:
        for rec in recs:
            assert m.import_key("fido", rec, no_pin=True) == rec[2]
    power(emulators, a, **MANUAL)
    with Mgmt() as m:
        # No PIN set: no RP or user without a touch, as CTAP gives none out
        # without user presence.
        no_touch(lambda: key_list(m, FIDO))
        no_touch(lambda: m.list_keys("fido", no_pin=True))
        # One touch lists every page, each credential once: what a
        # getAssertion with user presence alone gives. credProtect 2 and 3
        # passkeys need user verification (or the credential ID) there, and
        # user names are only answered with user verification.
        entries, exportable = pressing(lambda: m.list_keys("fido", no_pin=True))
        ids = [e[1] for e in entries]
        assert exportable and len(ids) == 32
        assert {e[1]: (e[2], e[6]) for e in entries} == {r[2]: (r[1], r[3]) for r in recs if r[9] == 1}
        assert not any(4 in e or 5 in e for e in entries)

        # the pages after the first: the list session ID, no touch
        first = pressing(lambda: key_list(m, FIDO))
        assert 0 < len(first[1]) < 32 and len(first[4]) == 8
        seen, page, pages = [e[1] for e in first[1]], first, 1
        while 3 in page:
            page = key_list(m, FIDO, cursor=page[3], sid=first[4])
            assert page.get(4, first[4]) == first[4]
            seen += [e[1] for e in page[1]]
            pages += 1
        assert sorted(seen) == sorted(ids) and 4 not in page and pages >= 3
        # complete: the listing is over
        assert sw_of(lambda: key_list(m, FIDO, cursor=first[3], sid=first[4])) == 0x6982

        # a wrong ID ends the listing
        first = pressing(lambda: key_list(m, FIDO))
        assert sw_of(lambda: key_list(m, FIDO, cursor=first[3], sid=bytes(8))) == 0x6982
        assert sw_of(lambda: key_list(m, FIDO, cursor=first[3], sid=first[4])) == 0x6982
        # a later page without the ID: refused, and the listing is over
        first = pressing(lambda: key_list(m, FIDO))
        assert sw_of(lambda: key_list(m, FIDO, cursor=first[3])) == 0x6982
        assert sw_of(lambda: key_list(m, FIDO, cursor=first[3], sid=first[4])) == 0x6982
        # the ID of the FIDO listing does not page another application
        first = pressing(lambda: key_list(m, FIDO))
        assert sw_of(lambda: key_list(m, OTP, cursor=first[3], sid=first[4])) == 0x6982
        # another management command in between ends it
        first = pressing(lambda: key_list(m, FIDO))
        m._cmd(INS_INFO)
        assert sw_of(lambda: key_list(m, FIDO, cursor=first[3], sid=first[4])) == 0x6982
        # an ID only continues a listing
        assert sw_of(lambda: key_list(m, FIDO, cursor=0, sid=first[4])) == 0x6A80

        # KEY_EXPORT without a PIN set: the touch alone
        no_touch(lambda: key_export(m, FIDO, ids[0]))
        assert pressing(lambda: key_export(m, FIDO, ids[0]))[2][2] == ids[0]

    set_pin(PIN)
    with Mgmt() as m:
        # With the PIN (what credential management needs): no touch, every
        # passkey with its names, on the pages after the first too (the host
        # library follows the list session ID).
        entries, _ = m.list_keys("fido", pin=PIN)
        assert {e[1]: (e[2], e[6], e[4], e[5]) for e in entries} == {r[2]: (r[1], r[3], r[4], r[5]) for r in recs}
        first = key_list(m, FIDO, pin=PIN)
        assert 3 in first and len(first[4]) == 8
        second = key_list(m, FIDO, cursor=first[3], sid=first[4])
        # such a listing may also be paged without the ID, with the PIN
        assert key_list(m, FIDO, pin=PIN, cursor=first[3])[1] == second[1]
        # the PIN missing: 6982 without using a retry; a wrong one: 63Cx
        assert sw_of(lambda: key_list(m, FIDO)) == 0x6982
        assert sw_of(lambda: key_list(m, FIDO, cursor=first[3])) == 0x6982
        assert pin_retries() == 8
        assert sw_of(lambda: key_list(m, FIDO, pin="000000")) == 0x63C7
        assert key_list(m, FIDO, pin=PIN)[1] == first[1] and pin_retries() == 8

        # KEY_EXPORT asks for the PIN exactly like EXPORT_BEGIN, then a touch
        assert sw_of(lambda: key_export(m, FIDO, ids[0])) == 0x6982
        assert sw_of(lambda: m._cmd(INS_EXPORT_BEGIN)) == 0x6982
        assert pin_retries() == 8
        assert sw_of(lambda: key_export(m, FIDO, ids[0], pin="000000")) == 0x63C7
        assert sw_of(lambda: m._cmd(INS_EXPORT_BEGIN, data=b"000000")) == 0x63C6
        no_touch(lambda: key_export(m, FIDO, ids[0], pin=PIN))
        assert pin_retries() == 8
        assert pressing(lambda: key_export(m, FIDO, ids[0], pin=PIN))[2][2] == ids[0]


def test_list_session_is_one_pass_soon_after_the_touch(pcscd, emulators):
    """The list session a touch opened gives each page once, in order, for
    KEY_LIST_SESSION_MS (10 s): it cannot be rewound, skipped ahead or kept
    to watch the passkeys made later."""
    a = emulators("a")
    recs = [synthetic(rp="rp%02d.%s.example" % (i, "x" * 100), user=b"user-%02d-" % i + bytes(52))
            for i in range(30)]
    power(emulators, a)
    with Mgmt() as m:
        for rec in recs:
            assert m.import_key("fido", rec, no_pin=True) == rec[2]
    power(emulators, a, **MANUAL)
    with Mgmt() as m:
        # a page again ends the listing (three pages: the second is not the last)
        first = pressing(lambda: key_list(m, FIDO))
        second = key_list(m, FIDO, cursor=first[3], sid=first[4])
        assert 3 in second
        assert sw_of(lambda: key_list(m, FIDO, cursor=first[3], sid=first[4])) == 0x6982
        assert sw_of(lambda: key_list(m, FIDO, cursor=second[3], sid=first[4])) == 0x6982
        # a rewind, a page skipped
        for cursor in (1, first[3] - 1, first[3] + 1, second[3]):
            first = pressing(lambda: key_list(m, FIDO))
            assert sw_of(lambda: key_list(m, FIDO, cursor=cursor, sid=first[4])) == 0x6982, cursor
            assert sw_of(lambda: key_list(m, FIDO, cursor=first[3], sid=first[4])) == 0x6982, cursor
        # a late page: over (it could show passkeys made after the touch)
        first = pressing(lambda: key_list(m, FIDO))
        time.sleep(10.5)
        assert sw_of(lambda: key_list(m, FIDO, cursor=first[3], sid=first[4])) == 0x6982
        # in time, in order: every page
        first = pressing(lambda: key_list(m, FIDO))
        seen, page = [e[1] for e in first[1]], first
        while 3 in page:
            time.sleep(1)
            page = key_list(m, FIDO, cursor=page[3], sid=first[4])
            seen += [e[1] for e in page[1]]
        assert sorted(seen) == sorted(r[2] for r in recs)


def test_oath_list_needs_a_touch_while_it_has_a_secret(pcscd, emulators):
    from yubikit.core.smartcard import ApduError as YkApduError
    a = emulators("a")
    power(emulators, a, **MANUAL)
    with Session() as card:
        s = yoath.OathSession(YkConnection(card))
        s.put_credential(yoath.CredentialData("alice", yoath.OATH_TYPE.TOTP, yoath.HASH_ALGORITHM.SHA1,
                                              os.urandom(20)))
        key = s.derive_key("oath password")
    with Mgmt() as m:
        assert [e[1] for e in m.list_keys("oath", no_pin=True)[0]] == [b"alice"]     # no secret: no touch

    for secret in ("password", "OTP PIN"):
        with Session() as card:
            s = yoath.OathSession(YkConnection(card))
            if secret == "password":
                s.set_key(key)
            else:
                s.validate(key)
                s.unset_key()
                # the OTP PIN of the Nitrokey extension: SET PIN, tag 80
                assert card.transmit(0x00, 0xB4, 0, 0, b"\x80\x04" + b"1234", check=False)[1] == 0x9000
        with Session() as card:
            # what YKOATH LIST answers without it
            with pytest.raises(YkApduError) as err:
                yoath.OathSession(YkConnection(card)).list_credentials()
            assert err.value.sw == 0x6982, secret
        with Mgmt() as m:
            no_touch(lambda: m.list_keys("oath", no_pin=True))
            assert [e[1] for e in pressing(lambda: m.list_keys("oath", no_pin=True))[0]] == [b"alice"]

    # the FIDO PIN does not stand in for the OATH secrets
    set_pin(PIN)
    with Mgmt() as m:
        no_touch(lambda: m.list_keys("oath", pin=PIN))
        assert [e[1] for e in pressing(lambda: m.list_keys("oath", pin=PIN))[0]] == [b"alice"]


def test_metadata_listings_need_no_touch(pcscd, emulators):
    """OTP (slot status), OpenPGP (GET DATA) and PIV (GET METADATA) list what
    their applets answer any host: no touch, with the button never pressed."""
    a = emulators("a")
    power(emulators, a)
    with Session() as card:
        yotp.YubiOtpSession(YkConnection(card)).put_configuration(
            yotp.SLOT.TWO, yotp.HmacSha1SlotConfiguration(os.urandom(20)), acc_code=b"code!!")
        card.select(OPENPGP_AID)
        pgp(card, 0x20, 0x00, 0x83, PW3)
        pgp(card, 0xDA, 0x00, 0xC1, ATTR["p256-ecdsa"])
        pgp(card, 0x47, 0x80, 0x00, CRT[1])
        s = ypiv.PivSession(YkConnection(card))
        s.authenticate(ypiv.DEFAULT_MANAGEMENT_KEY)
        s.generate_key(ypiv.SLOT.AUTHENTICATION, ypiv.KEY_TYPE.ECCP256, ypiv.PIN_POLICY.ONCE, ypiv.TOUCH_POLICY.NEVER)
    power(emulators, a, **MANUAL)
    with Mgmt() as m:
        assert m.list_keys("otp", no_pin=True)[0] == [{1: b"\x02", 2: "chal-hmac", 3: True}]
        assert [e[1] for e in m.list_keys("openpgp", no_pin=True)[0]] == [b"\x01"]
        assert [(e[1], e[2]) for e in m.list_keys("piv", no_pin=True)[0]] == [(b"\x9a", 0x11)]
        # such a listing answers no list session ID when it is complete
        assert 4 not in key_list(m, OTP) and 4 not in key_list(m, PIV)


# -- device policies -------------------------------------------------------------------

def test_no_export_and_secure_profiles(pcscd, emulators, tmp_path):
    a = emulators("a")
    power(emulators, a)
    with Mgmt() as m:
        assert m.import_key("otp", otp_record(), no_pin=True) == b"\x01"
        # a no-export profile: no key leaves it; imports go on
        m.set_profile(0, no_export=True)
        refuses_exports(m)
        rec = synthetic()
        assert m.import_key("fido", rec, no_pin=True) == rec[2]
        # a secure profile: no export, no FIDO import, OTP imports as on a YubiKey
        provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path))
        m.create_secure_profile(1)
        wait_reboot(m)
        m.select_profile(1)
        wait_reboot(m)
        assert m.info()["active"] == 1
        refuses_exports(m)
        assert sw_of(lambda: m.import_key("fido", synthetic(), no_pin=True)) == 0x6986
        assert m.import_key("otp", otp_record(2), no_pin=True) == b"\x02"
        assert m.list_keys("otp", no_pin=True) == ([{1: b"\x02", 2: "chal-hmac", 3: False}], False)
        assert m.list_keys("fido", no_pin=True) == ([], False)


@pytest.mark.skipif(not HARDENED or not os.path.exists(HARDENED), reason="LF_EMU_BIN_HARDENED not built")
def test_hardened_build(pcscd, emulators, tmp_path):
    from test_hardened import provisioned
    e, m = provisioned(emulators, tmp_path)
    try:
        assert m.import_key("otp", otp_record(), no_pin=True) == b"\x01"
        refuses_exports(m)
        assert sw_of(lambda: m.import_key("fido", synthetic(), no_pin=True)) == 0x6986
        assert m.list_keys("otp", no_pin=True)[0] == [{1: b"\x01", 2: "chal-hmac", 3: False}]
    finally:
        m.close()


def test_touch_is_never_automatic(pcscd, emulators):
    """Every automatic presence bit set: an export, an import and a listing
    that needs a touch still wait for the button."""
    a = emulators("a")
    power(emulators, a)
    with Mgmt() as m:
        assert m.import_key("otp", otp_record(), no_pin=True) == b"\x01"
        m.set_presence(0, **{app: True for app in policy.APPS})
        assert set(m.info()["profiles"][0]["auto_presence"]) == set(policy.APPS)
    power(emulators, a, **MANUAL)
    with Mgmt() as m:
        no_touch(lambda: key_export(m, OTP, b"\x01"))
        no_touch(lambda: m.import_key("otp", otp_record(2), no_pin=True))
        no_touch(lambda: key_list(m, FIDO))
        assert m.list_keys("otp", no_pin=True)[0] == [{1: b"\x01", 2: "chal-hmac", 3: False}]


def test_key_commands_end_transfers(pcscd, emulators):
    a = emulators("a")
    power(emulators, a)
    with Mgmt() as m:
        export_id = cbor.decode(m._cmd(INS_EXPORT_BEGIN))[3]
        m._cmd(INS_EXPORT_READ, data=struct.pack(">I", 0) + export_id)
        key_list(m, OTP)
        assert sw_of(lambda: m._cmd(INS_EXPORT_READ, data=struct.pack(">I", 0) + export_id)) == 0x6985

        stream = m.export_profile()
        sid = session_id(m._cmd(INS_IMPORT_BEGIN, 1, 0))
        m._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", 0) + sid + stream[:512])
        assert sw_of(lambda: key_export(m, OTP, b"\x01")) == 0x6A88                # no such key
        assert sw_of(lambda: m._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", 512) + sid + stream[512:600])) \
            == 0x6985

        with open(a.binary, "rb") as f:
            img = f.read(4096)
        sid = session_id(m._cmd(INS_FW_BEGIN, data=cbor.encode({1: len(img), 2: hashlib.sha256(img).digest()})))
        m._cmd(INS_FW_WRITE, data=struct.pack(">I", 0) + sid + img[:1024])
        assert sw_of(lambda: m._cmd(INS_KEY_IMPORT, data=cbor.encode({1: FIDO, 2: {}}))) == 0x6A80
        assert sw_of(lambda: m._cmd(INS_FW_WRITE, data=struct.pack(">I", 1024) + sid + img[1024:2048])) == 0x6985


def test_malformed_key_commands(pcscd, emulators):
    a = emulators("a")
    power(emulators, a)
    with Mgmt() as m:
        bad = [
            (INS_KEY_LIST, cbor.encode({1: 5})),                           # unknown application
            (INS_KEY_LIST, cbor.encode({1: 0xFFFFFFFF})),
            (INS_KEY_LIST, cbor.encode({2: b""})),                         # no application
            (INS_KEY_LIST, cbor.encode([0])),                              # not a map
            (INS_KEY_LIST, cbor.encode({1: 0}) + b"\x00"),                 # trailing bytes
            (INS_KEY_LIST, b"\xa1\x01"),                                   # cut short
            (INS_KEY_LIST, b""),
            (INS_KEY_LIST, cbor.encode({1: 0, 9: 0})),                     # unknown key
            (INS_KEY_LIST, b"\xa2\x01\x02\x01\x02"),                       # a key twice
            (INS_KEY_LIST, cbor.encode({1: 0, 2: b"1" * 65})),             # PIN too long
            (INS_KEY_LIST, cbor.encode({1: 0, 2: "1234"})),                # PIN as text
            (INS_KEY_LIST, cbor.encode({1: 2, 3: 1, 4: bytes(9)})),        # list session ID of 9 bytes
            (INS_KEY_LIST, cbor.encode({1: 2, 3: 1, 4: bytes(7)})),
            (INS_KEY_LIST, cbor.encode({1: 2, 3: 0xFFFFFFFF})),            # no page starts there
            (INS_KEY_LIST, cbor.encode({1: 2, 3: -1})),
            (INS_KEY_EXPORT, cbor.encode({1: 2})),                         # no key ID
            (INS_KEY_EXPORT, cbor.encode({1: 2, 2: bytes(65)})),           # key ID too long
            (INS_KEY_EXPORT, cbor.encode({1: 2, 2: b""})),
            (INS_KEY_EXPORT, cbor.encode({1: 3, 2: b"\x01", 4: bytes(128)})),  # secret too long
            (INS_KEY_EXPORT, cbor.encode({1: 7, 2: b"\x01"})),
            (INS_KEY_IMPORT, cbor.encode({1: 2})),                         # no record
            (INS_KEY_IMPORT, cbor.encode({1: 2, 2: [1]})),                 # record not a map
            (INS_KEY_IMPORT, cbor.encode({1: 2, 2: {}, 6: bytes(65)})),    # target too long
            (INS_KEY_IMPORT, cbor.encode({1: 2, 2: {}, 5: 1})),            # replace not a bool
            (INS_KEY_IMPORT, cbor.encode({1: 9, 2: {}})),
            (INS_KEY_IMPORT, b"\xff" * 300),
        ]
        for ins, data in bad:
            assert sw_of(lambda: m._cmd(ins, data=data)) == 0x6A80, (hex(ins), data.hex())
        # still answering; INFO key 19: the applications that export / import
        assert m.list_keys("otp", no_pin=True)[0] == []
        assert cbor.decode(m._cmd(INS_INFO))[19] == {1: 0x1F, 2: 0x05}
        assert m.key_transfer() == {"export": set(APPS), "import": {"fido", "otp"}}
