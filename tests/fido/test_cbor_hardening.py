"""Malformed and non-canonical CBOR in CTAP2 and management requests.

Canonical CTAP2 CBOR (CTAP 2.1, section 8) has no tags and no indefinite
lengths. tinycbor does not count a tag as an item of its container: a
parser that skips a tagged value stops at the tagged item, reads it as the
next key and then runs past the end of the map (an assertion in
cbor_value_advance(), found by tests/fuzz with seeds 3 and 5: a reboot of
the device, by any host). cbor_parse() now validates every CTAP2 request
once (CborValidateNoTags, no indefinite lengths, well-formed, nesting within
tinycbor's limit) and answers CTAP2_ERR_INVALID_CBOR; the management applet
does the same for its CBOR commands (KEY_*: 6A80, PROFILE_SET, BOARD_SET,
FW_BEGIN: 6700, their answer to any malformed data). After each request the
emulator must still answer.

A HARDENED build on an unprovisioned chip refuses every request but getInfo
before parsing it (its tests here are skipped, test_locked_key_store runs);
test_hardened_provisioned covers a provisioned one (LF_EMU_BIN_HARDENED, as
tests/profiles/test_hardened.py).

    LF_EMU_BIN_HARDENED=~/work/build-<name>-hard/pico_fido2 \
    bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/fido/test_cbor_hardening.py
"""

import os

import pytest
from fido2 import cbor
from fido2.hid import CTAPHID

from harness import ctaphid
from test_profiles_backup import emulators, pcscd  # noqa: F401  (fixtures)

INVALID_CBOR, NO_CREDENTIALS, NOT_ALLOWED = 0x12, 0x2E, 0x30
CTAP_VENDOR_CBOR = 0x41                     # CTAPHID_VENDOR_FIRST + 1
AID_FIDO = bytes.fromhex("A0000006472F0001")
AID_LFMGMT = b"\xF0LIBREFIDO"
INS_INFO, INS_PROFILE_SET, INS_BOARD_SET, INS_FW_BEGIN = 0x01, 0x11, 0x16, 0x40
INS_KEY_LIST, INS_KEY_EXPORT, INS_KEY_IMPORT = 0x60, 0x61, 0x62

# The request the fuzzer crashed the emulator with (getAssertion, hmac-secret
# member 13 with the value 11(0)); ~/work/fuzzcrash/seed5-crash-cbor.hex.
REPRO = bytes.fromhex(
    "02a5016b6578616d706c652e636f6d0258201111111111111111111111111111111111111111111111111111111111111111"
    "0381a26269645850" + "42" * 80 + "64747970656a7075626c69632d6b657904a16b686d61632d736563726574a301a101"
    "020258200000000000000000000000000070d836570cd356df982806708aae29af988d8c0dcb00000000000000000000"
    "00000000000000000000000003500000000000000000000000000000000005a1627570f4")

E = cbor.encode


def cmap(*pairs):
    """A map of already encoded (key, value) pairs, in the given order."""
    return bytes([0xA0 + len(pairs)]) + b"".join(k + v for k, v in pairs)


def carr(*items):
    return bytes([0x80 + len(items)]) + b"".join(items)


def tagged(tag, item):
    return (bytes([0xC0 + tag]) if tag < 24 else b"\xd8" + bytes([tag]) if tag < 256 else
            b"\xd9" + tag.to_bytes(2, "big")) + item


def T(item, tag=11):
    """item (encoded) as a tagged item."""
    return tagged(tag, item)


RP = {"id": "example.com", "name": "Example"}
USER = {"id": b"\x01", "name": "a", "displayName": "A"}
PARAM = {"alg": -7, "type": "public-key"}
CRED = {"id": b"\x42" * 80, "type": "public-key"}
CDH = b"\x00" * 32
COSE = [(E(1), E(2)), (E(3), E(-25)), (E(-1), E(1)), (E(-2), E(b"\x01" * 32)), (E(-3), E(b"\x02" * 32))]


def mc():
    """makeCredential parameters as encoded (key, value) pairs."""
    return [(E(1), E(CDH)), (E(2), E(RP)), (E(3), E(USER)), (E(4), E([PARAM]))]


def ga(rp_id="example.com"):
    return [(E(1), E(rp_id)), (E(2), E(b"\x11" * 32))]


# (name, CTAPHID command, payload): each is answered CTAP2_ERR_INVALID_CBOR.
TAGGED = [
    ("fuzz reproducer", CTAPHID.CBOR, REPRO),
    # around the whole request, the self-describe tag included
    ("mc: tagged request", CTAPHID.CBOR, b"\x01" + T(cmap(*mc()), 24)),
    ("mc: self-describe", CTAPHID.CBOR, b"\x01" + T(cmap(*mc()), 55799)),
    ("ga: tagged request", CTAPHID.CBOR, b"\x02" + T(cmap(*ga()), 0)),
    # top-level keys and values
    ("mc: tagged key", CTAPHID.CBOR, b"\x01" + cmap((T(E(1), 1), E(CDH)), *mc()[1:])),
    ("mc: tagged clientDataHash", CTAPHID.CBOR, b"\x01" + cmap((E(1), T(E(CDH), 2)), *mc()[1:])),
    ("mc: unknown key, tagged value", CTAPHID.CBOR, b"\x01" + cmap(*mc(), (E(16), T(E(0))))),
    ("mc: tagged pinUvAuthProtocol", CTAPHID.CBOR, b"\x01" + cmap(*mc(), (E(8), E(bytes(32))), (E(9), T(E(2), 1)))),
    ("ga: tagged rpId", CTAPHID.CBOR, b"\x02" + cmap((E(1), T(E("example.com"), 32)), (E(2), E(b"\x11" * 32)))),
    # nested maps and arrays: rp, user, pubKeyCredParams, excludeList
    ("mc: rp.id", CTAPHID.CBOR, b"\x01" + cmap((E(1), E(CDH)), (E(2), cmap((E("id"), T(E("example.com"), 32)),
                                                                           (E("name"), E("Example")))),
                                               (E(3), E(USER)), (E(4), E([PARAM])))),
    ("mc: rp unknown member", CTAPHID.CBOR, b"\x01" + cmap((E(1), E(CDH)), (E(2), cmap((E("id"), E("example.com")),
                                                                                       (E("icon"), T(E(0))))),
                                                           (E(3), E(USER)), (E(4), E([PARAM])))),
    ("mc: user key", CTAPHID.CBOR, b"\x01" + cmap((E(1), E(CDH)), (E(2), E(RP)),
                                                  (E(3), cmap((T(E("id"), 0), E(b"\x01")), (E("name"), E("a")))),
                                                  (E(4), E([PARAM])))),
    ("mc: tagged param", CTAPHID.CBOR, b"\x01" + cmap((E(1), E(CDH)), (E(2), E(RP)), (E(3), E(USER)),
                                                      (E(4), carr(T(E(PARAM), 4))))),
    ("mc: param alg", CTAPHID.CBOR, b"\x01" + cmap((E(1), E(CDH)), (E(2), E(RP)), (E(3), E(USER)),
                                                   (E(4), carr(cmap((E("alg"), T(E(-7), 1)),
                                                                    (E("type"), E("public-key"))))))),
    ("mc: excludeList transports", CTAPHID.CBOR, b"\x01" + cmap(*mc(), (E(5), carr(cmap(
        (E("id"), E(b"\x42" * 80)), (E("type"), E("public-key")), (E("transports"), T(E(["usb"])))))))),
    ("ga: allowList unknown member", CTAPHID.CBOR, b"\x02" + cmap(*ga(), (E(3), carr(cmap(
        (E("id"), E(b"\x42" * 80)), (E("type"), E("public-key")), (E("x"), T(E(0)))))))),
    # extensions and options
    ("mc: credProtect", CTAPHID.CBOR, b"\x01" + cmap(*mc(), (E(6), cmap((E("credProtect"), T(E(3), 1)))))),
    ("mc: unknown extension", CTAPHID.CBOR, b"\x01" + cmap(*mc(), (E(6), cmap((E("x-ext"), T(E(0))))))),
    ("mc: option rk", CTAPHID.CBOR, b"\x01" + cmap(*mc(), (E(7), cmap((E("rk"), T(E(True), 1)))))),
    ("ga: hmac-secret salt", CTAPHID.CBOR, b"\x02" + cmap(*ga(), (E(4), cmap((E("hmac-secret"), cmap(
        (E(1), cmap(*COSE)), (E(2), T(E(bytes(32)), 2)), (E(3), E(bytes(16))))))))),
    # COSE keys: clientPIN keyAgreement, getAssertion hmac-secret
    ("clientPIN: COSE unknown member", CTAPHID.CBOR, b"\x06" + cmap(
        (E(1), E(2)), (E(2), E(5)), (E(3), cmap(*COSE, (E(-4), T(E(0))))), (E(6), E(bytes(32))))),
    ("clientPIN: COSE x", CTAPHID.CBOR, b"\x06" + cmap(
        (E(1), E(2)), (E(2), E(5)), (E(3), cmap(*COSE[:3], (E(-2), T(E(b"\x01" * 32), 2)), COSE[4])),
        (E(6), E(bytes(32))))),
    ("ga: hmac-secret COSE", CTAPHID.CBOR, b"\x02" + cmap(*ga(), (E(4), cmap((E("hmac-secret"), cmap(
        (E(1), cmap(*COSE, (E(7), T(E(0))))), (E(2), E(bytes(32))), (E(3), E(bytes(16))))))))),
    # the other commands
    ("clientPIN: getRetries", CTAPHID.CBOR, b"\x06" + cmap((E(1), E(1)), (E(2), T(E(1), 1)))),
    ("credMgmt: subCommandParams", CTAPHID.CBOR, b"\x0a" + cmap(
        (E(1), E(4)), (E(2), cmap((E(1), T(E(bytes(32)), 2)))), (E(3), E(2)), (E(4), E(bytes(32))))),
    ("credMgmt prototype", CTAPHID.CBOR, b"\x41" + cmap((E(1), E(1)), (E(2), T(E({}), 0)))),
    ("config: subCommandParams", CTAPHID.CBOR, b"\x0d" + cmap(
        (E(1), E(3)), (E(2), cmap((E(1), T(E(8), 1)))), (E(3), E(2)), (E(4), E(bytes(32))))),
    ("largeBlobs: offset", CTAPHID.CBOR, b"\x0c" + cmap((E(1), E(32)), (E(3), T(E(0), 1)))),
    ("largeBlobs: set", CTAPHID.CBOR, b"\x0c" + cmap((E(2), T(E(bytes(17)), 24)), (E(3), E(0)), (E(4), E(17)))),
    ("getInfo with a tagged body", CTAPHID.CBOR, b"\x04" + T(E({}), 0)),
    ("vendor: tagged parameter", CTAP_VENDOR_CBOR, b"\x06" + cmap((E(1), T(E(1), 1)))),
    ("vendor: tagged request", CTAP_VENDOR_CBOR, b"\x01" + T(cmap((E(1), E(1))), 24)),
]

MALFORMED = [
    # a map ending right after a key, at the top and nested
    ("map ends after a key", CTAPHID.CBOR, b"\x02\xa3" + E(1) + E("example.com") + E(2) + E(b"\x11" * 32) + E(4)),
    ("nested map ends after a key", CTAPHID.CBOR, b"\x02" + cmap(*ga()[:1], (E(2), b"\xa1" + E("up")))),
    ("indefinite map, break after a key", CTAPHID.CBOR, b"\x02\xbf" + E(1) + E("example.com") + E(2) + b"\xff"),
    # truncated arrays and strings
    ("truncated array", CTAPHID.CBOR, b"\x01" + cmap(*mc()[:3], (E(4), b"\x83" + E(PARAM)))),
    ("truncated byte string", CTAPHID.CBOR, b"\x02" + cmap(*ga()[:1], (E(2), b"\x58\x20" + b"\x11" * 31))),
    ("length beyond the message", CTAPHID.CBOR, b"\x02" + cmap(*ga()[:1], (E(2), b"\x5a\xff\xff\xff\xff"))),
    ("break outside a container", CTAPHID.CBOR, b"\x02\xff"),
    ("reserved additional info", CTAPHID.CBOR, b"\x02\xbc"),
    # indefinite lengths (never in canonical CBOR)
    ("indefinite map", CTAPHID.CBOR, b"\x02\xbf" + b"".join(k + v for k, v in ga()) + b"\xff"),
    ("indefinite array", CTAPHID.CBOR, b"\x01" + cmap(*mc()[:3], (E(4), b"\x9f" + E(PARAM) + b"\xff"))),
    ("chunked byte string", CTAPHID.CBOR, b"\x02" + cmap(*ga()[:1], (E(2), b"\x5f\x50" + b"\x11" * 16 +
                                                                     b"\x50" + b"\x11" * 16 + b"\xff"))),
    ("chunked text string", CTAPHID.CBOR, b"\x02" + cmap((E(1), b"\x7f\x67example\x64.com\xff"), *ga()[1:])),
    ("vendor: indefinite map", CTAP_VENDOR_CBOR, b"\x06\xbf" + E(1) + E(1) + b"\xff"),
    # deeper than tinycbor's recursion limit (16), in a member nobody reads
    ("nesting too deep", CTAPHID.CBOR, b"\x02" + cmap(*ga(), (E(9), b"\x81" * 40 + E(0)))),
]


def call(dev, cmd, payload):
    """The CTAP status of a request; fails if the emulator stops answering."""
    try:
        resp = dev.call(cmd, payload)
    except Exception as e:
        pytest.fail("no answer (emulator died?): %r" % e)
    return resp[0]


def alive(dev):
    info = cbor.decode(dev.call(CTAPHID.CBOR, b"\x04")[1:])
    assert "FIDO_2_0" in info[1]


GET_PIN_RETRIES = b"\x06" + cmap((E(1), E(2)), (E(2), E(1)))


def store_locked(dev):
    """A HARDENED build on an unprovisioned chip answers only getInfo."""
    return call(dev, CTAPHID.CBOR, GET_PIN_RETRIES) == NOT_ALLOWED


@pytest.fixture
def unlocked(ctap_device):
    """The session device, when it parses requests at all (see
    test_locked_key_store and test_hardened_provisioned)."""
    if store_locked(ctap_device):
        pytest.skip("key store locked (HARDENED, not provisioned): refused before parsing")
    return ctap_device


@pytest.mark.parametrize("name,cmd,payload", TAGGED, ids=[t[0] for t in TAGGED])
def test_tags_refused(unlocked, name, cmd, payload):
    assert call(unlocked, cmd, payload) == INVALID_CBOR
    alive(unlocked)


@pytest.mark.parametrize("name,cmd,payload", MALFORMED, ids=[t[0] for t in MALFORMED])
def test_malformed_refused(unlocked, name, cmd, payload):
    assert call(unlocked, cmd, payload) == INVALID_CBOR
    alive(unlocked)


def test_truncated_requests(unlocked):
    """Every strict prefix of a makeCredential and a getAssertion with
    extensions is incomplete CBOR."""
    for cmd, body in ((0x01, cmap(*mc(), (E(5), E([CRED])), (E(6), E({"credProtect": 2})), (E(7), E({"rk": False})))),
                      (0x02, cmap(*ga(), (E(3), E([CRED])), (E(5), E({"up": False}))))):
        for n in range(1, len(body), 3):
            assert call(unlocked, CTAPHID.CBOR, bytes([cmd]) + body[:n]) == INVALID_CBOR, n
    alive(unlocked)


def test_valid_requests_still_parsed(unlocked):
    """Canonical requests pass the validation: a getAssertion for an RP
    without credentials (NO_CREDENTIALS, not INVALID_CBOR), with an unknown
    member nested within the limit, and getPinRetries."""
    up = (E(5), E({"up": False}))
    rp = "cbor-hardening.invalid"
    assert call(unlocked, CTAPHID.CBOR, b"\x02" + cmap(*ga(rp), up)) == NO_CREDENTIALS
    assert call(unlocked, CTAPHID.CBOR, b"\x02" + cmap(*ga(rp), up, (E(9), b"\x81" * 12 + E(0)))) == NO_CREDENTIALS
    assert call(unlocked, CTAPHID.CBOR, GET_PIN_RETRIES) == 0
    alive(unlocked)


def test_locked_key_store(ctap_device):
    """A locked key store refuses every request but getInfo before it is
    parsed (NOT_ALLOWED), the reproducer and tagged getInfo parameters
    included."""
    if not store_locked(ctap_device):
        pytest.skip("key store not locked")
    assert call(ctap_device, CTAPHID.CBOR, REPRO) == NOT_ALLOWED
    assert call(ctap_device, CTAPHID.CBOR, b"\x04" + T(E({}), 0)) == INVALID_CBOR
    alive(ctap_device)


def ccid_status(card, payload):
    resp, sw = card.transmit(0x80, 0x10, 0x00, 0x00, payload, check=False)
    if sw == 0x9000:
        return resp[0]
    assert sw >> 8 == 0x64, hex(sw)
    return sw & 0xFF


@pytest.mark.parametrize("name,payload", [(t[0], t[2]) for t in TAGGED[:6] + MALFORMED[:3] if t[1] == CTAPHID.CBOR],
                         ids=[t[0] for t in TAGGED[:6] + MALFORMED[:3] if t[1] == CTAPHID.CBOR])
def test_ccid_ctap_path(unlocked, card, name, payload):
    """The same over the FIDO applet (CTAP over CCID/NFC)."""
    card.select(AID_FIDO)
    assert ccid_status(card, payload) == INVALID_CBOR
    assert ccid_status(card, b"\x04") == 0


# -- management applet -------------------------------------------------------

FIDO_RECORD = [(E(1), E("")), (E(2), E(b"\x11" * 42)), (E(3), E(b"u")), (E(6), E(-7)), (E(7), E(1)),
               (E(8), E(bytes(32)))]
OTP_RECORD = [(E(1), E(1)), (E(2), E(bytes(52))), (E(3), E(bytes(8)))]

MGMT_KEY = [
    # KEY_*: 6A80 (they need an unlocked key store, else 6985 first)
    ("key_list: tagged app", INS_KEY_LIST, cmap((E(1), T(E(0), 0))), 0x6A80),
    ("key_list: tagged request", INS_KEY_LIST, T(E({1: 0}), 24), 0x6A80),
    ("key_list: tagged key", INS_KEY_LIST, cmap((T(E(1), 1), E(0))), 0x6A80),
    ("key_list: indefinite map", INS_KEY_LIST, b"\xbf" + E(1) + E(0) + b"\xff", 0x6A80),
    ("key_list: map ends after a key", INS_KEY_LIST, b"\xa2" + E(1) + E(0) + E(3), 0x6A80),
    ("key_export: tagged id", INS_KEY_EXPORT, cmap((E(1), E(2)), (E(2), T(E(b"\x01"), 2))), 0x6A80),
    ("key_import: fido record, tagged field", INS_KEY_IMPORT,
     cmap((E(1), E(0)), (E(2), cmap(*FIDO_RECORD, (E(20), T(E(0)))))), 0x6A80),
    ("key_import: fido record, tagged rpId", INS_KEY_IMPORT,
     cmap((E(1), E(0)), (E(2), cmap((E(1), T(E("example.com"), 32)), *FIDO_RECORD[1:]))), 0x6A80),
    ("key_import: otp record, tagged field", INS_KEY_IMPORT,
     cmap((E(1), E(2)), (E(2), cmap(*OTP_RECORD[:1], (E(9), T(E(0))), *OTP_RECORD[1:]))), 0x6A80),
    ("key_import: tagged record", INS_KEY_IMPORT, cmap((E(1), E(0)), (E(2), T(cmap(*FIDO_RECORD), 24))), 0x6A80),
]
MGMT_SYS = [
    # PROFILE_SET, BOARD_SET, FW_BEGIN: 6700 (SW_WRONG_DATA, as for any
    # malformed data). {n: 11(0)} with an unknown n is the shape that ran
    # the parsers past the end of the map.
    ("profile_set: unknown key, tagged value", INS_PROFILE_SET, cmap((E(5), T(E(0)))), 0x6700),
    ("profile_set: tagged name", INS_PROFILE_SET, cmap((E(1), T(E("x"), 0))), 0x6700),
    ("profile_set: indefinite map", INS_PROFILE_SET, b"\xbf" + E(5) + E(0) + b"\xff", 0x6700),
    ("board_set: unknown key, tagged value", INS_BOARD_SET, cmap((E(2), T(E(0)))), 0x6700),
    ("board_set: tagged request", INS_BOARD_SET, T(E({1: 10}), 24), 0x6700),
    ("fw_begin: unknown key, tagged value", INS_FW_BEGIN, cmap((E(4), T(E(0)))), 0x6700),
]


@pytest.mark.parametrize("name,ins,data,sw", MGMT_KEY, ids=[t[0] for t in MGMT_KEY])
def test_mgmt_key_tags_refused(unlocked, card, name, ins, data, sw):
    mgmt_refused(card, ins, data, sw)
    alive(unlocked)


@pytest.mark.parametrize("name,ins,data,sw", MGMT_SYS, ids=[t[0] for t in MGMT_SYS])
def test_mgmt_tags_refused(ctap_device, card, name, ins, data, sw):
    mgmt_refused(card, ins, data, sw)
    alive(ctap_device)


def mgmt_refused(card, ins, data, sw):
    card.select(AID_LFMGMT)
    _, got = card.transmit(0x80, ins, 0x00, 0x00, data, check=False)
    assert got == sw, "%04X" % got
    card.select(AID_LFMGMT)
    _, got = card.transmit(0x80, INS_INFO, 0x00, 0x00, check=False)
    assert got == 0x9000


# -- HARDENED, provisioned ---------------------------------------------------

HARDENED_BIN = os.environ.get("LF_EMU_BIN_HARDENED")


@pytest.mark.skipif(not HARDENED_BIN or not os.path.exists(HARDENED_BIN), reason="LF_EMU_BIN_HARDENED not built")
def test_hardened_provisioned(pcscd, emulators, tmp_path):
    """A provisioned HARDENED device (its key store open) validates as the
    standard build does."""
    from test_hardened import provisioned
    e, m = provisioned(emulators, tmp_path)
    m.close()
    dev = ctaphid.open_device()
    try:
        assert not store_locked(dev)
        for _, cmd, payload in TAGGED[:8] + MALFORMED[:3]:
            assert call(dev, cmd, payload) == INVALID_CBOR
            alive(dev)
    finally:
        dev.close()
