"""USB transport regression tests: GET RESPONSE state, response chaining,
command chaining and CTAPHID arbitration with HID and CCID used together.

Every response must reach only the interface (and CTAPHID channel, or card
session) that issued the command, once; HID traffic must never disturb a
smart card session, and the other way round.

    source ~/work/testenv.sh
    PYTHONPATH=tests python -m pytest -p harness.plugin tests/transport
"""

import contextlib
import hashlib
import hmac
import os
import threading
import time

import pytest

from harness import ctaphid
from harness.ctaphid import CMD_CBOR, CMD_ERROR, CMD_INIT, CMD_OTP, CMD_PING, RawCtapHid
from harness.emulator import Button, Pcscd
from harness.plugin import emulator_instance

OPENPGP_AID = bytes.fromhex("D27600012401")
FIDO_AID = bytes.fromhex("A0000006472F0001")
U2F_AID = bytes.fromhex("A0000005271002")
PW1, PW3 = b"123456", b"12345678"
CCID_MAX_RESP = 2048 - 10 - 2       # data of one RDR_to_PC_DataBlock
ERR_CHANNEL_BUSY, ERR_MSG_TIMEOUT = 0x06, 0x05
CTAP2_ERR_NO_CREDENTIALS = 0x2E
U2F_VERSION = bytes.fromhex("0003000000")
GET_RESPONSE = bytes.fromhex("00C0000000")
OATH_LIST = bytes.fromhex("00A10000")
GET_INFO_2_FRAMES = b"\x04" + bytes(99)     # getInfo, padded to two frames


@pytest.fixture(scope="module")
def emu():
    e = emulator_instance()
    if e is None:
        pytest.skip("needs the harness plugin (-p harness.plugin)")
    e.wipe()                        # default PINs, no certificate
    e.start()
    yield e


@pytest.fixture
def hid(emu):
    h = RawCtapHid()
    yield h
    h.close()


def open_card(timeout=30.0):
    """A Card once the (re)started emulator is in the reader and answers: right
    after a restart pcscd may still report the old card, and the first
    transaction fails."""
    from harness.card import Card
    deadline = time.time() + timeout
    while True:
        c = None
        try:
            c = Card()
            c.raw(bytes([0, 0xA4, 4, 0, len(OPENPGP_AID)]) + OPENPGP_AID)
            return c
        except Exception:               # noqa: BLE001
            if c is not None:
                c.close()
            if time.time() > deadline:
                raise
            time.sleep(0.3)


@pytest.fixture
def card(emu):
    if not Pcscd().available:
        pytest.skip("no PC/SC stack configured (see tests/README.md)")
    c = open_card()
    yield c
    c.close()


@contextlib.contextmanager
def manual_button(emu, card=None, timeout_ms=8000):
    """The emulator restarted with a physical button (LF_EMU_UP=manual); yields
    a fresh Card and RawCtapHid, restores the normal emulator afterwards."""
    if card is not None:
        card.close()
    emu.restart(LF_EMU_UP="manual", LF_EMU_UP_TIMEOUT_MS=str(timeout_ms))
    c, h = None, None
    try:
        c = open_card()
        h = RawCtapHid()
        yield c, h
    finally:
        if h:
            h.close()
        if c:
            c.close()
        emu.restart()


def press():
    b = Button()
    b.press()
    b.close()


def otp_call(hid, cid, apdu):
    """CTAPHID_OTP: the answer carries the status word first."""
    cmd, data = hid.call(cid, CMD_OTP, apdu)
    assert cmd == CMD_OTP, data.hex()
    return data[2:], int.from_bytes(data[:2], "big")


def make_credential_cbor():
    from fido2 import cbor
    return b"\x01" + cbor.encode({1: os.urandom(32), 2: {"id": "example.com", "name": "x"},
                                  3: {"id": b"u", "name": "u", "displayName": "U"},
                                  4: [{"type": "public-key", "alg": -7}]})


def pgp_select(card):
    data, sw = card.raw(bytes([0, 0xA4, 4, 0, len(OPENPGP_AID)]) + OPENPGP_AID)
    assert sw == 0x9000


def pgp_verify(card, ref, pin):
    _, sw = card.raw(bytes([0, 0x20, 0, ref, len(pin)]) + pin)
    assert sw == 0x9000


def get_all(card, first):
    """Collects a response chained with 61xx using short GET RESPONSEs."""
    data, sw = first
    chunks = [len(data)]
    while (sw >> 8) == 0x61:
        more, sw = card.raw(bytes([0x00, 0xC0, 0x00, 0x00, sw & 0xFF]))
        chunks.append(len(more))
        data += more
    return data, sw, chunks


def put_cert(card, cert, between=None):
    """PUT DATA 7F21 with command chaining in 200 byte blocks."""
    blocks = [cert[i:i + 200] for i in range(0, len(cert), 200)]
    for i, b in enumerate(blocks):
        last = i == len(blocks) - 1
        _, sw = card.raw(bytes([0x00 if last else 0x10, 0xDA, 0x7F, 0x21, len(b)]) + b)
        assert sw == 0x9000, "block %d: %04X" % (i, sw)
        if between and not last:
            between(i)


# -- HID GET RESPONSE -----------------------------------------------------------
def test_hid_get_response_offsets(hid):
    """Chunks of 1, 2 and 3 bytes: offsets below the 7 byte frame header."""
    cid = hid.init()
    data, sw = hid.apdu(cid, bytes.fromhex("0003000001"))
    assert (data, sw) == (b"U", 0x6105)
    data, sw = hid.apdu(cid, bytes.fromhex("00C0000002"))
    assert (data, sw) == (b"2F", 0x6103)
    data, sw = hid.apdu(cid, GET_RESPONSE)
    assert (data, sw) == (b"_V2", 0x9000)
    # the channel still works normally afterwards
    assert hid.apdu(cid, U2F_VERSION) == (b"U2F_V2", 0x9000)


def test_hid_get_response_after_completion_is_not_replayed(hid):
    cid = hid.init()
    assert hid.apdu(cid, U2F_VERSION) == (b"U2F_V2", 0x9000)
    data, sw = hid.apdu(cid, GET_RESPONSE)
    assert data == b"" and sw != 0x9000 and (sw >> 8) != 0x61
    # also not after a response that was fetched to the end with GET RESPONSE
    assert hid.apdu(cid, bytes.fromhex("0003000004")) == (b"U2F_", 0x6102)
    assert hid.apdu(cid, GET_RESPONSE) == (b"V2", 0x9000)
    data, sw = hid.apdu(cid, GET_RESPONSE)
    assert data == b"" and sw != 0x9000


def test_hid_get_response_belongs_to_its_channel(hid):
    a, b = hid.init(), hid.init()
    assert hid.apdu(a, bytes.fromhex("0003000001")) == (b"U", 0x6105)
    data, sw = hid.apdu(b, GET_RESPONSE)
    assert b"2F" not in data and sw != 0x9000
    data, sw = hid.apdu(a, GET_RESPONSE)        # another channel's command ended it
    assert b"2F" not in data and sw != 0x9000


def test_hid_does_not_chain(hid):
    cid = hid.init()
    data, sw = hid.apdu(cid, bytes.fromhex("1003000000"))
    assert (data, sw) == (b"", 0x6884)
    assert hid.apdu(cid, U2F_VERSION) == (b"U2F_V2", 0x9000)


def test_hid_frame_padding_is_zero(hid):
    """Frames carry no bytes of earlier, longer responses."""
    cid = hid.init()
    assert hid.call(cid, CMD_PING, b"\x5A" * 1000) == (CMD_PING, b"\x5A" * 1000)
    hid.send(cid, CMD_PING, b"\x11" * 100)
    rcid, cmd, data, raw = hid.recv()
    assert (rcid, cmd, data) == (cid, CMD_PING, b"\x11" * 100)
    assert len(raw) == 2
    assert raw[1][5 + 43:] == bytes(64 - 5 - 43)


# -- CCID GET RESPONSE ----------------------------------------------------------
def test_ccid_get_response_after_completion_is_not_replayed(card):
    pgp_select(card)
    data, sw = card.raw(bytes.fromhex("00CA00C400"))      # PW status bytes
    assert len(data) == 7 and sw == 0x9000
    more, sw = card.raw(GET_RESPONSE)
    assert more == b"" and sw != 0x9000 and (sw >> 8) != 0x61
    # also not after a response fetched to the end with GET RESPONSE
    data, sw, _ = get_all(card, card.raw(bytes.fromhex("00CA006E00")))
    assert data[0] == 0x6E and sw == 0x9000
    more, sw = card.raw(GET_RESPONSE)
    assert more == b"" and sw != 0x9000 and (sw >> 8) != 0x61


def test_ccid_get_response_does_not_survive_reset(card):
    pgp_select(card)
    data, sw = card.raw(bytes.fromhex("00CA006E10"))
    assert len(data) == 16 and (sw >> 8) == 0x61
    card.reset()
    more, sw = card.raw(GET_RESPONSE)
    assert more == b"" and sw != 0x9000 and (sw >> 8) != 0x61


def test_ccid_get_response_does_not_survive_select(card):
    pgp_select(card)
    data, sw = card.raw(bytes.fromhex("00CA006E10"))
    assert (sw >> 8) == 0x61
    pgp_select(card)
    more, sw = card.raw(GET_RESPONSE)
    assert more == b"" and (sw >> 8) != 0x61


def test_ccid_long_response(card):
    """A 2 KiB object read with short APDUs (256 byte chunks) and with an
    extended Le: one transfer never exceeds a CCID data block, the status
    word always is the real one."""
    cert = os.urandom(2048)
    pgp_select(card)
    pgp_verify(card, 0x83, PW3)
    put_cert(card, cert)
    data, sw, chunks = get_all(card, card.raw(bytes.fromhex("00CA7F2100")))
    assert sw == 0x9000 and data == cert
    assert chunks == [256] * 8
    # 1 byte at a time for the first few chunks: small GET RESPONSE offsets
    data, sw = card.raw(bytes.fromhex("00CA7F2101"))
    out = data
    for _ in range(5):
        assert (sw >> 8) == 0x61
        more, sw = card.raw(bytes.fromhex("00C0000001"))
        out += more
    assert out == cert[:6]
    # extended Le: the first transfer is a full CCID data block
    data, sw, chunks = get_all(card, card.raw(bytes.fromhex("00CA7F21000000")))
    assert sw == 0x9000 and data == cert
    assert max(chunks) <= CCID_MAX_RESP and chunks[0] == CCID_MAX_RESP
    # OATH-style SEND REMAINING (00 A5 00 00) continues like GET RESPONSE
    data, sw = card.raw(bytes.fromhex("00CA7F2100"))
    out = data
    while (sw >> 8) == 0x61:
        more, sw = card.raw(bytes.fromhex("00A50000"))
        out += more
    assert sw == 0x9000 and out == cert


def test_oath_long_answers_over_ccid(card):
    """LIST and CALCULATE ALL answers longer than one CCID data block are
    chained (61xx, SEND REMAINING) instead of being cut."""
    yk_oath = pytest.importorskip("yubikit.oath")
    from harness.card import YkConnection
    s = yk_oath.OathSession(YkConnection(card))
    s.reset()
    names = set()
    for i in range(40):
        cd = yk_oath.CredentialData(name="account%02d@example.com" % i, oath_type=yk_oath.OATH_TYPE.TOTP,
                                    hash_algorithm=yk_oath.HASH_ALGORITHM.SHA1, secret=os.urandom(20),
                                    issuer="issuer%02d-%s" % (i, "x" * 20))
        names.add(s.put_credential(cd).id)
    assert {c.id for c in s.list_credentials()} == names
    assert {c.id for c in s.calculate_all()} == names
    s.reset()


# -- HID and CCID together ------------------------------------------------------
def test_pending_responses_stay_on_their_interface(card, hid):
    cert = os.urandom(1500)
    pgp_select(card)
    pgp_verify(card, 0x83, PW3)
    put_cert(card, cert)
    first = card.raw(bytes.fromhex("00CA7F2100"))
    assert first[0] == cert[:256] and first[1] == 0x6100
    cid = hid.init()
    # a HID GET RESPONSE never gets the smart card's data
    data, sw = hid.apdu(cid, GET_RESPONSE)
    assert data == b"" and sw != 0x9000 and (sw >> 8) != 0x61
    # HID leaves data pending; a smart card GET RESPONSE continues its own
    assert hid.apdu(cid, bytes.fromhex("0003000001")) == (b"U", 0x6105)
    data, sw, _ = get_all(card, first)
    assert sw == 0x9000 and data == cert
    # the smart card never gets the HID data, which is still there for HID
    more, sw = card.raw(GET_RESPONSE)
    assert b"2F" not in more and (sw >> 8) != 0x61
    assert hid.apdu(cid, GET_RESPONSE) == (b"2F_V2", 0x9000)


def test_ctap_over_ccid_leaves_the_hid_buffer_alone(card, hid):
    """CTAP carried in an APDU over CCID encodes in scratch space of the smart
    card interface, not in the HID response buffer."""
    cid = hid.init()
    assert hid.apdu(cid, bytes.fromhex("0003000001")) == (b"U", 0x6105)
    assert card.raw(bytes.fromhex("00A4040008A0000006472F0001"))[1] == 0x9000
    data, sw, _ = get_all(card, card.raw(bytes.fromhex("80100000010400")))    # getInfo
    assert sw == 0x9000 and data[0] == 0 and len(data) > 64
    assert hid.apdu(cid, GET_RESPONSE) == (b"2F_V2", 0x9000)
    cmd, info = hid.call(cid, CMD_CBOR, b"\x04")
    assert cmd == CMD_CBOR and info == data


def test_chained_ccid_command_with_hid_traffic(card, hid):
    cert = os.urandom(1800)
    cid = hid.init()

    def hid_traffic(i):
        assert hid.apdu(cid, U2F_VERSION) == (b"U2F_V2", 0x9000)
        cmd, info = hid.call(cid, CMD_CBOR, b"\x04")
        assert cmd == CMD_CBOR and info[0] == 0
        assert hid.apdu(cid, bytes.fromhex("1003000000"))[1] == 0x6884

    pgp_select(card)
    pgp_verify(card, 0x83, PW3)
    put_cert(card, cert, between=hid_traffic)
    data, sw = card.transmit(0x00, 0xCA, 0x7F, 0x21, le=0)
    assert data == cert


def test_hid_command_keeps_the_smart_card_session(card, hid):
    pgp_select(card)
    pgp_verify(card, 0x82, PW1)
    cid = hid.init()
    for _ in range(3):
        assert hid.apdu(cid, U2F_VERSION) == (b"U2F_V2", 0x9000)
        assert card.raw(bytes.fromhex("00200082"))[1] == 0x9000
        cmd, info = hid.call(cid, CMD_CBOR, b"\x04")
        assert cmd == CMD_CBOR and info[0] == 0
        assert card.raw(bytes.fromhex("00200082"))[1] == 0x9000


def test_hid_message_completing_during_a_ccid_command(card, hid):
    """The last frame of a HID message arrives while a smart card command
    runs: the HID channel is told to retry, the smart card command gets its
    own answer."""
    pgp_select(card)
    pgp_verify(card, 0x83, PW3)
    # RSA 4096 for the signature key: its generation takes a while
    assert card.raw(bytes.fromhex("00DA00C106011000002000"))[1] == 0x9000
    cid = hid.init()
    frames = RawCtapHid.frames(CMD_CBOR, GET_INFO_2_FRAMES)
    assert len(frames) == 2
    hid.send_frame(cid, frames[0])
    result = {}

    def keygen():
        result["r"] = card.transmit(0x00, 0x47, 0x80, 0x00, bytes.fromhex("B600"), le=0, check=False)

    t = threading.Thread(target=keygen)
    t.start()
    time.sleep(0.25)
    running = t.is_alive()
    hid.send_frame(cid, frames[1])
    rcid, cmd, data, _ = hid.recv()
    t.join(120)
    assert not t.is_alive()
    data_k, sw_k = result["r"]
    assert sw_k == 0x9000 and data_k[:2] == b"\x7F\x49"
    assert rcid == cid
    if running:
        assert (cmd, data) == (CMD_ERROR, bytes([ERR_CHANNEL_BUSY]))
    else:
        pytest.skip("key generation finished before the HID message completed")
    # both interfaces work normally afterwards
    cmd, info = hid.call(cid, CMD_CBOR, b"\x04")
    assert cmd == CMD_CBOR and info[0] == 0
    assert card.transmit(0x00, 0xCA, 0x00, 0x6E, le=0)[1] == 0x9000


def test_card_reset_during_a_hid_command_is_not_skipped(emu, card):
    """SCARD_RESET_CARD while a FIDO request waits for a touch: the smart card
    session still ends (PIN state gone), once the HID command finished."""
    from fido2.ctap2 import Ctap2
    card.close()
    emu.restart(LF_EMU_UP="manual", LF_EMU_UP_TIMEOUT_MS="8000")
    try:
        c = open_card()
        pgp_select(c)
        pgp_verify(c, 0x82, PW1)
        assert c.raw(bytes.fromhex("00200082"))[1] == 0x9000
        dev = ctaphid.open_device()
        done = {}

        def make():
            try:
                Ctap2(dev).make_credential(os.urandom(32), {"id": "example.com", "name": "x"},
                                           {"id": b"u", "name": "u", "displayName": "U"},
                                           [{"type": "public-key", "alg": -7}])
                done["ok"] = True
            except Exception as ex:     # noqa: BLE001
                done["err"] = ex

        t = threading.Thread(target=make)
        t.start()
        time.sleep(0.8)                 # the request waits for the button
        assert t.is_alive()
        c.reset()
        b = Button()
        b.press()
        b.close()
        t.join(20)
        dev.close()
        assert done.get("ok"), done
        # no SELECT: the application was unloaded by the (deferred) reset
        assert c.raw(bytes.fromhex("00200082"))[1] != 0x9000
        pgp_select(c)
        assert c.raw(bytes.fromhex("00200082"))[1] != 0x9000
        c.close()
    finally:
        emu.restart()


def test_ping_completing_during_ctap_over_ccid(emu, card):
    """The last frame of a long CTAPHID_PING arrives while CTAP over CCID runs
    (makeCredential waiting for the button): the PING gets CHANNEL_BUSY, the
    smart card client gets its own, intact answer."""
    from fido2 import cbor
    with manual_button(emu, card) as (c, hid):
        cid = hid.init()
        assert c.raw(bytes([0, 0xA4, 4, 0, len(FIDO_AID)]) + FIDO_AID)[1] == 0x9000
        payload = os.urandom(100)
        frames = RawCtapHid.frames(CMD_PING, payload)
        mc = make_credential_cbor()
        result = {}

        def ctap_over_ccid():
            result["r"] = get_all(c, c.raw(bytes([0x80, 0x10, 0, 0, len(mc)]) + mc + b"\x00"))

        hid.send_frame(cid, frames[0])          # accepted: nothing runs yet
        t = threading.Thread(target=ctap_over_ccid)
        t.start()
        time.sleep(0.3)                         # waits for the button; < inter-frame timeout
        assert t.is_alive()
        hid.send_frame(cid, frames[1])
        rcid, cmd, data, _ = hid.recv()
        assert (rcid, cmd, data) == (cid, CMD_ERROR, bytes([ERR_CHANNEL_BUSY]))
        press()
        t.join(20)
        data, sw, _ = result["r"]
        assert sw == 0x9000 and data[0] == 0
        att = cbor.decode(data[1:])
        assert set(att) >= {1, 2, 3} and att[1] in ("packed", "none")
        assert hid.call(cid, CMD_PING, payload) == (CMD_PING, payload)


def test_otp_message_does_not_change_later_cbor_answers(hid):
    """The CTAPHID_OTP framing (status word first) is for that message only."""
    from fido2 import cbor
    cid = hid.init()
    cmd, info = hid.call(cid, CMD_CBOR, b"\x04")
    assert cmd == CMD_CBOR and info[0] == 0
    otp_call(hid, cid, OATH_LIST)
    assert hid.call(cid, CMD_CBOR, b"\x04") == (CMD_CBOR, info)
    assert isinstance(cbor.decode(info[1:]), dict)
    ga = b"\x02" + cbor.encode({1: "no-credential.example", 2: os.urandom(32), 5: {"up": False}})
    otp_call(hid, cid, OATH_LIST)
    assert hid.call(cid, CMD_CBOR, ga) == (CMD_CBOR, bytes([CTAP2_ERR_NO_CREDENTIALS]))
    assert hid.call(cid, CMD_CBOR, b"\x04") == (CMD_CBOR, info)


def test_otp_get_response_ends_the_nitrokey_framing(card, hid):
    """A CTAPHID_OTP GET RESPONSE answered without a command still ends the
    Nitrokey framing: a smart card OATH SELECT afterwards has no NK fields."""
    oath_aid = bytes.fromhex("A0000005272101")
    select = bytes([0, 0xA4, 4, 0, len(oath_aid)]) + oath_aid
    plain, sw = card.raw(select)
    assert sw == 0x9000 and 0x8F not in tlvs(plain)
    cid = hid.init()
    assert hid.apdu(cid, bytes.fromhex("0003000001")) == (b"U", 0x6105)
    assert otp_call(hid, cid, GET_RESPONSE) == (b"2F_V2", 0x9000)
    data, sw = card.raw(select)
    assert sw == 0x9000 and 0x8F not in tlvs(data) and 0x82 not in tlvs(data)


def test_otp_message_as_first_command_after_boot(emu):
    emu.restart()
    hid = RawCtapHid()
    try:
        cid = hid.init()
        data, sw = otp_call(hid, cid, OATH_LIST)
        assert sw in (0x9000, 0x6982)
        assert hid.call(cid, CMD_PING, b"alive") == (CMD_PING, b"alive")
        assert emu.proc.poll() is None
    finally:
        hid.close()


def test_otp_message_keeps_pending_responses(card, hid):
    """The implicit OATH selection of a CTAPHID_OTP message writes nowhere
    near data left for GET RESPONSE: the smart card's, or HID's own."""
    pgp_select(card)
    full, sw, _ = get_all(card, card.raw(bytes.fromhex("00CA006E00")))
    assert sw == 0x9000
    first = card.raw(bytes.fromhex("00CA006E01"))
    assert first[0] == full[:1] and (first[1] >> 8) == 0x61
    cid = hid.init()
    otp_call(hid, cid, OATH_LIST)
    data, sw, _ = get_all(card, first)
    assert sw == 0x9000 and data == full
    # HID: U2F data pending at offset 1, fetched with a CTAPHID_OTP message
    assert hid.apdu(cid, bytes.fromhex("0003000001")) == (b"U", 0x6105)
    assert otp_call(hid, cid, GET_RESPONSE) == (b"2F_V2", 0x9000)


def test_hid_select_cannot_log_out_the_smart_card_session(card, hid):
    pgp_select(card)
    pgp_verify(card, 0x82, PW1)
    cid = hid.init()
    select_pgp = bytes([0, 0xA4, 4, 0, len(OPENPGP_AID)]) + OPENPGP_AID
    assert hid.apdu(cid, select_pgp) == (b"", 0x6A82)
    assert otp_call(hid, cid, select_pgp) == (b"", 0x6A82)
    # the application the transport picked may be confirmed
    assert hid.apdu(cid, bytes([0, 0xA4, 4, 0, len(U2F_AID)]) + U2F_AID)[1] == 0x9000
    assert hid.apdu(cid, U2F_VERSION) == (b"U2F_V2", 0x9000)
    assert card.raw(bytes.fromhex("00200082"))[1] == 0x9000


def tlvs(data):
    out, i = {}, 0
    while i + 2 <= len(data):
        out[data[i]] = data[i + 2:i + 2 + data[i + 1]]
        i += 2 + data[i + 1]
    return out


def test_oath_validation_on_hid_belongs_to_its_channel(card, hid):
    """An OATH access code validated on one CTAPHID channel does not
    authorize another channel (another client), and ends when another channel
    uses the OATH slot."""
    yk_oath = pytest.importorskip("yubikit.oath")
    from harness.card import YkConnection
    s = yk_oath.OathSession(YkConnection(card))
    s.reset()
    s = yk_oath.OathSession(YkConnection(card))
    key = s.derive_key("hid channel")
    s.set_key(key)
    a, b = hid.init(), hid.init()
    oath_aid = bytes.fromhex("A0000005272101")
    sel, sw = otp_call(hid, a, bytes([0, 0xA4, 4, 0, len(oath_aid)]) + oath_aid)
    assert sw == 0x9000
    dev_chal = tlvs(sel)[0x74]
    mine = os.urandom(8)
    body = b"\x75\x14" + hmac.new(key, dev_chal, hashlib.sha1).digest() + b"\x74\x08" + mine
    data, sw = otp_call(hid, a, bytes([0, 0xA3, 0, 0, len(body)]) + body)
    assert sw == 0x9000
    assert otp_call(hid, a, OATH_LIST)[1] == 0x9000
    assert otp_call(hid, b, OATH_LIST)[1] == 0x6982
    assert otp_call(hid, a, OATH_LIST)[1] == 0x6982
    s = yk_oath.OathSession(YkConnection(card))
    s.validate(key)
    s.unset_key()
    s.reset()


def test_oath_slot_survives_u2f_and_fido_messages(card, hid):
    """U2F/FIDO and OATH messages have separate HID app slots: switching
    between them does not unload (reset) OATH, so the smart card OATH session
    stays validated."""
    yk_oath = pytest.importorskip("yubikit.oath")
    from harness.card import YkConnection
    a = hid.init()
    otp_call(hid, a, OATH_LIST)             # OATH selected in the HID slot
    s = yk_oath.OathSession(YkConnection(card))
    s.reset()
    s = yk_oath.OathSession(YkConnection(card))
    key = s.derive_key("access code")
    s.set_key(key)
    s = yk_oath.OathSession(YkConnection(card))
    s.validate(key)
    s.list_credentials()
    for _ in range(2):
        assert hid.apdu(a, U2F_VERSION) == (b"U2F_V2", 0x9000)
        assert hid.call(a, CMD_CBOR, b"\x04")[0] == CMD_CBOR
        otp_call(hid, a, OATH_LIST)
    s.list_credentials()                    # the smart card session is still validated
    s.unset_key()
    s.reset()


def test_single_frame_command_survives_other_frames(emu, card):
    """A single frame CTAPHID_OTP CALCULATE waits for the button while other
    frames arrive: it still computes the name and challenge it was sent."""
    yk_oath = pytest.importorskip("yubikit.oath")
    from harness.card import YkConnection
    with manual_button(emu, card) as (c, hid):
        s = yk_oath.OathSession(YkConnection(c))
        secret = os.urandom(20)
        cd = yk_oath.CredentialData(name="touch", oath_type=yk_oath.OATH_TYPE.TOTP,
                                    hash_algorithm=yk_oath.HASH_ALGORITHM.SHA1, secret=secret)
        cred = s.put_credential(cd, touch_required=True)
        chal = os.urandom(8)
        body = b"\x71\x05touch\x74\x08" + chal
        apdu = bytes([0x00, 0xA2, 0x00, 0x00, len(body)]) + body + b"\x00"
        assert len(apdu) <= 57
        cid = hid.init()
        hid.send(cid, CMD_OTP, apdu)
        time.sleep(0.5)                     # waits for the button
        for _ in range(3):                  # other clients open the device
            hid.send(ctaphid.CID_BROADCAST, CMD_INIT, os.urandom(8))
        press()
        while True:
            rcid, cmd, data, _ = hid.recv()
            if rcid == cid:
                break
        assert cmd == CMD_OTP and data[:2] == b"\x90\x00", data.hex()
        assert data[2:].endswith(hmac.new(secret, chal, hashlib.sha1).digest())
        s = yk_oath.OathSession(YkConnection(c))
        s.delete_credential(cred.id)


# -- CTAPHID arbitration ----------------------------------------------------------
def test_stalled_message_times_out_after_busy_replies(hid):
    a, b = hid.init(), hid.init()
    frames = RawCtapHid.frames(CMD_PING, bytes(200))
    hid.send_frame(a, frames[0])            # a stalls after its first frame
    assert hid.call(b, CMD_PING, b"x") == (CMD_ERROR, bytes([ERR_CHANNEL_BUSY]))
    hid.settimeout(3)
    t0 = time.time()
    rcid, cmd, data, _ = hid.recv()
    assert (rcid, cmd, data) == (a, CMD_ERROR, bytes([ERR_MSG_TIMEOUT]))
    assert time.time() - t0 < 1.5
    assert hid.call(b, CMD_PING, b"x") == (CMD_PING, b"x")


def test_broadcast_init_keeps_another_channels_message(hid):
    a = hid.init()
    payload = os.urandom(100)
    frames = RawCtapHid.frames(CMD_PING, payload)
    hid.send_frame(a, frames[0])
    b = hid.init()                          # a new client opens the device
    assert b != a
    hid.send_frame(a, frames[1])
    rcid, cmd, data, _ = hid.recv()
    assert (rcid, cmd, data) == (a, CMD_PING, payload)
    # INIT on the channel itself still resynchronizes it
    hid.send_frame(a, frames[0])
    nonce = os.urandom(8)
    assert hid.call(a, CMD_INIT, nonce)[1][:8] == nonce
    assert hid.call(a, CMD_PING, b"y") == (CMD_PING, b"y")


def test_init_on_another_channel_keeps_the_message(hid):
    """INIT resynchronizes its own channel only (CTAP 2.1, 11.2.9.1.3)."""
    a, b = hid.init(), hid.init()
    payload = os.urandom(100)
    frames = RawCtapHid.frames(CMD_PING, payload)
    hid.send_frame(a, frames[0])
    nonce = os.urandom(8)
    assert hid.call(b, CMD_INIT, nonce)[1][:8] == nonce     # b resyncs itself
    hid.send_frame(a, frames[1])
    rcid, cmd, data, _ = hid.recv()
    assert (rcid, cmd, data) == (a, CMD_PING, payload)
