"""Mutation fuzzing of every applet and of the CTAPHID transport.

Deterministic (seeded) mutations of well-formed commands are sent to the
emulator; after every batch the emulator must still be running and
answering. Run it against the ASan/UBSan build to turn silent memory errors
into failures:

    ~/work/scripts/locked_tests.sh asan -q tests/fuzz
    LF_FUZZ_ITER=20000 LF_FUZZ_SEED=7 ...   # longer / other runs

A crash leaves the inputs of the failing batch in the test's tmp_path
(reproducer) and the emulator log (sanitizer report) is quoted in the
failure message. Exit code 3 of the emulator is a legitimate reboot (e.g. a
fuzzed management command switched the profile) and is not a failure.
"""

import os
import random
import struct
import time

import pytest

from harness import ctaphid
from harness.card import Card
from harness.plugin import emulator_instance

ITER = int(os.environ.get("LF_FUZZ_ITER", "1500"))
SEED = int(os.environ.get("LF_FUZZ_SEED", "1"))
BATCH = 50

AID_OPENPGP = bytes.fromhex("D27600012401")
AID_PIV = bytes.fromhex("A000000308")
AID_OATH = bytes.fromhex("A0000005272101")
AID_OTP = bytes.fromhex("A0000005272001")
AID_YKMGMT = bytes.fromhex("A000000527471117")
AID_FIDO = bytes.fromhex("A0000006472F0001")
AID_LFMGMT = b"\xF0LIBREFIDO"


def tlv(tag, value):
    tag = tag.to_bytes(2, "big") if tag > 0xFF else bytes([tag])
    n = len(value)
    ln = bytes([n]) if n < 0x80 else (bytes([0x81, n]) if n < 0x100 else b"\x82" + n.to_bytes(2, "big"))
    return tag + ln + value


# Seeds: (cla, ins, p1, p2, data) of well-formed commands per applet.
SEEDS = {
    "openpgp": (AID_OPENPGP, [
        (0x00, 0xCA, 0x00, 0x6E, b""), (0x00, 0xCA, 0x00, 0xC4, b""), (0x00, 0xCA, 0x7F, 0x21, b""),
        (0x00, 0x20, 0x00, 0x81, b"123456"), (0x00, 0x20, 0x00, 0x83, b"12345678"),
        (0x00, 0xDA, 0x00, 0x5B, b"Test"), (0x00, 0xDA, 0x00, 0xC4, b"\x01"),
        (0x00, 0x47, 0x81, 0x00, bytes.fromhex("B600")), (0x00, 0x47, 0x80, 0x00, bytes.fromhex("B800")),
        (0x00, 0x2A, 0x9E, 0x9A, b"\x30" * 32), (0x00, 0x2A, 0x80, 0x86, b"\x00" + b"\xAA" * 64),
        (0x00, 0x88, 0x00, 0x00, b"\x55" * 32), (0x00, 0x24, 0x00, 0x81, b"123456654321"),
        (0x00, 0xDB, 0x3F, 0xFF, tlv(0x4D, tlv(0xB6, b"") + tlv(0x7F48, b"\x91\x03\x92\x81\x80") + tlv(0x5F48, b"\x01" * 64))),
        (0x00, 0xA5, 0x02, 0x04, bytes.fromhex("6004 5C027F21")), (0x00, 0xCC, 0x00, 0x00, b""),
        (0x00, 0x2C, 0x02, 0x81, b"123456"), (0x00, 0xE6, 0x00, 0x00, b""),
    ]),
    "piv": (AID_PIV, [
        (0x00, 0xCB, 0x3F, 0xFF, tlv(0x5C, bytes.fromhex("5FC105"))),
        (0x00, 0xCB, 0x3F, 0xFF, tlv(0x5C, bytes.fromhex("5FC109"))),
        (0x00, 0x20, 0x00, 0x80, b"123456\xff\xff"), (0x00, 0x20, 0xFF, 0x80, b""),
        (0x00, 0x87, 0x03, 0x9B, tlv(0x7C, tlv(0x80, b""))),
        (0x00, 0x87, 0x03, 0x9B, tlv(0x7C, tlv(0x80, b"\x11" * 8) + tlv(0x81, b""))),
        (0x00, 0x87, 0x11, 0x9A, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, b"\x22" * 32))),
        (0x00, 0x87, 0x07, 0x9C, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, b"\x00" + b"\x33" * 255))),
        (0x00, 0x47, 0x00, 0x9A, tlv(0xAC, tlv(0x80, b"\x11"))),
        (0x00, 0xDB, 0x3F, 0xFF, tlv(0x5C, bytes.fromhex("5FC105")) + tlv(0x53, b"\x70\x01\x00")),
        (0x00, 0xF7, 0x00, 0x80, b""), (0x00, 0xF9, 0x00, 0x9A, b""), (0x00, 0xFD, 0x00, 0x00, b""),
        (0x00, 0xFF, 0xFF, 0xFE, bytes.fromhex("9B18") + b"\x01" * 24), (0x00, 0xF6, 0x9A, 0x82, b""),
        (0x00, 0x2C, 0x00, 0x80, b"12345678123456\xff\xff"), (0x00, 0x24, 0x00, 0x80, b"123456\xff\xff654321\xff\xff"),
        (0x00, 0xFE, 0x11, 0x9A, tlv(0x06, b"\x01" * 32)),
    ]),
    "oath": (AID_OATH, [
        (0x00, 0xA1, 0x00, 0x00, b""), (0x00, 0xA4, 0x00, 0x01, tlv(0x74, b"\x00" * 8)),
        (0x00, 0x01, 0x00, 0x00, tlv(0x71, b"acct") + tlv(0x73, b"\x21\x06" + b"\x55" * 20) + tlv(0x78, b"\x02")),
        (0x00, 0x01, 0x00, 0x00, tlv(0x71, b"hotp") + tlv(0x73, b"\x11\x08" + b"\x66" * 20) + tlv(0x7A, b"\x00\x00\x00\x05")),
        (0x00, 0xA2, 0x00, 0x01, tlv(0x71, b"acct") + tlv(0x74, b"\x00" * 8)),
        (0x00, 0x03, 0x00, 0x00, tlv(0x74, b"\x01" * 16) + tlv(0x75, b"\x02" * 16)),
        (0x00, 0xA3, 0x00, 0x00, tlv(0x75, b"\x02" * 20) + tlv(0x74, b"\x03" * 8)),
        (0x00, 0x05, 0x00, 0x00, tlv(0x71, b"acct") + tlv(0x71, b"renamed")),
        (0x00, 0x02, 0x00, 0x00, tlv(0x71, b"acct")), (0x00, 0x04, 0xDE, 0xAD, b""),
        (0x00, 0xB1, 0x00, 0x00, tlv(0x71, b"hotp") + tlv(0x75, b"\x00\x00\x00\x01")),
        (0x00, 0xB2, 0x00, 0x00, tlv(0x71, b"acct")),
    ]),
    "otp": (AID_OTP, [
        (0x00, 0x03, 0x00, 0x00, b""), (0x00, 0x01, 0x10, 0x00, b""),
        (0x00, 0x01, 0x01, 0x00, b"\x00" * 16 + b"\x01" * 6 + b"\x02" * 16 + b"\x00" * 6 + b"\x00\x20\x00\x00\x00\x00" + b"\x00" * 6),
        (0x00, 0x01, 0x30, 0x00, b"\x55" * 64), (0x00, 0x01, 0x38, 0x00, b"\x55" * 32),
        (0x00, 0x01, 0x20, 0x00, b"\x55" * 6), (0x00, 0x01, 0x06, 0x00, b""),
        (0x00, 0x01, 0x04, 0x00, b"\x00" * 52), (0x00, 0x01, 0x13, 0x00, b""),
    ]),
    "ykmgmt": (AID_YKMGMT, [
        (0x00, 0x1D, 0x00, 0x00, b""), (0x00, 0x1C, 0x00, 0x00, b"\x02\x01\x3F"),
        (0x00, 0x1F, 0x00, 0x00, b""),
    ]),
    "fido-ccid": (AID_FIDO, [
        (0x80, 0x10, 0x00, 0x00, b"\x04"), (0x80, 0x10, 0x00, 0x00, b"\x06\xa2\x01\x01\x02\x02"),
        (0x00, 0x01, 0x03, 0x00, b"\x00" * 64), (0x00, 0x02, 0x07, 0x00, b"\x00" * 32 + b"\x00" * 32 + b"\x40" + b"\x00" * 64),
        (0x00, 0x03, 0x00, 0x00, b""),
    ]),
    # read-only management commands only: the others reboot or wipe
    "lfmgmt": (AID_LFMGMT, [
        (0x80, 0x01, 0x00, 0x00, b""), (0x80, 0x02, 0x00, 0x00, b""),
        (0x80, 0x21, 0x00, 0x00, b"\x00" * 16), (0x80, 0x29, 0x00, 0x00, b"\x00" * 64),
    ]),
}
LFMGMT_SAFE_INS = {0x01, 0x02, 0x21, 0x22, 0x29, 0x2A}


def mutate(rng, cmd):
    cla, ins, p1, p2, data = cmd
    data = bytearray(data)
    for _ in range(rng.choice((1, 1, 2, 3, 6))):
        op = rng.randrange(10)
        if op == 0 and data:
            i = rng.randrange(len(data))
            data[i] ^= 1 << rng.randrange(8)
        elif op == 1 and data:
            data[rng.randrange(len(data))] = rng.choice((0x00, 0x01, 0x7F, 0x80, 0x81, 0x82, 0xFF))
        elif op == 2:
            data[rng.randrange(len(data) + 1):rng.randrange(len(data) + 1)] = os.urandom(rng.randrange(1, 40))
        elif op == 3 and data:
            del data[rng.randrange(len(data)):]
        elif op == 4:
            p1 = rng.randrange(256)
        elif op == 5:
            p2 = rng.randrange(256)
        elif op == 6:
            ins = rng.randrange(256)
        elif op == 7:
            data += bytes(rng.randrange(200, 1400))
        elif op == 8 and data:
            # blow up a TLV length
            i = rng.randrange(len(data))
            data[i:i + 1] = rng.choice((b"\x82\xff\xff", b"\x81\xff", b"\x84\x00\x00\x10\x00", b"\x7f"))
        else:
            cla = rng.choice((cla, cla | 0x10, 0x80, 0x00, 0x0C, rng.randrange(256)))
    return cla, ins, p1, p2, bytes(data)


def encode(rng, cla, ins, p1, p2, data):
    """Short or extended APDU, with a random (sometimes inconsistent) Le."""
    if len(data) <= 255 and rng.random() < 0.7:
        apdu = bytes([cla, ins, p1, p2])
        if data:
            apdu += bytes([len(data)]) + data
        if rng.random() < 0.5:
            apdu += bytes([rng.choice((0, 1, 0x10, 0xFF))])
        return apdu
    apdu = bytes([cla, ins, p1, p2, 0]) + struct.pack(">H", len(data)) + data
    if rng.random() < 0.5:
        apdu += struct.pack(">H", rng.choice((0, 1, 0x100, 0xFFFF)))
    return apdu


class Target:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.emu = emulator_instance()
        self.card = None

    def alive(self):
        return self.emu.proc is not None and self.emu.proc.poll() is None

    def _restart(self):
        """Emulator plus pcscd: an emulator that died in the middle of a
        CCID command leaves pcscd's vpcd reader unusable."""
        from harness import emulator as H
        pcscd = H._session.get("pcscd")
        if pcscd is not None and pcscd.proc is not None:
            pcscd.stop()
            pcscd.start()
        self.emu.start()
        time.sleep(0.5)

    def check(self, what, inputs):
        """Fails with the reproducer and the emulator log if the emulator died."""
        if self.alive():
            return
        code = self.emu.proc.poll() if self.emu.proc else None
        if code == 3:              # legitimate reboot
            self.emu.proc = None
            self.emu._log.close()
            self._restart()
            self.reconnect()
            return
        repro = self.tmp_path / ("crash-%s.hex" % what)
        repro.write_text("\n".join(x.hex() for x in inputs))
        with open(self.emu.log_path, errors="replace") as f:
            f.seek(self.emu.log_start)
            log = f.read()[-6000:]
        self.emu.proc = None
        self.emu._log.close()
        self._restart()             # leave a working emulator for later tests
        pytest.fail("emulator died (exit %s) while fuzzing %s; inputs in %s\n%s" % (code, what, repro, log))

    def reconnect(self):
        if self.card:
            self.card.close()
        self.card = Card()


@pytest.fixture
def target(tmp_path):
    t = Target(tmp_path)
    t.reconnect()
    yield t
    if t.card:
        t.card.close()


@pytest.mark.parametrize("applet", sorted(SEEDS))
def test_fuzz_applet(target, applet):
    aid, seeds = SEEDS[applet]
    rng = random.Random("%d/%s" % (SEED, applet))
    sent = []
    for i in range(ITER):
        if i % BATCH == 0:
            target.check(applet, sent)
            sent = []
            try:
                target.card.select(aid, check=False)
            except Exception:
                target.check(applet, sent)
                target.reconnect()
                target.card.select(aid, check=False)
        cmd = mutate(rng, rng.choice(seeds))
        if applet == "lfmgmt" and cmd[1] not in LFMGMT_SAFE_INS:
            continue
        apdu = encode(rng, *cmd)
        sent.append(apdu)
        try:
            target.card.raw(apdu)
        except Exception:
            target.check(applet, sent)
            target.reconnect()
            target.card.select(aid, check=False)
    target.check(applet, sent)
    # still a working card
    target.card.select(aid, check=False)


def test_fuzz_ctaphid_frames(target):
    """Raw 64 byte HID reports: broken headers, sequences, lengths, channels."""
    rng = random.Random("%d/hid" % SEED)
    sent = []
    conn = ctaphid.open_connection(ctaphid.get_descriptor())
    conn.sock.settimeout(0.05)
    for i in range(ITER * 2):
        if i % BATCH == 0:
            target.check("ctaphid", sent)
            sent = []
        cid = rng.choice((b"\xff\xff\xff\xff", b"\x00\x00\x00\x00", os.urandom(4)))
        if rng.random() < 0.5:
            cmd = rng.choice((0x81, 0x83, 0x86, 0x90, 0x91, 0xBF, 0xC1, 0x80 | rng.randrange(128)))
            bcnt = rng.choice((0, 1, 57, 58, 7609, 7610, 0xFFFF, rng.randrange(0x10000)))
            pkt = cid + bytes([cmd]) + struct.pack(">H", bcnt) + os.urandom(57)
        else:
            pkt = cid + bytes([rng.randrange(0x80)]) + os.urandom(59)
        sent.append(pkt)
        try:
            conn.write_packet(pkt)
            while True:
                conn.read_packet()
        except OSError:
            pass
    conn.close()
    time.sleep(0.2)
    target.check("ctaphid", sent)
    from harness.emulator import HID_PORT, _wait_port
    _wait_port(HID_PORT, 15)
    dev = ctaphid.open_device()        # a normal client still works
    dev.close()


def test_fuzz_ctap2_cbor(target):
    """Well-framed CTAPHID_CBOR messages with mutated CBOR payloads."""
    from fido2 import cbor
    from fido2.hid import CTAPHID
    rng = random.Random("%d/cbor" % SEED)
    rp, user = {"id": "example.com", "name": "ex"}, {"id": b"\x01", "name": "a", "displayName": "A"}
    params = [{"alg": -7, "type": "public-key"}, {"alg": -8, "type": "public-key"}]
    cred = {"id": b"\x42" * 80, "type": "public-key"}
    seeds = [bytes([cmd]) + (cbor.encode(args) if args is not None else b"") for cmd, args in (
        (0x04, None),
        (0x06, {1: 1, 2: 2}),
        (0x06, {1: 2, 2: 3, 3: {1: 2, 3: 1, -1: 1, -2: b"\x00" * 32, -3: b"\x00" * 32}, 4: b"\x00" * 32, 5: b"\x00" * 64}),
        (0x01, {1: b"\x00" * 32, 2: rp, 3: user, 4: params}),
        (0x01, {1: b"\x00" * 32, 2: rp, 3: user, 4: params, 5: [cred], 6: {"credProtect": 3, "hmac-secret": True,
                                                                         "credBlob": b"\x01" * 32, "largeBlobKey": True},
                7: {"rk": True}, 8: b"\x00" * 32, 9: 2}),
        (0x02, {1: "example.com", 2: b"\x11" * 32}),
        (0x02, {1: "example.com", 2: b"\x11" * 32, 3: [cred], 4: {"hmac-secret": {1: {1: 2}, 2: b"\x00" * 32, 3: b"\x00" * 16}},
                5: {"up": False}}),
        (0x08, None),
        (0x0A, {1: 1, 2: {}, 3: 2, 4: b"\x00" * 32}),
        (0x0A, {1: 4, 2: {1: b"\x00" * 32}, 3: 2, 4: b"\x00" * 32}),
        (0x0C, {1: 32, 3: 0}),
        (0x0C, {2: b"\x00" * 17, 3: 0, 4: 17, 5: b"\x00" * 32, 6: 2}),
        (0x0D, {1: 3, 2: {1: 8}, 3: 2, 4: b"\x00" * 32}),
        (0x41, {1: 4, 2: {1: b"\x00" * 32}}),
        (0x0B, None),
    )]
    sent = []
    dev = ctaphid.open_device()
    for i in range(ITER):
        if i % BATCH == 0:
            target.check("cbor", sent)
            sent = []
        _, _, _, _, data = mutate(rng, (0, 0, 0, 0, rng.choice(seeds)))
        data = data[:7600]
        sent.append(data)
        try:
            dev.call(CTAPHID.CBOR, data)
        except Exception:
            target.check("cbor", sent)
            try:
                dev.close()
            except Exception:
                pass
            # A fuzzed command may have restarted the device: the emulator
            # re-executes itself (same process), its HID port is briefly closed.
            from harness.emulator import HID_PORT, _wait_port
            _wait_port(HID_PORT, 15)
            dev = ctaphid.open_device()
    dev.close()
    target.check("cbor", sent)
