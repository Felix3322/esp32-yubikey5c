"""PIN retry counters of OpenPGP (PW1) and PIV (PIN) are counted before the
PIN is compared, in a commit of their own: cutting the power when an answer
comes late never gives a wrong guess back, and a right guess cannot be told
from a wrong one before the attempt is durable.

Power cuts are injected by the emulator (lf_region.c): LF_FAULT_CTL names a
control file that the next boot reads; "tear <region> <n>" kills the process
at the n-th erase/write of that region.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tools/librefido python -m pytest tests/openpgp/test_pin_retry_durable.py
"""

import os
import time

import pytest

from harness.card import Card
from harness.emulator import Emulator, Pcscd

OPENPGP_AID = bytes.fromhex("D27600012401")
PIV_AID = bytes.fromhex("A000000308")
REG_STORE0 = 3                  # the profile store region (lf_region.c)


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    yield p
    p.stop()


@pytest.fixture
def device(pcscd, tmp_path):
    ctl = str(tmp_path / "dev" / "fault.ctl")
    e = Emulator(workdir=str(tmp_path / "dev"), env={"LF_FAULT_CTL": ctl})
    e.fault_ctl = ctl
    e.pcscd = pcscd
    try:
        yield e
    finally:
        e.stop()


def boot(e):
    from librefido.pcsc import open_device
    e.start()
    open_device(timeout=15).close()


def sw(card, *args, **kw):
    return card.transmit(*args, check=False, **kw)[1]


def status(aid, p2):
    """Retry counter from VERIFY without data (63Cx)."""
    card = Card()
    try:
        card.select(aid)
        s = sw(card, 0x00, 0x20, 0x00, p2)
        assert s & 0xFFF0 == 0x63C0, hex(s)
        return s & 0xF
    finally:
        card.close()


CASES = [
    (OPENPGP_AID, 0x82, b"123456", b"000000"),          # OpenPGP PW1
    (PIV_AID, 0x80, b"123456\xff\xff", b"000000\xff\xff"),  # PIV PIN
]


@pytest.mark.parametrize("aid,p2,right,wrong", CASES, ids=["openpgp-pw1", "piv-pin"])
def test_wrong_guess_survives_a_power_cut(device, aid, p2, right, wrong):
    e = device
    boot(e)
    assert status(aid, p2) == 3                         # provisioned by the first selection
    card = Card()
    try:
        card.select(aid)
        assert sw(card, 0x00, 0x20, 0x00, p2, wrong) == 0x63C2
    finally:
        card.close()
    e.stop(hard=True)                                   # power cut right after the answer
    boot(e)
    assert status(aid, p2) == 2


@pytest.mark.parametrize("aid,p2,right,wrong", CASES, ids=["openpgp-pw1", "piv-pin"])
def test_no_answer_before_the_attempt_is_durable(device, aid, p2, right, wrong):
    """The first store write of VERIFY is the retry counter, before the PIN
    is compared, for the right PIN as well: when that write is cut, no
    answer (not even 9000) has been given, and the counter is untouched."""
    e = device
    boot(e)
    assert status(aid, p2) == 3
    e.stop()
    with open(e.fault_ctl, "w") as f:
        f.write("tear %d 0" % REG_STORE0)               # cut at the next store write
    boot(e)
    answered = None
    card = Card()
    try:
        card.select(aid)                                # nothing to write: provisioned
        try:
            answered = card.transmit(0x00, 0x20, 0x00, p2, right, check=False)[1]
        except Exception:
            pass
    finally:
        card.close()
    deadline = time.time() + 10
    while e.proc.poll() is None and time.time() < deadline:
        time.sleep(0.05)
    assert e.proc.poll() is not None, "the retry counter was not written"
    assert answered is None, "answered %04X before the attempt was durable" % answered
    e.proc = None
    e._log.close()
    # the reader lost the card in the middle of a command: a fresh pcscd
    e.pcscd.stop()
    e.pcscd.start()
    boot(e)
    assert status(aid, p2) == 3                          # the cut write never happened
    card = Card()
    try:
        card.select(aid)
        assert sw(card, 0x00, 0x20, 0x00, p2, right) == 0x9000
        assert sw(card, 0x00, 0x20, 0x00, p2) == 0x9000
    finally:
        card.close()
    assert status(aid, p2) == 3                          # a right PIN puts it back


def test_blocked_pin_is_not_compared(device):
    e = device
    boot(e)
    card = Card()
    try:
        card.select(OPENPGP_AID)
        for left in (2, 1):
            assert sw(card, 0x00, 0x20, 0x00, 0x81, b"000000") == 0x63C0 | left
        assert sw(card, 0x00, 0x20, 0x00, 0x81, b"000000") == 0x6983
        assert sw(card, 0x00, 0x20, 0x00, 0x81, b"123456") == 0x6983     # the right PIN too
    finally:
        card.close()
