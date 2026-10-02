"""
The FIDO PIN check of the management applet (profile export, firmware
update): a PIN that cannot be right (none, or not 4..63 bytes) is refused
with 6982 before the retry counter is touched.
"""

import pytest
from fido2.ctap2 import ClientPin

from lf_fido_helpers import PIN, ctap2, fresh

MGMT_AID = b"\xF0LIBREFIDO"
CLA, INS_EXPORT_BEGIN, INS_EXPORT_END = 0x80, 0x20, 0x22


def export_begin(card, pin):
    card.select(MGMT_AID)
    _, sw = card.transmit(CLA, INS_EXPORT_BEGIN, 0, 0, pin, le=0, check=False)
    if sw == 0x9000:
        card.transmit(CLA, INS_EXPORT_END, 0, 0, b"", le=0, check=False)
    return sw


def retries(device):
    return ClientPin(ctap2(device)).get_pin_retries()[0]


def test_impossible_pin_uses_no_retry(device, card):
    fresh(device)
    assert retries(device) == 8
    for pin in (b"", b"123", b"x" * 64):
        for _ in range(4):
            assert export_begin(card, pin) == 0x6982
    assert retries(device) == 8
    # a wrong PIN of a possible length still costs a retry
    assert export_begin(card, b"87654321") == 0x63C7
    assert retries(device) == 7
    assert export_begin(card, PIN.encode()) == 0x9000
    assert retries(device) == 8
