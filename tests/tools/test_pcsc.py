"""librefido.pcsc.Card.transaction: exclusive access around multi-APDU
operations, without changing how the card is left (SCARD_LEAVE_CARD)."""

import pytest
from smartcard import scard as sc
from smartcard.Exceptions import CardConnectionException

from librefido import pcsc


class Conn:
    """pyscard connection stand-in: a decorator around the PC/SC connection."""

    class Inner:
        hcard = 0x1234

    def __init__(self):
        self.component = self.Inner()
        self.apdus = []
        self.reconnected = []

    def transmit(self, apdu):
        self.apdus.append(bytes(apdu))
        return [], 0x90, 0x00

    def reconnect(self, protocol=None, mode=None, disposition=None):
        self.reconnected.append(disposition)


class Scard:
    def __init__(self):
        self.calls = []
        self.results = []

    def begin(self, h):
        self.calls.append(("begin", h))
        return self.results.pop(0) if self.results else sc.SCARD_S_SUCCESS

    def end(self, h, disposition):
        self.calls.append(("end", h, disposition))
        return sc.SCARD_S_SUCCESS


@pytest.fixture
def scard(monkeypatch):
    s = Scard()
    monkeypatch.setattr(pcsc, "SCardBeginTransaction", s.begin)
    monkeypatch.setattr(pcsc, "SCardEndTransaction", s.end)
    return s


def test_transaction_locks_selects_and_nests(scard):
    conn = Conn()
    card = pcsc.Card(conn, "r")
    with card.transaction(pcsc.MGMT_AID):
        assert scard.calls == [("begin", 0x1234)]
        assert pcsc.MGMT_AID in conn.apdus[0]           # SELECT once the card is locked
        with card.transaction(b"\xA0\x00"):             # nested: no second lock, no second SELECT
            card.transmit(0x80, 0x01, 0, 0)
        assert len(scard.calls) == 1 and len(conn.apdus) == 2
    assert scard.calls[-1] == ("end", 0x1234, sc.SCARD_LEAVE_CARD)


def test_transaction_ends_on_errors(scard):
    card = pcsc.Card(Conn(), "r")
    with pytest.raises(ValueError):
        with card.transaction():
            raise ValueError("boom")
    assert [c[0] for c in scard.calls] == ["begin", "end"]
    assert card._locked == 0


def test_lock_refused(scard):
    scard.results.append(sc.SCARD_E_SHARING_VIOLATION)
    card = pcsc.Card(Conn(), "r")
    with pytest.raises(CardConnectionException, match="exclusive access"):
        with card.transaction():
            pass
    assert card._locked == 0 and [c[0] for c in scard.calls] == ["begin"]


def test_reset_when_the_session_could_not_be_ended(scard):
    card = pcsc.Card(Conn(), "r")
    with card.transaction():
        with card.transaction():
            card.mark_reset()
    assert scard.calls[-1] == ("end", 0x1234, sc.SCARD_RESET_CARD)
    with card.transaction():                            # only that once
        pass
    assert scard.calls[-1] == ("end", 0x1234, sc.SCARD_LEAVE_CARD)


def test_reset_card_is_acknowledged(scard):
    scard.results.append(sc.SCARD_W_RESET_CARD)
    conn = Conn()
    card = pcsc.Card(conn, "r")
    with card.transaction():
        pass
    assert conn.reconnected == [sc.SCARD_LEAVE_CARD]
    assert [c[0] for c in scard.calls] == ["begin", "begin", "end"]


def test_apdu_error_message():
    assert str(pcsc.ApduError(0x63C3, "export")) == "export: wrong PIN, 3 tries left (SW 63C3)"
    e = pcsc.ApduError(0x6F00, message="the device went back")
    assert str(e) == "the device went back" and e.sw == 0x6F00
