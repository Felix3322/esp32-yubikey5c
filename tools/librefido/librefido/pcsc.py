"""PC/SC transport to the LibreFido management applet.

PC/SC (CCID) works for unprivileged programs on Windows, macOS and Linux,
unlike raw FIDO HID access (Windows reserves FIDO HID devices for its WebAuthn
service), so every management operation goes through the smart card
interface.
"""

import time
from contextlib import contextmanager

from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException, NoCardException
from smartcard.scard import (SCARD_LEAVE_CARD, SCARD_RESET_CARD, SCARD_S_SUCCESS, SCARD_W_RESET_CARD,
                             SCardBeginTransaction, SCardEndTransaction, SCardGetErrorMessage)

# Proprietary, unregistered AID (ISO/IEC 7816-5 category F).
MGMT_AID = b"\xF0LIBREFIDO"

SW_MESSAGES = {
    0x6982: "security status not satisfied",
    0x6983: "PIN blocked",
    0x6984: "data invalid (backup rejected by the device)",
    0x6985: "conditions not satisfied (touch the key when it blinks, or finish the pending operation)",
    0x6986: "not allowed (by this profile, e.g. a secure one, or this build)",
    0x6A80: "incorrect parameters",
    0x6A81: "not supported by this device",
    0x6A84: "not enough space",
    0x6A86: "incorrect P1/P2",
    0x6A88: "not found",
    0x6D00: "instruction not supported (firmware too old?)",
    0x6E00: "class not supported",
    0x6F00: "internal error",
}


class ApduError(Exception):
    """Status word sw from the device; message replaces the text derived from
    it (for errors the host detects itself)."""

    def __init__(self, sw, what="", message=None):
        self.sw = sw
        if message is None:
            msg = SW_MESSAGES.get(sw)
            if msg is None and (sw & 0xFFF0) == 0x63C0:
                msg = "wrong PIN, %d tries left" % (sw & 0xF)
            message = "%s%s (SW %04X)" % (what + ": " if what else "", msg or "error", sw)
        super().__init__(message)


class Card:
    """One card connection with ISO 7816-4 chaining and GET RESPONSE."""

    def __init__(self, connection, reader_name):
        self.conn = connection
        self.reader = reader_name
        self.boot_id = None     # changes whenever the device restarts
        self.protocol = None    # management protocol (SELECT answer byte 2)
        self.extended = False   # extended-length APDUs work (probed by select())
        self._locked = 0        # nesting depth of transaction()
        self._lock_handle = None
        self._reset = False     # end the transaction with a card reset (mark_reset)

    def _handle(self):
        """SCARDHANDLE of the pyscard connection (under its decorators)."""
        c = self.conn
        while not hasattr(c, "hcard") and hasattr(c, "component"):
            c = c.component
        return getattr(c, "hcard", None)

    def mark_reset(self):
        """The transaction in progress ends with a card reset instead of
        leaving the card as it is: the device then drops whatever session
        the host could not end with a command (the application is unloaded
        before any other client's APDU)."""
        self._reset = True

    @contextmanager
    def transaction(self, aid=None):
        """Exclusive use of the device for a multi-APDU operation
        (SCardBeginTransaction): no other PC/SC client of this reader can send
        APDUs until the block ends, so none can read an export stream or slip
        chunks into an upload of this session. It does not lock the key's
        other interfaces (the WinUSB/WebUSB smart card interface, FIDO HID);
        from management protocol 2 on the export ID keeps them from reading
        an export. aid is selected first, as another client may have selected
        another application in between. Nests; the card stays powered when it
        ends (SCARD_LEAVE_CARD) unless mark_reset() was called. Do not prompt
        the user inside (a touch the device waits for is fine: the APDU is in
        progress): Windows resets a card whose transaction is idle for more
        than 5 seconds."""
        if self._locked == 0:
            h = self._handle()
            if h is None:
                raise CardConnectionException("not connected")
            hr = SCardBeginTransaction(h)
            if hr == SCARD_W_RESET_CARD and hasattr(self.conn, "reconnect"):
                # Reset by another program: the handle must acknowledge it
                # (and keeps leaving the card powered when it disconnects).
                self.conn.reconnect(disposition=SCARD_LEAVE_CARD)
                h = self._handle()
                hr = SCardBeginTransaction(h)
            if hr != SCARD_S_SUCCESS:
                raise CardConnectionException("cannot get exclusive access to the device: %s"
                                              % SCardGetErrorMessage(hr), hresult=hr)
            self._lock_handle = h
            self._reset = False
        self._locked += 1
        try:
            if aid is not None and self._locked == 1:
                self.select(aid)
            yield self
        finally:
            self._locked -= 1
            if self._locked == 0:
                h, self._lock_handle = self._lock_handle, None
                disposition, self._reset = (SCARD_RESET_CARD if self._reset else SCARD_LEAVE_CARD), False
                try:
                    SCardEndTransaction(h, disposition)     # fails harmlessly once the device restarted
                except Exception:
                    pass

    def _extended(self, cla, ins, p1, p2, data, le):
        apdu = [cla, ins, p1, p2, 0, len(data) >> 8, len(data) & 0xFF] + list(data)
        if le is not None:
            apdu += [0, 0]
        resp, sw1, sw2 = self.conn.transmit(apdu)
        return bytes(resp), (sw1 << 8) | sw2

    def transmit(self, cla, ins, p1, p2, data=b"", le=0, check=True, what=""):
        data = bytes(data)
        if len(data) > 255 and self.extended:
            # One round trip instead of a chain of short APDUs.
            resp, sw = self._extended(cla, ins, p1, p2, data, le)
            return self._finish(resp, sw, check, what)
        chunks = [data[i:i + 255] for i in range(0, len(data), 255)] or [b""]
        for i, chunk in enumerate(chunks):
            last = i == len(chunks) - 1
            apdu = [cla | (0 if last else 0x10), ins, p1, p2]
            if chunk:
                apdu += [len(chunk)] + list(chunk)
            if last and le is not None:
                apdu.append(le & 0xFF)
            resp, sw1, sw2 = self.conn.transmit(apdu)
            sw = (sw1 << 8) | sw2
            if not last and sw != 0x9000:
                if check:
                    raise ApduError(sw, what)
                return bytes(resp), sw
        return self._finish(bytes(resp), sw, check, what)

    def _finish(self, out, sw, check, what):
        while (sw >> 8) == 0x61:
            resp, sw1, sw2 = self.conn.transmit([0x00, 0xC0, 0x00, 0x00, sw & 0xFF])
            sw = (sw1 << 8) | sw2
            out += bytes(resp)
        if check and sw != 0x9000:
            raise ApduError(sw, what)
        return out, sw

    def select(self, aid):
        # SELECT has no side effects, so it doubles as the probe for
        # extended-length support (reader driver and card): a refusal or a
        # transport error just means short APDUs with chaining.
        try:
            resp, sw = self._extended(0x00, 0xA4, 0x04, 0x00, bytes(aid), 0)
            if sw == 0x9000 or (sw >> 8) == 0x61:
                self.extended = True
                return self._finish(resp, sw, True, "select")
        except CardConnectionException:
            pass
        self.extended = False
        return self.transmit(0x00, 0xA4, 0x04, 0x00, aid, le=0, what="select")

    def close(self):
        try:
            self.conn.disconnect()
        except Exception:
            pass


def _connect(r):
    """Shared connection that leaves the card powered on disconnect: pyscard
    unpowers it by default, which resets the card under every other session
    (another program, or this one's open management session)."""
    c = r.createConnection()
    c.connect(disposition=SCARD_LEAVE_CARD)
    return c


def list_devices():
    """(reader name, SELECT answer) of every connected LibreFido device."""
    found = []
    for r in readers():
        try:
            c = _connect(r)
        except (NoCardException, CardConnectionException):
            continue
        card = Card(c, str(r))
        try:
            answer, _ = card.select(MGMT_AID)
            found.append((str(r), answer))
        except (ApduError, CardConnectionException):
            pass
        finally:
            card.close()
    return found


def open_device(reader=None, timeout=0.0, not_boot_id=None):
    """Connects to the management applet (the first device, or reader).
    timeout > 0 waits for a device to (re)appear, e.g. after a reboot;
    not_boot_id skips a device instance that has not restarted yet."""
    deadline = time.time() + timeout
    while True:
        for r in readers():
            if reader and not str(r).startswith(reader):
                continue
            try:
                c = _connect(r)
            except (NoCardException, CardConnectionException):
                continue
            card = Card(c, str(r))
            try:
                answer, _ = card.select(MGMT_AID)
                card.boot_id = answer[4:8] if len(answer) >= 8 else None
                card.protocol = answer[2] if len(answer) >= 3 and answer[:2] == b"LF" else None
                if not_boot_id is not None and card.boot_id == not_boot_id:
                    card.close()
                    continue
                return card
            except (ApduError, CardConnectionException):
                card.close()
        if time.time() >= deadline:
            raise RuntimeError("no LibreFido device found%s" % (" in reader %r" % reader if reader else ""))
        time.sleep(0.25)
