"""PC/SC transport to the LibreFido management applet.

PC/SC (CCID) works for unprivileged programs on Windows, macOS and Linux,
unlike raw FIDO HID access (Windows reserves FIDO HID devices for its WebAuthn
service), so every management operation goes through the smart card
interface.
"""

import time

from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException, NoCardException

# Proprietary, unregistered AID (ISO/IEC 7816-5 category F).
MGMT_AID = b"\xF0LIBREFIDO"

SW_MESSAGES = {
    0x6982: "security status not satisfied",
    0x6983: "PIN blocked",
    0x6984: "data invalid (backup rejected by the device)",
    0x6985: "conditions not satisfied (touch the key when it blinks, or finish the pending operation)",
    0x6986: "not allowed (export disabled for this profile or build)",
    0x6A80: "incorrect parameters",
    0x6A84: "not enough space",
    0x6A86: "incorrect P1/P2",
    0x6A88: "not found",
    0x6D00: "instruction not supported (firmware too old?)",
    0x6E00: "class not supported",
    0x6F00: "internal error",
}


class ApduError(Exception):
    def __init__(self, sw, what=""):
        self.sw = sw
        msg = SW_MESSAGES.get(sw)
        if msg is None and (sw & 0xFFF0) == 0x63C0:
            msg = "wrong PIN, %d tries left" % (sw & 0xF)
        super().__init__("%s%s (SW %04X)" % (what + ": " if what else "", msg or "error", sw))


class Card:
    """One card connection with ISO 7816-4 chaining and GET RESPONSE."""

    def __init__(self, connection, reader_name):
        self.conn = connection
        self.reader = reader_name

    def transmit(self, cla, ins, p1, p2, data=b"", le=0, check=True, what=""):
        data = bytes(data)
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
        out = bytes(resp)
        while (sw >> 8) == 0x61:
            resp, sw1, sw2 = self.conn.transmit([0x00, 0xC0, 0x00, 0x00, sw & 0xFF])
            sw = (sw1 << 8) | sw2
            out += bytes(resp)
        if check and sw != 0x9000:
            raise ApduError(sw, what)
        return out, sw

    def select(self, aid):
        return self.transmit(0x00, 0xA4, 0x04, 0x00, aid, le=0, what="select")

    def close(self):
        try:
            self.conn.disconnect()
        except Exception:
            pass


def list_devices():
    """(reader name, SELECT answer) of every connected LibreFido device."""
    found = []
    for r in readers():
        c = r.createConnection()
        try:
            c.connect()
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


def open_device(reader=None, timeout=0.0):
    """Connects to the management applet (the first device, or reader).
    timeout > 0 waits for a device to (re)appear, e.g. after a reboot."""
    deadline = time.time() + timeout
    while True:
        for r in readers():
            if reader and not str(r).startswith(reader):
                continue
            c = r.createConnection()
            try:
                c.connect()
            except (NoCardException, CardConnectionException):
                continue
            card = Card(c, str(r))
            try:
                card.select(MGMT_AID)
                return card
            except (ApduError, CardConnectionException):
                card.close()
        if time.time() >= deadline:
            raise RuntimeError("no LibreFido device found%s" % (" in reader %r" % reader if reader else ""))
        time.sleep(0.25)
