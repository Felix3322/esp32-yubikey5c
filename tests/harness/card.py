"""Smart card access to the emulator through the user-mode pcscd (pyscard).

Card.transmit() follows ISO 7816-4: GET RESPONSE on 61xx and command
chaining for long data. YkConnection adapts it to yubikit so Yubico's own
client library (PIV/OATH/OpenPGP/Management sessions) can be pointed at the
emulator without any reader-name special casing.
"""

import time

from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException, NoCardException

from yubikit.core import TRANSPORT
from yubikit.core.smartcard import SmartCardConnection


class ApduError(Exception):
    def __init__(self, sw, data=b""):
        self.sw = sw
        self.data = data
        super().__init__("SW=%04X" % sw)


def find_reader(name="Virtual PCD", timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for r in readers():
            if str(r).startswith(name):
                c = r.createConnection()
                try:
                    c.connect()
                    return c
                except (NoCardException, CardConnectionException):
                    pass
        time.sleep(0.2)
    raise RuntimeError("no card in a reader named %r" % name)


class Card:
    def __init__(self, conn=None):
        self.conn = conn or find_reader()

    def raw(self, apdu):
        data, sw1, sw2 = self.conn.transmit(list(apdu))
        return bytes(data), (sw1 << 8) | sw2

    def transmit(self, cla, ins, p1, p2, data=b"", le=None, chain=255, check=True):
        """Sends a command (chained if needed) and collects the full response."""
        data = bytes(data)
        chunks = [data[i:i + chain] for i in range(0, len(data), chain)] or [b""]
        for i, chunk in enumerate(chunks):
            last = i == len(chunks) - 1
            apdu = bytes([cla | (0 if last else 0x10), ins, p1, p2])
            if chunk:
                apdu += bytes([len(chunk)]) + chunk
            if last and le is not None:
                apdu += bytes([le & 0xFF])
            resp, sw = self.raw(apdu)
            if not last and sw != 0x9000:
                if check:
                    raise ApduError(sw, resp)
                return resp, sw
        out = resp
        while (sw >> 8) == 0x61:
            resp, sw = self.raw(bytes([0x00, 0xC0, 0x00, 0x00, sw & 0xFF]))
            out += resp
        if check and sw != 0x9000:
            raise ApduError(sw, out)
        return out, sw

    def select(self, aid, check=True):
        return self.transmit(0x00, 0xA4, 0x04, 0x00, bytes(aid), le=0, check=check)

    def reset(self):
        """Card reset: application and security state must not survive."""
        from smartcard.scard import SCARD_RESET_CARD
        self.conn.reconnect(disposition=SCARD_RESET_CARD)

    def close(self):
        try:
            self.conn.disconnect()
        except Exception:
            pass


class YkConnection(SmartCardConnection):
    """yubikit SmartCardConnection over a harness Card."""

    def __init__(self, card):
        self.card = card

    @property
    def transport(self):
        return TRANSPORT.USB

    def send_and_receive(self, apdu):
        return self.card.raw(apdu)

    def close(self):
        pass
