"""python-fido2 HID backend talking to the emulator over TCP.

The emulator frames each 64 byte HID report with a 2 byte big-endian length.
install() makes fido2.hid.CtapHidDevice.list_devices() return the emulator.
RawCtapHid sends and receives CTAPHID frames on any channel, for transport
tests (the emulator serves one HID connection at a time: opening one closes
the previous).
"""

import os
import socket

import fido2.hid
from fido2.hid.base import CtapHidConnection, HidDescriptor

from .emulator import HID_PORT


class TcpCtapHidConnection(CtapHidConnection):
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.sock = socket.create_connection(("127.0.0.1", HID_PORT), timeout=60)

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise OSError("emulator closed the HID connection")
            buf += chunk
        return buf

    def write_packet(self, packet):
        self.sock.sendall(len(packet).to_bytes(2, "big") + packet)

    def read_packet(self):
        size = int.from_bytes(self._recv_exact(2), "big")
        return self._recv_exact(size)

    def close(self):
        self.sock.close()


def get_descriptor(path="emulator"):
    return HidDescriptor(path, 0x1D50, 0x619B, 64, 64, "LibreFido emulator", "EMU")


def list_descriptors():
    return [get_descriptor()]


def open_connection(descriptor):
    return TcpCtapHidConnection(descriptor)


def install():
    fido2.hid.list_descriptors = list_descriptors
    fido2.hid.get_descriptor = get_descriptor
    fido2.hid.open_connection = open_connection


def open_device():
    d = get_descriptor()
    return fido2.hid.CtapHidDevice(d, open_connection(d))


CID_BROADCAST = 0xFFFFFFFF
CMD_PING = 0x81
CMD_MSG = 0x83
CMD_INIT = 0x86
CMD_CBOR = 0x90
CMD_KEEPALIVE = 0xBB
CMD_ERROR = 0xBF
CMD_OTP = 0xF0          # vendor: OATH APDUs, answers carry the SW first


class RawCtapHid:
    """CTAPHID frames on any channel id (ids are 4 raw bytes, kept as ints)."""

    def __init__(self, timeout=10.0):
        self.conn = TcpCtapHidConnection(get_descriptor())
        self.conn.sock.settimeout(timeout)

    def close(self):
        self.conn.close()

    def settimeout(self, timeout):
        self.conn.sock.settimeout(timeout)

    @staticmethod
    def frames(cmd, data=b""):
        """The frames (without channel id) of one message."""
        data = bytes(data)
        out = [bytes([cmd, len(data) >> 8, len(data) & 0xFF]) + data[:57]]
        rest, seq = data[57:], 0
        while rest:
            out.append(bytes([seq]) + rest[:59])
            rest, seq = rest[59:], seq + 1
        return out

    def send_frame(self, cid, body):
        pkt = cid.to_bytes(4, "big") + bytes(body)
        self.conn.write_packet(pkt.ljust(64, b"\0"))

    def send(self, cid, cmd, data=b""):
        for f in self.frames(cmd, data):
            self.send_frame(cid, f)

    def recv_frame(self):
        """Next raw 64 byte report."""
        return self.conn.read_packet()

    def recv(self, keepalive=False):
        """Next message as (cid, cmd, data); keepalives are skipped unless
        asked for. Returns the raw reports too, as the 4th element."""
        while True:
            pkt = self.recv_frame()
            cid, cmd = int.from_bytes(pkt[:4], "big"), pkt[4]
            if cmd == CMD_KEEPALIVE and not keepalive:
                continue
            n = (pkt[5] << 8) | pkt[6]
            data, raw = pkt[7:7 + n], [pkt]
            while len(data) < n:
                c = self.recv_frame()
                raw.append(c)
                data += c[5:5 + n - len(data)]
            return cid, cmd, bytes(data), raw

    def init(self):
        """Allocates a channel (broadcast INIT)."""
        nonce = os.urandom(8)
        self.send(CID_BROADCAST, CMD_INIT, nonce)
        while True:
            cid, cmd, data, _ = self.recv()
            if cid == CID_BROADCAST and cmd == CMD_INIT and data[:8] == nonce:
                return int.from_bytes(data[8:12], "big")

    def call(self, cid, cmd, data=b""):
        """Sends a message and returns the answer's (cmd, data) on its channel."""
        self.send(cid, cmd, data)
        while True:
            rcid, rcmd, rdata, _ = self.recv()
            if rcid == cid:
                return rcmd, rdata

    def apdu(self, cid, apdu):
        """CTAPHID_MSG: returns (data, sw)."""
        cmd, data = self.call(cid, CMD_MSG, apdu)
        if cmd != CMD_MSG:
            raise OSError("CTAPHID error %s" % data.hex())
        return data[:-2], int.from_bytes(data[-2:], "big")
