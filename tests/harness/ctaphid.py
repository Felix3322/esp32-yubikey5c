"""python-fido2 HID backend talking to the emulator over TCP.

The emulator frames each 64 byte HID report with a 2 byte big-endian length.
install() makes fido2.hid.CtapHidDevice.list_devices() return the emulator.
"""

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
