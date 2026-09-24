"""Profile streams and backup files built by hand, like the firmware and older
versions of the tools write them (pico-keys-sdk/src/fs/lf_backup.h)."""

import hashlib
import os
import struct

from fido2 import cbor

UUID = bytes(range(16))
SERIAL = bytes.fromhex("0011223344556677")


def record(rtype, value):
    return bytes([rtype]) + struct.pack("<H", len(value)) + value


def header(name=b"Work", fw=(2, 0, 0), min_fw=(2, 0, 0), fmt=1, uuid=UUID):
    v = b"LFBK" + struct.pack("<HH", fmt, 0) + bytes(fw) + bytes(min_fw) + uuid + SERIAL
    v += bytes.fromhex("00c000") + b"\x00" + name.ljust(24, b"\0") + bytes(8)
    assert len(v) == 74
    return record(0x01, v)


def stream(records=None, **kw):
    """A valid stream: header, root key, the given records (default: two
    files and a counter), END."""
    if records is None:
        records = [record(0x03, struct.pack("<H", 0xCF00) + b"credential"),
                   record(0x03, struct.pack("<H", 0x1100) + b"fido"),
                   record(0x04, bytes([1]) + struct.pack("<I", 42))]
    s = header(**kw) + record(0x02, b"\x00" + bytes(32)) + b"".join(records)
    return s + record(0x7F, hashlib.sha256(s).digest())


def with_end(body):
    return body + record(0x7F, hashlib.sha256(body).digest())


def container(payload, params=b"", flags=0, fw=(2, 0, 0), min_fw=(2, 0, 0), uuid=UUID, length=None):
    """A backup file around payload (encrypted or not), with any parameters."""
    head = b"LFBACKUP" + struct.pack("<HH", 1, flags) + bytes(fw) + bytes(min_fw) + uuid
    head += struct.pack("<I", len(payload) if length is None else length)
    return head + hashlib.sha256(payload).digest() + struct.pack("<H", len(params)) + params + payload


def old_write(stream_bytes, passphrase=None, log_n=10):
    """Backup file exactly as write_file() of librefido-tools 2.0.0 wrote it
    (the passphrase used as given, no normalization)."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    uuid = stream_bytes[3 + 14:3 + 30]
    fw, min_fw = stream_bytes[3 + 8:3 + 11], stream_bytes[3 + 11:3 + 14]
    if not passphrase:
        return container(stream_bytes, fw=fw, min_fw=min_fw, uuid=uuid)
    salt, nonce = os.urandom(16), os.urandom(12)
    params = cbor.encode({1: "scrypt", 2: salt, 3: log_n, 4: 8, 5: 1, 6: "chacha20-poly1305", 7: nonce})
    head = b"LFBACKUP" + struct.pack("<HH", 1, 1) + fw + min_fw + uuid + struct.pack("<I", len(stream_bytes) + 16)
    key = Scrypt(salt=salt, length=32, n=1 << log_n, r=8, p=1).derive(passphrase.encode("utf-8"))
    payload = ChaCha20Poly1305(key).encrypt(nonce, stream_bytes, head + params)
    return head + hashlib.sha256(payload).digest() + struct.pack("<H", len(params)) + params + payload
