"""LibreFido backup files.

A backup file wraps the profile stream produced by the device (see
pico-keys-sdk/src/fs/lf_backup.h) in a small, versioned container:

    offset  size  field
    0       8     magic "LFBACKUP"
    8       2     file format version (LE), currently 1
    10      2     flags (LE): bit 0 = payload encrypted
    12      3     firmware version that produced the stream
    15      3     oldest firmware able to import it
    18      16    profile UUID
    34      4     payload length (LE)
    38      32    SHA-256 of the payload as stored
    70      2     length L of the parameters (LE)
    72      L     parameters, CBOR (only when encrypted):
                    1: "scrypt", 2: salt, 3: log2(N), 4: r, 5: p,
                    6: "chacha20-poly1305", 7: nonce
    72+L    ...   payload: the stream, or ChaCha20-Poly1305(stream) with the
                  header bytes 0..37 and the parameters as associated data

The plaintext header lets any tool check integrity (SHA-256) and identify the
profile without the passphrase. Readers accept every older file version.
"""

import hashlib
import os
import struct

from fido2 import cbor

MAGIC = b"LFBACKUP"
FILE_VERSION = 1
F_ENCRYPTED = 0x0001

REC_HEADER, REC_ROOTKEY, REC_FILE, REC_COUNTER, REC_END = 0x01, 0x02, 0x03, 0x04, 0x7F
STREAM_FORMAT = 1
HEADER_LEN = 74

# Default passphrase stretching: scrypt N=2^17, r=8, p=1 (128 MiB, ~0.5 s).
SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P = 17, 8, 1


class BackupError(Exception):
    pass


# ----------------------------------------------------------------------------
# Profile stream (device format)
# ----------------------------------------------------------------------------

def parse_stream(stream):
    """Validates a profile stream exactly like the firmware does and returns
    its header fields and records. Raises BackupError."""
    if len(stream) < 3:
        raise BackupError("stream too short")
    pos, records, header, end = 0, [], None, False
    fids = set()
    while pos < len(stream):
        if end:
            raise BackupError("data after the END record")
        if len(stream) - pos < 3:
            raise BackupError("truncated record header")
        rtype, rlen = stream[pos], struct.unpack_from("<H", stream, pos + 1)[0]
        value = stream[pos + 3:pos + 3 + rlen]
        if len(value) != rlen:
            raise BackupError("truncated record")
        if rtype == REC_END:
            if rlen != 32 or hashlib.sha256(stream[:pos]).digest() != value:
                raise BackupError("END digest mismatch: the stream is corrupted")
            end = True
        elif header is None:
            if rtype != REC_HEADER or rlen != HEADER_LEN or value[:4] != b"LFBK":
                raise BackupError("stream does not start with a LibreFido header")
            header = decode_header(value)
            if header["format"] > STREAM_FORMAT:
                raise BackupError("stream format %d is newer than this tool" % header["format"])
        elif rtype == REC_ROOTKEY:
            if rlen != 33 or any(r[0] == REC_ROOTKEY for r in records):
                raise BackupError("bad root key record")
        elif rtype == REC_FILE:
            if rlen < 2:
                raise BackupError("bad file record")
            fid = struct.unpack_from("<H", value)[0]
            if fid in fids:
                raise BackupError("file %04X appears twice" % fid)
            fids.add(fid)
        elif rtype == REC_COUNTER:
            if rlen != 5:
                raise BackupError("bad counter record")
        else:
            raise BackupError("unknown record type %02X (written by newer firmware?)" % rtype)
        records.append((rtype, value))
        pos += 3 + rlen
    if not end:
        raise BackupError("stream has no END record (incomplete)")
    return header, records


def decode_header(v):
    fmt, flags = struct.unpack_from("<HH", v, 4)
    return {
        "format": fmt,
        "flags": flags,
        "migration": bool(flags & 1),
        "firmware": "%d.%d.%d" % tuple(v[8:11]),
        "min_firmware": "%d.%d.%d" % tuple(v[11:14]),
        "uuid": v[14:30].hex(),
        "serial": v[30:38].hex().upper(),
        "color": v[38:41].hex(),
        "profile_flags": v[41],
        "name": v[42:66].split(b"\0", 1)[0].decode("utf-8", "replace"),
    }


def _app_of(fid):
    if 0xCF00 <= fid <= 0xCFFF:
        return "fido_resident_credentials"
    if 0xD000 <= fid <= 0xD0FF:
        return "fido_relying_parties"
    if fid in (0xCC00, 0xCC01, 0xCC0F, 0xCE00, 0xCE01, 0xC000, 0xC001, 0x1080, 0x1090, 0x1091,
               0x1100, 0x1101, 0x1102, 0x1122):
        return "fido"
    if 0xBA00 <= fid <= 0xBAFE:
        return "oath_credentials"
    if fid == 0xBAFF or fid == 0x10A0:
        return "oath"
    if 0xBB00 <= fid <= 0xBB03:
        return "otp_slots"
    if fid in (0x1184, 0x1185) or 0xFF00 <= fid <= 0xFF15 or 0x0082 <= fid <= 0x0095 or 0x009A <= fid <= 0x009E \
            or 0xCE00 < fid < 0xCF00:
        return "piv"
    if 0x1081 <= fid <= 0x1099 or 0x10C1 <= fid <= 0x10D6 or fid < 0x0100 or 0x1F21 <= fid <= 0x1F23 \
            or fid in (0x5F2D, 0x5F35, 0x5F50, 0x5F52, 0x7F21, 0x7F66, 0x7F74):
        return "openpgp"
    if fid in (0xE022,):
        return "system"
    return "other"


def summarize(header, records):
    files = [struct.unpack_from("<H", v)[0] for t, v in records if t == REC_FILE]
    apps = {}
    for fid in files:
        apps[_app_of(fid)] = apps.get(_app_of(fid), 0) + 1
    counters = {v[0]: struct.unpack_from("<I", v, 1)[0] for t, v in records if t == REC_COUNTER}
    return {
        "header": header,
        "root_key": any(t == REC_ROOTKEY for t, _ in records),
        "files": len(files),
        "by_application": apps,
        "resident_credentials": apps.get("fido_resident_credentials", 0),
        "oath_credentials": apps.get("oath_credentials", 0),
        "counters": counters,
        "stream_bytes": sum(3 + len(v) for _, v in records),
    }


# ----------------------------------------------------------------------------
# Backup file
# ----------------------------------------------------------------------------

def _kdf(passphrase, salt, log_n, r, p):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=1 << log_n, r=r, p=p).derive(passphrase.encode("utf-8"))


def write_file(path_or_file, stream, passphrase=None, scrypt_log_n=SCRYPT_LOG_N):
    """Writes a backup file. The stream is validated first."""
    header, _ = parse_stream(stream)
    fw = bytes(int(x) for x in header["firmware"].split("."))
    min_fw = bytes(int(x) for x in header["min_firmware"].split("."))
    params = b""
    payload = stream
    flags = 0
    if passphrase:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        salt, nonce = os.urandom(16), os.urandom(12)
        params = cbor.encode({1: "scrypt", 2: salt, 3: scrypt_log_n, 4: SCRYPT_R, 5: SCRYPT_P,
                              6: "chacha20-poly1305", 7: nonce})
        flags |= F_ENCRYPTED
        head = MAGIC + struct.pack("<HH", FILE_VERSION, flags) + fw + min_fw + bytes.fromhex(header["uuid"])
        head += struct.pack("<I", len(stream) + 16)
        key = _kdf(passphrase, salt, scrypt_log_n, SCRYPT_R, SCRYPT_P)
        payload = ChaCha20Poly1305(key).encrypt(nonce, stream, head + params)
    else:
        head = MAGIC + struct.pack("<HH", FILE_VERSION, flags) + fw + min_fw + bytes.fromhex(header["uuid"])
        head += struct.pack("<I", len(payload))
    blob = head + hashlib.sha256(payload).digest() + struct.pack("<H", len(params)) + params + payload
    if hasattr(path_or_file, "write"):
        path_or_file.write(blob)
    else:
        tmp = path_or_file + ".tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path_or_file)       # never leaves a half written backup
    return len(blob)


def read_file(path_or_bytes, passphrase=None):
    """Reads and fully verifies a backup file. Returns (info, stream); stream is
    None when the file is encrypted and no passphrase was given."""
    blob = path_or_bytes if isinstance(path_or_bytes, (bytes, bytearray)) else open(path_or_bytes, "rb").read()
    blob = bytes(blob)
    if len(blob) < 72 or blob[:8] != MAGIC:
        raise BackupError("not a LibreFido backup file")
    version, flags = struct.unpack_from("<HH", blob, 8)
    if version > FILE_VERSION:
        raise BackupError("backup file version %d is newer than this tool" % version)
    (length,) = struct.unpack_from("<I", blob, 34)
    digest = blob[38:70]
    (plen,) = struct.unpack_from("<H", blob, 70)
    params_raw = blob[72:72 + plen]
    payload = blob[72 + plen:]
    if len(params_raw) != plen or len(payload) != length:
        raise BackupError("backup file is truncated")
    if hashlib.sha256(payload).digest() != digest:
        raise BackupError("backup file is corrupted (SHA-256 mismatch)")
    info = {
        "file_version": version,
        "encrypted": bool(flags & F_ENCRYPTED),
        "firmware": "%d.%d.%d" % tuple(blob[12:15]),
        "min_firmware": "%d.%d.%d" % tuple(blob[15:18]),
        "uuid": blob[18:34].hex(),
        "sha256": digest.hex(),
    }
    if flags & F_ENCRYPTED:
        if passphrase is None:
            return info, None
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        params = cbor.decode(params_raw)
        if params.get(1) != "scrypt" or params.get(6) != "chacha20-poly1305":
            raise BackupError("unsupported encryption parameters")
        key = _kdf(passphrase, params[2], params[3], params[4], params[5])
        try:
            stream = ChaCha20Poly1305(key).decrypt(params[7], payload, blob[:38] + params_raw)
        except InvalidTag:
            raise BackupError("wrong passphrase, or the backup was modified")
    else:
        stream = payload
    header, records = parse_stream(stream)
    if header["uuid"] != info["uuid"]:
        raise BackupError("file header and stream disagree on the profile")
    info["summary"] = summarize(header, records)
    return info, stream
