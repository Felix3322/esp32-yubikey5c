"""LibreFido single-key files (".lfkey").

One key of one application (docs/KEY_TRANSFER.md) in a small, versioned
container with the protection of a backup file (librefido.backup):

    offset  size  field
    0       8     magic "LFKEYFIL"
    8       2     file format version (LE), currently 1
    10      2     flags (LE): bit 0 = payload encrypted
    12      4     payload length (LE)
    16      32    SHA-256 of the payload as stored
    48      2     length L of the parameters (LE)
    50      L     parameters, CBOR (only when encrypted), as in a backup file:
                    1: "scrypt", 2: salt, 3: log2(N), 4: r, 5: p,
                    6: "chacha20-poly1305", 7: nonce
    50+L    ...   payload: the CBOR below, or ChaCha20-Poly1305 of it with
                  the header bytes 0..15 and the parameters as associated data

The payload is the CBOR map {1: "librefido-key", 2: 1 (payload format),
3: application name, 4: record, 5: {1: created (unix time), 2: firmware of
the source device, 3: label, 4: tool version}}; the records are those of
the management applet's KEY_EXPORT (integer keys, docs/KEY_TRANSFER.md).

As with backups, only an encrypted file is authenticated: readers expect
one unless the user explicitly accepts a file in the clear.
"""

import hashlib
import os
import struct
import time

from fido2 import cbor

from . import __version__
from .backup import (SCRYPT_LOG_N, SCRYPT_LOG_N_WRITE, SCRYPT_P, SCRYPT_R, BackupError, _kdf, _passphrase_forms,
                     _scrypt_params, _write_private)
from .policy import APPS

MAGIC = b"LFKEYFIL"
FILE_VERSION = 1
F_ENCRYPTED = 0x0001
HEADER_LEN = 50
PAYLOAD_TAG = "librefido-key"
PAYLOAD_FORMAT = 1
# One key with its certificate is a few KiB; anything much larger is no key file.
MAX_FILE = 256 * 1024
SUFFIX = ".lfkey"

META_NAMES = {1: "created", 2: "firmware", 3: "label", 4: "tool"}
META_KEYS = {v: k for k, v in META_NAMES.items()}

# Record fields (docs/KEY_TRANSFER.md) the host checks before a record goes
# anywhere: presence and type; the values are the device's to check.
_BYTES, _TEXT, _UINT, _INT, _BOOL, _MAP = bytes, str, "uint", int, bool, dict
_FIELDS = {
    "fido": {1: (_TEXT, True), 2: (_BYTES, True), 3: (_BYTES, True), 4: (_TEXT, False), 5: (_TEXT, False),
             6: (_INT, True), 7: (_INT, True), 8: (_BYTES, True), 9: (_UINT, False), 10: (_BYTES, False),
             11: (_BYTES, False), 12: (_BYTES, False), 13: (_BOOL, False), 14: (_UINT, False),
             15: (_UINT, False), 16: (_BOOL, False)},
    "oath": {1: (_BYTES, True), 2: (_UINT, True), 3: (_UINT, True), 4: (_BYTES, True), 5: (_UINT, False),
             6: (_BOOL, False)},
    "otp": {1: (_UINT, True), 2: (_BYTES, True), 3: (_BYTES, True), 4: (_TEXT, False)},
    "openpgp": {1: (_UINT, False), 2: (_BYTES, True), 3: (_MAP, True), 4: (_BYTES, True), 5: (_UINT, True),
                6: (_BYTES, False)},
    "piv": {1: (_UINT, False), 2: (_UINT, True), 3: (_MAP, True), 4: (_UINT, False), 5: (_UINT, False),
            8: (_BYTES, False)},
}


class KeyFileError(BackupError):
    """A key file or record that cannot be used (a BackupError, so callers
    handling backup files handle these alike)."""


def _typed(value, kind):
    if kind == _UINT:
        return type(value) is int and value >= 0
    if kind == _INT:
        return type(value) is int
    return isinstance(value, kind)


def check_record(app, record):
    """Raises KeyFileError when record is not a record of application app
    (a name of APPS): a map with the fields the contract requires for it,
    each of its type, and the private key map of an OpenPGP / PIV record
    either RSA {1: e, 2: p, 3: q} or EC {6: private, 7: public}."""
    if app not in APPS:
        raise KeyFileError("unknown application %r" % (app,))
    if not isinstance(record, dict) or not all(type(k) is int for k in record):
        raise KeyFileError("the %s record is not a map with integer keys" % app)
    for key, (kind, required) in _FIELDS[app].items():
        if key not in record:
            if required:
                raise KeyFileError("this is not a %s key: field %d is missing" % (app, key))
            continue
        if not _typed(record[key], kind):
            raise KeyFileError("this is not a %s key: field %d has the wrong type" % (app, key))
    if app == "oath" and not 1 <= len(record[1]) <= 64:
        raise KeyFileError("OATH name of %d bytes (1 to 64)" % len(record[1]))
    # the type/algorithm byte, digits and counter go to the device as a byte,
    # a byte and at most 8 bytes (YKOATH PUT)
    if app == "oath" and (record[2] > 0xFF or record[3] > 0xFF or record.get(5, 0) >= 1 << 64):
        raise KeyFileError("malformed OATH account (type, digits or HOTP counter out of range)")
    if app == "otp" and (record[1] not in (1, 2) or len(record[2]) != 52 or len(record[3]) != 8):
        raise KeyFileError("malformed OTP slot record")
    if app == "openpgp" and len(record[4]) != 20:
        raise KeyFileError("OpenPGP fingerprint of %d bytes (20)" % len(record[4]))
    if app in ("openpgp", "piv"):
        k = record[3]
        rsa, ec = set(k) >= {1, 2, 3}, 6 in k
        if rsa == ec or not all(isinstance(k[i], bytes) and k[i] for i in ((1, 2, 3) if rsa else (6,))) \
                or (ec and not isinstance(k.get(7, b""), bytes)):
            raise KeyFileError("malformed %s private key" % ("OpenPGP" if app == "openpgp" else "PIV"))


class SingleKey:
    """One key of one application: app (a name of APPS), record (the map of
    docs/KEY_TRANSFER.md, integer keys), meta (dict with any of "created"
    (unix time), "firmware" (of the source device), "label", "tool"; the
    file's integer-keyed form is taken too). The record holds the secret:
    it is never part of repr()."""

    def __init__(self, app, record, meta=None):
        if type(app) is int and 0 <= app < len(APPS):
            app = APPS[app]
        if app not in APPS:
            raise KeyFileError("unknown application %r" % (app,))
        self.app = app
        self.record = record
        self.meta = {}
        for k, v in (meta or {}).items():
            name = META_NAMES.get(k, k)
            if name in META_KEYS:
                self.meta[name] = v

    def __repr__(self):
        return "SingleKey(%r, label=%r)" % (self.app, self.meta.get("label"))


def _payload(key):
    meta = {"created": int(time.time()), "tool": __version__}
    meta.update({k: v for k, v in key.meta.items() if v is not None})
    m = {}
    for name, v in meta.items():
        want = int if name == "created" else str
        if not isinstance(v, want) or isinstance(v, bool):
            raise KeyFileError("key file metadata %r has the wrong type" % name)
        m[META_KEYS[name]] = v
    return cbor.encode({1: PAYLOAD_TAG, 2: PAYLOAD_FORMAT, 3: key.app, 4: key.record, 5: m})


def write_key_file(path_or_file, key, passphrase=None, warn=None, scrypt_log_n=SCRYPT_LOG_N):
    """Writes key (a SingleKey) to a key file, encrypted with passphrase.
    None writes the key in the clear, which must be the user's explicit
    choice (an empty passphrase is refused, it never means "no encryption").
    A path is written privately and atomically (backup._write_private);
    warn(message) reports what the user must know about the written file.
    Returns the file size."""
    if passphrase is not None and not isinstance(passphrase, str):
        raise TypeError("passphrase must be a str or None")
    if passphrase == "":
        raise KeyFileError("empty passphrase (a key file in the clear must be asked for explicitly)")
    if type(scrypt_log_n) is not int or not SCRYPT_LOG_N_WRITE[0] <= scrypt_log_n <= SCRYPT_LOG_N_WRITE[1]:
        raise KeyFileError("scrypt log2(N) must be %d..%d" % SCRYPT_LOG_N_WRITE)
    check_record(key.app, key.record)
    payload = _payload(key)
    params, flags = b"", 0
    if passphrase is not None:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        salt, nonce = os.urandom(16), os.urandom(12)
        params = cbor.encode({1: "scrypt", 2: salt, 3: scrypt_log_n, 4: SCRYPT_R, 5: SCRYPT_P,
                              6: "chacha20-poly1305", 7: nonce})
        flags |= F_ENCRYPTED
        head = MAGIC + struct.pack("<HHI", FILE_VERSION, flags, len(payload) + 16)
        payload = ChaCha20Poly1305(_kdf(passphrase, salt, scrypt_log_n, SCRYPT_R, SCRYPT_P)).encrypt(
            nonce, payload, head + params)
    else:
        head = MAGIC + struct.pack("<HHI", FILE_VERSION, flags, len(payload))
    blob = head + hashlib.sha256(payload).digest() + struct.pack("<H", len(params)) + params + payload
    if hasattr(path_or_file, "write"):
        path_or_file.write(blob)
    else:
        _write_private(path_or_file, blob, plaintext=passphrase is None, warn=warn)
    return len(blob)


def _read_blob(path_or_bytes):
    if isinstance(path_or_bytes, (bytes, bytearray)):
        return bytes(path_or_bytes)
    with open(path_or_bytes, "rb") as f:
        blob = f.read(MAX_FILE + 1)
    if len(blob) > MAX_FILE:
        raise KeyFileError("not a LibreFido key file (larger than %d KiB)" % (MAX_FILE // 1024))
    return blob


def is_key_file(data):
    """Whether data (bytes) starts like a key file."""
    return bytes(data[:8]) == MAGIC


def read_key_file(path_or_bytes, passphrase=None, require_encryption=False):
    """Reads and fully verifies a key file. Returns (info, key): key is a
    SingleKey, or None when the file is encrypted and no passphrase was
    given. passphrase may also be a list of candidates, tried in order (as
    backup.read_file). require_encryption refuses a file in the clear:
    nothing authenticates its content."""
    blob = _read_blob(path_or_bytes)
    if len(blob) < HEADER_LEN or blob[:8] != MAGIC:
        raise KeyFileError("not a LibreFido key file")
    version, flags, length = struct.unpack_from("<HHI", blob, 8)
    if version > FILE_VERSION:
        raise KeyFileError("key file version %d is newer than this tool" % version)
    if version < 1 or flags & ~F_ENCRYPTED:
        raise KeyFileError("not a LibreFido key file (version %d, flags %04X)" % (version, flags))
    encrypted = bool(flags & F_ENCRYPTED)
    if require_encryption and not encrypted:
        raise KeyFileError("the key file is NOT encrypted, so nothing proves it was not replaced "
                           "(accept unencrypted key files explicitly if you made it without a passphrase)")
    digest = blob[16:48]
    (plen,) = struct.unpack_from("<H", blob, 48)
    params_raw = blob[HEADER_LEN:HEADER_LEN + plen]
    payload = blob[HEADER_LEN + plen:]
    if len(params_raw) != plen or len(payload) != length:
        raise KeyFileError("key file is truncated")
    if hashlib.sha256(payload).digest() != digest:
        raise KeyFileError("key file is corrupted (SHA-256 mismatch)")
    if not encrypted and plen:
        raise KeyFileError("malformed key file (parameters without encryption)")
    info = {"file_version": version, "encrypted": encrypted, "sha256": digest.hex()}
    if encrypted:
        if passphrase is None:
            return info, None
        payload = _decrypt(blob[:16], params_raw, payload, passphrase)
    key = _parse_payload(payload)
    info.update({"app": key.app, **key.meta})
    return info, key


def _decrypt(head, params_raw, payload, passphrase):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    try:
        salt, log_n, r, p, nonce = _scrypt_params(params_raw)
    except BackupError as e:
        raise KeyFileError(str(e))
    candidates = [passphrase] if isinstance(passphrase, str) else list(passphrase)
    secrets = []
    for i, candidate in enumerate(candidates):
        for form in (_passphrase_forms(candidate) if i == 0 else [candidate.encode("utf-8")]):
            if form not in secrets:
                secrets.append(form)
    for secret in secrets:
        try:
            k = _kdf(secret, salt, log_n, r, p)
        except (MemoryError, ValueError) as e:
            raise KeyFileError("key derivation failed: %s" % e)
        try:
            return ChaCha20Poly1305(k).decrypt(nonce, payload, head + params_raw)
        except InvalidTag:
            pass
    raise KeyFileError("wrong passphrase, or the key file was modified")


def _parse_payload(payload):
    try:
        m = cbor.decode(payload)
    except Exception as e:                  # malformed or deeply nested CBOR
        raise KeyFileError("malformed key file content (%s)" % e.__class__.__name__)
    if not isinstance(m, dict) or m.get(1) != PAYLOAD_TAG or type(m.get(2)) is not int:
        raise KeyFileError("not a LibreFido key file (unknown content)")
    if m[2] > PAYLOAD_FORMAT:
        raise KeyFileError("the key file content (format %d) is newer than this tool" % m[2])
    if m.get(3) not in APPS:
        raise KeyFileError("key file for an unknown application %r" % (m.get(3),))
    meta = m.get(5, {})
    if not isinstance(meta, dict):
        raise KeyFileError("malformed key file metadata")
    check_record(m[3], m.get(4))
    return SingleKey(m[3], m[4], {k: v for k, v in meta.items() if k in META_NAMES and
                                  isinstance(v, int if k == 1 else str) and not isinstance(v, bool)})


__all__ = ["SingleKey", "KeyFileError", "check_record", "read_key_file", "write_key_file", "is_key_file", "MAGIC",
           "SUFFIX"]
