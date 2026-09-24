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

Only an encrypted file is authenticated: the SHA-256 of an unencrypted one can
be recomputed by whoever changes it, so imports expect encrypted files unless
the user explicitly accepts an unencrypted one (read_file(require_encryption)).
"""

import hashlib
import os
import struct
import tempfile
import unicodedata
import warnings

from fido2 import cbor

MAGIC = b"LFBACKUP"
FILE_VERSION = 1
F_ENCRYPTED = 0x0001

REC_HEADER, REC_ROOTKEY, REC_FILE, REC_COUNTER, REC_END = 0x01, 0x02, 0x03, 0x04, 0x7F
STREAM_FORMAT = 1
HEADER_LEN = 74

# Limits of the firmware's import check (pico-keys-sdk/src/fs/lf_backup.c).
REC_MAX = 2 + 4096                  # longest record value (a file of one sector)
MAX_FILES = 1024
CTR_MAX_IDS = 16                    # LF_CTR_MAX_IDS
NOT_EXPORTED = (0xE020, 0xE021, 0xE023, 0x0000, 0xFFFF)     # EF_PHY, EF_DEVROOT, EF_PROFILE_ID, invalid

# Default passphrase stretching: scrypt N=2^17, r=8, p=1 (128 MiB, ~0.5 s).
SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P = 17, 8, 1
# What write_file() accepts for log2(N), and what read_file() accepts from a
# file before the passphrase is checked: at most 1 GiB and a few seconds, so
# a crafted file cannot exhaust memory or CPU.
SCRYPT_LOG_N_WRITE = (10, 20)
SCRYPT_LOG_N_READ = (1, 20)
SCRYPT_MAX_COST = (1 << 20) * 8     # N * r * p


class BackupError(Exception):
    pass


class BackupWarning(UserWarning):
    pass


def _default_warn(message):
    warnings.warn(message, BackupWarning, stacklevel=3)


def version_tuple(v):
    """(major, minor, patch) from "x.y.z" or a sequence."""
    if isinstance(v, str):
        v = v.split(".")
    return tuple(int(x) for x in v)


def firmware_supports(firmware, min_firmware):
    """True when a device running firmware can import a stream that needs
    min_firmware (both "x.y.z" or tuples)."""
    return version_tuple(min_firmware) <= version_tuple(firmware)


# ----------------------------------------------------------------------------
# Profile stream (device format)
# ----------------------------------------------------------------------------

def parse_stream(stream, firmware=None):
    """Validates a profile stream with the checks the firmware makes before it
    imports one (lf_backup_check) and returns its header fields and records.
    firmware, the version of the target device, also checks that it can
    import the stream (otherwise the minimum version is only reported). The
    device additionally checks what depends on its build: that the profile
    fits its storage, and that no file is one its applications keep outside
    the store; only its check (Management.check_backup) is final. Raises
    BackupError."""
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
        if rlen > REC_MAX:
            raise BackupError("record of %d bytes is longer than the firmware accepts" % rlen)
        value = stream[pos + 3:pos + 3 + rlen]
        if len(value) != rlen:
            raise BackupError("truncated record")
        if header is None:
            # The header comes first, even before END.
            if rtype != REC_HEADER or rlen != HEADER_LEN or value[:4] != b"LFBK":
                raise BackupError("stream does not start with a LibreFido header")
            header = decode_header(value)
            if header["format"] != STREAM_FORMAT:
                raise BackupError("stream format %d is not supported (this tool reads format %d)"
                                  % (header["format"], STREAM_FORMAT))
            if firmware is not None and not firmware_supports(firmware, header["min_firmware"]):
                raise BackupError("the backup needs firmware %s or newer (the device runs %s)"
                                  % (header["min_firmware"], ".".join(str(x) for x in version_tuple(firmware))))
        elif rtype == REC_END:
            if rlen != 32 or hashlib.sha256(stream[:pos]).digest() != value:
                raise BackupError("END digest mismatch: the stream is corrupted")
            end = True
        elif rtype == REC_HEADER:
            raise BackupError("second header record")
        elif rtype == REC_ROOTKEY:
            if rlen != 33 or any(r[0] == REC_ROOTKEY for r in records):
                raise BackupError("bad root key record")
        elif rtype == REC_FILE:
            if rlen < 2:
                raise BackupError("bad file record")
            fid = struct.unpack_from("<H", value)[0]
            if fid in NOT_EXPORTED:
                raise BackupError("file %04X is never part of a backup" % fid)
            if fid in fids:
                raise BackupError("file %04X appears twice" % fid)
            if len(fids) == MAX_FILES:
                raise BackupError("more than %d files" % MAX_FILES)
            fids.add(fid)
        elif rtype == REC_COUNTER:
            if rlen != 5 or value[0] >= CTR_MAX_IDS:
                raise BackupError("bad counter record")
        else:
            raise BackupError("unknown record type %02X (written by newer firmware?)" % rtype)
        records.append((rtype, value))
        pos += 3 + rlen
    if header is None or not end:
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

def _passphrase_forms(passphrase):
    """UTF-8 forms of a passphrase to derive the key from. New files use
    Unicode NFC, so the same passphrase typed on any system (or read from a
    file) gives the same key; files written before NFC was applied used the
    string as given, which is tried second when it differs."""
    nfc = unicodedata.normalize("NFC", passphrase)
    forms = [nfc.encode("utf-8")]
    if nfc != passphrase:
        forms.append(passphrase.encode("utf-8"))
    return forms


def _kdf(secret, salt, log_n, r, p):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    if isinstance(secret, str):
        secret = _passphrase_forms(secret)[0]
    return Scrypt(salt=salt, length=32, n=1 << log_n, r=r, p=p).derive(secret)


def _fsync_dir(directory):
    """Makes a rename in directory durable (POSIX; a no-op elsewhere)."""
    if os.name != "posix":
        return
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass                                # not supported by this file system
    finally:
        os.close(fd)


_WINDOWS = os.name == "nt"
# Protected DACL: full access for OWNER RIGHTS and SYSTEM, nothing inherited.
OWNER_ONLY_SDDL = "D:P(A;;FA;;;OW)(A;;FA;;;SY)"


def _create_private_nt(directory, base):
    """Windows: creates a new temporary file in directory that carries an
    owner-only ACL from the moment it exists (CreateFileW with a security
    descriptor, CREATE_NEW) and that nobody else can open while it is written
    (no sharing). Returns (fd, path, acls): acls is False on a volume that
    keeps no ACLs (FAT, exFAT), where no file can be restricted. Raises
    OSError when the file cannot be created that way."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    to_sd = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    to_sd.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                      ctypes.POINTER(wintypes.ULONG)]
    to_sd.restype = wintypes.BOOL
    create = kernel32.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(SECURITY_ATTRIBUTES),
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    volinfo = kernel32.GetVolumeInformationByHandleW
    volinfo.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
                        wintypes.DWORD]
    volinfo.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    GENERIC_WRITE, CREATE_NEW, FILE_ATTRIBUTE_NORMAL = 0x40000000, 1, 0x80
    ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS, FILE_PERSISTENT_ACLS = 80, 183, 0x8
    invalid = ctypes.c_void_p(-1).value

    sd = ctypes.c_void_p()
    if not to_sd(OWNER_ONLY_SDDL, 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)
        for _ in range(16):
            tmp = os.path.join(directory, ".%s.%s.tmp" % (base, os.urandom(8).hex()))
            h = create(tmp, GENERIC_WRITE, 0, ctypes.byref(sa), CREATE_NEW, FILE_ATTRIBUTE_NORMAL, None)
            if h is not None and h != invalid:
                break
            err = ctypes.get_last_error()
            if err not in (ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS):
                raise ctypes.WinError(err)
        else:
            raise FileExistsError("no free temporary file name in %s" % directory)
    finally:
        kernel32.LocalFree(sd)
    try:
        flags = wintypes.DWORD(0)
        acls = bool(volinfo(h, None, 0, None, None, ctypes.byref(flags), None, 0)) and \
            bool(flags.value & FILE_PERSISTENT_ACLS)
        fd = msvcrt.open_osfhandle(h, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    except BaseException:
        kernel32.CloseHandle(h)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return fd, tmp, acls


def _write_private(path, blob, plaintext=False, warn=None):
    """Writes blob to path atomically and privately: a new temporary file in
    the same directory with a random name, created exclusively and private
    from the start (mode 0600 on POSIX; on Windows an owner-only ACL set at
    creation and no sharing while it is written), synced to disk and renamed
    over path, then the directory is synced. On any failure the temporary
    file is removed, so no partial copy of the keys is left behind.
    On a Windows volume without ACLs (FAT, exFAT) nothing can restrict the
    file: plaintext (the keys in the clear) is refused there, an encrypted
    backup is written and warn(message) is called."""
    path = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(path))
    base = os.path.basename(path)
    if _WINDOWS:
        try:
            fd, tmp, acls = _create_private_nt(directory, base)
        except OSError as e:
            raise BackupError("cannot create a private file in %s (%s)" % (directory, e))
        if not acls:
            msg = "the drive of %s cannot restrict access to files (no ACLs, e.g. FAT/exFAT)" % directory
            if plaintext:
                os.close(fd)
                os.unlink(tmp)
                raise BackupError(msg + ": an unencrypted backup is not written there; use an NTFS drive "
                                        "or a passphrase")
            (warn or _default_warn)(msg + ": anyone with access to it can copy the encrypted backup")
    else:
        fd, tmp = tempfile.mkstemp(dir=directory, prefix="." + base + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            fd = None
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(directory)


def write_file(path_or_file, stream, passphrase=None, scrypt_log_n=SCRYPT_LOG_N, warn=None):
    """Writes a backup file; the stream is validated first. It is encrypted
    with passphrase; None writes the keys in the clear, which must be the
    user's explicit choice (an empty passphrase is refused, it never means
    "no encryption"). A path is written with _write_private(); warn(message)
    reports what the user must know about the written file (default: a
    BackupWarning)."""
    if passphrase is not None and not isinstance(passphrase, str):
        raise TypeError("passphrase must be a str or None")
    if passphrase == "":
        raise BackupError("empty passphrase (an unencrypted backup must be asked for explicitly)")
    if type(scrypt_log_n) is not int or not SCRYPT_LOG_N_WRITE[0] <= scrypt_log_n <= SCRYPT_LOG_N_WRITE[1]:
        raise BackupError("scrypt log2(N) must be %d..%d" % SCRYPT_LOG_N_WRITE)
    header, _ = parse_stream(stream)
    fw = bytes(version_tuple(header["firmware"]))
    min_fw = bytes(version_tuple(header["min_firmware"]))
    params = b""
    payload = stream
    flags = 0
    if passphrase is not None:
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
        _write_private(path_or_file, blob, plaintext=passphrase is None, warn=warn)
    return len(blob)


def _scrypt_params(params_raw):
    """Encryption parameters of a file, checked before any work is done with
    them (they are not authenticated until the passphrase is)."""
    try:
        params = cbor.decode(params_raw)
    except Exception as e:                  # malformed or deeply nested CBOR
        raise BackupError("malformed encryption parameters (%s)" % e.__class__.__name__)
    if not isinstance(params, dict) or set(params) != {1, 2, 3, 4, 5, 6, 7}:
        raise BackupError("malformed encryption parameters")
    salt, log_n, r, p, nonce = params[2], params[3], params[4], params[5], params[7]
    if (params[1] != "scrypt" or params[6] != "chacha20-poly1305"
            or not isinstance(salt, bytes) or len(salt) != 16
            or not isinstance(nonce, bytes) or len(nonce) != 12
            or type(log_n) is not int or not SCRYPT_LOG_N_READ[0] <= log_n <= SCRYPT_LOG_N_READ[1]
            or type(r) is not int or not 1 <= r <= SCRYPT_R
            or type(p) is not int or not 1 <= p <= 16
            or (1 << log_n) * r * p > SCRYPT_MAX_COST):
        raise BackupError("unsupported encryption parameters")
    return salt, log_n, r, p, nonce


def read_file(path_or_bytes, passphrase=None, require_encryption=False, firmware=None):
    """Reads and fully verifies a backup file. Returns (info, stream); stream is
    None when the file is encrypted and no passphrase was given.
    passphrase may also be a list of candidates, tried in order (the first
    also in Unicode NFC, the others as given: the ways older versions of the
    tool derived a passphrase from the same input, see
    cli.legacy_passphrases).
    require_encryption refuses an unencrypted file: nothing authenticates its
    content, anyone who could write it could have replaced it.
    firmware: the version of the device the stream is meant for (it must be
    able to import it, see parse_stream)."""
    if isinstance(path_or_bytes, (bytes, bytearray)):
        blob = bytes(path_or_bytes)
    else:
        with open(path_or_bytes, "rb") as f:
            blob = f.read()
    if len(blob) < 72 or blob[:8] != MAGIC:
        raise BackupError("not a LibreFido backup file")
    version, flags = struct.unpack_from("<HH", blob, 8)
    if version > FILE_VERSION:
        raise BackupError("backup file version %d is newer than this tool" % version)
    if require_encryption and not flags & F_ENCRYPTED:
        raise BackupError("the backup is NOT encrypted, so nothing proves it was not replaced "
                          "(accept unencrypted backups explicitly if you made it without a passphrase)")
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
        salt, log_n, r, p, nonce = _scrypt_params(params_raw)
        stream = None
        candidates = [passphrase] if isinstance(passphrase, str) else list(passphrase)
        secrets = []
        for i, candidate in enumerate(candidates):
            for form in (_passphrase_forms(candidate) if i == 0 else [candidate.encode("utf-8")]):
                if form not in secrets:
                    secrets.append(form)
        for secret in secrets:
            try:
                key = _kdf(secret, salt, log_n, r, p)
            except (MemoryError, ValueError) as e:
                raise BackupError("key derivation failed: %s" % e)
            try:
                stream = ChaCha20Poly1305(key).decrypt(nonce, payload, blob[:38] + params_raw)
                break
            except InvalidTag:
                pass
        if stream is None:
            raise BackupError("wrong passphrase, or the backup was modified")
    else:
        stream = payload
    header, records = parse_stream(stream, firmware)
    if (header["uuid"], header["firmware"], header["min_firmware"]) != \
            (info["uuid"], info["firmware"], info["min_firmware"]):
        raise BackupError("file header and stream disagree on the profile or its firmware")
    info["summary"] = summarize(header, records)
    return info, stream
