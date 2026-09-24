"""librefido.backup: stream checks, file format, encryption, file writes."""

import os
import stat
import struct
import time

import pytest
from fido2 import cbor

import lfstreams as S
from librefido import backup
from librefido.backup import BackupError, parse_stream, read_file, write_file

PW = "correct horse battery staple"


# -- profile stream ------------------------------------------------------------

def test_valid_stream():
    header, records = parse_stream(S.stream(name="Work".encode()))
    assert header["name"] == "Work" and header["uuid"] == S.UUID.hex()
    s = backup.summarize(header, records)
    assert s["root_key"] and s["files"] == 2 and s["resident_credentials"] == 1 and s["counters"] == {1: 42}


def test_end_only_stream_is_an_error_not_a_crash():
    with pytest.raises(BackupError, match="header"):
        parse_stream(S.with_end(b""))
    with pytest.raises(BackupError):
        read_file(S.container(S.with_end(b"")))


@pytest.mark.parametrize("body, match", [
    (S.header(fmt=0), "format 0"),
    (S.header(fmt=2), "format 2"),
    (S.header() + S.header(), "second header"),
    (S.header() + S.record(0x03, struct.pack("<H", 0xE021) + b"x"), "never part"),        # EF_DEVROOT
    (S.header() + S.record(0x03, struct.pack("<H", 0xE020) + b"x"), "never part"),        # EF_PHY
    (S.header() + S.record(0x03, struct.pack("<H", 0xE023) + b"x"), "never part"),        # EF_PROFILE_ID
    (S.header() + S.record(0x03, struct.pack("<H", 0xFFFF) + b"x"), "never part"),
    (S.header() + S.record(0x04, bytes([16]) + bytes(4)), "counter"),
    (S.header() + S.record(0x03, struct.pack("<H", 0xCF00) + bytes(4097)), "longer than"),
    (S.header() + S.record(0x02, bytes(33)) + S.record(0x02, bytes(33)), "root key"),
    (S.header() + S.record(0x03, b"\x00\xCF") + S.record(0x03, b"\x00\xCF"), "twice"),
])
def test_stream_checks_mirror_the_firmware(body, match):
    with pytest.raises(BackupError, match=match):
        parse_stream(S.with_end(body))


def test_file_limit():
    files = [S.record(0x03, struct.pack("<H", 0x2000 + i)) for i in range(1025)]
    with pytest.raises(BackupError, match="more than 1024"):
        parse_stream(S.with_end(S.header() + b"".join(files)))
    parse_stream(S.with_end(S.header() + b"".join(files[:1024])))


def test_min_firmware():
    s = S.stream(min_fw=(2, 1, 0))
    parse_stream(s)                                     # offline: only reported
    parse_stream(s, firmware="2.1.0")
    with pytest.raises(BackupError, match="2.1.0 or newer"):
        parse_stream(s, firmware="2.0.9")
    assert backup.firmware_supports("2.10.0", "2.9.1") and not backup.firmware_supports((2, 0, 0), "2.0.1")


def test_corrupted_and_truncated_streams():
    s = bytearray(S.stream())
    s[100] ^= 1
    with pytest.raises(BackupError, match="END digest"):
        parse_stream(bytes(s))
    with pytest.raises(BackupError):
        parse_stream(S.stream()[:-5])
    with pytest.raises(BackupError, match="after the END"):
        parse_stream(S.stream() + b"\x01")


# -- files -------------------------------------------------------------------

def test_encrypted_round_trip(tmp_path):
    path = str(tmp_path / "p.lfbk")
    s = S.stream()
    write_file(path, s, PW, scrypt_log_n=10)
    info, out = read_file(path)
    assert info["encrypted"] and out is None
    info, out = read_file(path, PW, require_encryption=True)
    assert out == s and info["summary"]["files"] == 2
    with pytest.raises(BackupError, match="wrong passphrase"):
        read_file(path, "other")


def test_files_of_the_previous_version_still_open(tmp_path):
    s = S.stream()
    # written with the passphrase as typed (here not in NFC: e + combining accent)
    decomposed = "café au lait"
    blob = S.old_write(s, decomposed)
    assert read_file(blob, decomposed)[1] == s
    assert read_file(S.old_write(s, PW), PW)[1] == s
    assert read_file(S.old_write(s))[1] == s            # unencrypted


def test_passphrase_is_normalized():
    s = S.stream()
    path_bytes = []

    class Sink:
        def write(self, b):
            path_bytes.append(b)
    write_file(Sink(), s, "café", scrypt_log_n=10)
    blob = b"".join(path_bytes)
    assert read_file(blob, "café")[1] == s         # typed precomposed elsewhere
    assert read_file(blob, "café")[1] == s


def test_empty_passphrase_never_means_plaintext(tmp_path):
    path = str(tmp_path / "p.lfbk")
    with pytest.raises(BackupError, match="empty passphrase"):
        write_file(path, S.stream(), "")
    assert not os.listdir(str(tmp_path))
    write_file(path, S.stream(), None)                  # explicit: in the clear
    info, out = read_file(path)
    assert not info["encrypted"] and out == S.stream()


def test_import_can_require_encryption(tmp_path):
    plain = S.old_write(S.stream())
    with pytest.raises(BackupError, match="NOT encrypted"):
        read_file(plain, require_encryption=True)
    with pytest.raises(BackupError, match="NOT encrypted"):
        read_file(plain, PW, require_encryption=True)   # a passphrase does not make it acceptable


class _Null:
    def write(self, b):
        pass


def test_scrypt_range_for_new_files():
    for bad in (9, 21, "17", True):
        with pytest.raises(BackupError):
            write_file(_Null(), S.stream(), PW, scrypt_log_n=bad)


def _encrypted_with(params, payload=bytes(64)):
    return S.container(payload, cbor.encode(params) if isinstance(params, dict) else params, flags=1)


GOOD = {1: "scrypt", 2: bytes(16), 3: 10, 4: 8, 5: 1, 6: "chacha20-poly1305", 7: bytes(12)}


@pytest.mark.parametrize("params", [
    {**GOOD, 3: 25},                                    # 32 GiB of memory
    {**GOOD, 3: 20, 5: 2},                              # too much work in total
    {**GOOD, 5: 10000},
    {**GOOD, 4: 1024},
    {**GOOD, 3: -1},
    {**GOOD, 3: 0},
    {**GOOD, 3: "17"},
    {**GOOD, 3: True},
    {**GOOD, 7: bytes(11)},
    {**GOOD, 2: "salt"},
    {**GOOD, 1: "argon2"},
    {k: v for k, v in GOOD.items() if k != 7},
    {**GOOD, 8: 0},
    b"\x81\x01",                                        # an array
    b"\xff",                                            # not CBOR
    cbor.encode(GOOD) + b"\x00",                        # trailing data
    b"\x81" * 5000 + b"\x00",                           # deeply nested
])
def test_crafted_parameters_are_refused_before_the_kdf(params):
    t = time.time()
    with pytest.raises(BackupError, match="parameters"):
        read_file(_encrypted_with(params), PW)
    assert time.time() - t < 2


def test_valid_parameters_reach_the_authentication():
    with pytest.raises(BackupError, match="wrong passphrase"):
        read_file(_encrypted_with(GOOD), PW)


def test_header_must_match_the_stream():
    s = S.stream()
    with pytest.raises(BackupError, match="disagree"):
        read_file(S.container(s, uuid=bytes(16)))
    with pytest.raises(BackupError, match="disagree"):
        read_file(S.container(s, min_fw=(1, 0, 0)))


def test_passphrase_candidates():
    blob = S.old_write(S.stream(), "﻿secret")
    assert read_file(blob, ["secret", "﻿secret"])[1] == S.stream()
    with pytest.raises(BackupError, match="wrong passphrase"):
        read_file(blob, ["secret", "other"])


def test_device_firmware_is_checked_on_read():
    blob = S.old_write(S.stream(min_fw=(2, 1, 0)))
    read_file(blob)
    with pytest.raises(BackupError, match="2.1.0 or newer"):
        read_file(blob, firmware="2.0.0")


# -- writing -------------------------------------------------------------------

class _FakeNt:
    """_create_private_nt stand-in (the real one needs Windows): a private
    temporary file, on a volume with or without ACLs."""

    def __init__(self, acls=True, fail=False):
        self.acls, self.fail, self.made = acls, fail, []

    def __call__(self, directory, base):
        if self.fail:
            raise PermissionError("CreateFileW failed")
        import tempfile
        fd, tmp = tempfile.mkstemp(dir=directory, prefix="." + base + ".", suffix=".tmp")
        self.made.append(tmp)
        return fd, tmp, self.acls


def test_windows_file_cannot_be_created_privately(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "_WINDOWS", True)
    monkeypatch.setattr(backup, "_create_private_nt", _FakeNt(fail=True))
    with pytest.raises(BackupError, match="cannot create a private file"):
        write_file(str(tmp_path / "k.lfbk"), S.stream(), "pw", scrypt_log_n=10)
    assert not os.listdir(str(tmp_path))


def test_windows_volume_without_acls(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "_WINDOWS", True)
    monkeypatch.setattr(backup, "_create_private_nt", _FakeNt(acls=False))
    with pytest.raises(BackupError, match="unencrypted backup is not written"):
        write_file(str(tmp_path / "k.lfbk"), S.stream(), None)
    assert not os.listdir(str(tmp_path))                # the keys in the clear never went there
    notes = []
    write_file(str(tmp_path / "k.lfbk"), S.stream(), "pw", scrypt_log_n=10, warn=notes.append)
    assert os.listdir(str(tmp_path)) == ["k.lfbk"] and "cannot restrict access" in notes[0]
    with pytest.warns(backup.BackupWarning):
        write_file(str(tmp_path / "k.lfbk"), S.stream(), "pw", scrypt_log_n=10)


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs")
def test_windows_owner_only_acl(tmp_path):
    import subprocess
    path = str(tmp_path / "k.lfbk")
    write_file(path, S.stream(), None)
    acl = subprocess.run(["icacls", path], capture_output=True, text=True).stdout
    assert "OWNER RIGHTS" in acl and "Users" not in acl


# -- writing (POSIX) -------------------------------------------------------------

@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_file_is_private_and_nothing_else_is_left(tmp_path):
    path = str(tmp_path / "keys.lfbk")
    old = os.umask(0o022)
    try:
        write_file(path, S.stream(), None)
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert os.listdir(str(tmp_path)) == ["keys.lfbk"]
    # replacing a world-readable file makes it private too
    os.chmod(path, 0o644)
    write_file(path, S.stream(), PW, scrypt_log_n=10)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert os.listdir(str(tmp_path)) == ["keys.lfbk"]


def test_failed_write_leaves_no_copy_of_the_keys(tmp_path, monkeypatch):
    path = str(tmp_path / "keys.lfbk")
    with open(path, "wb") as f:
        f.write(b"previous backup")

    def fail(src, dst):
        raise PermissionError("target locked")
    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(PermissionError):
        write_file(path, S.stream(), None)
    assert os.listdir(str(tmp_path)) == ["keys.lfbk"]
    with open(path, "rb") as f:
        assert f.read() == b"previous backup"


def test_temporary_name_is_not_predictable(tmp_path):
    """A planted <file>.tmp (e.g. a symlink) is neither followed nor used."""
    path = str(tmp_path / "keys.lfbk")
    decoy = tmp_path / "keys.lfbk.tmp"
    decoy.write_bytes(b"decoy")
    write_file(path, S.stream(), None)
    assert decoy.read_bytes() == b"decoy"
    assert read_file(path)[1] == S.stream()


def test_directory_is_synced(tmp_path, monkeypatch):
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real(fd)))
    write_file(str(tmp_path / "a.lfbk"), S.stream(), None)
    assert len(synced) == (2 if os.name == "posix" else 1)     # the file, then its directory
