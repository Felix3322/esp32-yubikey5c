"""librefido command line: passphrases, explicit plaintext, PIN prompts,
profile numbers, single keys (list, export, import)."""

import argparse
import base64
import datetime
import functools
import getpass
import io
import json
import os
import sys
import urllib.parse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID
from fido2 import cbor

import fakedev as F
import lfstreams as S
from librefido import cli, keyfile, keyio, mgmt, stdformats
from librefido.backup import read_file, write_file
from librefido.keyfile import SingleKey, read_key_file
from librefido.pcsc import MGMT_AID


@pytest.fixture
def device(monkeypatch):
    """Simulated device behind Management.open(); dev.opened counts sessions."""
    dev = F.FakeDevice(stream=S.stream())
    dev.opened = 0

    def open_(cls, reader=None, timeout=0.0):
        dev.opened += 1
        return F.management(dev, monkeypatch)
    monkeypatch.setattr(mgmt.Management, "open", classmethod(open_))
    return dev


class Prompts(list):
    pass


@pytest.fixture
def ask(monkeypatch):
    p = Prompts()
    p.answers = []
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": (p.append(prompt), p.answers.pop(0))[1])
    return p


def args(**kw):
    return argparse.Namespace(**kw)


# -- passphrases ---------------------------------------------------------------

def test_passphrase_file_is_utf8_without_bom_and_line_end(tmp_path):
    f = tmp_path / "pw"
    f.write_bytes("﻿pässwörd 密码\r\nsecond line\n".encode("utf-8"))
    assert cli._passphrase(args(passphrase_file=str(f)), confirm=True) == "pässwörd 密码"
    f.write_bytes(b"  spaces kept \n")
    assert cli._passphrase(args(passphrase_file=str(f)), confirm=True) == "  spaces kept "
    f.write_bytes(b"\xff\xfe not utf-8")
    with pytest.raises(SystemExit, match="UTF-8"):
        cli._passphrase(args(passphrase_file=str(f)), confirm=False)


@pytest.mark.parametrize("content", [b"", b"\n", b"\r\n", b"\xef\xbb\xbf\n"])
def test_export_refuses_an_empty_passphrase_file(tmp_path, device, content):
    pw = tmp_path / "pw"
    pw.write_bytes(content)
    out = tmp_path / "out.lfbk"
    with pytest.raises(SystemExit, match="empty passphrase"):
        cli.main(["export", str(out), "--passphrase-file", str(pw), "--no-pin"])
    assert not out.exists() and device.opened == 0


def test_export_refuses_an_empty_typed_passphrase(tmp_path, device, ask):
    ask.answers += ["", ""]
    with pytest.raises(SystemExit, match="empty passphrase"):
        cli.main(["export", str(tmp_path / "out.lfbk")])
    assert device.opened == 0


def test_export_encrypted_and_plaintext(tmp_path, device, ask, capsys):
    pw = tmp_path / "pw"
    pw.write_text("secret\n", encoding="utf-8")
    out = str(tmp_path / "enc.lfbk")
    cli.main(["export", out, "--passphrase-file", str(pw)])
    assert not ask                                      # no PIN on this profile: not asked
    info, stream = read_file(out, "secret")
    assert info["encrypted"] and stream == S.stream()
    out = str(tmp_path / "plain.lfbk")
    cli.main(["export", out, "--no-encrypt"])
    assert not read_file(out)[0]["encrypted"]
    assert "NOT encrypted" in capsys.readouterr().out


def test_export_asks_for_the_pin_when_the_profile_has_one(tmp_path, device, ask):
    device.pin = "1234"
    ask.answers.append("1234")
    cli.main(["export", str(tmp_path / "p.lfbk"), "--no-encrypt"])
    assert ask == ["FIDO PIN of the active profile: "]
    ask.answers.append("")
    with pytest.raises(SystemExit, match="FIDO PIN"):
        cli.main(["export", str(tmp_path / "q.lfbk"), "--no-encrypt"])
    assert device.retries == 8                          # no attempt was spent


def test_backups_of_the_previous_version_open_with_the_same_passphrase_file(tmp_path, device, capsys):
    """librefido-tools 2.0.0 read --passphrase-file with open() (the locale's
    encoding) and kept a UTF-8 BOM: the same file still opens its backups."""
    pw = tmp_path / "pw"
    pw.write_bytes("﻿secret\r\n".encode("utf-8"))
    old = tmp_path / "old.lfbk"
    old.write_bytes(S.old_write(S.stream(), "﻿secret"))       # what 2.0.0 derived on Linux
    cli.main(["verify", str(old), "--passphrase-file", str(pw)])
    assert S.UUID.hex() in capsys.readouterr().out
    # a new backup from the same file uses the passphrase without the BOM
    new = tmp_path / "new.lfbk"
    cli.main(["export", str(new), "--passphrase-file", str(pw)])
    assert read_file(str(new), "secret")[1] == S.stream()


def test_backups_of_the_previous_version_on_a_chinese_windows(tmp_path, device, monkeypatch, capsys):
    """There the old reader decoded the file with the ANSI code page (GBK)."""
    raw = "密码".encode("utf-8")                         # saved as UTF-8 by an editor
    pw = tmp_path / "pw"
    pw.write_bytes(raw + b"\n")
    mojibake = raw.decode("gbk")
    assert mojibake != "密码"
    old = tmp_path / "old.lfbk"
    old.write_bytes(S.old_write(S.stream(), mojibake))
    monkeypatch.setattr(cli.locale, "getpreferredencoding", lambda do_setlocale=True: "cp936")
    cli.main(["verify", str(old), "--passphrase-file", str(pw)])
    assert S.UUID.hex() in capsys.readouterr().out
    assert cli.legacy_passphrases(str(pw))[0] == mojibake


def test_legacy_candidates():
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\xef\xbb\xbfabc\rdef")
    try:
        assert "﻿abc" in cli.legacy_passphrases(f.name)
    finally:
        os.unlink(f.name)


# -- import --------------------------------------------------------------------

def test_import_refuses_an_unencrypted_backup(tmp_path, device):
    path = str(tmp_path / "plain.lfbk")
    write_file(path, S.stream(), None)
    with pytest.raises(SystemExit, match="NOT encrypted"):
        cli.main(["import", path, "--profile", "2"])
    assert device.opened == 0
    cli.main(["import", path, "--profile", "2", "--allow-unencrypted"])
    assert device.last_result == 2


def test_import_of_an_encrypted_backup(tmp_path, device, capsys):
    path = str(tmp_path / "enc.lfbk")
    write_file(path, S.stream(), "pw", scrypt_log_n=10)
    pw = tmp_path / "pw"
    pw.write_text("pw", encoding="utf-8")
    cli.main(["import", path, "--profile", "1", "--passphrase-file", str(pw)])
    err = capsys.readouterr().err
    assert "REPLACE profile 1 (Profile 1, the active one)" in err and "UUID %s" % S.UUID.hex() in err


# -- firmware ------------------------------------------------------------------

def test_firmware_update_asks_for_the_pin_only_when_set(tmp_path, device, ask):
    img = tmp_path / "fw.bin"
    img.write_bytes(F.image((2, 0, 1)))
    cli.main(["firmware", "update", str(img), "-y"])
    assert not ask and device.version == (2, 0, 1)
    device.pin = "123456"
    img.write_bytes(F.image((2, 0, 2)))
    ask.answers.append("123456")
    cli.main(["firmware", "update", str(img), "-y"])
    assert ask == ["FIDO PIN of the active profile: "] and device.version == (2, 0, 2)
    assert device.retries == 8


def test_firmware_update_without_file(device):
    with pytest.raises(SystemExit, match="image file"):
        cli.main(["firmware", "update", "-y"])


# -- profiles ------------------------------------------------------------------

@pytest.mark.parametrize("argv", [["profile", "wipe"], ["profile", "delete"], ["profile", "select"],
                                  ["profile", "slots"], ["profile", "set", "--name", "x"],
                                  ["profile", "delete", "5"], ["profile", "wipe", "0"]])
def test_profile_number_is_required(device, argv):
    with pytest.raises(SystemExit):
        cli.main(argv)
    assert device.opened == 0


def test_long_name_is_shortened_visibly(device, capsys):
    cli.main(["profile", "set", "1", "--name", "我的工作安全密钥"])
    assert "shortened to '我的工作安全密'" in capsys.readouterr().err
    assert F.commands(device, mgmt.INS_PROFILE_SET)[-1][3] == b"\xa1\x01\x75" + "我的工作安全密".encode()


def test_rollback_asks_for_the_pin(device, ask):
    device.pin = "1234"
    ask.answers.append("1234")
    cli.main(["firmware", "rollback"])
    assert ask == ["FIDO PIN of the active profile: "] and device.retries == 8


@pytest.mark.parametrize("argv", [["profile", "select", "1"], ["profile", "wipe", "1"], ["profile", "delete", "1"],
                                  ["profile", "list"]])
def test_safe_mode_is_a_clear_refusal(device, argv):
    device.boot_status = 2                              # system area unreadable: no profiles in INFO
    with pytest.raises(SystemExit, match="safe mode"):
        cli.main(argv)


def test_import_in_safe_mode_asks_for_no_passphrase(tmp_path, device, ask):
    device.boot_status = 1
    path = str(tmp_path / "enc.lfbk")
    write_file(path, S.stream(), "pw", scrypt_log_n=10)
    with pytest.raises(SystemExit, match="safe mode"):
        cli.main(["import", path, "--profile", "1"])
    assert not ask                                      # nothing decrypted for a device that refuses


def test_min_firmware_is_checked_against_the_device(tmp_path, device, ask, capsys):
    path = str(tmp_path / "new.lfbk")
    write_file(path, S.stream(min_fw=(2, 2, 0)), "pw", scrypt_log_n=10)     # newer than this tool too
    with pytest.raises(SystemExit, match="runs firmware 2.0.0; this backup needs 2.2.0"):
        cli.main(["import", path, "--profile", "2"])
    assert not ask and not F.commands(device, mgmt.INS_IMPORT_BEGIN)
    ask.answers.append("pw")
    with pytest.raises(SystemExit, match="runs firmware 2.0.0"):
        cli.main(["verify", path, "--device"])
    ask.answers.append("pw")
    cli.main(["verify", path])                          # offline: a warning about this tool only
    assert "this tool knows" in capsys.readouterr().err


def test_pin_asked_when_the_device_wants_it(tmp_path, device, ask):
    """Key store locked: getInfo says no PIN, the device asks for one."""
    device.pin = "1234"
    device.store_locked = True
    ask.answers.append("1234")
    cli.main(["export", str(tmp_path / "p.lfbk"), "--no-encrypt"])
    assert ask == ["FIDO PIN of the active profile: "] and device.retries == 8
    assert read_file(str(tmp_path / "p.lfbk"))[1] == S.stream()


def test_import_into_the_active_profile_asks_for_the_pin(tmp_path, device, ask):
    device.protocol, device.pin = 3, "1234"
    path = str(tmp_path / "p.lfbk")
    write_file(path, S.stream(), None)
    ask.answers.append("1234")
    cli.main(["import", path, "--profile", "1", "--allow-unencrypted"])
    assert ask == ["FIDO PIN of the active profile: "] and device.last_result == 2 and device.retries == 8


def test_pin_from_a_file_never_from_the_command_line(tmp_path, device, ask):
    device.pin = "1234"
    pin = tmp_path / "pin"
    pin.write_text("1234\n", encoding="utf-8")
    cli.main(["export", str(tmp_path / "p.lfbk"), "--no-encrypt", "--pin-file", str(pin)])
    assert not ask
    with pytest.raises(SystemExit):
        cli.main(["export", str(tmp_path / "q.lfbk"), "--no-encrypt", "--pin", "1234"])   # no PIN in argv


def test_names_from_the_device_are_escaped(device, capsys):
    device.names[0] = "\x1b[19Dfill 3 (empty"
    cli.main(["profile", "wipe", "1"])
    err = capsys.readouterr().err
    assert "\x1b" not in err and "\\x1b[19Dfill 3 (empty" in err
    cli.main(["profile", "list"])
    assert "\x1b" not in capsys.readouterr().out


def test_presence_command(device, capsys):
    device.protocol = 3
    cli.main(["presence", "1"])
    assert "fido: touch" in capsys.readouterr().out
    cli.main(["presence", "1", "--fido", "--oath"])
    out = capsys.readouterr()
    assert device.presence[0] == 0b11 and "fido: no touch" in out.out and "warning" in out.err
    cli.main(["presence", "1", "--no-fido"])
    assert device.presence[0] == 0b10
    cli.main(["presence", "1", "--all"])
    assert device.presence[0] == 0x1F
    cli.main(["presence", "1", "--no-all", "--piv"])
    assert device.presence[0] == 0x10
    with pytest.raises(SystemExit):
        cli.main(["presence", "5", "--fido"])


def test_board_and_info(device, capsys):
    device.protocol = 3
    cli.main(["board", "--led-brightness", "40"])
    assert device.led == 40 and "led_brightness: 40" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="0..255"):
        cli.main(["board", "--led-brightness", "300"])
    device.presence[0], device.secure[2], device.used[2] = 0b1, True, True
    cli.main(["info"])
    out = capsys.readouterr().out
    assert "protection_level: 0 / 3" in out and "auto_presence" in out and "secure: True" in out
    assert "led_brightness: 40" in out
    cli.main(["--json", "info"])
    import json
    assert json.loads(capsys.readouterr().out)["protection_level"] == 0
    cli.main(["profile", "list"])
    out = capsys.readouterr().out
    assert "[no touch: fido]" in out and "[secure]" in out


def test_create_secure_profile(device, capsys, monkeypatch):
    device.protocol = 3
    with pytest.raises(SystemExit, match="6982"):        # the root key is not bound yet
        cli.main(["profile", "create-secure", "2"])
    device.hmac_key = True
    cli.main(["profile", "create-secure", "2"])
    assert device.secure[1] and "Touch the key" in capsys.readouterr().err
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    with pytest.raises(SystemExit, match="aborted"):     # a used slot: asked first
        cli.main(["profile", "create-secure", "2"])


def test_profile_without_root_key_is_recorded(tmp_path, device, capsys, monkeypatch):
    """A NO-OTP profile on a Secure Boot + HMAC chip: INFO says root "none",
    the key store is locked; plan explains it, bind-root-key records it,
    after the restart it is unlocked and nothing is asked again."""
    device.protocol = 3
    device.hmac_key, device.secure_boot, device.drk_source, device.store_locked = True, True, 0, True
    cli.main(["info"])
    assert "key_store: LOCKED" in capsys.readouterr().out
    cli.main(["provision", "plan"])
    out = capsys.readouterr().out
    assert "has no root key" in out and "bind-root-key --apply" in out
    cli.main(["provision", "bind-root-key"])            # dry run
    assert "dry run" in capsys.readouterr().out and not device.unlock_at_boot
    monkeypatch.setattr("builtins.input", lambda prompt="": "BURN 0000000000000000")
    cli.main(["provision", "bind-root-key", "--apply", "--metadata-dir", str(tmp_path)])
    out = capsys.readouterr()
    assert device.unlock_at_boot and "record that the profile has no root key" in out.err
    assert "key_store: unlocked" in out.out
    device.reboot()                                     # the user restarts the key
    cli.main(["info"])
    assert "key_store: unlocked" in capsys.readouterr().out
    cli.main(["provision", "bind-root-key", "--apply", "--metadata-dir", str(tmp_path)])
    assert "recorded on the chip" in capsys.readouterr().out


def test_update_that_locks_the_profile_is_not_confirmed(tmp_path, device, capsys, monkeypatch):
    device.protocol = 3
    real = device.reboot

    def reboot():                                       # the new firmware holds the active profile
        real()
        if device.staged is None and device.pending:
            device.store_locked = True
    device.reboot = reboot
    img = tmp_path / "fw.bin"
    img.write_bytes(F.image((2, 0, 1)))
    cli.main(["firmware", "update", str(img), "-y"])
    out = capsys.readouterr()
    assert device.pending and "NOT confirmed" in out.err and "unconfirmed" in out.out


def test_destructive_prompt_names_the_profile(device, capsys):
    cli.main(["profile", "wipe", "1"])
    assert "WIPE profile 1 (Profile 1, the active one)" in capsys.readouterr().err
    cli.main(["profile", "list"])
    assert device.opened == 2


# -- single keys (key list / export / import) ------------------------------------------

_ed = ed25519.Ed25519PrivateKey.generate()
SEED = _ed.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
ED_PUB = _ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
_p256 = ec.generate_private_key(ec.SECP256R1())
P256_D = _p256.private_numbers().private_value.to_bytes(32, "big")
P256_Q = _p256.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
CRED1, CRED2 = bytes(range(42)), bytes(range(1, 43))
PGP_ATTR = bytes.fromhex("162b06010401da470f01")          # EdDSA ed25519
PGP_FP = bytes(range(20))
OATH_SECRET = b"12345678901234567890"
ACCESS_CODE = bytes.fromhex("010203040506")
TOTP_LINK = "otpauth://totp/Example:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example"

# (KEY_LIST entry, KEY_EXPORT record) of the keys of each application number
KEYS = {
    0: [({1: CRED1, 2: "example.com", 3: -7, 4: "alice", 5: "Alice", 6: b"user-1", 7: False},
         {1: "example.com", 2: CRED1, 3: b"user-1", 4: "alice", 5: "Alice", 6: -7, 7: 1, 8: bytes(range(32)),
          9: 2, 10: bytes(64), 11: bytes(32), 13: True, 14: 5}),
        ({1: CRED2, 2: "rp.example", 3: -8, 6: b"u2", 7: True},
         {1: "rp.example", 2: CRED2, 3: b"u2", 6: -8, 7: 6, 8: SEED, 13: True, 14: 9})],
    1: [({1: b"Example:alice", 2: 0x21, 3: 6, 4: False},
         {1: b"Example:alice", 2: 0x21, 3: 6, 4: OATH_SECRET, 6: False})],
    2: [({1: b"\x01", 2: "chal-hmac", 3: True}, {1: 1, 2: bytes(range(52)), 3: bytes(8), 4: "chal-hmac"})],
    3: [({1: b"\x01", 2: PGP_ATTR, 3: PGP_FP, 4: 1700000000},
         {1: 1, 2: PGP_ATTR, 3: {6: SEED, 7: ED_PUB}, 4: PGP_FP, 5: 1700000000})],
    4: [({1: b"\x9a", 2: 0x11, 3: 2, 4: 1}, {1: 0x9A, 2: 0x11, 3: {6: P256_D, 7: P256_Q}, 4: 2, 5: 1})],
}


class KeyDevice(F.FakeDevice):
    """FakeDevice with the single-key commands of lf_mgmt.c (KEY_LIST,
    KEY_EXPORT, KEY_IMPORT: their checks in the firmware's order, the FIDO
    PIN like EXPORT_BEGIN, the OpenPGP Admin PIN 12345678, the access code
    of an OTP slot) and a PIV application without certificates. requests:
    (INS, request) of each; refuse: {INS: status word} answered at once."""

    def __init__(self, **kw):
        kw.setdefault("protocol", 3)
        super().__init__(**kw)
        self.masks = {1: 0b11111, 2: 0b00101}           # export: all, import: FIDO and OTP
        self.keys = {n: [(dict(e), dict(r)) for e, r in pairs] for n, pairs in KEYS.items()}
        self.exportable = True
        self.page_size = 2
        self.list_sid = None            # the list session ID a KEY_LIST page answers while more follow
        self.requests = []
        self.refuse = {}

    def _info(self):
        m = cbor.decode(super()._info())
        if self.masks is not None:
            m[19] = self.masks                          # (firmware before 2.1.0: no key 19)
        return cbor.encode(m)

    def handle(self, app, ins, p1, p2, data):
        if app == keyio.PIV_AID and ins == keyio.PIV_INS_GET_DATA:
            return b"", 0x6A82
        if app != MGMT_AID or ins not in (mgmt.INS_KEY_LIST, mgmt.INS_KEY_EXPORT, mgmt.INS_KEY_IMPORT):
            return super().handle(app, ins, p1, p2, data)
        if self.masks is None:
            return b"", 0x6D00
        req = cbor.decode(data)
        self.requests.append((ins, req))
        if ins in self.refuse:
            return b"", self.refuse[ins]
        n, pairs = req[1], self.keys.setdefault(req[1], [])
        if ins == mgmt.INS_KEY_EXPORT and not self.exportable:
            return b"", 0x6986
        if not self.masks[2 if ins == mgmt.INS_KEY_IMPORT else 1] >> n & 1:
            return b"", 0x6A81
        paging = ins == mgmt.INS_KEY_LIST and 4 in req     # a later page: the ID, no PIN
        if paging and (self.list_sid is None or req[4] != self.list_sid):
            return b"", 0x6982
        sw = 0 if paging else self._pin_check(req.get(2 if ins == mgmt.INS_KEY_LIST else 3, b""))
        if sw:
            return b"", sw
        if ins == mgmt.INS_KEY_LIST:
            cur = req.get(3, 0)
            page = {1: [e for e, _ in pairs[cur:cur + self.page_size]], 2: self.exportable}
            if cur + self.page_size < len(pairs):
                page[3] = cur + self.page_size
                if self.list_sid is not None:
                    page[4] = self.list_sid
            return cbor.encode(page), 0x9000
        if ins == mgmt.INS_KEY_EXPORT:
            found = [r for e, r in pairs if e[1] == req[2]]
            if not found:
                return b"", 0x6A88
            if n == 3 and req.get(4) != b"12345678":
                return b"", 0x63C2
            return cbor.encode({1: n, 2: found[0]}), 0x9000
        record = req[2]
        if n == 0:
            key_id, entry = record[2], {1: record[2], 2: record[1], 3: record[6], 6: record[3], 7: True}
        else:
            slot = req[6][0] if 6 in req else record[1]
            key_id, entry = bytes([slot]), {1: bytes([slot]), 2: record.get(4, "?"), 3: False}
        there = [i for i, (e, _) in enumerate(pairs) if e[1] == key_id]
        if there and not req.get(5):
            return b"", 0x6A89
        if n == 2 and there and pairs[there[0]][0][3] and req.get(4) != ACCESS_CODE:
            return b"", 0x6982
        for i in reversed(there):
            del pairs[i]
        pairs.append((entry, record))
        return cbor.encode({1: n, 2: key_id}), 0x9000


def sent(dev, ins):
    return [r for i, r in dev.requests if i == ins]


@pytest.fixture
def kdev(monkeypatch):
    """KeyDevice behind Management.open(); key files written with a fast KDF."""
    dev = KeyDevice(stream=S.stream())
    dev.opened = 0

    def open_(cls, reader=None, timeout=0.0):
        dev.opened += 1
        return F.management(dev, monkeypatch)
    monkeypatch.setattr(mgmt.Management, "open", classmethod(open_))
    monkeypatch.setattr(cli, "write_key_file", functools.partial(keyfile.write_key_file, scrypt_log_n=10))
    return dev


@pytest.fixture
def added(monkeypatch):
    """keyio.import_single replaced by a spy: OATH, OpenPGP and PIV keys go
    through applications the simulated device does not have."""
    calls = []

    def spy(m, key, **kw):
        calls.append((key, kw))
        return "added: %s" % keyio.describe(key)
    monkeypatch.setattr(keyio, "import_single", spy)
    return calls


@pytest.fixture
def pw(tmp_path):
    f = tmp_path / "pw"
    f.write_text("file pw\n", encoding="utf-8")
    return str(f)


def key_file(tmp_path, app, record=None, passphrase="file pw", name="k.lfkey"):
    path = str(tmp_path / name)
    keyfile.write_key_file(path, SingleKey(app, dict(record or KEYS[mgmt.APPS.index(app)][0][1])), passphrase,
                           scrypt_log_n=10)
    return path


def test_key_list(kdev, ask, capsys):
    kdev.page_size = 1
    kdev.keys[1][0][0][1] = b"Ex\x1b[2K:alice"                         # a name with a terminal escape
    cli.main(["key", "list"])
    out = capsys.readouterr().out
    assert "fido: 2 keys\n  fido:1    example.com  user alice (Alice), ES256\n" in out
    assert "  fido:2    rp.example  user ID 7532, EdDSA, imported\n" in out
    assert "  oath:1    Ex\\x1b[2K:alice  TOTP SHA1, 6 digits\n" in out and "\x1b" not in out
    assert "  otp:1     slot 1  chal-hmac, access code\n" in out
    assert "  openpgp:1 signature key  EdDSA ed25519, fingerprint 0001 0203 0405" in out
    assert "created 2023-11-14" in out
    assert "  piv:1     slot 9A  ECC P-256, PIN policy once, touch policy never\n" in out
    assert "secret keys can be exported: yes" in out and not ask
    assert [r.get(3, 0) for r in sent(kdev, mgmt.INS_KEY_LIST) if r[1] == 0] == [0, 1]    # every page
    assert not F.commands(kdev, mgmt.INS_KEY_EXPORT)                                       # no touch
    cli.main(["--json", "key", "list", "--app", "fido"])
    j = json.loads(capsys.readouterr().out)
    assert [(k["selector"], k["id"]) for k in j["keys"]] == [("fido:1", CRED1.hex()), ("fido:2", CRED2.hex())]
    assert j["exportable"] is True and j["applications"] == ["fido"]


def test_key_list_session_and_touch(kdev, capsys):
    """The pages after the first follow the list session ID, without the
    PIN; a listing that may wait for a touch says so, and a 6985 then asks
    for the touch."""
    kdev.page_size, kdev.list_sid, kdev.pin = 1, b"S" * 8, "1234"
    m = mgmt.Management.open()
    entries, _ = m.list_keys("fido", pin="1234")
    assert [e[1] for e in entries] == [CRED1, CRED2]
    assert sent(kdev, mgmt.INS_KEY_LIST) == [{1: 0, 2: b"1234"}, {1: 0, 3: 1, 4: b"S" * 8}]
    assert m.list_needs_touch("fido") and not m.list_needs_touch("fido", "1234") and m.list_needs_touch("oath")
    assert not any(m.list_needs_touch(a) for a in ("otp", "openpgp", "piv"))
    real = kdev.handle

    def ended(app, ins, p1, p2, data):                                  # another command ends each listing
        answer = real(app, ins, p1, p2, data)
        kdev.list_sid = os.urandom(8)
        return answer
    kdev.handle = ended
    with pytest.raises(mgmt.ApduError, match="the device ended the listing") as err:
        m.list_keys("fido", pin="1234")
    assert err.value.sw == 0x6982
    kdev.handle = real
    kdev.pin = None
    kdev.refuse[mgmt.INS_KEY_LIST] = 0x6985
    with pytest.raises(SystemExit, match=r"key list \(fido\): the key was not touched: without the FIDO PIN"):
        cli.main(["key", "list", "--app", "fido"])
    assert "Touch the key when it blinks to list the fido keys" in capsys.readouterr().err
    with pytest.raises(SystemExit, match=r"key list \(otp\): the key store of the active profile is locked"):
        cli.main(["key", "list", "--app", "otp"])
    assert "Touch" not in capsys.readouterr().err


def test_key_list_pin_and_refusals(tmp_path, kdev, ask, capsys):
    kdev.pin = "1234"
    ask.answers.append("1234")
    cli.main(["key", "list", "--app", "oath"])
    assert ask == ["FIDO PIN of the active profile: "] and kdev.retries == 8
    assert sent(kdev, mgmt.INS_KEY_LIST) == [{1: 1, 2: b"1234"}]
    pin = tmp_path / "pin"
    pin.write_text("1234\n", encoding="utf-8")
    kdev.exportable = False
    cli.main(["key", "list", "--app", "piv", "--pin-file", str(pin)])
    assert "can be exported: no: this profile or build does not let secret keys out" in capsys.readouterr().out
    kdev.refuse[mgmt.INS_KEY_LIST] = 0x6985
    with pytest.raises(SystemExit, match=r"key list \(piv\): the key store of the active profile is locked"):
        cli.main(["key", "list", "--app", "piv", "--pin-file", str(pin)])
    kdev.refuse.clear()
    kdev.masks = {1: 0b00001, 2: 0}
    with pytest.raises(SystemExit, match="lists no oath keys"):
        cli.main(["key", "list", "--app", "oath"])
    kdev.masks = None                                                   # firmware before 2.1.0
    with pytest.raises(SystemExit, match="cannot list single keys .LibreFido 2.1.0 or newer"):
        cli.main(["key", "list"])
    assert cli.key_entry_text("oath", {1: b"x"}) == ("?", "malformed entry")


def test_fido_without_the_pin_says_what_it_leaves_out(tmp_path, kdev, ask, capsys, pw):
    """Without a verified FIDO PIN the device lists the credProtect 1
    passkeys only, without user names (docs/KEY_TRANSFER.md): key list and
    export fido:N say so and how to give the PIN, and export fido:N says that
    it needs two touches (the listing and the export)."""
    note = "note: " + cli.FIDO_NO_PIN_NOTE
    assert "passkeys that need user verification are only listed with the FIDO PIN" in note and "--pin" in note
    cli.main(["key", "list"])
    assert capsys.readouterr().err.count(note) == 1
    cli.main(["--json", "key", "list", "--app", "fido"])                # (stdout stays JSON)
    got = capsys.readouterr()
    assert note in got.err and json.loads(got.out)["applications"] == ["fido"]
    cli.main(["key", "list", "--app", "otp"])                           # no FIDO listing: nothing to say
    assert "FIDO PIN" not in capsys.readouterr().err
    out = str(tmp_path / "k.lfkey")
    cli.main(["key", "export", "fido:1", "-o", out, "--passphrase-file", pw])
    err = capsys.readouterr().err
    assert "Touch the key when it blinks to list the fido keys (touch 1 of 2: without the FIDO PIN, the listing " \
           "and the export need one each)..." in err
    assert "Touch the key when it blinks to export fido:1 (example.com), touch 2 of 2..." in err and note in err
    assert err.index("1 of 2") < err.index(note) < err.index("2 of 2")
    cli.main(["key", "export", "fido:hex:" + CRED1.hex(), "-o", out, "--passphrase-file", pw])     # no listing
    err = capsys.readouterr().err
    assert "of 2" not in err and note not in err and "to export fido key %s..." % CRED1.hex() in err
    kdev.pin = "1234"                                                   # with the PIN: all of them, no touch to list
    pin = tmp_path / "pin"
    pin.write_text("1234\n", encoding="utf-8")
    cli.main(["key", "list", "--app", "fido", "--pin-file", str(pin)])
    assert note not in capsys.readouterr().err
    cli.main(["key", "export", "fido:1", "-o", out, "--passphrase-file", pw, "--pin-file", str(pin)])
    err = capsys.readouterr().err
    assert "of 2" not in err and note not in err and "to list" not in err
    assert "Touch the key when it blinks to export fido:1 (example.com)..." in err


def test_key_export_to_an_encrypted_key_file(tmp_path, kdev, ask, capsys, pw):
    out = str(tmp_path / "k.lfkey")
    cli.main(["key", "export", "fido:1", "-o", out, "--passphrase-file", pw])
    info, key = read_key_file(out, "file pw", require_encryption=True)
    assert key.app == "fido" and key.record == KEYS[0][0][1] and info["label"] == "FIDO passkey for example.com (alice)"
    captured = capsys.readouterr()
    assert "Touch the key when it blinks to export fido:1 (example.com)" in captured.err
    assert "note (sign counter): the passkey stays on this key as well" in captured.err
    assert "wrote %s" % out in captured.out and ", encrypted): FIDO passkey for example.com" in captured.out
    assert sent(kdev, mgmt.INS_KEY_EXPORT) == [{1: 0, 2: CRED1}] and not ask
    kdev.requests.clear()                                               # APP:hex:ID: no list first
    cli.main(["key", "export", "fido:hex:" + CRED2.hex(), "-o", out, "--passphrase-file", pw])
    assert [i for i, _ in kdev.requests] == [mgmt.INS_KEY_EXPORT]
    assert read_key_file(out, "file pw")[1].record[1] == "rp.example"
    ask.answers += ["typed", "typed"]                                   # typed twice, as for a backup
    cli.main(["key", "export", "oath:1", "-o", out])
    assert ask == ["Key file passphrase: ", "Repeat passphrase: "]
    assert read_key_file(out, "typed")[1].record[4] == OATH_SECRET


def test_key_export_asks_for_the_fido_pin(tmp_path, kdev, ask, pw):
    kdev.pin = "1234"
    ask.answers.append("1234")
    cli.main(["key", "export", "otp:1", "-o", str(tmp_path / "otp.lfkey"), "--passphrase-file", pw])
    assert ask == ["FIDO PIN of the active profile: "] and kdev.retries == 8
    assert [r.get(2) for r in sent(kdev, mgmt.INS_KEY_LIST)] == [b"1234"]
    assert [r.get(3) for r in sent(kdev, mgmt.INS_KEY_EXPORT)] == [b"1234"]


def test_key_export_in_the_clear_needs_a_second_confirmation(tmp_path, kdev, monkeypatch, capsys, pw):
    out = tmp_path / "plain.lfkey"
    with pytest.raises(SystemExit, match="--yes-plaintext confirms --plaintext, which is missing"):
        cli.main(["key", "export", "oath:1", "-o", str(out), "--yes-plaintext"])
    question = "The key will NOT be encrypted: anyone with it has your key. Continue? [y/N] "
    for answer in ("n\n", "\n", ""):                                    # "": the end of the input
        monkeypatch.setattr(sys, "stdin", io.StringIO(answer))
        with pytest.raises(SystemExit, match="aborted"):
            cli.main(["key", "export", "oath:1", "-o", str(out), "--plaintext"])
    assert kdev.opened == 0 and not out.exists()
    capsys.readouterr()
    monkeypatch.setattr(sys, "stdin", io.StringIO("y\n"))
    cli.main(["key", "export", "oath:1", "-o", str(out), "--plaintext"])
    got = capsys.readouterr()
    assert got.err.startswith(question) and question not in got.out
    assert "NOT encrypted: anyone with this file has the key" in got.out
    assert read_key_file(str(out))[1].record[4] == OATH_SECRET
    out.unlink()
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    cli.main(["key", "export", "oath:1", "-o", str(out), "--plaintext", "--yes-plaintext"])     # scripts
    assert "Continue?" not in capsys.readouterr().err and not read_key_file(str(out))[0]["encrypted"]
    # -o -: standard output holds the link alone (redirected to a file, it
    # imports again); the question goes to stderr
    monkeypatch.setattr(sys, "stdin", io.StringIO("yes\n"))
    cli.main(["key", "export", "oath:1", "-o", "-", "--format", "otpauth", "--plaintext"])
    got = capsys.readouterr()
    assert got.out.startswith("otpauth://totp/") and "Continue?" not in got.out
    assert got.err.startswith("The otpauth:// link holds the secret in the clear: anyone with it has your key.")
    assert stdformats.parse_otpauth(got.out)[0][4] == OATH_SECRET
    empty = tmp_path / "empty"
    empty.write_bytes(b"\n")
    with pytest.raises(SystemExit, match=r"empty passphrase refused \(--plaintext writes"):
        cli.main(["key", "export", "oath:1", "-o", str(out), "--passphrase-file", str(empty)])


def test_key_export_formats(tmp_path, kdev, capsys, pw):
    with pytest.raises(SystemExit, match="in the clear; add --plaintext"):
        cli.main(["key", "export", "oath:1", "-o", "-", "--format", "otpauth"])
    with pytest.raises(SystemExit, match="--format pem is for piv keys only"):
        cli.main(["key", "export", "oath:1", "-o", "x", "--format", "pem"])
    with pytest.raises(SystemExit, match="standard output"):
        cli.main(["key", "export", "piv:1", "-o", "-", "--format", "pem", "--passphrase-file", pw])
    assert kdev.opened == 0
    cli.main(["key", "export", "oath:1", "-o", "-", "--format", "otpauth", "--plaintext", "--yes-plaintext"])
    link = capsys.readouterr().out.strip()
    assert link.startswith("otpauth://totp/Example:alice?secret=")
    assert stdformats.parse_otpauth(link) == [{1: b"Example:alice", 2: 0x21, 3: 6, 4: OATH_SECRET}]
    txt = tmp_path / "link.txt"
    cli.main(["key", "export", "oath:1", "-o", str(txt), "--format", "otpauth", "--plaintext", "--yes-plaintext"])
    assert txt.read_text(encoding="utf-8") == link + "\n"
    pem = tmp_path / "k.pem"
    cli.main(["key", "export", "piv:1", "-o", str(pem), "--format", "pem", "--passphrase-file", pw])
    [(record, cert)] = stdformats.load_piv_key(pem.read_bytes(), "file pw")
    assert record[3][6] == P256_D and cert is None
    with pytest.raises(stdformats.PassphraseRequired):
        stdformats.load_piv_key(pem.read_bytes())


def test_key_export_refusals(tmp_path, kdev, capsys, pw):
    out = str(tmp_path / "k.lfkey")

    def export(selector):
        cli.main(["key", "export", selector, "-o", out, "--passphrase-file", pw])
    for selector in ("fido", "ssh:1", "fido:0", "fido:x", "fido:hex:zz", "fido:hex:", "fido:hex:" + "00" * 65):
        with pytest.raises(SystemExit, match="key selector"):
            export(selector)
    assert kdev.opened == 0
    with pytest.raises(SystemExit, match="fido:3: the device lists 2 fido keys"):
        export("fido:3")
    kdev.exportable = False                                             # secure / no-export profile, HARDENED
    with pytest.raises(SystemExit, match="refused: this profile or build does not let secret keys out"):
        export("fido:1")
    # before the export's touch (the listing without a FIDO PIN asks for one of its own)
    err = capsys.readouterr().err
    assert not sent(kdev, mgmt.INS_KEY_EXPORT) and "to export" not in err and "to list the fido keys" in err
    with pytest.raises(SystemExit, match="exporting secret keys is not allowed by this profile or build"):
        export("fido:hex:" + CRED1.hex())                               # the device refuses it (6986)
    kdev.exportable = True
    with pytest.raises(SystemExit, match="no such key on the device"):
        export("otp:hex:02")
    kdev.refuse[mgmt.INS_KEY_EXPORT] = 0x6985
    with pytest.raises(SystemExit, match="not confirmed: touch the key"):
        export("otp:hex:01")
    kdev.masks = {1: 0b00001, 2: 0}
    with pytest.raises(SystemExit, match="refused: the firmware of this device cannot export piv keys"):
        export("piv:1")
    kdev.masks = None
    with pytest.raises(SystemExit, match="cannot export single keys .LibreFido 2.1.0 or newer"):
        export("fido:1")
    assert not os.path.exists(out)


def test_key_export_of_an_openpgp_key_asks_for_the_admin_pin(tmp_path, kdev, ask, pw):
    out = str(tmp_path / "pgp.lfkey")
    ask.answers.append("12345678")
    cli.main(["key", "export", "openpgp:1", "-o", out, "--passphrase-file", pw])
    assert ask == ["OpenPGP Admin PIN: "] and sent(kdev, mgmt.INS_KEY_EXPORT)[-1][4] == b"12345678"
    assert read_key_file(out, "file pw")[1].record[3] == {6: SEED, 7: ED_PUB}
    ask.answers.append("87654321")
    with pytest.raises(SystemExit, match=r"wrong PIN \(the FIDO PIN or the OpenPGP Admin PIN\), 2 tries left"):
        cli.main(["key", "export", "openpgp:1", "-o", out, "--passphrase-file", pw])
    with pytest.raises(SystemExit, match="--admin-pin is for OpenPGP keys"):
        cli.main(["key", "export", "fido:1", "-o", out, "--admin-pin"])


def test_key_import_of_a_fido_key_file(tmp_path, kdev, capsys, pw):
    path = key_file(tmp_path, "fido")                                   # the passkey the device has
    with pytest.raises(SystemExit, match=r"already on the device \(replace it explicitly\) \(SW 6A89\) \(--replace "
                                         r"replaces it\)"):
        cli.main(["key", "import", path, "--passphrase-file", pw])
    err = capsys.readouterr().err
    assert "note (sign counter): the passkey's signature counter goes on" in err
    assert "Touch the key when it blinks to add the FIDO passkey for example.com (alice)" in err
    cli.main(["key", "import", path, "--passphrase-file", pw, "--replace"])
    assert sent(kdev, mgmt.INS_KEY_IMPORT)[-1] == {1: 0, 2: KEYS[0][0][1], 5: True}
    assert "imported (credential ID %s)" % CRED1.hex() in capsys.readouterr().out
    kdev.refuse[mgmt.INS_KEY_IMPORT] = 0x6986
    with pytest.raises(SystemExit, match="cannot be imported into a secure profile or a HARDENED build"):
        cli.main(["key", "import", path, "--passphrase-file", pw, "--replace"])
    kdev.masks = {1: 0b11111, 2: 0}
    n = len(kdev.requests)
    with pytest.raises(SystemExit, match="refused: the firmware of this device cannot import fido keys"):
        cli.main(["key", "import", path, "--passphrase-file", pw])
    assert len(kdev.requests) == n
    with pytest.raises(SystemExit, match="holds a fido key, --app says oath"):
        cli.main(["key", "import", path, "--passphrase-file", pw, "--app", "oath"])
    with pytest.raises(SystemExit, match="--slot is not used for fido keys"):
        cli.main(["key", "import", path, "--passphrase-file", pw, "--slot", "1"])
    bad = tmp_path / "bad"
    bad.write_text("wrong\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="wrong passphrase"):
        cli.main(["key", "import", path, "--passphrase-file", str(bad)])


def test_key_import_of_an_unencrypted_key_file(tmp_path, kdev, capsys):
    path = key_file(tmp_path, "otp", passphrase=None)
    with pytest.raises(SystemExit, match="NOT encrypted, so nothing proves .* --allow-unencrypted"):
        cli.main(["key", "import", path])
    assert kdev.opened == 0
    cli.main(["key", "import", path, "--allow-unencrypted", "--slot", "2"])      # slot 2 is free
    assert sent(kdev, mgmt.INS_KEY_IMPORT)[-1] == {1: 2, 2: KEYS[2][0][1], 6: b"\x02"}
    captured = capsys.readouterr()
    assert "NOT encrypted, nothing proves it was not modified" in captured.err
    assert "OTP slot 2 written (from slot 1 of the file)" in captured.out


def test_key_import_otp_slot_with_an_access_code(tmp_path, kdev, ask, pw):
    path = key_file(tmp_path, "otp")
    with pytest.raises(SystemExit, match=r"OTP slot 1 is configured .*; replace it explicitly \(--replace"):
        cli.main(["key", "import", path, "--passphrase-file", pw])
    with pytest.raises(SystemExit, match=r"protected by an access code; give it \(--access-code\)"):
        cli.main(["key", "import", path, "--passphrase-file", pw, "--replace"])
    assert not sent(kdev, mgmt.INS_KEY_IMPORT)
    ask.answers.append("000000000000")
    with pytest.raises(SystemExit, match="access code of OTP slot 1 is wrong"):
        cli.main(["key", "import", path, "--passphrase-file", pw, "--replace", "--access-code"])
    ask.answers.append(ACCESS_CODE.hex())
    cli.main(["key", "import", path, "--passphrase-file", pw, "--replace", "--access-code"])
    assert ask == ["Access code of the target OTP slot (12 hex digits): "] * 2
    assert sent(kdev, mgmt.INS_KEY_IMPORT)[-1] == {1: 2, 2: KEYS[2][0][1], 4: ACCESS_CODE, 5: True, 6: b"\x01"}
    with pytest.raises(SystemExit, match="--oath-password is for oath keys"):
        cli.main(["key", "import", path, "--passphrase-file", pw, "--oath-password"])


def _migration_link(accounts, size=1, index=0):
    """Google Authenticator export link: accounts (secret, name, algorithm
    enum, digits enum)."""
    def varint(v):
        out = b""
        while True:
            out += bytes([(v & 0x7F) | (0x80 if v > 0x7F else 0)])
            v >>= 7
            if not v:
                return out

    def field(n, v):
        if isinstance(v, int):
            return varint(n << 3) + varint(v)
        return varint(n << 3 | 2) + varint(len(v)) + v
    data = b"".join(field(1, field(1, s) + field(2, name.encode()) + field(4, alg) + field(5, digits) + field(6, 2))
                    for s, name, alg, digits in accounts)
    data += field(2, 1) + field(3, size) + field(4, index) + field(5, 77)
    return "otpauth-migration://offline?data=" + urllib.parse.quote(base64.b64encode(data).decode())


def test_key_import_of_otpauth_links(tmp_path, kdev, added, ask, capsys, monkeypatch):
    cli.main(["key", "import", TOTP_LINK])
    [(key, kw)] = added
    assert key.app == "oath" and key.record[1] == b"Example:bob" and kw == {"pin": None, "no_pin": False,
                                                                           "replace": False}
    captured = capsys.readouterr()
    assert "other users of this computer can see it" in captured.err
    assert "added: OATH TOTP account Example:bob" in captured.out and kdev.opened == 1
    # - reads links from standard input, one per line; the OATH password is asked for
    monkeypatch.setattr(sys, "stdin", io.StringIO(TOTP_LINK + "\n\n" + TOTP_LINK.replace("bob", "carol") + "\n"))
    ask.answers.append("oath pw")
    cli.main(["key", "import", "-", "--oath-password", "--replace"])
    assert [(k.record[1], kw["oath_password"], kw["replace"]) for k, kw in added[1:]] == \
        [(b"Example:bob", "oath pw", True), (b"Example:carol", "oath pw", True)]
    assert "can see it" not in capsys.readouterr().err
    # a Google Authenticator export (a text file) with an account the device cannot hold, one of 2 QR codes
    txt = tmp_path / "links.txt"
    txt.write_text(_migration_link([(OATH_SECRET, "Good", 1, 1), (OATH_SECRET, "Old", 4, 1)], size=2), "utf-8")
    del added[:]
    cli.main(["key", "import", str(txt)])
    assert [k.record[1] for k, _ in added] == [b"Good"]
    err = capsys.readouterr().err
    assert "left out: accounts the device cannot hold: Old (algorithm MD5)" in err
    assert "split over several QR codes: number 2 is not here" in err
    with pytest.raises(SystemExit, match="not a piv key"):
        cli.main(["key", "import", TOTP_LINK, "--app", "piv"])
    with pytest.raises(SystemExit, match="error: the secret is not base32"):
        cli.main(["key", "import", "otpauth://totp/x?secret=1"])


def test_key_import_of_a_qr_code_image(tmp_path, kdev, added, capsys, monkeypatch):
    png = tmp_path / "qr.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(40))
    monkeypatch.setattr(stdformats, "decode_qr_image", lambda path: [TOTP_LINK, "https://example.com"])
    cli.main(["key", "import", str(png)])
    assert [k.record[1] for k, _ in added] == [b"Example:bob"]
    assert "1 QR code without an otpauth link left out" in capsys.readouterr().err
    monkeypatch.setattr(stdformats, "decode_qr_image", lambda path: ["hello"])
    with pytest.raises(SystemExit, match="no QR code with an otpauth:// link"):
        cli.main(["key", "import", str(png)])


def _certificate(key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cli test")])
    now = datetime.datetime(2026, 1, 1)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256()))


def test_key_import_of_a_piv_key_file(tmp_path, kdev, added, ask):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _certificate(key)
    pem = tmp_path / "k.pem"
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.BestAvailableEncryption(b"key pw")) +
                    cert.public_bytes(serialization.Encoding.PEM))
    ask.answers.append("key pw")
    with pytest.raises(SystemExit, match="--slot is needed: the PIV slot"):
        cli.main(["key", "import", str(pem)])
    assert kdev.opened == 0
    ask.answers += ["key pw", "00" * 24]
    cli.main(["key", "import", str(pem), "--slot", "9C", "--mgmt-key", "-", "--replace"])
    assert ask == ["Password of %s: " % pem] * 2 + ["PIV management key (hex): "]
    [(k, kw)] = added
    assert k.app == "piv" and k.record[8] == cert.public_bytes(serialization.Encoding.DER)
    assert kw["piv_slot"] == "9c" and kw["piv_mgmt_key"] == "00" * 24 and kw["replace"]
    der = tmp_path / "k.der"                                            # DER in the clear, the key on the line
    der.write_bytes(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    cli.main(["key", "import", str(der), "--slot", "82", "--mgmt-key", "0102"])
    assert added[-1][1]["piv_mgmt_key"] == "0102" and 8 not in added[-1][0].record
    wrong = tmp_path / "wrong"
    wrong.write_text("nope", encoding="utf-8")
    with pytest.raises(SystemExit, match="wrong password"):
        cli.main(["key", "import", str(pem), "--slot", "9c", "--passphrase-file", str(wrong)])


def test_key_import_of_an_openpgp_key_file(tmp_path, kdev, added, ask, monkeypatch, capsys):
    def pgp(record, usage, fp, primary, **kw):
        return dict({"record": record, "usage": set(usage), "fingerprint": fp, "key_id": fp[-8:].hex().upper(),
                     "created": 1700000000, "user_ids": ["Alice <alice@example.org>"], "primary": primary,
                     "algorithm": "EdDSA ed25519", "revoked": False, "unsupported": None}, **kw)
    sig = pgp(KEYS[3][0][1], ("sig", "cert"), PGP_FP, True)
    dec = pgp({2: bytes.fromhex("122b060104019755010501"), 3: {6: bytes(32), 7: bytes(32)}, 4: bytes(20),
               5: 1700000000}, ("dec",), bytes(range(20, 40)), False, algorithm="ECDH cv25519")
    old = pgp(KEYS[3][0][1], ("sig",), bytes(range(40, 60)), False, revoked=True)
    stub = pgp(None, ("aut",), bytes(range(60, 80)), False, unsupported="no secret key in the file (a GnuPG stub)")
    passphrases = []

    def parse(data, passphrase=None):
        passphrases.append(passphrase)
        if passphrase is None:
            raise stdformats.PassphraseRequired("the OpenPGP secret key is protected: give its passphrase")
        return [sig, dec, old, stub]
    monkeypatch.setattr(stdformats, "parse_openpgp_secret", parse)
    path = tmp_path / "alice.asc"
    path.write_bytes(b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n-----END PGP PRIVATE KEY BLOCK-----\n")
    ask.answers.append("gpg pw")
    with pytest.raises(SystemExit, match=r"2 keys fit; choose one with --key-id \(and --slot sig, dec or aut\)"):
        cli.main(["key", "import", str(path)])
    err = capsys.readouterr().err
    assert "left out: revoked" in err and "left out: no secret key in the file (a GnuPG stub)" in err
    assert passphrases == [None, "gpg pw"] and not added
    ask.answers += ["gpg pw", "12345678"]
    cli.main(["key", "import", str(path), "--slot", "dec"])
    assert ask[-2:] == ["Passphrase of the OpenPGP key: ", "OpenPGP Admin PIN: "]
    k, kw = added[-1]
    assert k.record is dec["record"] and kw["pgp_key_ref"] == "dec" and kw["pgp_admin_pin"] == "12345678"
    ask.answers += ["gpg pw", "12345678"]
    cli.main(["key", "import", str(path), "--key-id", "0x" + PGP_FP[-4:].hex()])    # the slot from its usage
    assert added[-1][0].record is sig["record"] and added[-1][1]["pgp_key_ref"] == "sig"
    ask.answers.append("gpg pw")
    with pytest.raises(SystemExit, match="--slot of an OpenPGP key: sig, dec or aut"):
        cli.main(["key", "import", str(path), "--slot", "9a"])


def test_key_source_kinds(tmp_path, kdev):
    kind = cli.key_source_kind
    assert kind(keyfile.MAGIC + bytes(50)) == "lfkey"
    assert kind(b"\xef\xbb\xbf \r\notpauth://totp/x?secret=AA") == "links"
    assert kind(b"OTPAUTH-MIGRATION://offline?data=") == "links"
    assert kind(b"\x89PNG\r\n\x1a\n" + bytes(8)) == "image" and kind(b"RIFF\0\0\0\0WEBPVP8 ") == "image"
    assert kind(b"-----BEGIN PGP PRIVATE KEY BLOCK-----") == "openpgp" and kind(b"\x95\x01\x00") == "openpgp"
    assert kind(b"-----BEGIN PRIVATE KEY-----") == "piv" and kind(b"\x30\x82\x01\x00") == "piv"
    assert kind(b"hello") is None
    unknown = tmp_path / "unknown"
    unknown.write_bytes(b"hello")
    with pytest.raises(SystemExit, match="cannot tell what .* holds: --app names the application"):
        cli.main(["key", "import", str(unknown)])
    with pytest.raises(SystemExit, match="fido keys are added from LibreFido key files only"):
        cli.main(["key", "import", str(unknown), "--app", "fido"])
    big = tmp_path / "big.pem"
    big.write_bytes(b"-----BEGIN PRIVATE KEY-----" + bytes(cli.KEY_SOURCE_MAX))
    with pytest.raises(SystemExit, match="larger than 1024 KiB: not a key file"):
        cli.main(["key", "import", str(big), "--slot", "9a"])
    assert kdev.opened == 0
