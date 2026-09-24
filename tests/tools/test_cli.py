"""librefido command line: passphrases, explicit plaintext, PIN prompts,
profile numbers."""

import argparse
import getpass
import os

import pytest

import fakedev as F
import lfstreams as S
from librefido import cli, mgmt
from librefido.backup import read_file, write_file


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
    write_file(path, S.stream(min_fw=(2, 1, 0)), "pw", scrypt_log_n=10)
    with pytest.raises(SystemExit, match="runs firmware 2.0.0; this backup needs 2.1.0"):
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
