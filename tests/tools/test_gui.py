"""librefido-gui without a device (offscreen, simulated device): secrets are
not kept, a failed load drops the previous backup, imports and plaintext
exports are confirmed, device and backup names are shown as plain text, the
PIN is asked for when the device wants one, slow work runs in the worker;
the Keys tab (single keys)."""

import functools
import inspect
import os
import re
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

import fakedev as F                     # noqa: E402
import lfstreams as S                   # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from fido2 import cbor                  # noqa: E402
from librefido import cli, gui, keyfile, keyio, mgmt, stdformats  # noqa: E402
from librefido.backup import write_file  # noqa: E402
from librefido.keyfile import SingleKey, read_key_file  # noqa: E402
# the simulated device with single keys, and its keys
from test_cli import ACCESS_CODE, CRED1, KEYS, OATH_SECRET, TOTP_LINK, KeyDevice, _certificate, sent  # noqa: E402

Yes, No = QtWidgets.QMessageBox.StandardButton.Yes, QtWidgets.QMessageBox.StandardButton.No


@pytest.fixture
def app(monkeypatch):
    a = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    a.messages = []
    for kind in ("information", "critical"):
        monkeypatch.setattr(QtWidgets.QMessageBox, kind, staticmethod(
            lambda parent, title, text, *x, _k=kind: a.messages.append((_k, text))))
    a.answers = {"question": [], "warning": []}
    for kind in ("question", "warning"):
        monkeypatch.setattr(QtWidgets.QMessageBox, kind, staticmethod(
            lambda parent, title, text, *x, _k=kind: (a.messages.append((_k, text)),
                                                      a.answers[_k].pop(0) if a.answers[_k] else No)[1]))
    a.inputs = []
    monkeypatch.setattr(QtWidgets.QInputDialog, "getText", staticmethod(
        lambda *x, **k: (a.messages.append(("input", x[2])), a.inputs.pop(0) if a.inputs else ("", False))[1]))
    return a


@pytest.fixture
def window(app, monkeypatch):
    monkeypatch.setattr(gui, "list_devices", lambda: [])       # never touch a real reader
    w = gui.MainWindow()
    dev = F.FakeDevice(stream=S.stream())
    w.mgmt = F.management(dev, monkeypatch)
    # refresh() finds the simulated device from now on (and keeps w.mgmt)
    monkeypatch.setattr(gui, "list_devices", lambda: [(w.mgmt.card.reader, b"")])
    w.refresh()
    assert w.info is not None
    w.dev = dev
    yield w
    wait_idle(app, w)
    w.close()


def choose_file(monkeypatch, path, save=False):
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName" if save else "getOpenFileName",
                        staticmethod(lambda *a, **k: (path, "")))


def wait_idle(app, w, timeout=20.0):
    deadline = time.time() + timeout
    while True:
        app.processEvents()
        if not w.busy or time.time() > deadline:
            break
        time.sleep(0.01)
    assert not w.busy
    app.processEvents()


def test_failed_load_drops_the_previous_backup(app, window, monkeypatch, tmp_path):
    good, bad = str(tmp_path / "a.lfbk"), str(tmp_path / "b.lfbk")
    write_file(good, S.stream(), None)
    with open(bad, "wb") as f:
        f.write(b"LFBACKUP" + bytes(100))
    choose_file(monkeypatch, good)
    window._verify_file()
    wait_idle(app, window)
    assert window.loaded_path == good and "a.lfbk" in window.verify_out.toPlainText()
    assert "NOT encrypted" in window.verify_out.toPlainText()
    choose_file(monkeypatch, bad)
    window._verify_file()
    wait_idle(app, window)
    assert window.loaded_path is None and window.verify_out.toPlainText() == ""
    assert app.messages[-1][0] == "critical"
    # the device checks now ask for a file again instead of testing a.lfbk
    choose_file(monkeypatch, "")
    window.dev.log.clear()
    window._device_check(True)
    window._device_check(False)
    wait_idle(app, window)
    assert not F.commands(window.dev)


def test_device_check_reads_the_file_again_and_names_it(app, window, monkeypatch, tmp_path):
    path = str(tmp_path / "work.lfbk")
    write_file(path, S.stream(), "pw", scrypt_log_n=10)
    choose_file(monkeypatch, path)
    app.inputs.append(("pw", True))
    window._verify_file()
    wait_idle(app, window)
    assert window.loaded_path == path and not hasattr(window, "loaded_stream")
    app.inputs.append(("pw", True))                     # the stream was not kept: asked again
    window._device_check(False)
    wait_idle(app, window)
    wait_idle(app, window)
    assert app.messages[-1] == ("information", gui.T("The firmware accepts this backup.") + "\nwork.lfbk")
    assert F.commands(window.dev, 0x2A)                 # IMPORT_END of the dry run
    assert window._job.fn is None and window._then is None and window._on_error is None


def test_device_check_while_busy_changes_nothing(app, window, monkeypatch, tmp_path):
    path = str(tmp_path / "work.lfbk")
    write_file(path, S.stream(), None)
    window.loaded_path = path
    window.busy = True
    choose_file(monkeypatch, "/nonexistent")
    window._device_check(True)
    window.busy = False
    assert window.loaded_path == path and not app.messages


def test_key_derivation_runs_in_the_worker(app, window, monkeypatch, tmp_path):
    path = str(tmp_path / "enc.lfbk")
    write_file(path, S.stream(), "pw", scrypt_log_n=10)
    threads = []
    real = gui.read_file

    def spy(blob, passphrase=None, **kw):
        if passphrase is not None:
            threads.append(threading.current_thread() is threading.main_thread())
        return real(blob, passphrase, **kw)
    monkeypatch.setattr(gui, "read_file", spy)
    choose_file(monkeypatch, path)
    app.inputs.append(("pw", True))
    window._verify_file()
    wait_idle(app, window)
    assert threads == [False] and window.loaded_path == path


def test_export_does_not_keep_the_pin_or_passphrase(app, window, monkeypatch, tmp_path):
    window.pass1.setText("pw")
    window.pass2.setText("pw")
    window.pin_edit.setText("1234")
    window.fw_pin.setText("1234")
    choose_file(monkeypatch, "", save=True)             # the user cancels the file dialog
    window._export()
    assert not window.pass1.text() and not window.pass2.text() and not window.pin_edit.text()
    choose_file(monkeypatch, "")
    window._update_firmware()
    assert not window.fw_pin.text()
    window.fw_pin.setText("1234")
    window._confirm_firmware()                          # "Keep this firmware" clears it as well
    wait_idle(app, window)
    assert not window.fw_pin.text()
    path = str(tmp_path / "p.lfbk")
    choose_file(monkeypatch, path, save=True)
    window.pass1.setText("secret passphrase")
    window.pass2.setText("secret passphrase")
    window._export()
    wait_idle(app, window)
    assert os.path.exists(path), app.messages
    # nothing the GUI keeps refers to the passphrase any more
    assert window._job.fn is None and window._then is None and window._on_error is None


def test_plaintext_export_is_confirmed(app, window, monkeypatch, tmp_path):
    path = str(tmp_path / "plain.lfbk")
    choose_file(monkeypatch, path, save=True)
    window.enc_check.setChecked(False)
    window._export()                                    # answered No
    assert not window.busy and not os.path.exists(path)
    app.answers["question"].append(Yes)
    window._export()
    wait_idle(app, window)
    assert os.path.exists(path)


def test_export_asks_for_a_pin_the_profile_has(app, window, monkeypatch, tmp_path):
    window.dev.pin = "1234"
    path = str(tmp_path / "p.lfbk")
    choose_file(monkeypatch, path, save=True)
    window.pass1.setText("pw")
    window.pass2.setText("pw")
    window._export()                                    # the PIN dialog is cancelled
    wait_idle(app, window)
    assert app.messages[-1][0] == "input"
    assert not F.commands(window.dev, 0x20) and window.dev.retries == 8
    window.pass1.setText("pw")
    window.pass2.setText("pw")
    app.inputs.append(("1234", True))
    window._export()
    wait_idle(app, window)
    wait_idle(app, window)
    assert os.path.exists(path) and window.dev.retries == 8


def test_pin_asked_when_the_device_wants_it_although_getinfo_says_none(app, window, monkeypatch, tmp_path):
    """Key store locked: getInfo reports no PIN, the management applet asks
    for it. The GUI asks for the PIN and tries again, without a retry used."""
    window.dev.pin = "123456"
    window.dev.store_locked = True
    img = tmp_path / "fw.bin"
    img.write_bytes(F.image((2, 0, 1)))
    choose_file(monkeypatch, str(img))
    app.answers["question"].append(Yes)
    app.inputs.append(("123456", True))
    window._update_firmware()
    wait_idle(app, window)
    wait_idle(app, window)
    kinds = [k for k, _ in app.messages]
    assert "input" in kinds and "critical" not in kinds, app.messages
    assert window.dev.version == (2, 0, 1) and window.dev.retries == 8


def test_import_into_a_used_slot_is_confirmed(app, window, monkeypatch, tmp_path):
    path = str(tmp_path / "plain.lfbk")
    write_file(path, S.stream(), None)
    choose_file(monkeypatch, path)
    window.target_spin.setValue(1)
    window._import()                                    # unencrypted: warned, answered No
    wait_idle(app, window)
    assert app.messages[-1][0] == "warning" and not window.busy
    app.answers["warning"].append(Yes)
    window._import()                                    # replacing slot 1: answered No
    wait_idle(app, window)
    kind, text = app.messages[-1]
    assert kind == "question" and "Slot 1 (Profile 1)" in text and "plain.lfbk" in text
    assert not window.busy and not F.commands(window.dev, 0x28)


def test_names_are_shown_as_plain_text(app, window, monkeypatch, tmp_path):
    """A name that Qt would take for rich text cannot hide the warning."""
    window.dev.names[0] = "W<b></b><!--"
    window.info = window.mgmt.info()
    path = str(tmp_path / "enc.lfbk")
    write_file(path, S.stream(name=b"x<i>\x1b[2K"), "pw", scrypt_log_n=10)
    choose_file(monkeypatch, path)
    app.inputs.append(("pw", True))
    window.target_spin.setValue(1)
    window._import()
    wait_idle(app, window)
    kind, text = app.messages[-1]
    first = text.split("\n", 1)[0]
    assert kind == "question" and "<" not in first and "&" not in first
    assert "erases its keys for good" in text and "\x1b" not in text and "\\x1b" in text
    assert gui._plain("<b>x</b>\nmore").split("\n", 1)[0] == gui.T("Details:")
    for lbl in window.dev_labels.values():
        assert lbl.textFormat() == gui.Qt.TextFormat.PlainText


def test_backup_from_newer_firmware_is_refused_before_the_upload(app, window, monkeypatch, tmp_path):
    path = str(tmp_path / "new.lfbk")
    write_file(path, S.stream(min_fw=(2, 1, 0)), None)
    choose_file(monkeypatch, path)
    app.answers["warning"].append(Yes)                  # (unencrypted)
    window._import()
    wait_idle(app, window)
    assert app.messages[-1][0] == "critical" and "2.1.0" in app.messages[-1][1]
    assert not F.commands(window.dev, 0x28)


def test_rename_clips_to_bytes(app, window, monkeypatch):
    window.table.selectRow(0)
    app.inputs.append(("我的工作安全密钥", True))
    window._rename()
    wait_idle(app, window)
    assert cbor.decode(F.commands(window.dev, 0x11)[0][3]) == {1: "我的工作安全密"}


def protocol_3(window):
    window.dev.protocol = window.mgmt.card.protocol = 3
    window.refresh()
    return window.security_tab


def test_security_tab_presence(app, window):
    tab = protocol_3(window)
    assert window.tabs.tabText(window.tabs.indexOf(tab)) == gui.T("Security")
    assert all(cb.isChecked() for cb in tab.need_touch.values())
    tab.need_touch["fido"].setChecked(False)
    tab._apply_presence()                               # switching on: warned, answered No
    wait_idle(app, window)
    assert window.dev.presence[0] == 0 and tab.need_touch["fido"].isChecked()
    app.answers["question"].append(Yes)
    tab.need_touch["fido"].setChecked(False)
    tab._apply_presence()
    wait_idle(app, window)
    assert window.dev.presence[0] == 1 and not tab.need_touch["fido"].isChecked()
    tab.safe.setChecked(True)                           # "my device is safe": all of them
    app.answers["question"].append(Yes)
    tab._apply_presence()
    wait_idle(app, window)
    assert window.dev.presence[0] == 0x1F and tab.safe.isChecked()
    tab.safe.setChecked(False)                          # switching off: no question
    tab._apply_presence()
    wait_idle(app, window)
    assert window.dev.presence[0] == 0


def test_security_tab_provisioning(app, window, monkeypatch, tmp_path):
    tab = protocol_3(window)
    monkeypatch.setattr(gui.gui_policy, "metadata_dir", lambda: str(tmp_path))
    assert tab.bind_btn.isEnabled() and tab.lock_btn.isEnabled() and "0 / 3" in tab.level.text()
    app.inputs.append(("BURN wrong", True))
    tab._bind()
    assert not window.busy and not window.dev.hmac_key and app.messages[-1][0] == "warning"
    app.inputs.append(("BURN 0000000000000000", True))
    tab._bind()
    wait_idle(app, window)
    assert window.dev.hmac_key and "1 / 3" in tab.level.text() and not tab.bind_btn.isEnabled()
    app.inputs.append(("BURN 0000000000000000", True))
    tab._lock_debug()
    wait_idle(app, window)
    assert window.dev.jtag and "2 / 3" in tab.level.text() and not tab.lock_btn.isEnabled()
    assert app.messages[-1][0] == "information" and "2 / 3" in app.messages[-1][1]
    assert len([p for p in tmp_path.iterdir() if p.name.startswith("librefido-provision-")]) == 2
    # a secure profile, then the presence settings are off limits for it
    tab.slot.setCurrentIndex(2)
    app.answers["question"].append(Yes)
    tab._create_secure()
    wait_idle(app, window)
    assert window.dev.secure[2]
    assert window.table.item(2, 4).text() == gui.T("secure profile")


def test_security_tab_binds_a_profile_without_root_key(app, window, monkeypatch, tmp_path):
    tab = protocol_3(window)
    d = window.dev
    d.hmac_key, d.secure_boot, d.drk_source, d.store_locked = True, True, 0, True
    window.refresh()
    monkeypatch.setattr(gui.gui_policy, "metadata_dir", lambda: str(tmp_path))
    assert tab.bind_btn.isEnabled()
    app.inputs.append(("BURN 0000000000000000", True))
    tab._bind()
    wait_idle(app, window)
    shown = [text for kind, text in app.messages if kind == "input"][-1]
    assert shown.startswith(gui.T("held-none-info")[:40])
    assert d.unlock_at_boot and app.messages[-1][0] == "information"
    assert "key_store: unlocked" in app.messages[-1][1]
    assert gui.T("bind-info") != "bind-info"            # keyed texts have English


def test_security_tab_brightness(app, window):
    tab = protocol_3(window)
    assert tab.bright.value() == 255
    tab.bright.setValue(40)
    tab._brightness()
    wait_idle(app, window)
    assert window.dev.led == 40 and window.info["board"]["led_brightness"] == 40
    window.dev.free_changes = 0
    window.refresh()
    assert window._change_touch()


def test_safe_mode_does_not_crash_the_profile_buttons(app, window):
    window.dev.boot_status = 2                          # system area unreadable: no profiles
    window.info = window.mgmt.info()
    window.table.selectRow(0)
    window._toggle_export()
    window._wipe()                                      # (answered No)
    wait_idle(app, window)


# -- Keys tab (single keys) ------------------------------------------------------------

@pytest.fixture
def keys(app, window, monkeypatch):
    """The Keys tab of the window on a device with single keys (KeyDevice);
    key files with a fast KDF; QInputDialog.getItem answered from app.items
    (default: the proposed item), the passphrase dialog from app.passphrases
    ((passphrase, repeated), False for no encryption; default: cancelled)."""
    dev = KeyDevice(stream=S.stream())
    window.mgmt = F.management(dev, monkeypatch)
    window.dev = dev
    window.refresh()
    monkeypatch.setattr(cli, "write_key_file", functools.partial(keyfile.write_key_file, scrypt_log_n=10))
    app.items = []
    monkeypatch.setattr(QtWidgets.QInputDialog, "getItem", staticmethod(
        lambda parent, title, label, items, current=0, editable=True, *a, **k:
        (app.messages.append(("item", label)), app.items.pop(0) if app.items else (items[current], True))[1]))
    app.passphrases = []

    def exec_(dlg):
        answer = app.passphrases.pop(0) if app.passphrases else None
        if answer is None:
            return 0
        if answer is False:
            dlg.plain.setChecked(True)
        else:
            dlg.pass1.setText(answer[0])
            dlg.pass2.setText(answer[1])
        dlg._accept()
        return int(dlg.ok)
    monkeypatch.setattr(gui.KeyPassphraseDialog, "exec", exec_)
    return window.keys_tab


@pytest.fixture
def applets(monkeypatch):
    """keyio.import_single replaced by a spy (OATH, OpenPGP and PIV keys go
    through applications the simulated device does not have); an OATH
    account named Example:bob is already there."""
    calls = []

    def spy(m, key, replace=False, **kw):
        calls.append((key, dict(kw, replace=replace)))
        if key.app == "oath" and key.record[1] == b"Example:bob" and not replace:
            raise keyio.KeyTransferError("an OATH account named Example:bob is already on the device; replace it "
                                         "explicitly", 0x6A89)
        return "added: %s" % keyio.describe(key)
    monkeypatch.setattr(keyio, "import_single", spy)
    return calls


def listed(app, window, tab):
    tab.refresh_keys()
    wait_idle(app, window)
    return [[tab.table.item(r, c).text() for c in range(3)] for r in range(tab.table.rowCount())]


def test_keys_tab_lists_in_the_worker_and_exports(app, window, keys, monkeypatch, tmp_path):
    tab = keys
    assert window.tabs.tabText(window.tabs.indexOf(tab)) == gui.T("Keys")
    threads = []
    real = gui.list_all_keys

    def spy(*a, **k):
        threads.append(threading.current_thread() is threading.main_thread())
        return real(*a, **k)
    monkeypatch.setattr(gui, "list_all_keys", spy)
    rows = listed(app, window, tab)
    assert threads == [False] and len(rows) == 6
    assert rows[0] == [gui.T("FIDO2 passkeys")] + list(cli.key_entry_text("fido", KEYS[0][0][0], gui.T))
    assert rows[5] == [gui.T("PIV keys")] + list(cli.key_entry_text("piv", KEYS[4][0][0], gui.T))
    assert rows[0][1] == "example.com" and "ECC P-256" in rows[5][2]
    assert tab.state.text() == "%s %s\n%s" % (gui.T("Keys listed: %d") % 6, gui.T("Secret keys of this profile can "
                                                                                  "be exported."),
                                              gui.T("fido-listed-without-pin"))      # (the profile has no FIDO PIN)
    assert not F.commands(window.dev, mgmt.INS_KEY_EXPORT)
    path = str(tmp_path / "k.lfkey")
    choose_file(monkeypatch, path, save=True)
    tab.table.selectRow(0)
    app.passphrases.append(("pw", "pw"))
    tab.export_selected()
    wait_idle(app, window)
    info, key = read_key_file(path, "pw", require_encryption=True)
    assert key.record == KEYS[0][0][1] and info["label"] == "FIDO passkey for example.com (alice)"
    kind, text = app.messages[-1]
    assert kind == "information" and path in text and gui.T("fido-counter-export") in text
    assert gui.T("NOT encrypted: anyone with this file has the key.") not in text
    assert window._job.fn is None and window._then is None and window._on_error is None     # nothing kept


def test_keys_tab_says_what_fido_leaves_out_without_the_pin(app, window, keys):
    """A FIDO listing without a verified PIN (credProtect 1 passkeys only,
    without user names) says so, and "List with FIDO PIN..." asks for the
    PIN and lists with it."""
    tab = keys
    assert tab.pin_btn.isHidden()
    listed(app, window, tab)                            # the profile has no FIDO PIN
    fido = [r for r in sent(window.dev, mgmt.INS_KEY_LIST) if r[1] == 0]
    assert fido == [{1: 0}] and tab.state.text().endswith("\n" + gui.T("fido-listed-without-pin"))
    assert not tab.pin_btn.isHidden() and "passkeys that need user verification" in gui.T("fido-listed-without-pin")
    app.inputs.append(("", True))                       # nothing typed: said, nothing listed
    tab.refresh_with_pin()
    assert app.messages[-1] == ("warning", gui.T("Enter the FIDO PIN.")) and not window.busy
    app.inputs.append(("", False))                      # cancelled
    tab.refresh_with_pin()
    assert not window.busy
    window.dev.pin = "1234"                             # (set meanwhile)
    app.inputs.append(("1234", True))
    tab.refresh_with_pin()
    wait_idle(app, window)
    assert ("input", gui.T("FIDO PIN of the active profile:")) in app.messages
    assert [r for r in sent(window.dev, mgmt.INS_KEY_LIST) if r[1] == 0][-1] == {1: 0, 2: b"1234"}
    assert tab.table.rowCount() == 6 and gui.T("fido-listed-without-pin") not in tab.state.text()
    assert tab.pin_btn.isHidden()
    window.dev.pin = None
    tab.app_box.setCurrentIndex(tab.app_box.findData("otp"))       # no FIDO listed: nothing to say
    listed(app, window, tab)
    assert gui.T("fido-listed-without-pin") not in tab.state.text() and tab.pin_btn.isHidden()
    tab.app_box.setCurrentIndex(0)
    listed(app, window, tab)
    assert not tab.pin_btn.isHidden()
    window.info = dict(window.info, active=1)           # another profile: the list and the button go
    tab.show_info(window.info)
    assert tab.pin_btn.isHidden()


def test_quiet_work_shows_no_banner_but_its_errors(app, window):
    """MainWindow._run(quiet=True), for work the user did not ask for (the
    OATH page's code refresh): no banner and no progress bar, errors reported
    as always."""
    done = []
    assert window._run(lambda p: (p(1, 2), 7)[1], then=done.append, quiet=True)
    assert window.busy and window.banner.isHidden() and window.progress.isHidden()
    wait_idle(app, window)
    assert done == [7] and window.banner.isHidden() and window.progress.isHidden()

    def fail(p):
        raise RuntimeError("quiet failure")
    assert window._run(fail, quiet=True)
    assert window.banner.isHidden()
    wait_idle(app, window)
    assert app.messages[-1] == ("critical", "quiet failure")
    assert window._run(lambda p: None)                  # asked for: the banner
    assert not window.banner.isHidden() and window.banner.text() == gui.T("Working...")
    wait_idle(app, window)


def test_what_quiet_work_turns_away_is_not_silent(app, window):
    """What the user asks for while quiet work runs (no banner) cannot start
    either: instead of a click that does nothing without a word, the banner
    says the window is busy, until that work ended."""
    from librefido import gui_manager
    busy_text = gui.T("Busy with work in the background...")
    gate = threading.Event()
    assert window._run(lambda p: gate.wait(10), quiet=True)
    try:
        assert not window._run(lambda p: None, quiet=True)  # more work of its own: still nothing shown
        assert window.banner.isHidden()
        turned_away = [window._ready,                                   # a button of the window
                       lambda: window._run(lambda p: None),             # an operation of a Key manager page
                       window.refresh,                                  # the Refresh button
                       gui_manager.ManagerContext(window, gui.T).free]  # a button of an OpenPGP / PIV page
        for ask in turned_away:
            window.banner.setVisible(False)
            assert not ask()
            assert not window.banner.isHidden() and window.banner.text() == busy_text
    finally:
        gate.set()
    wait_idle(app, window)
    assert window.banner.isHidden()
    # an operation the user started has its banner: left as it is
    gate.clear()
    assert window._run(lambda p: gate.wait(10))
    try:
        assert not window._ready() and window.banner.text() == gui.T("Working...")
    finally:
        gate.set()
    wait_idle(app, window)


@pytest.mark.parametrize("how", ["build", "import"])
def test_a_broken_key_manager_leaves_the_rest_of_the_window(app, monkeypatch, how):
    """When the Key manager tab cannot be imported or built, the window still
    starts, with its other tabs, and the tab says why."""
    import sys
    from librefido import gui_manager
    if how == "build":
        def broken(*a, **k):
            raise RuntimeError("the page failed")
        monkeypatch.setattr(gui_manager, "KeyManagerTab", broken)
    else:
        monkeypatch.setitem(sys.modules, "librefido.gui_manager", None)
    monkeypatch.setattr(gui, "list_devices", lambda: [])
    w = gui.MainWindow()
    try:
        tab = w.manager_tab
        assert isinstance(tab, gui.UnavailableTab) and w.tabs.tabText(w.tabs.indexOf(tab)) == gui.T("Key manager")
        assert tab.state.text() == gui.T("key-manager-failed")
        assert ("the page failed" if how == "build" else "import of librefido.gui_manager halted") in \
            tab.details.toPlainText()
        assert w.tabs.indexOf(w.keys_tab) >= 0 and w.tabs.count() == 7
        w.refresh()                                     # (its show_info does nothing)
        dev = F.FakeDevice(stream=S.stream())
        w.mgmt = F.management(dev, monkeypatch)
        monkeypatch.setattr(gui, "list_devices", lambda: [(w.mgmt.card.reader, b"")])
        w.refresh()
        assert w.info is not None
    finally:
        w.close()


def test_keys_tab_passphrase_dialog(app, window, keys):
    dlg = gui.KeyPassphraseDialog(window, gui.T)
    dlg.pass1.setText("a")
    dlg.pass2.setText("b")
    dlg._accept()
    assert not dlg.ok and app.messages[-1] == ("warning", gui.T("Passphrases differ")) and not dlg.pass1.text()
    dlg._accept()
    assert not dlg.ok and app.messages[-1] == ("warning", gui.T("Enter a passphrase"))
    dlg.plain.setChecked(True)                          # no encryption: a second confirmation, answered No
    assert not dlg.pass1.isEnabled()
    dlg._accept()
    assert not dlg.ok and app.messages[-1][0] == "question"
    app.answers["question"].append(Yes)
    dlg._accept()
    assert dlg.ok and dlg.passphrase is None


def test_keys_tab_exports_in_the_clear_only_when_confirmed(app, window, keys, monkeypatch, tmp_path):
    tab = keys
    listed(app, window, tab)
    tab.table.selectRow(2)                              # the OATH account
    path = tmp_path / "plain.lfkey"
    choose_file(monkeypatch, str(path), save=True)
    app.items.append((gui.T("LibreFido key file (.lfkey, encrypted)"), True))
    app.passphrases.append(False)                       # "do not encrypt", then answered No
    tab.export_selected()
    wait_idle(app, window)
    assert not path.exists() and not sent(window.dev, mgmt.INS_KEY_EXPORT)
    app.items.append((gui.T("LibreFido key file (.lfkey, encrypted)"), True))
    app.passphrases.append(False)
    app.answers["question"].append(Yes)
    tab.export_selected()
    wait_idle(app, window)
    assert read_key_file(str(path))[1].record[4] == OATH_SECRET
    assert gui.T("NOT encrypted: anyone with this file has the key.") in app.messages[-1][1]
    link = tmp_path / "link.txt"                        # an otpauth:// link: in the clear, confirmed
    choose_file(monkeypatch, str(link), save=True)
    app.items.append((gui.T("otpauth:// link (NOT encrypted)"), True))
    tab.export_selected()                               # answered No
    wait_idle(app, window)
    assert not link.exists() and app.messages[-1] == ("question", gui.T("otpauth-plain"))
    app.items.append((gui.T("otpauth:// link (NOT encrypted)"), True))
    app.answers["question"].append(Yes)
    tab.export_selected()
    wait_idle(app, window)
    assert stdformats.parse_otpauth(link.read_text(encoding="utf-8"))[0][4] == OATH_SECRET


def test_keys_tab_export_refusals_and_pins(app, window, keys, monkeypatch, tmp_path):
    tab = keys
    window.dev.pin = "1234"
    app.inputs.append(("1234", True))                   # the FIDO PIN, asked when the device wants it
    listed(app, window, tab)
    assert ("input", gui.T("FIDO PIN of the active profile:")) in app.messages and window.dev.retries == 8
    assert tab.table.rowCount() == 6
    tab.export_selected()                               # nothing selected
    assert app.messages[-1] == ("warning", gui.T("Select a key first."))
    tab.table.selectRow(4)                              # the OpenPGP key: its Admin PIN too
    path = str(tmp_path / "pgp.lfkey")
    choose_file(monkeypatch, path, save=True)
    app.passphrases.append(("pw", "pw"))
    app.inputs += [("12345678", True), ("1234", True)]
    tab.export_selected()
    wait_idle(app, window)
    assert sent(window.dev, mgmt.INS_KEY_EXPORT)[-1] == {1: 3, 2: b"\x01", 3: b"1234", 4: b"12345678"}
    assert read_key_file(path, "pw")[1].app == "openpgp"
    window.dev.exportable = False                       # a secure or no-export profile, a HARDENED build
    app.inputs.append(("1234", True))
    listed(app, window, tab)
    assert tab.state.text().endswith(gui.T("not-exportable"))
    tab.table.selectRow(0)
    n = len(sent(window.dev, mgmt.INS_KEY_EXPORT))
    tab.export_selected()
    assert app.messages[-1] == ("warning", gui.T("not-exportable"))
    assert len(sent(window.dev, mgmt.INS_KEY_EXPORT)) == n
    # a list of another profile (or of no device) is dropped
    window.info = dict(window.info, active=1)
    tab.show_info(window.info)
    assert tab.table.rowCount() == 0 and tab.listed_for is None and tab.state.text() == gui.T("keys-hint")
    window.dev.masks = None                             # firmware before 2.1.0
    listed(app, window, tab)
    assert tab.state.text() == gui.T("no-key-transfer") and tab.table.rowCount() == 0


def test_keys_tab_import_of_a_key_file_asks_before_replacing(app, window, keys, monkeypatch, tmp_path):
    tab = keys
    path = str(tmp_path / "fido.lfkey")
    keyfile.write_key_file(path, SingleKey("fido", dict(KEYS[0][0][1])), "pw", scrypt_log_n=10)
    choose_file(monkeypatch, path)
    app.inputs.append(("pw", True))                     # the key file's passphrase
    app.answers["question"] += [Yes, No]                # add it (the sign counter note); replace: No
    tab.import_file()
    wait_idle(app, window)
    questions = [text for kind, text in app.messages if kind == "question"]
    assert questions[0].startswith(gui.T("Add this passkey to the device?")) and gui.T("fido-counter-import") in \
        questions[0] and "FIDO passkey for example.com (alice)" in questions[0]
    assert questions[1].startswith(gui.T("Replace what is on the device?")) and "already on the device" in questions[1]
    assert [r.get(5) for r in sent(window.dev, mgmt.INS_KEY_IMPORT)] == [None]
    app.inputs.append(("pw", True))
    app.answers["question"] += [Yes, Yes]
    tab.import_file()
    wait_idle(app, window)
    assert [r.get(5) for r in sent(window.dev, mgmt.INS_KEY_IMPORT)] == [None, None, True]
    assert app.messages[-1][0] == "information" and "credential ID %s" % CRED1.hex() in app.messages[-1][1]
    plain = str(tmp_path / "plain.lfkey")               # a key file in the clear: warned first
    keyfile.write_key_file(plain, SingleKey("fido", dict(KEYS[0][0][1])), None)
    choose_file(monkeypatch, plain)
    tab.import_file()                                   # answered No
    wait_idle(app, window)
    assert app.messages[-1] == ("warning", gui.T("key-file-plain")) and len(sent(window.dev, mgmt.INS_KEY_IMPORT)) == 3


def test_keys_tab_otp_import_asks_for_the_slot_and_access_code(app, window, keys, monkeypatch, tmp_path):
    tab = keys
    path = str(tmp_path / "otp.lfkey")
    keyfile.write_key_file(path, SingleKey("otp", dict(KEYS[2][0][1])), "pw", scrypt_log_n=10)
    choose_file(monkeypatch, path)
    listed(app, window, tab)
    app.inputs += [("pw", True), (ACCESS_CODE.hex(), True)]
    app.answers["question"] += [Yes, Yes]               # add it; slot 1 is configured: replace it
    tab.import_file()
    wait_idle(app, window)
    assert ("item", gui.T("OTP slot:")) in app.messages
    assert sent(window.dev, mgmt.INS_KEY_IMPORT) == [{1: 2, 2: KEYS[2][0][1], 4: ACCESS_CODE, 5: True, 6: b"\x01"}]
    assert app.messages[-1][0] == "information" and "OTP slot 1 written" in app.messages[-1][1]
    assert tab.table.rowCount() == 0 and tab.state.text() == gui.T("The keys changed: Refresh lists them again.")


def test_keys_tab_imports_otpauth_links_and_qr_codes(app, window, keys, applets, monkeypatch, tmp_path):
    tab = keys
    app.inputs += [(TOTP_LINK, True), ("oath pw", True)]
    app.answers["question"] += [Yes, Yes]               # add it; it is there: replace it
    tab.import_link()
    wait_idle(app, window)
    assert [(k.record[1], kw["oath_password"], kw["replace"]) for k, kw in applets] == \
        [(b"Example:bob", "oath pw", False), (b"Example:bob", "oath pw", True)]
    assert app.messages[-1][0] == "information" and "added: OATH TOTP account Example:bob" in app.messages[-1][1]
    png = tmp_path / "qr.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(40))
    threads = []

    def decode(path):
        threads.append(threading.current_thread() is threading.main_thread())
        return [TOTP_LINK.replace("bob", "carol"), "https://example.com"]
    monkeypatch.setattr(stdformats, "decode_qr_image", decode)
    choose_file(monkeypatch, str(png))
    app.inputs.append(("", True))                       # no OATH password
    app.answers["question"].append(Yes)
    tab.import_qr()
    wait_idle(app, window)
    assert threads == [False]
    assert applets[-1][0].record[1] == b"Example:carol" and applets[-1][1]["oath_password"] is None
    question = [text for kind, text in app.messages if kind == "question"][-1]
    assert question.startswith(gui.T("Add this key to the device?")) and gui.T("others-qr") % 1 in question
    app.inputs.append(("otpauth://totp/x?secret=1", True))
    tab.import_link()
    assert app.messages[-1] == ("critical", "the secret is not base32") and len(applets) == 3


def test_keys_tab_imports_a_piv_key_file(app, window, keys, applets, monkeypatch, tmp_path):
    tab = keys
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _certificate(key)
    pem = tmp_path / "k.pem"
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.BestAvailableEncryption(b"key pw")) +
                    cert.public_bytes(serialization.Encoding.PEM))
    choose_file(monkeypatch, str(pem))
    app.inputs += [("key pw", True), ("", True)]        # the file's password; the default management key
    app.items.append(("9C", True))
    app.answers["question"].append(Yes)
    tab.import_file()
    wait_idle(app, window)
    assert ("input", gui.T("Password of %s:") % "k.pem") in app.messages
    [(k, kw)] = applets
    assert k.app == "piv" and k.record[8] == cert.public_bytes(serialization.Encoding.DER)
    assert kw["piv_slot"] == 0x9C and kw["piv_mgmt_key"] is None


def test_keys_tab_texts_have_both_languages(monkeypatch):
    """Every text of the Keys tab and of the key list has a Chinese
    translation, keyed texts an English one; the translations take the same
    arguments."""
    source = inspect.getsource(gui)
    section = source[source.index("# Keys tab: single keys"):source.index("def main():")]
    texts = set(re.findall(r'\bT\("((?:[^"\\]|\\.)*)"\)', section))
    texts |= set(re.findall(r'\bT\("((?:[^"\\]|\\.)*)"\)', inspect.getsource(cli.key_entry_text)))
    texts |= set(gui.KEY_APP_TITLES.values()) | set(gui.PGP_SLOT_TITLES.values())
    texts |= {"%s key" % name for name in keyio.PGP_SLOT_NAMES.values()}
    texts |= set(cli.PIV_PIN_POLICIES.values()) | set(cli.PIV_TOUCH_POLICIES.values())
    assert len(texts) > 60
    missing = sorted(t for t in texts if t not in gui.ZH)
    assert not missing
    for t in texts:
        assert re.findall(r"%[sd]", gui.ZH[t]) == re.findall(r"%[sd]", gui.EN.get(t, t)), t
        if "-" in t and " " not in t:
            assert t in gui.EN, t                       # keyed text
    monkeypatch.setattr(gui, "_LANG_ZH", True)
    joined = 0
    for n, pairs in KEYS.items():
        for entry, _ in pairs:
            name, details = cli.key_entry_text(mgmt.APPS[n], entry, gui.T)
            assert "malformed" not in details and "条目" not in details
            assert ", " not in details                  # the details joined with the full-width comma
            joined += "，" in details
    assert joined >= 4
    # the command line keeps the ASCII one
    assert cli.key_entry_text("oath", {1: b"x", 2: 0x21, 3: 6, 4: 1}) == ("x", "TOTP SHA1, 6 digits, touch")
    assert cli.key_entry_text("otp", {1: b"\x02", 2: "chal-hmac", 3: True}) == ("slot 2", "chal-hmac, access code")
    assert cli.key_entry_text("otp", {1: b"\x02", 2: "chal-hmac", 3: True}, gui.T) == ("槽位 2", "chal-hmac，有访问码")
