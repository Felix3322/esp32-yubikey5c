"""librefido-gui without a device (offscreen, simulated device): secrets are
not kept, a failed load drops the previous backup, imports and plaintext
exports are confirmed, device and backup names are shown as plain text, the
PIN is asked for when the device wants one, slow work runs in the worker."""

import os
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

import fakedev as F                     # noqa: E402
import lfstreams as S                   # noqa: E402
from fido2 import cbor                  # noqa: E402
from librefido import gui               # noqa: E402
from librefido.backup import write_file  # noqa: E402

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
