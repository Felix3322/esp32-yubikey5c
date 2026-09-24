"""librefido-gui against the emulator, rendered offscreen.

    PYTHONPATH=tests:tools/librefido python -m pytest tests/profiles/test_gui_smoke.py
"""

import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

from harness import ctaphid                     # noqa: E402
from harness.emulator import Emulator, Pcscd    # noqa: E402
from librefido import firmware, gui             # noqa: E402
from librefido.backup import read_file          # noqa: E402
from librefido.mgmt import Management           # noqa: E402


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    ctaphid.install()
    yield p
    p.stop()


@pytest.fixture
def app(monkeypatch):
    a = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    messages = []
    for kind in ("information", "warning", "critical"):
        monkeypatch.setattr(QtWidgets.QMessageBox, kind,
                            staticmethod(lambda parent, title, text, *a, _k=kind: messages.append((_k, text))))
    a.messages = messages
    return a


def wait_idle(app, w, timeout=40.0):
    deadline = time.time() + timeout
    while w.busy and time.time() < deadline:
        app.processEvents()
        time.sleep(0.02)
    assert not w.busy, "GUI operation did not finish"
    app.processEvents()


def test_gui_manages_the_device(pcscd, app, tmp_path, monkeypatch):
    e = Emulator(workdir=str(tmp_path / "dev"))
    e.start()
    try:
        Management.open(timeout=15).close()
        w = gui.MainWindow()
        assert w.mgmt is not None, app.messages
        assert w.table.item(0, 3).text() == gui.T("active")
        assert w.table.item(1, 3).text() == gui.T("empty")

        # storage scrub through the worker machinery
        w._run(lambda p: w.mgmt.health(scrub=True), then=w._show_health)
        wait_idle(app, w)
        assert w.health_state.text() == gui.T("Healthy")

        # export an encrypted backup
        path = str(tmp_path / "p1.lfbk")
        monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (path, "")))
        w.pass1.setText("pw")
        w.pass2.setText("pw")
        w._export()
        wait_idle(app, w)
        info, stream = read_file(path, "pw")
        assert info["encrypted"] and stream

        # switch to profile 2: the device restarts and the GUI reconnects
        w.table.selectRow(1)
        assert w._selected_slot() == 1
        w._switch()
        assert w.busy
        wait_idle(app, w)
        assert w.info["active"] == 1, (app.messages, w.statusBar().currentMessage(), w.mgmt)
        assert w.table.item(1, 3).text() == gui.T("active")

        # firmware update from a file, confirmed once the new firmware answers
        fw_path = str(tmp_path / "fw.bin")
        with open(e.binary, "rb") as f:
            new = firmware.set_version(f.read(), (2, 0, 7))
        with open(fw_path, "wb") as f:
            f.write(new)
        monkeypatch.setattr(QtWidgets.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (fw_path, "")))
        monkeypatch.setattr(QtWidgets.QMessageBox, "question",
                            staticmethod(lambda *a, **k: QtWidgets.QMessageBox.StandardButton.Yes))
        w._update_firmware()
        wait_idle(app, w, timeout=240)                  # the image is the emulator itself (large with ASan)
        assert w.info["firmware"] == "2.0.7", app.messages
        assert not w.info["firmware_slot"]["unconfirmed"]
        assert "2.0.7" in w.fw_state.text()
        assert w.info["active"] == 1                    # profiles untouched
        assert not [m for m in app.messages if m[0] == "critical"], app.messages
        w.close()
    finally:
        e.stop()


def test_gui_security_tab(pcscd, app, tmp_path, monkeypatch):
    """The Security tab: presence per application, LED brightness, binding
    the root key and locking debugging (level 2), a secure profile."""
    e = Emulator(workdir=str(tmp_path / "dev"))
    e.start()
    try:
        Management.open(timeout=15).close()
        w = gui.MainWindow()
        tab = w.security_tab
        assert w.tabs.tabText(w.tabs.indexOf(tab)) == gui.T("Security")
        assert w.mgmt is not None and "0 / 3" in tab.level.text(), app.messages
        monkeypatch.setattr(QtWidgets.QMessageBox, "question",
                            staticmethod(lambda *a, **k: QtWidgets.QMessageBox.StandardButton.Yes))
        monkeypatch.setattr(gui.gui_policy, "metadata_dir", lambda: str(tmp_path))

        # automatic presence for FIDO (the emulator confirms the touch itself)
        tab.need_touch["fido"].setChecked(False)
        tab._apply_presence()
        wait_idle(app, w)
        assert w.info["profiles"][0]["auto_presence"] == ["fido"], app.messages
        tab.need_touch["fido"].setChecked(True)         # a touch again (needs none itself)
        tab._apply_presence()
        wait_idle(app, w)
        assert w.info["profiles"][0]["auto_presence"] == []

        # LED brightness, applied at once
        tab.bright.setValue(40)
        tab._brightness()
        wait_idle(app, w)
        assert w.info["board"]["led_brightness"] == 40

        # level 2: bind the root key, lock debugging (typed confirmations)
        confirm = "BURN %s" % w.info["chip_serial"]
        monkeypatch.setattr(QtWidgets.QInputDialog, "getText", staticmethod(lambda *a, **k: (confirm, True)))
        tab._bind()
        wait_idle(app, w)
        assert w.info["security"]["root_key"] == "flash, bound to HMAC eFuse key", app.messages
        tab._lock_debug()
        wait_idle(app, w)
        sec = w.info["security"]
        assert sec["jtag_disabled"] and sec["download_restricted"] and "2 / 3" in tab.level.text(), app.messages

        # a secure profile in slot 3; the device restarts and the GUI reconnects
        tab.slot.setCurrentIndex(2)
        tab._create_secure()
        wait_idle(app, w, timeout=60)
        p = w.info["profiles"][2]
        assert p["used"] and p["secure"] and p["no_export"], app.messages
        assert not [m for m in app.messages if m[0] == "critical"], app.messages
        w.close()
    finally:
        e.stop()
