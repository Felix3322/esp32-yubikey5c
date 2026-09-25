"""The Passkeys, OATH and OTP pages of the Key manager end to end: the main
window finds the emulated device over PC/SC as it finds a real one, the pages
drive the real managers (mgr_fido, mgr_oath, mgr_otp); dialogs are answered
as in test_gui_manager. The emulator confirms presence by itself. Skipped
without the user-mode PC/SC stack (tests/README.md).

    bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/tools/test_gui_manager_a_emu.py
"""

import base64
import hmac
import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")
emulator = pytest.importorskip("harness.emulator")

from fido2.ctap2 import ClientPin, Ctap2  # noqa: E402
from librefido import cli, gui, keyfile, mgr_oath  # noqa: E402
from librefido import gui_mgr_pages_a as A  # noqa: E402
from librefido.gui_manager import KeyManagerTab  # noqa: E402
from librefido.keyfile import read_key_file  # noqa: E402
from librefido.mgr_common import CcidCtapDevice  # noqa: E402
import test_gui_manager  # noqa: E402
from test_gui_manager import Clock, Yes, fill_add, fill_program, texts, wait_idle  # noqa: E402

app = test_gui_manager.app              # the same fixture: dialogs answered from lists

RFC_SECRET = b"12345678901234567890"
B32 = base64.b32encode(RFC_SECRET).decode()


@pytest.fixture(scope="module")
def pcscd():
    p = emulator.Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    plugin = emulator.ensure_session() is not None
    if not plugin:
        p.start()
    yield p
    if plugin:
        emulator.ensure_session()
    else:
        p.stop()


@pytest.fixture
def device(pcscd, tmp_path):
    e = emulator.Emulator(workdir=str(tmp_path / "dev"))
    e.start()
    yield e
    e.stop()


def _release(m):
    """Closes a Management and its PC/SC context now (as tests/manager)."""
    m.close()
    c = getattr(m.card, "conn", None)
    while c is not None and not hasattr(c, "hcontext") and hasattr(c, "component"):
        c = c.component
    try:
        c.release()
    except Exception:
        pass


@pytest.fixture
def window(app, device):
    w = gui.MainWindow()                                # its refresh() looks for devices over PC/SC
    deadline = time.time() + 20
    while (w.mgmt is None or w.info is None) and time.time() < deadline:
        time.sleep(0.25)
        w.refresh()
    assert w.mgmt is not None, "the window found no device"
    yield w
    wait_idle(app, w)
    if w.mgmt is not None:
        _release(w.mgmt)
        w.mgmt = None
    w.close()


@pytest.fixture
def tab(app, window):
    t = KeyManagerTab(window, gui.T)
    t.show_info(window.info)
    yield t
    t.deleteLater()


def make_passkey(m, pin, rp_id, user_id, name, display_name):
    """A discoverable credential made over the window's connection, as a
    browser would (CTAP over the smart card interface)."""
    c = Ctap2(CcidCtapDevice(m))
    cp = ClientPin(c)
    token = cp.get_pin_token(pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, rp_id)
    cdh = os.urandom(32)
    c.make_credential(cdh, {"id": rp_id, "name": rp_id}, {"id": user_id, "name": name, "displayName": display_name},
                      [{"type": "public-key", "alg": -7}], options={"rk": True},
                      pin_uv_param=cp.protocol.authenticate(token, cdh), pin_uv_protocol=cp.protocol.VERSION)


def prompts(app):
    return [text for kind, text in app.messages if kind == "input"]


def test_passkeys_page(app, window, tab):
    page = tab.pages[0]
    page.refresh()
    wait_idle(app, window)
    assert page.state.text() == A.EN["fido-no-pin"] and page.pin_btn.text() == "Set PIN..."
    app.new_secrets.append("123456")
    page.change_pin()
    wait_idle(app, window)
    assert app.messages[-1] == ("information", "FIDO PIN set.") and page.state.text() == "Passkeys: 0"
    assert "FIDO PIN set (8 attempts left)" in page.summary.text()
    # a passkey made by "a browser": its PIN token ends the page's, which asks for the PIN again
    make_passkey(window.mgmt, "123456", "example.com", b"user-1", "alice", "Alice")
    app.inputs += [("000000", True), ("123456", True)]
    page.refresh()
    wait_idle(app, window)
    assert prompts(app)[0] == "FIDO PIN of the active profile:"
    assert "wrong PIN, 7 tries left" in prompts(app)[1]
    assert [r[:3] for r in texts(page.table)] == [["example.com", "alice", "Alice"]]
    assert texts(page.table)[0][3].startswith("ES256")
    page.table.selectRow(0)
    app.edits.append(["alice2", "Alice Two"])
    page.edit_user()
    wait_idle(app, window)
    assert [r[:3] for r in texts(page.table)] == [["example.com", "alice2", "Alice Two"]]
    page.table.selectRow(0)
    app.answers["warning"].append(Yes)
    page.delete()
    wait_idle(app, window)
    assert page.table.rowCount() == 0 and app.messages[-1] == ("information", "Passkey deleted.")
    app.inputs.append(("123456", True))
    app.new_secrets.append("654321")
    page.change_pin()
    wait_idle(app, window)
    assert app.messages[-1] == ("information", "FIDO PIN changed.") and page.state.text() == "Passkeys: 0"


def test_oath_page(app, window, tab, monkeypatch, tmp_path):
    page = tab.pages[1]
    page.clock = Clock(59.0)
    page.refresh()
    wait_idle(app, window)
    assert page.state.text() == "OATH accounts: 0"
    monkeypatch.setattr(A.OathAddDialog, "exec", fill_add({"issuer": "RFC6238", "account": "sha1", "secret": B32}))
    page.add_account()
    wait_idle(app, window)
    assert texts(page.table)[0][:4] == ["RFC6238", "sha1", "287082", "1 s"]     # RFC 6238 at 59 s
    page.clock.t = 60.0
    page.tick()
    wait_idle(app, window)
    assert texts(page.table)[0][2:4] == [mgr_oath.totp(RFC_SECRET, 60), "30 s"]
    # a touch account and a HOTP account (from a link): calculated on demand
    monkeypatch.setattr(A.OathAddDialog, "exec", fill_add({"issuer": "T", "account": "touchy", "secret": B32,
                                                           "touch": True}))
    page.add_account()
    wait_idle(app, window)
    monkeypatch.setattr(A.OathAddDialog, "exec", fill_add({}, lambda dlg: dlg.link.setText(
        "otpauth://hotp/Bank:carol?secret=%s&issuer=Bank&counter=0" % B32)))
    page.add_account()
    wait_idle(app, window)
    rows = {r[1]: r for r in texts(page.table)}
    assert rows["touchy"][2:4] == ["", "touch: press Calculate"] and rows["carol"][2:4] == ["", "press Calculate"]
    for account, code in (("touchy", mgr_oath.totp(RFC_SECRET, 60)), ("carol", "755224")):
        page.table.selectRow([a["account"] for a in page.rows].index(account))
        page.calculate()
        wait_idle(app, window)
        assert {r[1]: r for r in texts(page.table)}[account][2] == code
    # export through the Keys tab (a key file), delete, import it back
    monkeypatch.setattr(cli, "write_key_file", lambda *a, **k: keyfile.write_key_file(*a, scrypt_log_n=10, **k))

    def passphrase(dlg):
        dlg.pass1.setText("pw")
        dlg.pass2.setText("pw")
        dlg._accept()
        return 1
    monkeypatch.setattr(gui.KeyPassphraseDialog, "exec", passphrase)
    path = str(tmp_path / "sha1.lfkey")
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (path, "")))
    monkeypatch.setattr(QtWidgets.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (path, "")))
    page.table.selectRow([a["account"] for a in page.rows].index("sha1"))
    page.export()
    wait_idle(app, window)
    key = read_key_file(path, "pw")[1]
    assert key.app == "oath" and key.record[1] == b"RFC6238:sha1" and key.record[4][:20] == RFC_SECRET
    page.table.selectRow([a["account"] for a in page.rows].index("sha1"))
    app.answers["warning"].append(Yes)
    page.delete()
    wait_idle(app, window)
    assert "sha1" not in [a["account"] for a in page.rows]
    app.inputs += [("pw", True), ("", True)]            # the key file's passphrase; no OATH password
    app.answers["question"].append(Yes)                 # add it
    page.import_keys()
    deadline = time.time() + 20
    while "sha1" not in [a["account"] for a in page.rows] and time.time() < deadline:
        app.processEvents()
        time.sleep(0.02)
    assert "sha1" in [a["account"] for a in page.rows]
    # a password: a new manager (another connection) asks for it
    app.new_secrets.append("secret pw")
    page.set_password()
    wait_idle(app, window)
    page.device_changed()
    app.inputs += [("wrong", True), ("secret pw", True)]
    page.refresh()
    wait_idle(app, window)
    assert prompts(app)[-2:] == ["OATH password:", "wrong OATH password\n\nOATH password:"]
    assert page.table.rowCount() == 3 and "protected by a password" in page.state.text()
    app.answers["warning"] += [Yes, Yes]
    page.reset()
    wait_idle(app, window)
    assert page.table.rowCount() == 0 and page.state.text() == "OATH accounts: 0"


def test_otp_page(app, window, tab, monkeypatch):
    page = tab.pages[2]
    page.refresh()
    wait_idle(app, window)
    assert [page.slots[s]["label"].text() for s in (1, 2)] == ["Empty", "Empty"]
    key = bytes(range(1, 21))
    mode = page.slots[2]["mode"]
    mode.setCurrentIndex(mode.findData("chal-hmac"))
    monkeypatch.setattr(A.OtpProgramDialog, "exec", fill_program({"key": key.hex()}))
    page.program(2)
    wait_idle(app, window)
    assert app.messages[-1] == ("information", "Slot 2 programmed.")
    assert page.slots[2]["label"].text().startswith("Challenge-response (HMAC-SHA1)")
    app.inputs.append(("00112233", True))
    page.test(2)
    wait_idle(app, window)
    assert app.messages[-1] == ("information", "Challenge: 00112233\nResponse: " +
                                hmac.new(key, bytes.fromhex("00112233"), "sha1").hexdigest())
    # Yubico OTP with an access code: the summary for the upload
    summaries = []
    monkeypatch.setattr(A.SecretSummaryDialog, "show_text", classmethod(
        lambda cls, parent, T, title, text: summaries.append(text)))
    monkeypatch.setattr(A.OtpProgramDialog, "exec", fill_program({"new_code": "010203040506",
                                                                  "new_code_repeat": "010203040506"}, generate=True))
    page.program(1)
    wait_idle(app, window)
    public_id = [line for line in summaries[0].splitlines() if line.startswith("Public ID: ")][0][11:]
    assert public_id.startswith("vv") and len(public_id) == 12
    assert page.slots[1]["label"].text().startswith("Yubico OTP, public ID " + public_id)
    # deleting it needs the access code (asked for; a wrong one again)
    app.answers["warning"].append(Yes)
    app.inputs += [("0a0a0a0a0a0a", True), ("010203040506", True)]
    page.delete(1)
    wait_idle(app, window)
    assert prompts(app)[-2].startswith("OTP slot 1: delete: protected by an access code")
    assert prompts(app)[-1].startswith("OTP slot 1: delete: wrong access code")
    assert page.slots[1]["label"].text() == "Empty"
    app.answers["warning"].append(Yes)
    page.swap()
    wait_idle(app, window)
    assert page.slots[1]["label"].text().startswith("Challenge-response (HMAC-SHA1)")
    assert page.slots[2]["label"].text() == "Empty"
