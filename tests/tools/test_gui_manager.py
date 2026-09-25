"""The Key manager tab of librefido-gui (gui_manager, gui_mgr_pages_a)
without a device: offscreen, the main window on a simulated device, the
FIDO / OATH / OTP managers replaced by fakes. Device work runs in the worker,
the PIN / password / access code is asked for when the manager wants it (and
again after a wrong one) and not kept, destructive actions are confirmed
(resets twice), OATH codes follow a fake clock, errors are shown."""

import ast
import inspect
import os
import re
import sys
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")
QtCore = pytest.importorskip("PySide6.QtCore")

import fakedev as F                     # noqa: E402
import lfstreams as S                   # noqa: E402
from librefido import cli, gui, gui_manager, keyfile, mgr_oath, mgr_otp, stdformats  # noqa: E402
from librefido import gui_mgr_pages_a as A  # noqa: E402
from librefido.gui_manager import KeyManagerTab, ManagerContext  # noqa: E402
from librefido.keyfile import read_key_file  # noqa: E402
from librefido.mgr_common import AuthRequired, ManagerError, WrongSecret  # noqa: E402
from librefido.mgr_fido import FidoPinNotSet, FidoPinRequired  # noqa: E402
from librefido.mgr_oath import OathPasswordRequired  # noqa: E402
from test_cli import KEYS, OATH_SECRET, TOTP_LINK, KeyDevice  # noqa: E402

Yes, No = QtWidgets.QMessageBox.StandardButton.Yes, QtWidgets.QMessageBox.StandardButton.No
MAIN = threading.main_thread


# ----------------------------------------------------------------------------
# Fixtures: dialogs answered from lists, the window on a simulated device
# ----------------------------------------------------------------------------

@pytest.fixture
def app(monkeypatch):
    a = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    monkeypatch.setattr(gui, "_LANG_ZH", False)
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
    a.items = []
    monkeypatch.setattr(QtWidgets.QInputDialog, "getItem", staticmethod(
        lambda parent, title, label, items, current=0, editable=True, *x, **k:
        (a.messages.append(("item", label)), a.items.pop(0) if a.items else (items[current], True))[1]))
    # the page dialogs of gui_manager (tested on their own below)
    a.new_secrets = []
    monkeypatch.setattr(A, "ask_new_secret", lambda ctx, title, label, **k: (
        a.messages.append(("new", label)), a.new_secrets.pop(0) if a.new_secrets else None)[1])
    a.edits = []
    monkeypatch.setattr(A, "edit_texts", lambda ctx, title, fields, **k: (
        a.messages.append(("edit", [v for _, v in fields])), a.edits.pop(0) if a.edits else None)[1])
    return a


def wait_idle(app, w, timeout=20.0):
    deadline = time.time() + timeout
    while True:
        app.processEvents()
        if not w.busy or time.time() > deadline:
            break
        time.sleep(0.01)
    assert not w.busy
    app.processEvents()


def settle(app, w, quiet=0.6, timeout=20.0):
    """Processes events until no operation has run for `quiet` seconds (what
    waits in ManagerContext.when_idle, polled every 250 ms, has started and
    ended)."""
    deadline = time.time() + timeout
    idle_since = None
    while time.time() < deadline:
        app.processEvents()
        if w.busy:
            idle_since = None
        elif idle_since is None:
            idle_since = time.time()
        elif time.time() - idle_since >= quiet:
            break
        time.sleep(0.01)
    assert not w.busy
    app.processEvents()


@pytest.fixture
def window(app, monkeypatch):
    monkeypatch.setattr(gui, "list_devices", lambda: [])       # never touch a real reader
    w = gui.MainWindow()
    dev = KeyDevice(stream=S.stream())
    w.mgmt = F.management(dev, monkeypatch)
    monkeypatch.setattr(gui, "list_devices", lambda: [(w.mgmt.card.reader, b"")])
    w.refresh()
    assert w.info is not None
    w.dev = dev
    yield w
    wait_idle(app, w)
    w.close()


@pytest.fixture
def tab(app, window):
    t = KeyManagerTab(window, gui.T)
    t.show_info(window.info)
    yield t
    t.deleteLater()


def texts(table, col=None):
    rows = [[table.item(r, c).text() for c in range(table.columnCount())] for r in range(table.rowCount())]
    return [r[col] for r in rows] if col is not None else rows


def kinds(app):
    return [k for k, _ in app.messages]


def nothing_kept(window):
    """The worker keeps neither the work function nor the callbacks (which
    hold what an operation needed: a PIN, a password, a key)."""
    return window._job is None or (window._job.fn is None and window._then is None and window._on_error is None)


def holds(obj, secret):
    """Whether obj's attributes (one level into containers) hold secret."""
    for v in vars(obj).values():
        values = list(v.values()) if isinstance(v, dict) else list(v) if isinstance(v, (list, tuple, set)) else [v]
        if any(x == secret for x in values):
            return True
    return False


# ----------------------------------------------------------------------------
# Fake managers (device state shared by every manager object made for it)
# ----------------------------------------------------------------------------

class Calls(list):
    def add(self, *entry):
        self.append(entry)
        self.threads.append(threading.current_thread() is MAIN())

    def names(self):
        return [c[0] for c in self]


def calls():
    c = Calls()
    c.threads = []
    return c


class FidoState:
    def __init__(self):
        self.pin = "1234"
        self.retries = 8
        self.creds = [
            {"rp_id": "example.com", "rp_id_hash": bytes(32), "credential_id": b"\x01" * 42, "user_id": b"u-1",
             "user_name": "alice", "display_name": "Alice", "cred_protect": 2, "large_blob_key": True,
             "public_key_alg": -7, "third_party_payment": False},
            {"rp_id": "rp.example", "rp_id_hash": bytes(32), "credential_id": b"\x02" * 42, "user_id": b"u-2",
             "user_name": "<b>bob</b>", "display_name": None, "cred_protect": None, "large_blob_key": False,
             "public_key_alg": -8, "third_party_payment": False}]
        self.calls = calls()
        self.fail = {}
        self.made = 0


class FakeFido:
    def __init__(self, m, st):
        self.m, self.st, self.token = m, st, False
        st.made += 1

    def _call(self, name, *args):
        self.st.calls.add(name, *args)
        e = self.st.fail.pop(name, None)
        if e:
            raise e

    def _need_token(self):
        if self.st.pin is None:
            raise FidoPinNotSet("FIDO: no PIN")
        if not self.token:
            raise FidoPinRequired("FIDO: enter the FIDO PIN to manage passkeys")

    def info(self):
        self._call("info")
        st = self.st
        return {"versions": ["FIDO_2_0", "FIDO_2_1"], "aaguid": "00" * 16, "options": {}, "pin_set": st.pin is not None,
                "pin_retries": st.retries if st.pin else None, "min_pin_length": 4, "force_pin_change": False,
                "remaining_rk": 98, "cred_mgmt": True, "unlocked": self.token}

    def unlock(self, pin):
        self._call("unlock", pin)
        if pin != self.st.pin:
            self.st.retries -= 1
            raise WrongSecret("FIDO PIN: wrong PIN, %d tries left" % self.st.retries, None,
                              "FIDO PIN：PIN 错误，还剩 %d 次" % self.st.retries, retries=self.st.retries)
        self.token = True

    def list_credentials(self):
        self._call("list_credentials")
        self._need_token()
        return [dict(c) for c in self.st.creds]

    def delete_credential(self, cid):
        self._call("delete_credential", cid)
        self._need_token()
        self.st.creds = [c for c in self.st.creds if c["credential_id"] != cid]

    def update_user(self, cid, uid, name, display_name):
        self._call("update_user", cid, uid, name, display_name)
        self._need_token()
        for c in self.st.creds:
            if c["credential_id"] == cid:
                c.update(user_name=name or None, display_name=display_name or None)

    def set_pin(self, new):
        self._call("set_pin", new)
        self.st.pin, self.token = new, False

    def change_pin(self, old, new):
        self._call("change_pin", old, new)
        if old != self.st.pin:
            raise WrongSecret("change FIDO PIN: wrong PIN, 7 tries left", None, "修改 FIDO PIN：PIN 错误，还剩 7 次", 7)
        self.st.pin, self.token = new, False

    def lock(self):
        self.token = False


def code_of(raw, ts, period=30):
    return "%06d" % ((int(ts) // period * 7919 + len(raw)) % 1000000)


class OathState:
    def __init__(self):
        self.password = None
        self.accounts = {}
        for raw, kind, touch in ((b"Example:alice", "totp", False), (b"GitHub:bob", "totp", True),
                                 (b"Bank:carol", "hotp", False), (b"60/Slow:dave", "totp", False)):
            self.put(raw, kind, touch)
        self.calls = calls()
        self.fail = {}

    def put(self, raw, kind="totp", touch=False, secret=OATH_SECRET):
        name = raw.decode()
        issuer, account, period = mgr_oath.parse_name(raw, mgr_oath.TYPES[kind])
        self.accounts[raw] = {"raw": raw, "name": name, "issuer": issuer, "account": account, "type": kind,
                              "algorithm": "SHA1", "digits": 6, "period": period if kind == "totp" else None,
                              "touch": touch, "secret": secret}


class FakeOath:
    def __init__(self, m, st):
        self.m, self.st, self.key = m, st, None

    def _call(self, name, *args, auth=True):
        self.st.calls.add(name, *args)
        e = self.st.fail.pop(name, None)
        if e:
            raise e
        if auth and self.st.password is not None and self.key != self.st.password:
            raise OathPasswordRequired("OATH: the accounts are protected by a password; enter it")

    def status(self):
        self._call("status", auth=False)
        pw = self.st.password
        return {"password_set": pw is not None, "locked": pw is not None and self.key != pw, "device_id": "X",
                "version": "1.0"}

    def unlock(self, password):
        self._call("unlock", password, auth=False)
        if self.st.password is None:
            return False
        if password != self.st.password:
            raise WrongSecret("wrong OATH password", 0x6984, "OATH 密码错误")
        self.key = password
        return True

    def lock(self):
        self.key = None

    def list(self):
        self._call("list")
        return [{k: v for k, v in a.items() if k != "secret"} for a in self.st.accounts.values()]

    def calculate_all(self, timestamp=None):
        self._call("calculate_all", timestamp)
        return {raw: None if a["touch"] or a["type"] == "hotp" else code_of(raw, timestamp, a["period"])
                for raw, a in self.st.accounts.items()}

    def calculate(self, raw, timestamp=None):
        self._call("calculate", raw, timestamp)
        a = self.st.accounts[raw]
        return code_of(raw, timestamp, a["period"] or 30)

    def add(self, issuer, account, secret, type="totp", algorithm="SHA1", digits=6, period=30, counter=0,
            touch=False, replace=False):
        self._call("add", dict(issuer=issuer, account=account, secret=secret, type=type, algorithm=algorithm,
                               digits=digits, period=period, counter=counter, touch=touch, replace=replace))
        raw = mgr_oath.build_name(issuer, account, mgr_oath.TYPES[type], period)
        if raw in self.st.accounts and not replace:
            raise ManagerError("OATH: an account named x is already on the device; replace it explicitly", 0x6A89)
        self.st.put(raw, type, touch, secret)
        return raw

    def add_record(self, record, replace=False):
        self._call("add_record", record, replace)
        kind = "hotp" if record[2] & 0xF0 == stdformats.OATH_HOTP else "totp"
        self.st.put(record[1], kind, bool(record.get(6)), record[4])
        return record[1]

    def rename(self, raw, issuer, account):
        self._call("rename", raw, issuer, account)
        a = self.st.accounts.pop(raw)
        new = mgr_oath.build_name(issuer, account, mgr_oath.TYPES[a["type"]], a["period"] or 30)
        self.st.put(new, a["type"], a["touch"], a["secret"])
        return new

    def delete(self, raw):
        self._call("delete", raw)
        del self.st.accounts[raw]

    def set_password(self, new):
        self._call("set_password", new)
        self.st.password = new or None
        self.key = new or None

    def reset(self):
        self._call("reset", auth=False)
        self.st.accounts, self.st.password, self.key = {}, None, None


class OtpState:
    def __init__(self):
        self.slots = {1: {"configured": True, "touch_triggered": True, "mode": "yubico-otp",
                          "public_id": "vvcccccccccc", "digits": None, "append_cr": True, "touch": None},
                      2: {"configured": False, "touch_triggered": False, "mode": None, "public_id": None,
                          "digits": None, "append_cr": None, "touch": None}}
        self.codes = {1: bytes.fromhex("010203040506"), 2: None}
        self.calls = calls()
        self.fail = {}


class FakeOtp:
    def __init__(self, m, st):
        self.m, self.st = m, st

    def _call(self, name, *args):
        self.st.calls.add(name, *args)
        e = self.st.fail.pop(name, None)
        if e:
            raise e

    def _code(self, slot, access_code):
        need = self.st.codes.get(slot)
        if need and access_code is None:
            raise AuthRequired("OTP slot %d: protected by an access code; enter it" % slot, 0x6982)
        if need and access_code != need:
            raise WrongSecret("OTP slot %d: wrong access code" % slot, 0x6982)

    def status(self):
        self._call("status")
        return {"version": "3.4.0", "serial": 1234, "slots": {s: dict(v) for s, v in self.st.slots.items()}}

    def _program(self, name, slot, mode, access_code, replace, new_access_code, kw):
        self._call(name, slot, dict(kw, access_code=access_code, new_access_code=new_access_code, replace=replace))
        self._code(slot, access_code)
        if self.st.slots[slot]["configured"] and not replace:
            raise ManagerError("OTP slot %d: the slot is programmed; replace it explicitly" % slot, 0x6A89)
        self.st.slots[slot] = dict(self.st.slots[slot], configured=True, mode=mode)
        self.st.codes[slot] = new_access_code

    def program_yubico_otp(self, slot, public_id, private_id, key, access_code=None, new_access_code=None,
                           append_cr=True, replace=False):
        self._program("program_yubico_otp", slot, "yubico-otp", access_code, replace, new_access_code,
                      dict(public_id=public_id, private_id=private_id, key=key, append_cr=append_cr))

    def program_chalresp(self, slot, key, touch=False, access_code=None, new_access_code=None, replace=False):
        self._program("program_chalresp", slot, "chal-hmac", access_code, replace, new_access_code,
                      dict(key=key, touch=touch))

    def program_static(self, slot, password, layout="us", append_cr=True, access_code=None, new_access_code=None,
                       replace=False):
        self._program("program_static", slot, "static", access_code, replace, new_access_code,
                      dict(password=password, layout=layout, append_cr=append_cr))

    def program_hotp(self, slot, secret, digits=6, counter=0, append_cr=True, access_code=None,
                     new_access_code=None, replace=False):
        self._program("program_hotp", slot, "hotp", access_code, replace, new_access_code,
                      dict(secret=secret, digits=digits, counter=counter, append_cr=append_cr))

    def set_access_code(self, slot, new_access_code, access_code=None):
        self._call("set_access_code", slot, new_access_code, access_code)
        self._code(slot, access_code)
        self.st.codes[slot] = new_access_code

    def delete(self, slot, access_code=None):
        self._call("delete", slot, access_code)
        self._code(slot, access_code)
        self.st.slots[slot] = dict(self.st.slots[slot], configured=False, mode=None, public_id=None)
        self.st.codes[slot] = None

    def swap(self, access_code=None):
        self._call("swap", access_code)
        for slot in (1, 2):
            self._code(slot, access_code)
        s = self.st.slots
        s[1], s[2] = s[2], s[1]
        self.st.codes[1], self.st.codes[2] = self.st.codes[2], self.st.codes[1]

    def calculate_hmac(self, slot, challenge):
        self._call("calculate_hmac", slot, challenge)
        return bytes(20)


@pytest.fixture
def fido(monkeypatch):
    st = FidoState()
    monkeypatch.setattr(A, "FidoManager", lambda m: FakeFido(m, st))
    return st


@pytest.fixture
def oath(monkeypatch):
    st = OathState()
    monkeypatch.setattr(A, "OathManager", lambda m: FakeOath(m, st))
    return st


@pytest.fixture
def otp(monkeypatch):
    st = OtpState()
    monkeypatch.setattr(A, "OtpManager", lambda m: FakeOtp(m, st))
    return st


# ----------------------------------------------------------------------------
# Tab and context
# ----------------------------------------------------------------------------

def test_tab_pages_and_device_change(app, window, tab, fido, oath, monkeypatch):
    assert [tab.tabs.tabText(i) for i in range(tab.tabs.count())] == ["Passkeys", "OATH", "OTP", "OpenPGP", "PIV"]
    assert tab.title() == "Key manager"
    passkeys, oath_page = tab.pages[0], tab.pages[1]
    app.inputs.append(("1234", True))
    passkeys.refresh()
    wait_idle(app, window)
    assert passkeys.table.rowCount() == 2 and fido.made == 1
    oath_page.refresh()
    wait_idle(app, window)
    assert oath_page.table.rowCount() == 4
    tab.show_info(window.info)                          # same device, profile, boot: kept
    assert passkeys.table.rowCount() == 2 and passkeys.loaded
    window.info = dict(window.info, active=1)           # another profile: every page drops what it read
    tab.show_info(window.info)
    assert passkeys.table.rowCount() == 0 and not passkeys.loaded and passkeys._mgr is None
    assert oath_page.table.rowCount() == 0 and oath_page.codes == {} and not oath_page.live
    assert passkeys.state.text() == A.EN["passkeys-hint"]
    tab.show_info(None)                                 # no device
    assert tab._identity is None
    # a manager is made anew for another card connection (its token is gone)
    tab.show_info(window.info)
    app.inputs.append(("1234", True))
    passkeys.refresh()
    wait_idle(app, window)
    assert fido.made == 2 and passkeys.table.rowCount() == 2
    old = passkeys._mgr
    window.mgmt = F.management(KeyDevice(stream=S.stream()), monkeypatch)
    app.inputs.append(("1234", True))
    passkeys.refresh()
    wait_idle(app, window)
    assert fido.made == 3 and passkeys._mgr is not old and passkeys._mgr.m is window.mgmt


def test_main_window_tab_follows_the_device(app, window, fido):
    """The main window's own Key manager tab, right after Keys, follows the
    window's device: when it is shown, while it is visible (a timer, also
    for changes that do not pass through a refresh of the window) and after
    the window's Refresh button (show_info), its pages drop what they read
    (the FIDO token with its manager) once the device, profile or connection
    changed."""
    tab = window.manager_tab
    i = window.tabs.indexOf(tab)
    assert [window.tabs.tabText(k) for k in (i - 1, i)] == ["Keys", "Key manager"] and tab.title() == "Key manager"
    passkeys = tab.pages[0]
    window.show()
    window.tabs.setCurrentIndex(i)
    wait_idle(app, window)
    assert tab._sync_timer.isActive() and tab._identity == tab._identity_of(window.info)
    assert passkeys.loaded and "input" not in kinds(app) and fido.made == 1     # shown: loaded, no PIN prompt
    app.inputs.append(("1234", True))
    passkeys.refresh()
    wait_idle(app, window)
    assert passkeys.table.rowCount() == 2 and passkeys._mgr.token
    # the window changed profile without a word to the tab: the visible tab notices, the page loads anew
    window.info = dict(window.info, active=(window.info.get("active") or 0) + 1)
    deadline = time.time() + 5
    while fido.made < 2 and time.time() < deadline:
        app.processEvents()
        time.sleep(0.02)
    wait_idle(app, window)
    assert fido.made == 2 and passkeys.loaded and passkeys.table.rowCount() == 0 and not passkeys._mgr.token
    assert tab._identity == tab._identity_of(window.info)
    # hidden: no timer; the window's Refresh button reads the device's own profile again
    window.tabs.setCurrentIndex(0)
    app.processEvents()
    assert not tab._sync_timer.isActive()
    window.refresh_btn.click()
    wait_idle(app, window)
    assert tab._identity == tab._identity_of(window.info) and passkeys._mgr is None and not passkeys.loaded
    assert fido.made == 2                               # (hidden: nothing loaded)
    window.hide()


def test_main_window_refresh_tells_the_key_manager(app, window, fido, monkeypatch):
    """The main window hands each refresh to its Key manager (show_info),
    hidden or not and without waiting for the tab's timer: the pages of
    another profile drop what they read at once, and so do they without a
    device."""
    tab = window.manager_tab
    passkeys = tab.pages[0]
    assert tab._identity == tab._identity_of(window.info) and not tab._sync_timer.isActive()
    app.inputs.append(("1234", True))
    passkeys.refresh()
    wait_idle(app, window)
    assert passkeys.loaded and passkeys._mgr.token
    mgr = passkeys._mgr
    real = window.mgmt.info
    window.mgmt.info = lambda lock=True: dict(real(lock=lock), active=(real(lock=lock).get("active") or 0) + 1)
    window.refresh()                                    # another profile
    assert tab._identity == tab._identity_of(window.info) and passkeys._mgr is None and not passkeys.loaded
    assert not mgr.token                                # (wiped)
    monkeypatch.setattr(gui, "list_devices", lambda: [])
    window.refresh()                                    # no device
    assert tab._identity is None


def test_device_change_wipes_what_the_managers_hold(app, window, tab, fido, oath):
    """Another device, profile or boot: the pages' managers are not only
    dropped, what they hold is wiped first (lock / forget: the OATH access
    key, the FIDO token), once no operation may use it any more. A manager
    made anew for another card connection wipes the one it replaces."""
    passkeys, page = tab.pages[0], tab.pages[1]
    oath.password = "pw"
    app.inputs += [("1234", True), ("pw", True)]
    passkeys.refresh()
    wait_idle(app, window)
    page.refresh()
    wait_idle(app, window)
    fido_mgr, oath_mgr = passkeys._mgr, page._mgr
    assert fido_mgr.token and oath_mgr.key == "pw"
    window.busy = True                                  # an operation may still use them: wiped once it ended
    window.info = dict(window.info, active=1)
    tab.show_info(window.info)
    assert passkeys._mgr is None and page._mgr is None and fido_mgr.token and oath_mgr.key == "pw"
    window.busy = False
    deadline = time.time() + 5
    while (fido_mgr.token or oath_mgr.key is not None) and time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert not fido_mgr.token and oath_mgr.key is None
    # the real OathManager: its access key (a bytearray) is zeroed, not only dropped
    real = mgr_oath.OathManager(window.mgmt)
    key = bytearray(b"\x55" * 16)
    real._key, real._salt = key, b"salt"
    page._mgr, page._mgr_for = real, window.mgmt
    window.info = dict(window.info, active=2)
    tab.show_info(window.info)
    assert key == bytearray(16) and not real.unlocked
    # replaced by a manager for another card connection (in the worker)
    key = bytearray(b"\x66" * 16)
    real = mgr_oath.OathManager(None)
    real._key, real._salt = key, b"salt"
    page._mgr, page._mgr_for = real, object()
    oath.password = None
    page.refresh()
    wait_idle(app, window)
    assert page._mgr is not real and page._mgr.m is window.mgmt and key == bytearray(16)


def test_pages_load_when_shown_without_asking(app, window, tab, fido, otp):
    passkeys, otp_page = tab.pages[0], tab.pages[2]
    passkeys.shown()                                    # (a page shown: loaded without a PIN prompt)
    wait_idle(app, window)
    assert "input" not in kinds(app) and passkeys.loaded and passkeys.table.rowCount() == 0
    assert passkeys.state.text() == A.EN["fido-locked"] and "FIDO PIN set (8 attempts left)" in passkeys.summary.text()
    assert fido.calls.names() == ["info"]
    passkeys.shown()                                    # loaded once
    wait_idle(app, window)
    assert fido.calls.names() == ["info"]
    window.busy = True                                  # another operation runs: not loaded, nothing said
    otp_page.shown()
    window.busy = False
    assert not otp_page.loaded and not app.messages
    otp_page.shown()
    wait_idle(app, window)
    assert otp_page.loaded and otp.calls.names() == ["status"]


def test_context_run_and_errors(app, window, tab):
    ctx = tab.ctx
    results, threads = [], []

    def work():
        threads.append(threading.current_thread() is MAIN())
        return 42
    assert ctx.run(work, results.append)
    assert not ctx.run(work, results.append)            # one operation at a time
    wait_idle(app, window)
    assert results == [42] and threads == [False] and nothing_kept(window)
    # a ManagerError: its message, in the language of the GUI
    ctx.run(lambda: (_ for _ in ()).throw(ManagerError("OATH: boom", 0x6A80, "OATH：出错")))
    wait_idle(app, window)
    assert app.messages[-1] == ("critical", "OATH: boom")
    gui._LANG_ZH = True
    try:
        ctx.run(lambda: (_ for _ in ()).throw(ManagerError("OATH: boom", 0x6A80, "OATH：出错")))
        wait_idle(app, window)
        assert app.messages[-1] == ("critical", "OATH：出错")
        assert ctx.T("Passkeys") == "通行密钥" and ctx.T("Refresh") == "刷新"
    finally:
        gui._LANG_ZH = False
    # on_error handles it (True) or passes it on
    seen = []
    ctx.run(lambda: 1 / 0, None, lambda e: seen.append(e) or True)
    wait_idle(app, window)
    assert isinstance(seen[0], ZeroDivisionError) and app.messages[-1][1] == "OATH：出错"
    ctx.run(lambda: 1 / 0)                              # unexpected: the window shows the traceback
    wait_idle(app, window)
    assert app.messages[-1][0] == "critical" and "ZeroDivisionError" in app.messages[-1][1]
    # dialogs: a name that looks like HTML stays plain text
    ctx.error("<b>x</b>")
    assert app.messages[-1] == ("critical", "Details:\n<b>x</b>")
    assert not ctx.confirm("delete it?") and app.messages[-1] == ("question", "delete it?")
    app.answers["warning"].append(Yes)
    assert ctx.confirm("erase it?", danger=True) and app.messages[-1] == ("warning", "erase it?")
    app.inputs.append(("s3cret", True))
    assert ctx.ask_secret("t", "p") == "s3cret" and ctx.ask_secret("t", "p") is None
    assert ctx.management() is window.mgmt
    window.mgmt, m = None, window.mgmt
    try:
        with pytest.raises(RuntimeError):
            ctx.management()
        assert not ctx.run(work)                        # without a device: said
        assert app.messages[-1] == ("warning", "No device")
    finally:
        window.mgmt = m


def test_context_when_idle_and_import_file(app, window, tab, monkeypatch):
    ctx, called = tab.ctx, []
    window.busy = True
    ctx.when_idle(lambda: called.append(1), interval=10)
    for _ in range(5):
        app.processEvents()
        time.sleep(0.02)
    assert not called
    window.busy = False
    deadline = time.time() + 5
    while not called and time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert called == [1]
    for _ in range(5):
        app.processEvents()
        time.sleep(0.02)
    assert called == [1]                                # once
    imported = []
    monkeypatch.setattr(window.keys_tab, "import_file", lambda: imported.append(1))
    ctx.import_file(then=lambda: called.append(2))
    deadline = time.time() + 5
    while len(called) < 2 and time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert imported == [1] and called == [1, 2]


def test_context_exports_a_key_like_the_keys_tab(app, window, tab, monkeypatch, tmp_path):
    ctx = tab.ctx
    monkeypatch.setattr(cli, "write_key_file", lambda *a, **k: keyfile.write_key_file(*a, scrypt_log_n=10, **k))
    passphrases = [("pw", "pw")]

    def exec_(dlg):
        p = passphrases.pop(0) if passphrases else None
        if p is None:
            return 0
        dlg.pass1.setText(p[0])
        dlg.pass2.setText(p[1])
        dlg._accept()
        return int(dlg.ok)
    monkeypatch.setattr(gui.KeyPassphraseDialog, "exec", exec_)
    path = str(tmp_path / "oath.lfkey")
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (path, "")))
    oath_id = KEYS[1][0][0][1]
    assert ctx.export_selected("oath", oath_id, label="Example:alice")
    wait_idle(app, window)
    assert read_key_file(path, "pw")[1].record[4] == OATH_SECRET
    assert app.messages[-1][0] == "information" and path in app.messages[-1][1]
    assert nothing_kept(window)
    # an otpauth link: in the clear, confirmed (answered No: nothing written)
    link = tmp_path / "l.txt"
    path = str(link)
    app.items.append(("otpauth:// link (NOT encrypted)", True))
    assert not ctx.export_selected("oath", oath_id)
    assert app.messages[-1] == ("question", gui_manager.EN["mgr-otpauth-plain"]) and not link.exists()
    # a passkey: the sign counter note; an OpenPGP key: its Admin PIN is asked for
    path = str(tmp_path / "fido.lfkey")
    passphrases.append(("pw", "pw"))
    ctx.export_selected("fido", KEYS[0][0][0][1], label="example.com")
    wait_idle(app, window)
    assert gui_manager.EN["mgr-fido-counter-export"] in app.messages[-1][1]
    passphrases.append(("pw", "pw"))
    app.inputs.append(("", True))
    assert not ctx.export_selected("openpgp", 1)
    assert app.messages[-1] == ("warning", "The OpenPGP Admin PIN is needed.")
    window.dev.exportable = False                       # refused by the device: said
    passphrases.append(("pw", "pw"))
    path = str(tmp_path / "no.lfkey")
    ctx.export_selected("oath", oath_id)
    wait_idle(app, window)
    assert app.messages[-1][0] == "critical" and "not allowed" in app.messages[-1][1] and not os.path.exists(path)


def test_new_secret_and_edit_dialogs(app, window, tab, monkeypatch):
    """gui_manager.ask_new_secret and edit_texts (the pages' tests replace them)."""
    ctx = tab.ctx
    entries = []

    def exec_(dlg):
        edits = dlg.findChildren(QtWidgets.QLineEdit)
        for e, text in zip(edits, entries.pop(0)):
            e.setText(text)
        dlg.findChild(QtWidgets.QDialogButtonBox).button(QtWidgets.QDialogButtonBox.StandardButton.Ok).click()
        return dlg.result()
    monkeypatch.setattr(QtWidgets.QDialog, "exec", exec_)
    entries.append(("1234", "1235"))
    assert gui_manager.ask_new_secret(ctx, "t", "l", min_len=4) is None
    assert app.messages[-1] == ("warning", "The two entries differ.")
    entries.append(("123", "123"))
    assert gui_manager.ask_new_secret(ctx, "t", "l", min_len=4) is None
    assert app.messages[-1] == ("warning", "At least 4 characters.")
    entries.append(("中" * 22, "中" * 22))        # 22 characters, 66 bytes
    assert gui_manager.ask_new_secret(ctx, "t", "l", min_len=4, max_bytes=63) is None
    assert app.messages[-1] == ("warning", "At most 63 bytes (UTF-8).")
    entries.append(("", ""))
    assert gui_manager.ask_new_secret(ctx, "t", "l") is None
    entries.append(("", ""))
    assert gui_manager.ask_new_secret(ctx, "t", "l", allow_empty=True) == ""
    entries.append(("123456", "123456"))
    assert gui_manager.ask_new_secret(ctx, "t", "l", min_len=4) == "123456"
    entries.append((" a ", "b"))
    assert gui_manager.edit_texts(ctx, "t", [("x", "1"), ("y", "2")]) == ["a", "b"]


# ----------------------------------------------------------------------------
# Passkeys
# ----------------------------------------------------------------------------

def test_passkeys_pin_prompt_list_and_nothing_kept(app, window, tab, fido):
    page = tab.pages[0]
    app.inputs += [("0000", True), ("1234", True)]      # a wrong PIN: asked again with the tries left
    page.refresh()
    wait_idle(app, window)
    prompts = [text for k, text in app.messages if k == "input"]
    assert prompts[0] == "FIDO PIN of the active profile:"
    assert prompts[1].startswith("FIDO PIN: wrong PIN, 7 tries left")
    assert texts(page.table) == [["example.com", "alice", "Alice", "ES256, credProtect 2, large blob"],
                                 ["rp.example", "<b>bob</b>", "", "EdDSA"]]
    assert page.state.text() == "Passkeys: 2"
    assert [c for c in fido.calls if c[0] == "unlock"] == [("unlock", "0000"), ("unlock", "1234")]
    assert not any(fido.calls.threads)                  # every manager call in the worker
    assert nothing_kept(window) and not holds(page, "1234")
    # cancelled: nothing listed, the page says it is locked
    page._mgr.token = False
    app.inputs.append(("", False))
    page.refresh()
    wait_idle(app, window)
    assert page.state.text() == A.EN["fido-locked"]
    app.inputs.append(("", True))                       # empty: said
    page.refresh()
    wait_idle(app, window)
    assert app.messages[-1] == ("critical", "Enter the FIDO PIN.")


def test_passkeys_without_pin(app, window, tab, fido):
    page = tab.pages[0]
    fido.pin = None
    page.refresh()
    wait_idle(app, window)
    assert page.state.text() == A.EN["fido-no-pin"] and "list_credentials" not in fido.calls.names()
    assert page.pin_btn.text() == "Set PIN..." and "No FIDO PIN" in page.summary.text()
    app.new_secrets.append("5678")
    page.change_pin()
    wait_idle(app, window)
    assert ("set_pin", "5678") in fido.calls and ("unlock", "5678") in fido.calls
    assert app.messages[-1] == ("information", "FIDO PIN set.") and page.table.rowCount() == 2
    assert ("new", A.EN["fido-new-pin"] % 4) in app.messages


def test_passkeys_change_pin(app, window, tab, fido):
    page = tab.pages[0]
    page.change_pin()                                   # not read yet
    assert app.messages[-1] == ("critical", "Refresh first.")
    page.auto_refresh()
    wait_idle(app, window)
    assert page.pin_btn.text() == "Change PIN..."
    app.inputs.append(("", False))                      # cancelled
    page.change_pin()
    assert "change_pin" not in fido.calls.names()
    app.inputs.append(("1111", True))
    app.new_secrets.append(None)                        # new PIN cancelled
    page.change_pin()
    assert "change_pin" not in fido.calls.names()
    app.inputs.append(("1111", True))
    app.new_secrets.append("98765")
    page.change_pin()                                   # wrong current PIN: said
    wait_idle(app, window)
    assert app.messages[-1] == ("critical", "change FIDO PIN: wrong PIN, 7 tries left")
    app.inputs.append(("1234", True))
    app.new_secrets.append("98765")
    page.change_pin()
    wait_idle(app, window)
    assert fido.calls[-4:][0] == ("change_pin", "1234", "98765") and fido.pin == "98765"
    assert app.messages[-1] == ("information", "FIDO PIN changed.") and page.table.rowCount() == 2
    assert nothing_kept(window) and not holds(page, "98765")


def test_passkeys_delete_is_confirmed(app, window, tab, fido):
    page = tab.pages[0]
    app.inputs.append(("1234", True))
    page.refresh()
    wait_idle(app, window)
    page.delete()                                       # nothing selected
    assert app.messages[-1] == ("critical", "Select an entry first.")
    page.table.selectRow(1)
    page.delete()                                       # answered No
    assert app.messages[-1] == ("warning", A.EN["fido-delete"] % ("rp.example", "<b>bob</b>"))
    assert "delete_credential" not in fido.calls.names()
    app.answers["warning"].append(Yes)
    page.delete()
    wait_idle(app, window)
    assert ("delete_credential", b"\x02" * 42) in fido.calls
    assert texts(page.table, 0) == ["example.com"] and app.messages[-1] == ("information", "Passkey deleted.")
    # the token ended meanwhile: the PIN is asked for and the deletion done then
    page._mgr.token = False
    page.table.selectRow(0)
    app.answers["warning"].append(Yes)
    app.inputs.append(("1234", True))
    page.delete()
    wait_idle(app, window)
    assert page.table.rowCount() == 0 and fido.calls.names()[-4:] == ["unlock", "delete_credential", "info",
                                                                      "list_credentials"]
    # an error is shown
    fido.creds.append(dict(rp_id="x.example", credential_id=b"\x03" * 42, user_id=b"u3", user_name="z"))
    page.refresh()
    wait_idle(app, window)
    page.table.selectRow(0)
    fido.fail["delete_credential"] = ManagerError("delete passkey: no such passkey on the device (list them again)")
    app.answers["warning"].append(Yes)
    page.delete()
    wait_idle(app, window)
    assert app.messages[-1] == ("critical", "delete passkey: no such passkey on the device (list them again)")


def test_passkeys_edit_user(app, window, tab, fido):
    page = tab.pages[0]
    app.inputs.append(("1234", True))
    page.refresh()
    wait_idle(app, window)
    page.table.selectRow(0)
    page.edit_user()                                    # cancelled
    assert app.messages[-1] == ("edit", ["alice", "Alice"]) and "update_user" not in fido.calls.names()
    app.edits.append(["a" * 65, ""])
    page.edit_user()
    assert app.messages[-1] == ("critical", "At most 64 bytes (UTF-8).")
    app.edits.append(["alice2", "Alice Two"])
    page.edit_user()
    wait_idle(app, window)
    assert ("update_user", b"\x01" * 42, b"u-1", "alice2", "Alice Two") in fido.calls
    assert texts(page.table)[0][:3] == ["example.com", "alice2", "Alice Two"]


def test_passkeys_export_and_import_go_through_the_context(app, window, tab, fido, monkeypatch):
    page = tab.pages[0]
    exported, imported = [], []
    monkeypatch.setattr(tab.ctx, "export_selected", lambda app_, key_id, label=None: exported.append(
        (app_, key_id, label)))
    monkeypatch.setattr(tab.ctx, "import_file", lambda then=None: imported.append(then))
    page.export()
    assert app.messages[-1] == ("critical", "Select an entry first.")
    app.inputs.append(("1234", True))
    page.refresh()
    wait_idle(app, window)
    page.table.selectRow(0)
    page.export()
    page.import_keys()
    assert exported == [("fido", b"\x01" * 42, "example.com")] and imported == [page.auto_refresh]


# ----------------------------------------------------------------------------
# OATH
# ----------------------------------------------------------------------------

class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def row_of(page, raw):
    return [a["raw"] for a in page.rows].index(raw)


def test_oath_codes_follow_the_clock(app, window, tab, oath):
    page = tab.pages[1]
    page.clock = Clock(1005.0)
    page.refresh()
    wait_idle(app, window)
    rows = {r[1]: r for r in texts(page.table)}
    assert rows["alice"] == ["Example", "alice", code_of(b"Example:alice", 1005), "15 s", "TOTP SHA1, 6 digits"]
    assert rows["bob"][2:4] == ["", "touch: press Calculate"] and rows["bob"][4].endswith("touch")
    assert rows["carol"][2:4] == ["", "press Calculate"]
    assert rows["dave"][2:] == [code_of(b"60/Slow:dave", 1005, 60), "15 s", "TOTP SHA1, 6 digits, 60 s"]
    assert page.countdown.value() == 15 and page.countdown.format() == "15 s"
    assert oath.calls[-1] == ("calculate_all", 1005) and not any(oath.calls.threads)
    page.clock.t = 1019.5                               # still valid: nothing asked
    page.tick()
    assert len(oath.calls) == 3 and texts(page.table)[row_of(page, b"Example:alice")][3] == "1 s"
    page.clock.t = 1020.0                               # expired: calculated again
    page.tick()
    assert texts(page.table)[row_of(page, b"Example:alice")][2] == ""      # (no stale code meanwhile)
    wait_idle(app, window)
    assert oath.calls[-1] == ("calculate_all", 1020)
    assert texts(page.table)[row_of(page, b"Example:alice")][2:4] == [code_of(b"Example:alice", 1020), "30 s"]
    assert texts(page.table)[row_of(page, b"60/Slow:dave")][2:4] == [code_of(b"60/Slow:dave", 1020, 60), "60 s"]
    window.busy = True                                  # another operation runs: waits for it
    page.clock.t = 1050.0
    page.tick()
    window.busy = False
    assert oath.calls[-1] == ("calculate_all", 1020)
    page.tick()
    wait_idle(app, window)
    assert oath.calls[-1] == ("calculate_all", 1050)
    # a failure stops the updates and is shown on the page (no dialog every second)
    oath.fail["calculate_all"] = ManagerError("OATH codes: the device is gone")
    page.clock.t = 1080.0
    page.tick()
    wait_idle(app, window)
    n = len(oath.calls)
    assert page.state.text() == "Codes are not updated: OATH codes: the device is gone" and not page.live
    assert "critical" not in kinds(app)
    page.clock.t = 1200.0
    page.tick()
    wait_idle(app, window)
    assert len(oath.calls) == n and texts(page.table)[row_of(page, b"Example:alice")][2] == ""


def test_oath_refresh_by_itself_is_quiet(app, window, tab, oath):
    """The recalculation of expired codes runs without the "Working..."
    banner, which would flash every 30 s; what the user starts shows it, and
    a failure of the quiet one is still reported (on the page)."""
    page = tab.pages[1]
    page.clock = Clock(1005.0)
    runs = []
    real_run = window._run
    window._run = lambda fn, **k: runs.append(k.get("quiet", False)) or real_run(fn, **k)
    try:
        page.refresh()
        assert window.busy and not window.banner.isHidden()     # asked for: the banner
        wait_idle(app, window)
        page.clock.t = 1020.0
        page.tick()                                             # by itself: quiet
        assert window.busy and window.banner.isHidden() and window.progress.isHidden()
        wait_idle(app, window)
        assert oath.calls[-1] == ("calculate_all", 1020) and window.banner.isHidden()
        oath.fail["calculate_all"] = ManagerError("OATH codes: the device is gone")
        page.clock.t = 1050.0
        page.tick()
        assert window.banner.isHidden()
        wait_idle(app, window)
    finally:
        window._run = real_run
    assert runs == [False, True, True]
    assert page.state.text() == "Codes are not updated: OATH codes: the device is gone" and not page.live


def test_oath_touch_hotp_and_copy(app, window, tab, oath):
    page = tab.pages[1]
    page.clock = Clock(2000.0)
    page.refresh()
    wait_idle(app, window)
    page.table.selectRow(row_of(page, b"GitHub:bob"))
    touched = []
    real_run = window._run
    window._run = lambda fn, **k: touched.append(k.get("touch")) or real_run(fn, **k)
    try:
        page.copy_code()                                # no code yet: calculated (with a touch), then copied
        wait_idle(app, window)
    finally:
        window._run = real_run
    assert touched == [True] and oath.calls[-1] == ("calculate", b"GitHub:bob", 2000)
    assert QtWidgets.QApplication.clipboard().text() == code_of(b"GitHub:bob", 2000)
    assert page.state.text() == "Code of bob (GitHub) copied."
    page.clock.t = 2005.0
    page.tick()
    assert texts(page.table)[row_of(page, b"GitHub:bob")][2:4] == [code_of(b"GitHub:bob", 2000), "5 s"]
    page.clock.t = 2010.0
    page.tick()                                         # a touch code is not calculated again by itself
    wait_idle(app, window)
    assert oath.calls[-1] == ("calculate_all", 2010)
    assert texts(page.table)[row_of(page, b"GitHub:bob")][2] == ""
    assert ("calculate", b"GitHub:bob", 2010) not in oath.calls
    page.table.selectRow(row_of(page, b"Bank:carol"))    # HOTP: on demand, no expiry
    page.calculate()
    wait_idle(app, window)
    assert texts(page.table)[row_of(page, b"Bank:carol")][2:4] == [code_of(b"Bank:carol", 2010), ""]
    page.table.selectRow(row_of(page, b"Example:alice"))
    page.copy_code()                                    # a valid code: copied at once
    assert QtWidgets.QApplication.clipboard().text() == code_of(b"Example:alice", 2010)
    page.filter.setText("ban")
    assert texts(page.table, 1) == ["carol"] and page._selected() is None
    page.filter.setText("")
    assert page.table.rowCount() == 4


def test_oath_password(app, window, tab, oath):
    page = tab.pages[1]
    oath.password = "pw"
    page.auto_refresh()                                 # shown: not asked
    wait_idle(app, window)
    assert page.state.text() == A.EN["oath-locked"] and "input" not in kinds(app)
    app.inputs += [("nope", True), ("pw", True)]        # wrong, then right
    page.refresh()
    wait_idle(app, window)
    prompts = [text for k, text in app.messages if k == "input"]
    assert prompts == ["OATH password:", "wrong OATH password\n\nOATH password:"]
    assert page.table.rowCount() == 4 and "protected by a password" in page.state.text()
    assert page.password_btn.text() == "Change password..." and page.remove_password_btn.isEnabled()
    assert nothing_kept(window) and not holds(page, "pw")
    app.new_secrets.append("new pw")                    # change it
    page.set_password()
    wait_idle(app, window)
    assert ("set_password", "new pw") in oath.calls and app.messages[-1] == ("information", "OATH password set.")
    page.remove_password()                              # answered No
    assert app.messages[-1] == ("warning", A.EN["oath-remove-password"]) and oath.password == "new pw"
    app.answers["warning"].append(Yes)
    page.remove_password()
    wait_idle(app, window)
    assert oath.password is None and app.messages[-1] == ("information", "OATH password removed.")
    page.remove_password()
    assert app.messages[-1] == ("information", "The OATH application has no password.")
    # another program set a password meanwhile: an operation asks for it
    oath.password = "other"
    page._mgr.key = None
    page.table.selectRow(0)
    app.answers["warning"].append(Yes)
    app.inputs.append(("other", True))
    page.delete()
    wait_idle(app, window)
    assert oath.calls.names()[-5:] == ["unlock", "delete", "status", "list", "calculate_all"]


def fill_add(values, action=None):
    """exec of OathAddDialog: action(dialog) first, then the fields, then OK."""
    def exec_(dlg):
        if action:
            action(dlg)
        for name, value in values.items():
            w = getattr(dlg, name)
            if isinstance(w, QtWidgets.QLineEdit):
                w.setText(value)
            elif isinstance(w, QtWidgets.QComboBox):
                w.setCurrentIndex(w.findData(value))
            elif isinstance(w, QtWidgets.QCheckBox):
                w.setChecked(value)
            else:
                w.setValue(value)
        dlg._accept()
        return int(dlg.value is not None)
    return exec_


def test_oath_add_account(app, window, tab, oath, monkeypatch):
    page = tab.pages[1]
    page.refresh()
    wait_idle(app, window)
    monkeypatch.setattr(A.OathAddDialog, "exec", fill_add({"issuer": "Site", "account": "me",
                                                           "secret": "JBSW Y3DP EHPK 3PXP", "period": 60,
                                                           "algorithm": "SHA256", "digits": 8, "touch": True}))
    page.add_account()
    wait_idle(app, window)
    add = [c for c in oath.calls if c[0] == "add"][-1][1]
    assert add == dict(issuer="Site", account="me", secret=b"Hello!\xde\xad\xbe\xef", type="totp",
                       algorithm="SHA256", digits=8, period=60, counter=0, touch=True, replace=False)
    assert app.messages[-1] == ("information", "Account added: 60/Site:me") and page.table.rowCount() == 5
    assert nothing_kept(window)
    # an account of that name is there: replacing it is confirmed (No: nothing sent)
    monkeypatch.setattr(A.OathAddDialog, "exec", fill_add({"issuer": "Example", "account": "alice",
                                                           "secret": "JBSWY3DPEHPK3PXP"}))
    n = len(oath.calls)
    page.add_account()
    assert app.messages[-1] == ("warning", A.EN["oath-replace"] % "Example:alice") and len(oath.calls) == n
    app.answers["warning"].append(Yes)
    page.add_account()
    wait_idle(app, window)
    assert [c for c in oath.calls if c[0] == "add"][-1][1]["replace"] is True
    # checked in the dialog: nothing sent, the dialog stays open
    for values, warning in (({"account": "", "secret": "AAAA"}, "Enter the account name."),
                            ({"issuer": "a:b", "account": "x", "secret": "AAAA"}, A.EN["oath-colon"]),
                            ({"account": "x", "secret": ""}, "Enter the secret."),
                            ({"account": "x", "secret": "1!"}, "The secret is not base32."),
                            ({"account": "x" * 65, "secret": "AAAA"},
                             "OATH: the name is too long (65 bytes, at most 64 with issuer and period)"),
                            ({"account": "a:b", "secret": "AAAA"},
                             "OATH: without an issuer, the account name cannot contain a colon (:); the part before "
                             "it would read back as the issuer")):
        n = len(oath.calls)
        monkeypatch.setattr(A.OathAddDialog, "exec", fill_add(values))
        page.add_account()
        assert app.messages[-1] == ("warning", warning) and len(oath.calls) == n


def test_oath_add_from_a_link_and_a_qr_image(app, window, tab, oath, monkeypatch, tmp_path):
    page = tab.pages[1]
    page.refresh()
    wait_idle(app, window)
    # a link fills the fields (editable)
    monkeypatch.setattr(A.OathAddDialog, "exec", fill_add(
        {"account": "bobby"}, lambda dlg: dlg.link.setText(TOTP_LINK.replace("Example", "Other"))))
    page.add_account()
    wait_idle(app, window)
    add = [c for c in oath.calls if c[0] == "add"][-1][1]
    assert add["issuer"] == "Other" and add["account"] == "bobby" and add["secret"] == b"1234567890" * 2
    # a bad link is said in the dialog
    seen = []
    monkeypatch.setattr(A.OathAddDialog, "exec", lambda dlg: (dlg.link.setText("otpauth://totp/x?secret=1"),
                                                              seen.append(dlg.note.text()), 0)[2])
    page.add_account()
    assert seen == ["Not a usable link: the secret is not base32"]
    # a QR image with two accounts, decoded in the worker; one is there already (not replaced)
    png = tmp_path / "qr.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n")
    monkeypatch.setattr(QtWidgets.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(png), "")))
    threads = []

    def links(path):
        threads.append(threading.current_thread() is MAIN())
        return [TOTP_LINK.replace("bob", "zed"), TOTP_LINK.replace("bob", "alice")], 1
    monkeypatch.setattr(A, "qr_links", links)

    def open_qr(dlg):
        dlg._open_qr()
        wait_idle(app, window)
        seen.append((dlg.note.text(), dlg.account.isEnabled()))
    monkeypatch.setattr(A.OathAddDialog, "exec", fill_add({}, open_qr))
    page.add_account()                                  # replace Example:alice? No
    wait_idle(app, window)
    assert threads == [False]
    assert seen[-1][0].startswith(A.EN["oath-several"] % (2, "Example:zed\nExample:alice"))
    assert gui.T("others-qr") % 1 in seen[-1][0] and seen[-1][1] is False
    assert app.messages[-2] == ("warning", A.EN["oath-replace-n"] % "Example:alice")    # answered No
    records = [c for c in oath.calls if c[0] == "add_record"]
    assert [(r[1][1], r[2]) for r in records] == [(b"Example:zed", False)]
    assert app.messages[-1] == ("information", "Accounts added: 1")


def test_oath_rename_delete_reset(app, window, tab, oath):
    page = tab.pages[1]
    page.refresh()
    wait_idle(app, window)
    page.table.selectRow(row_of(page, b"Example:alice"))
    page.rename()                                       # cancelled
    assert app.messages[-1] == ("edit", ["Example", "alice"])
    app.edits.append(["GitHub", "bob"])                 # that name is taken
    page.rename()
    assert app.messages[-1] == ("critical", A.EN["oath-exists"] % "GitHub:bob")
    app.edits.append(["Example", ""])
    page.rename()
    assert app.messages[-1] == ("critical", "Enter the account name.")
    app.edits.append(["New", "alice"])
    page.rename()
    wait_idle(app, window)
    assert ("rename", b"Example:alice", "New", "alice") in oath.calls and b"New:alice" in oath.accounts
    page.table.selectRow(row_of(page, b"New:alice"))
    page.delete()                                       # answered No
    assert app.messages[-1] == ("warning", A.EN["oath-delete"] % "alice (New)") and b"New:alice" in oath.accounts
    app.answers["warning"].append(Yes)
    page.delete()
    wait_idle(app, window)
    assert b"New:alice" not in oath.accounts and page.table.rowCount() == 3
    page.reset()                                        # first confirmation: No
    assert "reset" not in oath.calls.names() and app.messages[-1] == ("warning", A.EN["oath-reset"] % 3)
    app.answers["warning"] += [Yes, No]                 # second: No
    page.reset()
    assert "reset" not in oath.calls.names() and app.messages[-1] == ("warning", A.EN["oath-reset-2"])
    app.answers["warning"] += [Yes, Yes]
    page.reset()
    wait_idle(app, window)
    assert oath.accounts == {} and page.table.rowCount() == 0
    assert app.messages[-1] == ("information", "OATH application reset.")


def test_oath_export_import(app, window, tab, oath, monkeypatch):
    page = tab.pages[1]
    exported, imported = [], []
    monkeypatch.setattr(tab.ctx, "export_selected", lambda app_, key_id, label=None: exported.append(
        (app_, key_id, label)))
    monkeypatch.setattr(tab.ctx, "import_file", lambda then=None: imported.append(then))
    page.refresh()
    wait_idle(app, window)
    page.table.selectRow(row_of(page, b"60/Slow:dave"))
    page.export()
    page.import_keys()
    assert exported == [("oath", b"60/Slow:dave", "60/Slow:dave")] and imported == [page.auto_refresh]


def test_oath_names_that_look_like_a_period(app, window, tab, oath, monkeypatch):
    """A 30 s account named "0/work" (typed, or from a link) is added as
    "0/work" with 30 s, stored as 30/0/work (mgr_oath.build_name), not as a
    period of 0 (or 1) seconds; a rename to "12/alice" keeps 30 s."""
    page = tab.pages[1]
    page.refresh()
    wait_idle(app, window)
    monkeypatch.setattr(A.OathAddDialog, "exec", fill_add(
        {}, lambda dlg: dlg.link.setText("otpauth://totp/0%2Fwork?secret=JBSWY3DPEHPK3PXP")))
    page.add_account()
    wait_idle(app, window)
    add = [c for c in oath.calls if c[0] == "add"][-1][1]
    assert (add["issuer"], add["account"], add["period"]) == (None, "0/work", 30)
    assert app.messages[-1] == ("information", "Account added: 30/0/work") and b"30/0/work" in oath.accounts
    rows = {r[1]: r for r in texts(page.table)}
    assert rows["0/work"][0] == "" and rows["0/work"][4] == "TOTP SHA1, 6 digits"
    page.table.selectRow(row_of(page, b"Example:alice"))
    app.edits.append(["", "12/alice"])
    page.rename()
    wait_idle(app, window)
    assert ("rename", b"Example:alice", None, "12/alice") in oath.calls and b"30/12/alice" in oath.accounts
    page.table.selectRow(row_of(page, b"30/12/alice"))
    app.edits.append(["", "a:b"])                       # would read back as issuer "a": refused, nothing sent
    n = len(oath.calls)
    page.rename()
    assert app.messages[-1][0] == "critical" and "cannot contain a colon" in app.messages[-1][1]
    assert len(oath.calls) == n


def test_oath_reset_names_the_count_only_when_listed(app, window, tab, oath):
    """The first reset question gives the number of accounts only when the
    page listed them: not while the password protects them (the usual reason
    for a reset) nor before Refresh."""
    page = tab.pages[1]
    page.reset()                                        # not read yet (answered No)
    assert app.messages[-1] == ("warning", A.EN["oath-reset-unknown"])
    oath.password = "pw"
    page.auto_refresh()                                 # locked: nothing listed
    wait_idle(app, window)
    assert page.state.text() == A.EN["oath-locked"]
    page.reset()
    assert app.messages[-1] == ("warning", A.EN["oath-reset-unknown"]) and "reset" not in oath.calls.names()
    app.inputs.append(("pw", True))
    page.refresh()
    wait_idle(app, window)
    page.reset()
    assert app.messages[-1] == ("warning", A.EN["oath-reset"] % 4)
    gui._LANG_ZH = True
    try:
        assert tab.ctx.T("oath-reset-unknown") == A.ZH["oath-reset-unknown"] and "%" not in A.ZH["oath-reset-unknown"]
    finally:
        gui._LANG_ZH = False


def test_oath_recalculation_leaves_the_worker_to_the_user(app, window, tab, oath, monkeypatch):
    """The codes' recalculation (the page's own operation in the shared
    worker) does not start under a dialog, so what the user confirms there
    finds the worker free; an action that finds the recalculation running
    starts when it ended; one that finds another operation running says
    so (never dropped without a word)."""
    page = tab.pages[1]
    page.clock = Clock(1005.0)
    page.refresh()
    wait_idle(app, window)
    modal = []
    real_modal = QtWidgets.QApplication.activeModalWidget
    monkeypatch.setattr(QtWidgets.QApplication, "activeModalWidget",
                        staticmethod(lambda: modal[-1] if modal else real_modal()))

    def confirm(parent, title, text, *x):
        app.messages.append(("warning", text))
        modal.append(parent)                            # the question is open ...
        page.clock.t += 15                              # ... when codes expire: the page's timer ticks
        page.tick()
        modal.pop()
        return Yes
    monkeypatch.setattr(QtWidgets.QMessageBox, "warning", staticmethod(confirm))
    page.table.selectRow(row_of(page, b"Example:alice"))
    page.delete()
    wait_idle(app, window)
    assert ("delete", b"Example:alice") in oath.calls and b"Example:alice" not in oath.accounts
    assert oath.calls.names()[-4:] == ["delete", "status", "list", "calculate_all"]
    # a code expires and its recalculation runs as the user copies it: the copy follows
    QtWidgets.QApplication.clipboard().setText("")
    page.table.selectRow(row_of(page, b"60/Slow:dave"))
    page.clock.t = 1080.0
    page.tick()
    assert window.busy and page.pending
    page.copy_code()
    settle(app, window)
    assert oath.calls[-2:] == [("calculate_all", 1080), ("calculate", b"60/Slow:dave", 1080)]
    assert QtWidgets.QApplication.clipboard().text() == code_of(b"60/Slow:dave", 1080, 60)
    # so do an export and an import asked for meanwhile (they, too, need the worker free)
    exported, imported = [], []
    monkeypatch.setattr(tab.ctx, "export_selected", lambda app_, key_id, label=None: not window.busy and (
        exported.append(key_id) or True))
    monkeypatch.setattr(tab.ctx, "import_file", lambda then=None: not window.busy and (imported.append(then) or True))
    page.clock.t = 1140.0
    page.tick()
    assert window.busy and page.pending
    page.export()
    page.import_keys()
    assert not exported and not imported
    settle(app, window)
    assert exported == [b"60/Slow:dave"] and imported == [page.auto_refresh]
    # another operation runs: said, nothing sent then or later
    n = len(oath.calls)
    window.busy = True
    page.delete()
    window.busy = False
    settle(app, window)
    assert app.messages[-1] == ("critical", "Another operation is running: try again once it has ended.")
    assert len(oath.calls) == n and b"60/Slow:dave" in oath.accounts


def test_oath_qr_image_decoding_holds_the_dialog(app, window, tab, oath, monkeypatch, tmp_path):
    """While a QR image is decoded (in the worker) the add dialog cannot be
    accepted (the account could not be added: the worker is taken) nor
    another image picked; cancelled meanwhile, the result is dropped (its
    widgets are gone); afterwards, or after a failure, it works again."""
    import shiboken6
    page = tab.pages[1]
    page.refresh()
    wait_idle(app, window)
    png = tmp_path / "qr.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n")
    monkeypatch.setattr(QtWidgets.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(png), "")))
    release = threading.Event()

    def links(path):
        release.wait(10)
        return [TOTP_LINK.replace("bob", "zed")], 0
    monkeypatch.setattr(A, "qr_links", links)
    errors = []
    monkeypatch.setattr(sys, "excepthook", lambda *e: errors.append(e[1]))
    seen, dialogs = [], []

    def cancel_while_decoding(dlg):
        dialogs.append(dlg)
        dlg._open_qr()
        seen.append((window.busy, dlg.ok_btn.isEnabled(), dlg.qr_btn.isEnabled(), dlg.link.isEnabled()))
        dlg.account.setText("typed")
        dlg.secret.setText("JBSWY3DPEHPK3PXP")
        dlg.ok_btn.click()                              # disabled
        dlg._accept()                                   # (Enter: nothing either)
        seen.append(dlg.value)
        return 0                                        # Cancel
    monkeypatch.setattr(A.OathAddDialog, "exec", cancel_while_decoding)
    page.add_account()
    QtCore.QCoreApplication.sendPostedEvents(None, QtCore.QEvent.Type.DeferredDelete)
    assert not shiboken6.isValid(dialogs[0])            # the dialog is gone ...
    release.set()                                       # ... when the image is decoded
    wait_idle(app, window)
    assert seen == [(True, False, False, False), None] and not errors
    assert "add" not in oath.calls.names() and "add_record" not in oath.calls.names()

    def decode_then_ok(dlg):
        dlg._open_qr()
        wait_idle(app, window)
        seen.append((dlg.ok_btn.isEnabled(), dlg.qr_btn.isEnabled(), dlg.account.text()))
        dlg._accept()
        return int(dlg.value is not None)
    monkeypatch.setattr(A.OathAddDialog, "exec", decode_then_ok)
    page.add_account()
    wait_idle(app, window)
    assert seen[-1] == (True, True, "zed") and [c[1]["account"] for c in oath.calls if c[0] == "add"] == ["zed"]

    def broken(path):
        raise stdformats.FormatError("no QR code with an otpauth:// link in " + path)
    monkeypatch.setattr(A, "qr_links", broken)

    def decode_fails(dlg):
        dlg._open_qr()
        wait_idle(app, window)
        seen.append((dlg.ok_btn.isEnabled(), dlg.qr_btn.isEnabled()))
        return 0
    monkeypatch.setattr(A.OathAddDialog, "exec", decode_fails)
    page.add_account()
    assert seen[-1] == (True, True) and app.messages[-1][0] == "critical" and "no QR code" in app.messages[-1][1]
    # the worker is taken by another operation: said in the dialog, which stays usable

    def worker_taken(dlg):
        dlg._open_qr()
        seen.append((dlg.ok_btn.isEnabled(), dlg.qr_btn.isEnabled()))
        return 0
    monkeypatch.setattr(A.OathAddDialog, "exec", worker_taken)
    window.busy = True
    page.add_account()
    window.busy = False
    assert seen[-1] == (True, True)
    assert app.messages[-1] == ("warning", "Another operation is running: try again once it has ended.")
    assert not errors


# ----------------------------------------------------------------------------
# OTP
# ----------------------------------------------------------------------------

def fill_program(values, generate=False):
    def exec_(dlg):
        if generate:
            dlg._generate()
        for name, value in values.items():
            w = getattr(dlg, name)
            if isinstance(w, QtWidgets.QLineEdit):
                w.setText(value)
            elif isinstance(w, QtWidgets.QComboBox):
                w.setCurrentIndex(w.findData(value) if w.findData(value) >= 0 else w.findText(value))
            elif isinstance(w, QtWidgets.QCheckBox):
                w.setChecked(value)
            else:
                w.setValue(value)
        dlg._accept()
        return int(dlg.value is not None)
    return exec_


def test_otp_slots_and_yubico_otp(app, window, tab, otp, monkeypatch):
    page = tab.pages[2]
    page.refresh()
    wait_idle(app, window)
    assert page.state.text() == "OTP application 3.4.0, serial 1234"
    assert page.slots[1]["label"].text() == "Yubico OTP, public ID vvcccccccccc, Enter appended, types on a press"
    assert page.slots[2]["label"].text() == "Empty"
    assert not page.slots[2]["delete"].isEnabled() and page.slots[1]["delete"].isEnabled()
    assert not page.slots[1]["test"].isEnabled()
    # a challenge-response slot that waits for the button types nothing on a
    # press, even when a (2.0.x) configuration state calls it touch triggered
    page.otp_status["slots"][2] = dict(page.otp_status["slots"][2], configured=True, touch_triggered=True,
                                       mode="chal-hmac", touch=True)
    assert page._slot_text(2) == "Challenge-response (HMAC-SHA1), touch for each response"
    page.otp_status["slots"][2] = dict(otp.slots[2])
    summaries = []
    monkeypatch.setattr(A.SecretSummaryDialog, "show_text", classmethod(
        lambda cls, parent, T, title, text: summaries.append(text)))
    monkeypatch.setattr(A.OtpProgramDialog, "exec", fill_program({}, generate=True))
    page.program(2)                                     # an empty slot: no confirmation
    wait_idle(app, window)
    name, slot, args = otp.calls[-2]
    assert (name, slot) == ("program_yubico_otp", 2) and args["replace"] is False and args["access_code"] is None
    assert len(args["public_id"]) == 6 and args["public_id"][0] == 0xFF and len(args["key"]) == 16
    text = summaries[0]
    assert "Public ID: " + mgr_otp.modhex_encode(args["public_id"]) in text
    assert "Private ID: " + args["private_id"].hex() in text and "Secret key: " + args["key"].hex() in text
    csv = text.splitlines()[-1].split(",")
    assert csv[:5] == ["1234", mgr_otp.modhex_encode(args["public_id"]), args["private_id"].hex(),
                       args["key"].hex(), ""]
    assert nothing_kept(window) and not holds(page, args["key"]) and not holds(page, text)
    # a programmed slot: the overwrite names what is lost (answered No: nothing sent)
    n = len(otp.calls)
    monkeypatch.setattr(A.OtpProgramDialog, "exec", fill_program({"public_id": "vvcccccccccb",
                                                                  "private_id": "00" * 6, "key": "11" * 16,
                                                                  "new_code": "aabbccddeeff",
                                                                  "new_code_repeat": "aabbccddeeff"}))
    page.program(1)
    assert app.messages[-1] == ("warning", A.EN["otp-overwrite"] % (1, page._slot_text(1))) and len(otp.calls) == n
    # Yes: the slot's access code is asked for, a wrong one again
    app.answers["warning"].append(Yes)
    app.inputs += [("0a0a0a0a0a0a", True), ("010203040506", True)]
    page.program(1)
    wait_idle(app, window)
    prompts = [t for k, t in app.messages if k == "input"]
    assert prompts[-2].startswith("OTP slot 1: protected by an access code; enter it")
    assert prompts[-1].startswith("OTP slot 1: wrong access code")
    assert prompts[-1].endswith(A.EN["otp-access-code"])
    writes = [c for c in otp.calls if c[0] == "program_yubico_otp"][-3:]
    assert [w[2]["access_code"] for w in writes] == [None, bytes.fromhex("0a0a0a0a0a0a"),
                                                      bytes.fromhex("010203040506")]
    assert writes[-1][2]["replace"] is True and writes[-1][2]["new_access_code"] == bytes.fromhex("aabbccddeeff")
    assert writes[-1][2]["public_id"] == mgr_otp.modhex_decode("vvcccccccccb")
    assert otp.codes[1] == bytes.fromhex("aabbccddeeff") and len(summaries) == 2


def test_otp_program_modes_and_checks(app, window, tab, otp, monkeypatch):
    page = tab.pages[2]
    page.refresh()
    wait_idle(app, window)
    mode = page.slots[2]["mode"]
    cases = (("chal-hmac", {"key": "00" * 20, "touch": True}, "program_chalresp",
              {"key": "00" * 20, "touch": True}),
             ("static", {"password": "hello World", "layout_box": "us"}, "program_static",
              {"password": "hello World", "layout": "us", "append_cr": True}),
             ("hotp", {"secret": "JBSWY3DPEHPK3PXP", "digits": "8", "counter": 32}, "program_hotp",
              {"secret": "JBSWY3DPEHPK3PXP", "digits": 8, "counter": 32, "append_cr": True}))
    for key, values, method, expected in cases:
        otp.slots[2]["configured"] = False
        otp.codes[2] = None
        page.refresh()
        wait_idle(app, window)
        mode.setCurrentIndex(mode.findData(key))
        monkeypatch.setattr(A.OtpProgramDialog, "exec", fill_program(values))
        page.program(2)
        wait_idle(app, window)
        name, slot, args = [c for c in otp.calls if c[0] == method][-1]
        assert slot == 2 and {k: args[k] for k in expected} == expected, method
        assert app.messages[-1] == ("information", "Slot 2 programmed.")
    # the frame builders check the values before the dialog closes (nothing sent)
    for key, values, text in (("chal-hmac", {"key": "00" * 21}, "challenge-response key: at most 20 bytes"),
                              ("static", {"password": "été"}, "cannot be typed"),
                              ("hotp", {"secret": "JBSWY3DP", "counter": 17}, "multiple of 16"),
                              ("yubico-otp", {"public_id": "xyz", "private_id": "00" * 6, "key": "11" * 16},
                               "not valid modhex"),
                              ("yubico-otp", {"public_id": "vvcccccccccc", "private_id": "00" * 6, "key": "11" * 16,
                                              "new_code": "0102"}, "access code")):
        n = len(otp.calls)
        mode.setCurrentIndex(mode.findData(key))
        monkeypatch.setattr(A.OtpProgramDialog, "exec", fill_program(values))
        page.program(2)
        assert app.messages[-1][0] == "warning" and text in app.messages[-1][1] and len(otp.calls) == n, key
    # random values of every mode pass the checks
    for key in ("chal-hmac", "static", "hotp"):
        otp.slots[2]["configured"] = False
        page.refresh()
        wait_idle(app, window)
        mode.setCurrentIndex(mode.findData(key))
        monkeypatch.setattr(A.OtpProgramDialog, "exec", fill_program({}, generate=True))
        page.program(2)
        wait_idle(app, window)
        assert app.messages[-1] == ("information", "Slot 2 programmed."), key


def test_otp_new_access_code_is_typed_twice(app, window, tab, otp, monkeypatch):
    """A new access code typed once with a wrong digit would lock the slot
    with a code nobody knows: the program dialog asks for it twice."""
    page = tab.pages[2]
    page.refresh()
    wait_idle(app, window)
    monkeypatch.setattr(A.SecretSummaryDialog, "show_text", classmethod(lambda cls, parent, T, title, text: None))
    values = {"public_id": "vvcccccccccb", "private_id": "00" * 6, "key": "11" * 16, "new_code": "0a0b0c0d0e0f"}
    left = []
    for repeat in ("", "0a0b0c0d0e0e", "zz"):
        n = len(otp.calls)
        exec_ = fill_program(dict(values, new_code_repeat=repeat))
        monkeypatch.setattr(A.OtpProgramDialog, "exec", lambda dlg, e=exec_: (e(dlg), left.append(
            dlg.new_code_repeat.text()))[0])
        page.program(2)
        assert app.messages[-1] == ("warning", "The two new access codes differ.") and len(otp.calls) == n, repeat
    assert left == ["", "", ""]                         # (the repeat field is cleared for another try)
    monkeypatch.setattr(A.OtpProgramDialog, "exec", fill_program(dict(values, new_code_repeat="0A0B 0C0D 0E0F")))
    page.program(2)
    wait_idle(app, window)
    name, slot, args = otp.calls[-2]
    assert (name, slot, args["new_access_code"]) == ("program_yubico_otp", 2, bytes.fromhex("0a0b0c0d0e0f"))
    otp.slots[2]["configured"] = False                  # no new code: both fields empty
    otp.codes[2] = None
    page.refresh()
    wait_idle(app, window)
    monkeypatch.setattr(A.OtpProgramDialog, "exec", fill_program(dict(values, new_code="")))
    page.program(2)
    wait_idle(app, window)
    assert otp.calls[-2][2]["new_access_code"] is None


def test_otp_summary_copy_leaves_the_clipboard(app, window, tab, monkeypatch):
    """The Yubico OTP summary's Copy asks clipboard managers (Windows
    clipboard history and cloud clipboard, KDE) not to keep the secret, and
    takes it off the clipboard when the dialog closes - unless something else
    was copied since."""
    clipboard = QtWidgets.QApplication.clipboard()
    secret = "Secret key: 00112233445566778899aabbccddeeff"
    seen = []

    def copy_then(after=None):
        def exec_(dlg):
            dlg.copy_btn.click()
            seen.append((clipboard.text(), set(clipboard.mimeData().formats())))
            if after:
                after()
            return 1
        return exec_
    monkeypatch.setattr(A.SecretSummaryDialog, "exec", copy_then())
    A.SecretSummaryDialog.show_text(tab, tab.T, "t", secret)
    assert seen[0][0] == secret and {f for f, _ in A._NOT_KEPT} <= seen[0][1]
    assert clipboard.text() == ""
    monkeypatch.setattr(A.SecretSummaryDialog, "exec", copy_then(lambda: clipboard.setText("mine")))
    A.SecretSummaryDialog.show_text(tab, tab.T, "t", secret)
    assert clipboard.text() == "mine"
    assert "not keep" in A.EN["otp-summary"] and "clipboard" in A.EN["otp-summary"]


def test_otp_delete_swap_access_code_and_test(app, window, tab, otp):
    page = tab.pages[2]
    page.refresh()
    wait_idle(app, window)
    page.delete(1)                                      # answered No
    assert app.messages[-1] == ("warning", A.EN["otp-delete"] % (1, page._slot_text(1)))
    assert "delete" not in otp.calls.names()
    app.answers["warning"].append(Yes)
    app.inputs.append(("", False))                      # the access code: cancelled
    page.delete(1)
    wait_idle(app, window)
    assert otp.slots[1]["configured"] and [c for c in otp.calls if c[0] == "delete"] == [("delete", 1, None)]
    app.answers["warning"].append(Yes)
    app.inputs.append(("12", True))                     # not an access code: said
    page.delete(1)
    wait_idle(app, window)
    assert app.messages[-1][0] == "critical" and "access code" in app.messages[-1][1]
    app.answers["warning"].append(Yes)
    app.inputs.append(("010203040506", True))
    page.delete(1)
    wait_idle(app, window)
    assert not otp.slots[1]["configured"] and app.messages[-1] == ("information", "Slot 1 deleted.")
    # access code of a programmed slot
    otp.slots[2]["configured"] = True
    otp.slots[2]["mode"] = "chal-hmac"
    otp.slots[2]["touch"] = True
    page.refresh()
    wait_idle(app, window)
    app.new_secrets.append("0a0b0c0d0e0f")
    page.access_code(2)
    wait_idle(app, window)
    assert ("set_access_code", 2, bytes.fromhex("0a0b0c0d0e0f"), None) in otp.calls
    assert app.messages[-1] == ("information", "Access code of slot 2 changed.")
    app.new_secrets.append("zz")
    page.access_code(2)
    assert app.messages[-1][0] == "critical" and "hexadecimal" in app.messages[-1][1]
    # swap: confirmed; the access code asked for
    page.swap()
    assert app.messages[-1] == ("warning", A.EN["otp-swap"]) and "swap" not in otp.calls.names()
    app.answers["warning"].append(Yes)
    app.inputs.append(("0a0b0c0d0e0f", True))
    page.swap()
    wait_idle(app, window)
    assert otp.slots[1]["mode"] == "chal-hmac" and app.messages[-1] == ("information", "Slots swapped.")
    # challenge-response: with the touch banner when the slot needs one
    touched = []
    real_run = window._run
    window._run = lambda fn, **k: touched.append(k.get("touch")) or real_run(fn, **k)
    try:
        app.inputs.append(("0011", True))
        page.test(1)
        wait_idle(app, window)
    finally:
        window._run = real_run
    assert touched == [True] and otp.calls[-1] == ("calculate_hmac", 1, b"\x00\x11")
    assert app.messages[-1] == ("information", "Challenge: 0011\nResponse: " + "00" * 20)
    app.inputs.append(("xyz", True))
    page.test(1)
    assert app.messages[-1] == ("critical", "The challenge is not hexadecimal (at most 64 bytes).")


def test_otp_export_import_and_errors(app, window, tab, otp, monkeypatch):
    page = tab.pages[2]
    exported, imported = [], []
    monkeypatch.setattr(tab.ctx, "export_selected", lambda app_, key_id, label=None: exported.append(
        (app_, key_id, label)))
    monkeypatch.setattr(tab.ctx, "import_file", lambda then=None: imported.append(then))
    page.program(1)                                     # not read yet
    assert app.messages[-1] == ("critical", "Refresh first.")
    otp.fail["status"] = ManagerError("the device has no OTP application (SW 6A82)")
    page.refresh()
    wait_idle(app, window)
    assert app.messages[-1] == ("critical", "the device has no OTP application (SW 6A82)") and not page.loaded
    page.refresh()
    wait_idle(app, window)
    page.export(1)
    page.import_keys()
    assert exported == [("otp", b"\x01", "slot1")] and imported == [page.refresh]


# ----------------------------------------------------------------------------
# Texts
# ----------------------------------------------------------------------------

def test_chinese_composed_texts_use_full_width_punctuation(app, window, tab, fido, oath, monkeypatch):
    """Texts put together from translated parts ("FIDO PIN set" + "(8
    attempts left)") take the punctuation of the language: full-width in
    Chinese, as the translations themselves."""
    monkeypatch.setattr(gui, "_LANG_ZH", True)
    T = tab.ctx.T
    passkeys, page = tab.pages[0], tab.pages[1]
    passkeys._show_summary({"pin_set": True, "pin_retries": 8, "min_pin_length": 4})
    assert passkeys.summary.text() == "已设置 FIDO PIN（剩余 8 次）；最短 4 个字符"
    oath.password = "pw"
    app.inputs.append(("pw", True))
    page.clock = Clock(1005.0)
    page.refresh()
    wait_idle(app, window)
    assert page.state.text() == T("OATH accounts: %d") % 4 + "；" + T("protected by a password")
    shown = [page.state.text()] + [t for row in texts(page.table) for t in row[3:]]
    assert texts(page.table, 4)[texts(page.table, 1).index("dave")] == "TOTP SHA1，%s，%s" % (T("%d digits") % 6,
                                                                                            T("%d s") % 60)
    assert T("touch") + "：" + T("press Calculate") in shown
    assert not [t for t in shown if re.search(r"[(),;:]", t)], shown
    assert gui.T(":") == "：" and gui.T("%s: %s") % ("a", "b") == "a：b" and T(" (%s)") % "x" == "（x）"
    monkeypatch.setattr(gui, "_LANG_ZH", False)
    passkeys._show_summary({"pin_set": True, "pin_retries": 8, "min_pin_length": 4})
    assert passkeys.summary.text() == "FIDO PIN set (8 attempts left); minimum length 4"


def test_texts_have_both_languages(monkeypatch):
    """Every text of the Key manager (the tab and pages A) has a Chinese
    translation, keyed texts an English one, with the same arguments."""
    texts_used = set()
    for module in (gui_manager, A):
        texts_used |= {ast.literal_eval('"%s"' % t)
                       for t in re.findall(r'\bT\("((?:[^"\\]|\\.)*)"\)', inspect.getsource(module))}
    texts_used |= set(KeyManagerTab.PAGE_TITLES) | set(A.OTP_MODE_TITLES.values()) | set(A.OTP_SLOT_TITLES.values())
    assert len(texts_used) > 150
    zh = dict(gui.ZH, **gui_manager.ZH)
    missing = sorted(t for t in texts_used if t not in zh)
    assert not missing
    for t in texts_used:
        en = gui_manager.EN.get(t, gui.EN.get(t, t))
        assert re.findall(r"%[sd]", zh[t]) == re.findall(r"%[sd]", en), t
        if "-" in t and " " not in t and t.islower():         # keyed text
            assert t in gui_manager.EN or t in gui.EN, t
    monkeypatch.setattr(gui, "_LANG_ZH", True)
    ctx = ManagerContext(None, gui.T)
    assert ctx.T("fido-locked") == A.ZH["fido-locked"] and ctx.T("Keys") == gui.ZH["Keys"]
