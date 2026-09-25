"""Key manager, OpenPGP and PIV pages (gui_mgr_pages_b) without a device:
offscreen, the main window of test_gui (simulated device, its worker) and
fake managers with the signatures of mgr_pgp.OpenPgpManager and
mgr_piv.PivManager. Every button: the dialogs (generate, PIN / PUK / Admin
PIN / Reset Code, management key, certificates), the confirmations (what is
erased named; replace / permanent only after them; a reset twice), what
reaches the manager, errors shown; device work in the worker; no secret
kept."""

import copy
import datetime
import inspect
import os
import re
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

from cryptography import x509                                   # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec        # noqa: E402
from cryptography.x509.oid import NameOID                       # noqa: E402
from librefido import gui, gui_manager, mgr_pgp, mgr_piv        # noqa: E402
from librefido import gui_mgr_pages_b as B                      # noqa: E402
from librefido.mgr_common import ManagerError, WrongSecret      # noqa: E402
from test_gui import No, Yes, app, window                       # noqa: E402

FIXTURES = (app, window)        # test_gui's: the offscreen application and the main window on a simulated device
QLineEdit, QComboBox, QPushButton = QtWidgets.QLineEdit, QtWidgets.QComboBox, QtWidgets.QPushButton
T = gui_manager.ManagerContext(None, gui.T).T       # the pages' translation (the Key manager's tables first)
TOUCH_BANNER = "Touch the key now (it blinks yellow)..."


# ----------------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def english(monkeypatch):
    """English texts (the managers' messages are compared as they are)."""
    monkeypatch.setattr(gui, "_LANG_ZH", False)


def settle(app, window, quiet=0.4, timeout=20.0):
    """Processes events until no operation has run for `quiet` seconds (a
    page reads the device again after an operation, after a failure once
    idle: ManagerContext.when_idle polls every 250 ms)."""
    deadline = time.time() + timeout
    idle_since = None
    while time.time() < deadline:
        app.processEvents()
        if window.busy:
            idle_since = None
        elif idle_since is None:
            idle_since = time.time()
        elif time.time() - idle_since >= quiet:
            break
        time.sleep(0.01)
    assert not window.busy
    app.processEvents()


class Forms:
    """FormDialog answered from answers: per dialog a dict {field: value}
    (the key "do": a function called with the dialog, e.g. to click a
    button), a list of such dicts tried one after the other (a user
    correcting the form; None in it cancels), or None (cancelled). seen: per
    dialog its title, the problems shown after each try, the items of its
    choices, which fields are enabled and the values when it closed. left:
    the texts of its fields after it closed."""

    def __init__(self):
        self.answers, self.seen, self.left = [], [], []


@pytest.fixture
def forms(app, monkeypatch):
    f = Forms()

    def set_field(w, value):
        if isinstance(w, QLineEdit):
            w.setText(value)
        elif isinstance(w, QComboBox):
            index = next((i for i in range(w.count()) if w.itemData(i) == value), -1)
            assert index >= 0, (value, [w.itemData(i) for i in range(w.count())])
            w.setCurrentIndex(index)
        elif isinstance(w, QtWidgets.QCheckBox):
            w.setChecked(value)
        else:
            w.setValue(value)

    def exec_(dlg):
        answer = f.answers.pop(0) if f.answers else None
        tries = answer if isinstance(answer, list) else [answer]
        problems = []
        for values in tries:
            if values is None:
                break
            for key, value in values.items():
                if key == "do":
                    value(dlg)
                else:
                    set_field(dlg.fields[key], value)
            dlg._accept()
            problems.append(dlg.problem.text())
            if dlg.values is not None:
                break
        f.seen.append({"title": dlg.windowTitle(), "problems": problems,
                       "items": {k: [w.itemData(i) for i in range(w.count())] for k, w in dlg.fields.items()
                                 if isinstance(w, QComboBox)},
                       "enabled": {k: w.isEnabled() for k, w in dlg.fields.items()},
                       "values": {k: dlg.value(k) for k in dlg.fields}})
        return int(dlg.values is not None)
    monkeypatch.setattr(B.FormDialog, "exec", exec_)
    real_ask = B.FormDialog.ask

    def ask(dlg):
        try:
            return real_ask(dlg)
        finally:
            f.left.append([w.text() for w in dlg.fields.values() if isinstance(w, QLineEdit)])
    monkeypatch.setattr(B.FormDialog, "ask", ask)
    return f


@pytest.fixture
def ctx(app, window):
    parent = QtWidgets.QWidget()
    c = gui_manager.ManagerContext(window, gui.T, parent)
    c.keep = parent
    return c


class Fake:
    """A fake manager: records each call (name and every argument, defaults
    included) and whether it ran on the GUI thread; fail[name]: raised by
    the next call of name."""

    def __init__(self):
        self.calls, self.on_gui_thread, self.fail = [], [], {}

    def _call(self, name, *args):
        self.on_gui_thread.append(threading.current_thread() is threading.main_thread())
        self.calls.append((name,) + args)
        e = self.fail.pop(name, None)
        if e is not None:
            raise e

    def ops(self):
        return [c for c in self.calls if c[0] not in ("status", "supported_algorithms")]


FP_SIG = "0123456789ABCDEF0123456789ABCDEF01234567"
PGP_OFFERED = {"sig": ["rsa2048", "rsa3072", "rsa4096", "nistp256", "ed25519"],
               "dec": ["rsa2048", "nistp256", "cv25519"],
               "aut": ["rsa2048", "nistp256", "ed25519"]}


class FakePgp(Fake):
    def __init__(self):
        super().__init__()
        self.offered = copy.deepcopy(PGP_OFFERED)
        self.st = {"version": "3.4", "serial": "1234ABCD", "manufacturer": 0xF1D0, "name": "Doe<<Jane", "url": "",
                   "keys": {"sig": {"algorithm": "ed25519", "label": "EdDSA ed25519", "attributes": b"\x16",
                                    "present": True, "fingerprint": FP_SIG, "created": 1700000000, "uif": 0},
                            "dec": {"algorithm": "rsa2048", "label": "RSA 2048", "attributes": b"\x01",
                                    "present": False, "fingerprint": None, "created": None, "uif": 1},
                            "aut": {"algorithm": "nistp256", "label": "ECDSA nistp256", "attributes": b"\x13",
                                    "present": None, "fingerprint": None, "created": None, "uif": 2}},
                   "pin_retries": (3, 0, 3), "signature_counter": 5}

    def status(self):
        self._call("status")
        return copy.deepcopy(self.st)

    def supported_algorithms(self, ref):
        self._call("supported_algorithms", ref)
        if self.offered is None:
            raise ManagerError("OpenPGP: reading data object FA: not found (SW 6A88)", 0x6A88)
        return list(self.offered[ref])

    def generate(self, ref, algorithm, admin_pin, replace=False, created=None):
        self._call("generate", ref, algorithm, admin_pin, replace, created)
        self.st["keys"][ref].update(algorithm=algorithm, label=algorithm, present=True, fingerprint="AB" * 20,
                                    created=1800000000)
        return {"key_ref": ref, "algorithm": algorithm, "fingerprint": "AB" * 20, "created": 1800000000,
                "public_key": "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"}

    def delete_key(self, ref, admin_pin):
        self._call("delete_key", ref, admin_pin)

    def change_pin(self, old, new):
        self._call("change_pin", old, new)

    def change_admin_pin(self, old, new):
        self._call("change_admin_pin", old, new)

    def set_reset_code(self, admin_pin, code):
        self._call("set_reset_code", admin_pin, code)

    def unblock_pin(self, new_pin, admin_pin=None, reset_code=None):
        self._call("unblock_pin", new_pin, admin_pin, reset_code)

    def set_uif(self, ref, value, admin_pin, permanent=False):
        self._call("set_uif", ref, value, admin_pin, permanent)

    def set_cardholder(self, name, admin_pin):
        self._call("set_cardholder", name, admin_pin)

    def set_url(self, url, admin_pin):
        self._call("set_url", url, admin_pin)

    def reset(self, admin_pin=None):
        self._call("reset", admin_pin)


def make_cert(key, cn, not_before, not_after, serial=0x1234):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(serial).not_valid_before(not_before).not_valid_after(not_after)
            .sign(key, hashes.SHA256()))


def public_pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


UTC = datetime.timezone.utc
KEY_9A = ec.generate_private_key(ec.SECP256R1())
CERT_9A = make_cert(KEY_9A, "Alice", datetime.datetime(2025, 1, 1, tzinfo=UTC),
                    datetime.datetime(2030, 1, 1, tzinfo=UTC))
KEY_82 = ec.generate_private_key(ec.SECP384R1())
CERT_82 = make_cert(KEY_82, "Old", datetime.datetime(2019, 1, 1, tzinfo=UTC), datetime.datetime(2020, 1, 1, tzinfo=UTC))


def slot_info(algorithm=None, pin_policy=None, touch_policy=None, origin=None, key=None, cert=None):
    """A slot of PivManager.status() (certificate: mgr_piv.certificate_info)."""
    return {"name": "?", "name_zh": "?", "has_key": algorithm is not None, "algorithm": algorithm,
            "pin_policy": pin_policy, "touch_policy": touch_policy, "origin": origin,
            "public_key": public_pem(key) if key else None,
            "certificate": mgr_piv.certificate_info(cert.public_bytes(serialization.Encoding.DER),
                                                    key.public_key() if key else None) if cert else None}


class FakePiv(Fake):
    def __init__(self):
        super().__init__()
        slots = {s: slot_info() for s in mgr_piv.SLOTS}
        slots[0x9A] = slot_info("eccp256", "once", "never", "generated", KEY_9A, CERT_9A)
        slots[0x9D] = slot_info("rsa2048", "always", "always", "imported")
        slots[0x82] = slot_info("eccp384", "once", "never", "imported", KEY_82, CERT_82)
        self.st = {"version": "5.7.0", "serial": 123456, "pin_retries": 3, "pin_attempts": 3, "pin_default": False,
                   "puk_retries": 3, "puk_attempts": 3, "puk_default": False, "mgmt_key_algorithm": "aes192",
                   "mgmt_key_default": True, "mgmt_key_touch": False,
                   "algorithms": ["rsa1024", "rsa2048", "eccp256", "eccp384", "ed25519", "x25519"], "slots": slots}

    def status(self):
        self._call("status")
        return copy.deepcopy(self.st)

    def authenticate(self, mgmt_key=None):
        self._call("authenticate", mgmt_key)

    def forget(self):
        self._call("forget")

    def generate(self, slot, algorithm, pin_policy="default", touch_policy="default", replace=False):
        self._call("generate", slot, algorithm, pin_policy, touch_policy, replace)
        return public_pem(KEY_9A)

    def self_sign(self, slot, subject, days, pin, replace=False):
        self._call("self_sign", slot, subject, days, pin, replace)
        return CERT_9A.public_bytes(serialization.Encoding.PEM).decode()

    def csr(self, slot, subject, pin):
        self._call("csr", slot, subject, pin)
        return "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"

    def import_certificate(self, slot, data, replace=False, verify=True):
        self._call("import_certificate", slot, data, replace, verify)

    def export_certificate(self, slot):
        self._call("export_certificate", slot)
        return self.st["slots"][slot]["certificate"]["pem"]

    def delete_certificate(self, slot):
        self._call("delete_certificate", slot)

    def delete_key(self, slot, with_certificate=False):
        self._call("delete_key", slot, with_certificate)

    def move_key(self, src, dst, replace=False, with_certificate=True):
        self._call("move_key", src, dst, replace, with_certificate)

    def change_pin(self, old, new):
        self._call("change_pin", old, new)

    def change_puk(self, old, new):
        self._call("change_puk", old, new)

    def unblock_pin(self, puk, new_pin):
        self._call("unblock_pin", puk, new_pin)

    def set_management_key(self, new_key, algorithm="aes192", touch=False):
        self._call("set_management_key", new_key, algorithm, touch)

    def reset(self):
        self._call("reset")


def _page(app, window, cls, fake, ctx):
    made = []

    def factory(m):
        made.append(m)
        return fake
    page = cls(ctx, factory=factory)
    page.fake, page.made = fake, made
    page.refresh()
    settle(app, window)
    return page


@pytest.fixture
def pgp(app, window, ctx, forms):
    return _page(app, window, B.OpenPgpPage, FakePgp(), ctx)


@pytest.fixture
def piv(app, window, ctx, forms):
    return _page(app, window, B.PivPage, FakePiv(), ctx)


def rows(page):
    t = page.table
    return [[t.item(r, c).text() for c in range(t.columnCount())] for r in range(t.rowCount())]


def kinds(app):
    return [k for k, _ in app.messages]


def last(app, kind):
    return [text for k, text in app.messages if k == kind][-1]


def admin(*ops, key=None):
    """What an administrative PIV operation sends: the management key
    checked, the operations, the manager's copy of the key wiped."""
    return [("authenticate", key)] + list(ops) + [("forget",)]


def test_fakes_have_the_signatures_of_the_managers():
    for fake, real in ((FakePgp, mgr_pgp.OpenPgpManager), (FakePiv, mgr_piv.PivManager)):
        for name, fn in vars(fake).items():
            if not name.startswith("_"):
                assert inspect.signature(fn) == inspect.signature(getattr(real, name)), (real.__name__, name)


# ----------------------------------------------------------------------------
# OpenPGP
# ----------------------------------------------------------------------------

def test_pgp_status_is_read_in_the_worker_and_shown(app, window, pgp):
    fp = " ".join(FP_SIG[i:i + 4] for i in range(0, 40, 4))
    assert rows(pgp) == [[T("Signature"), "EdDSA ed25519", fp, "2023-11-14", T("off")],
                         [T("Decryption"), "-", T("no key"), "-", T("on")],
                         [T("Authentication"), "-", T("no key"), "-", T("on, permanent")]]
    assert {k: lbl.text() for k, lbl in pgp.labels.items()} == {
        "version": "3.4", "serial": "1234ABCD", "name": "Doe<<Jane", "url": "-",
        "retries": T("PIN %s, Reset Code %s, Admin PIN %s") % (3, 0, 3), "signatures": "5"}
    assert pgp.fake.calls == [("status",)] + [("supported_algorithms", r) for r in ("sig", "dec", "aut")]
    assert pgp.fake.on_gui_thread == [False] * 4 and pgp.made == [window.mgmt] and pgp.loaded
    for lbl in pgp.labels.values():
        assert lbl.textFormat() == gui.Qt.TextFormat.PlainText
    pgp.fake.st["pin_retries"] = (0, 0, 0)
    pgp.refresh()
    settle(app, window)
    assert T("The PIN is blocked: unblock it with the Reset Code or the Admin PIN.") in pgp.state.text()
    assert T("The Admin PIN is blocked: only a reset of OpenPGP makes its keys usable again.") in pgp.state.text()
    pgp.device_changed()                                # another device: nothing of this one stays
    assert pgp.status is None and not pgp.loaded and pgp.table.rowCount() == 0 and pgp.labels["name"].text() == "-"


def test_pgp_generate(app, window, pgp, forms):
    fake = pgp.fake
    pgp.table.selectRow(1)                              # the empty decryption slot
    forms.answers.append({"admin": "12345678"})
    pgp.generate()
    settle(app, window)
    seen = forms.seen[-1]
    assert seen["values"]["ref"] == "dec" and seen["values"]["algorithm"] == "cv25519"
    assert seen["items"]["algorithm"] == PGP_OFFERED["dec"]             # what the card offers for the slot
    assert fake.ops() == [("generate", "dec", "cv25519", "12345678", False, None)] and not any(fake.on_gui_thread)
    assert "warning" not in kinds(app)                  # an empty slot: nothing to confirm
    text = last(app, "information")
    assert text.startswith(T("New %s key generated on the device.") % T("Decryption"))
    assert "ABAB ABAB" in text and T("pgp-gnupg-hint") in text
    assert fake.calls[-4] == ("status",) and rows(pgp)[1][2].startswith("ABAB")     # read again
    # the signature slot holds a key: replacing it is confirmed, naming it
    forms.answers.append({"ref": "sig", "algorithm": "rsa4096", "admin": "12345678"})
    pgp.generate()                                      # answered No
    settle(app, window)
    assert forms.seen[-1]["items"]["algorithm"] == PGP_OFFERED["sig"]
    question = last(app, "warning")
    assert question.startswith(T("Replace the %s key?") % T("Signature")) and "0123 4567 89AB" in question
    assert T("pgp-replace-info") in question and len(fake.ops()) == 1
    forms.answers.append({"ref": "sig", "admin": "12345678"})       # (its own algorithm proposed)
    app.answers["warning"].append(Yes)
    pgp.generate()
    settle(app, window)
    assert fake.ops()[-1] == ("generate", "sig", "ed25519", "12345678", True, None)
    # no Admin PIN: said in the dialog, which stays open (then cancelled)
    forms.answers.append([{"admin": ""}, None])
    pgp.generate()
    assert forms.seen[-1]["problems"] == [T("The OpenPGP Admin PIN is needed.")] and len(fake.ops()) == 2
    # a card that cannot say what it offers: what fits the slot
    fake.offered = None
    pgp.refresh()
    settle(app, window)
    assert pgp.loaded and "critical" not in kinds(app)
    n = len(forms.seen)
    forms.answers.append(None)
    pgp.table.selectRow(1)
    pgp.generate()
    offered = forms.seen[-1]["items"]["algorithm"]
    assert len(forms.seen) == n + 1 and offered == B._pgp_algorithms_for("dec")
    assert "cv25519" in offered and "ed25519" not in offered and "rsa4096" in offered


def test_pgp_pins(app, window, pgp, forms):
    fake = pgp.fake
    forms.answers.append([{"current": "123456", "new": "654321", "repeat": "654320"}, {"repeat": "654321"}])
    pgp.change_pin()
    settle(app, window)
    assert forms.seen[-1]["problems"] == [T("The two entries differ."), ""]
    assert fake.ops() == [("change_pin", "123456", "654321")] and last(app, "information") == T("The PIN was changed.")
    forms.answers.append([{"current": "123456", "new": "123", "repeat": "123"}, None])
    pgp.change_pin()
    forms.answers.append([{"current": "123456", "new": "éé", "repeat": "éé"}, None])        # 4 bytes
    pgp.change_pin()
    forms.answers.append([{"current": "", "new": "1234567", "repeat": "1234567"}, None])
    pgp.change_pin()
    assert [s["problems"] for s in forms.seen[-3:]] == [[T("At least %d characters.") % 6],
                                                        [T("At least %d bytes (UTF-8).") % 6],
                                                        [T("Fill in every field.")]]
    forms.answers.append([{"current": "12345678", "new": "1234567", "repeat": "1234567"},
                          {"new": "87654321", "repeat": "87654321"}])
    pgp.change_admin_pin()
    settle(app, window)
    assert forms.seen[-1]["problems"] == [T("At least %d characters.") % 8, ""]
    forms.answers.append({"current": "87654321", "new": "resetcode1", "repeat": "resetcode1"})
    pgp.set_reset_code()
    settle(app, window)
    # unblocking: the Reset Code has no tries left, so the Admin PIN is proposed
    forms.answers.append({"secret": "87654321", "new": "111111", "repeat": "111111"})
    pgp.unblock_pin()
    settle(app, window)
    assert forms.seen[-1]["values"]["how"] == "admin_pin"
    forms.answers.append({"how": "reset_code", "secret": "resetcode1", "new": "222222", "repeat": "222222"})
    pgp.unblock_pin()
    settle(app, window)
    assert fake.ops()[1:] == [("change_admin_pin", "12345678", "87654321"),
                              ("set_reset_code", "87654321", "resetcode1"),
                              ("unblock_pin", "111111", "87654321", None),
                              ("unblock_pin", "222222", None, "resetcode1")]
    assert last(app, "information") == T("The PIN was unblocked and set.") and not any(fake.on_gui_thread)
    assert all(not any(texts) for texts in forms.left)          # the dialogs emptied their fields


def test_pgp_wrong_pin_is_shown_and_the_tries_read_again(app, window, pgp, forms, monkeypatch):
    fake = pgp.fake
    fake.fail["change_pin"] = WrongSecret("OpenPGP: wrong OpenPGP PIN, 2 tries left (SW 63C2)", 0x63C2,
                                          "OpenPGP：OpenPGP 用户 PIN错误，还剩 2 次（SW 63C2）", retries=2)
    fake.st["pin_retries"] = (2, 0, 3)                  # as the device counts
    forms.answers.append({"current": "000000", "new": "654321", "repeat": "654321"})
    pgp.change_pin()
    settle(app, window)
    assert last(app, "critical") == "OpenPGP: wrong OpenPGP PIN, 2 tries left (SW 63C2)"
    assert "information" not in kinds(app)
    assert pgp.labels["retries"].text() == T("PIN %s, Reset Code %s, Admin PIN %s") % (2, 0, 3)
    monkeypatch.setattr(gui, "_LANG_ZH", True)          # the manager's Chinese message
    fake.fail["change_pin"] = WrongSecret("OpenPGP: wrong OpenPGP PIN, 1 tries left (SW 63C1)", 0x63C1,
                                          "OpenPGP：OpenPGP 用户 PIN错误，还剩 1 次（SW 63C1）", retries=1)
    forms.answers.append({"current": "000000", "new": "654321", "repeat": "654321"})
    pgp.change_pin()
    settle(app, window)
    assert last(app, "critical") == "OpenPGP：OpenPGP 用户 PIN错误，还剩 1 次（SW 63C1）"
    # an unexpected failure (a bug) is not swallowed: the main window shows its traceback
    fake.fail["change_pin"] = KeyError("boom")
    forms.answers.append({"current": "000000", "new": "654321", "repeat": "654321"})
    pgp.change_pin()
    settle(app, window)
    assert "Traceback" in last(app, "critical") and "boom" in last(app, "critical")


def test_pgp_touch_policy(app, window, pgp, forms):
    fake = pgp.fake
    pgp.table.selectRow(0)
    forms.answers.append({"uif": 1, "admin": "12345678"})
    pgp.touch_policy()
    settle(app, window)
    assert fake.ops() == [("set_uif", "sig", 1, "12345678", False)]
    assert last(app, "information") == T("Touch policy of the %s key: %s") % (T("Signature"), T("on"))
    forms.answers.append({"uif": 2, "admin": "12345678"})          # permanent: confirmed (No)
    pgp.touch_policy()
    settle(app, window)
    assert last(app, "warning").startswith(T("Make the touch policy of the %s key permanent?") % T("Signature"))
    assert len(fake.ops()) == 1
    forms.answers.append({"uif": 4, "admin": "12345678"})
    app.answers["warning"].append(Yes)
    pgp.touch_policy()
    settle(app, window)
    assert fake.ops()[-1] == ("set_uif", "sig", 4, "12345678", True)
    # another slot in the dialog: its own policy is proposed (decryption: on, unchanged)
    forms.answers.append({"ref": "dec", "admin": "12345678"})
    pgp.touch_policy()
    assert forms.seen[-1]["values"]["uif"] == 1 and last(app, "information") == T("Nothing to change.")
    pgp.table.selectRow(2)                              # authentication: permanently on
    forms.answers.append({"uif": 0, "admin": "12345678"})
    pgp.touch_policy()
    assert last(app, "critical") == T("pgp-uif-fixed") and len(fake.ops()) == 2


def test_pgp_cardholder_name_and_url(app, window, pgp, forms):
    forms.answers.append([{"text": "x" * 40, "admin": "12345678"}, {"text": "Müller<<Jane"},
                          {"text": " Doe<<John "}])
    pgp.cardholder_name()
    settle(app, window)
    assert forms.seen[-1]["problems"] == [T("At most %d characters.") % 39, T("pgp-ascii"), ""]
    assert pgp.fake.ops() == [("set_cardholder", "Doe<<John", "12345678")]
    assert last(app, "information") == T("The cardholder name was set.")
    forms.answers.append(None)
    pgp.cardholder_name()                               # the current name is proposed; cancelled
    assert forms.seen[-1]["values"]["text"] == "Doe<<Jane" and len(pgp.fake.ops()) == 1
    forms.answers.append([{"text": "https://example.com/k.asc", "admin": ""},
                          {"admin": "12345678"}])
    pgp.url()
    settle(app, window)
    assert forms.seen[-1]["problems"] == [T("The OpenPGP Admin PIN is needed."), ""]
    assert pgp.fake.ops()[-1] == ("set_url", "https://example.com/k.asc", "12345678")


def test_pgp_delete_key(app, window, pgp):
    fake = pgp.fake
    pgp.delete_key()
    assert last(app, "critical") == T("Select a key slot first.")
    pgp.table.selectRow(1)
    pgp.delete_key()
    assert last(app, "critical") == T("The %s key slot is empty.") % T("Decryption")
    pgp.table.selectRow(0)
    pgp.delete_key()                                    # confirmation answered No
    question = last(app, "warning")
    assert question.startswith(T("Delete the %s key?") % T("Signature")) and "0123 4567" in question
    assert T("pgp-delete-info") in question and "input" not in kinds(app)
    app.answers["warning"].append(Yes)
    pgp.delete_key()                                    # the Admin PIN dialog cancelled
    app.answers["warning"].append(Yes)
    app.inputs.append(("", True))
    pgp.delete_key()                                    # no Admin PIN typed
    assert last(app, "critical") == T("The OpenPGP Admin PIN is needed.")
    assert not fake.ops()
    app.answers["warning"].append(Yes)
    app.inputs.append(("12345678", True))
    pgp.delete_key()
    settle(app, window)
    assert fake.ops() == [("delete_key", "sig", "12345678")]
    assert last(app, "information") == T("The %s key was deleted.") % T("Signature")


def test_pgp_reset_needs_two_confirmations(app, window, pgp):
    fake = pgp.fake
    pgp.reset()                                         # No
    first = last(app, "warning")
    assert first.startswith(T("Reset the OpenPGP application?")) and T("pgp-reset-info") in first
    assert "0123 4567" in first and "Doe<<Jane" in first
    app.answers["warning"] += [Yes, No]
    pgp.reset()
    assert last(app, "warning") == T("pgp-reset-again") and not fake.ops()
    app.answers["warning"] += [Yes, Yes]
    pgp.reset()                                         # the Admin PIN dialog cancelled
    assert ("input", T("pgp-reset-admin")) in app.messages and not fake.ops()
    app.answers["warning"] += [Yes, Yes]
    app.inputs.append(("", True))                       # not known: the manager blocks it first
    pgp.reset()
    assert window.busy and window.banner.text() == T(TOUCH_BANNER)          # the device waits for a touch
    settle(app, window)
    assert fake.ops() == [("reset", None)] and last(app, "information") == T("pgp-reset-done")
    app.answers["warning"] += [Yes, Yes]
    app.inputs.append(("12345678", True))
    pgp.reset()
    settle(app, window)
    assert fake.ops()[-1] == ("reset", "12345678")


def test_pgp_export_and_import_go_through_the_keys_tab(app, window, pgp, ctx, monkeypatch):
    exported, imported = [], []
    monkeypatch.setattr(ctx, "export_selected", lambda app_, key_id, label=None: exported.append((app_, key_id, label)))
    monkeypatch.setattr(window.keys_tab, "import_file", lambda: imported.append(True))
    pgp.table.selectRow(0)
    pgp.export_selected()
    assert exported == [("openpgp", 1, "signature")]
    pgp.table.selectRow(2)
    pgp.export_selected()
    assert last(app, "critical") == T("The %s key slot is empty.") % T("Authentication") and len(exported) == 1
    n = len(pgp.fake.calls)
    pgp.import_file()
    settle(app, window)
    assert imported == [True] and pgp.fake.calls[n] == ("status",)     # read again afterwards


def test_pgp_errors_before_loading_and_without_device(app, window, ctx, forms):
    fake = FakePgp()
    fake.fail["status"] = ManagerError("the device has no OpenPGP application (SW 6A82)", 0x6A82)
    page = B.OpenPgpPage(ctx, factory=lambda m: fake)
    page.auto_refresh()                                 # shown: written on the page, no message box
    settle(app, window)
    assert page.state.text() == "the device has no OpenPGP application (SW 6A82)" and not app.messages
    assert page.status is None and not page.loaded
    page.generate()
    assert last(app, "critical") == T("Refresh first: the page has not read the device yet.")
    fake.fail["status"] = ManagerError("the device has no OpenPGP application (SW 6A82)", 0x6A82)
    page.refresh()                                      # asked for: said
    settle(app, window)
    assert last(app, "critical") == "the device has no OpenPGP application (SW 6A82)"
    page.refresh()
    settle(app, window)
    assert page.loaded and page.table.rowCount() == 3
    mgmt, window.mgmt = window.mgmt, None
    page.change_pin()
    assert last(app, "critical") == T("No device") and not forms.seen
    window.mgmt = mgmt
    window.busy = True                                  # another operation runs: nothing starts
    page.change_pin()
    window.busy = False
    assert not forms.seen and not fake.ops()


def test_no_secret_is_kept(app, window, pgp, piv, forms):
    forms.answers.append({"current": "s3cret-old", "new": "s3cret-new", "repeat": "s3cret-new"})
    pgp.change_pin()
    settle(app, window)
    assert pgp.fake.ops() == [("change_pin", "s3cret-old", "s3cret-new")]
    assert window._job.fn is None and window._then is None and window._on_error is None
    assert forms.left[-1] == ["", "", ""]
    piv.fake.st["mgmt_key_default"] = False
    piv.refresh()
    settle(app, window)
    piv.table.selectRow(0)
    app.answers["warning"].append(Yes)
    app.inputs.append(("5ec7e7" * 8, True))
    piv.delete_certificate()
    settle(app, window)
    assert piv.fake.ops() == admin(("delete_certificate", 0x9A), key=bytes.fromhex("5ec7e7" * 8))    # (wiped)
    assert window._job.fn is None and window._then is None and window._on_error is None

    def holds(obj, depth=0):
        if isinstance(obj, str):
            return "s3cret" in obj or "5ec7e7" in obj.lower()
        if isinstance(obj, (bytes, bytearray)):
            return b"\x5e\xc7\xe7" * 8 in obj
        if depth > 3:
            return False
        if isinstance(obj, dict):
            return any(holds(v, depth + 1) for v in obj.values())
        if isinstance(obj, (list, tuple)):
            return any(holds(v, depth + 1) for v in obj)
        return False
    assert not holds(vars(pgp)) and not holds(vars(piv))


# ----------------------------------------------------------------------------
# PIV
# ----------------------------------------------------------------------------

def test_piv_slots_and_certificate_details(app, window, piv):
    shown = rows(piv)
    assert [r[0] for r in shown] == ["9A (%s)" % T("Authentication"), "9C (%s)" % T("Digital signature"),
                                     "9D (%s)" % T("Key management"), "9E (%s)" % T("Card authentication"),
                                     "82 (%s)" % (T("Retired %d") % 1)]
    assert shown[0][1:] == ["ECC P-256", T("generated"), T("once"), T("never"), "CN=Alice", "2030-01-01"]
    assert shown[1][1:] == [T("no key"), "-", "-", "-", "-", "-"]
    assert shown[2][1:] == ["RSA 2048", T("imported"), T("always"), T("always"), "-", "-"]
    assert shown[4][6] == "2020-01-01 " + T("(expired)")
    assert piv.labels["retries"].text() == T("PIN %s, PUK %s") % (3, 3)
    assert piv.labels["mgmt"].text() == "AES-192, " + T("default key") and T("piv-default-mgmt") in piv.state.text()
    piv.all_slots.setChecked(True)
    assert piv.table.rowCount() == 24
    piv.all_slots.setChecked(False)
    piv.table.selectRow(0)
    details = piv.details.toPlainText()
    for text in (T("Slot %s") % ("9A (%s)" % T("Authentication")), T("Subject: %s") % "CN=Alice",
                 T("Issuer: %s") % "CN=Alice", T("Serial number: %s") % "1234",
                 T("Valid from %s to %s") % ("2025-01-01", "2030-01-01"), "-----BEGIN PUBLIC KEY-----",
                 "-----BEGIN CERTIFICATE-----"):
        assert text in details, text
    assert T("The certificate does not belong to the key in this slot.") not in details
    piv.table.selectRow(1)
    assert T("Key: none") in piv.details.toPlainText() and T("Certificate: none") in piv.details.toPlainText()
    piv.refresh()                                       # the selection stays
    settle(app, window)
    assert B.selected_row(piv.table) == 1 and piv.fake.on_gui_thread == [False, False]
    # the device's warnings; a certificate of another key, an unreadable one
    st = piv.fake.st
    st.update(pin_default=True, puk_default=True, pin_retries=0, puk_retries=0, mgmt_key_default=False,
              mgmt_key_touch=True)
    st["slots"][0x9A]["certificate"]["matches_key"] = False
    st["slots"][0x9C]["certificate"] = mgr_piv.certificate_info(b"\x30\x03\x02\x01\x00")
    piv.refresh()
    settle(app, window)
    for text in (T("The default PIN is in use: change it."), T("The default PUK is in use: change it."),
                 T("The PIN is blocked: unblock it with the PUK."),
                 T("The PUK is blocked: once the PIN is blocked too, only a reset of PIV helps.")):
        assert text in piv.state.text(), text
    assert T("piv-default-mgmt") not in piv.state.text() and piv.labels["mgmt"].text() == "AES-192, " + T("touch")
    assert rows(piv)[1][5] == T("unreadable")
    assert T("The certificate cannot be read: %s") % "" in piv.details.toPlainText()
    piv.table.selectRow(0)
    assert T("The certificate does not belong to the key in this slot.") in piv.details.toPlainText()


def test_piv_generate_self_signed_with_the_default_management_key(app, window, piv, forms):
    fake = piv.fake
    piv.table.selectRow(1)                              # 9C, empty
    forms.answers.append({"algorithm": "eccp384", "pin_policy": "always", "touch_policy": "always",
                          "subject": "CN=Bob", "days": 730, "pin": "123456"})
    piv.generate()
    assert window.banner.text() == T(TOUCH_BANNER)      # the new key signs with touch policy "always"
    settle(app, window)
    seen = forms.seen[-1]
    assert seen["values"]["slot"] == 0x9C and "input" not in kinds(app)     # the default key: not asked
    assert seen["items"]["algorithm"] == ["eccp256", "eccp384", "ed25519", "rsa2048", "rsa1024", "x25519"]
    assert fake.ops() == admin(("generate", 0x9C, "eccp384", "always", "always", False),
                               ("self_sign", 0x9C, "CN=Bob", 730, "123456", True))
    text = last(app, "information")
    assert text == T("New %s key generated in slot %s.") % ("ECC P-384", "9C (%s)" % T("Digital signature")) + \
        "\n" + T("A self-signed certificate is in the slot.")
    assert not any(fake.on_gui_thread) and fake.calls[-1] == ("status",)
    forms.answers.append([{"subject": " ", "pin": "123456"}, {"subject": "CN=Bob", "pin": ""}, None])
    piv.generate()
    assert forms.seen[-1]["problems"] == [T("Enter a subject, e.g. CN=Alice."), T("Fill in every field.")]
    assert len(fake.ops()) == 4


def test_piv_generate_csr_x25519_and_replacement(app, window, piv, forms, monkeypatch, tmp_path):
    fake = piv.fake
    fake.st["mgmt_key_default"] = False
    piv.refresh()
    settle(app, window)
    piv.table.selectRow(0)                              # 9A holds a key and a certificate
    answer = {"certificate": "csr", "subject": "CN=Alice", "pin": "123456"}
    forms.answers.append(dict(answer))
    piv.generate()                                      # replacing it: answered No
    question = last(app, "warning")
    assert question.startswith(T("Replace what slot %s holds?") % ("9A (%s)" % T("Authentication")))
    assert "CN=Alice" in question and T("piv-replace-info") in question and "input" not in kinds(app)
    csr = tmp_path / "a.csr"
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(csr), "")))
    forms.answers.append(dict(answer))
    app.answers["warning"].append(Yes)
    app.inputs.append(("not hex", True))
    piv.generate()                                      # a management key that is not hexadecimal
    assert last(app, "critical") == T("piv-bad-hex") and not fake.ops()
    forms.answers.append(dict(answer))
    app.answers["warning"].append(Yes)
    app.inputs.append(("01 02 03 04 05 06 07 08 01 02 03 04 05 06 07 08 01 02 03 04 05 06 07 08", True))
    piv.generate()
    settle(app, window)
    key = bytes.fromhex("010203040506070801020304050607080102030405060708")
    assert fake.ops() == admin(("generate", 0x9A, "eccp256", "default", "default", True),
                               ("csr", 0x9A, "CN=Alice", "123456"), key=key)
    assert csr.read_text().startswith("-----BEGIN CERTIFICATE REQUEST-----")
    assert T("Certificate signing request written: %s") % csr in last(app, "information")
    assert T("piv-csr-cert") in last(app, "information")
    # X25519 agrees keys only: no certificate, no PIN
    piv.table.selectRow(3)                              # 9E, empty
    forms.answers.append({"algorithm": "x25519", "pin": ""})
    app.inputs.append(("", True))                       # the default management key
    n = len(fake.ops())
    piv.generate()
    settle(app, window)
    seen = forms.seen[-1]
    assert not seen["enabled"]["certificate"] and not seen["enabled"]["pin"] and not seen["enabled"]["subject"]
    assert fake.ops()[n:] == admin(("generate", 0x9E, "x25519", "default", "default", False))
    assert T("An X25519 key has no certificate.") in last(app, "information")


def test_piv_certificates(app, window, piv, forms, monkeypatch, tmp_path):
    fake = piv.fake

    def open_file(path):
        monkeypatch.setattr(QtWidgets.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(path), "")))
    other = ec.generate_private_key(ec.SECP256R1())
    cert = make_cert(other, "Carol", datetime.datetime(2025, 1, 1, tzinfo=UTC),
                     datetime.datetime(2027, 1, 1, tzinfo=UTC))
    pem = tmp_path / "carol.pem"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    der = cert.public_bytes(serialization.Encoding.DER)
    open_file(pem)
    piv.table.selectRow(1)                              # 9C: nothing there, a plain question
    app.answers["question"].append(Yes)
    piv.import_certificate()
    settle(app, window)
    question = last(app, "question")
    assert question.startswith(T("Import this certificate into slot %s?") % ("9C (%s)" % T("Digital signature")))
    assert T("Subject: %s") % "CN=Carol" in question and T("piv-cert-mismatch") not in question
    assert fake.ops() == admin(("import_certificate", 0x9C, der, False, True))
    assert last(app, "information") == T("The certificate was imported.")
    piv.table.selectRow(0)                              # 9A: replaces its certificate, of another key
    piv.import_certificate()                            # answered No
    warning = last(app, "warning")
    assert warning.startswith(T("Replace the certificate of slot %s?") % ("9A (%s)" % T("Authentication")))
    assert T("piv-cert-replace-info") in warning and T("piv-cert-mismatch") in warning and "CN=Alice" in warning
    assert len(fake.ops()) == 3
    app.answers["warning"].append(Yes)                  # confirmed: the manager must not refuse it
    piv.import_certificate()
    settle(app, window)
    assert fake.ops()[-2] == ("import_certificate", 0x9A, der, True, False)
    # a chain in one PEM file: the certificate of the slot's key is the one
    own = make_cert(KEY_9A, "Alice 2", datetime.datetime(2025, 1, 1, tzinfo=UTC),
                    datetime.datetime(2031, 1, 1, tzinfo=UTC))
    chain = tmp_path / "chain.pem"
    chain.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + own.public_bytes(serialization.Encoding.PEM))
    open_file(chain)
    app.answers["warning"].append(Yes)
    piv.import_certificate()
    settle(app, window)
    assert T("piv-cert-mismatch") not in last(app, "warning") and "CN=Alice 2" in last(app, "warning")
    assert fake.ops()[-2] == ("import_certificate", 0x9A, own.public_bytes(serialization.Encoding.DER), True, True)
    bad = tmp_path / "bad.pem"
    bad.write_bytes(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")
    open_file(bad)
    piv.import_certificate()
    assert last(app, "critical").startswith("PIV: not a certificate (PEM or DER)")
    big = tmp_path / "big.der"
    big.write_bytes(b"\x30" + bytes(B.CERT_FILE_MAX + 10))
    open_file(big)
    piv.import_certificate()
    assert last(app, "critical") == T("%s is larger than %d KiB: not a certificate.") % ("big.der", 64)
    assert len(fake.ops()) == 9
    # export: the certificate from the device into a file
    out = tmp_path / "9a.pem"
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(out), "")))
    piv.export_certificate()
    settle(app, window)
    assert x509.load_pem_x509_certificate(out.read_bytes()) == CERT_9A
    assert last(app, "information") == T("Certificate written: %s") % out
    assert fake.ops()[-1] == ("export_certificate", 0x9A)
    piv.table.selectRow(3)
    piv.export_certificate()
    assert last(app, "critical") == T("Slot %s holds no certificate.") % ("9E (%s)" % T("Card authentication"))
    piv.delete_certificate()
    assert last(app, "critical") == T("Slot %s holds no certificate.") % ("9E (%s)" % T("Card authentication"))
    piv.table.selectRow(0)
    piv.delete_certificate()                            # No
    assert last(app, "warning").startswith(T("Delete the certificate of slot %s?") % ("9A (%s)" % T("Authentication")))
    assert T("piv-delete-cert-info") in last(app, "warning") and len(fake.ops()) == 10
    app.answers["warning"].append(Yes)
    piv.delete_certificate()
    settle(app, window)
    assert fake.ops()[10:] == admin(("delete_certificate", 0x9A))


def test_piv_delete_and_move_key(app, window, piv, forms):
    fake = piv.fake
    piv.table.selectRow(1)
    piv.delete_key()
    assert last(app, "critical") == T("Slot %s holds no key.") % ("9C (%s)" % T("Digital signature"))
    piv.move_key()
    assert last(app, "critical") == T("Slot %s holds no key.") % ("9C (%s)" % T("Digital signature"))
    piv.table.selectRow(0)
    piv.delete_key()                                    # No
    warning = last(app, "warning")
    assert warning.startswith(T("Delete the key of slot %s?") % ("9A (%s)" % T("Authentication")))
    assert "ECC P-256" in warning and "CN=Alice" in warning and T("piv-delete-key-info") in warning
    assert not fake.ops()
    app.answers["warning"].append(Yes)                  # its certificate: kept (No)
    piv.delete_key()
    settle(app, window)
    assert last(app, "question") == T("Delete its certificate as well?")
    assert fake.ops() == admin(("delete_key", 0x9A, False))
    app.answers["warning"].append(Yes)
    app.answers["question"].append(Yes)
    piv.delete_key()
    settle(app, window)
    assert fake.ops()[3:] == admin(("delete_key", 0x9A, True))
    # move: an empty slot is proposed; onto a key: what is there named as erased
    forms.answers.append(None)
    piv.move_key()
    assert forms.seen[-1]["values"]["to"] == 0x9C and 0x9A not in forms.seen[-1]["items"]["to"]
    forms.answers.append({"to": 0x9D})
    piv.move_key()                                      # No
    warning = last(app, "warning")
    assert warning.startswith(T("Move the key of slot %s to slot %s?") % ("9A (%s)" % T("Authentication"),
                                                                           "9D (%s)" % T("Key management")))
    assert T("What slot %s holds is erased for good:") % ("9D (%s)" % T("Key management")) in warning
    assert "RSA 2048" in warning and T("piv-move-info") in warning and len(fake.ops()) == 6
    forms.answers.append({"to": 0x9D})
    app.answers["warning"].append(Yes)
    piv.move_key()
    settle(app, window)
    assert fake.ops()[6:] == admin(("move_key", 0x9A, 0x9D, True, True))
    forms.answers.append({"to": 0x9E})
    app.answers["warning"].append(Yes)
    piv.move_key()
    settle(app, window)
    assert T("What slot %s holds is erased for good:") % "9E" not in last(app, "warning")
    assert fake.ops()[9:] == admin(("move_key", 0x9A, 0x9E, False, True))
    assert last(app, "information") == T("The key was moved.")


def test_piv_pin_puk_and_unblock(app, window, piv, forms):
    fake = piv.fake
    forms.answers.append([{"current": "123456", "new": "123456789", "repeat": "123456789"},
                          {"new": "87654321", "repeat": "87654321"}])
    piv.change_pin()
    settle(app, window)
    assert forms.seen[-1]["problems"] == [T("At most %d characters.") % 8, ""]
    forms.answers.append({"current": "12345678", "new": "11223344", "repeat": "11223344"})
    piv.change_puk()
    settle(app, window)
    forms.answers.append([{"current": "11223344", "new": "12345", "repeat": "12345"},
                          {"new": "246810", "repeat": "246810"}])
    piv.unblock_pin()
    settle(app, window)
    assert forms.seen[-1]["problems"] == [T("At least %d characters.") % 6, ""]
    assert fake.ops() == [("change_pin", "123456", "87654321"), ("change_puk", "12345678", "11223344"),
                          ("unblock_pin", "11223344", "246810")]
    assert not any(fake.on_gui_thread)


def test_piv_management_key(app, window, piv, forms):
    fake = piv.fake

    def random(dlg):
        [b] = [b for b in dlg.findChildren(QPushButton) if b.text() == T("Random")]
        b.click()
    forms.answers.append(None)
    piv.management_key()                                # cancelled: the device's algorithm was proposed
    assert forms.seen[-1]["values"]["algorithm"] == "aes192" and not forms.seen[-1]["values"]["touch"]
    assert not fake.ops()
    forms.answers.append({"algorithm": "aes256", "do": random})
    app.answers["warning"].append(Yes)
    piv.management_key()
    settle(app, window)
    new = forms.seen[-1]["values"]["new"]
    assert re.fullmatch("[0-9A-F]{64}", new)
    assert fake.ops() == admin(("set_management_key", bytes.fromhex(new), "aes256", False))
    assert last(app, "information") == T("The management key was changed.")
    assert T("piv-mgmt-keep") in last(app, "warning")
    forms.answers.append([{"algorithm": "aes128", "new": "00" * 24}, {"current": "xyz", "new": "00" * 16}, None])
    piv.management_key()
    assert forms.seen[-1]["problems"] == [T("%s: the new key must be %d bytes (%d hex digits).") % ("AES-128", 16, 32),
                                          T("piv-bad-hex")]
    forms.answers.append({"current": "01" * 24, "algorithm": "3des", "new": "11" * 24})
    piv.management_key()                                # the confirmation answered No
    assert len(fake.ops()) == 3
    forms.answers.append({"current": "01" * 24, "algorithm": "3des", "new": "11" * 24, "touch": True})
    app.answers["warning"].append(Yes)
    piv.management_key()
    settle(app, window)
    assert fake.ops()[3:] == admin(("set_management_key", b"\x11" * 24, "3des", True), key=b"\x01" * 24)
    assert all(not any(texts) for texts in forms.left)


def test_piv_reset_needs_two_confirmations(app, window, piv):
    fake = piv.fake
    piv.reset()
    first = last(app, "warning")
    assert first.startswith(T("Reset the PIV application?")) and T("piv-reset-info") in first
    for text in ("9A (%s)" % T("Authentication"), "9D (%s)" % T("Key management"), "82 (%s)" % (T("Retired %d") % 1),
                 "CN=Alice", "CN=Old"):
        assert text in first, text
    app.answers["warning"] += [Yes, No]
    piv.reset()
    assert last(app, "warning") == T("piv-reset-again") and not fake.ops()
    app.answers["warning"] += [Yes, Yes]
    piv.reset()
    assert window.banner.text() == T(TOUCH_BANNER)
    settle(app, window)
    assert fake.ops() == [("reset",)] and last(app, "information") == T("piv-reset-done")


def test_piv_export_selected_and_errors(app, window, piv, ctx, monkeypatch):
    exported = []
    monkeypatch.setattr(ctx, "export_selected", lambda app_, key_id, label=None: exported.append((app_, key_id, label)))
    piv.export_selected()
    assert last(app, "critical") == T("Select a slot first.")
    piv.table.selectRow(4)
    piv.export_selected()
    assert exported == [("piv", 0x82, "82")]
    piv.table.selectRow(0)
    piv.fake.fail["delete_key"] = ManagerError("PIV: deleting the key of slot 9A: not authenticated (SW 6982)",
                                               0x6982)
    app.answers["warning"].append(Yes)
    piv.delete_key()
    settle(app, window)
    assert last(app, "critical") == "PIV: deleting the key of slot 9A: not authenticated (SW 6982)"
    assert piv.fake.ops() == admin(("delete_key", 0x9A, False))           # the key wiped after a failure too
    assert piv.fake.calls[-1] == ("status",)            # read again once the error was seen


def test_device_gone_during_an_operation(app, window, piv, forms, monkeypatch):
    """The device goes away during an operation: its error is shown once;
    the page's own re-read afterwards says nothing more (no second, 'No
    device' box) and leaves the page cleared. A device change also wipes
    what the page's manager kept (its forget())."""
    fake = piv.fake

    def unplugged(old, new):
        fake._call("change_pin", old, new)
        monkeypatch.setattr(gui, "list_devices", lambda: [])       # (the main window's refresh finds none)
        raise ManagerError("the device was removed")
    monkeypatch.setattr(fake, "change_pin", unplugged)
    forms.answers.append({"current": "123456", "new": "87654321", "repeat": "87654321"})
    piv.change_pin()
    settle(app, window, quiet=0.8)
    assert window.mgmt is None
    assert [m for m in app.messages if m[0] in ("warning", "critical")] == [("critical", "the device was removed")]
    assert piv.status is None and not piv.loaded and piv.table.rowCount() == 0
    piv.device_changed()
    assert fake.calls[-1] == ("forget",) and piv._mgr is None


# ----------------------------------------------------------------------------
# Texts
# ----------------------------------------------------------------------------

def test_texts_have_both_languages(app, window, ctx, monkeypatch):
    """Every text of the pages has a Chinese translation (the pages' table,
    the Key manager's or the main window's), keyed texts an English one;
    the translations take the same arguments."""
    source = inspect.getsource(B)
    texts = set(re.findall(r'\bT\("((?:[^"\\]|\\.)*)"\)', source))
    texts |= set(B.PGP_SLOT_TITLES.values()) | set(B.PGP_UIF.values()) | set(B.PIV_SLOT_TITLES.values())
    texts |= set(B.PIV_PIN_POLICIES) | set(B.PIV_TOUCH_POLICIES) | set(mgr_piv.ORIGINS.values())
    texts |= {"Version", "Serial number", "Cardholder name", "Public key URL", "PIN tries left", "Signatures made",
              "Tries left", "Management key"}
    assert len(texts) > 150
    zh = dict(gui.ZH, **gui_manager.ZH)
    en = dict(gui.EN, **gui_manager.EN)
    missing = sorted(t for t in texts if t not in zh)
    assert not missing
    for t in texts:
        assert re.findall(r"%[sd]", zh[t]) == re.findall(r"%[sd]", en.get(t, t)), t
        if "-" in t and " " not in t and not t.endswith("..."):
            assert t in en, t                           # keyed text
    monkeypatch.setattr(gui, "_LANG_ZH", True)
    page = B.OpenPgpPage(ctx, factory=lambda m: FakePgp())
    page.refresh()
    settle(app, window)
    assert rows(page)[0][0] == "签名" and page.table.horizontalHeaderItem(2).text() == "指纹"
    page = B.PivPage(ctx, factory=lambda m: FakePiv())
    page.refresh()
    settle(app, window)
    assert rows(page)[0][:3] == ["9A（认证）", "ECC P-256", "设备生成"]         # (full-width punctuation)


# ----------------------------------------------------------------------------
# End to end: the pages on the emulated device, with the real managers.
# Skipped without the emulator harness and the user-mode PC/SC stack:
#   bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/tools/test_gui_manager_b.py
# The emulator confirms presence by itself (the resets).
# ----------------------------------------------------------------------------

@pytest.fixture(scope="module")
def pcscd():
    emulator = pytest.importorskip("harness.emulator")
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
def emu_window(app, pcscd, tmp_path):
    """The main window on a fresh emulated device, which it finds over PC/SC
    as it finds a real one."""
    from harness.emulator import Emulator
    e = Emulator(workdir=str(tmp_path / "dev"))
    e.start()
    w = None
    try:
        w = gui.MainWindow()
        deadline = time.time() + 20
        while (w.mgmt is None or w.info is None) and time.time() < deadline:
            time.sleep(0.25)
            w.refresh()
        assert w.mgmt is not None, "the window found no device"
        yield w
    finally:
        if w is not None:
            deadline = time.time() + 60
            while w.busy and time.time() < deadline:
                app.processEvents()
                time.sleep(0.02)
            if w.mgmt is not None:
                _release(w.mgmt)
                w.mgmt = None
            w.close()
        e.stop()


def e2e_page(app, window, cls):
    parent = QtWidgets.QWidget()
    page = cls(gui_manager.ManagerContext(window, gui.T, parent))
    page.keep = parent
    page.refresh()
    settle(app, window, timeout=60)
    assert page.loaded, (page.state.text(), app.messages)
    return page


def no_error(app):
    assert "critical" not in kinds(app), [text for k, text in app.messages if k == "critical"]


def test_openpgp_page_end_to_end(app, emu_window, forms):
    w = emu_window
    page = e2e_page(app, w, B.OpenPgpPage)
    assert [r[2] for r in rows(page)] == [T("no key")] * 3
    assert page.labels["retries"].text() == T("PIN %s, Reset Code %s, Admin PIN %s") % (3, 0, 3)
    offered = page.algorithms["sig"]
    algorithm = "ed25519" if "ed25519" in offered else "nistp256"
    page.table.selectRow(0)
    forms.answers.append({"algorithm": algorithm, "admin": "12345678"})
    page.generate()
    settle(app, w, timeout=120)
    no_error(app)
    fp = rows(page)[0][2]
    assert fp != T("no key") and fp in last(app, "information")
    assert rows(page)[0][1] == page.status["keys"]["sig"]["label"]
    forms.answers.append({"uif": 1, "admin": "12345678"})
    page.touch_policy()
    settle(app, w)
    forms.answers.append({"text": "Doe<<Jane", "admin": "12345678"})
    page.cardholder_name()
    settle(app, w)
    no_error(app)
    assert rows(page)[0][4] == T("on") and page.labels["name"].text() == "Doe<<Jane"
    # a wrong Admin PIN costs a try: said, and the tries read again
    app.answers["warning"].append(Yes)
    app.inputs.append(("87654321", True))
    page.delete_key()
    settle(app, w)
    assert "2" in last(app, "critical") and rows(page)[0][2] == fp
    assert page.labels["retries"].text() == T("PIN %s, Reset Code %s, Admin PIN %s") % (3, 0, 2)
    app.answers["warning"].append(Yes)
    app.inputs.append(("12345678", True))
    page.delete_key()
    settle(app, w)
    assert rows(page)[0][2] == T("no key") and last(app, "information") == T("The %s key was deleted.") % T("Signature")
    forms.answers.append({"current": "123456", "new": "654321", "repeat": "654321"})
    page.change_pin()
    settle(app, w)
    assert last(app, "information") == T("The PIN was changed.")
    # a key to lose, then the reset without the Admin PIN (blocked first)
    page.table.selectRow(2)
    forms.answers.append({"algorithm": algorithm, "admin": "12345678"})
    page.generate()
    settle(app, w, timeout=120)
    fp = rows(page)[2][2]
    assert fp != T("no key")
    n = len(app.messages)
    app.answers["warning"] += [Yes, Yes]
    app.inputs.append(("", True))
    page.reset()
    settle(app, w, timeout=120)
    after = app.messages[n:]
    assert after[0][0] == "warning" and fp in after[0][1] and "Doe<<Jane" in after[0][1]
    assert [k for k, _ in after] == ["warning", "warning", "input", "information"], after
    assert after[-1][1] == T("pgp-reset-done")
    assert [r[2] for r in rows(page)] == [T("no key")] * 3 and page.labels["name"].text() == "-"
    assert page.labels["retries"].text() == T("PIN %s, Reset Code %s, Admin PIN %s") % (3, 0, 3)


def test_piv_page_end_to_end(app, emu_window, forms, monkeypatch, tmp_path):
    w = emu_window
    page = e2e_page(app, w, B.PivPage)
    assert T("default key") in page.labels["mgmt"].text(), page.status.get("mgmt_key_default")
    assert [r[1] for r in rows(page)] == [T("no key")] * 4
    # a key with a self-signed certificate (the default management key: not asked)
    page.table.selectRow(0)
    forms.answers.append({"algorithm": "eccp256", "subject": "CN=E2E", "days": 30, "pin": "123456"})
    page.generate()
    settle(app, w, timeout=60)
    no_error(app)
    assert rows(page)[0][1:3] == ["ECC P-256", T("generated")] and rows(page)[0][5] == "CN=E2E"
    assert T("The certificate does not belong to the key in this slot.") not in page.details.toPlainText()
    out = tmp_path / "9a.pem"
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(out), "")))
    page.export_certificate()
    settle(app, w)
    cert = x509.load_pem_x509_certificate(out.read_bytes())
    assert cert.subject.rfc4514_string() == "CN=E2E"
    assert _spki_of_pem(page.status["slots"][0x9A]["public_key"]) == B._spki(cert.public_key())
    # a certificate request for a new key in 9C
    csr = tmp_path / "9c.csr"
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(csr), "")))
    page.table.selectRow(1)
    forms.answers.append({"algorithm": "eccp384", "certificate": "csr", "subject": "CN=Request", "pin": "123456"})
    page.generate()
    settle(app, w, timeout=60)
    no_error(app)
    req = x509.load_pem_x509_csr(csr.read_bytes())
    assert req.is_signature_valid and req.subject.rfc4514_string() == "CN=Request"
    assert rows(page)[1][1] == "ECC P-384"
    # the certificate of 9A into 9C: not for its key, stored once confirmed
    monkeypatch.setattr(QtWidgets.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(out), "")))
    app.answers["warning"].append(Yes)
    page.import_certificate()
    settle(app, w)
    no_error(app)
    assert T("piv-cert-mismatch") in last(app, "warning") and rows(page)[1][5] == "CN=E2E"
    assert T("The certificate does not belong to the key in this slot.") in page.details.toPlainText()
    # the key of 9A to 9E: its certificate goes with it
    page.table.selectRow(0)
    forms.answers.append({"to": 0x9E})
    app.answers["warning"].append(Yes)
    page.move_key()
    settle(app, w)
    no_error(app)
    shown = rows(page)
    assert shown[0][1] == T("no key") and shown[0][5] == "-" and shown[3][1] == "ECC P-256" and shown[3][5] == "CN=E2E"
    # a management key of our own: asked for from then on (a wrong one is said)

    def random(dlg):
        [b] = [b for b in dlg.findChildren(QPushButton) if b.text() == T("Random")]
        b.click()
    forms.answers.append({"algorithm": "aes192", "do": random})
    app.answers["warning"].append(Yes)
    page.management_key()
    settle(app, w)
    no_error(app)
    new = forms.seen[-1]["values"]["new"]
    assert page.labels["mgmt"].text() == "AES-192"
    page.table.selectRow(3)
    app.answers["warning"].append(Yes)
    app.answers["question"].append(Yes)
    app.inputs.append(("22" * 24, True))
    page.delete_key()
    settle(app, w)
    assert "critical" in kinds(app) and rows(page)[3][1] == "ECC P-256"
    app.answers["warning"].append(Yes)
    app.answers["question"].append(Yes)             # its certificate as well
    app.inputs.append((new, True))
    page.delete_key()
    settle(app, w)
    assert rows(page)[3][1] == T("no key") and rows(page)[3][5] == "-"
    forms.answers.append({"current": "123456", "new": "11223344", "repeat": "11223344"})
    page.change_pin()
    settle(app, w)
    assert last(app, "information") == T("The PIN was changed.")
    # the reset: PIN and PUK blocked first, then every key and certificate goes
    app.answers["warning"] += [Yes, Yes]
    page.reset()
    settle(app, w, timeout=120)
    assert last(app, "information") == T("piv-reset-done")
    assert T("default key") in page.labels["mgmt"].text()
    assert all(r[1] == T("no key") and r[5] == "-" for r in rows(page))
    assert page.labels["retries"].text() == T("PIN %s, PUK %s") % (3, 3)


def _spki_of_pem(pem):
    return B._spki(serialization.load_pem_public_key(pem.encode() if isinstance(pem, str) else pem))
