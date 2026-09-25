"""'Key manager' tab of librefido-gui: the keys of every application of the
active profile, managed directly (like Yubico Authenticator and YubiKey
Manager do for a YubiKey): FIDO passkeys, OATH accounts, OTP slots, OpenPGP
and PIV keys, one page each (gui_mgr_pages_a, gui_mgr_pages_b).

The pages reach the main window only through a ManagerContext: device work
goes through the main window's worker machinery (MainWindow._run: one
operation at a time on the one card connection, worker thread, touch banner),
dialogs through the context. The pages import this module (ManagerPage,
helpers, register_translations); this module imports the page modules only
when the tab is built (gui.py imports this module).

Page protocol (what KeyManagerTab calls, each only if the page has it):
  page.device_changed()   another device, profile or boot: drop what was read
                          and the manager objects, wiping what they hold (a
                          FIDO token, an OATH key, a PIV management key).
  page.shown()            the page became visible (loads it once per device).
"""

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QHeaderView, QInputDialog,
    QLabel, QLineEdit, QMessageBox, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from . import keyio
from .mgr_common import ManagerError, error_text

ZH = {
    "Key manager": "密钥管理",
    "Passkeys": "通行密钥",
    "OATH": "OATH",
    "OTP": "OTP",
    "OpenPGP": "OpenPGP",
    "PIV": "PIV",
    "Refresh": "刷新",
    "Done": "完成",
    "Error": "错误",
    "No device": "未找到设备",
    "Details:": "详细信息：",
    "Export selected...": "导出所选…",
    "Import...": "导入…",
    "Select an entry first.": "请先选择一项。",
    "New value": "新值",
    "Repeat": "重复",
    "The two entries differ.": "两次输入不一致。",
    "Enter a value.": "请输入内容。",
    "At least %d characters.": "至少 %d 个字符。",
    "At most %d characters.": "最多 %d 个字符。",
    "At most %d bytes (UTF-8).": "最多 %d 字节（UTF-8）。",
    "File format:": "文件格式：",
    "LibreFido key file (.lfkey, encrypted)": "LibreFido 密钥文件（.lfkey，加密）",
    "otpauth:// link (NOT encrypted)": "otpauth:// 链接（不加密）",
    "PEM file (PKCS#8, encrypted)": "PEM 文件（PKCS#8，加密）",
    "OpenPGP Admin PIN": "OpenPGP 管理员 PIN",
    "OpenPGP Admin PIN:": "OpenPGP 管理员 PIN（Admin PIN）：",
    "The OpenPGP Admin PIN is needed.": "必须输入 OpenPGP 管理员 PIN。",
    "Key file written": "密钥文件已写入",
    "Key files": "密钥文件",
    "NOT encrypted: anyone with this file has the key.": "未加密：拿到此文件的人即拿到该密钥。",
    "mgr-otpauth-plain": "otpauth:// 链接以明文保存密钥：拿到此文件的人即拿到你的密钥。继续？",
    "mgr-fido-counter-export": ("签名计数器：该通行密钥仍保留在本设备上。会校验签名计数器的网站可能把在两个设备上使用的"
                                "通行密钥视为克隆并停用它：请只在一个设备上使用它。"),
    "mgr-not-exportable": "此环境或固件构建不允许导出私钥（安全环境、禁止导出的环境或 HARDENED 构建）。",
    # punctuation of composed texts (full-width in Chinese)
    ":": "：",
    ": ": "：",
    "%s: %s": "%s：%s",
    ", ": "，",
    "; ": "；",
    " (%s)": "（%s）",
}

# English of the texts that are keys rather than English sentences.
EN = {
    "mgr-otpauth-plain": "An otpauth:// link holds the secret in the clear: anyone with the file has your key. "
                         "Continue?",
    "mgr-fido-counter-export": "Sign counter: the passkey stays on this key as well. A site that checks signature "
                               "counters may take a passkey used on two keys for a clone and block it: use it on "
                               "one key only.",
    "mgr-not-exportable": "This profile or build does not let secret keys out (a secure or no-export profile, or a "
                          "HARDENED build).",
}


def register_translations(zh, en=None):
    """Adds a page module's texts to the tables ManagerContext.T reads:
    Chinese, and the English of the keyed ones. Page modules call it when
    they are imported."""
    ZH.update(zh)
    if en:
        EN.update(en)


def install_translations(zh, en=None):
    """Adds this tab's texts to another table (the main window's, for the tab
    title), like gui_policy.install_translations."""
    zh.update(ZH)
    if en is not None:
        en.update(EN)


def _chinese():
    """The main window's language switch (gui._LANG_ZH), read when needed:
    gui imports this module."""
    from . import gui
    return gui._LANG_ZH


def plain(text, T=lambda s: s):
    """Text for a QMessageBox, which shows rich text when its first line looks
    like HTML: a name from the device or a file could hide or rewrite the
    message. A fixed first line keeps it plain text (as gui._plain)."""
    text = str(text)
    first = text.split("\n", 1)[0]
    if "<" in first or "&" in first:
        return T("Details:") + "\n" + text
    return text


# ----------------------------------------------------------------------------
# Context: what the pages use of the main window
# ----------------------------------------------------------------------------

class ManagerContext:
    """What a page of the Key manager uses of the main window. window is the
    MainWindow (its worker: _run / _run_pin / busy / mgmt / info, its Keys
    tab for key files), T its translation function, parent the widget that
    owns the dialogs."""

    def __init__(self, window, T, parent=None):
        self.w = window
        self._T = T or (lambda s: s)
        self.parent = parent

    # -- texts -----------------------------------------------------------------
    def T(self, text):
        """Translation: the Key manager's tables (this module and the pages'),
        then the main window's."""
        own = (ZH if _chinese() else EN).get(text)
        return own if own is not None else self._T(text)

    # -- device work -----------------------------------------------------------
    def run(self, fn, on_done=None, on_error=None, touch=False, quiet=False):
        """Runs fn() (no argument) in the main window's worker thread: one
        device operation at a time, the banner while it runs (touch: the device
        waits for one; quiet: none, for work the user did not ask for, see
        MainWindow._run). Afterwards, on the GUI thread: on_done(result), or
        on_error(exception), which returns True when it handled the failure;
        otherwise the failure is shown (a ManagerError, ApduError, ... by its
        message; anything unexpected with its traceback). Returns whether it
        started: not while another operation runs, nor without a device (which
        is said)."""
        def failed(e):
            if on_error is not None and on_error(e):
                return True
            if isinstance(e, ManagerError):         # (the worker shows only known types without traceback)
                self.error(self.error_text(e))
                return True
            return False
        return bool(self.w._run(lambda progress: fn(), then=on_done, touch=touch, on_error=failed, quiet=quiet))

    @staticmethod
    def error_text(e):
        """Message of an exception for the user, in the language of the GUI
        (a ManagerError has both)."""
        return error_text(e, _chinese())

    def idle(self):
        """A device is connected and no operation runs (nothing is said)."""
        return self.w.mgmt is not None and not self.w.busy

    def busy(self):
        """An operation runs in the worker (nothing is said)."""
        return bool(self.w.busy)

    def free(self):
        """No operation runs, for what the user asked for: while one does, the
        main window shows that it is busy when its banner does not already
        (a quiet operation, MainWindow._turned_away)."""
        if self.w.busy:
            self.w._turned_away()
            return False
        return True

    def connected(self):
        """The main window has a device (nothing is said)."""
        return self.w.mgmt is not None

    def sync(self):
        """Has the tab (parent) drop what its pages read when the main window
        now has another device, profile, boot or connection
        (KeyManagerTab.sync); nothing for another parent."""
        sync = getattr(self.parent, "sync", None)
        if sync is not None:
            sync()

    def management(self):
        """The main window's Management (one card connection). Raises
        RuntimeError without a device."""
        m = self.w.mgmt
        if m is None:
            raise RuntimeError(self.T("No device"))
        return m

    # -- dialogs ---------------------------------------------------------------
    def ask_secret(self, title, prompt):
        """A secret typed in a password field: the text ("" when left empty),
        or None when cancelled."""
        text, ok = QInputDialog.getText(self.parent, title, prompt, QLineEdit.EchoMode.Password)
        return text if ok else None

    def confirm(self, text, danger=False):
        """Yes / No question (No by default); danger: a warning."""
        yes, no = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
        ask = QMessageBox.warning if danger else QMessageBox.question
        return ask(self.parent, self.T("Key manager"), plain(text, self.T), yes | no, no) == yes

    def info(self, text, title=None):
        QMessageBox.information(self.parent, title or self.T("Done"), plain(text, self.T))

    def error(self, text):
        QMessageBox.critical(self.parent, self.T("Error"), plain(text, self.T))

    # -- key files (the Keys tab) ----------------------------------------------
    def export_selected(self, app, key_id, label=None):
        """Exports one key of the device to a file with the Keys tab's dialogs,
        formats and checks: app is an application name (mgmt.APPS), key_id its
        KEY_LIST ID (FIDO credential ID, OATH name as stored, OTP slot, OpenPGP
        key reference, PIV slot; an int is taken as that one byte), label the
        name for the suggested file. The FIDO PIN is asked for when the profile
        has one. Returns whether the export started."""
        from . import gui                       # (gui imports this module)
        from .cli import write_key
        from .keyfile import SUFFIX
        T, w = self.T, self.w
        if not w._ready():
            return False
        if type(key_id) is int:
            key_id = bytes([key_id])
        if not isinstance(key_id, bytes) or not key_id:
            self.error(T("Select an entry first."))
            return False
        yes, no = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
        formats = [("lfkey", T("LibreFido key file (.lfkey, encrypted)"))]
        if app == "oath":
            formats.append(("otpauth", T("otpauth:// link (NOT encrypted)")))
        if app == "piv":
            formats.append(("pem", T("PEM file (PKCS#8, encrypted)")))
        fmt = "lfkey"
        if len(formats) > 1:
            choice, ok = QInputDialog.getItem(self.parent, T("Export selected..."), T("File format:"),
                                              [text for _, text in formats], 0, False)
            if not ok:
                return False
            fmt = next((f for f, text in formats if text == choice), "lfkey")
        if fmt == "otpauth":
            if QMessageBox.question(self.parent, T("Export selected..."), T("mgr-otpauth-plain"), yes | no,
                                    no) != yes:
                return False
            passphrase = None
        else:
            ok, passphrase = gui.KeyPassphraseDialog.get(self.parent, T)
            if not ok:
                return False
        admin = None
        if app == "openpgp":
            admin = self.ask_secret(T("OpenPGP Admin PIN"), T("OpenPGP Admin PIN:"))
            if admin is None:
                return False
            if not admin:
                QMessageBox.warning(self.parent, T("Error"), T("The OpenPGP Admin PIN is needed."))
                return False
        from PySide6.QtWidgets import QFileDialog
        suffix = {"lfkey": SUFFIX, "pem": ".pem", "otpauth": ".txt"}[fmt]
        path, _ = QFileDialog.getSaveFileName(self.parent, T("Export selected..."),
                                              gui._key_file_name(app, label or key_id.hex()) + suffix,
                                              "%s (*%s)" % (T("Key files"), suffix))
        if not path:
            return False
        encrypted = passphrase is not None

        def export(pin, no_pin, progress):
            key = keyio.export_single(w.mgmt, app, key_id, pin=pin, no_pin=no_pin, secret=admin)
            notes = []
            write_key(path, key, fmt, passphrase, warn=notes.append)
            return path, keyio.describe(key), notes

        def done(r):                            # (holds no secret: it lives as long as the Job)
            written, what, notes = r
            msg = T("Key file written") + T(":") + "\n" + written + "\n\n" + what
            if not encrypted:
                msg += "\n\n" + T("NOT encrypted: anyone with this file has the key.")
            if app == "fido":
                msg += "\n\n" + T("mgr-fido-counter-export")
            for n in notes:
                msg += "\n\n" + n
            self.info(msg)
        w._run_pin(export, None, False, then=done)
        return True

    def import_file(self, then=None):
        """Adds keys from a file with the Keys tab (its file dialog, key file,
        PEM, OpenPGP, otpauth and QR code readers, confirmations and secrets).
        then() runs once that is over: no operation running and no dialog open
        (the page lists its keys again). Returns whether it started (not while
        an operation runs, nor without a device, which is said)."""
        keys_tab = getattr(self.w, "keys_tab", None)
        if keys_tab is None or not self.w._ready():
            return False
        keys_tab.import_file()
        if then is not None:
            self.when_idle(then)
        return True

    def when_idle(self, fn, interval=250):
        """Calls fn() on the GUI thread once no operation runs and no modal
        dialog is open (an operation may ask something when it ends)."""
        timer = QTimer(self.parent)
        timer.setInterval(interval)

        def check():
            if self.w.busy or QApplication.activeModalWidget() is not None:
                return
            timer.stop()
            timer.deleteLater()
            fn()
        timer.timeout.connect(check)
        timer.start()


# ----------------------------------------------------------------------------
# Helpers for the pages
# ----------------------------------------------------------------------------

def ask_new_secret(ctx, title, label, min_len=0, max_len=None, allow_empty=False, max_bytes=None):
    """A new secret (PIN, password, code) typed twice: the text, or None when
    cancelled. min_len / max_len count characters, max_bytes its UTF-8 bytes
    (a FIDO PIN: at least min_len characters, at most 63 bytes); allow_empty
    lets an empty entry through."""
    T = ctx.T
    dlg = QDialog(ctx.parent)
    dlg.setWindowTitle(title)
    form = QFormLayout(dlg)
    intro = QLabel(label)
    intro.setTextFormat(Qt.TextFormat.PlainText)
    intro.setWordWrap(True)
    form.addRow(intro)
    first, second = QLineEdit(), QLineEdit()
    for field in (first, second):
        field.setEchoMode(QLineEdit.EchoMode.Password)
    form.addRow(T("New value") + T(":"), first)
    form.addRow(T("Repeat") + T(":"), second)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    form.addRow(buttons)
    result = []

    def accept():
        a, b = first.text(), second.text()
        problem = None
        if a != b:
            problem = T("The two entries differ.")
        elif not a and not allow_empty:
            problem = T("Enter a value.")
        elif a and len(a) < min_len:
            problem = T("At least %d characters.") % min_len
        elif max_len is not None and len(a) > max_len:
            problem = T("At most %d characters.") % max_len
        elif max_bytes is not None and len(a.encode("utf-8")) > max_bytes:
            problem = T("At most %d bytes (UTF-8).") % max_bytes
        if problem:
            second.clear()
            QMessageBox.warning(dlg, title, problem)
            return
        result.append(a)
        dlg.accept()
    buttons.accepted.connect(accept)
    buttons.rejected.connect(dlg.reject)
    try:
        dlg.exec()
        return result[0] if result else None
    finally:
        first.clear()
        second.clear()
        dlg.deleteLater()


def edit_texts(ctx, title, fields, max_length=None):
    """A dialog of text fields, fields [(label, current value)]: the texts
    typed (stripped), or None when cancelled."""
    dlg = QDialog(ctx.parent)
    dlg.setWindowTitle(title)
    form = QFormLayout(dlg)
    edits = []
    for label, value in fields:
        edit = QLineEdit(value or "")
        if max_length:
            edit.setMaxLength(max_length)
        form.addRow(label, edit)
        edits.append(edit)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    result = []

    def accept():
        result.append([e.text().strip() for e in edits])
        dlg.accept()
    buttons.accepted.connect(accept)
    buttons.rejected.connect(dlg.reject)
    form.addRow(buttons)
    try:
        dlg.exec()
        return result[0] if result else None
    finally:
        dlg.deleteLater()


def make_table(headers):
    """Read-only table of whole rows, one selected at a time."""
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    header = table.horizontalHeader()
    for c in range(len(headers)):
        header.setSectionResizeMode(c, QHeaderView.ResizeMode.Stretch if c == 0 else
                                    QHeaderView.ResizeMode.ResizeToContents)
    header.setStretchLastSection(True)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.verticalHeader().setVisible(False)
    return table


def fill_table(table, rows):
    """Puts rows (sequences of texts, shown as plain text) into table. The
    selection is cleared: a row number may now be another entry (select it
    again by what it shows)."""
    table.clearSelection()
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, text in enumerate(row):
            table.setItem(r, c, QTableWidgetItem("" if text is None else str(text)))


def selected_row(table):
    """Index of the selected row, or None."""
    rows = table.selectionModel().selectedRows()
    return rows[0].row() if rows else None


def text_label(text="", wrap=True):
    """Label that shows its text as plain text (names come from the device)."""
    lbl = QLabel(text)
    lbl.setTextFormat(Qt.TextFormat.PlainText)
    lbl.setWordWrap(wrap)
    return lbl


def button_row(buttons):
    """Horizontal row of (text, slot) buttons; returns (layout, {text: button})."""
    row = QHBoxLayout()
    made = {}
    for text, slot in buttons:
        b = QPushButton(text)
        b.clicked.connect(slot)
        row.addWidget(b)
        made[text] = b
    row.addStretch(1)
    return row, made


def forget_secrets(mgr):
    """Wipes what a manager object holds for its device (an OATH access key,
    a FIDO PIN token, a PIV management key: its lock() or forget(), which do
    not touch the device)."""
    wipe = getattr(mgr, "lock", None) or getattr(mgr, "forget", None)
    if wipe is not None:
        wipe()


class ManagerPage(QWidget):
    """Base of a page (optional: KeyManagerTab calls device_changed() and
    shown() when a page has them). A page reads the device in refresh() and
    sets self.loaded; manager() gives its manager object (made in the worker
    thread, anew for another Management). A manager that is dropped has its
    secrets wiped first."""

    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.T = ctx.T
        self.loaded = False
        self._mgr = None
        self._mgr_for = None

    def manager(self, factory):
        """The page's manager object, factory(Management) made once per card
        connection. Call it in the worker thread (fn of ctx.run)."""
        m = self.ctx.management()
        if self._mgr is None or self._mgr_for is not m:
            old = self._mgr
            self._mgr, self._mgr_for = factory(m), m
            if old is not None:
                forget_secrets(old)             # (in the worker: nothing else uses it now)
        return self._mgr

    def device_changed(self):
        old, self._mgr, self._mgr_for = self._mgr, None, None
        self.loaded = False
        self.clear()
        if old is not None:
            if self.ctx.busy():                 # an operation may still use it: once it ended
                self.ctx.when_idle(lambda: forget_secrets(old))
            else:
                forget_secrets(old)

    def shown(self):
        if not self.loaded and self.ctx.idle():
            self.auto_refresh()

    def auto_refresh(self):
        """Loading when the page is shown (not asked for): the page may skip
        what needs a secret."""
        self.refresh()

    def refresh(self):
        pass

    def clear(self):
        pass

    def showEvent(self, event):
        super().showEvent(event)
        self.ctx.sync()                         # (what was read may belong to another device)
        self.shown()


# ----------------------------------------------------------------------------
# Tab
# ----------------------------------------------------------------------------

class KeyManagerTab(QWidget):
    """The Key manager: one page per application (QTabWidget). window is the
    MainWindow, T its translation function (like gui_policy.SecurityTab).

    The main window calls show_info(info) after each of its refreshes (a
    device, profile or boot change, and after every operation that changes
    them), so the pages drop what they read at once. The tab also compares
    what its pages belong to with the window's device, profile, boot and
    connection (sync, no device access) when it is shown and every
    SYNC_INTERVAL ms while it is visible: that catches what does not pass
    through a refresh of the window (another reader chosen in its list, a
    connection an operation replaced before its refresh) and costs nothing
    while the tab is hidden."""

    PAGE_TITLES = ("Passkeys", "OATH", "OTP", "OpenPGP", "PIV")
    SYNC_INTERVAL = 300

    def __init__(self, window, T=None):
        super().__init__()
        from .gui_mgr_pages_a import OathPage, OtpPage, PasskeysPage
        from .gui_mgr_pages_b import OpenPgpPage, PivPage
        self.w = window
        self.ctx = ManagerContext(window, T, self)
        self.T = self.ctx.T
        self._identity = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.tabs = QTabWidget()
        self.pages = []
        for cls, title in zip((PasskeysPage, OathPage, OtpPage, OpenPgpPage, PivPage), self.PAGE_TITLES):
            page = cls(self.ctx)
            self.pages.append(page)
            self.tabs.addTab(page, self.T(title))
        lay.addWidget(self.tabs, 1)
        self._sync_timer = QTimer(self)
        self._sync_timer.setInterval(self.SYNC_INTERVAL)
        self._sync_timer.timeout.connect(self.sync)

    def title(self):
        return self.T("Key manager")

    def sync(self):
        """show_info with the main window's current state: the pages drop what
        they read when the device, profile, boot or connection changed."""
        self.show_info(self.w.info if self.w.mgmt is not None else None)

    def showEvent(self, event):
        super().showEvent(event)
        self.sync()
        self._sync_timer.start()

    def hideEvent(self, event):
        self._sync_timer.stop()
        super().hideEvent(event)

    def _identity_of(self, info):
        """What the pages' contents belong to: the device, its profile and its
        boot (after a restart a FIDO token or an OATH unlock is gone), and the
        card connection."""
        m = self.w.mgmt
        if info is None or m is None:
            return None
        card = getattr(m, "card", None)
        reader = self.w.reader_box.currentText() if hasattr(self.w, "reader_box") else None
        return (reader, info.get("chip_serial"), info.get("serial"), info.get("active"), id(m), id(card),
                getattr(card, "boot_id", None))

    def show_info(self, info):
        """After the main window refreshed (info None: no device): pages of
        another device, profile or boot drop what they read."""
        identity = self._identity_of(info)
        if identity == self._identity:
            return
        self._identity = identity
        for page in self.pages:
            if hasattr(page, "device_changed"):
                page.device_changed()
        page = self.tabs.currentWidget()
        if identity is not None and page is not None and page.isVisible() and hasattr(page, "shown"):
            page.shown()
