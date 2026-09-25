"""Pages of the Key manager tab (gui_manager): FIDO passkeys, OATH accounts
(live codes) and OTP slots of the active profile.

Each page works through its manager (mgr_fido, mgr_oath, mgr_otp), made in
the main window's worker thread and dropped when the device, profile or card
connection changes. A secret typed for an operation (PIN, password, key,
access code) goes into that operation's work function only: the worker drops
it when the operation ends, and the fields it was typed into are cleared."""

import base64
import binascii
import hashlib
import math
import os
import re
import time

from PySide6.QtCore import QMimeData, QTimer
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout,
    QInputDialog, QLabel, QLineEdit, QMessageBox, QProgressBar, QPushButton, QSpinBox, QTextEdit, QVBoxLayout,
)

from . import mgr_otp, stdformats
from .cli import COSE_ALGS, oath_keys_from_links, qr_links
from .gui_manager import (ManagerPage, ask_new_secret, edit_texts, fill_table, make_table, register_translations,
                          selected_row, text_label)
from .mgmt import display_name
from .mgr_common import AuthRequired, ManagerError, WrongSecret
from .mgr_fido import PIN_MAX_BYTES, PIN_MIN_CHARS, USER_FIELD_MAX, FidoManager, FidoPinRequired
from .mgr_oath import HOTP, TOTP, OathManager, build_name, parse_name
from .mgr_otp import OtpManager
from .policy import format_aaguid

ZH = {
    # common
    "Delete...": "删除…",
    "Rename...": "重命名…",
    "Cancel": "取消",
    "Show": "显示",
    "Generate random": "随机生成",
    "Copy": "复制",
    "Close": "关闭",
    "Select an entry first.": "请先选择一项。",
    "Another operation is running: try again once it has ended.": "另一项操作正在进行：请在它结束后重试。",
    # passkeys
    "passkeys-hint": "点击“刷新”列出当前环境的通行密钥（需要 FIDO PIN）。",
    "Site (RP ID)": "网站（RP ID）",
    "User name": "用户名",
    "Display name": "显示名称",
    "Details": "详情",
    "Edit user...": "编辑用户信息…",
    "Set PIN...": "设置 PIN…",
    "Change PIN...": "修改 PIN…",
    "FIDO PIN": "FIDO PIN",
    "FIDO PIN of the active profile:": "当前环境的 FIDO PIN：",
    "Current FIDO PIN:": "当前 FIDO PIN：",
    "Enter the FIDO PIN.": "请输入 FIDO PIN。",
    "fido-new-pin": "新的 FIDO PIN：至少 %d 个字符，最多 63 字节（UTF-8）。",
    "FIDO PIN set": "已设置 FIDO PIN",
    "No FIDO PIN": "未设置 FIDO PIN",
    "%d attempts left": "剩余 %d 次",
    "minimum length %d": "最短 %d 个字符",
    "room for %d more passkeys": "还可保存 %d 个通行密钥",
    "the PIN must be changed": "必须修改 PIN",
    "versions %s": "版本 %s",
    "Passkeys: %d": "通行密钥：%d 个",
    "fido-no-pin": "管理通行密钥需要 FIDO PIN，当前环境没有：请先点击“设置 PIN…”。",
    "fido-locked": "已锁定：点击“刷新”并输入 FIDO PIN 以列出通行密钥。",
    "fido-no-cm": "此固件不能管理通行密钥（不支持凭据管理）。",
    "credProtect %s": "凭据保护 %s",
    "large blob": "大数据块",
    "third-party payment": "第三方支付",
    "User name:": "用户名：",
    "Display name:": "显示名称：",
    "fido-delete": ("删除此通行密钥？\n\n网站 %s，用户 %s\n\n之后无法再用此密钥登录该网站（网站上保存的公钥请在网站上一并删除）。"
                    "此操作不可撤销。"),
    "Passkey deleted.": "通行密钥已删除。",
    "FIDO PIN set.": "FIDO PIN 已设置。",
    "FIDO PIN changed.": "FIDO PIN 已修改。",
    "Refresh first.": "请先点击“刷新”。",
    # OATH
    "oath-hint": "点击“刷新”列出 OATH 账户。",
    "Issuer": "发行方",
    "Account": "账户",
    "Code": "验证码",
    "Valid": "有效期",
    "Type": "类型",
    "Search:": "搜索：",
    "Copy code": "复制验证码",
    "Calculate": "计算",
    "Add account...": "添加账户…",
    "Set password...": "设置密码…",
    "Change password...": "修改密码…",
    "Remove password...": "删除密码…",
    "Reset OATH...": "重置 OATH…",
    "OATH password": "OATH 密码",
    "OATH password:": "OATH 密码：",
    "Enter the password.": "请输入密码。",
    "New OATH password:": "新的 OATH 密码：",
    "OATH accounts: %d": "OATH 账户：%d 个",
    "protected by a password": "受密码保护",
    "oath-locked": "OATH 应用受密码保护：点击“刷新”并输入密码。",
    "Codes are not updated: %s": "验证码未更新：%s",
    "%d s": "%d 秒",
    "touch": "需按键",
    "press Calculate": "请点击“计算”",
    "expired": "已过期",
    "Code of %s copied.": "已复制 %s 的验证码。",
    "%d digits": "%d 位",
    "Issuer:": "发行方：",
    "Account:": "账户：",
    "Enter the account name.": "请输入账户名。",
    "oath-colon": "发行方不能包含冒号（:）。",
    "oath-exists": "设备上已有名为 %s 的账户。",
    "oath-replace": "替换已有的账户？\n\n设备上已有名为 %s 的账户。它现有的密钥将被永久清除。",
    "oath-replace-n": "替换已有的账户？\n\n设备上已有这些账户：\n%s\n\n它们现有的密钥将被永久清除（选“否”则跳过它们）。",
    "oath-delete": "删除此 OATH 账户？\n\n%s\n\n它的密钥将被永久清除：除非你在别处还有该密钥，否则将无法再为该账户生成验证码。",
    "oath-reset": "重置 OATH 应用？\n\n全部 %d 个 OATH 账户及其密钥和 OATH 密码将被永久清除。",
    "oath-reset-unknown": ("重置 OATH 应用？\n\n设备上的所有 OATH 账户及其密钥和 OATH 密码将被永久清除。"
                           "无法显示账户数量：它们尚未列出（受 OATH 密码保护，或尚未读取）。"),
    "oath-reset-2": "确定要清除所有 OATH 账户吗？此操作不可撤销。",
    "oath-remove-password": "删除 OATH 密码？之后任何拿到此按键的人都能读取验证码。",
    "The OATH application has no password.": "OATH 应用没有设置密码。",
    "OATH password set.": "OATH 密码已设置。",
    "OATH password removed.": "OATH 密码已删除。",
    "OATH application reset.": "OATH 应用已重置。",
    "Account added: %s": "已添加账户：%s",
    "Accounts added: %d": "已添加账户：%d 个",
    # OATH add dialog
    "Add OATH account": "添加 OATH 账户",
    "otpauth:// link:": "otpauth:// 链接：",
    "QR image...": "二维码图片…",
    "Secret (base32):": "密钥（base32）：",
    "Type:": "类型：",
    "Algorithm:": "算法：",
    "Digits:": "位数：",
    "Period (s):": "周期（秒）：",
    "Counter:": "计数器：",
    "Require a touch": "需要按键确认",
    "The secret is not base32.": "密钥不是有效的 base32。",
    "Enter the secret.": "请输入密钥。",
    "Not a usable link: %s": "无法使用此链接：%s",
    "oath-several": "此链接/二维码包含 %d 个账户，将按原样添加：\n%s",
    "Images": "图片",
    "All files": "所有文件",
    # OTP
    "otp-hint": "点击“刷新”读取 OTP 槽位。",
    "Slot 1 (one press)": "槽位 1（按一下）",
    "Slot 2 (two presses)": "槽位 2（按两下）",
    "Programmed": "已配置",
    "Empty": "空",
    "Program...": "配置…",
    "Access code...": "访问码…",
    "Test challenge-response...": "测试挑战-响应…",
    "Export...": "导出…",
    "Swap slots...": "交换槽位…",
    "Yubico OTP": "Yubico OTP",
    "Challenge-response (HMAC-SHA1)": "挑战-响应（HMAC-SHA1）",
    "Challenge-response (Yubico)": "挑战-响应（Yubico）",
    "Static password": "静态密码",
    "OATH-HOTP": "OATH-HOTP",
    "public ID %s": "公共 ID %s",
    "Enter appended": "末尾回车",
    "types on a press": "按键时输入",
    "touch for each response": "每次响应需按键",
    "OTP application %s, serial %s": "OTP 应用 %s，序列号 %s",
    "OTP application %s": "OTP 应用 %s",
    "otp-overwrite": "槽位 %d 已有配置（%s）。\n\n重新配置会永久清除它现有的配置和密钥：由它生成的验证码或密码将不再有效。",
    "otp-delete": "删除槽位 %d 的配置（%s）？\n\n它的密钥将被永久清除：由它生成的验证码或密码将不再有效。",
    "otp-swap": "交换槽位 1 和槽位 2 的配置？\n\n按一下和按两下时输出的内容会互换。",
    "OTP access code": "OTP 访问码",
    "otp-access-code": "槽位受访问码保护。访问码（12 位十六进制）：",
    "Slot %d programmed.": "槽位 %d 已配置。",
    "Slot %d deleted.": "槽位 %d 已删除。",
    "Slots swapped.": "槽位已交换。",
    "Access code of slot %d changed.": "槽位 %d 的访问码已更改。",
    "Challenge (hex; empty: a random one):": "挑战（十六进制；留空则随机生成）：",
    "The challenge is not hexadecimal (at most 64 bytes).": "挑战不是有效的十六进制（最多 64 字节）。",
    "Challenge: %s\nResponse: %s": "挑战：%s\n响应：%s",
    "Program slot %d: %s": "配置槽位 %d：%s",
    "Public ID (modhex):": "公共 ID（modhex）：",
    "Private ID (hex):": "私有 ID（十六进制）：",
    "Secret key (hex):": "密钥（十六进制）：",
    "HMAC key (hex, up to 20 bytes):": "HMAC 密钥（十六进制，最多 20 字节）：",
    "Password:": "密码：",
    "Keyboard layout:": "键盘布局：",
    "US English": "美式英语",
    "modhex letters only (any Latin layout)": "仅 modhex 字母（适用于各种拉丁字母键盘布局）",
    "Secret (base32):": "密钥（base32）：",
    "Initial counter (multiple of 16):": "初始计数器（16 的倍数）：",
    "Append Enter": "末尾追加回车",
    "Show secrets": "显示密钥",
    "Current access code (hex, if the slot has one):": "当前访问码（十六进制，如有）：",
    "New access code (hex, empty: none):": "新访问码（十六进制，留空则不设）：",
    "Repeat the new access code:": "再次输入新访问码：",
    "The two new access codes differ.": "两次输入的新访问码不一致。",
    "Access code of slot %d": "槽位 %d 的访问码",
    "Yubico OTP credential": "Yubico OTP 凭据",
    "otp-summary": ("以下内容包含密钥：请把它上传到你的验证服务器（例如 YubiCloud），然后关闭此窗口。"
                    "本工具不会保存它，也无法再次显示；“复制”会把它放到剪贴板上，直到关闭此窗口"
                    "（并要求剪贴板历史不要保留它）。"),
    "Slot": "槽位",
    "Public ID": "公共 ID",
    "Private ID": "私有 ID",
    "Secret key": "密钥",
    "Serial": "序列号",
    "CSV (YubiCloud upload)": "CSV（YubiCloud 上传格式）",
    "unknown": "未知",
}

EN = {
    "passkeys-hint": "Refresh lists the passkeys of the active profile (the FIDO PIN is needed).",
    "fido-new-pin": "New FIDO PIN: at least %d characters, at most 63 bytes (UTF-8).",
    "fido-no-pin": "Managing passkeys needs a FIDO PIN and this profile has none: Set PIN... first.",
    "fido-locked": "Locked: Refresh asks for the FIDO PIN and lists the passkeys.",
    "fido-no-cm": "This firmware cannot manage passkeys (no credential management).",
    "fido-delete": "Delete this passkey?\n\nSite %s, user %s\n\nYou can no longer sign in to that site with this key "
                   "(remove its public key on the site as well). This cannot be undone.",
    "oath-hint": "Refresh lists the OATH accounts.",
    "oath-locked": "The OATH application is protected by a password: Refresh asks for it.",
    "oath-colon": "The issuer cannot contain a colon (:).",
    "oath-exists": "An account named %s is already on the device.",
    "oath-replace": "Replace an account?\n\nAn account named %s is already on the device. Its current secret is "
                    "erased for good.",
    "oath-replace-n": "Replace accounts?\n\nThese accounts are already on the device:\n%s\n\nTheir current secrets "
                      "are erased for good (No: they are left out).",
    "oath-delete": "Delete this OATH account?\n\n%s\n\nIts secret is erased for good: unless you have it elsewhere, "
                   "no more codes can be made for that account.",
    "oath-reset": "Reset the OATH application?\n\nAll %d OATH accounts with their secrets, and the OATH password, "
                  "are erased for good.",
    "oath-reset-unknown": "Reset the OATH application?\n\nEvery OATH account on the device with its secret, and the "
                          "OATH password, is erased for good. How many accounts that is cannot be shown: they were "
                          "not listed (the OATH password protects them, or they were not read yet).",
    "oath-reset-2": "Really erase every OATH account? This cannot be undone.",
    "oath-remove-password": "Remove the OATH password? Anyone who has the key can then read its codes.",
    "oath-several": "The link or QR code holds %d accounts; they are added as they are:\n%s",
    "otp-hint": "Refresh reads the OTP slots.",
    "otp-overwrite": "Slot %d is programmed (%s).\n\nProgramming it again erases its configuration and secret for "
                     "good: codes or passwords it produced no longer work.",
    "otp-delete": "Delete the configuration of slot %d (%s)?\n\nIts secret is erased for good: codes or passwords "
                  "it produced no longer work.",
    "otp-swap": "Swap the configurations of slots 1 and 2?\n\nWhat one press and two presses type is exchanged.",
    "otp-access-code": "The slot is protected by an access code. Access code (12 hexadecimal digits):",
    "otp-summary": "This holds the secret key: upload it to your validation server (YubiCloud, for example), then "
                   "close this window. This tool does not keep it and cannot show it again; Copy puts it on the "
                   "clipboard until this window closes (clipboard history is asked not to keep it).",
}

register_translations(ZH, EN)


def _text(value):
    """A text from the device (str or bytes), safe to show."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    return display_name(value) if isinstance(value, str) else ("" if value is None else str(value))


def _b32decode(text):
    """bytes of base32 text (spaces, dashes and padding ignored); ValueError."""
    s = re.sub(r"[\s-]", "", text).upper().rstrip("=")
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8))
    except (binascii.Error, ValueError):
        raise ValueError("not base32") from None


def _secret_field(placeholder=""):
    field = QLineEdit()
    field.setEchoMode(QLineEdit.EchoMode.Password)
    field.setPlaceholderText(placeholder)
    return field


def _copy(text):
    QApplication.clipboard().setText(text)


# Clipboard formats that ask clipboard managers to keep no copy of a secret:
# Windows clipboard history and cloud clipboard (clipboard formats registered
# by name), KDE Klipper.
_NOT_KEPT = (('application/x-qt-windows-mime;value="ExcludeClipboardContentFromMonitorProcessing"', b"\x00"),
             ('application/x-qt-windows-mime;value="CanIncludeInClipboardHistory"', bytes(4)),
             ('application/x-qt-windows-mime;value="CanUploadToCloudClipboard"', bytes(4)),
             ("x-kde-passwordManagerHint", b"secret"))


def _copy_secret(text):
    """Puts a secret on the clipboard, marked for clipboard managers as not
    to be kept; returns what identifies it there (see _uncopy_secret)."""
    mime = QMimeData()
    mime.setText(text)
    for fmt, value in _NOT_KEPT:
        mime.setData(fmt, value)
    QApplication.clipboard().setMimeData(mime)
    return hashlib.sha256(text.encode("utf-8")).digest()


def _uncopy_secret(digest):
    """Clears the clipboard if it still holds the secret _copy_secret put
    there (digest), not when something else was copied since."""
    clipboard = QApplication.clipboard()
    if digest is not None and hashlib.sha256(clipboard.text().encode("utf-8")).digest() == digest:
        clipboard.clear()


# ----------------------------------------------------------------------------
# FIDO passkeys
# ----------------------------------------------------------------------------

class PasskeysPage(ManagerPage):
    """The passkeys (discoverable credentials) of the active profile: list
    (FIDO PIN), edit the user names, delete, export / import (the Keys tab's
    key files), set or change the FIDO PIN. The PIN is asked for when the
    manager holds no token (FidoPinRequired) and is never kept."""

    APP = "fido"

    def __init__(self, ctx):
        super().__init__(ctx)
        T = self.T
        self.fido_info = None
        self.creds = []
        lay = QVBoxLayout(self)
        top = QHBoxLayout()
        self.state = text_label(T("passkeys-hint"))
        top.addWidget(self.state, 1)
        self.refresh_btn = QPushButton(T("Refresh"))
        self.refresh_btn.clicked.connect(self.refresh)
        top.addWidget(self.refresh_btn)
        lay.addLayout(top)
        self.summary = text_label("")
        lay.addWidget(self.summary)
        self.table = make_table([T("Site (RP ID)"), T("User name"), T("Display name"), T("Details")])
        self.table.itemSelectionChanged.connect(self._update_buttons)
        lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.edit_btn = QPushButton(T("Edit user..."))
        self.delete_btn = QPushButton(T("Delete..."))
        self.export_btn = QPushButton(T("Export selected..."))
        self.import_btn = QPushButton(T("Import..."))
        self.pin_btn = QPushButton(T("Set PIN..."))
        for b, slot in ((self.edit_btn, self.edit_user), (self.delete_btn, self.delete),
                        (self.export_btn, self.export), (self.import_btn, self.import_keys)):
            b.clicked.connect(slot)
            row.addWidget(b)
        row.addStretch(1)
        self.pin_btn.clicked.connect(self.change_pin)
        row.addWidget(self.pin_btn)
        lay.addLayout(row)
        self._update_buttons()

    # -- state -----------------------------------------------------------------
    def clear(self):
        self.fido_info, self.creds = None, []
        fill_table(self.table, [])
        self.summary.setText("")
        self.state.setText(self.T("passkeys-hint"))
        self.pin_btn.setText(self.T("Set PIN..."))
        self._update_buttons()

    def _update_buttons(self):
        selected = self._selected() is not None
        for b in (self.edit_btn, self.delete_btn, self.export_btn):
            b.setEnabled(selected)

    def _selected(self):
        r = selected_row(self.table)
        return self.creds[r] if r is not None and r < len(self.creds) else None

    def _locked(self):
        self.state.setText(self.T("fido-locked"))

    # -- device work -----------------------------------------------------------
    def _run_unlocked(self, op, then):
        """Runs op(manager) in the worker. When the manager holds no PIN token
        (FidoPinRequired) the FIDO PIN is asked for, the manager unlocked and
        op run again; after a wrong PIN it is asked for again (with the tries
        left)."""
        def work(pin=None):
            mgr = self.manager(FidoManager)
            if pin is not None:
                mgr.unlock(pin)
            return op(mgr)

        def ask(note):
            pin = self._ask_pin(note)
            if pin is None:
                self._locked()
                return True
            self.ctx.run(lambda: work(pin), then, retry)
            return True

        def first(e):
            return isinstance(e, FidoPinRequired) and ask(None)

        def retry(e):
            if isinstance(e, WrongSecret):
                return ask(self.ctx.error_text(e))
            return False
        return self.ctx.run(work, then, first)

    def _ask_pin(self, note=None):
        T = self.T
        label = T("FIDO PIN of the active profile:")
        if note:
            label = note + "\n\n" + label
        pin = self.ctx.ask_secret(T("FIDO PIN"), label)
        if pin is None:
            return None
        if not pin:
            self.ctx.error(T("Enter the FIDO PIN."))
            return None
        return pin

    @staticmethod
    def _read(mgr, listing=True):
        """(info, passkeys or None) in the worker: None without a PIN on the
        profile, without credential management, or (listing False) without a
        token."""
        info = mgr.info()
        if not info.get("pin_set") or info.get("cred_mgmt") is False:
            return info, None
        if not listing and not info.get("unlocked", True):
            return info, None
        try:
            return info, mgr.list_credentials()
        except FidoPinRequired:
            if listing:
                raise
            return info, None

    def refresh(self):
        self._run_unlocked(lambda mgr: self._read(mgr), self._loaded)

    def auto_refresh(self):
        # (shown, not asked for: no PIN prompt; the passkeys when a token is held)
        self.ctx.run(lambda: self._read(self.manager(FidoManager), listing=False), self._loaded)

    def _loaded(self, result):
        T = self.T
        info, creds = result
        before = self._selected()
        self.fido_info = info
        self.loaded = True
        self._show_summary(info)
        self.creds = list(creds or [])
        fill_table(self.table, [self._row(c) for c in self.creds])
        ids = [c["credential_id"] for c in self.creds]
        if before is not None and before["credential_id"] in ids:
            self.table.selectRow(ids.index(before["credential_id"]))
        if creds is not None:
            self.state.setText(T("Passkeys: %d") % len(self.creds))
        elif info.get("cred_mgmt") is False:
            self.state.setText(T("fido-no-cm"))
        elif not info.get("pin_set"):
            self.state.setText(T("fido-no-pin"))
        else:
            self._locked()
        self._update_buttons()

    def _show_summary(self, info):
        T = self.T
        parts = []
        if info.get("pin_set"):
            text = T("FIDO PIN set")
            if info.get("pin_retries") is not None:
                text += T(" (%s)") % (T("%d attempts left") % info["pin_retries"])
            parts.append(text)
        else:
            parts.append(T("No FIDO PIN"))
        if info.get("force_pin_change"):
            parts.append(T("the PIN must be changed"))
        if info.get("min_pin_length"):
            parts.append(T("minimum length %d") % info["min_pin_length"])
        if info.get("remaining_rk") is not None:
            parts.append(T("room for %d more passkeys") % info["remaining_rk"])
        if info.get("aaguid"):
            parts.append("AAGUID " + format_aaguid(info["aaguid"]))
        if info.get("versions"):
            parts.append(T("versions %s") % ", ".join(_text(v) for v in info["versions"]))
        self.summary.setText(T("; ").join(parts))
        self.pin_btn.setText(T("Change PIN...") if info.get("pin_set") else T("Set PIN..."))

    def _row(self, c):
        T = self.T
        details = []
        alg = c.get("public_key_alg")
        if alg is not None:
            details.append(COSE_ALGS.get(alg, "alg %s" % alg))
        if c.get("cred_protect"):
            details.append(T("credProtect %s") % c["cred_protect"])
        if c.get("large_blob_key"):
            details.append(T("large blob"))
        if c.get("third_party_payment"):
            details.append(T("third-party payment"))
        return (_text(c.get("rp_id")), _text(c.get("user_name")), _text(c.get("display_name")), T(", ").join(details))

    # -- actions ---------------------------------------------------------------
    def edit_user(self):
        T = self.T
        c = self._selected()
        if c is None:
            self.ctx.error(T("Select an entry first."))
            return
        values = edit_texts(self.ctx, T("Edit user..."), [(T("User name:"), c.get("user_name") or ""),
                                                           (T("Display name:"), c.get("display_name") or "")])
        if values is None:
            return
        name, shown = values
        for v in (name, shown):
            if len(v.encode("utf-8")) > USER_FIELD_MAX:
                self.ctx.error(T("At most %d bytes (UTF-8).") % USER_FIELD_MAX)
                return
        cid, uid = c["credential_id"], c["user_id"]

        def op(mgr):
            mgr.update_user(cid, uid, name, shown)
            return self._read(mgr)
        self._run_unlocked(op, self._loaded)

    def delete(self):
        T = self.T
        c = self._selected()
        if c is None:
            self.ctx.error(T("Select an entry first."))
            return
        user = _text(c.get("user_name") or c.get("display_name")) or c["user_id"].hex()
        if not self.ctx.confirm(T("fido-delete") % (_text(c.get("rp_id")), user), danger=True):
            return
        cid = c["credential_id"]

        def op(mgr):
            mgr.delete_credential(cid)
            return self._read(mgr)

        def done(r):
            self._loaded(r)
            self.ctx.info(T("Passkey deleted."))
        self._run_unlocked(op, done)

    def change_pin(self):
        T = self.T
        info = self.fido_info
        if info is None:
            self.ctx.error(T("Refresh first."))
            return
        minimum = max(PIN_MIN_CHARS, info.get("min_pin_length") or PIN_MIN_CHARS)
        old = None
        if info.get("pin_set"):
            old = self.ctx.ask_secret(T("Change PIN..."), T("Current FIDO PIN:"))
            if old is None:
                return
            if not old:
                self.ctx.error(T("Enter the FIDO PIN."))
                return
        new = ask_new_secret(self.ctx, T("Change PIN...") if old else T("Set PIN..."), T("fido-new-pin") % minimum,
                             min_len=minimum, max_bytes=PIN_MAX_BYTES)
        if new is None:
            return

        def work():
            mgr = self.manager(FidoManager)
            if old is None:
                mgr.set_pin(new)
            else:
                mgr.change_pin(old, new)
            try:
                mgr.unlock(new)                 # (the device ended the token: list with the new PIN)
            except ManagerError:
                pass                            # the PIN is changed; the list says it is locked
            return self._read(mgr, listing=False)

        def done(r):
            self._loaded(r)
            self.ctx.info(T("FIDO PIN changed.") if old else T("FIDO PIN set."))
        self.ctx.run(work, done)

    def export(self):
        c = self._selected()
        if c is None:
            self.ctx.error(self.T("Select an entry first."))
            return
        self.ctx.export_selected("fido", c["credential_id"], label=_text(c.get("rp_id")))

    def import_keys(self):
        self.ctx.import_file(then=self.auto_refresh)


# ----------------------------------------------------------------------------
# OATH
# ----------------------------------------------------------------------------

class OathAddDialog(QDialog):
    """A new OATH account: typed, from an otpauth:// (or Google Authenticator
    otpauth-migration://) link, or from a QR code image (decoded in the
    worker). get() returns ("fields", keyword arguments of OathManager.add)
    or ("records", [OATH records]) for a link with several accounts, or None.
    While an image is decoded the dialog cannot be accepted (the worker is
    taken: the account could not be added); a result that comes after the
    dialog closed is dropped."""

    def __init__(self, page):
        super().__init__(page)
        self.page = page
        self.ctx = page.ctx
        T = self.T = page.T
        self.records = None
        self.value = None
        self.decoding = False           # a QR image is decoded in the worker
        self.closed = False             # get() is over (the widgets may be gone)
        self.setWindowTitle(T("Add OATH account"))
        self.setMinimumWidth(460)
        form = QFormLayout(self)
        link_row = QHBoxLayout()
        self.link = _secret_field("otpauth://...")      # the link holds the secret
        self.link.textChanged.connect(self._link_changed)
        link_row.addWidget(self.link, 1)
        self.qr_btn = QPushButton(T("QR image..."))
        self.qr_btn.clicked.connect(self._open_qr)
        link_row.addWidget(self.qr_btn)
        form.addRow(T("otpauth:// link:"), link_row)
        self.note = text_label("")
        form.addRow(self.note)
        self.issuer, self.account = QLineEdit(), QLineEdit()
        form.addRow(T("Issuer:"), self.issuer)
        form.addRow(T("Account:"), self.account)
        secret_row = QHBoxLayout()
        self.secret = _secret_field("base32")
        secret_row.addWidget(self.secret, 1)
        self.show_secret = QCheckBox(T("Show"))
        self.show_secret.toggled.connect(lambda on: self.secret.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        secret_row.addWidget(self.show_secret)
        form.addRow(T("Secret (base32):"), secret_row)
        self.kind = QComboBox()
        self.kind.addItem("TOTP", "totp")
        self.kind.addItem("HOTP", "hotp")
        self.kind.currentIndexChanged.connect(self._kind_changed)
        form.addRow(T("Type:"), self.kind)
        self.algorithm = QComboBox()
        for name in stdformats.OATH_ALGORITHMS:
            self.algorithm.addItem(name, name)
        form.addRow(T("Algorithm:"), self.algorithm)
        self.digits = QSpinBox()
        self.digits.setRange(6, 8)
        self.digits.setValue(6)
        form.addRow(T("Digits:"), self.digits)
        self.period = QSpinBox()
        self.period.setRange(1, 3600)
        self.period.setValue(stdformats.DEFAULT_PERIOD)
        form.addRow(T("Period (s):"), self.period)
        self.counter = QSpinBox()
        self.counter.setRange(0, 2 ** 31 - 1)
        form.addRow(T("Counter:"), self.counter)
        self.touch = QCheckBox(T("Require a touch"))
        form.addRow(self.touch)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.ok_btn = buttons.button(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)
        self._kind_changed()

    def _fields(self):
        return (self.issuer, self.account, self.secret, self.show_secret, self.kind, self.algorithm, self.digits,
                self.period, self.counter, self.touch)

    def _kind_changed(self, *_):
        totp = self.kind.currentData() == "totp"
        manual = self.records is None
        self.period.setEnabled(manual and totp)
        self.counter.setEnabled(manual and not totp)

    def _set_manual(self, on):
        for w in self._fields():
            w.setEnabled(on)
        self._kind_changed()

    # -- links and QR codes ----------------------------------------------------
    def _link_changed(self, text):
        self.records = None
        self._set_manual(True)
        if not text.strip():
            self.note.setText("")
            return
        try:
            keys, left_out, missing = oath_keys_from_links([text])
        except stdformats.FormatError as e:
            self.note.setText(self.T("Not a usable link: %s") % e)
            return
        self._use([k.record for k in keys], left_out, missing)

    def _open_qr(self):
        T = self.T
        path, _ = QFileDialog.getOpenFileName(self, T("QR image..."), "", "%s (*.png *.jpg *.jpeg *.gif *.bmp *.webp);;"
                                              "%s (*)" % (T("Images"), T("All files")))
        if not path:
            return
        self._set_decoding(True)
        if not self.ctx.run(lambda: qr_links(path), self._qr_read, self._qr_failed):
            self._set_decoding(False)
            if self.ctx.busy():                 # (without a device the main window said so)
                self._warn(T("Another operation is running: try again once it has ended."))

    def _set_decoding(self, on):
        self.decoding = on
        for w in (self.ok_btn, self.qr_btn, self.link):
            w.setEnabled(not on)

    def _qr_failed(self, e):
        if not self.closed:
            self._set_decoding(False)
        return False                            # (shown like any failure)

    def _qr_read(self, result):
        if self.closed:                         # cancelled meanwhile: nothing to fill
            return
        self._set_decoding(False)
        links, others = result
        try:
            keys, left_out, missing = oath_keys_from_links(links)
        except stdformats.FormatError as e:
            self.ctx.error(str(e))
            return
        self.link.blockSignals(True)
        self.link.clear()
        self.link.blockSignals(False)
        notes = [] if not others else [self.ctx.T("others-qr") % others]
        self._use([k.record for k in keys], left_out, missing, notes)

    def _use(self, records, left_out=(), missing=None, notes=()):
        T = self.T
        notes = list(notes) + [T("left-out") % why for why in left_out]
        notes += [T("missing-qr") % ", ".join(map(str, n)) for n in (missing or {}).values()]
        rec = records[0]
        if len(records) == 1 and rec.get(5, 0) <= self.counter.maximum():
            kind = rec[2] & 0xF0
            totp = kind == TOTP
            issuer, account, period = parse_name(rec[1], kind)
            self.issuer.setText(issuer or "")
            self.account.setText(account)
            self.secret.setText(base64.b32encode(rec[4]).decode("ascii").rstrip("="))
            self.kind.setCurrentIndex(0 if totp else 1)
            self.algorithm.setCurrentText(stdformats.OATH_ALGORITHM_NAMES.get(rec[2] & 0x0F, "SHA1"))
            self.digits.setValue(rec[3])
            self.period.setValue(period if totp else stdformats.DEFAULT_PERIOD)
            self.counter.setValue(rec.get(5, 0))
            self.touch.setChecked(bool(rec.get(6)))
            self.records = None
            self._set_manual(True)
        else:
            self.records = list(records)
            for field in (self.secret, self.issuer, self.account):
                field.clear()
            self._set_manual(False)
            notes.insert(0, T("oath-several") % (len(records), "\n".join(
                _text(r[1]) for r in records)))
        self.note.setText("\n".join(notes))

    # -- result ----------------------------------------------------------------
    def _warn(self, text):
        QMessageBox.warning(self, self.windowTitle(), text)

    def _accept(self):
        T = self.T
        if self.decoding:                       # (OK is disabled meanwhile; Enter too)
            return
        if self.records:
            self.value = ("records", self.records)
            self.accept()
            return
        issuer, account = self.issuer.text().strip(), self.account.text().strip()
        totp = self.kind.currentData() == "totp"
        if not account:
            self._warn(T("Enter the account name."))
            return
        if ":" in issuer:
            self._warn(T("oath-colon"))
            return
        if not self.secret.text().strip():
            self._warn(T("Enter the secret."))
            return
        try:
            secret = _b32decode(self.secret.text())
        except ValueError:
            self._warn(T("The secret is not base32."))
            return
        if not secret:
            self._warn(T("Enter the secret."))
            return
        period = self.period.value() if totp else stdformats.DEFAULT_PERIOD
        try:
            build_name(issuer or None, account, TOTP if totp else HOTP, period)     # (stored so it reads back)
        except ManagerError as e:
            self._warn(self.ctx.error_text(e))
            return
        self.value = ("fields", {
            "issuer": issuer or None, "account": account, "secret": secret, "type": "totp" if totp else "hotp",
            "algorithm": self.algorithm.currentData(), "digits": self.digits.value(), "period": period,
            "counter": 0 if totp else self.counter.value(), "touch": self.touch.isChecked()})
        self.accept()

    @classmethod
    def get(cls, page):
        dlg = cls(page)
        try:
            dlg.exec()
            return dlg.value
        finally:
            dlg.closed = True
            dlg.value = dlg.records = None
            for field in (dlg.secret, dlg.link):
                field.clear()
            dlg.deleteLater()


class OathPage(ManagerPage):
    """The OATH accounts with their codes, recalculated when they expire
    while the page is shown (a one-second countdown; clock is replaceable for
    tests). Touch and HOTP accounts are calculated on demand. Add (typed,
    otpauth link, QR code), rename, delete, password, reset, export / import
    (the Keys tab's key files).

    The recalculation is the page's own operation in the main window's
    worker: it does not start under a dialog, and an action of the user that
    finds the worker taken by it starts as soon as it ended."""

    APP = "oath"
    PERIOD = stdformats.DEFAULT_PERIOD

    def __init__(self, ctx, clock=time.time):
        super().__init__(ctx)
        T = self.T
        self.clock = clock
        self.status = None
        self.accounts = []              # OathManager.list() of the device
        self.listed = False             # accounts is what the device holds (listed, not locked)
        self.codes = {}                 # raw name -> (code, valid until (None: HOTP, no expiry))
        self.rows = []                  # accounts of the table rows (filtered)
        self.live = False               # expired codes are recalculated
        self.stale = False              # a code of calculate_all expired: calculate again
        self.pending = False            # a recalculation runs
        self.generation = 0             # counts clear(): an action waiting for the worker belongs to one
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.tick)
        lay = QVBoxLayout(self)
        top = QHBoxLayout()
        self.state = text_label(T("oath-hint"))
        top.addWidget(self.state, 1)
        self.refresh_btn = QPushButton(T("Refresh"))
        self.refresh_btn.clicked.connect(self.refresh)
        top.addWidget(self.refresh_btn)
        lay.addLayout(top)
        frow = QHBoxLayout()
        frow.addWidget(QLabel(T("Search:")))
        self.filter = QLineEdit()
        self.filter.textChanged.connect(self._fill)
        frow.addWidget(self.filter, 1)
        self.countdown = QProgressBar()
        self.countdown.setRange(0, self.PERIOD)
        self.countdown.setTextVisible(True)
        self.countdown.setMaximumWidth(160)
        frow.addWidget(self.countdown)
        lay.addLayout(frow)
        self.table = make_table([T("Issuer"), T("Account"), T("Code"), T("Valid"), T("Type")])
        self.code_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self.code_font.setBold(True)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.table.cellDoubleClicked.connect(lambda r, c: self.copy_code())
        lay.addWidget(self.table, 1)
        row1 = QHBoxLayout()
        self.copy_btn = QPushButton(T("Copy code"))
        self.calc_btn = QPushButton(T("Calculate"))
        self.add_btn = QPushButton(T("Add account..."))
        self.rename_btn = QPushButton(T("Rename..."))
        self.delete_btn = QPushButton(T("Delete..."))
        self.export_btn = QPushButton(T("Export selected..."))
        self.import_btn = QPushButton(T("Import..."))
        for b, slot in ((self.copy_btn, self.copy_code), (self.calc_btn, lambda: self.calculate()),
                        (self.add_btn, self.add_account), (self.rename_btn, self.rename),
                        (self.delete_btn, self.delete), (self.export_btn, self.export),
                        (self.import_btn, self.import_keys)):
            b.clicked.connect(slot)
            row1.addWidget(b)
        row1.addStretch(1)
        lay.addLayout(row1)
        row2 = QHBoxLayout()
        self.password_btn = QPushButton(T("Set password..."))
        self.remove_password_btn = QPushButton(T("Remove password..."))
        self.reset_btn = QPushButton(T("Reset OATH..."))
        for b, slot in ((self.password_btn, self.set_password), (self.remove_password_btn, self.remove_password),
                        (self.reset_btn, self.reset)):
            b.clicked.connect(slot)
            row2.addWidget(b)
        row2.addStretch(1)
        lay.addLayout(row2)
        self._update_countdown(self.clock())
        self._update_buttons()

    # -- visibility: the codes are kept up to date only while shown -------------
    def showEvent(self, event):
        super().showEvent(event)
        self.timer.start()
        self.tick()

    def hideEvent(self, event):
        self.timer.stop()
        super().hideEvent(event)

    # -- state -----------------------------------------------------------------
    def clear(self):
        self.status, self.accounts, self.codes, self.rows = None, [], {}, []
        self.live = self.pending = self.stale = self.listed = False
        self.generation += 1
        fill_table(self.table, [])
        self.state.setText(self.T("oath-hint"))
        self._update_buttons()

    def _update_buttons(self):
        acc = self._selected()
        for b in (self.copy_btn, self.calc_btn, self.rename_btn, self.delete_btn, self.export_btn):
            b.setEnabled(acc is not None)
        st = self.status or {}
        self.password_btn.setText(self.T("Change password...") if st.get("password_set") else
                                  self.T("Set password..."))
        self.remove_password_btn.setEnabled(bool(st.get("password_set")))

    def _selected(self):
        r = selected_row(self.table)
        return self.rows[r] if r is not None and r < len(self.rows) else None

    def _label(self, acc):
        issuer, account = _text(acc.get("issuer")), _text(acc.get("account") or acc.get("name"))
        return "%s (%s)" % (account, issuer) if issuer else account

    @staticmethod
    def _totp(acc):
        return acc.get("type", "totp") == "totp"

    def _valid_until(self, acc, ts):
        if not self._totp(acc):
            return None
        period = acc.get("period") or self.PERIOD
        return (int(ts) // period + 1) * period

    # -- device work -----------------------------------------------------------
    def _start(self, start):
        """start() begins an operation of the user (ctx.run, export_selected,
        import_file: whether it started). While the page's own recalculation
        of the codes holds the worker, it begins as soon as that ended (on the
        same device) instead of not at all; while another operation runs,
        that is said."""
        if start():
            return True
        if not self.ctx.busy():
            return False                        # no device (the main window said so)
        if not self.pending:
            self.ctx.error(self.T("Another operation is running: try again once it has ended."))
            return False
        generation = self.generation

        def later():
            if self.generation == generation:
                start()
        self.ctx.when_idle(later)
        return True

    def _run_auth(self, op, then, touch=False):
        """Runs op(manager) in the worker. When the OATH application wants its
        password (AuthRequired), it is asked for, the manager unlocked and op
        run again; after a wrong one it is asked for again."""
        def work(password=None):
            mgr = self.manager(OathManager)
            if password is not None:
                mgr.unlock(password)
            return op(mgr)

        def ask(note):
            password = self._ask_password(note)
            if password is None:
                self.state.setText(self.T("oath-locked"))
                return True
            self._start(lambda: self.ctx.run(lambda: work(password), then, retry, touch=touch))
            return True

        def first(e):
            return isinstance(e, AuthRequired) and ask(None)

        def retry(e):
            if isinstance(e, WrongSecret):
                return ask(self.ctx.error_text(e))
            return False
        return self._start(lambda: self.ctx.run(work, then, first, touch=touch))

    def _ask_password(self, note=None):
        T = self.T
        label = T("OATH password:") if not note else note + "\n\n" + T("OATH password:")
        password = self.ctx.ask_secret(T("OATH password"), label)
        if password is None:
            return None
        if not password:
            self.ctx.error(T("Enter the password."))
            return None
        return password

    def _read(self, mgr, ts, ask=True):
        """(status, accounts or None (locked), codes, ts) in the worker."""
        st = mgr.status()
        if st.get("locked"):
            if ask:
                raise AuthRequired("OATH: the password is needed", None, "OATH：需要密码")
            return st, None, {}, ts
        accounts = mgr.list()
        codes = mgr.calculate_all(ts) if accounts else {}
        return st, accounts, codes, ts

    def refresh(self):
        ts = int(self.clock())
        self._run_auth(lambda mgr: self._read(mgr, ts), self._loaded)

    def auto_refresh(self):
        ts = int(self.clock())
        self.ctx.run(lambda: self._read(self.manager(OathManager), ts, ask=False), self._loaded)

    def _loaded(self, result):
        T = self.T
        st, accounts, codes, ts = result
        self.status = st
        self.loaded = True
        self.codes = {}
        self.pending = self.stale = False
        self.listed = accounts is not None
        if accounts is None:
            self.accounts, self.live = [], False
            self.state.setText(T("oath-locked"))
        else:
            self.accounts = list(accounts)
            self._set_codes(codes, ts)
            self.live = True
            text = T("OATH accounts: %d") % len(self.accounts)
            if st.get("password_set"):
                text += T("; ") + T("protected by a password")
            self.state.setText(text)
        self._fill()

    def _set_codes(self, codes, ts):
        for acc in self.accounts:
            code = (codes or {}).get(acc["raw"])
            if code is not None:
                self.codes[acc["raw"]] = (code, self._valid_until(acc, ts))

    def _recalculate(self, now):
        ts = int(now)
        self.pending = True

        def done(codes):
            self.pending = self.stale = False
            self._set_codes(codes, ts)
            self._show_codes(self.clock())

        def failed(e):
            self.pending = self.stale = False
            self.live = False
            if isinstance(e, AuthRequired):
                self.state.setText(self.T("oath-locked"))
            else:
                self.state.setText(self.T("Codes are not updated: %s") % self.ctx.error_text(e))
            self._show_codes(self.clock())
            return True
        # quiet: no "Working..." banner every 30 s (failed() says what went wrong)
        if not self.ctx.run(lambda: self.manager(OathManager).calculate_all(ts), done, failed, quiet=True):
            self.pending = False

    # -- display ---------------------------------------------------------------
    def tick(self):
        """Every second while shown: the countdown, expired codes dropped, and
        a new calculation once a code that calculate_all gives expired (as
        soon as no other operation runs and no dialog is open: what the user
        confirms there must find the worker free)."""
        now = self.clock()
        self._update_countdown(now)
        expired = [raw for raw, (_, until) in self.codes.items() if until is not None and until <= now]
        auto = {a["raw"] for a in self.accounts if self._totp(a) and not a.get("touch")}
        for raw in expired:
            del self.codes[raw]
            if raw in auto:
                self.stale = True
        self._show_codes(now)
        if self.stale and self.live and not self.pending and self.ctx.idle() and \
                QApplication.activeModalWidget() is None:
            self._recalculate(now)

    def _update_countdown(self, now):
        left = int(math.ceil(self.PERIOD - now % self.PERIOD))
        self.countdown.setValue(left)
        self.countdown.setFormat(self.T("%d s") % left)

    def _fill(self, *_):
        T = self.T
        selected = self._selected()
        selected = selected["raw"] if selected is not None else None
        text = self.filter.text().strip().lower()
        self.rows = [a for a in self.accounts
                     if not text or text in _text(a.get("issuer")).lower() or
                     text in _text(a.get("account") or a.get("name")).lower()]
        rows = []
        for a in self.rows:
            kind = [T("%d digits") % a.get("digits", 6)]
            if self._totp(a) and (a.get("period") or self.PERIOD) != self.PERIOD:
                kind.append(T("%d s") % a["period"])
            if a.get("touch"):
                kind.append(T("touch"))
            kind = "%s %s%s%s" % (a.get("type", "totp").upper(), a.get("algorithm", "SHA1"), T(", "),
                                  T(", ").join(kind))
            rows.append((_text(a.get("issuer")), _text(a.get("account") or a.get("name")), "", "", kind))
        fill_table(self.table, rows)
        for r in range(len(rows)):
            self.table.item(r, 2).setFont(self.code_font)
        raws = [a["raw"] for a in self.rows]
        if selected in raws:
            self.table.selectRow(raws.index(selected))
        self._update_countdown(self.clock())
        self._show_codes(self.clock())
        self._update_buttons()

    def _show_codes(self, now):
        T = self.T
        for r, a in enumerate(self.rows):
            code, until = self.codes.get(a["raw"], (None, None))
            if code is not None:
                valid = T("%d s") % int(math.ceil(until - now)) if until is not None else ""
            elif a.get("touch"):
                code, valid = "", T("touch") + T(": ") + T("press Calculate")
            elif not self._totp(a):
                code, valid = "", T("press Calculate")
            else:
                code, valid = "", ""
            for c, text in ((2, code or ""), (3, valid)):
                item = self.table.item(r, c)
                if item is not None and item.text() != text:
                    item.setText(text)

    def _code_of(self, acc):
        code, until = self.codes.get(acc["raw"], (None, None))
        if code is None or (until is not None and until <= self.clock()):
            return None
        return code

    # -- actions ---------------------------------------------------------------
    def copy_code(self):
        T = self.T
        acc = self._selected()
        if acc is None:
            self.ctx.error(T("Select an entry first."))
            return
        code = self._code_of(acc)
        if code is None:
            self.calculate(copy=True)
            return
        _copy(code)
        self.state.setText(T("Code of %s copied.") % self._label(acc))

    def calculate(self, copy=False):
        """Calculates the code of the selected account (a touch account: the
        device waits for it; HOTP: its counter moves on)."""
        acc = self._selected()
        if acc is None:
            self.ctx.error(self.T("Select an entry first."))
            return
        ts = int(self.clock())
        raw = acc["raw"]

        def done(code):
            self.codes[raw] = (code, self._valid_until(acc, ts))
            self._show_codes(self.clock())
            if copy:
                _copy(code)
                self.state.setText(self.T("Code of %s copied.") % self._label(acc))
        self._run_auth(lambda mgr: mgr.calculate(raw, ts), done, touch=bool(acc.get("touch")))

    def _change(self, op, message=None):
        """Runs op(manager) and reads the accounts again (same operation)."""
        ts = int(self.clock())

        def work(mgr):
            op(mgr)
            return self._read(mgr, ts)

        def done(r):
            self._loaded(r)
            if message:
                self.ctx.info(message)
        return self._run_auth(work, done)

    def add_account(self):
        T = self.T
        result = OathAddDialog.get(self)
        if result is None:
            return
        kind, data = result
        existing = {a["raw"] for a in self.accounts}
        if kind == "fields":
            # (the name OathManager.add stores; the dialog checked that it can be built)
            name = build_name(data["issuer"], data["account"], TOTP if data["type"] == "totp" else HOTP,
                              data["period"])
            replace = name in existing
            if replace and not self.ctx.confirm(T("oath-replace") % _text(name), danger=True):
                return
            args = dict(data, replace=replace)
            self._change(lambda mgr: mgr.add(**args), T("Account added: %s") % _text(name))
            return
        records = data
        there = [r for r in records if r[1] in existing]
        replace = set()
        if there:
            if self.ctx.confirm(T("oath-replace-n") % "\n".join(_text(r[1]) for r in there), danger=True):
                replace = {r[1] for r in there}
        todo = [r for r in records if r[1] not in existing or r[1] in replace]
        if not todo:
            return

        def add_all(mgr):
            for r in todo:
                mgr.add_record(r, replace=r[1] in replace)
        self._change(add_all, T("Accounts added: %d") % len(todo))

    def rename(self):
        T = self.T
        acc = self._selected()
        if acc is None:
            self.ctx.error(T("Select an entry first."))
            return
        values = edit_texts(self.ctx, T("Rename..."), [(T("Issuer:"), acc.get("issuer") or ""),
                                                        (T("Account:"), acc.get("account") or acc.get("name") or "")])
        if values is None:
            return
        issuer, account = values
        if not account:
            self.ctx.error(T("Enter the account name."))
            return
        if ":" in issuer:
            self.ctx.error(T("oath-colon"))
            return
        totp = self._totp(acc)
        try:
            name = build_name(issuer or None, account, TOTP if totp else HOTP, acc.get("period") or self.PERIOD)
        except ManagerError as e:
            self.ctx.error(self.ctx.error_text(e))
            return
        raw = acc["raw"]
        if name == raw:
            return
        if name in {a["raw"] for a in self.accounts}:
            self.ctx.error(T("oath-exists") % _text(name))
            return
        self._change(lambda mgr: mgr.rename(raw, issuer or None, account))

    def delete(self):
        T = self.T
        acc = self._selected()
        if acc is None:
            self.ctx.error(T("Select an entry first."))
            return
        if not self.ctx.confirm(T("oath-delete") % self._label(acc), danger=True):
            return
        raw = acc["raw"]
        self._change(lambda mgr: mgr.delete(raw))

    def set_password(self):
        T = self.T
        st = self.status
        if st is None:
            self.ctx.error(T("Refresh first."))
            return
        title = T("Change password...") if st.get("password_set") else T("Set password...")
        new = ask_new_secret(self.ctx, title, T("New OATH password:"), min_len=1)
        if new is None:
            return
        self._change(lambda mgr: mgr.set_password(new), T("OATH password set."))

    def remove_password(self):
        T = self.T
        st = self.status
        if st is None:
            self.ctx.error(T("Refresh first."))
            return
        if not st.get("password_set"):
            self.ctx.info(T("The OATH application has no password."))
            return
        if not self.ctx.confirm(T("oath-remove-password"), danger=True):
            return
        self._change(lambda mgr: mgr.set_password(None), T("OATH password removed."))

    def reset(self):
        T = self.T
        # (the number only when the accounts were listed: while the password
        # protects them, or before Refresh, the page does not know it)
        first = T("oath-reset") % len(self.accounts) if self.listed else T("oath-reset-unknown")
        if not self.ctx.confirm(first, danger=True):
            return
        if not self.ctx.confirm(T("oath-reset-2"), danger=True):
            return
        ts = int(self.clock())

        def work():
            mgr = self.manager(OathManager)
            mgr.reset()
            return self._read(mgr, ts, ask=False)

        def done(r):
            self._loaded(r)
            self.ctx.info(T("OATH application reset."))
        self._start(lambda: self.ctx.run(work, done, touch=True))      # (the device asks for a touch)

    def export(self):
        acc = self._selected()
        if acc is None:
            self.ctx.error(self.T("Select an entry first."))
            return
        raw, label = acc["raw"], _text(acc.get("name")) or self._label(acc)
        self._start(lambda: self.ctx.export_selected("oath", raw, label=label))

    def import_keys(self):
        self._start(lambda: self.ctx.import_file(then=self.auto_refresh))


# ----------------------------------------------------------------------------
# OTP
# ----------------------------------------------------------------------------

OTP_MODES = (("yubico-otp", "Yubico OTP"), ("chal-hmac", "Challenge-response (HMAC-SHA1)"),
             ("static", "Static password"), ("hotp", "OATH-HOTP"))
OTP_MODE_TITLES = dict(OTP_MODES, **{"chal-yubico": "Challenge-response (Yubico)"})
OTP_SLOT_TITLES = {1: "Slot 1 (one press)", 2: "Slot 2 (two presses)"}


class OtpProgramDialog(QDialog):
    """What to program into an OTP slot in one of the four modes, checked
    with mgr_otp's frame builders before the dialog closes. get() returns
    the keyword arguments of the OtpManager.program_* method, or None."""

    def __init__(self, page, mode, slot):
        super().__init__(page)
        self.page = page
        self.mode = mode
        T = self.T = page.T
        self.value = None
        self.setWindowTitle(T("Program slot %d: %s") % (slot, T(OTP_MODE_TITLES[mode])))
        self.setMinimumWidth(520)
        form = QFormLayout(self)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.secrets = []
        gen = QPushButton(T("Generate random"))
        gen.clicked.connect(self._generate)
        if mode == "yubico-otp":
            self.public_id = QLineEdit()
            self.private_id = self._secret()
            self.key = self._secret()
            form.addRow(T("Public ID (modhex):"), self.public_id)
            form.addRow(T("Private ID (hex):"), self.private_id)
            form.addRow(T("Secret key (hex):"), self.key)
        elif mode == "chal-hmac":
            self.key = self._secret()
            form.addRow(T("HMAC key (hex, up to 20 bytes):"), self.key)
            self.touch = QCheckBox(T("Require a touch"))
            form.addRow(self.touch)
        elif mode == "static":
            self.password = self._secret()
            self.password.setMaxLength(mgr_otp.SCAN_CODES_SIZE)
            form.addRow(T("Password:"), self.password)
            self.layout_box = QComboBox()
            self.layout_box.addItem(T("US English"), "us")
            self.layout_box.addItem(T("modhex letters only (any Latin layout)"), "modhex")
            form.addRow(T("Keyboard layout:"), self.layout_box)
        else:
            self.secret = self._secret()
            form.addRow(T("Secret (base32):"), self.secret)
            self.digits = QComboBox()
            self.digits.addItems(["6", "8"])
            form.addRow(T("Digits:"), self.digits)
            self.counter = QSpinBox()
            self.counter.setRange(0, mgr_otp.HOTP_IMF_MAX)
            self.counter.setSingleStep(16)
            form.addRow(T("Initial counter (multiple of 16):"), self.counter)
        form.addRow(gen)
        self.show_box = QCheckBox(T("Show secrets"))
        self.show_box.toggled.connect(self._show)
        form.addRow(self.show_box)
        self.append_cr = None
        if mode != "chal-hmac":
            self.append_cr = QCheckBox(T("Append Enter"))
            self.append_cr.setChecked(True)
            form.addRow(self.append_cr)
        self.current_code = self._secret()
        self.new_code = self._secret()
        self.new_code_repeat = self._secret()           # (a mistyped code would lock the slot)
        form.addRow(T("Current access code (hex, if the slot has one):"), self.current_code)
        form.addRow(T("New access code (hex, empty: none):"), self.new_code)
        form.addRow(T("Repeat the new access code:"), self.new_code_repeat)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _secret(self):
        field = _secret_field()
        self.secrets.append(field)
        return field

    def _show(self, on):
        for field in self.secrets:
            field.setEchoMode(QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password)

    def _generate(self):
        if self.mode == "yubico-otp":
            public_id, private_id, key = mgr_otp.random_yubico_otp()
            self.public_id.setText(mgr_otp.modhex_encode(public_id))
            self.private_id.setText(private_id.hex())
            self.key.setText(key.hex())
        elif self.mode == "chal-hmac":
            self.key.setText(os.urandom(mgr_otp.HMAC_KEY_SIZE).hex())
        elif self.mode == "static":
            self.password.setText(mgr_otp.random_static_password(layout=self.layout_box.currentData()))
        else:
            self.secret.setText(base64.b32encode(os.urandom(mgr_otp.HMAC_KEY_SIZE)).decode("ascii"))

    def _accept(self):
        # The frame builders check every value (without the device); their
        # messages never contain a secret.
        try:
            code = mgr_otp.access_code_bytes(self.new_code.text(), "new access code", "新访问码")
            try:
                repeat = mgr_otp.access_code_bytes(self.new_code_repeat.text())
            except ManagerError:
                repeat = False
            if repeat != code:
                self.new_code_repeat.clear()
                QMessageBox.warning(self, self.windowTitle(), self.T("The two new access codes differ."))
                return
            current = mgr_otp.access_code_bytes(self.current_code.text(), "current access code", "当前访问码")
            args = {"access_code": current, "new_access_code": code}
            append = {} if self.append_cr is None else {"append_cr": self.append_cr.isChecked()}
            if self.mode == "yubico-otp":
                args.update(public_id=self.public_id.text().strip(), private_id=self.private_id.text().strip(),
                            key=self.key.text().strip(), **append)
                mgr_otp.yubico_otp_config(args["public_id"], args["private_id"], args["key"])
                args.update(public_id=mgr_otp.modhex_decode("".join(args["public_id"].split())),
                            private_id=bytes.fromhex(args["private_id"]), key=bytes.fromhex(args["key"]))
            elif self.mode == "chal-hmac":
                args.update(key=self.key.text().strip(), touch=self.touch.isChecked())
                mgr_otp.hmac_sha1_config(args["key"])
            elif self.mode == "static":
                args.update(password=self.password.text(), layout=self.layout_box.currentData(), **append)
                mgr_otp.encode_scan_codes(args["password"], args["layout"])
            else:
                args.update(secret=self.secret.text().strip(), digits=int(self.digits.currentText()),
                            counter=self.counter.value(), **append)
                mgr_otp.hotp_config(args["secret"], args["digits"], args["counter"])
        except ManagerError as e:
            QMessageBox.warning(self, self.windowTitle(), self.page.ctx.error_text(e))
            return
        except ValueError as e:
            QMessageBox.warning(self, self.windowTitle(), str(e))
            return
        self.value = args
        self.accept()

    @classmethod
    def get(cls, page, mode, slot):
        dlg = cls(page, mode, slot)
        try:
            dlg.exec()
            return dlg.value
        finally:
            dlg.value = None
            for field in dlg.secrets:
                field.clear()
            dlg.deleteLater()


class SecretSummaryDialog(QDialog):
    """Read-only text holding secrets (a new Yubico OTP credential for an
    upload), with a Copy button. The copy asks clipboard managers not to keep
    it and leaves the clipboard when the dialog closes (unless something else
    was copied since); the text is cleared then too."""

    def __init__(self, parent, T, title, text):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(520)
        self.copied = None              # what identifies the copy on the clipboard (a digest, not the text)
        lay = QVBoxLayout(self)
        warn = text_label(T("otp-summary"))
        warn.setStyleSheet("color:#a00;")
        lay.addWidget(warn)
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setPlainText(text)
        lay.addWidget(self.text, 1)
        row = QHBoxLayout()
        self.copy_btn = QPushButton(T("Copy"))
        self.copy_btn.clicked.connect(self._copy)
        row.addWidget(self.copy_btn)
        row.addStretch(1)
        close = QPushButton(T("Close"))
        close.clicked.connect(self.accept)
        row.addWidget(close)
        lay.addLayout(row)

    def _copy(self):
        self.copied = _copy_secret(self.text.toPlainText())

    @classmethod
    def show_text(cls, parent, T, title, text):
        dlg = cls(parent, T, title, text)
        try:
            dlg.exec()
        finally:
            _uncopy_secret(dlg.copied)
            dlg.copied = None
            dlg.text.clear()
            dlg.deleteLater()


class OtpPage(ManagerPage):
    """The two OTP slots: what each holds, program one of the four modes
    (with random values and, for Yubico OTP, a copyable summary for the
    upload), delete, set the access code, test challenge-response, swap,
    export / import (the Keys tab's key files). A slot protected by an access
    code asks for it when the device refuses (AuthRequired, WrongSecret)."""

    APP = "otp"

    def __init__(self, ctx):
        super().__init__(ctx)
        T = self.T
        self.otp_status = None
        lay = QVBoxLayout(self)
        top = QHBoxLayout()
        self.state = text_label(T("otp-hint"))
        top.addWidget(self.state, 1)
        self.refresh_btn = QPushButton(T("Refresh"))
        self.refresh_btn.clicked.connect(self.refresh)
        top.addWidget(self.refresh_btn)
        lay.addLayout(top)
        self.slots = {}
        for slot in mgr_otp.SLOTS:
            box = QGroupBox(T(OTP_SLOT_TITLES[slot]))
            bl = QVBoxLayout(box)
            label = text_label("-")
            bl.addWidget(label)
            prow = QHBoxLayout()
            mode = QComboBox()
            for key, title in OTP_MODES:
                mode.addItem(T(title), key)
            prow.addWidget(mode, 1)
            program = QPushButton(T("Program..."))
            program.clicked.connect(lambda _=False, s=slot: self.program(s))
            prow.addWidget(program)
            bl.addLayout(prow)
            arow = QHBoxLayout()
            buttons = {}
            for key, text, fn in (("delete", T("Delete..."), self.delete), ("code", T("Access code..."),
                                                                           self.access_code),
                                  ("test", T("Test challenge-response..."), self.test),
                                  ("export", T("Export..."), self.export)):
                b = QPushButton(text)
                b.clicked.connect(lambda _=False, s=slot, f=fn: f(s))
                arow.addWidget(b)
                buttons[key] = b
            arow.addStretch(1)
            bl.addLayout(arow)
            lay.addWidget(box)
            self.slots[slot] = {"label": label, "mode": mode, "program": program, **buttons}
        row = QHBoxLayout()
        self.swap_btn = QPushButton(T("Swap slots..."))
        self.swap_btn.clicked.connect(self.swap)
        row.addWidget(self.swap_btn)
        self.import_btn = QPushButton(T("Import..."))
        self.import_btn.clicked.connect(self.import_keys)
        row.addWidget(self.import_btn)
        row.addStretch(1)
        lay.addLayout(row)
        lay.addStretch(1)
        self._show_slots()

    # -- state -----------------------------------------------------------------
    def clear(self):
        self.otp_status = None
        self.state.setText(self.T("otp-hint"))
        self._show_slots()

    def _slot_info(self, slot):
        return ((self.otp_status or {}).get("slots") or {}).get(slot) or {}

    def _slot_text(self, slot):
        """What the slot holds, in words (for the display and confirmations)."""
        T = self.T
        s = self._slot_info(slot)
        if not s.get("configured"):
            return T("Empty")
        parts = [T(OTP_MODE_TITLES[s["mode"]]) if s.get("mode") in OTP_MODE_TITLES else T("Programmed")]
        if s.get("public_id"):
            parts.append(T("public ID %s") % _text(s["public_id"]))
        if s.get("digits"):
            parts.append(T("%d digits") % s["digits"])
        if s.get("append_cr"):
            parts.append(T("Enter appended"))
        if s.get("touch"):
            parts.append(T("touch for each response"))
        # (a challenge-response slot types nothing, whatever a state says)
        if s.get("touch_triggered") and not str(s.get("mode") or "").startswith("chal-"):
            parts.append(T("types on a press"))
        return T(", ").join(parts)

    def _show_slots(self):
        loaded = self.otp_status is not None
        for slot, ui in self.slots.items():
            s = self._slot_info(slot)
            ui["label"].setText(self._slot_text(slot) if loaded else "-")
            configured = bool(s.get("configured"))
            for key in ("delete", "code", "export"):
                ui[key].setEnabled(configured)
            ui["test"].setEnabled(configured and s.get("mode") in (None, "chal-hmac"))
            ui["program"].setEnabled(loaded)
        self.swap_btn.setEnabled(loaded and any(self._slot_info(s).get("configured") for s in self.slots))

    # -- device work -----------------------------------------------------------
    def _run_code(self, slot, call, then, access_code=None, touch=False):
        """Runs call(manager, access_code) in the worker. When the slot turns
        out to be protected by an access code (AuthRequired) or the one given
        is wrong (WrongSecret), the access code is asked for and call run
        again."""
        def work(code):
            return call(self.manager(OtpManager), code)

        def ask(e):
            if not isinstance(e, (AuthRequired, WrongSecret)):
                return False
            T = self.T
            text = self.ctx.ask_secret(T("Access code of slot %d") % slot if slot else T("OTP access code"),
                                       self.ctx.error_text(e) + "\n\n" + T("otp-access-code"))
            if text is None:
                return True
            try:
                code = mgr_otp.access_code_bytes(text)
            except ManagerError as bad:
                self.ctx.error(self.ctx.error_text(bad))
                return True
            self.ctx.run(lambda: work(code), then, ask, touch=touch)
            return True
        return self.ctx.run(lambda: work(access_code), then, ask, touch=touch)

    def refresh(self):
        self.ctx.run(lambda: self.manager(OtpManager).status(), self._loaded)

    def _loaded(self, status):
        T = self.T
        self.otp_status = status
        self.loaded = True
        version = _text(status.get("version"))
        serial = status.get("serial")
        self.state.setText(T("OTP application %s, serial %s") % (version, serial) if serial is not None else
                           T("OTP application %s") % version)
        self._show_slots()

    # -- actions ---------------------------------------------------------------
    def program(self, slot):
        T = self.T
        if self.otp_status is None:
            self.ctx.error(T("Refresh first."))
            return
        mode = self.slots[slot]["mode"].currentData()
        args = OtpProgramDialog.get(self, mode, slot)
        if args is None:
            return
        configured = bool(self._slot_info(slot).get("configured"))
        if configured and not self.ctx.confirm(T("otp-overwrite") % (slot, self._slot_text(slot)), danger=True):
            return
        method = {"yubico-otp": "program_yubico_otp", "chal-hmac": "program_chalresp", "static": "program_static",
                  "hotp": "program_hotp"}[mode]
        summary = None
        if mode == "yubico-otp":
            serial = self.otp_status.get("serial")
            summary = "\n".join((
                T("%s: %s") % (T("Slot"), slot),
                T("%s: %s") % (T("Serial"), serial if serial is not None else T("unknown")),
                T("%s: %s") % (T("Public ID"), mgr_otp.modhex_encode(args["public_id"])),
                T("%s: %s") % (T("Private ID"), args["private_id"].hex()),
                T("%s: %s") % (T("Secret key"), args["key"].hex()),
                "", T("CSV (YubiCloud upload)") + T(":"),
                # (without the access code: it is not the validation server's)
                mgr_otp.format_csv(serial, args["public_id"], args["private_id"], args["key"])))
        first_code = args.pop("access_code")

        def call(mgr, code):
            getattr(mgr, method)(slot, access_code=code, replace=configured, **args)
            return mgr.status()

        def done(status):
            self._loaded(status)
            if summary is not None:
                SecretSummaryDialog.show_text(self, T, T("Yubico OTP credential"), summary)
            else:
                self.ctx.info(T("Slot %d programmed.") % slot)
        self._run_code(slot, call, done, first_code)

    def delete(self, slot):
        T = self.T
        if not self.ctx.confirm(T("otp-delete") % (slot, self._slot_text(slot)), danger=True):
            return

        def call(mgr, code):
            mgr.delete(slot, access_code=code)
            return mgr.status()

        def done(status):
            self._loaded(status)
            self.ctx.info(T("Slot %d deleted.") % slot)
        self._run_code(slot, call, done)

    def access_code(self, slot):
        T = self.T
        new = ask_new_secret(self.ctx, T("Access code of slot %d") % slot, T("New access code (hex, empty: none):"),
                             allow_empty=True)
        if new is None:
            return
        try:
            new_code = mgr_otp.access_code_bytes(new, "new access code", "新访问码")
        except ManagerError as e:
            self.ctx.error(self.ctx.error_text(e))
            return

        def call(mgr, code):
            mgr.set_access_code(slot, new_code, access_code=code)
            return mgr.status()

        def done(status):
            self._loaded(status)
            self.ctx.info(T("Access code of slot %d changed.") % slot)
        self._run_code(slot, call, done)

    def test(self, slot):
        T = self.T
        text, ok = QInputDialog.getText(self, T("Test challenge-response..."),
                                        T("Challenge (hex; empty: a random one):"))
        if not ok:
            return
        try:
            challenge = bytes.fromhex("".join(text.split())) if text.strip() else os.urandom(32)
        except ValueError:
            challenge = None
        if challenge is None or len(challenge) > mgr_otp.HMAC_CHALLENGE_SIZE:
            self.ctx.error(T("The challenge is not hexadecimal (at most 64 bytes)."))
            return
        touch = bool(self._slot_info(slot).get("touch"))
        self.ctx.run(lambda: self.manager(OtpManager).calculate_hmac(slot, challenge),
                     lambda r: self.ctx.info(T("Challenge: %s\nResponse: %s") % (challenge.hex(), bytes(r).hex())),
                     touch=touch)

    def swap(self):
        T = self.T
        if not self.ctx.confirm(T("otp-swap"), danger=True):
            return

        def call(mgr, code):
            mgr.swap(access_code=code)
            return mgr.status()

        def done(status):
            self._loaded(status)
            self.ctx.info(T("Slots swapped."))
        self._run_code(None, call, done)

    def export(self, slot):
        self.ctx.export_selected("otp", bytes([slot]), label="slot%d" % slot)

    def import_keys(self):
        self.ctx.import_file(then=self.refresh)
