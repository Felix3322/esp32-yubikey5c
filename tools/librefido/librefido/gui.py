"""librefido-gui: desktop configuration tool for LibreFido devices (PySide6).

Every device operation runs in a worker thread; operations that need a touch
show a banner while the device waits. Operations after which the device
restarts (profile switch, wipe, import, restore test, factory reset)
reconnect automatically.
"""

import locale
import os
import sys
import traceback

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QColorDialog, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGroupBox, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit,
    QVBoxLayout, QWidget,
)

from smartcard.Exceptions import CardConnectionException

from . import __version__, firmware, gui_policy, keyio, provision, stdformats
from .backup import BackupError, firmware_supports, read_file, write_file
from .cli import (PGP_SLOTS, already_there, key_entry_text, list_all_keys, oath_keys_from_links, pgp_key_text,
                  qr_links, read_key_source, write_key)
from .keyfile import SUFFIX, SingleKey, read_key_file
from .keyio import KeyTransferError
from .mgmt import APPS, Management, PinRequired, clip_name, display_name
from .pcsc import ApduError, list_devices

# ----------------------------------------------------------------------------
# Texts (English keys, Chinese translation chosen from the system locale)
# ----------------------------------------------------------------------------

ZH = {
    "LibreFido Manager": "LibreFido 管理器",
    "Device": "设备",
    "Profiles": "环境",
    "Backup": "备份",
    "Health": "磁盘健康",
    "Refresh": "刷新",
    "No device": "未找到设备",
    "Firmware": "固件版本",
    "Build profile": "构建配置",
    "Chip serial": "芯片序列号",
    "Profile serial": "当前环境序列号",
    "Storage": "存储状态",
    "Last operation": "上次操作",
    "Chip security": "芯片安全状态",
    "secure profile": "安全环境",
    "Secure Boot": "安全启动",
    "Flash encryption": "Flash 加密",
    "JTAG disabled": "JTAG 已禁用",
    "Root key": "根密钥",
    "yes": "是",
    "no": "否",
    "Restart": "重启",
    "Restart into recovery (ROM loader)": "重启进入恢复模式（ROM 下载）",
    "Factory reset...": "恢复出厂设置…",
    "Slot": "槽位",
    "Colour": "颜色",
    "Name": "名称",
    "State": "状态",
    "Export": "导出",
    "active": "当前",
    "in use": "已使用",
    "empty": "空",
    "allowed": "允许",
    "blocked": "禁止",
    "Switch to": "切换到此环境",
    "Rename...": "重命名…",
    "Colour...": "颜色…",
    "Allow / forbid export": "允许/禁止导出",
    "Create / wipe": "创建/清空",
    "Delete": "删除",
    "Long press cycles through": "长按按钮循环切换的环境数",
    "Apply": "应用",
    "Export the active profile": "导出当前环境",
    "Encrypt with a passphrase": "用口令加密",
    "Passphrase": "口令",
    "Repeat passphrase": "重复口令",
    "FIDO PIN of the profile (if set)": "此环境的 FIDO PIN（如已设置）",
    "Export to file...": "导出到文件…",
    "Verify a backup file": "校验备份文件",
    "Open and verify...": "打开并校验…",
    "Check on the device (dry run)": "在设备上校验（不导入）",
    "Full restore test (device restarts)": "完整恢复测试（设备会重启）",
    "Restore / clone into a slot": "恢复/克隆到槽位",
    "Target slot": "目标槽位",
    "Import...": "导入…",
    "Scrub now": "立即全盘校验",
    "Touch the key now (it blinks yellow)...": "请触摸按键（黄灯闪烁）…",
    "Working...": "处理中…",
    "Busy with work in the background...": "正在后台处理…",
    "If the key blinks, touch it to list the keys...": "如按键闪烁，请触摸以列出密钥…",
    "Done": "完成",
    "Error": "错误",
    "The device restarts...": "设备正在重启…",
    "Passphrases differ": "两次口令不一致",
    "Backup file written": "备份文件已写入",
    "NOT encrypted: anyone with this file has your keys.": "未加密：拿到此文件的人即拿到你的密钥。",
    "Backup OK": "备份校验通过",
    "The firmware accepts this backup.": "固件接受此备份。",
    "Restore test passed: the backup can be restored.": "恢复测试通过：此备份可以被完整恢复。",
    "Restore test FAILED.": "恢复测试失败。",
    "Imported": "已导入",
    "Imported: %d files": "已导入：%d 个文件",
    "%s (%s, UUID %s, %d files)": "%s（%s，UUID %s，%d 个文件）",
    # punctuation of composed texts (full-width in Chinese)
    ":": "：",
    "%s: %s": "%s：%s",
    "revoked": "已吊销",
    "Type 'erase' to erase every profile and key:": "输入 erase 以清除所有环境和密钥：",
    "Profile name:": "环境名称：",
    "Healthy": "健康",
    "Repaired": "已自动修复",
    "Damaged": "有无法恢复的扇区",
    "Firmware update": "固件升级",
    "Update firmware...": "升级固件…",
    "Keep this firmware": "保留当前固件",
    "Roll back": "回滚到上一版本",
    "Firmware image": "固件镜像",
    "Firmware updated": "固件已升级",
    "Running %s in slot %s.": "当前运行 %s（槽位 %s）。",
    "Unconfirmed: the next restart goes back to the previous firmware.": "尚未确认：下次重启会回到上一版本固件。",
    "The previous firmware can be restored.": "可以回滚到上一版本固件。",
    "Install firmware %s (%s, %s build) over %s?\n\nKey storage is not touched. If the new firmware "
    "does not start, the key returns to the current one at the next restart.":
        "用固件 %s（%s，%s 构建）替换当前的 %s？\n\n密钥存储不会被改动。如果新固件无法正常启动，"
        "下次重启时会自动回到当前固件。",
    "This image is older than the running firmware. Install it anyway?": "此镜像比当前固件旧，仍然安装？",
    "FIDO PIN": "FIDO PIN",
    "FIDO PIN of the active profile:": "当前环境的 FIDO PIN：",
    "FIDO PIN of the active profile (leave empty if it has none):": "当前环境的 FIDO PIN（如未设置请留空）：",
    "The active profile has a FIDO PIN: it is needed.": "当前环境设置了 FIDO PIN，必须输入。",
    "Enter a passphrase": "请输入口令",
    "The backup will NOT be encrypted: anyone with the file has your keys. Continue?":
        "备份将不加密：拿到此文件的人即拿到你的密钥。继续？",
    "Warning": "警告",
    "NOT encrypted: nothing proves this file was not modified.": "未加密：无法证明此文件未被篡改。",
    "The connected device (firmware %s) cannot import it: it needs %s or newer.":
        "已连接的设备（固件 %s）无法导入：需要 %s 或更新版本。",
    "This backup needs firmware %s or newer.": "此备份需要固件 %s 或更新版本。",
    "This backup is NOT encrypted, so nothing proves it was not replaced by someone who could write "
    "the file. Import it anyway?": "此备份未加密，无法证明它没有被能写入该文件的人替换。仍然导入？",
    "Replace slot %d?": "替换槽位 %d？",
    "Import into slot %d?": "导入到槽位 %d？",
    "Slot %d (%s) is in use. Importing %s replaces it and erases its keys for good.":
        "槽位 %d（%s）已在使用。导入 %s 会替换它，其中的密钥将被永久清除。",
    "Details:": "详细信息：",
    "The device asks for the FIDO PIN of the active profile.": "设备要求输入当前环境的 FIDO PIN。",
    "warning": "安全性与便利性不可兼得：LibreFido 专注于便利性（可导出、可克隆）。请勿用它保存任何有价值的数据。",
}

# English of the texts that are keys rather than English sentences.
EN = {
    "warning": "Security and convenience cannot both be had: LibreFido favours convenience (exportable, "
               "clonable keys). Do not keep anything valuable on it.",
}

gui_policy.install_translations(ZH, EN)

def _chinese_ui():
    """LIBREFIDO_LANG=zh|en wins; otherwise the system UI language. Qt's
    locale name is the reliable one: on Windows, Python reports names such
    as 'Chinese (Simplified)_China' instead of 'zh_CN'."""
    forced = os.environ.get("LIBREFIDO_LANG", "").strip().lower()
    if forced:
        return forced.startswith("zh")
    try:
        from PySide6.QtCore import QLocale
        if QLocale.system().name().lower().startswith("zh"):
            return True
    except Exception:
        pass
    name = (locale.getlocale()[0] or os.environ.get("LANG", "")).lower()
    return name.startswith("zh") or name.startswith("chinese")


_LANG_ZH = _chinese_ui()


def T(text):
    return ZH.get(text, text) if _LANG_ZH else EN.get(text, text)


HEALTH_LABELS = {
    "generation": "Transactions committed",
    "sectors_written": "Sectors in use",
    "repaired_from_copy": "Sectors rebuilt from the mirror copy (last check)",
    "corrected_ecc": "Sectors corrected by Reed-Solomon (last check)",
    "ecc_bytes_corrected": "Bytes corrected by Reed-Solomon",
    "uncorrectable": "Unrecoverable sectors",
    "metadata_repaired": "Metadata rebuilt",
    "served_from_copy_b": "Sectors served from copy B",
    "journal_replayed": "Interrupted write completed at boot",
    "commit_failures": "Failed writes",
    "max_erase_count": "Most rewritten sector (erase cycles)",
    "lifetime_repairs": "Repairs (lifetime)",
    "lifetime_uncorrectable": "Unrecoverable (lifetime)",
    "fs_used_bytes": "Used bytes",
    "fs_total_bytes": "Capacity bytes",
    "fs_files": "Files",
    "system_area_bad_copies": "Damaged system area copies",
}
ZH.update({
    "Transactions committed": "已提交事务数",
    "Sectors in use": "已使用扇区",
    "Sectors rebuilt from the mirror copy (last check)": "从镜像副本重建的扇区（最近一次检查）",
    "Sectors corrected by Reed-Solomon (last check)": "经 Reed-Solomon 纠错的扇区（最近一次检查）",
    "Bytes corrected by Reed-Solomon": "Reed-Solomon 纠正的字节数",
    "Unrecoverable sectors": "无法恢复的扇区",
    "Metadata rebuilt": "重建的元数据",
    "Sectors served from copy B": "从副本 B 读取的扇区",
    "Interrupted write completed at boot": "开机时补完的中断写入",
    "Failed writes": "写入失败次数",
    "Most rewritten sector (erase cycles)": "擦写最多的扇区（擦除次数）",
    "Repairs (lifetime)": "累计修复",
    "Unrecoverable (lifetime)": "累计无法恢复",
    "Used bytes": "已用字节",
    "Capacity bytes": "容量字节",
    "Files": "文件数",
    "Damaged system area copies": "损坏的系统区副本",
})

# The "Keys" tab (single keys, KeysTab below).
KEY_APP_TITLES = {"fido": "FIDO2 passkeys", "oath": "OATH accounts", "otp": "OTP slots", "openpgp": "OpenPGP keys",
                  "piv": "PIV keys"}
PGP_SLOT_TITLES = dict(zip(PGP_SLOTS, ("signature", "decryption", "authentication")))
ZH.update({
    "Keys": "密钥",
    "Key manager": "密钥管理",
    "Application": "应用",
    "All applications": "全部应用",
    "FIDO2 passkeys": "FIDO2 通行密钥",
    "OATH accounts": "OATH 账户",
    "OTP slots": "OTP 槽位",
    "OpenPGP keys": "OpenPGP 密钥",
    "PIV keys": "PIV 密钥",
    "Key": "密钥",
    "Details": "详情",
    "Export selected...": "导出所选…",
    "Import file...": "从文件导入…",
    "Import otpauth link...": "导入 otpauth 链接…",
    "Import QR image...": "导入二维码图片…",
    "keys-hint": "点击“刷新”列出当前环境的密钥（可能需要输入 FIDO PIN）。",
    "Secret keys of this profile can be exported.": "此环境的私钥可以导出。",
    "not-exportable": "此环境或固件构建不允许导出私钥（安全环境、禁止导出的环境或 HARDENED 构建）。",
    "no-key-transfer": ("此设备的固件不能列出或导出单个密钥（需要 LibreFido 2.1.0 或更新版本）。"
                        "OATH、OpenPGP 和 PIV 密钥仍可通过各自的应用导入。"),
    "This firmware lists no keys of this application.": "此固件不能列出该应用的密钥。",
    "Keys listed: %d": "已列出密钥：%d",
    "fido-listed-without-pin": ("通行密钥是在未输入 FIDO PIN 的情况下列出的：需要用户验证的通行密钥只有输入 FIDO PIN "
                                "后才会列出，用户名也只在那时显示。点击“用 FIDO PIN 列出…”输入 PIN（未设置 FIDO PIN "
                                "的环境需先设置一个）。"),
    "List with FIDO PIN...": "用 FIDO PIN 列出…",
    "Enter the FIDO PIN.": "请输入 FIDO PIN。",
    "key-manager-failed": "密钥管理无法启动（其他标签页不受影响）。详细信息：",
    "The keys changed: Refresh lists them again.": "密钥已变更：点击“刷新”重新列出。",
    "The device or profile changed: Refresh lists its keys.": "设备或环境已变更：点击“刷新”列出它的密钥。",
    "Select a key first.": "请先选择一个密钥。",
    "File format:": "文件格式：",
    "LibreFido key file (.lfkey, encrypted)": "LibreFido 密钥文件（.lfkey，加密）",
    "otpauth:// link (NOT encrypted)": "otpauth:// 链接（不加密）",
    "PEM file (PKCS#8, encrypted)": "PEM 文件（PKCS#8，加密）",
    "Key file passphrase": "密钥文件口令",
    "Do not encrypt (anyone with the file has the key)": "不加密（拿到文件的人即拿到密钥）",
    "The key will NOT be encrypted: anyone with the file has your key. Continue?":
        "密钥将不加密：拿到此文件的人即拿到你的密钥。继续？",
    "otpauth-plain": "otpauth:// 链接以明文保存密钥：拿到此文件的人即拿到你的密钥。继续？",
    "OpenPGP Admin PIN": "OpenPGP 管理员 PIN",
    "OpenPGP Admin PIN:": "OpenPGP 管理员 PIN（Admin PIN）：",
    "The OpenPGP Admin PIN is needed.": "必须输入 OpenPGP 管理员 PIN。",
    "OATH password": "OATH 密码",
    "OATH password (leave empty if the OATH application has none):": "OATH 密码（如未设置请留空）：",
    "OTP access code": "OTP 访问码",
    "Access code of OTP slot %s (12 hex digits; leave empty if it has none):":
        "OTP 槽位 %s 的访问码（12 位十六进制；如未设置请留空）：",
    "PIV management key": "PIV 管理密钥",
    "PIV management key (hex; leave empty for the default key):": "PIV 管理密钥（十六进制；留空则使用默认密钥）：",
    "OTP slot:": "OTP 槽位：",
    "PIV slot:": "PIV 槽位：",
    "OpenPGP key slot:": "OpenPGP 密钥槽位：",
    "signature": "签名",
    "decryption": "解密",
    "authentication": "认证",
    "Key file written": "密钥文件已写入",
    "NOT encrypted: anyone with this file has the key.": "未加密：拿到此文件的人即拿到该密钥。",
    "Add this passkey to the device?": "把此通行密钥添加到设备？",
    "Add this key to the device?": "把此密钥添加到设备？",
    "Add %d OATH accounts to the device?": "把 %d 个 OATH 账户添加到设备？",
    "fido-counter-export": ("签名计数器：该通行密钥仍保留在本设备上。会校验签名计数器的网站可能把在两个设备上使用的"
                            "通行密钥视为克隆并停用它：请只在一个设备上使用它。"),
    "fido-counter-import": ("签名计数器：导入的通行密钥从导出时源设备的计数值继续。如果源设备也继续使用它，"
                            "会校验签名计数器的网站可能把它视为克隆并停用：请只在一个设备上使用它。"),
    "Replace what is on the device?": "替换设备上已有的内容？",
    "What is there now is erased for good.": "现有内容将被永久清除。",
    "Not imported": "未导入",
    "otpauth:// or otpauth-migration:// link:": "otpauth:// 或 otpauth-migration:// 链接：",
    "left-out": "设备无法保存的账户已略过：%s",
    "missing-qr": "此 Google 身份验证器导出分为多个二维码，这里缺少第 %s 个：请把它们也导入。",
    "others-qr": "%d 个不含 otpauth 链接的二维码已略过。",
    "Choose the key": "选择密钥",
    "Key of the file:": "文件中的密钥：",
    "Password of %s:": "%s 的密码：",
    "Passphrase of the OpenPGP key:": "OpenPGP 密钥的口令：",
    "key-file-plain": "此密钥文件未加密，无法证明它没有被能写入该文件的人替换。仍然导入？",
    "unknown-source": "无法识别此文件：不是 LibreFido 密钥文件、PEM/DER/PKCS#12 密钥、OpenPGP 密钥、otpauth 链接或二维码图片。",
    "No key of this file can go onto the device.": "此文件中没有可以存入设备的密钥。",
    "Images": "图片",
    "Key files": "密钥文件",
    "All files": "所有文件",
    # words of the key list (cli.key_entry_text), and the joiner of its details
    ", ": "，",
    "user %s": "用户 %s",
    "imported": "导入的",
    "%d digits": "%d 位",
    "touch": "需按键",
    "slot %s": "槽位 %s",
    "access code": "有访问码",
    "fingerprint %s": "指纹 %s",
    "created %s": "创建于 %s",
    "signature key": "签名密钥",
    "decryption key": "解密密钥",
    "authentication key": "认证密钥",
    "PIN policy %s": "PIN 策略：%s",
    "touch policy %s": "按键策略：%s",
    "default": "默认",
    "never": "从不",
    "once": "一次",
    "always": "总是",
    "cached": "缓存",
    "malformed entry": "条目格式错误",
})
EN.update({
    "keys-hint": "Refresh lists the keys of the active profile (the FIDO PIN may be asked for).",
    "fido-listed-without-pin": "Passkeys listed without the FIDO PIN: passkeys that need user verification are only "
                               "listed with the FIDO PIN, and user names only then. \"List with FIDO PIN...\" asks "
                               "for it (a profile without a FIDO PIN lists them once one is set).",
    "key-manager-failed": "The Key manager could not be started (the other tabs work as usual). Details:",
    "not-exportable": "This profile or build does not let secret keys out (a secure or no-export profile, or a "
                      "HARDENED build).",
    "no-key-transfer": "The firmware of this device cannot list or export single keys (LibreFido 2.1.0 or newer). "
                       "OATH, OpenPGP and PIV keys can still be added through their own applications.",
    "otpauth-plain": "An otpauth:// link holds the secret in the clear: anyone with the file has your key. Continue?",
    "fido-counter-export": "Sign counter: the passkey stays on this key as well. A site that checks signature "
                           "counters may take a passkey used on two keys for a clone and block it: use it on one "
                           "key only.",
    "fido-counter-import": "Sign counter: the passkey goes on from the counter of the key it was exported from, as "
                           "it was at the export. If that key keeps using it, a site that checks signature counters "
                           "may take it for a clone and block it: use it on one key only.",
    "left-out": "Left out (the device cannot hold them): %s",
    "missing-qr": "This Google Authenticator export is split over several QR codes; number(s) %s are not here: "
                  "add them too.",
    "others-qr": "%d QR code(s) without an otpauth link left out.",
    "key-file-plain": "This key file is NOT encrypted, so nothing proves it was not replaced by someone who could "
                      "write the file. Import it anyway?",
    "unknown-source": "Unknown file: not a LibreFido key file, a PEM, DER or PKCS#12 key, an OpenPGP key, otpauth "
                      "links or a QR code image.",
})


# ----------------------------------------------------------------------------
# Worker
# ----------------------------------------------------------------------------

class _Signals(QObject):
    done = Signal(object)
    failed = Signal(object)         # (exception, message)
    progress = Signal(int, int)


class Job(QRunnable):
    def __init__(self, fn):
        super().__init__()
        self.fn = fn
        self.signals = _Signals()

    def run(self):
        # The work function goes with this frame: what its closure holds (a
        # decrypted backup, a PIN, a passphrase, an image) is not kept by the
        # Job, which lives on until the next one (Python cannot wipe memory,
        # but nothing refers to the secrets any more).
        fn, self.fn = self.fn, None
        try:
            self.signals.done.emit(fn(lambda a, b: self.signals.progress.emit(a, b)))
        except (ApduError, BackupError, RuntimeError, OSError, CardConnectionException,
                provision.ProvisionError, KeyTransferError, stdformats.FormatError) as e:
            self.signals.failed.emit((e, str(e)))
        except Exception as e:
            self.signals.failed.emit((e, traceback.format_exc()))
        finally:
            fn = None


def _plain(text):
    """Text for a QMessageBox, which shows rich text when its first line looks
    like HTML: a name from the device or a backup could hide or rewrite the
    message. A fixed first line keeps it plain text."""
    first = text.split("\n", 1)[0]
    if "<" in first or "&" in first:
        return T("Details:") + "\n" + text
    return text


class UnavailableTab(QWidget):
    """A tab that could not be built: what went wrong (text) and its details
    (a traceback), as plain text. show_info() does nothing."""

    def __init__(self, text, details=""):
        super().__init__()
        lay = QVBoxLayout(self)
        self.state = QLabel(text)
        self.state.setTextFormat(Qt.TextFormat.PlainText)
        self.state.setWordWrap(True)
        self.state.setStyleSheet("color:#a00;")
        lay.addWidget(self.state)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlainText(details)
        lay.addWidget(self.details, 1)

    def show_info(self, info):
        pass


# ----------------------------------------------------------------------------
# Main window
# ----------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("%s %s" % (T("LibreFido Manager"), __version__))
        self.resize(820, 600)
        self.pool = QThreadPool.globalInstance()
        self.mgmt = None
        self.info = None
        self.busy = False
        self._quiet = False                     # the operation running is quiet (see _run)
        self._job = None
        self._then = self._on_error = None
        self._refresh_after = False

        central = QWidget()
        root = QVBoxLayout(central)
        top = QHBoxLayout()
        self.reader_box = QComboBox()
        self.refresh_btn = QPushButton(T("Refresh"))
        self.refresh_btn.clicked.connect(self.refresh)
        top.addWidget(self.reader_box, 1)
        top.addWidget(self.refresh_btn)
        root.addLayout(top)

        self.banner = QLabel("")
        self.banner.setStyleSheet("background:#fff3b0;color:#333;padding:6px;border-radius:4px;")
        self.banner.setVisible(False)
        root.addWidget(self.banner)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        root.addWidget(self.progress)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._device_tab(), T("Device"))
        self.tabs.addTab(self._profiles_tab(), T("Profiles"))
        self.keys_tab = KeysTab(self)
        self.tabs.addTab(self.keys_tab, T("Keys"))
        self.manager_tab = self._key_manager_tab()
        self.tabs.addTab(self.manager_tab, T("Key manager"))
        self.tabs.addTab(self._backup_tab(), T("Backup"))
        self.security_tab = gui_policy.SecurityTab(self, T)
        self.tabs.addTab(self.security_tab, T("Security"))
        self.tabs.addTab(self._health_tab(), T("Health"))
        root.addWidget(self.tabs, 1)

        warn = QLabel(T("warning"))
        warn.setWordWrap(True)
        warn.setStyleSheet("color:#a00;")
        root.addWidget(warn)
        self.setCentralWidget(central)
        self.statusBar().showMessage(T("No device"))
        self.refresh()

    # -- tabs ----------------------------------------------------------------
    def _key_manager_tab(self):
        """The Key manager tab (gui_manager and its five pages). When
        importing or building it fails, the rest of the window still starts
        and the tab shows why."""
        try:
            from .gui_manager import KeyManagerTab
            return KeyManagerTab(self, T)
        except Exception:
            return UnavailableTab(T("key-manager-failed"), traceback.format_exc())

    def _device_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        form = QFormLayout()
        self.dev_labels = {}
        for key, title in (("firmware", "Firmware"), ("build_profile", "Build profile"),
                           ("chip_serial", "Chip serial"), ("serial", "Profile serial"),
                           ("boot_message", "Storage"), ("last_result", "Last operation")):
            lbl = QLabel("-")
            lbl.setTextFormat(Qt.TextFormat.PlainText)         # device text, never rich text
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.dev_labels[key] = lbl
            form.addRow(T(title) + T(":"), lbl)
        lay.addLayout(form)
        sec = QGroupBox(T("Chip security"))
        sform = QFormLayout(sec)
        self.sec_labels = {}
        for key, title in (("secure_boot", "Secure Boot"), ("flash_encryption", "Flash encryption"),
                           ("jtag_disabled", "JTAG disabled"), ("root_key", "Root key")):
            lbl = QLabel("-")
            lbl.setTextFormat(Qt.TextFormat.PlainText)
            self.sec_labels[key] = lbl
            sform.addRow(T(title) + T(":"), lbl)
        lay.addWidget(sec)
        fwg = QGroupBox(T("Firmware update"))
        fwl = QVBoxLayout(fwg)
        self.fw_state = QLabel("-")
        self.fw_state.setTextFormat(Qt.TextFormat.PlainText)
        self.fw_state.setWordWrap(True)
        fwl.addWidget(self.fw_state)
        fwrow = QHBoxLayout()
        self.fw_pin = QLineEdit()
        self.fw_pin.setEchoMode(QLineEdit.EchoMode.Password)
        self.fw_pin.setPlaceholderText(T("FIDO PIN of the profile (if set)"))
        fwrow.addWidget(self.fw_pin, 1)
        for text, slot in ((T("Update firmware..."), self._update_firmware),
                           (T("Keep this firmware"), self._confirm_firmware),
                           (T("Roll back"), self._rollback_firmware)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            fwrow.addWidget(b)
        fwl.addLayout(fwrow)
        lay.addWidget(fwg)
        row = QHBoxLayout()
        for text, slot in ((T("Restart"), lambda: self._reboot(False)),
                           (T("Restart into recovery (ROM loader)"), lambda: self._reboot(True)),
                           (T("Factory reset..."), self._factory_reset)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            row.addWidget(b)
        lay.addLayout(row)
        lay.addStretch(1)
        return w

    def _profiles_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        self.table = QTableWidget(4, 5)
        self.table.setHorizontalHeaderLabels([T("Slot"), T("Colour"), T("Name"), T("State"), T("Export")])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        lay.addWidget(self.table)
        row = QHBoxLayout()
        for text, slot in ((T("Switch to"), self._switch), (T("Rename..."), self._rename),
                           (T("Colour..."), self._colour), (T("Allow / forbid export"), self._toggle_export),
                           (T("Create / wipe"), self._wipe), (T("Delete"), self._delete)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            row.addWidget(b)
        lay.addLayout(row)
        srow = QHBoxLayout()
        srow.addWidget(QLabel(T("Long press cycles through")))
        self.slots_spin = QSpinBox()
        self.slots_spin.setRange(1, 4)
        srow.addWidget(self.slots_spin)
        apply_btn = QPushButton(T("Apply"))
        apply_btn.clicked.connect(lambda: self._run(lambda p: self.mgmt.set_button_slots(self.slots_spin.value()),
                                                    touch=self._change_touch(), refresh=True))
        srow.addWidget(apply_btn)
        srow.addStretch(1)
        lay.addLayout(srow)
        return w

    def _backup_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        ex = QGroupBox(T("Export the active profile"))
        f = QFormLayout(ex)
        self.enc_check = QCheckBox(T("Encrypt with a passphrase"))
        self.enc_check.setChecked(True)
        self.pass1 = QLineEdit()
        self.pass1.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass2 = QLineEdit()
        self.pass2.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_edit = QLineEdit()
        self.pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        f.addRow(self.enc_check)
        f.addRow(T("Passphrase") + T(":"), self.pass1)
        f.addRow(T("Repeat passphrase") + T(":"), self.pass2)
        f.addRow(T("FIDO PIN of the profile (if set)") + T(":"), self.pin_edit)
        b = QPushButton(T("Export to file..."))
        b.clicked.connect(self._export)
        f.addRow(b)
        lay.addWidget(ex)

        ve = QGroupBox(T("Verify a backup file"))
        v = QVBoxLayout(ve)
        brow = QHBoxLayout()
        for text, slot in ((T("Open and verify..."), self._verify_file),
                           (T("Check on the device (dry run)"), lambda: self._device_check(False)),
                           (T("Full restore test (device restarts)"), lambda: self._device_check(True))):
            btn = QPushButton(text)
            btn.clicked.connect(slot)
            brow.addWidget(btn)
        v.addLayout(brow)
        self.verify_out = QTextEdit()
        self.verify_out.setReadOnly(True)
        v.addWidget(self.verify_out)
        lay.addWidget(ve)

        im = QGroupBox(T("Restore / clone into a slot"))
        irow = QHBoxLayout(im)
        irow.addWidget(QLabel(T("Target slot")))
        self.target_spin = QSpinBox()
        self.target_spin.setRange(1, 4)
        irow.addWidget(self.target_spin)
        ib = QPushButton(T("Import..."))
        ib.clicked.connect(self._import)
        irow.addWidget(ib)
        irow.addStretch(1)
        lay.addWidget(im)
        # The last verified backup file: only its path is kept. The device
        # checks read and decrypt it again, so the decrypted stream (every
        # key of the profile) lives only as long as one operation.
        self.loaded_path = None
        return w

    def _health_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        self.health_state = QLabel("-")
        self.health_state.setStyleSheet("font-size:16px;font-weight:bold;")
        lay.addWidget(self.health_state)
        self.health_table = QTableWidget(len(HEALTH_LABELS), 2)
        self.health_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.health_table.horizontalHeader().setVisible(False)
        self.health_table.verticalHeader().setVisible(False)
        self.health_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        lay.addWidget(self.health_table)
        b = QPushButton(T("Scrub now"))
        b.clicked.connect(lambda: self._run(lambda p: self.mgmt.health(scrub=True), then=self._show_health))
        lay.addWidget(b)
        return w

    # -- plumbing ------------------------------------------------------------
    def _run(self, fn, then=None, touch=False, reboots=False, refresh=False, on_error=None, device=True, banner=None,
             quiet=False):
        """Runs fn(progress) in a worker thread. Afterwards, on the GUI
        thread: then(result), or on_error(exception), which returns True when
        it handled the failure (otherwise the error is shown). device=False
        for work without a device (backup files). banner: the text shown
        meanwhile instead of the touch or "working" one. quiet: background
        work the user did not ask for (the OATH page's code refresh): no
        banner and no progress bar, which would flash every time; errors are
        reported as always. Returns whether it started (not while another
        operation runs: see _turned_away)."""
        if self.busy:
            if not quiet:
                self._turned_away()
            return False
        if device and self.mgmt is None:
            QMessageBox.warning(self, T("Error"), T("No device"))
            return False
        self.busy, self._quiet = True, quiet
        if not quiet:
            self.banner.setText(banner or (T("Touch the key now (it blinks yellow)...") if touch else
                                           T("Working...")))
            self.banner.setVisible(True)
            self.progress.setVisible(False)

        def work(progress):
            r = fn(progress)
            if reboots:
                self.mgmt.reconnect()
            return r
        job = Job(work)
        job.setAutoDelete(False)
        if not quiet:
            job.signals.progress.connect(self._on_progress)
        # The callbacks are kept here and dropped once used, not in the Job's
        # signal connections, which live as long as the Job: they may hold
        # what the operation needs (a passphrase for a retry, for example).
        self._then, self._on_error, self._refresh_after = then, on_error, refresh or reboots
        job.signals.done.connect(self._finished)
        job.signals.failed.connect(self._failed)
        # The Python side (and its signals) must outlive the worker thread.
        self._job = job
        self.pool.start(job)
        return True

    def _on_progress(self, done, total):
        self.progress.setVisible(True)
        self.progress.setMaximum(max(total, 1))
        self.progress.setValue(done)

    def _finished(self, result):
        then, refresh = self._then, self._refresh_after
        self._then = self._on_error = None
        self.busy = self._quiet = False
        self.banner.setVisible(False)
        self.progress.setVisible(False)
        if then:
            then(result)
        if refresh:
            self.refresh()

    def _failed(self, failure):
        exc, msg = failure
        on_error = self._on_error
        self._then = self._on_error = None
        self.busy = self._quiet = False
        self.banner.setVisible(False)
        self.progress.setVisible(False)
        if not (on_error and on_error(exc)):
            QMessageBox.critical(self, T("Error"), _plain(msg))
        self.refresh()                          # (does nothing while a retry runs)

    def _run_pin(self, op, typed, no_pin=False, then=None, refresh=False, touch=True, banner=None):
        """Runs op(pin, no_pin, progress), an operation that takes the FIDO
        PIN of the active profile, with the PIN typed in a field. When it
        turns out that a PIN is needed and none was typed (checked in the
        worker: the check waits for the device), the PIN is asked for and op
        runs once more. touch: the device waits for one (the banner).
        banner(pin): the banner text instead, for the PIN op runs with."""
        def on_error(e):
            if typed or not isinstance(e, PinRequired) or not e.ask:
                return False
            if e.kind == "unknown":
                label = T("FIDO PIN of the active profile (leave empty if it has none):")
            elif e.kind == "device":
                label = T("The device asks for the FIDO PIN of the active profile.") + "\n" + \
                    T("FIDO PIN of the active profile:")
            else:
                label = T("FIDO PIN of the active profile:")
            pin, ok = QInputDialog.getText(self, T("FIDO PIN"), label, QLineEdit.EchoMode.Password)
            if not ok:
                return True
            if not pin and e.kind != "unknown":
                QMessageBox.warning(self, T("Error"), T("The active profile has a FIDO PIN: it is needed."))
                return True
            self._run(lambda p: op(pin or None, not pin, p), then=then, touch=touch, refresh=refresh,
                      banner=banner and banner(pin or None))
            return True
        self._run(lambda p: op(typed or None, no_pin, p), then=then, touch=touch, refresh=refresh, on_error=on_error,
                  banner=banner and banner(typed or None))

    def refresh(self):
        if self.busy:
            self._turned_away()
            return
        try:
            devices = list_devices()
        except Exception:
            devices = []
        current = self.reader_box.currentText()
        self.reader_box.clear()
        for reader, _ in devices:
            self.reader_box.addItem(reader)
        if current and self.reader_box.findText(current) >= 0:
            self.reader_box.setCurrentText(current)
        if not devices:
            self.mgmt = None
            self.statusBar().showMessage(T("No device"))
            self.keys_tab.show_info(None)
            self.manager_tab.show_info(None)
            return
        try:
            if self.mgmt is None or self.mgmt.card.reader != self.reader_box.currentText():
                if self.mgmt:
                    self.mgmt.close()
                self.mgmt = Management.open(self.reader_box.currentText())
            # (no transaction: the GUI thread must not wait for another program's)
            self.info = self.mgmt.info(lock=False)
        except Exception as e:
            self.mgmt = None
            self.statusBar().showMessage(str(e))
            self.keys_tab.show_info(None)
            self.manager_tab.show_info(None)
            return
        self._show_info(self.info)

    def _show_info(self, info):
        yn = lambda v: T("yes") if v else T("no")
        for key, lbl in self.dev_labels.items():
            lbl.setText(str(info.get(key, "-")))
        for key, lbl in self.sec_labels.items():
            v = info["security"].get(key)
            lbl.setText(v if isinstance(v, str) else yn(v))
        self.statusBar().showMessage("%s  %s" % (self.reader_box.currentText(), info.get("boot_message", "")))
        for p in info.get("profiles", []):
            r = p["index"]
            self.table.setItem(r, 0, QTableWidgetItem(str(r + 1)))
            swatch = QTableWidgetItem("")
            swatch.setBackground(QColor("#" + p["color"]))
            self.table.setItem(r, 1, swatch)
            self.table.setItem(r, 2, QTableWidgetItem(display_name(p["name"]) if p["used"] else ""))
            state = T("empty")
            if p["used"]:
                state = T("active") if r == info.get("active") else T("in use")
            self.table.setItem(r, 3, QTableWidgetItem(state))
            export = T("secure profile") if p["used"] and p.get("secure") else \
                (T("blocked") if p["no_export"] else T("allowed"))
            self.table.setItem(r, 4, QTableWidgetItem(export))
        if "button_slots" in info:
            self.slots_spin.setValue(info["button_slots"])
        fw = info.get("firmware_slot")
        if fw:
            text = T("Running %s in slot %s.") % (fw["version"], fw["slot"])
            if fw["unconfirmed"]:
                text += " " + T("Unconfirmed: the next restart goes back to the previous firmware.")
            elif fw["rollback_possible"]:
                text += " " + T("The previous firmware can be restored.")
            self.fw_state.setText(text)
            self.fw_state.setStyleSheet("color:#b70;" if fw["unconfirmed"] else "")
        self.security_tab.show_info(info)
        self.keys_tab.show_info(info)
        self.manager_tab.show_info(info)

    def _show_health(self, h):
        for i, (key, title) in enumerate(HEALTH_LABELS.items()):
            self.health_table.setItem(i, 0, QTableWidgetItem(T(title)))
            self.health_table.setItem(i, 1, QTableWidgetItem(str(h.get(key, "-"))))
        if h.get("uncorrectable") or h.get("lifetime_uncorrectable"):
            state, colour = T("Damaged"), "#b00"
        elif h.get("repaired_from_copy") or h.get("corrected_ecc") or h.get("lifetime_repairs"):
            state, colour = T("Repaired"), "#b70"
        else:
            state, colour = T("Healthy"), "#080"
        self.health_state.setText(state)
        self.health_state.setStyleSheet("font-size:16px;font-weight:bold;color:%s;" % colour)

    def _selected_slot(self):
        rows = self.table.selectionModel().selectedRows()
        return rows[0].row() if rows else None

    def _ready(self):
        """No operation running and a device connected (says so otherwise)."""
        if self.busy:
            self._turned_away()
            return False
        if self.mgmt is None:
            QMessageBox.warning(self, T("Error"), T("No device"))
            return False
        return True

    def _turned_away(self):
        """What the user asked for cannot start now: another operation runs.
        Its banner says so; a quiet one (see _run) has none, so one is shown
        now, or the click would do nothing without a word (or wait for it
        without one: the OATH page starts the user's operation once its own
        recalculation ended). It goes when the operation ends."""
        if self.busy and self._quiet:
            self.banner.setText(T("Busy with work in the background..."))
            self.banner.setVisible(True)

    def _change_touch(self):
        """Whether a name, colour, button slot or board change needs a touch:
        once the free changes (INFO key 18) are used up (unknown: assume so)."""
        left = (self.info or {}).get("free_changes")
        return left is None or left == 0

    def _update_pin(self):
        """PIN typed for a firmware update or rollback and the ROM loader, and
        whether the device checks none (safe mode: its key storage is not
        open). The field is emptied at once: a PIN typed once must not serve
        a later click by someone else at this computer."""
        typed = self.fw_pin.text()
        self.fw_pin.clear()
        if (self.info or {}).get("boot_status", "ok") != "ok":
            return None, True
        return typed, False

    # -- actions -------------------------------------------------------------
    def _reboot(self, bootloader):
        typed, no_pin = self._update_pin()
        if not self._ready():
            return
        if not bootloader:
            self._run(lambda p: self.mgmt.reboot(), touch=True, reboots=True)
            return
        if (self.info or {}).get("protocol", 1) < 2:
            typed, no_pin = None, True          # older firmware: no PIN for the ROM loader
        self._run_pin(lambda pin, no_pin, p: self.mgmt.reboot(bootloader=True, pin=pin, no_pin=no_pin),
                      typed, no_pin)

    def _update_firmware(self):
        typed_pin, no_pin = self._update_pin()
        if self.busy:
            self._turned_away()
            return
        if self.mgmt is None or not self.info:
            return
        path, _ = QFileDialog.getOpenFileName(self, T("Firmware image"), "", "Firmware (*.bin);;*")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                image = f.read()
            desc = firmware.parse(image)
        except (OSError, firmware.FirmwareError) as e:
            QMessageBox.critical(self, T("Error"), _plain(str(e)))
            return
        running = self.info.get("firmware_slot", {}).get("version", self.info["firmware"])
        question = T("Install firmware %s (%s, %s build) over %s?\n\nKey storage is not touched. If the new "
                     "firmware does not start, the key returns to the current one at the next restart.") % (
            desc["version"], desc["platform"], desc["build_profile"], display_name(running))
        if QMessageBox.question(self, T("Firmware update"), _plain(question)) != QMessageBox.StandardButton.Yes:
            return
        try:
            downgrade = firmware.compare(desc["version_tuple"], tuple(int(x) for x in running.split("."))) < 0
        except ValueError:
            downgrade = False                   # the device decides
        if downgrade and QMessageBox.question(
                self, T("Firmware update"),
                T("This image is older than the running firmware. Install it anyway?")) != QMessageBox.StandardButton.Yes:
            return
        self._run_pin(lambda pin, no_pin, p: self.mgmt.update_firmware(image, pin=pin, allow_downgrade=downgrade,
                                                                       progress=p, no_pin=no_pin),
                      typed_pin, no_pin,
                      then=lambda r: (QMessageBox.warning(self, T("Firmware update"), _plain(r["warning"]))
                                      if r.get("warning") else
                                      QMessageBox.information(self, T("Firmware updated"), r["installed"])),
                      refresh=True)

    def _confirm_firmware(self):
        self.fw_pin.clear()                     # a PIN typed here is not kept for a later click
        self._run(lambda p: self.mgmt.confirm_firmware(), refresh=True)

    def _rollback_firmware(self):
        typed, no_pin = self._update_pin()
        if not self._ready():
            return
        if (self.info or {}).get("protocol", 1) < 2:
            typed, no_pin = None, True          # older firmware: no PIN for a rollback
        self._run_pin(lambda pin, no_pin, p: self.mgmt.rollback_firmware(pin=pin, no_pin=no_pin),
                      typed, no_pin, refresh=True)

    def _factory_reset(self):
        text, ok = QInputDialog.getText(self, T("Factory reset..."), T("Type 'erase' to erase every profile and key:"))
        if ok and text == "erase":
            self._run(lambda p: self.mgmt.factory_reset(), touch=True, reboots=True)

    def _switch(self):
        s = self._selected_slot()
        if s is not None:
            self._run(lambda p: self.mgmt.select_profile(s), touch=True, reboots=True)

    def _rename(self):
        s = self._selected_slot()
        if s is None:
            return
        name, ok = QInputDialog.getText(self, T("Rename..."), T("Profile name:"))
        if ok:
            name = clip_name(name)              # the slot holds 23 bytes of UTF-8
            self._run(lambda p: self.mgmt.set_profile(s, name=name), touch=self._change_touch(), refresh=True)

    def _colour(self):
        s = self._selected_slot()
        if s is None:
            return
        c = QColorDialog.getColor(parent=self)
        if c.isValid():
            hexc = "%02x%02x%02x" % (c.red(), c.green(), c.blue())
            self._run(lambda p: self.mgmt.set_profile(s, color=hexc), touch=self._change_touch(), refresh=True)

    def _profile(self, s):
        """What the device reported about slot s (None in safe mode)."""
        profiles = (self.info or {}).get("profiles") or []
        return profiles[s] if s is not None and s < len(profiles) else None

    def _toggle_export(self):
        s = self._selected_slot()
        prof = self._profile(s)
        if prof is None:
            return
        blocked = prof["no_export"]
        self._run(lambda p: self.mgmt.set_profile(s, no_export=not blocked), touch=True, refresh=True)

    def _wipe(self):
        s = self._selected_slot()
        if s is None:
            return
        prof = self._profile(s)
        used = bool(prof and prof["used"])
        if used and QMessageBox.question(self, T("Create / wipe"), T("Create / wipe") + " %d ?" % (s + 1)) \
                != QMessageBox.StandardButton.Yes:
            return
        self._run(lambda p: self.mgmt.wipe_profile(s), touch=True, reboots=True)     # (creating one too)

    def _delete(self):
        s = self._selected_slot()
        if s is None:
            return
        if QMessageBox.question(self, T("Delete"), T("Delete") + " %d ?" % (s + 1)) == QMessageBox.StandardButton.Yes:
            self._run(lambda p: self.mgmt.delete_profile(s), touch=True, reboots=True)

    def _export(self):
        # Take the secrets out of the fields at once, whatever happens next:
        # nothing typed is kept for a later click by someone else.
        encrypt = self.enc_check.isChecked()
        pass1, pass2, typed_pin = self.pass1.text(), self.pass2.text(), self.pin_edit.text()
        for field in (self.pass1, self.pass2, self.pin_edit):
            field.clear()
        if not self._ready():
            return
        passphrase = None
        if encrypt:
            if pass1 != pass2 or not pass1:
                QMessageBox.warning(self, T("Error"), T("Passphrases differ") if pass1 != pass2 else
                                    T("Enter a passphrase"))
                return
            passphrase = pass1
        elif QMessageBox.question(
                self, T("Export to file..."),
                T("The backup will NOT be encrypted: anyone with the file has your keys. Continue?"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        path, _ = QFileDialog.getSaveFileName(self, T("Export to file..."), "librefido-profile.lfbk",
                                              "LibreFido backup (*.lfbk)")
        if not path:
            return
        encrypted = passphrase is not None

        def export(pin, no_pin, progress):
            stream = self.mgmt.export_profile(pin=pin, progress=progress, no_pin=no_pin)
            notes = []
            write_file(path, stream, passphrase, warn=notes.append)
            return path, notes

        def done(r):                            # (holds no secret: it lives as long as the Job)
            p, notes = r
            msg = T("Backup file written") + T(":") + "\n" + p
            if not encrypted:
                msg += "\n\n" + T("NOT encrypted: anyone with this file has your keys.")
            for n in notes:
                msg += "\n\n" + n
            QMessageBox.information(self, T("Done"), _plain(msg))
        self._run_pin(export, typed_pin, False, then=done)

    def _load_backup(self, title, then, path=None):
        """Reads a backup file (asked for unless path is given), asks for its
        passphrase and verifies it in a worker thread (the key derivation
        takes a while); then(info, stream, path) runs afterwards on the GUI
        thread. Returns whether it started."""
        if path is None:
            path, _ = QFileDialog.getOpenFileName(self, title, "", "LibreFido backup (*.lfbk)")
            if not path:
                return False
        try:
            with open(path, "rb") as f:
                blob = f.read()                 # read once: the file cannot change between the steps
            head, _ = read_file(blob)
        except (BackupError, OSError) as e:
            QMessageBox.critical(self, T("Error"), _plain(str(e)))
            return False
        if head["encrypted"]:
            pw, ok = QInputDialog.getText(self, T("Passphrase"), T("Passphrase") + T(":"), QLineEdit.EchoMode.Password)
            if not ok:
                return False
            work = lambda p: read_file(blob, pw, require_encryption=True)   # noqa: E731
        else:
            work = lambda p: read_file(blob)    # noqa: E731
        return self._run(work, then=lambda r: then(r[0], r[1], path), device=False)

    def _verify_file(self):
        # Forget the previous backup first: a file that fails to load (or a
        # cancelled dialog) must not leave it in place for the device checks.
        if self.busy:
            self._turned_away()
            return
        self.loaded_path = None
        self.verify_out.clear()
        self._load_backup(T("Open and verify..."), self._show_verified)

    def _show_verified(self, info, stream, path):
        s = info["summary"]
        h = s["header"]
        title, notes = T("Backup OK"), []
        running = (self.info or {}).get("firmware")
        if running and not firmware_supports(running, h["min_firmware"]):
            title = T("Warning")
            notes.append(T("The connected device (firmware %s) cannot import it: it needs %s or newer.")
                         % (display_name(running), h["min_firmware"]))
        elif not running and not firmware_supports(__version__, h["min_firmware"]):
            title = T("Warning")
            notes.append(T("This backup needs firmware %s or newer.") % h["min_firmware"])
        if not info["encrypted"]:
            notes.append(T("NOT encrypted: nothing proves this file was not modified."))
        lines = [title, path] + notes + [
                 "", "UUID: %s" % h["uuid"], T("%s: %s") % (T("Name"), display_name(h["name"])),
                 "Serial: %s" % h["serial"], "Firmware: %s (min %s)" % (h["firmware"], h["min_firmware"]),
                 "Encrypted: %s" % info["encrypted"], "Root key: %s" % s["root_key"],
                 "Files: %d" % s["files"], "FIDO resident credentials: %d" % s["resident_credentials"],
                 "OATH credentials: %d" % s["oath_credentials"], "Counters: %s" % s["counters"],
                 "By application: %s" % s["by_application"]]
        self.verify_out.setPlainText("\n".join(lines))
        self.loaded_path = path             # only the path: the stream is not kept

    def _cannot_import(self, h):
        """True (after saying so) when the connected device cannot import a
        backup with header h: its firmware is older than the backup needs."""
        running = (self.info or {}).get("firmware")
        if running and not firmware_supports(running, h["min_firmware"]):
            QMessageBox.critical(self, T("Error"), _plain(
                T("The connected device (firmware %s) cannot import it: it needs %s or newer.")
                % (display_name(running), h["min_firmware"])))
            return True
        return False

    def _device_check(self, restore_test):
        if not self._ready():
            return

        def check(info, stream, path):
            if not self._ready() or self._cannot_import(info["summary"]["header"]):
                return
            name = os.path.basename(path)
            if restore_test:
                self._run(lambda p: self.mgmt.restore_test(stream, progress=p)[1],
                          then=lambda ok: QMessageBox.information(
                              self, T("Done"), (T("Restore test passed: the backup can be restored.") if ok else
                                                T("Restore test FAILED.")) + "\n" + name), touch=True, refresh=True)
            else:
                self._run(lambda p: self.mgmt.check_backup(stream, progress=p),
                          then=lambda r: QMessageBox.information(
                              self, T("Done"), T("The firmware accepts this backup.") + "\n" + name))
        # The last verified file is read (and decrypted) again: its stream was not kept.
        self._load_backup(T("Open and verify..."), check, path=self.loaded_path)

    def _import(self):
        if not self._ready():
            return
        self._load_backup(T("Import..."), self._import_loaded)

    def _import_loaded(self, info, stream, path):
        if not self._ready():
            return
        yes, no = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
        if not info["encrypted"] and QMessageBox.warning(
                self, T("Import..."), T("This backup is NOT encrypted, so nothing proves it was not replaced by "
                                        "someone who could write the file. Import it anyway?"),
                yes | no, no) != yes:
            return
        h = info["summary"]["header"]
        if self._cannot_import(h):
            return
        backup = T("%s (%s, UUID %s, %d files)") % (display_name(os.path.basename(path)),
                                                    display_name(h["name"]) or "-", h["uuid"], info["summary"]["files"])
        target = self.target_spin.value() - 1
        prof = self._profile(target)
        # The first line is fixed text: Qt then shows the names as plain text.
        if prof and prof["used"]:
            question = T("Replace slot %d?") % (target + 1) + "\n\n" + \
                T("Slot %d (%s) is in use. Importing %s replaces it and erases its keys for good.") % (
                    target + 1, display_name(prof["name"]) or "-", backup)
        else:
            question = T("Import into slot %d?") % (target + 1) + "\n\n" + backup
        if QMessageBox.question(self, T("Import..."), question, yes | no, no) != yes:
            return
        # (an import into the active profile asks for its FIDO PIN from protocol 3 on)
        self._run_pin(lambda pin, no_pin, p: self.mgmt.import_profile(stream, target, progress=p, pin=pin,
                                                                      no_pin=no_pin),
                      None, False,
                      then=lambda r: QMessageBox.information(self, T("Done"), T("Imported: %d files") % r["files"]),
                      refresh=True)


# ----------------------------------------------------------------------------
# Keys tab: single keys (docs/KEY_TRANSFER.md)
# ----------------------------------------------------------------------------

def _key_file_name(app, name):
    """Suggested file name (without suffix) for a key named name."""
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:40].strip("._")
    return "%s-%s" % (app, safe or "key")


class KeyPassphraseDialog(QDialog):
    """Passphrase for a key file to write: encrypted by default; the key in
    the clear needs the box ticked and a second confirmation."""

    def __init__(self, parent, T):
        super().__init__(parent)
        self.T = T
        self.ok = False
        self.passphrase = None
        self.setWindowTitle(T("Key file passphrase"))
        form = QFormLayout(self)
        self.pass1 = QLineEdit()
        self.pass2 = QLineEdit()
        for field in (self.pass1, self.pass2):
            field.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow(T("Passphrase") + T(":"), self.pass1)
        form.addRow(T("Repeat passphrase") + T(":"), self.pass2)
        self.plain = QCheckBox(T("Do not encrypt (anyone with the file has the key)"))
        self.plain.toggled.connect(self._plain_toggled)
        form.addRow(self.plain)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _plain_toggled(self, on):
        for field in (self.pass1, self.pass2):
            field.setEnabled(not on)
            if on:
                field.clear()

    def _accept(self):
        T = self.T
        p1, p2 = self.pass1.text(), self.pass2.text()
        self.pass1.clear()
        self.pass2.clear()
        if self.plain.isChecked():
            yes, no = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
            if QMessageBox.question(self, T("Key file passphrase"),
                                    T("The key will NOT be encrypted: anyone with the file has your key. Continue?"),
                                    yes | no, no) != yes:
                return
            self.passphrase = None
        elif p1 != p2 or not p1:
            QMessageBox.warning(self, T("Error"), T("Passphrases differ") if p1 != p2 else T("Enter a passphrase"))
            return
        else:
            self.passphrase = p1
        self.ok = True
        self.accept()

    @classmethod
    def get(cls, parent, T):
        """(True, passphrase), passphrase None for a key in the clear
        (confirmed twice), or (False, None) when cancelled."""
        dlg = cls(parent, T)
        try:
            dlg.exec()
            return (True, dlg.passphrase) if dlg.ok else (False, None)
        finally:
            dlg.passphrase = None
            dlg.deleteLater()


class KeysTab(QWidget):
    """'Keys' tab: the single keys of the active profile (docs/KEY_TRANSFER.md):
    list them, export one to a file, add one from a file, an otpauth:// link
    or a QR code image. Device work, key files that take a while to decrypt
    and QR codes run in the main window's worker (MainWindow._run / _run_pin).
    A key and the secrets typed for it live only as long as one operation;
    the list holds no secrets."""

    def __init__(self, window):
        super().__init__()
        self.w = window
        self.rows = []                  # (application, KEY_LIST entry) of each table row
        self.exportable = None
        self.listed_for = None          # the device and profile the list is of (_identity)
        lay = QVBoxLayout(self)
        top = QHBoxLayout()
        top.addWidget(QLabel(T("Application") + T(":")))
        self.app_box = QComboBox()
        self.app_box.addItem(T("All applications"), None)
        for app in APPS:
            self.app_box.addItem(T(KEY_APP_TITLES[app]), app)
        top.addWidget(self.app_box, 1)
        self.refresh_btn = QPushButton(T("Refresh"))
        self.refresh_btn.clicked.connect(lambda: self.refresh_keys())
        top.addWidget(self.refresh_btn)
        # shown after a FIDO listing without the PIN, which leaves passkeys out
        self.pin_btn = QPushButton(T("List with FIDO PIN..."))
        self.pin_btn.clicked.connect(self.refresh_with_pin)
        self.pin_btn.setVisible(False)
        top.addWidget(self.pin_btn)
        lay.addLayout(top)
        self.state = QLabel(T("keys-hint"))
        self.state.setTextFormat(Qt.TextFormat.PlainText)
        self.state.setWordWrap(True)
        lay.addWidget(self.state)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels([T("Application"), T("Key"), T("Details")])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        for text, slot in ((T("Export selected..."), self.export_selected), (T("Import file..."), self.import_file),
                           (T("Import otpauth link..."), self.import_link),
                           (T("Import QR image..."), self.import_qr)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            row.addWidget(b)
        lay.addLayout(row)

    # -- list ------------------------------------------------------------------
    def _identity(self):
        info = self.w.info or {}
        return self.w.reader_box.currentText(), info.get("chip_serial"), info.get("serial"), info.get("active")

    def _clear(self, text):
        self.rows, self.exportable, self.listed_for = [], None, None
        self.table.setRowCount(0)
        self.state.setText(text)
        self.pin_btn.setVisible(False)

    def show_info(self, info):
        """After the main window refreshed: the list of another device or
        profile (or of none) is dropped."""
        if self.listed_for is not None and (info is None or self._identity() != self.listed_for):
            self._clear(T("keys-hint"))

    def refresh_keys(self, pin=None):
        """Lists the keys (in the worker). pin: the FIDO PIN to list with;
        without one it is asked for when the profile has one, and a profile
        without one lists FIDO without it (credProtect 1 passkeys only,
        without user names: the state says so, and pin_btn lists again with
        a PIN)."""
        w = self.w
        if not w._ready():
            return
        only = self.app_box.currentData()
        identity = self._identity()

        def listing(pin, no_pin, progress):
            support = w.mgmt.key_transfer()["export"]
            apps = [a for a in APPS if a in support and only in (None, a)]
            return (support,) + list_all_keys(w.mgmt, apps, pin, no_pin) + (bool(pin),)

        def banner(pin):
            # The device never lists more than the application gives out
            # without its secret: FIDO without the PIN, OATH with a password.
            touch = any(w.mgmt.list_needs_touch(a, pin) for a in APPS if only in (None, a))
            return T("If the key blinks, touch it to list the keys...") if touch else None
        w._run_pin(listing, pin, False, then=lambda r: self._show(identity, *r), touch=False, banner=banner)

    def refresh_with_pin(self):
        """Lists again with the FIDO PIN, asked for here: FIDO then lists the
        passkeys that need user verification too, with user names."""
        if not self.w._ready():
            return
        pin, ok = QInputDialog.getText(self, T("FIDO PIN"), T("FIDO PIN of the active profile:"),
                                       QLineEdit.EchoMode.Password)
        if not ok:
            return
        if not pin:
            QMessageBox.warning(self, T("Error"), T("Enter the FIDO PIN."))
            return
        self.refresh_keys(pin)

    def _show(self, identity, support, rows, exportable, listed, with_pin=False):
        self.rows, self.exportable, self.listed_for = rows, exportable, identity
        self.table.setRowCount(len(rows))
        for r, (app, entry) in enumerate(rows):
            name, details = key_entry_text(app, entry, T)
            for c, text in enumerate((T(KEY_APP_TITLES[app]), name, details)):
                self.table.setItem(r, c, QTableWidgetItem(text))
        if not support:
            state = T("no-key-transfer")
        elif not listed:
            state = T("This firmware lists no keys of this application.")
        else:
            state = T("Secret keys of this profile can be exported.") if exportable else T("not-exportable")
        text = "%s %s" % (T("Keys listed: %d") % len(rows), state) if listed else state
        # FIDO without a verified PIN lists the credProtect 1 passkeys only, without user names
        without_pin = "fido" in listed and not with_pin
        if without_pin:
            text += "\n" + T("fido-listed-without-pin")
        self.state.setText(text)
        self.pin_btn.setVisible(without_pin)

    def _selected(self):
        rows = self.table.selectionModel().selectedRows()
        return self.rows[rows[0].row()] if rows and rows[0].row() < len(self.rows) else None

    # -- export ----------------------------------------------------------------
    def export_selected(self):
        w = self.w
        if not w._ready():
            return
        selected = self._selected()
        if selected is None:
            QMessageBox.warning(self, T("Export selected..."), T("Select a key first."))
            return
        if self.listed_for != self._identity():
            self._clear(T("keys-hint"))
            QMessageBox.warning(self, T("Export selected..."), T("The device or profile changed: Refresh lists its keys."))
            return
        if not self.exportable:
            QMessageBox.warning(self, T("Export selected..."), T("not-exportable"))
            return
        app, entry = selected
        key_id = entry.get(1)
        if not isinstance(key_id, bytes) or not key_id:
            QMessageBox.critical(self, T("Error"), T("malformed entry"))
            return
        yes, no = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
        formats = [("lfkey", T("LibreFido key file (.lfkey, encrypted)"))]
        if app == "oath":
            formats.append(("otpauth", T("otpauth:// link (NOT encrypted)")))
        if app == "piv":
            formats.append(("pem", T("PEM file (PKCS#8, encrypted)")))
        fmt = "lfkey"
        if len(formats) > 1:
            choice, ok = QInputDialog.getItem(self, T("Export selected..."), T("File format:"),
                                              [text for _, text in formats], 0, False)
            if not ok:
                return
            fmt = next((f for f, text in formats if text == choice), "lfkey")
        if fmt == "otpauth":
            if QMessageBox.question(self, T("Export selected..."), T("otpauth-plain"), yes | no, no) != yes:
                return
            passphrase = None
        else:
            ok, passphrase = KeyPassphraseDialog.get(self, T)
            if not ok:
                return
        admin = None
        if app == "openpgp":
            admin, ok = QInputDialog.getText(self, T("OpenPGP Admin PIN"), T("OpenPGP Admin PIN:"),
                                             QLineEdit.EchoMode.Password)
            if not ok:
                return
            if not admin:
                QMessageBox.warning(self, T("Error"), T("The OpenPGP Admin PIN is needed."))
                return
        suffix = {"lfkey": SUFFIX, "pem": ".pem", "otpauth": ".txt"}[fmt]
        path, _ = QFileDialog.getSaveFileName(self, T("Export selected..."),
                                              _key_file_name(app, key_entry_text(app, entry)[0]) + suffix,
                                              "%s (*%s)" % (T("Key files"), suffix))
        if not path:
            return
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
                msg += "\n\n" + T("fido-counter-export")
            for n in notes:
                msg += "\n\n" + n
            QMessageBox.information(self, T("Done"), _plain(msg))
        w._run_pin(export, None, False, then=done)

    # -- import ----------------------------------------------------------------
    def import_file(self):
        if not self.w._ready():
            return
        path, _ = QFileDialog.getOpenFileName(
            self, T("Import file..."), "",
            "%s (*%s *.pem *.der *.key *.p12 *.pfx *.asc *.gpg *.pgp *.txt *.png *.jpg *.jpeg *.gif *.webp);;%s (*)"
            % (T("Key files"), SUFFIX, T("All files")))
        if not path:
            return
        try:
            data, kind = read_key_source(path)
        except (OSError, stdformats.FormatError) as e:
            QMessageBox.critical(self, T("Error"), _plain(str(e)))
            return
        if kind == "lfkey":
            self._open_key_file(data)
        elif kind == "links":
            self._import_links(data.decode("utf-8", "replace").splitlines())
        elif kind == "image":
            self._decode_qr(path)
        elif kind == "piv":
            self._open_piv(path, data)
        elif kind == "openpgp":
            self._open_pgp(path, data)
        else:
            QMessageBox.critical(self, T("Error"), T("unknown-source"))

    def import_link(self):
        if not self.w._ready():
            return
        text, ok = QInputDialog.getText(self, T("Import otpauth link..."), T("otpauth:// or otpauth-migration:// link:"),
                                        QLineEdit.EchoMode.Password)       # the link holds the secret
        if ok and text.strip():
            self._import_links([text])

    def import_qr(self):
        if not self.w._ready():
            return
        path, _ = QFileDialog.getOpenFileName(self, T("Import QR image..."), "",
                                              "%s (*.png *.jpg *.jpeg *.gif *.bmp *.webp);;%s (*)"
                                              % (T("Images"), T("All files")))
        if path:
            self._decode_qr(path)

    def _decode_qr(self, path):
        self.w._run(lambda p: qr_links(path), then=lambda r: self._import_links(*r), device=False)

    def _import_links(self, texts, others=0):
        try:
            keys, left_out, missing = oath_keys_from_links(texts)
        except stdformats.FormatError as e:
            QMessageBox.critical(self, T("Error"), _plain(str(e)))
            return
        notes = [T("left-out") % why for why in left_out]
        notes += [T("missing-qr") % ", ".join(map(str, numbers)) for numbers in missing.values()]
        if others:
            notes.append(T("others-qr") % others)
        self._confirm_import(keys, notes)

    def _open_key_file(self, data):
        try:
            info, _ = read_key_file(data)
        except BackupError as e:
            QMessageBox.critical(self, T("Error"), _plain(str(e)))
            return
        if info["encrypted"]:
            pw, ok = QInputDialog.getText(self, T("Passphrase"), T("Passphrase") + T(":"), QLineEdit.EchoMode.Password)
            if not ok:
                return
            work = lambda p: read_key_file(data, pw, require_encryption=True)[1]     # noqa: E731 (scrypt: a while)
        else:
            yes, no = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
            if QMessageBox.warning(self, T("Import file..."), T("key-file-plain"), yes | no, no) != yes:
                return
            work = lambda p: read_key_file(data)[1]                                 # noqa: E731
        self.w._run(work, then=lambda key: self._confirm_import([key]), device=False)

    def _ask_file_password(self, label, retry):
        """on_error of reading a protected key file: asks for its password
        (label) and calls retry(password)."""
        def on_error(e):
            if not isinstance(e, stdformats.PassphraseRequired):
                return False
            pw, ok = QInputDialog.getText(self, T("Import file..."), label, QLineEdit.EchoMode.Password)
            if ok:
                retry(pw)
            return True
        return on_error

    def _open_piv(self, path, data, password=None):
        self.w._run(lambda p: stdformats.load_piv_key(data, password), then=self._piv_loaded,
                    on_error=self._ask_file_password(T("Password of %s:") % os.path.basename(path),
                                                     lambda pw: self._open_piv(path, data, pw)), device=False)

    def _piv_loaded(self, found):
        record, cert = found[0]
        if len(found) > 1:
            items = ["%d: %s" % (i + 1, keyio.describe(SingleKey("piv", r))) for i, (r, _) in enumerate(found)]
            choice, ok = QInputDialog.getItem(self, T("Choose the key"), T("Key of the file:"), items, 0, False)
            if not ok:
                return
            record, cert = found[items.index(choice)]
        if cert:
            record[8] = cert
        self._confirm_import([SingleKey("piv", record)])

    def _open_pgp(self, path, data, passphrase=None):
        self.w._run(lambda p: stdformats.parse_openpgp_secret(data, passphrase), then=self._pgp_loaded,
                    on_error=self._ask_file_password(T("Passphrase of the OpenPGP key:"),
                                                     lambda pw: self._open_pgp(path, data, pw)), device=False)

    def _pgp_loaded(self, found):
        usable = [k for k in found if k["record"] is not None and not k["revoked"]]
        if not usable:
            QMessageBox.critical(self, T("Error"), T("No key of this file can go onto the device.") + "\n\n" + "\n".join(
                T("%s: %s") % (pgp_key_text(k), T("revoked") if k["revoked"] else k["unsupported"]) for k in found))
            return
        k = usable[0]
        if len(usable) > 1:
            items = ["%d: %s" % (i + 1, pgp_key_text(k)) for i, k in enumerate(usable)]
            choice, ok = QInputDialog.getItem(self, T("Choose the key"), T("Key of the file:"), items, 0, False)
            if not ok:
                return
            k = usable[items.index(choice)]
        hint = next((s for s in PGP_SLOTS if s in k["usage"]), None)
        self._confirm_import([SingleKey("openpgp", k["record"])], slot_hint=hint)

    def _confirm_import(self, keys, notes=(), slot_hint=None):
        """Shows what is added and asks for what the application needs
        (slot, its secret), then adds keys (of one application) in the
        worker."""
        if not keys or not self.w._ready():
            return
        app = keys[0].app
        what = "\n".join(keyio.describe(k) for k in keys)
        if app == "fido":
            question = T("Add this passkey to the device?") + "\n\n" + what + "\n\n" + T("fido-counter-import")
        elif len(keys) > 1:
            question = T("Add %d OATH accounts to the device?") % len(keys) + "\n\n" + what
        else:
            question = T("Add this key to the device?") + "\n\n" + what
        for n in notes:
            question += "\n\n" + n
        yes, no = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
        if QMessageBox.question(self, T("Keys"), question, yes | no, no) != yes:
            return
        opts = self._import_options(app, keys[0].record, slot_hint)
        if opts is not None:
            self._run_import(keys, opts, False)

    def _import_options(self, app, record, slot_hint):
        """keyio.import_single options of app: its slot and secret, asked
        for; None when cancelled."""
        password = QLineEdit.EchoMode.Password
        if app == "otp":
            slot, ok = QInputDialog.getItem(self, T("Keys"), T("OTP slot:"), ["1", "2"],
                                            1 if record.get(1) == 2 else 0, False)
            if not ok:
                return None
            code, ok = QInputDialog.getText(self, T("OTP access code"), T("Access code of OTP slot %s (12 hex digits; "
                                                                          "leave empty if it has none):") % slot,
                                            password)
            return {"target": int(slot), "otp_access_code": code.strip() or None} if ok else None
        if app == "oath":
            pw, ok = QInputDialog.getText(self, T("OATH password"),
                                          T("OATH password (leave empty if the OATH application has none):"), password)
            return {"oath_password": pw or None} if ok else None
        if app == "openpgp":
            refs = list(PGP_SLOTS)
            names = [T(PGP_SLOT_TITLES[r]) for r in refs]
            current = record.get(1)
            default = refs.index(slot_hint) if slot_hint in refs else current - 1 if current in (1, 2, 3) else 0
            choice, ok = QInputDialog.getItem(self, T("Keys"), T("OpenPGP key slot:"), names, default, False)
            if not ok:
                return None
            pin, ok = QInputDialog.getText(self, T("OpenPGP Admin PIN"), T("OpenPGP Admin PIN:"), password)
            if not ok:
                return None
            if not pin:
                QMessageBox.warning(self, T("Error"), T("The OpenPGP Admin PIN is needed."))
                return None
            return {"pgp_key_ref": refs[names.index(choice)], "pgp_admin_pin": pin}
        if app == "piv":
            slots = ["%02X" % s for s in keyio.PIV_SLOTS]
            current = "%02X" % record[1] if type(record.get(1)) is int else None
            choice, ok = QInputDialog.getItem(self, T("Keys"), T("PIV slot:"), slots,
                                              slots.index(current) if current in slots else 0, False)
            if not ok:
                return None
            key, ok = QInputDialog.getText(self, T("PIV management key"),
                                           T("PIV management key (hex; leave empty for the default key):"), password)
            return {"piv_slot": int(choice, 16), "piv_mgmt_key": key.strip() or None} if ok else None
        return {}

    def _run_import(self, keys, opts, replace):
        w = self.w

        def add(pin, no_pin, progress):
            results = []
            for key in keys:
                try:
                    text = keyio.import_single(w.mgmt, key, pin=pin, no_pin=no_pin, replace=replace, **opts)
                    results.append((key, text, None))
                except KeyTransferError as e:
                    results.append((key, None, e))
            return results
        # FIDO and OTP go through the management applet: a touch and the FIDO PIN.
        w._run_pin(add, None, False, then=lambda results: self._imported(results, opts),
                   touch=keys[0].app in ("fido", "otp"))

    def _imported(self, results, opts):
        added = [text for _, text, e in results if e is None]
        there = [(key, e) for key, _, e in results if e is not None and already_there(e)]
        failed = [e for _, _, e in results if e is not None and not already_there(e)]
        if added and self.listed_for is not None:
            self._clear(T("The keys changed: Refresh lists them again."))
        parts = []
        if added:
            parts.append(T("Imported") + T(":") + "\n" + "\n".join(added))
        if failed:
            parts.append(T("Not imported") + T(":") + "\n" + "\n".join(str(e) for e in failed))
        if failed:
            QMessageBox.critical(self, T("Error"), "\n\n".join(parts))
        elif added:
            QMessageBox.information(self, T("Done"), "\n\n".join(parts))
        if there:
            yes, no = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
            question = T("Replace what is on the device?") + "\n\n" + "\n".join(str(e) for _, e in there) + \
                "\n\n" + T("What is there now is erased for good.")
            if QMessageBox.question(self, T("Keys"), question, yes | no, no) == yes:
                self._run_import([key for key, _ in there], opts, True)


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
