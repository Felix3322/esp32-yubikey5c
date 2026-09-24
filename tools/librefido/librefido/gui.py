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
    QAbstractItemView, QApplication, QCheckBox, QColorDialog, QComboBox, QFileDialog, QFormLayout,
    QGroupBox, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit,
    QVBoxLayout, QWidget,
)

from smartcard.Exceptions import CardConnectionException

from . import __version__, firmware, gui_policy, provision
from .backup import BackupError, firmware_supports, read_file, write_file
from .mgmt import Management, PinRequired, clip_name, display_name
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

_LANG_ZH = (locale.getlocale()[0] or os.environ.get("LANG", "")).lower().startswith("zh") or \
    os.environ.get("LIBREFIDO_LANG", "").lower().startswith("zh")


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
                provision.ProvisionError) as e:
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
            form.addRow(T(title) + ":", lbl)
        lay.addLayout(form)
        sec = QGroupBox(T("Chip security"))
        sform = QFormLayout(sec)
        self.sec_labels = {}
        for key, title in (("secure_boot", "Secure Boot"), ("flash_encryption", "Flash encryption"),
                           ("jtag_disabled", "JTAG disabled"), ("root_key", "Root key")):
            lbl = QLabel("-")
            lbl.setTextFormat(Qt.TextFormat.PlainText)
            self.sec_labels[key] = lbl
            sform.addRow(T(title) + ":", lbl)
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
        f.addRow(T("Passphrase") + ":", self.pass1)
        f.addRow(T("Repeat passphrase") + ":", self.pass2)
        f.addRow(T("FIDO PIN of the profile (if set)") + ":", self.pin_edit)
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
    def _run(self, fn, then=None, touch=False, reboots=False, refresh=False, on_error=None, device=True):
        """Runs fn(progress) in a worker thread. Afterwards, on the GUI
        thread: then(result), or on_error(exception), which returns True when
        it handled the failure (otherwise the error is shown). device=False
        for work without a device (backup files). Returns whether it started."""
        if self.busy:
            return False
        if device and self.mgmt is None:
            QMessageBox.warning(self, T("Error"), T("No device"))
            return False
        self.busy = True
        self.banner.setText(T("Touch the key now (it blinks yellow)...") if touch else T("Working..."))
        self.banner.setVisible(True)
        self.progress.setVisible(False)

        def work(progress):
            r = fn(progress)
            if reboots:
                self.mgmt.reconnect()
            return r
        job = Job(work)
        job.setAutoDelete(False)
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
        self.busy = False
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
        self.busy = False
        self.banner.setVisible(False)
        self.progress.setVisible(False)
        if not (on_error and on_error(exc)):
            QMessageBox.critical(self, T("Error"), _plain(msg))
        self.refresh()                          # (does nothing while a retry runs)

    def _run_pin(self, op, typed, no_pin=False, then=None, refresh=False):
        """Runs op(pin, no_pin, progress), an operation that takes the FIDO
        PIN of the active profile, with the PIN typed in a field. When it
        turns out that a PIN is needed and none was typed (checked in the
        worker: the check waits for the device), the PIN is asked for and op
        runs once more."""
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
            self._run(lambda p: op(pin or None, not pin, p), then=then, touch=True, refresh=refresh)
            return True
        self._run(lambda p: op(typed or None, no_pin, p), then=then, touch=True, refresh=refresh, on_error=on_error)

    def refresh(self):
        if self.busy:
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
            return False
        if self.mgmt is None:
            QMessageBox.warning(self, T("Error"), T("No device"))
            return False
        return True

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
        if self.mgmt is None or not self.info or self.busy:
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
            msg = T("Backup file written") + ":\n" + p
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
            pw, ok = QInputDialog.getText(self, T("Passphrase"), T("Passphrase") + ":", QLineEdit.EchoMode.Password)
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
                 "", "UUID: %s" % h["uuid"], "%s: %s" % (T("Name"), display_name(h["name"])),
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
        backup = "%s (%s, UUID %s, %d files)" % (display_name(os.path.basename(path)), display_name(h["name"]) or "-",
                                                 h["uuid"], info["summary"]["files"])
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
                      then=lambda r: QMessageBox.information(self, T("Done"), T("Imported") + ": %d files" % r["files"]),
                      refresh=True)


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
