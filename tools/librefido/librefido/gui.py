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

from . import __version__
from .backup import BackupError, read_file, write_file
from .mgmt import Management
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
    "Security": "安全状态",
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
    "warning": "安全性与便利性不可兼得：LibreFido 专注于便利性（可导出、可克隆）。请勿用它保存任何有价值的数据。",
}

_LANG_ZH = (locale.getlocale()[0] or os.environ.get("LANG", "")).lower().startswith("zh") or \
    os.environ.get("LIBREFIDO_LANG", "").lower().startswith("zh")


def T(text):
    return ZH.get(text, text) if _LANG_ZH else (text if text != "warning" else
        "Security and convenience cannot both be had: LibreFido favours convenience (exportable, "
        "clonable keys). Do not keep anything valuable on it.")


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
    failed = Signal(str)
    progress = Signal(int, int)


class Job(QRunnable):
    def __init__(self, fn):
        super().__init__()
        self.fn = fn
        self.signals = _Signals()

    def run(self):
        try:
            self.signals.done.emit(self.fn(lambda a, b: self.signals.progress.emit(a, b)))
        except (ApduError, BackupError, RuntimeError, OSError) as e:
            self.signals.failed.emit(str(e))
        except Exception:
            self.signals.failed.emit(traceback.format_exc())


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
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.dev_labels[key] = lbl
            form.addRow(T(title) + ":", lbl)
        lay.addLayout(form)
        sec = QGroupBox(T("Security"))
        sform = QFormLayout(sec)
        self.sec_labels = {}
        for key, title in (("secure_boot", "Secure Boot"), ("flash_encryption", "Flash encryption"),
                           ("jtag_disabled", "JTAG disabled"), ("root_key", "Root key")):
            lbl = QLabel("-")
            self.sec_labels[key] = lbl
            sform.addRow(T(title) + ":", lbl)
        lay.addWidget(sec)
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
                                                    refresh=True))
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
        self.loaded_stream = None
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
    def _run(self, fn, then=None, touch=False, reboots=False, refresh=False):
        if self.busy:
            return
        if self.mgmt is None:
            QMessageBox.warning(self, T("Error"), T("No device"))
            return
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
        job.signals.done.connect(lambda r: self._finished(r, then, refresh or reboots))
        job.signals.failed.connect(self._failed)
        # The Python side (and its signals) must outlive the worker thread.
        self._job = job
        self.pool.start(job)

    def _on_progress(self, done, total):
        self.progress.setVisible(True)
        self.progress.setMaximum(max(total, 1))
        self.progress.setValue(done)

    def _finished(self, result, then, refresh):
        self.busy = False
        self.banner.setVisible(False)
        self.progress.setVisible(False)
        if then:
            then(result)
        if refresh:
            self.refresh()

    def _failed(self, msg):
        self.busy = False
        self.banner.setVisible(False)
        self.progress.setVisible(False)
        QMessageBox.critical(self, T("Error"), msg)
        self.refresh()

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
            self.info = self.mgmt.info()
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
            self.table.setItem(r, 2, QTableWidgetItem(p["name"] if p["used"] else ""))
            state = T("empty")
            if p["used"]:
                state = T("active") if r == info.get("active") else T("in use")
            self.table.setItem(r, 3, QTableWidgetItem(state))
            self.table.setItem(r, 4, QTableWidgetItem(T("blocked") if p["no_export"] else T("allowed")))
        if "button_slots" in info:
            self.slots_spin.setValue(info["button_slots"])

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

    # -- actions -------------------------------------------------------------
    def _reboot(self, bootloader):
        self._run(lambda p: self.mgmt.reboot(bootloader=bootloader), reboots=not bootloader)

    def _factory_reset(self):
        text, ok = QInputDialog.getText(self, T("Factory reset..."), T("Type 'erase' to erase every profile and key:"))
        if ok and text == "erase":
            self._run(lambda p: self.mgmt.factory_reset(), touch=True, reboots=True)

    def _switch(self):
        s = self._selected_slot()
        if s is not None:
            self._run(lambda p: self.mgmt.select_profile(s), reboots=True)

    def _rename(self):
        s = self._selected_slot()
        if s is None:
            return
        name, ok = QInputDialog.getText(self, T("Rename..."), T("Profile name:"))
        if ok:
            self._run(lambda p: self.mgmt.set_profile(s, name=name[:23]), refresh=True)

    def _colour(self):
        s = self._selected_slot()
        if s is None:
            return
        c = QColorDialog.getColor(parent=self)
        if c.isValid():
            hexc = "%02x%02x%02x" % (c.red(), c.green(), c.blue())
            self._run(lambda p: self.mgmt.set_profile(s, color=hexc), refresh=True)

    def _toggle_export(self):
        s = self._selected_slot()
        if s is None or not self.info:
            return
        blocked = self.info["profiles"][s]["no_export"]
        self._run(lambda p: self.mgmt.set_profile(s, no_export=not blocked), touch=blocked, refresh=True)

    def _wipe(self):
        s = self._selected_slot()
        if s is None:
            return
        used = self.info and self.info["profiles"][s]["used"]
        if used and QMessageBox.question(self, T("Create / wipe"), T("Create / wipe") + " %d ?" % (s + 1)) \
                != QMessageBox.StandardButton.Yes:
            return
        self._run(lambda p: self.mgmt.wipe_profile(s), touch=bool(used), reboots=True)

    def _delete(self):
        s = self._selected_slot()
        if s is None:
            return
        if QMessageBox.question(self, T("Delete"), T("Delete") + " %d ?" % (s + 1)) == QMessageBox.StandardButton.Yes:
            self._run(lambda p: self.mgmt.delete_profile(s), touch=True, reboots=True)

    def _export(self):
        passphrase = None
        if self.enc_check.isChecked():
            if self.pass1.text() != self.pass2.text() or not self.pass1.text():
                QMessageBox.warning(self, T("Error"), T("Passphrases differ"))
                return
            passphrase = self.pass1.text()
        path, _ = QFileDialog.getSaveFileName(self, T("Export to file..."), "librefido-profile.lfbk",
                                              "LibreFido backup (*.lfbk)")
        if not path:
            return
        pin = self.pin_edit.text() or None

        def work(progress):
            stream = self.mgmt.export_profile(pin=pin, progress=progress)
            write_file(path, stream, passphrase)
            return path

        def done(p):
            msg = T("Backup file written") + ": " + p
            if not passphrase:
                msg += "\n\n" + T("NOT encrypted: anyone with this file has your keys.")
            QMessageBox.information(self, T("Done"), msg)
        self._run(work, then=done, touch=True)

    def _load_backup(self):
        path, _ = QFileDialog.getOpenFileName(self, T("Open and verify..."), "", "LibreFido backup (*.lfbk)")
        if not path:
            return None, None
        try:
            info, stream = read_file(path)
            if info["encrypted"]:
                pw, ok = QInputDialog.getText(self, T("Passphrase"), T("Passphrase") + ":", QLineEdit.EchoMode.Password)
                if not ok:
                    return None, None
                info, stream = read_file(path, pw)
        except BackupError as e:
            QMessageBox.critical(self, T("Error"), str(e))
            return None, None
        return info, stream

    def _verify_file(self):
        info, stream = self._load_backup()
        if stream is None:
            return
        self.loaded_stream = stream
        s = info["summary"]
        h = s["header"]
        lines = [T("Backup OK"), "",
                 "UUID: %s" % h["uuid"], "%s: %s" % (T("Name"), h["name"]), "Serial: %s" % h["serial"],
                 "Firmware: %s (min %s)" % (h["firmware"], h["min_firmware"]),
                 "Encrypted: %s" % info["encrypted"], "Root key: %s" % s["root_key"],
                 "Files: %d" % s["files"], "FIDO resident credentials: %d" % s["resident_credentials"],
                 "OATH credentials: %d" % s["oath_credentials"], "Counters: %s" % s["counters"],
                 "By application: %s" % s["by_application"]]
        self.verify_out.setPlainText("\n".join(lines))

    def _device_check(self, restore_test):
        if self.loaded_stream is None:
            self._verify_file()
            if self.loaded_stream is None:
                return
        stream = self.loaded_stream
        if restore_test:
            def work(progress):
                return self.mgmt.restore_test(stream, progress=progress)[1]
            self._run(work, then=lambda ok: QMessageBox.information(
                self, T("Done"), T("Restore test passed: the backup can be restored.") if ok else
                T("Restore test FAILED.")), refresh=True)
        else:
            self._run(lambda p: self.mgmt.check_backup(stream, progress=p),
                      then=lambda r: QMessageBox.information(self, T("Done"), T("The firmware accepts this backup.")))

    def _import(self):
        info, stream = self._load_backup()
        if stream is None:
            return
        target = self.target_spin.value() - 1
        used = self.info and self.info["profiles"][target]["used"]

        def work(progress):
            return self.mgmt.import_profile(stream, target, progress=progress)
        self._run(work, then=lambda r: QMessageBox.information(self, T("Done"), T("Imported") + ": %d files" % r["files"]),
                  touch=bool(used), refresh=True)


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
