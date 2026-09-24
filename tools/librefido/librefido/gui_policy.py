"""'Security' tab of librefido-gui: protection level and the two provisioning
steps (bind the root key to the chip, lock debugging), secure profiles,
presence per application ("my device is safe"), LED brightness.

Every device operation goes through the main window's worker machinery
(MainWindow._run: worker thread, touch banner, PC/SC transactions)."""

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QGroupBox, QHBoxLayout, QInputDialog, QLabel, QMessageBox,
    QPushButton, QSlider, QVBoxLayout, QWidget,
)

from . import policy, provision
from .mgmt import display_name

ZH = {
    "Security": "安全",
    "Protection of the keys": "密钥防护",
    "Protection level": "防护等级",
    "Protect keys against flash reads (bind to this chip)...": "防止从 flash 读取密钥（绑定到本芯片）…",
    "Lock debugging (JTAG, download mode)...": "锁定调试接口（JTAG、下载模式）…",
    "bind-info": ("把根密钥绑定到本芯片：设备在芯片内生成一个 HMAC 密钥并烧入 eFuse（软件不可读）。\n"
                  "此操作不可逆，会永久占用一个 eFuse 密钥块，但不会导致设备变砖。"),
    "held-info": ("芯片已有 HMAC 密钥，但当前环境的根密钥以明文存放（在绑定之前创建，或被能写 flash 的人放入）。"
                  "在你绑定它之前，设备会锁住此环境的密钥库。只有当此环境是你自己创建的时才绑定它；"
                  "不会再次烧写 eFuse。绑定后请重新插拔设备。"),
    "held-none-info": ("当前环境没有根密钥：它的密钥由设备序列号派生（从没有 eFuse 密钥的存储迁移而来，"
                       "或从不含根密钥的备份恢复）。在此芯片上（已有 HMAC 密钥且启用安全启动），"
                       "这样的环境在你确认之前一直被锁住：绑定会在芯片上记录此环境没有根密钥，下次启动后解锁。"
                       "它的密钥保持不变（由序列号派生，flash 转储即可得到，此环境防护等级为 0）。"
                       "只有当此环境是你自己创建的时才确认；不会再次烧写 eFuse。确认后请重新插拔设备。"),
    "lock-info": ("锁定调试接口：烧写 JTAG 禁用和安全下载模式的 eFuse（不可逆）。\n"
                  "之后仍可用 esptool 刷写固件（write_flash，--no-stub），恢复刷机依然可行，"
                  "但 ROM 下载模式不能再读取 flash 或在 RAM 中运行代码。此步骤不会导致设备变砖。"),
    "Type %s to continue:": "输入 %s 以继续：",
    "Not confirmed: nothing was changed.": "未确认：没有做任何改动。",
    "Done": "完成",
    "Active profile": "当前环境",
    "Secure profile (keys never leave it)": "安全环境（密钥永不离开设备）",
    "Standard profile": "普通环境",
    "My device is safe: no touch needed": "我的设备是安全的：无需按键",
    "Require a touch for": "需要按键确认的应用",
    "Apply": "应用",
    "auto-warning": ("关闭按键确认后，这台电脑上的任何程序都可以在你不知情的情况下使用对应应用的密钥。"
                     "开启时需要按一次键；恢复按键确认不需要。重置、导出、导入、固件升级等操作始终需要按键。"),
    "Switch automatic presence on?": "开启自动确认（无需按键）？",
    "not-available-secure": "安全环境始终需要按键确认。",
    "Secure profiles": "安全环境",
    "Create a secure profile in slot": "在槽位中创建安全环境",
    "Create...": "创建…",
    "secure-info": ("安全环境对标 YubiKey：在设备内新建、不可导入、任何情况下都不可导出，始终需要按键。\n"
                    "需要先把根密钥绑定到芯片。所选槽位中的现有数据会被清除。"),
    "Create a secure profile in slot %d?": "在槽位 %d 中创建安全环境？",
    "Board": "板级设置",
    "LED brightness": "LED 亮度",
}


EN = {
    "bind-info": ("Bind the root key to this chip: the device generates an HMAC key on the chip and burns it into "
                  "an eFuse (no software can read it).\nIrreversible: it uses one eFuse key block for good, but "
                  "cannot brick the device."),
    "held-info": ("The chip already has its HMAC key, but the root key of the active profile is stored in plain "
                  "(created before the binding, or put there by someone who could write the flash). The device "
                  "keeps its key store locked until you bind it. Bind it only if you created this profile "
                  "yourself; the eFuse is not burned again. Restart the key afterwards."),
    "held-none-info": provision.HELD_NONE_TEXT + " Restart the key afterwards.",
    "lock-info": provision.LOCK_TEXT,
    "auto-warning": ("Without a touch, any program on this computer can use the keys of these applications without "
                     "you noticing. Switching it on needs a touch; switching it off does not. Resets, exports, "
                     "imports and firmware updates always need a touch."),
    "not-available-secure": "A secure profile always needs a touch.",
    "secure-info": ("A secure profile is made empty on the device, is never imported into and never exported, "
                    "and every presence needs a touch.\nThe root key must be bound to the chip first. What the "
                    "slot holds now is erased."),
}


def install_translations(zh, en=None):
    """Adds this tab's texts: Chinese, and the English of the keyed ones."""
    zh.update(ZH)
    if en is not None:
        en.update(EN)


def metadata_dir():
    """Where the provisioning steps save the device metadata first."""
    d = os.path.join(os.path.expanduser("~"), "librefido-provision")
    os.makedirs(d, exist_ok=True)
    return d


class SecurityTab(QWidget):
    def __init__(self, window, T):
        super().__init__()
        self.w = window
        self.T = T
        lay = QVBoxLayout(self)

        prot = QGroupBox(T("Protection of the keys"))
        pl = QVBoxLayout(prot)
        self.level = QLabel("-")
        self.level.setTextFormat(Qt.TextFormat.PlainText)
        self.level.setWordWrap(True)
        pl.addWidget(self.level)
        brow = QHBoxLayout()
        self.bind_btn = QPushButton(T("Protect keys against flash reads (bind to this chip)..."))
        self.bind_btn.clicked.connect(self._bind)
        brow.addWidget(self.bind_btn)
        self.lock_btn = QPushButton(T("Lock debugging (JTAG, download mode)..."))
        self.lock_btn.clicked.connect(self._lock_debug)
        brow.addWidget(self.lock_btn)
        pl.addLayout(brow)
        lay.addWidget(prot)

        prof = QGroupBox(T("Active profile"))
        fl = QVBoxLayout(prof)
        self.kind = QLabel("-")
        self.kind.setTextFormat(Qt.TextFormat.PlainText)
        fl.addWidget(self.kind)
        self.safe = QCheckBox(T("My device is safe: no touch needed"))
        self.safe.toggled.connect(self._safe_toggled)
        fl.addWidget(self.safe)
        fl.addWidget(QLabel(T("Require a touch for")))
        self.need_touch = {}
        for app in policy.APPS:
            cb = QCheckBox(policy.APP_LABELS[app])
            cb.setChecked(True)
            self.need_touch[app] = cb
            fl.addWidget(cb)
        warn = QLabel(T("auto-warning"))
        warn.setWordWrap(True)
        warn.setStyleSheet("color:#a00;")
        fl.addWidget(warn)
        self.apply_btn = QPushButton(T("Apply"))
        self.apply_btn.clicked.connect(self._apply_presence)
        fl.addWidget(self.apply_btn)
        lay.addWidget(prof)

        sec = QGroupBox(T("Secure profiles"))
        sl = QHBoxLayout(sec)
        sl.addWidget(QLabel(T("Create a secure profile in slot")))
        self.slot = QComboBox()
        self.slot.addItems([str(i + 1) for i in range(4)])
        sl.addWidget(self.slot)
        self.create_btn = QPushButton(T("Create..."))
        self.create_btn.clicked.connect(self._create_secure)
        sl.addWidget(self.create_btn)
        sl.addStretch(1)
        lay.addWidget(sec)

        board = QGroupBox(T("Board"))
        bl = QFormLayout(board)
        row = QHBoxLayout()
        self.bright = QSlider(Qt.Orientation.Horizontal)
        self.bright.setRange(0, 255)
        self.bright.setValue(255)
        self.bright_value = QLabel("255")
        self.bright.valueChanged.connect(lambda v: self.bright_value.setText(str(v)))
        self.bright.sliderReleased.connect(self._brightness)
        row.addWidget(self.bright, 1)
        row.addWidget(self.bright_value)
        bl.addRow(T("LED brightness") + ":", row)
        lay.addWidget(board)
        lay.addStretch(1)

    # -- display -------------------------------------------------------------
    def show_info(self, info):
        T = self.T
        sec = info["security"]
        lvl = policy.protection_level(sec)
        self.level.setText("%s: %d / 3 — %s" % (T("Protection level"), lvl, policy.LEVELS[lvl]))
        state = provision.state(info)
        # (a profile without root key may be held: the binding checks the key store in the worker)
        self.bind_btn.setEnabled(lvl == 0 and (not sec.get("hmac_key") or state["held"] or state["root_none"]))
        self.lock_btn.setEnabled(not (sec.get("jtag_disabled") and sec.get("download_restricted")))
        board = info.get("board") or {}
        if "led_brightness" in board:
            self.bright.blockSignals(True)
            self.bright.setValue(board["led_brightness"])
            self.bright_value.setText(str(board["led_brightness"]))
            self.bright.blockSignals(False)
        self.bright.setEnabled("led_brightness" in board)
        profiles = info.get("profiles") or []
        hardened = info.get("build_profile") == "hardened"
        self.create_btn.setEnabled(bool(profiles) and not hardened)
        if "active" not in info or not profiles:
            self.apply_btn.setEnabled(False)
            return
        p = profiles[info["active"]]
        secure = p.get("secure", False) or hardened
        self.kind.setText(T("Secure profile (keys never leave it)") if secure else T("Standard profile"))
        auto = set(p.get("auto_presence", []))
        for app, cb in self.need_touch.items():
            cb.blockSignals(True)
            cb.setChecked(app not in auto)
            cb.setEnabled(not secure)
            cb.blockSignals(False)
        self.safe.blockSignals(True)
        self.safe.setChecked(len(auto) == len(policy.APPS))
        self.safe.setEnabled(not secure)
        self.safe.blockSignals(False)
        self.safe.setToolTip(T("not-available-secure") if secure else "")
        self.apply_btn.setEnabled(not secure)

    # -- actions -------------------------------------------------------------
    def _safe_toggled(self, on):
        for cb in self.need_touch.values():
            cb.setChecked(not on)

    def _apply_presence(self):
        info = self.w.info
        if not info or "active" not in info or not self.w._ready():
            return
        idx = info["active"]
        apps = {app: not cb.isChecked() for app, cb in self.need_touch.items()}
        enabling = set(a for a, on in apps.items() if on) - set(info["profiles"][idx].get("auto_presence", []))
        if enabling and QMessageBox.question(
                self, self.T("Security"), self.T("Switch automatic presence on?") + "\n\n" +
                ", ".join(policy.APP_LABELS[a] for a in policy.APPS if a in enabling) + "\n\n" +
                self.T("auto-warning"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            self.show_info(info)                # back to what the device has
            return
        # switching on needs a touch; switching off only counts as a change
        self.w._run(lambda p: self.w.mgmt.set_presence(idx, **apps), touch=bool(enabling) or self.w._change_touch(),
                    refresh=True)

    def _confirmed(self, text):
        """Typed confirmation naming the device (BURN <chip serial>), as the
        command line asks for it. True when it was typed exactly."""
        expected = "BURN %s" % self.w.info["chip_serial"]
        typed, ok = QInputDialog.getText(self, self.T("Security"),
                                         text + "\n\n" + self.T("Type %s to continue:") % expected)
        if not ok:
            return False
        if typed.strip() != expected:
            QMessageBox.warning(self, self.T("Security"), self.T("Not confirmed: nothing was changed."))
            return False
        return True

    def _provision(self, step, text):
        if not self.w.info or not self.w._ready():
            return
        if not self._confirmed(text):
            return
        notes = []
        expected = "BURN %s" % self.w.info["chip_serial"]

        def done(after):
            lvl = policy.protection_level(after["security"])
            QMessageBox.information(self, self.T("Done"), "%s: %d / 3\n\n%s" % (
                self.T("Protection level"), lvl, "\n".join(display_name(n) for n in notes)))
        self.w._run(lambda p: step(self.w.mgmt, lambda e: expected, directory=metadata_dir(), out=notes.append),
                    then=done, touch=True, refresh=True)

    def _bind(self):
        s = provision.state(self.w.info) if self.w.info else None
        if s and s["hmac_key"] and s["root_none"]:
            text = self.T("held-none-info")         # (held or not: the worker checks the key store)
        elif s and s["held"]:
            text = self.T("held-info")
        else:
            text = self.T("bind-info")
        self._provision(provision.bind_root_key, text)

    def _lock_debug(self):
        self._provision(provision.lock_debug, self.T("lock-info"))

    def _create_secure(self):
        if not self.w._ready():
            return
        idx = self.slot.currentIndex()
        if QMessageBox.question(
                self, self.T("Secure profiles"), self.T("Create a secure profile in slot %d?") % (idx + 1) +
                "\n\n" + self.T("secure-info"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self.w._run(lambda p: self.w.mgmt.create_secure_profile(idx), touch=True, reboots=True)

    def _brightness(self):
        if not self.w._ready():
            return
        v = self.bright.value()
        self.w._run(lambda p: self.w.mgmt.set_led_brightness(v), touch=self.w._change_touch(), refresh=True)
