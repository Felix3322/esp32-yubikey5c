"""OpenPGP and PIV pages of the Key manager (gui_manager.KeyManagerTab).

OpenPgpPage: the three key slots of the OpenPGP application (algorithm,
fingerprint, creation time, touch policy); a key generated on the device; the
PIN, Admin PIN and Reset Code; unblocking the PIN; the touch policy (UIF); the
cardholder name and public key URL; deleting a key; resetting the application.

PivPage: the PIV slots and their certificates (details of the selected slot);
a key generated with a self-signed certificate or a certificate signing
request; certificates imported, exported and deleted; keys deleted and moved;
the PIN, PUK and management key; resetting the application.

Device work runs in the main window's worker (ManagerContext.run) on the
page's manager (mgr_pgp.OpenPgpManager, mgr_piv.PivManager), used only in the
worker. A PIN, PUK, Reset Code or management key typed in a dialog goes into
the closure of that one operation, which the worker drops once it ran; the
PIV manager's copy of the management key is wiped (forget()) when the
operation ends. The pages keep none, and the dialogs empty their fields when
they close. Every destructive action names what it erases and is confirmed
(the managers replace nothing without replace=True); a reset twice.
"""

import datetime
import os
import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QGroupBox, QLineEdit, QPlainTextEdit,
    QPushButton, QSpinBox, QVBoxLayout,
)

from . import mgr_pgp, mgr_piv
from .gui_manager import (ManagerPage, button_row, fill_table, make_table, register_translations, selected_row,
                          text_label)
from .mgmt import display_name
from .mgr_common import ManagerError
from .pcsc import ApduError

# ----------------------------------------------------------------------------
# Texts (English keys; the Chinese of every one, the English of keyed ones)
# ----------------------------------------------------------------------------

ZH = {
    # shared
    "Version": "版本",
    "Serial number": "序列号",
    "Algorithm": "算法",
    "Algorithm:": "算法：",
    "Created": "创建时间",
    "Touch": "按键",
    "Generate...": "生成…",
    "Delete key...": "删除密钥…",
    "Change PIN...": "修改 PIN…",
    "Unblock PIN...": "解锁 PIN…",
    "Current PIN:": "当前 PIN：",
    "New PIN:": "新 PIN：",
    "Repeat:": "重复：",
    "Fill in every field.": "请填写所有字段。",
    "The two entries differ.": "两次输入不一致。",
    "At least %d characters.": "至少 %d 个字符。",
    "At most %d characters.": "最多 %d 个字符。",
    "At least %d bytes (UTF-8).": "至少 %d 字节（UTF-8）。",
    "At most %d bytes (UTF-8).": "最多 %d 字节（UTF-8）。",
    "Refresh first: the page has not read the device yet.": "请先刷新：此页面尚未读取设备。",
    "no key": "无密钥",
    "(expired)": "（已过期）",
    "PINs": "PIN",
    "Nothing to change.": "没有需要修改的内容。",
    "The PIN was changed.": "PIN 已修改。",
    "The PIN was unblocked and set.": "PIN 已解锁并设置为新值。",
    "Change PIN": "修改 PIN",
    "Unblock PIN": "解锁 PIN",
    # OpenPGP
    "pgp-hint": "OpenPGP：三个密钥槽位（签名、解密、认证）、PIN 和卡片设置。“刷新”读取设备。",
    "Cardholder name": "持卡人姓名",
    "Public key URL": "公钥 URL",
    "PIN tries left": "PIN 剩余尝试次数",
    "Signatures made": "已签名次数",
    "PIN %s, Reset Code %s, Admin PIN %s": "PIN %s，重置码 %s，管理员 PIN %s",
    "Key": "密钥",
    "Fingerprint": "指纹",
    "Signature": "签名",
    "Decryption": "解密",
    "Authentication": "认证",
    "off": "关闭",
    "on": "开启",
    "on, permanent": "开启（永久）",
    "cached": "缓存",
    "cached, permanent": "缓存（永久）",
    "Touch policy...": "按键策略…",
    "Change Admin PIN...": "修改管理员 PIN…",
    "Set Reset Code...": "设置重置码…",
    "Cardholder name...": "持卡人姓名…",
    "Public key URL...": "公钥 URL…",
    "Reset OpenPGP...": "重置 OpenPGP…",
    "The PIN is blocked: unblock it with the Reset Code or the Admin PIN.": "PIN 已锁定：请用重置码或管理员 PIN 解锁。",
    "The Admin PIN is blocked: only a reset of OpenPGP makes its keys usable again.":
        "管理员 PIN 已锁定：只有重置 OpenPGP 才能让它重新可用。",
    "Select a key slot first.": "请先选择一个密钥槽位。",
    "The %s key slot is empty.": "%s密钥槽位是空的。",
    "%s key: none": "%s密钥：无",
    "%s key: %s, fingerprint %s, created %s": "%s密钥：%s，指纹 %s，创建于 %s",
    "Generate an OpenPGP key": "生成 OpenPGP 密钥",
    "pgp-generate-info": ("密钥在设备上生成，私钥不会离开设备。RSA 密钥生成需要一段时间（RSA 4096 可能要几分钟）。"
                          "需要 OpenPGP 管理员 PIN（默认 12345678）。"),
    "Key slot:": "密钥槽位：",
    "Admin PIN:": "管理员 PIN：",
    "Replace the %s key?": "替换%s密钥？",
    "pgp-replace-info": ("当前密钥会被永久清除：用它加密的数据将无法再用本设备解密，它的签名也无法再生成。"
                         "只有在你之前导出过它时才存在副本。"),
    "New %s key generated on the device.": "已在设备上生成新的%s密钥。",
    "Fingerprint: %s": "指纹：%s",
    "Created: %s": "创建时间：%s",
    "pgp-gnupg-hint": ("在 GnuPG 中使用：gpg --expert --full-generate-key，选择“Existing key from card”"
                       "（卡上已有的密钥），为它创建 OpenPGP 证书。"),
    "Touch policy": "按键策略",
    "pgp-uif-info": ("开启后，每次用该密钥签名、解密或认证都需要按一下按键。“缓存”在本设备上同样每次都需要按键。"
                     "“永久”只能通过重置 OpenPGP 撤销。需要管理员 PIN。"),
    "Touch:": "按键：",
    "pgp-uif-fixed": "此密钥的按键策略是永久的：只有重置 OpenPGP 才能更改。",
    "Make the touch policy of the %s key permanent?": "把%s密钥的按键策略设为永久？",
    "pgp-uif-permanent": "之后只有重置 OpenPGP（会清除所有 OpenPGP 密钥）才能关闭或更改它。",
    "Touch policy of the %s key: %s": "%s密钥的按键策略：%s",
    "pgp-pin-info": "签名、解密或认证时需要 PIN（默认 123456）：6 到 127 个字符。",
    "Change Admin PIN": "修改管理员 PIN",
    "pgp-admin-pin-info": "生成、删除密钥和修改卡片设置时需要管理员 PIN（默认 12345678）：8 到 127 个字符。",
    "Current Admin PIN:": "当前管理员 PIN：",
    "New Admin PIN:": "新管理员 PIN：",
    "The Admin PIN was changed.": "管理员 PIN 已修改。",
    "Set Reset Code": "设置重置码",
    "pgp-reset-code-info": "重置码让不知道管理员 PIN 的人也能解锁 PIN（8 到 127 个字符）。需要管理员 PIN。",
    "New Reset Code:": "新重置码：",
    "The Reset Code was set.": "重置码已设置。",
    "pgp-unblock-info": "用重置码或管理员 PIN 解锁 PIN 并设置新的 PIN（6 到 127 个字符）。",
    "Unblock with:": "解锁方式：",
    "the Reset Code": "重置码",
    "the Admin PIN": "管理员 PIN",
    "Reset Code:": "重置码：",
    "pgp-name-info": ("GnuPG（--card-status）显示的姓名：普通 ASCII 字符，最多 39 个；OpenPGP 的写法是“姓<<名”，"
                      "留空则删除。需要管理员 PIN。"),
    "Name:": "姓名：",
    "pgp-ascii": "只能使用普通 ASCII 字母、数字和符号：GnuPG 不支持其他字符。",
    "The cardholder name was set.": "持卡人姓名已设置。",
    "pgp-url-info": "GnuPG 获取公钥的地址（gpg --card-edit 中的 fetch），最多 255 字节；留空则删除。需要管理员 PIN。",
    "URL:": "URL：",
    "The public key URL was set.": "公钥 URL 已设置。",
    "Delete the %s key?": "删除%s密钥？",
    "pgp-delete-info": ("它会从设备上被永久清除：用它加密的数据将无法再用本设备解密，它也无法再签名或认证。"
                        "只有在你之前导出过它时才存在副本。"),
    "The %s key was deleted.": "%s密钥已删除。",
    "Reset the OpenPGP application?": "重置 OpenPGP 应用？",
    "pgp-reset-info": ("下列所有 OpenPGP 密钥、持卡人数据和按键策略都会被永久清除；PIN 恢复为 123456，"
                       "管理员 PIN 恢复为 12345678，重置码被删除。FIDO、OATH、OTP 和 PIV 不受影响。"
                       "设备会要求按键确认。"),
    "It holds no key.": "其中没有密钥。",
    "Cardholder name: %s": "持卡人姓名：%s",
    "pgp-reset-again": "确定要清除 OpenPGP 应用吗？此操作不可撤销，上述密钥将永久丢失。",
    "pgp-reset-admin": ("OpenPGP 管理员 PIN（如果知道）。留空：重置前会先用错误尝试锁定管理员 PIN；"
                        "若随后没有按键确认，它会一直锁定，直到重置成功。"),
    "pgp-reset-done": "OpenPGP 已重置：PIN 为 123456，管理员 PIN 为 12345678。",
    # PIV
    "piv-hint": "PIV：密钥槽位及其证书、PIN、PUK 和管理密钥。“刷新”读取设备。",
    "Tries left": "剩余尝试次数",
    "Management key": "管理密钥",
    "PIN %s, PUK %s": "PIN %s，PUK %s",
    "default key": "默认密钥",
    "touch": "需按键",
    "piv-default-mgmt": "正在使用默认管理密钥：任何人都能更改 PIV 密钥和证书。请用“管理密钥…”设置你自己的密钥。",
    "The default PIN is in use: change it.": "正在使用默认 PIN：请修改它。",
    "The default PUK is in use: change it.": "正在使用默认 PUK：请修改它。",
    "The PIN is blocked: unblock it with the PUK.": "PIN 已锁定：请用 PUK 解锁。",
    "The PUK is blocked: once the PIN is blocked too, only a reset of PIV helps.":
        "PUK 已锁定：一旦 PIN 也被锁定，只有重置 PIV 才能恢复。",
    "Show all slots (retired key slots too)": "显示所有槽位（包括历史密钥槽位）",
    "Slot": "槽位",
    "Origin": "来源",
    "PIN policy": "PIN 策略",
    "Certificate": "证书",
    "Expires": "到期",
    "Select a slot to see its key and certificate.": "选择一个槽位查看它的密钥和证书。",
    "Import certificate...": "导入证书…",
    "Export certificate...": "导出证书…",
    "Delete certificate...": "删除证书…",
    "Move key...": "移动密钥…",
    "PIN, PUK and management key": "PIN、PUK 和管理密钥",
    "Change PUK...": "修改 PUK…",
    "Management key...": "管理密钥…",
    "Reset PIV...": "重置 PIV…",
    "Card authentication": "卡片认证",
    "Digital signature": "数字签名",
    "Key management": "密钥管理",
    "Retired %d": "历史密钥 %d",
    "generated": "设备生成",
    "imported": "导入",
    "default": "默认",
    "never": "从不",
    "once": "每次会话一次",
    "always": "总是",
    "unreadable": "无法读取",
    "Select a slot first.": "请先选择一个槽位。",
    "Slot %s holds no key.": "槽位 %s 中没有密钥。",
    "Slot %s holds no certificate.": "槽位 %s 中没有证书。",
    "Slot %s": "槽位 %s",
    "Key: none": "密钥：无",
    "Key: %s, %s; PIN policy %s, touch policy %s": "密钥：%s，%s；PIN 策略：%s，按键策略：%s",
    "Certificate: none": "证书：无",
    "Certificate:": "证书：",
    "Subject: %s": "主题：%s",
    "Issuer: %s": "颁发者：%s",
    "Serial number: %s": "序列号：%s",
    "Valid from %s to %s": "有效期：%s 至 %s",
    "The certificate cannot be read: %s": "证书无法读取：%s",
    "The certificate does not belong to the key in this slot.": "此证书与该槽位中的密钥不匹配。",
    "Public key:": "公钥：",
    "PIV management key": "PIV 管理密钥",
    "PIV management key (hex; leave empty for the default key):": "PIV 管理密钥（十六进制；留空则使用默认密钥）：",
    "piv-bad-hex": "管理密钥必须是十六进制（3DES / AES-192 为 48 位，AES-128 为 32 位，AES-256 为 64 位）。",
    "Generate a PIV key": "生成 PIV 密钥",
    "piv-generate-info": ("密钥在设备上生成，私钥不会离开设备。自签名证书或证书签名请求（CSR）由这把新密钥签名，"
                          "需要 PIV PIN。X25519 密钥只能用于密钥协商：没有证书。"),
    "Slot:": "槽位：",
    "PIN policy:": "PIN 策略：",
    "Touch policy:": "按键策略：",
    "Self-signed certificate": "自签名证书",
    "Certificate signing request (CSR) to a file": "证书签名请求（CSR），保存到文件",
    "Subject:": "主题：",
    "Valid for (days):": "有效天数：",
    "PIV PIN:": "PIV PIN：",
    "Enter a subject, e.g. CN=Alice.": "请输入主题，例如 CN=Alice。",
    "Replace what slot %s holds?": "替换槽位 %s 中的内容？",
    "piv-replace-info": ("当前密钥和证书会被永久清除：用该密钥加密的数据将无法再用本设备解密，它也无法再签名或认证。"
                         "只有在你之前导出过它时才存在副本。"),
    "Certificate signing request": "证书签名请求",
    "Certificate requests": "证书签名请求",
    "New %s key generated in slot %s.": "已生成新的 %s 密钥，位于槽位 %s。",
    "A self-signed certificate is in the slot.": "槽位中已放入自签名证书。",
    "Certificate signing request written: %s": "证书签名请求已写入：%s",
    "piv-csr-cert": "在 CA 签发的证书导入之前，槽位中是设备自己生成的证书。",
    "An X25519 key has no certificate.": "X25519 密钥没有证书。",
    "Certificates": "证书",
    "All files": "所有文件",
    "%s is larger than %d KiB: not a certificate.": "%s 大于 %d KiB：不是证书。",
    "Replace the certificate of slot %s?": "替换槽位 %s 中的证书？",
    "Import this certificate into slot %s?": "把此证书导入槽位 %s？",
    "piv-cert-replace-info": "当前证书会被永久清除（密钥保留）。",
    "piv-cert-mismatch": "此证书不属于该槽位中的密钥：使用该槽位的程序会找到不匹配的证书。",
    "The certificate was imported.": "证书已导入。",
    "Certificate written: %s": "证书已写入：%s",
    "Delete the certificate of slot %s?": "删除槽位 %s 中的证书？",
    "piv-delete-cert-info": "它会从设备上被永久清除（可先用“导出证书…”保存副本）。槽位中的密钥保留。",
    "The certificate was deleted.": "证书已删除。",
    "Delete the key of slot %s?": "删除槽位 %s 中的密钥？",
    "piv-delete-key-info": ("它会从设备上被永久清除：用它加密的数据将无法再用本设备解密，它也无法再签名或认证。"
                            "只有在你之前导出过它时才存在副本。"),
    "Delete its certificate as well?": "同时删除它的证书？",
    "The key was deleted.": "密钥已删除。",
    "Move key": "移动密钥",
    "To slot:": "目标槽位：",
    "%s (in use)": "%s（已使用）",
    "Move the key of slot %s to slot %s?": "把槽位 %s 中的密钥移动到槽位 %s？",
    "What slot %s holds is erased for good:": "槽位 %s 中的内容将被永久清除：",
    "piv-move-info": "证书随密钥一起移动。",
    "The key was moved.": "密钥已移动。",
    "piv-pin-info": "PIV PIN（默认 123456）：6 到 8 个字符。",
    "Change PUK": "修改 PUK",
    "piv-puk-info": "PUK 用于解锁 PIN（默认 12345678）：6 到 8 个字符。",
    "Current PUK:": "当前 PUK：",
    "New PUK:": "新 PUK：",
    "The PUK was changed.": "PUK 已修改。",
    "piv-unblock-info": "用 PUK 解锁 PIV PIN 并设置新的 PIN（6 到 8 个字符）。",
    "PUK:": "PUK：",
    "Change the management key": "修改管理密钥",
    "piv-mgmt-info": "生成、导入和删除 PIV 密钥与证书时需要管理密钥。",
    "Current management key (hex; empty: the default key):": "当前管理密钥（十六进制；留空：默认密钥）：",
    "New management key (hex):": "新管理密钥（十六进制）：",
    "Random": "随机生成",
    "Require a touch for every use of the management key": "每次使用管理密钥都需要按键",
    "%s: the new key must be %d bytes (%d hex digits).": "%s：新密钥必须是 %d 字节（%d 位十六进制）。",
    "Change the PIV management key?": "修改 PIV 管理密钥？",
    "piv-mgmt-keep": ("请记下新密钥并妥善保管：没有它就无法再生成、导入或删除任何 PIV 密钥和证书"
                      "（只能重置 PIV，那会清除它们全部）。"),
    "The management key was changed.": "管理密钥已修改。",
    "Reset the PIV application?": "重置 PIV 应用？",
    "piv-reset-info": ("下列所有 PIV 密钥和证书都会被永久清除；PIN 恢复为 123456，PUK 恢复为 12345678，"
                       "管理密钥恢复为默认值。FIDO、OATH、OTP 和 OpenPGP 不受影响。重置前会先用错误尝试锁定 PIN 和 PUK，"
                       "然后设备要求按键确认：若没有按键，它们会一直锁定，直到重置成功。"),
    "It holds no key and no certificate.": "其中没有密钥和证书。",
    "piv-reset-again": "确定要清除 PIV 应用吗？此操作不可撤销，上述密钥和证书将永久丢失。",
    "piv-reset-done": "PIV 已重置：PIN 为 123456，PUK 为 12345678，管理密钥为默认值。",
}

EN = {
    "pgp-hint": "OpenPGP: the three key slots (signature, decryption, authentication), the PINs and the card "
                "settings. Refresh reads the device.",
    "pgp-generate-info": "The key is made on the device; its private part never leaves it. RSA keys take a while "
                         "(RSA 4096: minutes). The OpenPGP Admin PIN is needed (default 12345678).",
    "pgp-replace-info": "The current key is erased for good: what was encrypted to it can no longer be decrypted "
                        "with this device, and it can no longer sign. A copy exists only if you exported it.",
    "pgp-gnupg-hint": "To use it with GnuPG: gpg --expert --full-generate-key, choice \"Existing key from card\", "
                      "makes an OpenPGP certificate for it.",
    "pgp-uif-info": "When on, every signature, decryption or authentication with the key needs a touch. \"Cached\" "
                    "needs one every time on this device too. A permanent policy is undone only by an OpenPGP "
                    "reset. The Admin PIN is needed.",
    "pgp-uif-fixed": "The touch policy of this key is permanent: only an OpenPGP reset changes it.",
    "pgp-uif-permanent": "Afterwards only an OpenPGP reset (which erases every OpenPGP key) switches it off or "
                         "changes it.",
    "pgp-pin-info": "The PIN (default 123456) is asked for to sign, decrypt or authenticate: 6 to 127 characters.",
    "pgp-admin-pin-info": "The Admin PIN (default 12345678) is asked for to generate or delete keys and change card "
                          "settings: 8 to 127 characters.",
    "pgp-reset-code-info": "The Reset Code lets someone who does not know the Admin PIN unblock the PIN (8 to 127 "
                           "characters). The Admin PIN is needed.",
    "pgp-unblock-info": "Unblocks the PIN with the Reset Code or the Admin PIN and sets a new PIN (6 to 127 "
                        "characters).",
    "pgp-name-info": "The name GnuPG shows (--card-status): plain ASCII, at most 39 characters; OpenPGP writes it "
                     "Surname<<Given names. Empty removes it. The Admin PIN is needed.",
    "pgp-ascii": "Plain ASCII letters, digits and signs only: GnuPG reads nothing else.",
    "pgp-url-info": "Where GnuPG fetches the public key (gpg --card-edit, fetch), at most 255 bytes; empty removes "
                    "it. The Admin PIN is needed.",
    "pgp-delete-info": "It is erased from the device for good: what was encrypted to it can no longer be decrypted "
                       "with this device, and it can no longer sign or authenticate. A copy exists only if you "
                       "exported it.",
    "pgp-reset-info": "Every OpenPGP key below, the cardholder data and the touch policies are erased for good; the "
                      "PIN goes back to 123456, the Admin PIN to 12345678, the Reset Code is removed. FIDO, OATH, "
                      "OTP and PIV are not touched. The device asks for a touch.",
    "pgp-reset-again": "Really erase the OpenPGP application? This cannot be undone: the keys above are lost for "
                       "good.",
    "pgp-reset-admin": "OpenPGP Admin PIN, if you know it. Empty: the Admin PIN is blocked first by wrong attempts; "
                       "if the key is then not touched, it stays blocked until a reset succeeds.",
    "pgp-reset-done": "OpenPGP was reset: PIN 123456, Admin PIN 12345678.",
    "piv-hint": "PIV: the key slots and their certificates, the PIN, PUK and management key. Refresh reads the "
                "device.",
    "piv-default-mgmt": "The default management key is in use: anyone can change the PIV keys and certificates. Set "
                        "your own with Management key...",
    "piv-bad-hex": "The management key must be hexadecimal (48 digits for 3DES and AES-192, 32 for AES-128, 64 for "
                   "AES-256).",
    "piv-generate-info": "The key is made on the device; its private part never leaves it. The self-signed "
                         "certificate or the certificate signing request (CSR) is signed by the new key, which "
                         "needs the PIV PIN. An X25519 key only agrees keys: it gets no certificate.",
    "piv-replace-info": "The current key and certificate are erased for good: what was encrypted to the key can no "
                        "longer be decrypted with this device, and it can no longer sign or authenticate. A copy "
                        "exists only if you exported it.",
    "piv-csr-cert": "Until the certificate of your CA is imported, the slot holds a certificate the device made "
                    "itself.",
    "piv-cert-replace-info": "The current certificate is erased for good (the key stays).",
    "piv-cert-mismatch": "This certificate does not belong to the key in this slot: programs using the slot will "
                         "find a certificate that does not match.",
    "piv-delete-cert-info": "It is erased from the device for good (Export certificate... keeps a copy first). The "
                            "key of the slot stays.",
    "piv-delete-key-info": "It is erased from the device for good: what was encrypted to it can no longer be "
                           "decrypted with this device, and it can no longer sign or authenticate. A copy exists only "
                           "if you exported it.",
    "piv-move-info": "The certificate moves with the key.",
    "piv-pin-info": "The PIV PIN (default 123456): 6 to 8 characters.",
    "piv-puk-info": "The PUK unblocks the PIN (default 12345678): 6 to 8 characters.",
    "piv-unblock-info": "Unblocks the PIV PIN with the PUK and sets a new PIN (6 to 8 characters).",
    "piv-mgmt-info": "The management key is needed to generate, import and delete PIV keys and certificates.",
    "piv-mgmt-keep": "Write the new key down and keep it safe: without it no PIV key or certificate can be "
                     "generated, imported or deleted any more (only a PIV reset, which erases them all).",
    "piv-reset-info": "Every PIV key and certificate below is erased for good; the PIN goes back to 123456, the PUK "
                      "to 12345678 and the management key to the default one. FIDO, OATH, OTP and OpenPGP are not "
                      "touched. The PIN and the PUK are blocked first by wrong attempts, then the device asks for a "
                      "touch: without it they stay blocked until a reset succeeds.",
    "piv-reset-again": "Really erase the PIV application? This cannot be undone: the keys and certificates above are "
                       "lost for good.",
    "piv-reset-done": "PIV was reset: PIN 123456, PUK 12345678, the default management key.",
}

register_translations(ZH, EN)

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------

PGP_REFS = ("sig", "dec", "aut")
PGP_REF_NUMBERS = mgr_pgp.KEY_REFS                  # KEY_LIST key IDs (keyio.PGP_KEY_REFS)
PGP_SLOT_TITLES = {"sig": "Signature", "dec": "Decryption", "aut": "Authentication"}
PGP_FILE_LABELS = {"sig": "signature", "dec": "decryption", "aut": "authentication"}
PGP_PREFERRED = {"sig": "ed25519", "dec": "cv25519", "aut": "ed25519"}     # for an empty slot
PGP_UIF = {0: "off", 1: "on", 2: "on, permanent", 3: "cached", 4: "cached, permanent"}
PGP_UIF_FIXED = mgr_pgp.UIF_PERMANENT
PGP_PIN_MIN, PGP_ADMIN_PIN_MIN, PGP_PIN_MAX = mgr_pgp.PW1_MIN, mgr_pgp.PW3_MIN, mgr_pgp.PW_MAX
PGP_RC_MIN = mgr_pgp.RC_MIN
PGP_NAME_MAX = mgr_pgp.NAME_MAX
PGP_URL_MAX = 255

PIV_SLOTS = mgr_piv.SLOTS
PIV_MAIN_SLOTS = PIV_SLOTS[:4]
PIV_SLOT_TITLES = {0x9A: "Authentication", 0x9C: "Digital signature", 0x9D: "Key management",
                   0x9E: "Card authentication"}
# The order a list shows what the device generates (mgr_piv.ALGORITHMS names).
PIV_ALGORITHM_ORDER = ("eccp256", "eccp384", "ed25519", "rsa2048", "rsa3072", "rsa4096", "rsa1024", "x25519")
PIV_GENERATED = ("rsa1024", "rsa2048", "eccp256", "eccp384")        # when the device lists none
PIV_NO_SIGNATURE = ("x25519",)          # agrees keys only: no certificate, no request
PIV_PIN_POLICIES = tuple(mgr_piv.PIN_POLICIES)          # ("default", "never", "once", "always")
PIV_TOUCH_POLICIES = tuple(mgr_piv.TOUCH_POLICIES)      # ("default", "never", "always", "cached")
# (name for PivManager.set_management_key, label)
PIV_MGMT_ALGORITHMS = (("aes192", "AES-192"), ("aes128", "AES-128"), ("aes256", "AES-256"), ("3des", "3DES"))
PIV_PIN_MIN, PIV_PIN_MAX = mgr_piv.PIN_MIN, mgr_piv.PIN_LEN
PIV_DAYS_MAX = mgr_piv.DAYS_MAX
CERT_FILE_MAX = 64 * 1024


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def _text(v):
    """A value of a status as text safe to show."""
    if v is None or v == "" or v == b"":
        return "-"
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).hex().upper()
    if isinstance(v, (tuple, list)):
        return ".".join(str(x) for x in v)
    return display_name(str(v))


def _date(v):
    """A time of a status (Unix seconds, datetime or text) as a date."""
    if v is None or v == "" or isinstance(v, bool):
        return "-"
    if isinstance(v, (int, float)):
        try:
            return time.strftime("%Y-%m-%d", time.gmtime(v))
        except (OverflowError, OSError, ValueError):
            return str(v)
    if isinstance(v, datetime.datetime):
        return v.strftime("%Y-%m-%d")
    if isinstance(v, datetime.date):
        return v.isoformat()
    return display_name(str(v))


def _expired(v):
    if isinstance(v, datetime.datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=datetime.timezone.utc)
        return v < datetime.datetime.now(datetime.timezone.utc)
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v < time.time()
    return False


def _fingerprint(fp):
    """A fingerprint (hex or bytes) in groups of four digits; None when there
    is none (or zeros)."""
    if isinstance(fp, (bytes, bytearray)):
        fp = bytes(fp).hex()
    if not isinstance(fp, str) or not fp.strip("0 "):
        return None
    fp = "".join(fp.split()).upper()
    return " ".join(fp[i:i + 4] for i in range(0, len(fp), 4))


def _parse_hex(text):
    """The bytes of a key typed in hexadecimal (spaces, colons and a 0x prefix
    allowed). Raises ValueError."""
    t = "".join(text.split()).replace(":", "")
    if t[:2].lower() == "0x":
        t = t[2:]
    if not t:
        raise ValueError("empty")
    return bytes.fromhex(t)


def _size_problem(T, text, low, high):
    """Why a new PIN / code of text does not fit low..high (UTF-8 bytes, as
    the cards count), or None."""
    size = len(text.encode("utf-8"))
    ascii_only = text.isascii()
    if size < low:
        return (T("At least %d characters.") if ascii_only else T("At least %d bytes (UTF-8).")) % low
    if high is not None and size > high:
        return (T("At most %d characters.") if ascii_only else T("At most %d bytes (UTF-8).")) % high
    return None


def _write_public(path, data):
    """Writes public data (a certificate, a certificate request) to path."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    with open(path, "wb") as f:
        f.write(bytes(data))
    return path


def _spki(public_key):
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _pem_public_key(pem):
    """The DER SubjectPublicKeyInfo of a PEM public key, or None."""
    from cryptography.hazmat.primitives import serialization
    if isinstance(pem, str):
        pem = pem.encode("ascii", "replace")
    try:
        return _spki(serialization.load_pem_public_key(pem))
    except (ValueError, TypeError):
        return None


def _cert_time(cert, which):
    """not_valid_before / not_valid_after of a certificate, in UTC."""
    utc = getattr(cert, which + "_utc", None)         # cryptography 42 and newer
    return utc if utc is not None else getattr(cert, which).replace(tzinfo=datetime.timezone.utc)


def _pem_lines(pem):
    """PEM text (public data from the device) as lines safe to show."""
    if isinstance(pem, (bytes, bytearray)):
        pem = bytes(pem).decode("ascii", "replace")
    return [display_name(line) for line in str(pem).strip().splitlines()]


def _pgp_algorithms_for(ref):
    """What generate() offers for key slot ref when the card lists nothing."""
    out = []
    for name in mgr_pgp.ALGORITHMS:
        try:
            mgr_pgp.algorithm_attributes(name, ref)
        except ManagerError:
            continue
        out.append(name)
    return out


# ----------------------------------------------------------------------------
# Form dialog
# ----------------------------------------------------------------------------

class FormDialog(QDialog):
    """A small form (text and secret fields, choices, numbers, check boxes)
    whose checks run before it closes; a problem is shown in the dialog,
    which stays open. ask() returns {key: value} or None (cancelled). Every
    text field is emptied when the dialog closes: what was typed lives on
    only in the returned dict, which the caller hands to one operation."""

    def __init__(self, parent, T, title, intro=None):
        super().__init__(parent)
        self.T = T
        self.setWindowTitle(title)
        self.fields = {}
        self.checks = []
        self.values = None
        self.form = QFormLayout(self)
        if intro:
            self.form.addRow(text_label(intro))
        self.problem = text_label("")
        self.problem.setStyleSheet("color:#a00;")
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self._accept)
        self.buttons.rejected.connect(self.reject)

    # -- building --------------------------------------------------------------
    def line(self, key, label, text="", secret=False, placeholder="", max_length=None):
        field = QLineEdit(text)
        if secret:
            field.setEchoMode(QLineEdit.EchoMode.Password)
        if placeholder:
            field.setPlaceholderText(placeholder)
        if max_length:
            field.setMaxLength(max_length)
        self.fields[key] = field
        self.form.addRow(label, field)
        return field

    def choice(self, key, label, items, current=None):
        box = QComboBox()
        self.set_items(box, items, current)
        self.fields[key] = box
        self.form.addRow(label, box)
        return box

    def number(self, key, label, low, high, value):
        spin = QSpinBox()
        spin.setRange(low, high)
        spin.setValue(value)
        self.fields[key] = spin
        self.form.addRow(label, spin)
        return spin

    def flag(self, key, text, checked=False):
        box = QCheckBox(text)
        box.setChecked(checked)
        self.fields[key] = box
        self.form.addRow(box)
        return box

    def widget(self, widget, label=""):
        self.form.addRow(label, widget)
        return widget

    def note(self, text):
        self.form.addRow(text_label(text))

    @staticmethod
    def set_items(box, items, current=None):
        """Puts items [(text, data)] into box, current selected if there
        (else the first one)."""
        box.blockSignals(True)
        box.clear()
        for text, data in items:
            box.addItem(text, data)
        index = next((i for i, (_, data) in enumerate(items) if current is not None and data == current), 0)
        box.setCurrentIndex(index)
        box.blockSignals(False)

    def set_label(self, field, text):
        label = self.form.labelForField(field)
        if label is not None:
            label.setText(text)

    # -- checks ----------------------------------------------------------------
    def check(self, fn):
        """fn(values) -> the problem (text) or None."""
        self.checks.append(fn)

    def require(self, *keys, message=None):
        """The fields keys (enabled ones) must not be empty."""
        text = message or self.T("Fill in every field.")
        self.check(lambda v: text if any(self.fields[k].isEnabled() and not v[k] for k in keys) else None)

    def new_secret(self, new, repeat, low, high):
        """A new PIN / code typed twice, low..high bytes long."""
        def check(v):
            if v[new] != v[repeat]:
                self.fields[repeat].clear()
                return self.T("The two entries differ.")
            if not v[new]:
                return self.T("Fill in every field.")
            return _size_problem(self.T, v[new], low, high)
        self.check(check)

    # -- running ---------------------------------------------------------------
    def value(self, key):
        w = self.fields[key]
        if isinstance(w, QLineEdit):
            return w.text()
        if isinstance(w, QComboBox):
            return w.currentData()
        if isinstance(w, QCheckBox):
            return w.isChecked()
        return w.value()

    def _accept(self):
        values = {key: self.value(key) for key in self.fields}
        for fn in self.checks:
            problem = fn(values)
            if problem:
                self.problem.setText(problem)
                return
        self.problem.setText("")
        self.values = values
        self.accept()

    def ask(self):
        self.form.addRow(self.problem)
        self.form.addRow(self.buttons)
        try:
            self.exec()
            return self.values
        finally:
            self.values = None
            for w in self.fields.values():
                if isinstance(w, QLineEdit):
                    w.clear()
            self.deleteLater()


# ----------------------------------------------------------------------------
# Page base
# ----------------------------------------------------------------------------

class _AppPage(ManagerPage):
    """What the OpenPGP and PIV pages share: the status read in the worker,
    operations on the manager, errors, PIN dialogs."""

    APP = None

    def __init__(self, ctx, factory):
        super().__init__(ctx)
        self.factory = factory          # Management -> manager (tests give fakes)
        self.status = None
        self.state = None

    # -- plumbing --------------------------------------------------------------
    def _ready(self):
        """A device is connected (said when not) and no operation runs (a
        quiet one is shown: ManagerContext.free)."""
        try:
            self.ctx.management()
        except RuntimeError as e:
            self.ctx.error(str(e))
            return False
        return self.ctx.free()

    def _need_status(self):
        if self.status is None:
            self.ctx.error(self.T("Refresh first: the page has not read the device yet."))
            return False
        return True

    def _read(self, mgr):
        """What the page shows, read in the worker."""
        return mgr.status()

    def refresh(self, quiet=False):
        """Reads the application in the worker. quiet: loaded by the page
        itself (shown, or after an operation): a failure is only written on
        the page, and without a device (gone meanwhile) the page is only
        cleared."""
        if quiet and not self.ctx.connected():
            self.clear()
            self.loaded = False
            return
        if not quiet and not self._ready():
            return
        factory = self.factory

        def failed(e):
            self.clear()
            self.state.setText(self.ctx.error_text(e))
            if quiet:
                return True
            if isinstance(e, (ManagerError, ApduError)):
                self.ctx.error(self.ctx.error_text(e))
                return True
            return False                        # (the main window shows it)
        self.ctx.run(lambda: self._read(self.manager(factory)), self._show, failed)

    def auto_refresh(self):
        self.refresh(quiet=True)

    def _op(self, work, done=None, touch=False, reread=True):
        """Runs work(manager) in the worker; afterwards done(result) on the GUI
        thread. The page reads the device again afterwards (reread), after a
        failure too (tries left change), once the error was seen."""
        factory = self.factory

        def finished(result):
            if done is not None:
                done(result)
            if reread:
                self.refresh(quiet=True)

        def failed(e):
            if reread:
                self.ctx.when_idle(lambda: self.refresh(quiet=True))
            if isinstance(e, (ManagerError, ApduError)):
                self.ctx.error(self.ctx.error_text(e))
                return True
            return False                        # (the main window shows it)
        return self.ctx.run(lambda: work(self.manager(factory)), finished, failed, touch=touch)

    def _change_dialog(self, title, intro, current_label, new_label, low, high):
        """(current, new) of a PIN / code change dialog, or None."""
        T = self.T
        dlg = FormDialog(self, T, title, intro)
        dlg.line("current", current_label, secret=True)
        dlg.line("new", new_label, secret=True)
        dlg.line("repeat", T("Repeat:"), secret=True)
        dlg.require("current")
        dlg.new_secret("new", "repeat", low, high)
        v = dlg.ask()
        return None if v is None else (v["current"], v["new"])

    def import_file(self):
        if self._ready():
            self.ctx.import_file(then=lambda: self.refresh(quiet=True))


# ----------------------------------------------------------------------------
# OpenPGP
# ----------------------------------------------------------------------------

class OpenPgpPage(_AppPage):
    APP = "openpgp"

    def __init__(self, ctx, factory=None):
        super().__init__(ctx, factory or mgr_pgp.OpenPgpManager)
        T = self.T
        self.algorithms = {}            # key slot -> names the card offers (None: it lists none)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.labels = {}
        for key, title in (("version", "Version"), ("serial", "Serial number"), ("name", "Cardholder name"),
                           ("url", "Public key URL"), ("retries", "PIN tries left"),
                           ("signatures", "Signatures made")):
            lbl = text_label("-")
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.labels[key] = lbl
            form.addRow(T(title) + T(":"), lbl)
        lay.addLayout(form)
        self.state = text_label(T("pgp-hint"))
        lay.addWidget(self.state)
        self.table = make_table([T("Key"), T("Algorithm"), T("Fingerprint"), T("Created"), T("Touch")])
        lay.addWidget(self.table, 1)
        row, _ = button_row([(T("Generate..."), self.generate), (T("Touch policy..."), self.touch_policy),
                             (T("Delete key..."), self.delete_key), (T("Export selected..."), self.export_selected),
                             (T("Import..."), self.import_file)])
        lay.addLayout(row)
        pins = QGroupBox(T("PINs"))
        row, _ = button_row([(T("Change PIN..."), self.change_pin), (T("Change Admin PIN..."), self.change_admin_pin),
                             (T("Set Reset Code..."), self.set_reset_code), (T("Unblock PIN..."), self.unblock_pin)])
        pins.setLayout(row)
        lay.addWidget(pins)
        row, _ = button_row([(T("Cardholder name..."), self.cardholder_name), (T("Public key URL..."), self.url),
                             (T("Reset OpenPGP..."), self.reset), (T("Refresh"), lambda: self.refresh())])
        lay.addLayout(row)

    # -- display -----------------------------------------------------------------
    def clear(self):
        self.status = None
        self.algorithms = {}
        for lbl in self.labels.values():
            lbl.setText("-")
        self.table.setRowCount(0)
        self.state.setText(self.T("pgp-hint"))

    def _read(self, mgr):
        status = mgr.status()
        algorithms = {}
        for ref in PGP_REFS:
            try:
                algorithms[ref] = list(mgr.supported_algorithms(ref))
            except ManagerError:
                algorithms[ref] = None
        return status, algorithms

    def _key(self, ref):
        return ((self.status or {}).get("keys") or {}).get(ref) or {}

    def _has_key(self, ref):
        """Whether key slot ref holds a key: what the card says (key
        information), else whether it has a fingerprint."""
        k = self._key(ref)
        present = k.get("present")
        return bool(present) if present is not None else _fingerprint(k.get("fingerprint")) is not None

    def _retries(self):
        return (list((self.status or {}).get("pin_retries") or ()) + [None] * 3)[:3]

    def _uif_text(self, v):
        return "-" if v is None else self.T(PGP_UIF[v]) if v in PGP_UIF else str(v)

    def _algorithm_text(self, ref):
        k = self._key(ref)
        return _text(k.get("label") or k.get("algorithm"))

    def _key_text(self, ref):
        T = self.T
        if not self._has_key(ref):
            return T("%s key: none") % T(PGP_SLOT_TITLES[ref])
        k = self._key(ref)
        return T("%s key: %s, fingerprint %s, created %s") % (
            T(PGP_SLOT_TITLES[ref]), self._algorithm_text(ref), _fingerprint(k.get("fingerprint")) or "-",
            _date(k.get("created")))

    def _show(self, result):
        T = self.T
        st, self.algorithms = result
        self.status, self.loaded = st, True
        self.labels["version"].setText(_text(st.get("version")))
        self.labels["serial"].setText(_text(st.get("serial")))
        self.labels["name"].setText(_text(st.get("name")))
        self.labels["url"].setText(_text(st.get("url")))
        pw1, rc, pw3 = self._retries()
        self.labels["retries"].setText(T("PIN %s, Reset Code %s, Admin PIN %s") % (_text(pw1), _text(rc), _text(pw3)))
        self.labels["signatures"].setText(_text(st.get("signature_counter")))
        row = selected_row(self.table)
        rows = []
        for ref in PGP_REFS:
            k = self._key(ref)
            has = self._has_key(ref)
            rows.append((T(PGP_SLOT_TITLES[ref]), self._algorithm_text(ref) if has else "-",
                         (_fingerprint(k.get("fingerprint")) or "-") if has else T("no key"),
                         _date(k.get("created")) if has else "-", self._uif_text(k.get("uif"))))
        fill_table(self.table, rows)
        if row is not None:
            self.table.selectRow(row)
        notes = []
        if pw1 == 0:
            notes.append(T("The PIN is blocked: unblock it with the Reset Code or the Admin PIN."))
        if pw3 == 0:
            notes.append(T("The Admin PIN is blocked: only a reset of OpenPGP makes its keys usable again."))
        self.state.setText("\n".join(notes))

    def _selected_ref(self, need=True):
        r = selected_row(self.table)
        if r is not None and r < len(PGP_REFS) and self.status is not None:
            return PGP_REFS[r]
        if need:
            self.ctx.error(self.T("Select a key slot first."))
        return None

    def _admin_pin(self):
        """The Admin PIN for one operation, or None (cancelled, or not typed:
        said)."""
        T = self.T
        pin = self.ctx.ask_secret(T("OpenPGP Admin PIN"), T("OpenPGP Admin PIN:"))
        if pin is None:
            return None
        if not pin:
            self.ctx.error(T("The OpenPGP Admin PIN is needed."))
            return None
        return pin

    def _algorithm_items(self, ref):
        names = self.algorithms.get(ref) or _pgp_algorithms_for(ref)
        return [(mgr_pgp.ALGORITHM_LABELS.get(n, n), n) for n in names]

    def _proposed_algorithm(self, ref):
        """The slot's algorithm when it holds a key, else a modern one."""
        if self._has_key(ref) and self._key(ref).get("algorithm"):
            return self._key(ref)["algorithm"]
        return PGP_PREFERRED[ref]

    def _slot_items(self):
        return [(self.T(PGP_SLOT_TITLES[r]), r) for r in PGP_REFS]

    # -- keys ----------------------------------------------------------------------
    def generate(self):
        if not self._ready() or not self._need_status():
            return
        T = self.T
        first = self._selected_ref(need=False) or "sig"
        dlg = FormDialog(self, T, T("Generate an OpenPGP key"), T("pgp-generate-info"))
        slot = dlg.choice("ref", T("Key slot:"), self._slot_items(), first)
        algo = dlg.choice("algorithm", T("Algorithm:"), self._algorithm_items(first), self._proposed_algorithm(first))
        slot.currentIndexChanged.connect(lambda _i: dlg.set_items(
            algo, self._algorithm_items(slot.currentData()), self._proposed_algorithm(slot.currentData())))
        dlg.line("admin", T("Admin PIN:"), secret=True)
        dlg.require("admin", message=T("The OpenPGP Admin PIN is needed."))
        v = dlg.ask()
        if v is None:
            return
        ref, algorithm, admin = v["ref"], v["algorithm"], v["admin"]
        title = T(PGP_SLOT_TITLES[ref])
        replace = self._has_key(ref)
        if replace and not self.ctx.confirm(T("Replace the %s key?") % title + "\n\n" + self._key_text(ref) + "\n\n" +
                                            T("pgp-replace-info"), danger=True):
            return

        def done(r):
            r = r if isinstance(r, dict) else {}
            self.ctx.info("\n".join((T("New %s key generated on the device.") % title,
                                     T("Fingerprint: %s") % (_fingerprint(r.get("fingerprint")) or "-"),
                                     T("Created: %s") % _date(r.get("created")), "", T("pgp-gnupg-hint"))))
        self._op(lambda mgr: mgr.generate(ref, algorithm, admin, replace=replace), done)

    def delete_key(self):
        if not self._ready() or not self._need_status():
            return
        T = self.T
        ref = self._selected_ref()
        if ref is None:
            return
        title = T(PGP_SLOT_TITLES[ref])
        if not self._has_key(ref):
            self.ctx.error(T("The %s key slot is empty.") % title)
            return
        if not self.ctx.confirm(T("Delete the %s key?") % title + "\n\n" + self._key_text(ref) + "\n\n" +
                                T("pgp-delete-info"), danger=True):
            return
        admin = self._admin_pin()
        if admin is None:
            return
        self._op(lambda mgr: mgr.delete_key(ref, admin), lambda r: self.ctx.info(T("The %s key was deleted.") % title))

    def touch_policy(self):
        if not self._ready() or not self._need_status():
            return
        T = self.T
        first = self._selected_ref(need=False) or "sig"
        choices = [(T(PGP_UIF[n]), n) for n in sorted(PGP_UIF)]
        dlg = FormDialog(self, T, T("Touch policy"), T("pgp-uif-info"))
        slot = dlg.choice("ref", T("Key slot:"), self._slot_items(), first)
        uif = dlg.choice("uif", T("Touch:"), choices, self._key(first).get("uif"))
        slot.currentIndexChanged.connect(
            lambda _i: dlg.set_items(uif, choices, self._key(slot.currentData()).get("uif")))
        dlg.line("admin", T("Admin PIN:"), secret=True)
        dlg.require("admin", message=T("The OpenPGP Admin PIN is needed."))
        v = dlg.ask()
        if v is None:
            return
        ref, value, admin = v["ref"], v["uif"], v["admin"]
        title = T(PGP_SLOT_TITLES[ref])
        current = self._key(ref).get("uif")
        if value == current:
            self.ctx.info(T("Nothing to change."))
            return
        if current in PGP_UIF_FIXED:
            self.ctx.error(T("pgp-uif-fixed"))
            return
        permanent = value in PGP_UIF_FIXED
        if permanent and not self.ctx.confirm(T("Make the touch policy of the %s key permanent?") % title + "\n\n" +
                                              T("pgp-uif-permanent"), danger=True):
            return
        self._op(lambda mgr: mgr.set_uif(ref, value, admin, permanent=permanent),
                 lambda r: self.ctx.info(T("Touch policy of the %s key: %s") % (title, T(PGP_UIF[value]))))

    def export_selected(self):
        if not self._ready() or not self._need_status():
            return
        ref = self._selected_ref()
        if ref is None:
            return
        if not self._has_key(ref):
            self.ctx.error(self.T("The %s key slot is empty.") % self.T(PGP_SLOT_TITLES[ref]))
            return
        self.ctx.export_selected(self.APP, PGP_REF_NUMBERS[ref], label=PGP_FILE_LABELS[ref])

    # -- PINs and settings -----------------------------------------------------------
    def change_pin(self):
        if not self._ready():
            return
        T = self.T
        got = self._change_dialog(T("Change PIN"), T("pgp-pin-info"), T("Current PIN:"), T("New PIN:"),
                                  PGP_PIN_MIN, PGP_PIN_MAX)
        if got is None:
            return
        old, new = got
        self._op(lambda mgr: mgr.change_pin(old, new), lambda r: self.ctx.info(T("The PIN was changed.")))

    def change_admin_pin(self):
        if not self._ready():
            return
        T = self.T
        got = self._change_dialog(T("Change Admin PIN"), T("pgp-admin-pin-info"), T("Current Admin PIN:"),
                                  T("New Admin PIN:"), PGP_ADMIN_PIN_MIN, PGP_PIN_MAX)
        if got is None:
            return
        old, new = got
        self._op(lambda mgr: mgr.change_admin_pin(old, new), lambda r: self.ctx.info(T("The Admin PIN was changed.")))

    def set_reset_code(self):
        if not self._ready():
            return
        T = self.T
        got = self._change_dialog(T("Set Reset Code"), T("pgp-reset-code-info"), T("Admin PIN:"),
                                  T("New Reset Code:"), PGP_RC_MIN, PGP_PIN_MAX)
        if got is None:
            return
        admin, code = got
        self._op(lambda mgr: mgr.set_reset_code(admin, code), lambda r: self.ctx.info(T("The Reset Code was set.")))

    def unblock_pin(self):
        if not self._ready():
            return
        T = self.T
        rc = self._retries()[1]
        labels = {"reset_code": T("Reset Code:"), "admin_pin": T("Admin PIN:")}
        dlg = FormDialog(self, T, T("Unblock PIN"), T("pgp-unblock-info"))
        how = dlg.choice("how", T("Unblock with:"), [(T("the Reset Code"), "reset_code"),
                                                     (T("the Admin PIN"), "admin_pin")],
                         "reset_code" if rc else "admin_pin")
        secret = dlg.line("secret", labels[how.currentData()], secret=True)
        how.currentIndexChanged.connect(lambda _i: dlg.set_label(secret, labels[how.currentData()]))
        dlg.line("new", T("New PIN:"), secret=True)
        dlg.line("repeat", T("Repeat:"), secret=True)
        dlg.require("secret")
        dlg.new_secret("new", "repeat", PGP_PIN_MIN, PGP_PIN_MAX)
        v = dlg.ask()
        if v is None:
            return
        new, kwargs = v["new"], {v["how"]: v["secret"]}
        self._op(lambda mgr: mgr.unblock_pin(new, **kwargs),
                 lambda r: self.ctx.info(T("The PIN was unblocked and set.")))

    def _setting(self, title, intro, label, current, max_len, ascii_only, apply, done_text):
        """A card setting (text) changed with the Admin PIN: apply(manager,
        text, admin PIN)."""
        T = self.T
        dlg = FormDialog(self, T, title, intro)
        dlg.line("text", label, text=current if isinstance(current, str) else "")
        dlg.line("admin", T("Admin PIN:"), secret=True)
        dlg.require("admin", message=T("The OpenPGP Admin PIN is needed."))
        if ascii_only:
            dlg.check(lambda v: T("pgp-ascii") if any(not " " <= c <= "~" for c in v["text"].strip()) else None)
        dlg.check(lambda v: _size_problem(T, v["text"].strip(), 0, max_len))
        v = dlg.ask()
        if v is None:
            return
        text, admin = v["text"].strip(), v["admin"]
        self._op(lambda mgr: apply(mgr, text, admin), lambda r: self.ctx.info(done_text))

    def cardholder_name(self):
        if self._ready():
            T = self.T
            self._setting(T("Cardholder name"), T("pgp-name-info"), T("Name:"), (self.status or {}).get("name"),
                          PGP_NAME_MAX, True, lambda mgr, text, admin: mgr.set_cardholder(text, admin),
                          T("The cardholder name was set."))

    def url(self):
        if self._ready():
            T = self.T
            self._setting(T("Public key URL"), T("pgp-url-info"), T("URL:"), (self.status or {}).get("url"),
                          PGP_URL_MAX, False, lambda mgr, text, admin: mgr.set_url(text, admin),
                          T("The public key URL was set."))

    def reset(self):
        if not self._ready() or not self._need_status():
            return
        T = self.T
        lost = [self._key_text(r) for r in PGP_REFS if self._has_key(r)] or [T("It holds no key.")]
        name = (self.status or {}).get("name")
        if name:
            lost.append(T("Cardholder name: %s") % _text(name))
        if not self.ctx.confirm(T("Reset the OpenPGP application?") + "\n\n" + T("pgp-reset-info") + "\n\n" +
                                "\n".join(lost), danger=True):
            return
        if not self.ctx.confirm(T("pgp-reset-again"), danger=True):
            return
        admin = self.ctx.ask_secret(T("OpenPGP Admin PIN"), T("pgp-reset-admin"))
        if admin is None:
            return
        admin = admin or None
        self._op(lambda mgr: mgr.reset(admin_pin=admin), lambda r: self.ctx.info(T("pgp-reset-done")), touch=True)


# ----------------------------------------------------------------------------
# PIV
# ----------------------------------------------------------------------------

def _policy_text(T, v, names):
    """A PIN or touch policy (name, or metadata number) as text."""
    if v is None:
        return "-"
    if type(v) is int:
        return T(names[v]) if 0 <= v < len(names) else str(v)
    return T(str(v))


class PivPage(_AppPage):
    APP = "piv"

    def __init__(self, ctx, factory=None):
        super().__init__(ctx, factory or mgr_piv.PivManager)
        T = self.T
        self.slots = []                 # the slot of each table row
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.labels = {}
        for key, title in (("version", "Version"), ("serial", "Serial number"), ("retries", "Tries left"),
                           ("mgmt", "Management key")):
            lbl = text_label("-")
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.labels[key] = lbl
            form.addRow(T(title) + T(":"), lbl)
        lay.addLayout(form)
        self.state = text_label(T("piv-hint"))
        lay.addWidget(self.state)
        self.all_slots = QCheckBox(T("Show all slots (retired key slots too)"))
        self.all_slots.toggled.connect(lambda _on: self._fill())
        lay.addWidget(self.all_slots)
        self.table = make_table([T("Slot"), T("Key"), T("Origin"), T("PIN policy"), T("Touch policy"),
                                 T("Certificate"), T("Expires")])
        self.table.itemSelectionChanged.connect(self._show_details)
        lay.addWidget(self.table, 1)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText(T("Select a slot to see its key and certificate."))
        self.details.setMaximumHeight(170)
        lay.addWidget(self.details)
        row, _ = button_row([(T("Generate..."), self.generate), (T("Import certificate..."), self.import_certificate),
                             (T("Export certificate..."), self.export_certificate),
                             (T("Delete certificate..."), self.delete_certificate)])
        lay.addLayout(row)
        row, _ = button_row([(T("Delete key..."), self.delete_key), (T("Move key..."), self.move_key),
                             (T("Export selected..."), self.export_selected), (T("Import..."), self.import_file)])
        lay.addLayout(row)
        creds = QGroupBox(T("PIN, PUK and management key"))
        row, _ = button_row([(T("Change PIN..."), self.change_pin), (T("Change PUK..."), self.change_puk),
                             (T("Unblock PIN..."), self.unblock_pin), (T("Management key..."), self.management_key)])
        creds.setLayout(row)
        lay.addWidget(creds)
        row, _ = button_row([(T("Reset PIV..."), self.reset), (T("Refresh"), lambda: self.refresh())])
        lay.addLayout(row)

    # -- display -----------------------------------------------------------------
    def clear(self):
        self.status = None
        self.slots = []
        for lbl in self.labels.values():
            lbl.setText("-")
        self.table.setRowCount(0)
        self.details.clear()
        self.state.setText(self.T("piv-hint"))

    def _slot(self, s):
        return ((self.status or {}).get("slots") or {}).get(s) or {}

    def _has_key(self, s):
        e = self._slot(s)
        return bool(e["has_key"]) if e.get("has_key") is not None else bool(e.get("algorithm") or
                                                                              e.get("public_key"))

    def _cert(self, s):
        c = self._slot(s).get("certificate")
        return c if isinstance(c, dict) else None

    def _occupied(self, s):
        return self._has_key(s) or self._cert(s) is not None

    def _title(self, s):
        T = self.T
        name = T(PIV_SLOT_TITLES[s]) if s in PIV_SLOT_TITLES else T("Retired %d") % (s - 0x81)
        return "%02X" % s + T(" (%s)") % name

    def _algorithm_text(self, s):
        name = self._slot(s).get("algorithm")
        return _text(mgr_piv.ALGORITHM_LABELS.get(name, name))

    def _origin_text(self, s):
        origin = self._slot(s).get("origin")
        return self.T(str(origin)) if origin else "-"

    def _show(self, st):
        T = self.T
        self.status, self.loaded = st, True
        serial = st.get("serial")
        self.labels["version"].setText(_text(st.get("version")))
        self.labels["serial"].setText(str(serial) if type(serial) is int else _text(serial))
        pin, puk = st.get("pin_retries"), st.get("puk_retries")
        self.labels["retries"].setText(T("PIN %s, PUK %s") % (_text(pin), _text(puk)))
        algo = st.get("mgmt_key_algorithm")
        mgmt = [_text(dict(PIV_MGMT_ALGORITHMS).get(algo, algo))]
        if st.get("mgmt_key_default"):
            mgmt.append(T("default key"))
        if st.get("mgmt_key_touch"):
            mgmt.append(T("touch"))
        self.labels["mgmt"].setText(T(", ").join(mgmt))
        notes = []
        if st.get("mgmt_key_default"):
            notes.append(T("piv-default-mgmt"))
        if st.get("pin_default"):
            notes.append(T("The default PIN is in use: change it."))
        if st.get("puk_default"):
            notes.append(T("The default PUK is in use: change it."))
        if pin == 0:
            notes.append(T("The PIN is blocked: unblock it with the PUK."))
        if puk == 0:
            notes.append(T("The PUK is blocked: once the PIN is blocked too, only a reset of PIV helps."))
        self.state.setText("\n".join(notes))
        self._fill()

    def _fill(self):
        T = self.T
        before = self._selected_slot(need=False)
        slots = [s for s in PIV_SLOTS if self.all_slots.isChecked() or s in PIV_MAIN_SLOTS or self._occupied(s)] \
            if self.status is not None else []
        rows = []
        for s in slots:
            e, c = self._slot(s), self._cert(s)
            subject, expires = "-", "-"
            if c and c.get("error"):
                subject = T("unreadable")
            elif c:
                subject = _text(c.get("subject"))
                expires = _date(c.get("not_after")) + (" " + T("(expired)") if _expired(c.get("not_after")) else "")
            has = self._has_key(s)
            rows.append((self._title(s), self._algorithm_text(s) if has else T("no key"),
                         self._origin_text(s) if has else "-",
                         _policy_text(T, e.get("pin_policy"), PIV_PIN_POLICIES) if has else "-",
                         _policy_text(T, e.get("touch_policy"), PIV_TOUCH_POLICIES) if has else "-",
                         subject, expires))
        self.slots = slots
        fill_table(self.table, rows)
        if before in slots:
            self.table.selectRow(slots.index(before))
        self._show_details()

    def _slot_lines(self, s, full=False):
        """What slot s holds, as lines of text (full: with the public key and
        the certificate in PEM)."""
        T = self.T
        e, c = self._slot(s), self._cert(s)
        lines = [T("Slot %s") % self._title(s)]
        if self._has_key(s):
            lines.append(T("Key: %s, %s; PIN policy %s, touch policy %s") % (
                self._algorithm_text(s), self._origin_text(s),
                _policy_text(T, e.get("pin_policy"), PIV_PIN_POLICIES),
                _policy_text(T, e.get("touch_policy"), PIV_TOUCH_POLICIES)))
        else:
            lines.append(T("Key: none"))
        if c and c.get("error"):
            lines.append(T("The certificate cannot be read: %s") % _text(c["error"]))
        elif c:
            serial = c.get("serial")
            lines += [T("Certificate:"), "  " + T("Subject: %s") % _text(c.get("subject")),
                      "  " + T("Issuer: %s") % _text(c.get("issuer")),
                      "  " + T("Serial number: %s") % ("%X" % serial if type(serial) is int else _text(serial)),
                      "  " + T("Valid from %s to %s") % (_date(c.get("not_before")), _date(c.get("not_after"))) +
                      (" " + T("(expired)") if _expired(c.get("not_after")) else "")]
            if c.get("matches_key") is False:
                lines.append("  " + T("The certificate does not belong to the key in this slot."))
        else:
            lines.append(T("Certificate: none"))
        if full:
            for title, pem in ((T("Public key:"), e.get("public_key")), (T("Certificate:"), c and c.get("pem"))):
                if pem:
                    lines += ["", title] + _pem_lines(pem)
        return lines

    def _show_details(self):
        s = self._selected_slot(need=False)
        if s is None:
            self.details.clear()
        else:
            self.details.setPlainText("\n".join(self._slot_lines(s, full=True)))

    def _selected_slot(self, need=True):
        r = selected_row(self.table)
        if r is not None and r < len(self.slots):
            return self.slots[r]
        if need:
            self.ctx.error(self.T("Select a slot first."))
        return None

    def _mgmt_key(self):
        """The management key for one operation: None for the default key
        (the device says it is in use, or left empty), else what was typed;
        False when cancelled or not hexadecimal (said)."""
        T = self.T
        if (self.status or {}).get("mgmt_key_default"):
            return None
        text = self.ctx.ask_secret(T("PIV management key"), T("PIV management key (hex; leave empty for the default "
                                                              "key):"))
        if text is None:
            return False
        if not text.strip():
            return None
        try:
            return _parse_hex(text)
        except ValueError:
            self.ctx.error(T("piv-bad-hex"))
            return False

    def _admin_op(self, work, done=None, touch=False, key=False):
        """_op with the management key checked first (asked for here unless
        given; None: the default one). The manager keeps it for its
        administrative commands: it is wiped once the operation ends. A
        management key set to need a touch makes the device wait for one."""
        if key is False:
            key = self._mgmt_key()
            if key is False:
                return False

        def run(mgr):
            try:
                mgr.authenticate(key)
                return work(mgr)
            finally:
                mgr.forget()
        return self._op(run, done, touch or bool((self.status or {}).get("mgmt_key_touch")))

    # -- keys ----------------------------------------------------------------------
    def _algorithm_items(self):
        listed = (self.status or {}).get("algorithms") or PIV_GENERATED
        names = [n for n in PIV_ALGORITHM_ORDER if n in listed] + [n for n in listed if n not in PIV_ALGORITHM_ORDER]
        return [(mgr_piv.ALGORITHM_LABELS.get(n, n), n) for n in names]

    def generate(self):
        if not self._ready() or not self._need_status():
            return
        T = self.T
        first = self._selected_slot(need=False) or PIV_MAIN_SLOTS[0]
        dlg = FormDialog(self, T, T("Generate a PIV key"), T("piv-generate-info"))
        dlg.choice("slot", T("Slot:"), [(self._title(s), s) for s in PIV_SLOTS], first)
        algo = dlg.choice("algorithm", T("Algorithm:"), self._algorithm_items())
        dlg.choice("pin_policy", T("PIN policy:"), [(T(p), p) for p in PIV_PIN_POLICIES])
        dlg.choice("touch_policy", T("Touch policy:"), [(T(p), p) for p in PIV_TOUCH_POLICIES])
        cert = dlg.choice("certificate", T("Certificate:"),
                          [(T("Self-signed certificate"), "self"),
                           (T("Certificate signing request (CSR) to a file"), "csr")])
        subject = dlg.line("subject", T("Subject:"), placeholder="CN=Alice")
        days = dlg.number("days", T("Valid for (days):"), 1, PIV_DAYS_MAX, 365)
        pin = dlg.line("pin", T("PIV PIN:"), secret=True)

        def update(_i=None):
            signs = algo.currentData() not in PIV_NO_SIGNATURE
            for w in (cert, subject, pin):
                w.setEnabled(signs)
            days.setEnabled(signs and cert.currentData() == "self")
        algo.currentIndexChanged.connect(update)
        cert.currentIndexChanged.connect(update)
        update()
        dlg.check(lambda v: T("Enter a subject, e.g. CN=Alice.") if subject.isEnabled() and not v["subject"].strip()
                  else None)
        dlg.require("pin")
        v = dlg.ask()
        if v is None:
            return
        s, algorithm = v["slot"], v["algorithm"]
        pin_policy, touch_policy = v["pin_policy"], v["touch_policy"]
        mode = "none" if algorithm in PIV_NO_SIGNATURE else v["certificate"]
        name, valid, pin_value = v["subject"].strip(), v["days"], v["pin"]
        replace = self._occupied(s)
        if replace and not self.ctx.confirm(T("Replace what slot %s holds?") % self._title(s) + "\n\n" +
                                            "\n".join(self._slot_lines(s)) + "\n\n" + T("piv-replace-info"),
                                            danger=True):
            return
        path = None
        if mode == "csr":
            path, _ = QFileDialog.getSaveFileName(self, T("Certificate signing request"), "piv-%02x.csr" % s,
                                                  "%s (*.csr *.pem);;%s (*)" % (T("Certificate requests"),
                                                                                T("All files")))
            if not path:
                return

        def work(mgr):
            mgr.generate(s, algorithm, pin_policy=pin_policy, touch_policy=touch_policy, replace=replace)
            if mode == "self":          # (over the certificate the device made itself)
                mgr.self_sign(s, name, valid, pin_value, replace=True)
            elif mode == "csr":
                _write_public(path, mgr.csr(s, name, pin_value))
            return mode

        def done(r):
            label = mgr_piv.ALGORITHM_LABELS.get(algorithm, algorithm)
            lines = [T("New %s key generated in slot %s.") % (label, self._title(s))]
            if mode == "self":
                lines.append(T("A self-signed certificate is in the slot."))
            elif mode == "csr":
                lines += [T("Certificate signing request written: %s") % path, T("piv-csr-cert")]
            else:
                lines.append(T("An X25519 key has no certificate."))
            self.ctx.info("\n".join(lines))
        # a signature by a key with a touch policy waits for a touch
        self._admin_op(work, done, touch=mode != "none" and touch_policy in ("always", "cached"))

    def delete_key(self):
        if not self._ready() or not self._need_status():
            return
        T = self.T
        s = self._selected_slot()
        if s is None:
            return
        if not self._has_key(s):
            self.ctx.error(T("Slot %s holds no key.") % self._title(s))
            return
        if not self.ctx.confirm(T("Delete the key of slot %s?") % self._title(s) + "\n\n" +
                                "\n".join(self._slot_lines(s)) + "\n\n" + T("piv-delete-key-info"), danger=True):
            return
        with_certificate = self._cert(s) is not None and self.ctx.confirm(T("Delete its certificate as well?"))
        self._admin_op(lambda mgr: mgr.delete_key(s, with_certificate=with_certificate),
                       lambda r: self.ctx.info(T("The key was deleted.")))

    def move_key(self):
        if not self._ready() or not self._need_status():
            return
        T = self.T
        src = self._selected_slot()
        if src is None:
            return
        if not self._has_key(src):
            self.ctx.error(T("Slot %s holds no key.") % self._title(src))
            return
        targets = [((T("%s (in use)") % self._title(s)) if self._occupied(s) else self._title(s), s)
                   for s in PIV_SLOTS if s != src]
        first = next((s for _, s in targets if not self._occupied(s)), targets[0][1])
        dlg = FormDialog(self, T, T("Move key"), "\n".join(self._slot_lines(src)))
        dlg.choice("to", T("To slot:"), targets, first)
        v = dlg.ask()
        if v is None:
            return
        dst = v["to"]
        replace = self._occupied(dst)
        question = T("Move the key of slot %s to slot %s?") % (self._title(src), self._title(dst)) + "\n\n" + \
            "\n".join(self._slot_lines(src))
        if replace:
            question += "\n\n" + T("What slot %s holds is erased for good:") % self._title(dst) + "\n" + \
                "\n".join(self._slot_lines(dst)[1:])
        question += "\n\n" + T("piv-move-info")
        if not self.ctx.confirm(question, danger=True):
            return
        self._admin_op(lambda mgr: mgr.move_key(src, dst, replace=replace),
                       lambda r: self.ctx.info(T("The key was moved.")))

    def export_selected(self):
        if not self._ready() or not self._need_status():
            return
        s = self._selected_slot()
        if s is None:
            return
        if not self._has_key(s):
            self.ctx.error(self.T("Slot %s holds no key.") % self._title(s))
            return
        self.ctx.export_selected(self.APP, s, label="%02x" % s)

    # -- certificates ----------------------------------------------------------------
    def import_certificate(self):
        if not self._ready() or not self._need_status():
            return
        T = self.T
        s = self._selected_slot()
        if s is None:
            return
        path, _ = QFileDialog.getOpenFileName(self, T("Import certificate..."), "",
                                              "%s (*.pem *.crt *.cer *.der);;%s (*)" % (T("Certificates"),
                                                                                        T("All files")))
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read(CERT_FILE_MAX + 1)
        except OSError as e:
            self.ctx.error(str(e))
            return
        if len(data) > CERT_FILE_MAX:
            self.ctx.error(T("%s is larger than %d KiB: not a certificate.") % (os.path.basename(path),
                                                                                 CERT_FILE_MAX // 1024))
            return
        try:
            certs = mgr_piv.load_certificates(data)
        except ManagerError as e:
            self.ctx.error(self.ctx.error_text(e))
            return
        key = _pem_public_key(self._slot(s).get("public_key") or b"") if self._has_key(s) else None
        cert = next((c for c in certs if key is not None and _spki(c.public_key()) == key), certs[0])
        mismatch = key is not None and _spki(cert.public_key()) != key
        what = [T("Subject: %s") % display_name(cert.subject.rfc4514_string()),
                T("Issuer: %s") % display_name(cert.issuer.rfc4514_string()),
                T("Valid from %s to %s") % (_date(_cert_time(cert, "not_valid_before")),
                                            _date(_cert_time(cert, "not_valid_after")))]
        if _expired(_cert_time(cert, "not_valid_after")):
            what[-1] += " " + T("(expired)")
        old = self._cert(s)
        if old:
            question = T("Replace the certificate of slot %s?") % self._title(s) + "\n\n" + "\n".join(what) + \
                "\n\n" + T("piv-cert-replace-info") + "\n" + T("Subject: %s") % _text(old.get("subject"))
        else:
            question = T("Import this certificate into slot %s?") % self._title(s) + "\n\n" + "\n".join(what)
        if mismatch:
            question += "\n\n" + T("piv-cert-mismatch")
        if not self.ctx.confirm(question, danger=bool(old) or mismatch):
            return
        from cryptography.hazmat.primitives import serialization
        der, replace = cert.public_bytes(serialization.Encoding.DER), old is not None
        self._admin_op(lambda mgr: mgr.import_certificate(s, der, replace=replace, verify=not mismatch),
                       lambda r: self.ctx.info(T("The certificate was imported.")))

    def export_certificate(self):
        if not self._ready() or not self._need_status():
            return
        T = self.T
        s = self._selected_slot()
        if s is None:
            return
        if not self._cert(s):
            self.ctx.error(T("Slot %s holds no certificate.") % self._title(s))
            return
        path, _ = QFileDialog.getSaveFileName(self, T("Export certificate..."), "piv-%02x.pem" % s,
                                              "%s (*.pem *.crt);;%s (*)" % (T("Certificates"), T("All files")))
        if not path:
            return
        self._op(lambda mgr: _write_public(path, mgr.export_certificate(s)),
                 lambda p: self.ctx.info(T("Certificate written: %s") % p), reread=False)

    def delete_certificate(self):
        if not self._ready() or not self._need_status():
            return
        T = self.T
        s = self._selected_slot()
        if s is None:
            return
        if not self._cert(s):
            self.ctx.error(T("Slot %s holds no certificate.") % self._title(s))
            return
        if not self.ctx.confirm(T("Delete the certificate of slot %s?") % self._title(s) + "\n\n" +
                                "\n".join(self._slot_lines(s)) + "\n\n" + T("piv-delete-cert-info"), danger=True):
            return
        self._admin_op(lambda mgr: mgr.delete_certificate(s),
                       lambda r: self.ctx.info(T("The certificate was deleted.")))

    # -- PIN, PUK, management key ----------------------------------------------------------
    def change_pin(self):
        if not self._ready():
            return
        T = self.T
        got = self._change_dialog(T("Change PIN"), T("piv-pin-info"), T("Current PIN:"), T("New PIN:"),
                                  PIV_PIN_MIN, PIV_PIN_MAX)
        if got is None:
            return
        old, new = got
        self._op(lambda mgr: mgr.change_pin(old, new), lambda r: self.ctx.info(T("The PIN was changed.")))

    def change_puk(self):
        if not self._ready():
            return
        T = self.T
        got = self._change_dialog(T("Change PUK"), T("piv-puk-info"), T("Current PUK:"), T("New PUK:"),
                                  PIV_PIN_MIN, PIV_PIN_MAX)
        if got is None:
            return
        old, new = got
        self._op(lambda mgr: mgr.change_puk(old, new), lambda r: self.ctx.info(T("The PUK was changed.")))

    def unblock_pin(self):
        if not self._ready():
            return
        T = self.T
        got = self._change_dialog(T("Unblock PIN"), T("piv-unblock-info"), T("PUK:"), T("New PIN:"),
                                  PIV_PIN_MIN, PIV_PIN_MAX)
        if got is None:
            return
        puk, new = got
        self._op(lambda mgr: mgr.unblock_pin(puk, new), lambda r: self.ctx.info(T("The PIN was unblocked and set.")))

    def management_key(self):
        if not self._ready():
            return
        T = self.T
        labels = dict(PIV_MGMT_ALGORITHMS)
        sizes = {name: mgr_piv.MGMT_KEY_SIZES[mgr_piv.MGMT_ALGORITHMS[name]] for name, _ in PIV_MGMT_ALGORITHMS}
        st = self.status or {}
        dlg = FormDialog(self, T, T("Change the management key"), T("piv-mgmt-info"))
        dlg.line("current", T("Current management key (hex; empty: the default key):"), secret=True)
        algo = dlg.choice("algorithm", T("Algorithm:"), [(label, name) for name, label in PIV_MGMT_ALGORITHMS],
                          st.get("mgmt_key_algorithm"))
        new = dlg.line("new", T("New management key (hex):"))
        random_button = dlg.widget(QPushButton(T("Random")))
        random_button.clicked.connect(lambda: new.setText(mgr_piv.generate_management_key(algo.currentData())))
        dlg.flag("touch", T("Require a touch for every use of the management key"), bool(st.get("mgmt_key_touch")))
        dlg.note(T("piv-mgmt-keep"))

        def check(v):
            if v["current"].strip():
                try:
                    _parse_hex(v["current"])
                except ValueError:
                    return T("piv-bad-hex")
            size = sizes[v["algorithm"]]
            try:
                ok = len(_parse_hex(v["new"])) == size
            except ValueError:
                ok = False
            return None if ok else T("%s: the new key must be %d bytes (%d hex digits).") % (
                labels[v["algorithm"]], size, 2 * size)
        dlg.check(check)
        v = dlg.ask()
        if v is None:
            return
        current = _parse_hex(v["current"]) if v["current"].strip() else None
        key, algorithm, touch = _parse_hex(v["new"]), v["algorithm"], v["touch"]
        if not self.ctx.confirm(T("Change the PIV management key?") + "\n\n" + T("piv-mgmt-keep"), danger=True):
            return
        self._admin_op(lambda mgr: mgr.set_management_key(key, algorithm, touch=touch),
                       lambda r: self.ctx.info(T("The management key was changed.")), key=current)

    def reset(self):
        if not self._ready() or not self._need_status():
            return
        T = self.T
        lost = []
        for s in PIV_SLOTS:
            if self._occupied(s):
                lost += self._slot_lines(s) + [""]
        text = T("Reset the PIV application?") + "\n\n" + T("piv-reset-info") + "\n\n" + \
            ("\n".join(lost).strip() or T("It holds no key and no certificate."))
        if not self.ctx.confirm(text, danger=True):
            return
        if not self.ctx.confirm(T("piv-reset-again"), danger=True):
            return
        self._op(lambda mgr: mgr.reset(), lambda r: self.ctx.info(T("piv-reset-done")), touch=True)
