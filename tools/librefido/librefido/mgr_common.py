"""Shared parts of the key manager (librefido.mgr_*): errors, application
selection and APDU helpers, and CTAP over the smart card interface.

Every manager takes a Management (librefido.mgmt): one card connection,
shared by every application of the device. An operation selects its
application inside one PC/SC transaction (no other program's commands in
between) and selects the management applet again afterwards, which also
ends whatever was authenticated in the application.

Errors are ManagerError (or a subclass): a user-readable English message
(str(e)), the Simplified Chinese one (e.zh, e.text(zh=True)) and the status
word that caused it (e.sw, None when none did). Secrets are never part of a
message and never logged.
"""

from contextlib import contextmanager

from fido2.ctap import CtapDevice, CtapError
from fido2.hid import CAPABILITY, CTAPHID
from smartcard.Exceptions import CardConnectionException

from . import keyio
from .mgmt import FIDO_AID
from .pcsc import MGMT_AID, ApduError

# CTAP over ISO 7816 (CTAP 2.1, 11.3: NFCCTAP_MSG); the firmware answers each
# command at once (no NFCCTAP_GETRESPONSE polling): SW 9000 with the CTAP
# status byte and the CBOR answer, or SW 64xx with the status byte in xx.
NFCCTAP_CLA, NFCCTAP_MSG = 0x80, 0x10


# ----------------------------------------------------------------------------
# Errors
# ----------------------------------------------------------------------------

class ManagerError(Exception):
    """A key manager operation failed. str(e): English message; zh: the
    Simplified Chinese one (None: none given, the English one is used); sw:
    the device's status word when one caused it."""

    def __init__(self, message, sw=None, zh=None):
        super().__init__(message)
        self.sw = sw
        self.zh = zh

    def text(self, zh=False):
        """The message in Simplified Chinese (zh) or English."""
        return self.zh if zh and self.zh else str(self)


class AuthRequired(ManagerError):
    """The operation needs a secret (PIN, password) the manager does not
    hold: ask for it, unlock, and try again."""


class WrongSecret(ManagerError):
    """A PIN, password or key was wrong; retries: attempts left when the
    device said (None otherwise)."""

    def __init__(self, message, sw=None, zh=None, retries=None):
        super().__init__(message, sw, zh)
        self.retries = retries


class SecretBlocked(ManagerError):
    """A PIN or password is blocked (too many wrong attempts)."""


class NotSupported(ManagerError):
    """The device, its firmware or this profile does not offer this."""


# Windows (1903 and later) lets only processes started as administrator reach
# the FIDO function of a security key, over its smart card interface too: the
# SELECT of the FIDO application fails with this code before it reaches the
# device. The other applications are not affected.
SCARD_E_NO_ACCESS = 0x80100027


class FidoBlockedByOs(NotSupported):
    """The operating system keeps this program from the FIDO application
    (Windows without administrator rights)."""

    def __init__(self):
        super().__init__(
            "Windows lets only programs started as administrator use the FIDO function of a security key. "
            "Start the LibreFido GUI as administrator to manage passkeys and the FIDO PIN; the other pages, "
            "the Keys tab and single-key export / import work without it.", None,
            "Windows 只允许以管理员身份启动的程序使用安全密钥的 FIDO 功能。要管理通行密钥和 FIDO PIN，"
            "请以管理员身份启动 LibreFido GUI；其他页面、“密钥”标签页和单个密钥的导出/导入不需要管理员身份。")


def error_text(e, zh=False):
    """Message of any exception for the user: a ManagerError in the chosen
    language, anything else as it describes itself."""
    return e.text(zh) if isinstance(e, ManagerError) else str(e)


# Status words (ISO 7816-4 and the applications of the device).
SW_TEXT = {
    0x6581: ("memory failure", "存储器故障"),
    0x6700: ("wrong length", "长度错误"),
    0x6882: ("secure messaging not supported", "不支持安全报文"),
    0x6982: ("security status not satisfied (a PIN, password or key is missing or wrong)",
             "安全状态不满足（缺少 PIN、密码或密钥，或其不正确）"),
    0x6983: ("blocked after too many wrong attempts", "错误次数过多，已锁定"),
    0x6984: ("wrong data or password", "数据或密码错误"),
    0x6985: ("not confirmed: touch the key when it blinks (or the key store is locked, or another operation "
             "is pending)", "未确认：请在按键闪烁时触摸它（或密钥存储已锁定，或有其他操作未完成）"),
    0x6986: ("not allowed by this profile or build", "此环境或固件构建不允许此操作"),
    0x6A80: ("the device refused the data as invalid", "设备认为数据无效"),
    0x6A81: ("not supported by this device or firmware", "此设备或固件不支持"),
    0x6A82: ("not found", "未找到"),
    0x6A84: ("no space left on the device", "设备空间不足"),
    0x6A86: ("incorrect parameters", "参数错误"),
    0x6A88: ("not found", "未找到"),
    0x6A89: ("already there (replace it explicitly)", "已存在（需明确选择替换）"),
    0x6D00: ("the firmware does not support this command", "固件不支持此命令"),
    0x6E00: ("class not supported", "不支持的 CLA"),
    0x6F00: ("internal error of the device", "设备内部错误"),
}


def sw_text(sw, zh=False):
    """Text of a status word (63Cx: wrong, x tries left)."""
    if sw & 0xFFF0 == 0x63C0:
        n = sw & 0xF
        return ("PIN 错误，还剩 %d 次" % n) if zh else ("wrong PIN, %d tries left" % n)
    en, cn = SW_TEXT.get(sw, ("error", "错误"))
    return cn if zh else en


def sw_error(what, sw, what_zh=None, texts=None):
    """ManagerError for status word sw of an operation (what: English,
    what_zh: Chinese name of it). texts: {sw: (English, Chinese)} for this
    operation, before the general ones. 63Cx gives WrongSecret (retries),
    6983 SecretBlocked."""
    en, cn = (texts or {}).get(sw) or (sw_text(sw), sw_text(sw, True))
    message = "%s: %s (SW %04X)" % (what, en, sw)
    zh = "%s：%s（SW %04X）" % (what_zh or what, cn, sw)
    if sw & 0xFFF0 == 0x63C0:
        return WrongSecret(message, sw, zh, retries=sw & 0xF)
    if sw == 0x6983:
        return SecretBlocked(message, sw, zh)
    if sw in (0x6A81, 0x6D00, 0x6E00):
        return NotSupported(message, sw, zh)
    return ManagerError(message, sw, zh)


# ----------------------------------------------------------------------------
# Applications, APDUs, TLV
# ----------------------------------------------------------------------------

@contextmanager
def applet(m, aid, name, name_zh=None):
    """The application aid of the device of m (a Management), selected inside
    one PC/SC transaction; yields the SELECT answer. The management applet is
    selected again afterwards, which ends what was authenticated in the
    application. NotSupported when the device has no such application."""
    card = m.card
    with card.transaction():
        try:
            answer, _ = card.select(aid)
        except ApduError as e:
            raise NotSupported("the device has no %s application (SW %04X)" % (name, e.sw), e.sw,
                               "设备没有 %s 应用（SW %04X）" % (name_zh or name, e.sw)) from None
        try:
            yield answer
        finally:
            try:
                card.select(MGMT_AID)
            except (ApduError, CardConnectionException):
                pass


def send(card, ins, p1=0, p2=0, data=b"", cla=0x00):
    """ISO command (chaining and GET RESPONSE by pcsc.Card): (answer, status
    word); no exception for a status word."""
    return card.transmit(cla, ins, p1, p2, data, le=0, check=False)


def tlv(tag, value=b""):
    """BER-TLV with a tag of one or two bytes."""
    return keyio._tlv(tag, value)


def parse_tlvs(data, what, what_zh=None):
    """[(tag, value)] of BER-TLV data; ManagerError when malformed."""
    try:
        return keyio._tlvs(bytes(data), what)
    except keyio.KeyTransferError:
        raise ManagerError("%s: malformed answer from the device" % what, None,
                           "%s：设备的应答格式错误" % (what_zh or what)) from None


def wipe(buf):
    """Overwrites a bytearray holding a secret (bytes cannot be wiped)."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


# ----------------------------------------------------------------------------
# CTAP over the smart card interface
# ----------------------------------------------------------------------------

class CtapTransportError(CtapError):
    """The FIDO application answered a status word instead of a CTAP answer
    (sw). Its CTAP code is OTHER."""

    def __init__(self, sw):
        super().__init__(CtapError.ERR.OTHER)
        self.sw = sw


class CcidCtapDevice(CtapDevice):
    """CTAP over the FIDO application (AID A0000006472F0001) of the device's
    smart card interface, on the card connection the rest of the tools use:
    usable by python-fido2's Ctap2, ClientPin and CredentialManagement (and
    Ctap1 through CTAPHID.MSG). source: a Management (its current card is
    used, so a reconnect() is followed) or a pcsc.Card.

    Each call selects the FIDO application inside one PC/SC transaction and
    the management applet again afterwards, like Management._ctap. A caller
    that needs several commands without another program's in between (a
    credential enumeration) holds card.transaction() around them. The device
    answers each command when it is done (a touch included), so event
    (cancel) and on_keepalive are not used. Nothing is logged: commands
    carry PIN material."""

    def __init__(self, source):
        self._source = source

    @property
    def card(self):
        c = getattr(self._source, "card", None)
        return c if c is not None else self._source

    @property
    def capabilities(self):
        return CAPABILITY.CBOR

    @property
    def version(self):
        return 2

    def __repr__(self):
        return "CcidCtapDevice(%s)" % getattr(self.card, "reader", "?")

    def _transmit(self, cla, ins, p1, p2, data):
        card = self.card
        with card.transaction():
            try:
                try:
                    card.select(FIDO_AID)
                except ApduError as e:
                    raise NotSupported("the device has no FIDO application (SW %04X)" % e.sw, e.sw,
                                       "设备没有 FIDO 应用（SW %04X）" % e.sw) from None
                except CardConnectionException as e:
                    if (getattr(e, "hresult", 0) or 0) & 0xFFFFFFFF == SCARD_E_NO_ACCESS:
                        raise FidoBlockedByOs() from None
                    raise
                answer = card.transmit(cla, ins, p1, p2, data, le=0, check=False, what="FIDO")
            except BaseException:
                try:
                    card.select(MGMT_AID)
                except (ApduError, CardConnectionException):
                    pass            # the original failure is the one to report
                raise
            # Without the management applet selected again, the next
            # management command would reach the FIDO application.
            try:
                card.select(MGMT_AID)
            except (ApduError, CardConnectionException):
                raise ManagerError("the FIDO command was sent, but the device did not switch back to its "
                                   "management application (busy with another request, e.g. a FIDO request "
                                   "waiting for a touch?); check the result and try again", None,
                                   "FIDO 命令已发送，但设备没有切换回管理应用（可能正忙于另一个请求，例如等待触摸的 "
                                   "FIDO 请求）；请检查结果后重试") from None
            return answer

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        data = bytes(data)
        if cmd == CTAPHID.CBOR:
            resp, sw = self._transmit(NFCCTAP_CLA, NFCCTAP_MSG, 0x00, 0x00, data)
            if sw == 0x9000 and resp:
                return bytes(resp)
            if sw >> 8 == 0x64:
                return bytes([sw & 0xFF])       # CTAP status of a failed command
            raise CtapTransportError(sw)
        if cmd == CTAPHID.MSG:
            # A raw U2F APDU (short or extended encoding): answer + SW.
            if len(data) < 4:
                raise CtapError(CtapError.ERR.INVALID_LENGTH)
            cla, ins, p1, p2 = data[:4]
            body = data[4:]
            if len(body) >= 3 and body[0] == 0:
                n = int.from_bytes(body[1:3], "big")
                payload = body[3:3 + n]
            elif len(body) > 1:
                payload = body[1:1 + body[0]]
            else:
                payload = b""
            resp, sw = self._transmit(cla, ins, p1, p2, payload)
            return bytes(resp) + sw.to_bytes(2, "big")
        raise CtapError(CtapError.ERR.INVALID_COMMAND)

    def close(self):
        """The card connection belongs to the caller: nothing to close."""

    @classmethod
    def list_devices(cls):
        """Devices are opened through librefido.mgmt.Management: none here."""
        return iter(())


__all__ = ["ManagerError", "AuthRequired", "WrongSecret", "SecretBlocked", "NotSupported", "error_text", "SW_TEXT",
           "sw_text", "sw_error", "applet", "send", "tlv", "parse_tlvs", "wipe", "CcidCtapDevice",
           "CtapTransportError"]
