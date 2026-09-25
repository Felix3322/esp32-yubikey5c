"""Key manager: the FIDO application of the active profile - authenticator
information, the FIDO PIN, and the discoverable credentials (passkeys)
through CTAP 2.1 authenticatorCredentialManagement.

Everything goes over the smart card interface (mgr_common.CcidCtapDevice on
the Management's card connection), never raw FIDO HID, which Windows keeps
for administrators.

The PIN is never kept: unlock() trades it for a pinUvAuthToken with the
credential management permission, and only that token is kept, for the life
of the FidoManager (or until lock()). The device ends a token by itself (not
used within 30 s of being issued, or unused for 10 minutes, or when another
program asks for one): the operations then raise FidoPinRequired, and the
caller asks for the PIN again.
"""

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2, CredentialManagement

from .mgr_common import (AuthRequired, CcidCtapDevice, CtapTransportError, ManagerError, NotSupported, SecretBlocked,
                         WrongSecret, sw_error)

PIN_MIN_CHARS = 4           # CTAP 2.1: at least 4 Unicode code points
PIN_MAX_BYTES = 63          # ... and at most 63 bytes of UTF-8
USER_FIELD_MAX = 64         # bytes of a user name / display name the device keeps (credential.h)

ERR = CtapError.ERR
CM = CredentialManagement.RESULT
# thirdPartyPayment (CTAP 2.2) of a credential: named in python-fido2 2.0 and newer only
CM_THIRD_PARTY_PAYMENT = getattr(CM, "THIRD_PARTY_PAYMENT", 0x0C)

# Token failures: the token expired, was replaced by another program's, or
# lacks the permission. The PIN has to be entered again.
_TOKEN_GONE = (ERR.PIN_AUTH_INVALID, ERR.PIN_TOKEN_EXPIRED, ERR.PUAT_REQUIRED, ERR.UNAUTHORIZED_PERMISSION)

_CTAP_TEXT = {
    ERR.PIN_INVALID: ("wrong PIN", "PIN 错误"),
    ERR.PIN_BLOCKED: ("the FIDO PIN is blocked (too many wrong PINs); only a reset of the FIDO application helps "
                      "(it deletes every passkey)",
                      "FIDO PIN 已锁定（错误次数过多）；只能重置 FIDO 应用（会删除所有通行密钥）"),
    ERR.PIN_AUTH_BLOCKED: ("too many wrong PINs in a row: unplug the key, plug it in again and retry",
                           "连续输错 PIN 次数过多：请拔出按键、重新插入后再试"),
    ERR.PIN_NOT_SET: ("no FIDO PIN is set", "未设置 FIDO PIN"),
    ERR.PIN_POLICY_VIOLATION: ("the new PIN does not meet the device's rules (too short, or the same as before?)",
                               "新 PIN 不符合设备的要求（太短，或与原来相同？）"),
    ERR.NO_CREDENTIALS: ("no such passkey on the device (list them again)", "设备上没有该通行密钥（请重新列出）"),
    ERR.NOT_ALLOWED: ("not allowed now (the key store of the active profile may be locked)",
                      "当前不允许（当前环境的密钥存储可能已锁定）"),
    ERR.KEY_STORE_FULL: ("no space left on the device", "设备空间不足"),
    ERR.OPERATION_DENIED: ("not confirmed on the key", "未在按键上确认"),
    ERR.USER_ACTION_TIMEOUT: ("not confirmed: touch the key when it blinks", "未确认：请在按键闪烁时触摸它"),
    ERR.ACTION_TIMEOUT: ("not confirmed: touch the key when it blinks", "未确认：请在按键闪烁时触摸它"),
    ERR.INVALID_PARAMETER: ("the device refused the request as invalid", "设备认为请求无效"),
    ERR.INVALID_LENGTH: ("the device refused the request as too long", "设备认为请求过长"),
    ERR.REQUEST_TOO_LARGE: ("the request is too large for the device", "请求对设备来说太大"),
    ERR.INVALID_SUBCOMMAND: ("the firmware does not support this", "固件不支持此操作"),
    ERR.INVALID_COMMAND: ("the firmware does not support this", "固件不支持此操作"),
}


class FidoPinRequired(AuthRequired):
    """No valid pinUvAuthToken: ask for the FIDO PIN, call unlock(pin) and
    try again."""


class FidoPinNotSet(ManagerError):
    """Managing passkeys needs a FIDO PIN, and the profile has none: set one
    first (set_pin)."""


def _update_supported(info):
    """Whether updateUserInformation is there: CTAP 2.1 credential management
    (not its preview). python-fido2 1.1 has no is_update_supported."""
    check = getattr(CredentialManagement, "is_update_supported", None)
    return bool(check(info)) if check is not None else bool(info.options.get("credMgmt"))


def _pin_bytes_ok(pin):
    return isinstance(pin, str) and len(pin) >= PIN_MIN_CHARS and len(pin.encode("utf-8")) <= PIN_MAX_BYTES


def ctap_error(what, what_zh, e):
    """ManagerError for a CTAP failure of an operation."""
    if isinstance(e, CtapTransportError):
        return sw_error(what, e.sw, what_zh)
    code = e.code
    en, zh = _CTAP_TEXT.get(code, ("error", "错误"))
    name = getattr(code, "name", "0x%02X" % int(code))
    message = "%s: %s (CTAP %s)" % (what, en, name)
    message_zh = "%s：%s（CTAP %s）" % (what_zh, zh, name)
    if code in (ERR.PIN_BLOCKED, ERR.PIN_AUTH_BLOCKED):
        return SecretBlocked(message, None, message_zh)
    if code in (ERR.INVALID_SUBCOMMAND, ERR.INVALID_COMMAND):
        return NotSupported(message, None, message_zh)
    return ManagerError(message, None, message_zh)


class FidoManager:
    """The FIDO application of the device of m (a Management)."""

    def __init__(self, m):
        self.m = m
        self.device = CcidCtapDevice(m)
        self._token = None          # (PinProtocol, pinUvAuthToken) of unlock()

    # -- plumbing ------------------------------------------------------------------
    def _ctap(self):
        """A Ctap2 with fresh getInfo (options change with the PIN)."""
        try:
            return Ctap2(self.device)
        except CtapError as e:
            raise ctap_error("FIDO", "FIDO", e) from None

    @staticmethod
    def _client_pin(c):
        try:
            return ClientPin(c)
        except ValueError:
            raise NotSupported("FIDO: the device offers no PIN protocol this tool knows", None,
                               "FIDO：设备没有本工具支持的 PIN 协议") from None

    def _cm(self, c):
        """CredentialManagement with the cached token (FidoPinRequired or
        FidoPinNotSet without one)."""
        if not CredentialManagement.is_supported(c.info):
            raise NotSupported("FIDO: this firmware cannot manage passkeys (no credential management)", None,
                               "FIDO：此固件不能管理通行密钥（不支持凭据管理）")
        if self._token is None:
            if not c.info.options.get("clientPin"):
                raise FidoPinNotSet("FIDO: managing passkeys needs a FIDO PIN, and this profile has none: set one "
                                    "first", None, "FIDO：管理通行密钥需要 FIDO PIN，而当前环境没有：请先设置一个")
            raise FidoPinRequired("FIDO: enter the FIDO PIN to manage passkeys", None,
                                  "FIDO：请输入 FIDO PIN 以管理通行密钥")
        protocol, token = self._token
        return CredentialManagement(c, protocol, token)

    def _token_call(self, what, what_zh, fn):
        """fn(ctap2, credential management) in one PC/SC transaction; token
        failures drop the token and raise FidoPinRequired."""
        with self.m.card.transaction():
            c = self._ctap()
            cm = self._cm(c)
            try:
                return fn(c, cm)
            except CtapError as e:
                if not isinstance(e, CtapTransportError) and e.code in _TOKEN_GONE:
                    self._token = None
                    raise FidoPinRequired(
                        "%s: the PIN session ended (unused for a while, or another program asked for the PIN); "
                        "enter the FIDO PIN again" % what, None,
                        "%s：PIN 会话已结束（一段时间未使用，或其他程序请求了 PIN）；请重新输入 FIDO PIN" % what_zh
                    ) from None
                raise ctap_error(what, what_zh, e) from None

    def _pin_failure(self, what, what_zh, cp, e):
        """Error for a failed PIN check: WrongSecret with the retries left."""
        if isinstance(e, CtapError) and not isinstance(e, CtapTransportError) and e.code == ERR.PIN_INVALID:
            try:
                retries = cp.get_pin_retries()[0]
            except (CtapError, ManagerError):
                retries = None
            if retries is None:
                return WrongSecret("%s: wrong PIN" % what, None, "%s：PIN 错误" % what_zh)
            return WrongSecret("%s: wrong PIN, %d tries left" % (what, retries), None,
                               "%s：PIN 错误，还剩 %d 次" % (what_zh, retries), retries=retries)
        return ctap_error(what, what_zh, e)

    # -- information -----------------------------------------------------------------
    @property
    def unlocked(self):
        """A pinUvAuthToken is held (it may have expired on the device)."""
        return self._token is not None

    def info(self):
        """Authenticator information (getInfo, getPinRetries). No PIN needed.
        remaining_rk: from getInfo, else from getCredsMetadata when unlocked,
        else None."""
        with self.m.card.transaction():
            c = self._ctap()
            i = c.info
            options = dict(i.options)
            retries = None
            if "clientPin" in options:
                try:
                    retries = self._client_pin(c).get_pin_retries()[0]
                except CtapError as e:
                    raise ctap_error("FIDO PIN retries", "FIDO PIN 剩余次数", e) from None
            remaining = i.remaining_disc_creds
        if remaining is None and self._token is not None:
            try:
                remaining = self.metadata()["remaining"]
            except ManagerError:
                pass                # optional: info() works without it
        return {
            "versions": list(i.versions),
            "aaguid": bytes(i.aaguid).hex(),
            "options": options,
            "pin_set": bool(options.get("clientPin")),
            "pin_retries": retries,
            "min_pin_length": i.min_pin_length,
            "force_pin_change": bool(i.force_pin_change),
            "remaining_rk": remaining,
            "firmware_version": i.firmware_version,
            "algorithms": [a.get("alg") for a in (i.algorithms or [])],
            "extensions": list(i.extensions or []),
            "cred_mgmt": CredentialManagement.is_supported(i),
            "unlocked": self._token is not None,
        }

    # -- PIN -------------------------------------------------------------------------
    def unlock(self, pin):
        """Obtains a pinUvAuthToken with the credential management
        permission and keeps it (never the PIN). WrongSecret (retries left),
        SecretBlocked, FidoPinNotSet."""
        self._token = None
        if not _pin_bytes_ok(pin):
            raise WrongSecret("FIDO PIN: this cannot be the PIN (4 or more characters, at most 63 bytes); it was "
                              "not sent", None, "FIDO PIN：这不可能是 PIN（至少 4 个字符，最多 63 字节）；未发送")
        with self.m.card.transaction():
            c = self._ctap()
            if not c.info.options.get("clientPin"):
                raise FidoPinNotSet("FIDO: this profile has no FIDO PIN; set one first", None,
                                    "FIDO：当前环境没有 FIDO PIN；请先设置一个")
            cp = self._client_pin(c)
            try:
                token = cp.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
            except CtapError as e:
                raise self._pin_failure("FIDO PIN", "FIDO PIN", cp, e) from None
            self._token = (cp.protocol, token)

    def lock(self):
        """Forgets the token."""
        self._token = None

    def _check_new_pin(self, c, new_pin):
        minimum = max(PIN_MIN_CHARS, c.info.min_pin_length or PIN_MIN_CHARS)
        if not isinstance(new_pin, str) or len(new_pin) < minimum:
            raise ManagerError("FIDO PIN: the new PIN needs at least %d characters" % minimum, None,
                               "FIDO PIN：新 PIN 至少需要 %d 个字符" % minimum)
        if len(new_pin.encode("utf-8")) > PIN_MAX_BYTES:
            raise ManagerError("FIDO PIN: the new PIN has more than %d bytes" % PIN_MAX_BYTES, None,
                               "FIDO PIN：新 PIN 超过 %d 字节" % PIN_MAX_BYTES)

    def set_pin(self, new_pin):
        """Sets the first FIDO PIN of the profile (none may be set)."""
        with self.m.card.transaction():
            c = self._ctap()
            if c.info.options.get("clientPin"):
                raise ManagerError("FIDO PIN: this profile has a PIN already; change it instead", None,
                                   "FIDO PIN：当前环境已有 PIN；请改用修改 PIN")
            self._check_new_pin(c, new_pin)
            cp = self._client_pin(c)
            try:
                cp.set_pin(new_pin)
            except CtapError as e:
                raise ctap_error("set FIDO PIN", "设置 FIDO PIN", e) from None
        self._token = None

    def change_pin(self, old_pin, new_pin):
        """Changes the FIDO PIN (the device ends every token). WrongSecret
        (retries left) for a wrong old PIN, SecretBlocked."""
        if not _pin_bytes_ok(old_pin):
            raise WrongSecret("FIDO PIN: this cannot be the current PIN (4 or more characters, at most 63 bytes); "
                              "it was not sent", None,
                              "FIDO PIN：这不可能是当前 PIN（至少 4 个字符，最多 63 字节）；未发送")
        with self.m.card.transaction():
            c = self._ctap()
            if not c.info.options.get("clientPin"):
                raise FidoPinNotSet("FIDO PIN: this profile has no PIN; set one instead", None,
                                    "FIDO PIN：当前环境没有 PIN；请改用设置 PIN")
            self._check_new_pin(c, new_pin)
            cp = self._client_pin(c)
            self._token = None
            try:
                cp.change_pin(old_pin, new_pin)
            except CtapError as e:
                raise self._pin_failure("change FIDO PIN", "修改 FIDO PIN", cp, e) from None

    # -- passkeys ----------------------------------------------------------------------
    def metadata(self):
        """{"existing": passkeys stored, "remaining": how many more fit (at
        most)}. Needs the token."""
        def run(c, cm):
            meta = cm.get_metadata()
            return {"existing": meta.get(CM.EXISTING_CRED_COUNT), "remaining": meta.get(CM.MAX_REMAINING_COUNT)}
        return self._token_call("FIDO passkeys", "FIDO 通行密钥", run)

    def list_credentials(self):
        """The discoverable credentials, sorted by RP ID then user: dicts
        {rp_id, rp_id_hash, credential_id, user_id, user_name, display_name,
        cred_protect (1..3 or None), large_blob_key (bool), public_key_alg
        (COSE algorithm, None when the device cannot use the credential),
        third_party_payment (bool)}. Texts come from the device: show them
        through mgmt.display_name. Needs the token."""
        def run(c, cm):
            out = []
            for rp in cm.enumerate_rps():
                rp_id = (rp.get(CM.RP) or {}).get("id") or ""
                rp_hash = rp.get(CM.RP_ID_HASH)
                for cred in cm.enumerate_creds(rp_hash):
                    user = cred.get(CM.USER) or {}
                    pk = cred.get(CM.PUBLIC_KEY)
                    out.append({
                        "rp_id": rp_id,
                        "rp_id_hash": bytes(rp_hash),
                        "credential_id": bytes((cred.get(CM.CREDENTIAL_ID) or {}).get("id") or b""),
                        "user_id": bytes(user.get("id") or b""),
                        "user_name": user.get("name"),
                        "display_name": user.get("displayName"),
                        "cred_protect": cred.get(CM.CRED_PROTECT),
                        "large_blob_key": bool(cred.get(CM.LARGE_BLOB_KEY)),
                        "public_key_alg": pk.get(3) if isinstance(pk, dict) else None,
                        "third_party_payment": bool(cred.get(CM_THIRD_PARTY_PAYMENT)),
                    })
            out.sort(key=lambda e: (e["rp_id"], e["user_name"] or "", e["display_name"] or "", e["user_id"]))
            return out
        return self._token_call("list passkeys", "列出通行密钥", run)

    def delete_credential(self, credential_id):
        """Deletes one passkey for good (the caller confirmed). Needs the
        token."""
        credential_id = bytes(credential_id)
        if not credential_id:
            raise ManagerError("delete passkey: no credential ID", None, "删除通行密钥：没有凭据 ID")
        self._token_call("delete passkey", "删除通行密钥",
                         lambda c, cm: cm.delete_cred({"id": credential_id, "type": "public-key"}))

    def update_user(self, credential_id, user_id, name, display_name):
        """Replaces the user name and display name of a passkey (None or ""
        removes one; the device keeps at most 64 bytes of each). user_id must
        be the passkey's own. Needs the token."""
        credential_id, user_id = bytes(credential_id), bytes(user_id)
        if not credential_id or not user_id:
            raise ManagerError("rename passkey: no credential or user ID", None, "重命名通行密钥：没有凭据或用户 ID")
        user = {"id": user_id}
        if name:
            user["name"] = name
        if display_name:
            user["displayName"] = display_name

        def run(c, cm):
            if not _update_supported(c.info):
                raise NotSupported("rename passkey: this firmware cannot change user names", None,
                                   "重命名通行密钥：此固件不能修改用户名")
            cm.update_user_info({"id": credential_id, "type": "public-key"}, user)
        self._token_call("rename passkey", "重命名通行密钥", run)


__all__ = ["FidoManager", "FidoPinRequired", "FidoPinNotSet", "ctap_error"]
