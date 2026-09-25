"""Key manager, FIDO (librefido.mgr_fido) against the emulator: the CTAP over
CCID adapter with python-fido2, PIN set / change, the cached token and
FidoPinRequired, listing, renaming and deleting passkeys made by a
"browser" over CTAPHID.

    bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/manager/test_mgr_fido.py
"""

import pytest

from fido2.ctap2 import ClientPin, Ctap2

from librefido.mgr_common import CcidCtapDevice, ManagerError, SecretBlocked, WrongSecret
from librefido.mgr_fido import FidoManager, FidoPinNotSet, FidoPinRequired

PIN = "135790"
NEW_PIN = "246801"


def holds(obj, secret, seen=None):
    """Whether secret (text) is anywhere in obj's attributes, as text or bytes."""
    seen = seen if seen is not None else set()
    if id(obj) in seen:
        return False
    seen.add(id(obj))
    if isinstance(obj, str):
        return secret in obj
    if isinstance(obj, (bytes, bytearray)):
        return secret.encode() in bytes(obj)
    if isinstance(obj, dict):
        return any(holds(k, secret, seen) or holds(v, secret, seen) for k, v in obj.items())
    if isinstance(obj, (list, tuple, set)):
        return any(holds(v, secret, seen) for v in obj)
    if hasattr(obj, "__dict__") and type(obj).__module__.startswith(("librefido", "fido2")):
        return holds(vars(obj), secret, seen)
    return False


def test_adapter_drives_python_fido2(mgmt, fido_hid):
    ctap = Ctap2(CcidCtapDevice(mgmt))
    assert bytes(ctap.info.aaguid) == bytes(fido_hid.info().aaguid)
    assert ClientPin(ctap).get_pin_retries()[0] == 8
    # the management applet answers again afterwards
    assert mgmt.info()["boot_status"] == "ok"
    # a pcsc.Card works as the source too
    assert Ctap2(CcidCtapDevice(mgmt.card)).info.versions
    # a failing CTAP command comes back as python-fido2's CtapError
    from fido2.ctap import CtapError
    with pytest.raises(CtapError) as e:
        ClientPin(ctap).get_pin_token("0000")
    assert e.value.code == CtapError.ERR.PIN_NOT_SET
    assert mgmt.info()["boot_status"] == "ok"


def test_info_and_pin_set_change(mgmt, fido_hid):
    f = FidoManager(mgmt)
    info = f.info()
    assert info["pin_set"] is False and info["unlocked"] is False
    assert info["aaguid"] == bytes(fido_hid.info().aaguid).hex() and len(info["aaguid"]) == 32
    assert any(v.startswith("FIDO_2") for v in info["versions"])
    assert info["cred_mgmt"] and info["min_pin_length"] >= 4 and info["pin_retries"] == 8
    with pytest.raises(FidoPinNotSet):
        f.unlock(PIN)
    with pytest.raises(FidoPinNotSet):
        f.change_pin(PIN, NEW_PIN)
    with pytest.raises(ManagerError) as e:
        f.set_pin("123")                                    # too short: refused before sending
    assert "at least" in str(e.value) and e.value.zh and "至少" in e.value.text(zh=True)
    f.set_pin(PIN)
    info = f.info()
    assert info["pin_set"] and info["pin_retries"] == 8
    with pytest.raises(ManagerError):
        f.set_pin(NEW_PIN)                                  # one is set: change it instead
    with pytest.raises(WrongSecret) as e:
        f.change_pin("000000", NEW_PIN)
    assert e.value.retries == 7 and "7" in str(e.value)
    f.change_pin(PIN, NEW_PIN)
    assert f.info()["pin_retries"] == 8                     # a right PIN restores the retries
    # the new PIN is the device's PIN for a browser too
    fido_hid.make_rk(pin=NEW_PIN)
    # a PIN that cannot be right is not sent (no retry used)
    with pytest.raises(WrongSecret):
        f.unlock("12")
    with pytest.raises(WrongSecret):
        f.change_pin("x" * 64, PIN)
    assert f.info()["pin_retries"] == 8


def test_list_rename_delete(mgmt, fido_hid):
    f = FidoManager(mgmt)
    with pytest.raises(FidoPinNotSet):
        f.list_credentials()
    f.set_pin(PIN)
    with pytest.raises(FidoPinRequired):
        f.list_credentials()
    exts = fido_hid.info().extensions
    a = fido_hid.make_rk("example.com", b"alice", "alice", "Alice A", pin=PIN)
    fido_hid.make_rk("example.com", b"bob", "bob", "Bob B", pin=PIN)
    carol_ext = {"credProtect": 2} if "credProtect" in exts else None
    fido_hid.make_rk("another.org", b"carol", "carol", "Carol C", pin=PIN, extensions=carol_ext)

    f.unlock(PIN)
    assert f.unlocked and f.info()["unlocked"]
    creds = f.list_credentials()
    assert [(c["rp_id"], c["user_name"]) for c in creds] == [
        ("another.org", "carol"), ("example.com", "alice"), ("example.com", "bob")]
    alice = creds[1]
    assert alice["credential_id"] == a.auth_data.credential_data.credential_id
    assert alice["user_id"] == b"alice" and alice["display_name"] == "Alice A"
    assert alice["public_key_alg"] == -7 and alice["large_blob_key"] is False
    assert len(alice["rp_id_hash"]) == 32
    if carol_ext:
        assert creds[0]["cred_protect"] == 2
    assert f.metadata()["existing"] == 3
    assert f.info()["remaining_rk"] is not None

    # rename: the device and a browser see the new names
    f.update_user(alice["credential_id"], b"alice", "alice2", "Alice Two")
    after = {c["user_id"]: c for c in f.list_credentials()}
    assert (after[b"alice"]["user_name"], after[b"alice"]["display_name"]) == ("alice2", "Alice Two")
    assert (after[b"bob"]["user_name"], after[b"bob"]["display_name"]) == ("bob", "Bob B")
    users = fido_hid.rk_users("example.com", pin=PIN)
    assert users[b"alice"]["name"] == "alice2"

    # the browser took a new pinUvAuthToken: ours is gone, the PIN is asked again
    with pytest.raises(FidoPinRequired):
        f.delete_credential(alice["credential_id"])
    assert not f.unlocked
    f.unlock(PIN)
    f.delete_credential(alice["credential_id"])
    assert [c["user_id"] for c in f.list_credentials()] == [b"carol", b"bob"]
    with pytest.raises(ManagerError) as e:
        f.delete_credential(alice["credential_id"])         # gone already
    assert not isinstance(e.value, FidoPinRequired) and "no such passkey" in str(e.value)
    f.delete_credential(creds[0]["credential_id"])          # the last one of another.org
    assert [c["rp_id"] for c in f.list_credentials()] == ["example.com"]
    assert set(fido_hid.rk_users("example.com", pin=PIN)) == {b"bob"}
    assert fido_hid.rk_users("another.org", pin=PIN) == {}


def test_token_is_kept_never_the_pin(mgmt, fido_hid):
    f = FidoManager(mgmt)
    f.set_pin(PIN)
    fido_hid.make_rk(pin=PIN)
    f.unlock(PIN)
    assert not holds(f, PIN)
    # the token serves several operations without the PIN
    assert len(f.list_credentials()) == 1
    assert len(f.list_credentials()) == 1
    assert f.metadata()["existing"] == 1
    # another manager of the same connection holds nothing
    with pytest.raises(FidoPinRequired):
        FidoManager(mgmt).list_credentials()
    f.lock()
    with pytest.raises(FidoPinRequired):
        f.list_credentials()
    # a PIN change ends the token
    f.unlock(PIN)
    f.change_pin(PIN, NEW_PIN)
    with pytest.raises(FidoPinRequired):
        f.list_credentials()
    with pytest.raises(WrongSecret):
        f.unlock(PIN)
    f.unlock(NEW_PIN)
    assert len(f.list_credentials()) == 1


def test_wrong_pins_block_until_power_cycle(device, connect):
    e = device()
    f = FidoManager(connect())
    f.set_pin(PIN)
    with pytest.raises(WrongSecret) as w:
        f.unlock("000000")
    assert w.value.retries == 7
    with pytest.raises(WrongSecret) as w:
        f.unlock("000000")
    assert w.value.retries == 6
    with pytest.raises(SecretBlocked) as b:                 # third in a row: unplug first
        f.unlock("000000")
    assert "unplug" in str(b.value) and "拔出" in b.value.text(True)
    with pytest.raises(SecretBlocked):
        f.unlock(PIN)
    assert not f.unlocked
    e.restart()
    f = FidoManager(connect())
    f.unlock(PIN)
    assert f.info()["pin_retries"] == 8
