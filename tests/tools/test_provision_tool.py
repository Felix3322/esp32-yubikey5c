"""librefido.provision offline: the held root key state (HMAC key and Secure
Boot on the chip, the active profile's root key in plain) is bound with the
same confirmation and touch; genuinely inconsistent states are refused."""

import pytest

from librefido import cli, provision


class FakeMgmt:
    """INFO security state; PROVISION binds the root key or locks debugging."""

    def __init__(self, hmac_key, secure_boot, root_key):
        self.sec = {"secure_boot": secure_boot, "flash_encryption": False, "flash_encryption_release": False,
                    "jtag_disabled": False, "download_restricted": False, "anti_rollback": False,
                    "hmac_key": hmac_key, "root_key": root_key}
        self.bound = 0
        self.locked = 0
        self.lock_result = None     # ApduError to raise, or "ignored" (burned but not reported)
        self.keystore = True        # key store of the active profile unlocked

    def keystore_unlocked(self):
        return self.keystore

    def lock_debug(self):
        from librefido.pcsc import ApduError
        if isinstance(self.lock_result, int):
            raise ApduError(self.lock_result, "lock debugging")
        self.locked += 1
        if self.lock_result != "ignored":
            self.sec["jtag_disabled"] = self.sec["download_restricted"] = True

    def info(self):
        return {"security": dict(self.sec), "boot_status": "ok", "build_profile": "standard",
                "chip_serial": "00112233", "serial": "00112233", "firmware": "2.0.0",
                "firmware_slot": {"platform": "esp32s3"}, "profiles": []}

    def provision_hmac(self):
        self.bound += 1
        self.sec["hmac_key"] = True
        self.sec["root_key"] = provision.ROOT_BOUND


def test_held_root_key_is_bound_after_confirmation(tmp_path):
    m = FakeMgmt(True, True, provision.ROOT_PLAIN)
    s = provision.check_consistent(m.info())
    assert s["held"]
    assert not {x["id"]: x for x in provision.plan(m.info())}["hmac"]["is_done"]
    said = []
    with pytest.raises(provision.ProvisionError, match="not confirmed"):
        provision.bind_root_key(m, lambda expected: "no", directory=str(tmp_path), out=said.append)
    assert m.bound == 0 and provision.HELD_TEXT in said
    said.clear()
    after = provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path), out=said.append)
    assert m.bound == 1 and after["security"]["root_key"] == provision.ROOT_BOUND
    assert any("Restart the key" in line for line in said)


@pytest.mark.parametrize("hmac_key, secure_boot, root_key, keystore", [
    (True, False, provision.ROOT_PLAIN, True),          # no Secure Boot: the firmware binds on sight
    (True, True, "legacy eFuse", True),
    (True, False, "none (legacy)", False),              # locked without Secure Boot: refused by the firmware
    (True, True, "none (legacy)", None),                # cannot tell whether it is held
    (False, False, "none (legacy)", True),              # nothing the binding could do for this profile
])
def test_inconsistent_states_are_refused(tmp_path, hmac_key, secure_boot, root_key, keystore):
    m = FakeMgmt(hmac_key, secure_boot, root_key)
    m.keystore = keystore
    with pytest.raises(provision.ProvisionError):
        provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path))
    assert m.bound == 0


class NoRootMgmt(FakeMgmt):
    """A profile without root key on a chip with the HMAC key and Secure Boot:
    held (key store locked) until PROVISION records it; INFO says "none"
    either way, the key store opens at the next start."""

    def __init__(self, secure=False, build="standard", refuse=False):
        super().__init__(True, True, "none (legacy)")
        self.keystore, self.secure, self.build, self.refuse = False, secure, build, refuse

    def info(self):
        i = super().info()
        i.update({"build_profile": self.build, "active": 1,
                  "profiles": [{"index": n, "used": True, "name": "", "uuid": "", "secure": self.secure and n == 1}
                               for n in range(4)]})
        return i

    def provision_hmac(self):
        from librefido.pcsc import ApduError
        if self.refuse:
            raise ApduError(0x6F00, "bind")
        self.bound += 1                             # (INFO keeps "none", locked until the restart)

    def restart(self):
        if self.bound:
            self.keystore = True


def test_profile_without_root_key_held_after_the_update(tmp_path):
    """The final review's case: a NO-OTP profile on a Secure Boot + HMAC chip
    is locked by the new firmware; the tool explains it and records it."""
    m = NoRootMgmt()
    s = provision.check_consistent(m.info(), m.keystore_unlocked())
    assert s["held_none"] and s["held"]
    assert not {x["id"]: x for x in provision.plan(m.info(), False)}["hmac"]["is_done"]
    said = []
    provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path), out=said.append)
    assert m.bound == 1 and provision.HELD_NONE_TEXT in said and any("key_store: unlocked" in x for x in said)
    m.restart()
    said.clear()
    provision.bind_root_key(m, lambda expected: pytest.fail("asked"), directory=str(tmp_path), out=said.append)
    assert m.bound == 1 and "recorded on the chip" in said[-1]
    assert {x["id"]: x for x in provision.plan(m.info(), True)}["hmac"]["is_done"]
    # locking debugging is not refused for such a profile any more
    provision.lock_debug(m, lambda expected: expected, directory=str(tmp_path), out=lambda s: None)
    assert m.locked == 1


@pytest.mark.parametrize("kw, match", [({"secure": True}, "secure profile"), ({"build": "hardened"}, "HARDENED"),
                                       ({"refuse": True}, "refuses")])
def test_profile_without_root_key_that_cannot_be_recorded(tmp_path, kw, match):
    m = NoRootMgmt(**kw)
    with pytest.raises(provision.ProvisionError, match=match):
        provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path), out=lambda s: None)


def test_bound_is_done(tmp_path):
    m = FakeMgmt(True, True, provision.ROOT_BOUND)
    provision.bind_root_key(m, lambda expected: pytest.fail("asked"), directory=str(tmp_path), out=lambda s: None)
    assert m.bound == 0


def test_lock_debug_follows_the_same_rules(tmp_path):
    m = FakeMgmt(True, False, provision.ROOT_BOUND)
    said = []
    with pytest.raises(provision.ProvisionError, match="not confirmed"):
        provision.lock_debug(m, lambda expected: "BURN", directory=str(tmp_path), out=said.append)
    assert m.locked == 0 and provision.LOCK_TEXT in said
    assert [p for p in tmp_path.iterdir() if p.name.startswith("librefido-provision-")]    # metadata first
    after = provision.lock_debug(m, lambda expected: expected, directory=str(tmp_path), out=said.append)
    assert m.locked == 1 and after["security"]["jtag_disabled"] and after["security"]["download_restricted"]
    from librefido import policy
    assert policy.protection_level(after["security"]) == 2
    provision.lock_debug(m, lambda expected: pytest.fail("asked"), directory=str(tmp_path), out=said.append)
    assert m.locked == 1 and "already done" in said[-1]


@pytest.mark.parametrize("result, match", [(0x6A81, "cannot lock"), (0x6F00, "failed"), ("ignored", "does not report")])
def test_lock_debug_failures(tmp_path, result, match):
    m = FakeMgmt(True, False, provision.ROOT_BOUND)
    m.lock_result = result
    with pytest.raises(provision.ProvisionError, match=match):
        provision.lock_debug(m, lambda expected: expected, directory=str(tmp_path), out=lambda s: None)


def test_lock_debug_refuses_inconsistent_states(tmp_path):
    m = FakeMgmt(True, False, "legacy eFuse")
    with pytest.raises(provision.ProvisionError):
        provision.lock_debug(m, lambda expected: expected, directory=str(tmp_path), out=lambda s: None)
    assert m.locked == 0


def test_plan_reaches_level_2_with_the_automated_steps():
    steps = provision.plan(FakeMgmt(False, False, provision.ROOT_PLAIN).info())
    assert [s["id"] for s in steps if s["automated"]] == ["hmac", "lock_debug"]
    assert [s["id"] for s in steps if not s["automated"]] == ["secure_boot", "flash_encryption", "anti_rollback"]
    lock = {s["id"]: s for s in steps}["lock_debug"]
    assert "esptool" in lock["effect"] and "read the flash" in lock["effect"] and lock["brick_risk"].startswith("none")


def test_cli_lock_debug(tmp_path, monkeypatch, capsys):
    m = FakeMgmt(True, False, provision.ROOT_BOUND)
    m.close = lambda: None
    monkeypatch.setattr(cli.Management, "open", classmethod(lambda cls, reader=None, timeout=0.0: m))
    cli.main(["provision", "lock-debug"])                # dry run
    assert m.locked == 0 and "dry run" in capsys.readouterr().out
    cli.main(["provision", "plan"])
    out = capsys.readouterr().out
    assert "protection level 1 / 3" in out and "librefido provision lock-debug --apply" in out
    monkeypatch.setattr("builtins.input", lambda prompt="": "BURN 00112233")
    cli.main(["provision", "lock-debug", "--apply", "--metadata-dir", str(tmp_path)])
    out = capsys.readouterr()
    assert m.locked == 1 and "protection level 2 / 3" in out.out and "Touch the key" in out.err


def test_cli_explains_the_held_state(tmp_path, monkeypatch, capsys):
    m = FakeMgmt(True, True, provision.ROOT_PLAIN)
    monkeypatch.setattr(cli.Management, "open", classmethod(lambda cls, reader=None, timeout=0.0: m))
    m.close = lambda: None
    cli.main(["provision", "plan"])
    assert "root key of the active profile is stored in plain" in capsys.readouterr().out
    monkeypatch.setattr("builtins.input", lambda prompt="": "BURN 00112233")
    cli.main(["provision", "bind-root-key", "--apply", "--metadata-dir", str(tmp_path)])
    out = capsys.readouterr()
    assert m.bound == 1 and "Restart the key" in out.out and "bind the root key" in out.err
