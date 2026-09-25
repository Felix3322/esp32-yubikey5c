"""Shared fixtures of the key manager tests (tools/librefido/librefido/mgr_*.py)
against the emulator, over PC/SC like the GUI.

    bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/manager

Every test gets its own emulated device on a fresh flash (starting it
suspends the harness plugin's session emulator, which is brought back
afterwards). The emulator confirms presence by itself unless started with
LF_EMU_UP=manual (then the `button` fixture presses).

Fixtures (helpers are fixtures too: test modules never import this file):
  pcscd       module: the PC/SC daemon (the plugin's, or an own one); skips
              without a user-mode pcscd; installs the CTAPHID-over-TCP backend.
  device      device(**env) -> Emulator started on a fresh flash (its flash
              survives e.restart()); stopped at the end.
  connect     connect(timeout=15) -> Management of the running emulator
              (closed at the end); call it again after a restart.
  mgmt        a Management of a fresh device with the default environment.
  fido_hid    FidoHid: python-fido2 over CTAPHID (another interface than the
              managers use): make_rk(), set_pin(), rk_users(), info().
  button      Button of an emulator started with LF_EMU_UP=manual, with
              pressing(fn, delay) that presses once while fn() runs.
"""

import os
import threading
import time

import pytest

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2

from harness import ctaphid
from harness.emulator import Button, Emulator, Pcscd, ensure_session

from librefido.mgmt import Management


@pytest.fixture(scope="module")
def pcscd():
    """The PC/SC daemon: the harness plugin's one when the plugin is loaded,
    else an own one. With the plugin, the session emulator the tests here
    suspend is brought back at the end of the module."""
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    plugin = ensure_session() is not None
    if not plugin:
        p.start()
    ctaphid.install()
    yield p
    if plugin:
        ensure_session()
    else:
        p.stop()


@pytest.fixture
def device(pcscd, tmp_path):
    """device(binary=None, chip_id=None, **env) starts an emulator on a fresh
    flash; restart() keeps its flash. At most one runs at a time (same
    ports): a second call stops the first."""
    made = []

    def make(binary=None, chip_id=None, **env):
        for e in made:
            e.stop()
        e = Emulator(binary=binary, workdir=str(tmp_path / ("dev%d" % len(made))), env=env, chip_id=chip_id)
        e.start()
        made.append(e)
        return e
    yield make
    for e in made:
        e.stop()


def _release(m):
    """Closes a Management and releases its PC/SC context now: pyscard
    would release it when collected, possibly after pcscd stopped (a
    warning at the end of the run)."""
    m.close()
    c = getattr(m.card, "conn", None)
    while c is not None and not hasattr(c, "hcontext") and hasattr(c, "component"):
        c = c.component
    try:
        c.release()
    except Exception:
        pass


@pytest.fixture
def connect(pcscd):
    """connect(timeout=15) -> Management of the running emulator. Every
    Management opened is closed at the end."""
    opened = []

    def make(timeout=15.0):
        m = Management.open(timeout=timeout)
        opened.append(m)
        return m
    yield make
    for m in opened:
        _release(m)


@pytest.fixture
def mgmt(device, connect):
    """A Management of a fresh device (default environment)."""
    device()
    return connect()


class FidoHid:
    """python-fido2 over CTAPHID (the emulator's HID transport): what a
    browser does, to set up or check what the managers see over PC/SC."""

    def _open(self):
        dev = ctaphid.open_device()
        return dev, Ctap2(dev)

    def info(self):
        dev, c = self._open()
        try:
            return c.get_info()
        finally:
            dev.close()

    def set_pin(self, pin):
        dev, c = self._open()
        try:
            ClientPin(c).set_pin(pin)
        finally:
            dev.close()

    def make_rk(self, rp_id="example.com", user_id=b"user", name="user", display_name="User", pin=None,
                alg=-7, extensions=None):
        """A discoverable credential; with pin, made with a pinUvAuthToken
        (mc permission, bound to rp_id). Returns the AttestationResponse."""
        dev, c = self._open()
        try:
            cdh = os.urandom(32)
            kw = {}
            if pin is not None:
                cp = ClientPin(c)
                token = cp.get_pin_token(pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, rp_id)
                kw = {"pin_uv_param": cp.protocol.authenticate(token, cdh), "pin_uv_protocol": cp.protocol.VERSION}
            user = {"id": user_id}
            if name is not None:
                user["name"] = name
            if display_name is not None:
                user["displayName"] = display_name
            return c.make_credential(cdh, {"id": rp_id, "name": rp_id}, user,
                                     [{"type": "public-key", "alg": alg}], options={"rk": True},
                                     extensions=extensions, **kw)
        finally:
            dev.close()

    def rk_users(self, rp_id="example.com", pin=None):
        """{user ID: user entity} of the discoverable credentials of rp_id,
        by getAssertion (with a ga token when pin)."""
        dev, c = self._open()
        try:
            cdh = os.urandom(32)
            kw = {}
            if pin is not None:
                cp = ClientPin(c)
                token = cp.get_pin_token(pin, ClientPin.PERMISSION.GET_ASSERTION, rp_id)
                kw = {"pin_uv_param": cp.protocol.authenticate(token, cdh), "pin_uv_protocol": cp.protocol.VERSION}
            try:
                first = c.get_assertion(rp_id, cdh, **kw)
            except CtapError as e:
                if e.code == CtapError.ERR.NO_CREDENTIALS:
                    return {}
                raise
            found = [first]
            for _ in range((first.number_of_credentials or 1) - 1):
                found.append(c.get_next_assertion())
            return {a.user["id"]: a.user for a in found}
        finally:
            dev.close()


@pytest.fixture
def fido_hid(pcscd):
    return FidoHid()


class ManualButton:
    """The presence button of an emulator started with LF_EMU_UP=manual."""

    def press(self, hold=0.15):
        b = Button()
        try:
            b.press(hold)
        finally:
            b.close()

    def pressing(self, fn, delay=0.4):
        """Runs fn() while the button is pressed once, delay seconds after
        the start (the device waits for it). Returns what fn returns."""
        def press():
            time.sleep(delay)
            self.press()
        t = threading.Thread(target=press)
        t.start()
        try:
            return fn()
        finally:
            t.join()


@pytest.fixture
def button(pcscd):
    return ManualButton()
