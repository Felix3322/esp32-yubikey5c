"""pytest plugin: starts pcscd + the emulator for the whole session.

Usage (from the repository root, see tests/README.md):
    PYTHONPATH=tests:pico-fido/tests pytest -p harness.plugin tests/...
It also runs the upstream pico-fido suites unchanged: their Device.reboot()
(power cycle) is mapped to an emulator restart.
"""

import sys
import time

import pytest

from . import ctaphid
from .emulator import Emulator, Pcscd, ensure_session, set_session

_pcscd = None
_emu = None


def emulator_instance():
    """The session emulator, restarted if a self-managed test stopped it."""
    return ensure_session()


def pytest_configure(config):
    global _pcscd, _emu
    ctaphid.install()
    _pcscd = Pcscd()
    _pcscd.start()
    _emu = Emulator()
    _emu.start()
    set_session(_emu, _pcscd)
    time.sleep(0.5 if _pcscd.available else 0)


@pytest.fixture(scope="module", autouse=True)
def _lf_session_for_upstream(request):
    """The upstream pico-fido suites reach the session emulator through
    python-fido2 and class-scoped card fixtures directly: make sure it runs
    before any of them (a self-managed module earlier in the session may
    have suspended it). Module scope, so it runs before class fixtures."""
    if "/pico-fido/tests/" in str(request.node.fspath).replace("\\", "/"):
        ensure_session()
    yield


def pytest_unconfigure(config):
    if _emu:
        _emu.cleanup()
    if _pcscd:
        _pcscd.stop()


def _power_cycle_reboot(self):
    _emu.restart()
    time.sleep(0.3)
    # Re-open the transports the upstream Device object holds.
    self._Device__set_client(self._Device__origin, self._Device__user_interaction, self._Device__uv)
    self._Device__set_server(rp=self._Device__rp, attestation=self._Device__attestation)


def pytest_collection_modifyitems(session, config, items):
    mod = sys.modules.get("conftest")
    dev = getattr(mod, "Device", None) if mod else None
    if dev is not None:
        dev.reboot = _power_cycle_reboot


@pytest.fixture
def emulator():
    return ensure_session()


@pytest.fixture
def card():
    from .card import Card
    ensure_session()
    c = Card()
    yield c
    c.close()


@pytest.fixture
def ctap_device():
    ensure_session()
    d = ctaphid.open_device()
    yield d
    d.close()
