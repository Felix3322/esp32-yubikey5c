"""Lifecycle of the emulator process and of the user-mode PC/SC daemon.

Ports: CTAPHID on LF_TEST_PORT_BASE (default 35962), vpcd on +1, the
presence button on +8. Test runs with different bases (and their own
PCSCLITE_CSOCK_NAME) run side by side, see ~/work/scripts/locked_tests.sh.

The pytest plugin keeps a session emulator + pcscd for the suites that use
them (upstream pico-fido tests, `emulator`/`card`/`ctap_device` fixtures).
A test that starts its own Emulator or Pcscd suspends the session ones
(same ports); ensure_session() brings them back when needed.
"""

import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HID_PORT = int(os.environ.get("LF_TEST_PORT_BASE", "35962"))
VPCD_PORT = HID_PORT + 1
UP_PORT = HID_PORT + 8

# Session instances owned by the pytest plugin (harness.plugin).
_session = {"emu": None, "pcscd": None}


def set_session(emu, pcscd):
    _session["emu"], _session["pcscd"] = emu, pcscd


def ensure_session():
    """Restarts the session pcscd/emulator if a self-managed test stopped
    them and nothing else holds their ports now. Returns the emulator."""
    emu, pcscd = _session["emu"], _session["pcscd"]
    if pcscd is not None and pcscd.proc is None and not _port_open(VPCD_PORT):
        pcscd.start()
    if emu is not None and emu.proc is None and not _port_open(HID_PORT):
        emu.start()
        time.sleep(0.3)
    return emu


def _wait_port(port, timeout=10.0, host="127.0.0.1"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _port_open(port):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


class Pcscd:
    """Optional user-mode pcscd with the vpcd reader (see tests/README.md).

    Started only when PCSC_DIR, PCSCD_BIN and VPCD_DRIVER[_1SLOT] are set;
    otherwise the system pcscd with the vsmartcard-vpcd reader is used."""

    def __init__(self):
        self.proc = None
        self.dir = os.environ.get("PCSC_DIR")
        self.bin = os.environ.get("PCSCD_BIN")
        self.driver = os.environ.get("VPCD_DRIVER") or os.environ.get("VPCD_DRIVER_1SLOT")
        self.reader_name = os.environ.get("VPCD_READER_NAME", "Virtual PCD")
        # CI: the distribution's pcscd service with the vsmartcard-vpcd reader
        # (listening on VPCD_PORT) is already running; nothing to start.
        self.system = os.environ.get("LF_TEST_SYSTEM_PCSCD") == "1"
        self.available = self.system or bool(self.dir and self.bin and self.driver and os.path.exists(self.bin))

    def start(self):
        if not self.available or self.proc or self.system:
            return
        session = _session["pcscd"]
        if session is not None and session is not self and session.proc is not None:
            session.stop()      # same socket and vpcd port; ensure_session() restarts it
        os.makedirs(os.path.join(self.dir, "reader.conf.d"), exist_ok=True)
        conf = os.path.join(self.dir, "reader.conf.d", "vpcd-pytest-%d" % VPCD_PORT)
        with open(conf, "w") as f:
            f.write('FRIENDLYNAME "%s"\nDEVICENAME /dev/null:0x%X\nLIBPATH %s\nCHANNELID 0x%X\n'
                    % (self.reader_name, VPCD_PORT, self.driver, VPCD_PORT))
        sock = os.environ["PCSCLITE_CSOCK_NAME"]
        os.makedirs(os.path.dirname(sock), exist_ok=True)
        if os.path.exists(sock):
            os.unlink(sock)
        log = open(os.path.join(self.dir, "pcscd-pytest-%d.log" % VPCD_PORT), "w")
        self.proc = subprocess.Popen([self.bin, "--foreground", "--disable-polkit", "--config", conf],
                                     stdout=log, stderr=subprocess.STDOUT)
        deadline = time.time() + 5
        while time.time() < deadline and not _port_open(VPCD_PORT):
            time.sleep(0.05)

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None


class Emulator:
    """One emulator process with its own flash image.

    The flash file persists across restart() so tests can power-cycle the
    device; wipe() starts from an empty store.
    """

    def __init__(self, binary=None, workdir=None, env=None, chip_id=None):
        self.binary = binary or os.environ.get("LF_EMU_BIN") or os.path.join(REPO_ROOT, "build-emu", "pico_fido2")
        self.workdir = workdir or tempfile.mkdtemp(prefix="lf-emu-")
        os.makedirs(self.workdir, exist_ok=True)
        # Every emulated device gets its own silicon ID (kept across restarts).
        chip = os.path.join(self.workdir, "memory.efuse.chipid")
        if chip_id is not None:
            with open(chip, "wb") as f:
                f.write(chip_id)
        elif not os.path.exists(chip):
            with open(chip, "wb") as f:
                f.write(os.urandom(8))
        self.extra_env = dict(env or {})
        self.proc = None
        self.log_path = os.path.join(self.workdir, "emulator.log")
        self.starts = 0     # processes started with this log
        self.log_start = 0  # log offset where the current process began

    @property
    def flash_path(self):
        return os.path.join(self.workdir, "memory.flash")

    @property
    def efuse_path(self):
        return os.path.join(self.workdir, "memory.efuse")

    def start(self, **env):
        if self.proc:
            return
        session = _session["emu"]
        if session is not None and session is not self and session.proc is not None:
            session.stop()      # same ports; ensure_session() restarts it later
        if _port_open(HID_PORT):
            raise RuntimeError("HID port %d is taken: another emulator is still running" % HID_PORT)
        e = dict(os.environ)
        e.update(self.extra_env)
        e.update({k: str(v) for k, v in env.items()})
        e["PICO_FLASH_FILE"] = self.flash_path
        e["PICO_EFUSE_FILE"] = self.efuse_path
        e["LF_EMU_VPCD_PORT"] = str(VPCD_PORT)
        e["LF_EMU_UP_PORT"] = str(UP_PORT)
        self._log = open(self.log_path, "a")
        self._log.flush()
        self.log_start = os.path.getsize(self.log_path)
        self.starts += 1
        self.proc = subprocess.Popen([self.binary], cwd=self.workdir, env=e,
                                     stdout=self._log, stderr=subprocess.STDOUT)
        if not _wait_port(HID_PORT, 10):
            raise RuntimeError("emulator did not open the HID port, see %s" % self.log_path)

    def stop(self, hard=False):
        if not self.proc:
            return
        if hard:
            self.proc.send_signal(signal.SIGKILL)
        else:
            self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(5)
        self.proc = None
        self._log.close()
        # the kernel may keep the listening socket in TIME_WAIT for a moment
        deadline = time.time() + 5
        while time.time() < deadline and _port_open(HID_PORT):
            time.sleep(0.05)

    def restart(self, **env):
        self.stop()
        self.start(**env)

    def wipe(self):
        self.stop()
        for p in (self.flash_path, self.efuse_path):
            if os.path.exists(p):
                os.unlink(p)

    def run_until_exit(self, timeout=30, **env):
        """Runs the emulator until it exits by itself (fault injection)."""
        self.start(**env)
        try:
            return self.proc.wait(timeout)
        finally:
            self.proc = None
            self._log.close()

    def cleanup(self):
        self.stop()
        if os.environ.get("LF_EMU_KEEP"):
            print("emulator workdir kept at %s" % self.workdir)
            return
        shutil.rmtree(self.workdir, ignore_errors=True)


class Button:
    """Physical button of an emulator started with LF_EMU_UP=manual."""

    def __init__(self):
        self.sock = None

    def _conn(self):
        if self.sock is None:
            self.sock = socket.create_connection(("127.0.0.1", UP_PORT), timeout=2)
        return self.sock

    def down(self):
        self._conn().sendall(b"down\n")

    def up(self):
        self._conn().sendall(b"up\n")

    def press(self, hold=0.15):
        self.down()
        time.sleep(hold)
        self.up()

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
