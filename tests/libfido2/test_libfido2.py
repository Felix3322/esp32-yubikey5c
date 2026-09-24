"""libfido2 interoperability: Yubico's C library (used by OpenSSH, systemd,
pam-u2f) runs its own CTAP2 implementation against the emulator through custom
I/O functions (the emulator's HID is a TCP socket, WSL has no uhid).

    PYTHONPATH=tests python -m pytest tests/libfido2
"""

import os
import shutil
import subprocess

import pytest

from harness.emulator import HID_PORT, Emulator

HERE = os.path.dirname(os.path.abspath(__file__))


def pkg_config(*args):
    r = subprocess.run(["pkg-config", *args], capture_output=True, text=True)
    return r.stdout.split() if r.returncode == 0 else None


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    if not shutil.which("pkg-config") or not shutil.which("cc"):
        pytest.skip("no C toolchain")
    flags = pkg_config("--cflags", "--libs", "libfido2", "libcrypto")
    if flags is None:
        pytest.skip("libfido2 development files not found")
    out = str(tmp_path_factory.mktemp("libfido2") / "lf_fido2_tcp")
    subprocess.run(["cc", "-O1", "-Wall", "-Werror", "-o", out, os.path.join(HERE, "lf_fido2_tcp.c"), *flags],
                   check=True)
    return out


def test_libfido2_full_flow(client, tmp_path):
    e = Emulator(workdir=str(tmp_path / "dev"))
    e.start()
    try:
        env = dict(os.environ)
        libdirs = pkg_config("--variable=libdir", "libfido2")
        if libdirs:
            env["LD_LIBRARY_PATH"] = libdirs[0] + ":" + env.get("LD_LIBRARY_PATH", "")
        r = subprocess.run([client, str(HID_PORT)], capture_output=True, text=True, timeout=180, env=env)
        out = r.stdout + r.stderr
        assert r.returncode == 0, out
        for step in ("info", "set-pin", "make-credential", "get-assertion", "hmac-secret",
                     "credential-management", "large-blobs", "credential-delete", "reset"):
            assert "OK %s" % step in out, out
    finally:
        e.stop()
