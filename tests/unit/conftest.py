"""Host unit tests for platform independent firmware modules.

The C sources are compiled into a shared library per test session and loaded
with ctypes, so these tests need a host C compiler but no emulator:

    python -m pytest tests/unit
"""

import ctypes
import os
import shutil
import subprocess
import tempfile

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SDK_SRC = os.path.join(REPO, "pico-keys-sdk", "src")


def build_shared(name, sources, include_dirs=(), defines=()):
    cc = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")
    if not cc:
        pytest.skip("no host C compiler")
    out_dir = tempfile.mkdtemp(prefix="lf-unit-")
    lib = os.path.join(out_dir, "lib%s.so" % name)
    cmd = [cc, "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-o", lib]
    cmd += ["-I" + d for d in include_dirs]
    cmd += ["-D" + d for d in defines]
    cmd += list(sources)
    subprocess.run(cmd, check=True)
    return ctypes.CDLL(lib)


@pytest.fixture(scope="session")
def librs():
    lib = build_shared("rs", [os.path.join(SDK_SRC, "fs", "rs.c")])
    u8p = ctypes.POINTER(ctypes.c_uint8)
    lib.rs_encode_block.argtypes = [u8p, ctypes.c_size_t, u8p]
    lib.rs_encode_block.restype = None
    lib.rs_decode_block.argtypes = [u8p, ctypes.c_size_t, u8p]
    lib.rs_decode_block.restype = ctypes.c_int
    lib.rs_encode.argtypes = [u8p, ctypes.c_size_t, u8p]
    lib.rs_encode.restype = None
    lib.rs_decode.argtypes = [u8p, ctypes.c_size_t, u8p]
    lib.rs_decode.restype = ctypes.c_int
    return lib
