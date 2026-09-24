"""Reed-Solomon codec (pico-keys-sdk/src/fs/rs.c) against the reedsolo reference."""

import ctypes
import random

import pytest

reedsolo = pytest.importorskip("reedsolo")

NSYM = 32
MAX_DATA = 223


def buf(data):
    return (ctypes.c_uint8 * max(1, len(data))).from_buffer_copy(bytes(data) or b"\0")


def c_encode(lib, data):
    d = buf(data)
    p = (ctypes.c_uint8 * NSYM)()
    lib.rs_encode_block(d, len(data), p)
    return bytes(p)


def c_decode(lib, data, parity):
    d = buf(data)
    p = (ctypes.c_uint8 * NSYM).from_buffer_copy(bytes(parity))
    r = lib.rs_decode_block(d, len(data), p)
    return r, bytes(d)[:len(data)], bytes(p)


def corrupt(codeword, count, rnd):
    cw = bytearray(codeword)
    for pos in rnd.sample(range(len(cw)), count):
        cw[pos] ^= rnd.randrange(1, 256)
    return bytes(cw)


@pytest.mark.parametrize("length", [1, 2, 17, 82, 128, 222, 223])
def test_parity_matches_reference(librs, length):
    rnd = random.Random(length)
    ref = reedsolo.RSCodec(NSYM)
    for _ in range(20):
        msg = bytes(rnd.randrange(256) for _ in range(length))
        assert c_encode(librs, msg) == bytes(ref.encode(msg))[length:]


@pytest.mark.parametrize("length", [1, 50, 82, 223])
def test_corrects_up_to_16_errors(librs, length):
    rnd = random.Random(1000 + length)
    for nerr in range(0, 17):
        for _ in range(8):
            msg = bytes(rnd.randrange(256) for _ in range(length))
            cw = msg + c_encode(librs, msg)
            bad = corrupt(cw, min(nerr, len(cw)), rnd)
            r, data, parity = c_decode(librs, bad[:length], bad[length:])
            assert r == min(nerr, len(cw)), (nerr, r)
            assert data == msg and parity == cw[length:]


def test_too_many_errors_never_reported_as_clean(librs):
    """Beyond 16 errors the decoder must fail, or (rarely) land on another
    valid codeword, which the storage layer's CRC then rejects."""
    rnd = random.Random(7)
    ref = reedsolo.RSCodec(NSYM)
    failures = 0
    for _ in range(300):
        msg = bytes(rnd.randrange(256) for _ in range(MAX_DATA))
        cw = msg + c_encode(librs, msg)
        bad = corrupt(cw, rnd.randrange(17, 40), rnd)
        r, data, parity = c_decode(librs, bad[:MAX_DATA], bad[MAX_DATA:])
        if r < 0:
            failures += 1
            continue
        assert ref.check(data + parity)[0], "decoder returned a non-codeword"
        assert data != msg
    assert failures > 280


def test_whole_sector(librs):
    rnd = random.Random(4096)
    data = bytes(rnd.randrange(256) for _ in range(4096))
    nblk = -(-4096 // MAX_DATA)
    d = buf(data)
    p = (ctypes.c_uint8 * (nblk * NSYM))()
    librs.rs_encode(d, 4096, p)
    # errors spread over several blocks, <= 16 per block
    raw = bytearray(data)
    for blk in range(nblk):
        start = blk * MAX_DATA
        end = min(start + MAX_DATA, 4096)
        for pos in rnd.sample(range(start, end), min(12, end - start)):
            raw[pos] ^= 0xA5
    d2 = buf(raw)
    assert librs.rs_decode(d2, 4096, p) == 12 * nblk
    assert bytes(d2) == data
    # one block beyond repair: the call reports failure but fixes the others
    raw = bytearray(data)
    for pos in range(0, 40):
        raw[pos] ^= 0xFF
    raw[MAX_DATA + 5] ^= 1
    d3 = buf(raw)
    assert librs.rs_decode(d3, 4096, p) == -1
    assert bytes(d3)[MAX_DATA:] == data[MAX_DATA:]
