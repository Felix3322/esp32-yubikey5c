"""Ed25519 / X25519 (pico-keys-sdk/src/crypto/lf_25519.c):

  * RFC 8032 section 7.1 (all Ed25519 test vectors);
  * RFC 7748 section 5.2 (X25519 vectors, 1 and 1000 iterations) and 6.1
    (Diffie-Hellman);
  * a differential test against Python cryptography: public keys,
    signatures and shared secrets byte for byte, verification of both sides'
    signatures, rejection of flipped bits, S + L, non-canonical and invalid
    points;
  * timings and stack use (c25519_harness.c), printed with -s.

    python -m pytest tests/unit/test_25519.py
"""

import ctypes
import hashlib
import os
import random

import pytest

from conftest import REPO, SDK_SRC, build_shared

ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
x25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.x25519")
from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


@pytest.fixture(scope="module")
def lib():
    sdk = os.path.join(REPO, "pico-keys-sdk")
    here = os.path.dirname(os.path.abspath(__file__))
    mbed = os.path.join(sdk, "mbedtls", "library")
    lib = build_shared(
        "c25519",
        [os.path.join(SDK_SRC, "crypto", "lf_25519.c"), os.path.join(here, "c25519_harness.c"),
         os.path.join(mbed, "sha512.c"), os.path.join(mbed, "platform_util.c")],
        include_dirs=[os.path.join(SDK_SRC, "crypto"), os.path.join(sdk, "mbedtls", "include")],
        defines=['MBEDTLS_CONFIG_FILE="%s"' % os.path.join(sdk, "config", "mbedtls_config.h")])
    cp = ctypes.c_char_p
    lib.lf_ed25519_public_key.argtypes = [cp, cp]
    lib.lf_ed25519_sign.argtypes = [cp, cp, ctypes.c_size_t, cp, cp]
    lib.lf_ed25519_verify.argtypes = [cp, cp, ctypes.c_size_t, cp]
    lib.lf_x25519.argtypes = [cp, cp, cp]
    lib.lf_x25519_public_key.argtypes = [cp, cp]
    lib.h_x25519_iterate.argtypes = [cp, cp, ctypes.c_uint]
    lib.h_bench.argtypes = [ctypes.c_int, ctypes.c_uint]
    lib.h_bench.restype = ctypes.c_double
    lib.h_stack.argtypes = [ctypes.c_int]
    lib.h_stack.restype = ctypes.c_long
    return lib


def ed_pub(lib, seed):
    out = ctypes.create_string_buffer(32)
    assert lib.lf_ed25519_public_key(out, seed) == 0
    return out.raw


def ed_sign(lib, seed, msg, pub=None):
    out = ctypes.create_string_buffer(64)
    assert lib.lf_ed25519_sign(out, msg, len(msg), seed, pub) == 0
    return out.raw


def ed_verify(lib, sig, msg, pub):
    return lib.lf_ed25519_verify(sig, msg, len(msg), pub) == 0


def x_mul(lib, k, u):
    out = ctypes.create_string_buffer(32)
    rc = lib.lf_x25519(out, k, u)
    return out.raw if rc == 0 else None


def x_pub(lib, k):
    out = ctypes.create_string_buffer(32)
    assert lib.lf_x25519_public_key(out, k) == 0
    return out.raw


def raw_pub(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# RFC 8032 7.1: (secret key, public key, message, signature)
RFC8032 = [
    ("TEST 1",
     "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("TEST 2",
     "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("TEST 3",
     "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("TEST 1024",
     "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
     "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
     "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
     "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
     "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
     "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
     "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
     "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
     "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
     "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
     "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
     "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
     "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
     "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
     "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
     "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
     "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
     "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
     "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
     "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
     "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
     "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
     "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
     "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
     "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
     "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
     "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
     "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
     "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
     "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
     "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
     "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
     "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
     "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
     "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"),
    ("TEST SHA(abc)",
     "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     hashlib.sha512(b"abc").hexdigest(),
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
]


@pytest.mark.parametrize("name,sk,pk,msg,sig", RFC8032, ids=[v[0] for v in RFC8032])
def test_rfc8032_ed25519(lib, name, sk, pk, msg, sig):
    sk, pk, msg, sig = (bytes.fromhex(v) for v in (sk, pk, msg, sig))
    if name == "TEST 1024":
        assert len(msg) == 1023
    assert ed_pub(lib, sk) == pk
    assert ed_sign(lib, sk, msg, pk) == sig
    assert ed_sign(lib, sk, msg) == sig             # public key recomputed
    assert ed_verify(lib, sig, msg, pk)
    assert not ed_verify(lib, sig, msg + b"\0", pk)


RFC7748 = [
    ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
    ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
]


@pytest.mark.parametrize("k,u,out", RFC7748)
def test_rfc7748_x25519(lib, k, u, out):
    assert x_mul(lib, bytes.fromhex(k), bytes.fromhex(u)) == bytes.fromhex(out)


@pytest.mark.parametrize("n,out", [
    (1, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"),
    (1000, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"),
])
def test_rfc7748_iterations(lib, n, out):
    k = ctypes.create_string_buffer(b"\x09" + b"\0" * 31, 32)
    u = ctypes.create_string_buffer(b"\x09" + b"\0" * 31, 32)
    assert lib.h_x25519_iterate(k, u, n) == 0
    assert k.raw == bytes.fromhex(out)


def test_rfc7748_dh(lib):
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    apub = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    bpub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    k = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assert x_pub(lib, a) == apub
    assert x_pub(lib, b) == bpub
    assert x_mul(lib, a, bpub) == k
    assert x_mul(lib, b, apub) == k


def flip(data, bit):
    b = bytearray(data)
    b[bit // 8] ^= 1 << (bit % 8)
    return bytes(b)


def test_differential_ed25519(lib):
    rnd = random.Random(0x25519)
    for i in range(1200):
        seed = rnd.randbytes(32)
        msg = rnd.randbytes(rnd.randrange(0, 1001) if i >= 4 else i)
        ref = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        pub = ed_pub(lib, seed)
        assert pub == raw_pub(ref), seed.hex()
        sig = ed_sign(lib, seed, msg, pub)
        ref_sig = ref.sign(msg)
        assert sig == ref_sig, seed.hex()
        if i % 4 == 0:
            assert ed_sign(lib, seed, msg) == sig
        # both verifiers accept both signatures (they are the same bytes, and
        # the reference key accepts ours)
        ref.public_key().verify(sig, msg)
        assert ed_verify(lib, ref_sig, msg, raw_pub(ref))
        # a flipped bit anywhere is refused
        bad_sig = flip(sig, rnd.randrange(512))
        assert not ed_verify(lib, bad_sig, msg, pub)
        with pytest.raises(InvalidSignature):
            ref.public_key().verify(bad_sig, msg)
        if msg:
            assert not ed_verify(lib, sig, flip(msg, rnd.randrange(8 * len(msg))), pub)
        bad_pub = flip(pub, rnd.randrange(256))
        assert not ed_verify(lib, sig, msg, bad_pub)
        # S + L: the same scalar mod L, not canonical
        s = int.from_bytes(sig[32:], "little")
        mal = sig[:32] + (s + L).to_bytes(32, "little")
        assert not ed_verify(lib, mal, msg, pub)
        with pytest.raises(InvalidSignature):
            ref.public_key().verify(mal, msg)


def test_differential_x25519(lib):
    rnd = random.Random(0x7748)
    for _ in range(1200):
        a, b = rnd.randbytes(32), rnd.randbytes(32)
        ra = x25519.X25519PrivateKey.from_private_bytes(a)
        rb = x25519.X25519PrivateKey.from_private_bytes(b)
        apub, bpub = x_pub(lib, a), x_pub(lib, b)
        assert apub == raw_pub(ra)
        assert bpub == raw_pub(rb)
        k = x_mul(lib, a, bpub)
        assert k == ra.exchange(rb.public_key()) == x_mul(lib, b, apub)
        # any 32-byte u (bit 255 ignored, non-canonical u reduced mod p)
        u = rnd.randbytes(32)
        mine = x_mul(lib, a, u)
        theirs = ra.exchange(x25519.X25519PublicKey.from_public_bytes(u))
        assert mine == theirs


def test_x25519_low_order_points_are_refused(lib):
    k = os.urandom(32)
    low = [0, 1, P - 1, P, P + 1,
           0x00b8495f16056286fdb1329ceb8d09da6ac49ff1fae35616aeb8413b7c7aebe0,
           0x57119fd0dd4e22d8868e1c58c45c44045bef839c55b1d0b1248c50a3bc959c5f]
    for u in low:
        assert x_mul(lib, k, (u % 2**256).to_bytes(32, "little")) is None, hex(u)
    # bit 255 is ignored: u and u + 2^255 give the same result
    u = bytearray(os.urandom(32))
    u[31] &= 0x7f
    assert x_mul(lib, k, bytes(u)) == x_mul(lib, k, flip(bytes(u), 255))
    # non-canonical u (p + 9) is 9
    assert x_mul(lib, k, (P + 9).to_bytes(32, "little")) == x_pub(lib, k)


def test_ed25519_point_decoding(lib):
    seed = os.urandom(32)
    msg = b"point decoding"
    pub = ed_pub(lib, seed)
    sig = ed_sign(lib, seed, msg)
    assert ed_verify(lib, sig, msg, pub)
    # y >= p (not canonical) is refused, for every y in [p, 2^255)
    for y in range(P, 2**255):
        for sign in (0, 1):
            enc = (y | (sign << 255)).to_bytes(32, "little")
            assert not ed_verify(lib, sig, msg, enc)
    # y with no x on the curve (y = 2 is not a point)
    assert not ed_verify(lib, sig, msg, (2).to_bytes(32, "little"))
    # S = L, S = 2^256 - 1
    assert not ed_verify(lib, sig[:32] + L.to_bytes(32, "little"), msg, pub)
    assert not ed_verify(lib, sig[:32] + b"\xff" * 32, msg, pub)
    # With A = identity, (R = B, S = 1) satisfies [S]B = R + [k]A for any
    # message: RFC 8032 does not refuse such a key, so the canonical encoding
    # verifies (as with cryptography), which shows that the refusals of the
    # non-canonical encoding (y = p + 1) and of x = 0 with the sign bit set
    # (RFC 8032 5.1.3 steps 1 and 4) come from the decoding.
    base = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")
    weak = base + (1).to_bytes(32, "little")
    ident = (1).to_bytes(32, "little")
    assert ed_verify(lib, weak, msg, ident)
    ed25519.Ed25519PublicKey.from_public_bytes(ident).verify(weak, msg)
    assert not ed_verify(lib, weak, msg, (P + 1).to_bytes(32, "little"))
    assert not ed_verify(lib, weak, msg, (1 | 1 << 255).to_bytes(32, "little"))
    assert not ed_verify(lib, weak, msg, ((P + 1) | 1 << 255).to_bytes(32, "little"))


def test_sign_in_place(lib):
    """The signature may overwrite the message (APDU buffers)."""
    seed = os.urandom(32)
    for n in (0, 1, 63, 64, 65, 200):
        msg = os.urandom(n)
        want = ed_sign(lib, seed, msg)
        buf = ctypes.create_string_buffer(msg.ljust(max(n, 64), b"\0"), max(n, 64))
        assert lib.lf_ed25519_sign(buf, buf, n, seed, None) == 0
        assert buf.raw[:64] == want
        # X25519 out may alias the point or the scalar
        k, u = os.urandom(32), os.urandom(32)
        want = x_mul(lib, k, u)
        b = ctypes.create_string_buffer(u, 32)
        assert lib.lf_x25519(b, k, b) == 0 and b.raw == want


def test_null_arguments(lib):
    out = ctypes.create_string_buffer(64)
    seed = os.urandom(32)
    assert lib.lf_ed25519_public_key(None, seed) == -1
    assert lib.lf_ed25519_public_key(out, None) == -1
    assert lib.lf_ed25519_sign(out, None, 1, seed, None) == -1
    assert lib.lf_ed25519_sign(out, None, 0, seed, None) == 0
    assert out.raw == ed_sign(lib, seed, b"")
    assert lib.lf_ed25519_verify(out, None, 0, ed_pub(lib, seed)) == 0
    assert lib.lf_x25519(out, None, seed) == -1
    assert lib.lf_x25519_public_key(None, seed) == -1


OPS = ["none", "public_key", "sign", "sign (pub NULL)", "verify", "x25519", "x25519 public key"]


def test_timing_and_stack(lib, capsys):
    """Host timings (not a pass/fail criterion) and the stack each public
    function uses below its caller: it must stay small (the card task of the
    ESP32 has about 24 KB), the workspace is on the heap."""
    lines = []
    for op in range(1, len(OPS)):
        us = lib.h_bench(op, 50)
        stack = lib.h_stack(op)
        assert us > 0 and 0 < stack < 2048, (OPS[op], us, stack)
        lines.append("%-18s %8.1f us  stack %5d bytes" % (OPS[op], us, stack))
    with capsys.disabled():
        print("\nlf_25519 on this host:\n  " + "\n  ".join(lines))
