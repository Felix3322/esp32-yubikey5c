"""LibreFido firmware images: the descriptor every image carries
(pico-keys-sdk/src/fs/lf_fw.h) and the checks the host makes before an
update. The device checks everything again; this is for clear messages."""

import hashlib
import struct

MAGIC = b"LFFWDSC1"
MAGIC_INV = bytes(~c & 0xFF for c in MAGIC)
DESC_FMT = "<8s8sBBB3sBBBB16s4s"
DESC_SIZE = struct.calcsize(DESC_FMT)

PLATFORMS = {0x01: "esp32s3", 0x7F: "emulation"}
BUILD_PROFILES = {0: "development", 1: "standard", 2: "hardened"}
SLOT_FACTORY = 0xFF


class FirmwareError(Exception):
    pass


def parse(image):
    """Descriptor of a firmware image (bytes). Raises FirmwareError when the
    file is not a LibreFido 2 firmware image."""
    i = image.find(MAGIC + MAGIC_INV)
    if i < 0 or i + DESC_SIZE > len(image):
        raise FirmwareError("not a LibreFido firmware image (no descriptor)")
    if image.find(MAGIC + MAGIC_INV, i + 1) >= 0:
        raise FirmwareError("image carries more than one descriptor")
    (_, _, desc_version, platform, profile, version, store, store_min, sys_v, sys_min,
     board, _) = struct.unpack_from(DESC_FMT, image, i)
    if desc_version != 1:
        raise FirmwareError("descriptor version %d is not supported by this tool" % desc_version)
    return {
        "version": "%d.%d.%d" % tuple(version),
        "version_tuple": tuple(version),
        "platform": PLATFORMS.get(platform, "unknown (0x%02x)" % platform),
        "platform_id": platform,
        "build_profile": BUILD_PROFILES.get(profile, str(profile)),
        "store_format": (store_min, store),
        "system_format": (sys_min, sys_v),
        "board": board.rstrip(b"\0").decode(errors="replace"),
        "size": len(image),
        "sha256": hashlib.sha256(image).hexdigest(),
        "offset": i,
    }


def set_version(image, version):
    """Copy of image with another version in its descriptor (tests)."""
    d = parse(image)
    out = bytearray(image)
    out[d["offset"] + 19:d["offset"] + 22] = bytes(version)
    return bytes(out)


def compare(a, b):
    """-1, 0, 1 like cmp() for version tuples."""
    return (a > b) - (a < b)
