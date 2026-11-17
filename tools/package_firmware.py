"""Validate and package an ESP-IDF build; never connects to a device."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools/librefido"))
from librefido.firmware import parse

BOARDS = {
    "esp32s3": ("esp32s3", 16, 0),
    "atoms3u-4mb": ("esp32s3-4mb", 4, 41),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def package(build, output, board, profile, version, revision):
    platform, flash_mb, gpio = BOARDS[board]
    output.mkdir(parents=True, exist_ok=True)
    config = (build / "config/sdkconfig.h").read_text()
    require(f"#define CONFIG_LIBREFIDO_UP_BUTTON_GPIO {gpio}\n" in config, "wrong button GPIO")
    require("#define CONFIG_LIBREFIDO_UP_BUTTON_ACTIVE_HIGH " not in config, "button must be active low")
    require("#define CONFIG_LIBREFIDO_UP_BUTTON_PULL_UP 1\n" in config, "button needs pull-up")
    require("#define CONFIG_LIBREFIDO_DEV_AUTO_UP " not in config, "automatic presence is forbidden")
    require(f"#define CONFIG_ESPTOOLPY_FLASHSIZE_{flash_mb}MB 1\n" in config, "wrong flash size")

    app = (build / "pico_fido2.bin").read_bytes()
    descriptor = parse(app)
    require(descriptor["version"] == version, "wrong firmware version")
    require(descriptor["platform"] == platform, "wrong firmware platform")
    require(descriptor["build_profile"] == profile, "wrong build profile")

    # ESP-IDF partition entries are 32 bytes. Stop at the MD5 / erased entry.
    table = (build / "partition_table/partition-table.bin").read_bytes()
    partitions = {}
    for pos in range(0, len(table), 32):
        magic, kind, subtype, offset, size, label, flags = struct.unpack_from("<HBBII16sI", table, pos)
        if magic in (0xEBEB, 0xFFFF):
            break
        require(magic == 0x50AA, "invalid partition table magic")
        name = label.rstrip(b"\0").decode("ascii")
        require(name not in partitions, "duplicate partition")
        require(offset + size <= flash_mb * 1024 * 1024, "partition exceeds flash")
        partitions[name] = {"type": kind, "subtype": subtype, "offset": offset, "size": size, "flags": flags}
    ordered = sorted(partitions.values(), key=lambda p: p["offset"])
    require(all(a["offset"] + a["size"] <= b["offset"] for a, b in zip(ordered, ordered[1:])), "overlapping partitions")
    for name in ("ota_0", "ota_1"):
        require(name in partitions and partitions[name]["type"] == 0, "missing OTA app slot")
        require(len(app) <= partitions[name]["size"], "application exceeds OTA slot")

    flashing = json.loads((build / "flasher_args.json").read_text())
    require(flashing["flash_settings"]["flash_size"] == f"{flash_mb}MB", "wrong flashing flash size")
    require(int(flashing["app"]["offset"], 0) == partitions["ota_0"]["offset"], "wrong application offset")
    segments = sorted((int(offset, 0), path) for offset, path in flashing["flash_files"].items())
    expected_offsets = {0, 0x8000, partitions["otadata"]["offset"], partitions["ota_0"]["offset"]}
    require({offset for offset, _ in segments} == expected_offsets, "unexpected flashing segments")
    require(len(segments) == len(expected_offsets), "duplicate flashing segment")
    prefix = f"librefido-{version}-{board}-{profile}"
    app_path = output / f"{prefix}-app.bin"
    full_path = output / f"{prefix}-full.bin"
    zip_path = output / f"{prefix}-parts.zip"
    app_path.write_bytes(app)

    # Reuse exactly the flash mode, frequency and offsets emitted by ESP-IDF.
    merge = [sys.executable, "-m", "esptool", "--chip", "esp32s3", "merge_bin", "-o", str(full_path)]
    merge += flashing["write_flash_args"]
    for offset, path in segments:
        merge += [hex(offset), str(build / path)]
    subprocess.run(merge, check=True)
    full = full_path.read_bytes()
    end = max(offset + (build / path).stat().st_size for offset, path in segments)
    require(len(full) == end, "unexpected merged image length")
    for offset, path in segments:
        require(full[offset:offset + (build / path).stat().st_size] == (build / path).read_bytes(), "merged segment differs from build")
    require(full[partitions["ota_0"]["offset"]:] == app, "merged application mismatch")
    descriptor_full = parse(full)
    require(descriptor_full["version"] == version and descriptor_full["platform"] == platform, "merged firmware descriptor mismatch")

    metadata = {
        "version": version, "source_commit": revision, "board": board,
        "build_profile": profile, "platform": platform, "flash_layout_mb": flash_mb,
        "button_gpio": gpio, "button_active_low": True, "button_pull": "up",
        "partitions": partitions, "firmware_descriptor": descriptor,
        "idf_version": subprocess.check_output([sys.executable, os.environ["IDF_PATH"] + "/tools/idf.py", "--version"], text=True).strip(),
        "hardware_tested": False,
    }
    members = {path: (build / path).read_bytes() for _, path in segments}
    members.update({name: (build / name).read_bytes() for name in ("flash_args", "flasher_args.json")})
    members["BUILD_INFO.json"] = (json.dumps(metadata, indent=2) + "\n").encode()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    with zipfile.ZipFile(zip_path) as archive:
        require(archive.testzip() is None, "ZIP checksum failure")
        require(set(archive.namelist()) == set(members), "ZIP contents mismatch")
        for name, data in members.items():
            require(archive.read(name) == data, "ZIP member differs from build")
    for path in (app_path, full_path, zip_path):
        print(hashlib.sha256(path.read_bytes()).hexdigest(), path.name, path.stat().st_size)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=REPO / "release")
    parser.add_argument("--board", choices=BOARDS, required=True)
    parser.add_argument("--profile", choices=("standard", "hardened"), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"\d+\.\d+\.\d+", args.version) is not None, "invalid version")
    package(args.build_dir.resolve(), args.output_dir.resolve(), args.board, args.profile, args.version, args.revision)
