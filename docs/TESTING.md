# Testing

## Emulator

The firmware builds for Linux as an emulator (`-DENABLE_EMULATION=1`): FIDO
HID over a TCP socket, CCID through vpcd (vsmartcard) into a user-mode
pcscd, flash in a file with the ESP32-S3 partition layout, eFuses in a file,
an emulated button (`LF_EMU_UP=manual`, TCP port 35970), and an emulated
bootloader for A/B firmware updates.

```bash
cmake -S . -B build-emu -G Ninja -DENABLE_EMULATION=1 && ninja -C build-emu
cmake -S . -B build-emu-hard -G Ninja -DENABLE_EMULATION=1 -DLIBREFIDO_PROFILE=hardened && ninja -C build-emu-hard
```

Useful environment: `PICO_FLASH_FILE`, `PICO_EFUSE_FILE`, `LF_EMU_UP`
(`auto`/`manual`), `LF_EMU_UP_TIMEOUT_MS`, `LF_EMU_LONGPRESS_MS`,
`LF_FAULT_OPS` (power cut after n flash operations), `LF_EMU_CHIP_SECURE`
(report a complete chip security state), `LF_EMU_KEEP` (keep test work
directories).

## Suites

| Suite | What | Count |
|---|---|---|
| `pico-fido/tests/pico-fido` | upstream CTAP1/CTAP2 suite (python-fido2) | 203 |
| `tests/unit` | Reed-Solomon codec against reedsolo | 13 |
| `tests/storage` | power cut at every flash operation, damaged copies, parity repair, metadata, system area, legacy migration | 10 |
| `tests/profiles` | profiles, button gesture, backups, clones, restore tests, export PIN, firmware update and rollback, signature counter, PIN and user presence, provisioning, GUI | 22 |
| `tests/profiles/test_hardened.py` | HARDENED build (needs `LF_EMU_BIN_HARDENED`) | 4 |
| `tests/openpgp` | DO encoding, yubikit, GnuPG | 3 |
| `tests/isolation` | FIDO/OpenPGP/PIV resets, PIV authorization, PIV/OpenPGP file separation, vendor and rescue commands | 7 |

Run (with the user-mode PC/SC stack of your test environment):

```bash
export LF_EMU_BIN=$PWD/build-emu/pico_fido2 LF_EMU_BIN_HARDENED=$PWD/build-emu-hard/pico_fido2
PYTHONPATH=tests:tools/librefido:tests/profiles python -m pytest tests
PYTHONPATH=tests:pico-fido/tests python -m pytest -p harness.plugin pico-fido/tests/pico-fido
```

`tests/storage/test_migration.py` also needs an emulator built from the
unmodified upstream sources (`LF_EMU_BASELINE_BIN`).

## Hardware

First run on an ESP32-S3 N16R8 dev board (2026-09-23), flashed with the
Windows esptool: enumeration (FIDO HID + CCID), management applet (info,
health scrub of 128 sectors), OATH/OpenPGP/PIV/management SELECT, FIDO2
registration and assertion through Windows WebAuthn with the BOOT button,
profile switch by holding the button 5 s (new USB serial), reboot into the
ROM loader and back without touching the board. It found two bugs the
emulator could not (main task stack overflow on first boot, CCID reader
name), both fixed.
