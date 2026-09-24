# Testing

## Emulator

The firmware builds for Linux as an emulator (`-DENABLE_EMULATION=1`): FIDO
HID over a TCP socket, CCID through vpcd (vsmartcard) into a user-mode
pcscd, flash in a file with the ESP32-S3 partition layout, eFuses in a file,
an emulated button, and an emulated bootloader for A/B firmware updates.

```bash
cmake -S . -B build-emu -G Ninja -DENABLE_EMULATION=1 && ninja -C build-emu
cmake -S . -B build-emu-hard -G Ninja -DENABLE_EMULATION=1 -DLIBREFIDO_PROFILE=hardened && ninja -C build-emu-hard
# sanitizers
cmake -S . -B build-asan -G Ninja -DENABLE_EMULATION=1 \
  "-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
  "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined" && ninja -C build-asan
```

Emulator environment:

| Variable | Effect |
|---|---|
| `PICO_FLASH_FILE`, `PICO_EFUSE_FILE` | flash and eFuse files |
| `LF_EMU_VPCD_PORT`, `LF_EMU_UP_PORT` | vpcd port (CTAPHID listens on port − 1) and button port; the harness sets them |
| `LF_EMU_UP` | `auto` (every presence request succeeds) or `manual` (button socket) |
| `LF_EMU_UP_TIMEOUT_MS`, `LF_EMU_LONGPRESS_MS` | presence timeout, long-press length |
| `LF_FAULT_CTL`, `LF_FAULT_OPS` | power cut / failing writes at a given flash operation |
| `LF_EMU_CHIP_SECURE` | report a complete chip security state (Secure Boot etc.) |
| `LF_EMU_KEYBOARD_LOG` | log what an OTP slot would type |
| `LF_EMU_OATH_IDLE_MS` | OATH HID session idle limit |

## Running the suites

The harness (`tests/harness`) starts pcscd and emulators itself. Ports are
taken from `LF_TEST_PORT_BASE` (CTAPHID = base, vpcd = base + 1, button =
base + 8; default 35962), the pcscd socket from `PCSCLITE_CSOCK_NAME`, so
several runs can go side by side. Tests that start their own emulator
suspend the harness's session emulator and pcscd and get them back
afterwards.

```bash
export LF_EMU_BIN=$PWD/build-emu/pico_fido2 LF_EMU_BIN_HARDENED=$PWD/build-emu-hard/pico_fido2
export PYTHONPATH=tests:pico-fido/tests:tools/librefido:tests/profiles
python -m pytest -p harness.plugin pico-fido/tests/pico-fido tests
```

The development setup used for the results below runs each group in its own
slot (ports, pcscd socket, GnuPG home, temporary directory) in a new session
without a controlling terminal; see `~/work/scripts/locked_tests.sh` in the
test environment notes. Tests that need an earlier firmware build
(`LF_EMU_BASELINE_BIN`, `LF_EMU_PREVIOUS_BIN`, fixed ports) skip in a slot
and run separately on the default ports.

## Suites

| Directory | What |
|---|---|
| `pico-fido/tests/pico-fido` | upstream CTAP1/CTAP2 suite plus LibreFido additions (PIN/token rules, credMgmt, largeBlobs, config, vendor key protection, EdDSA, getInfo features) |
| `tests/fido` | presence policy, secure profiles, held root key, upgrade from 2.0.0 (unconfirmed/confirmed/rollback), HARDENED legacy keys, EdDSA compatibility |
| `tests/libfido2` | libfido2 1.17 interop over TCP custom I/O (ES256 and EdDSA) |
| `tests/transport` | CCID/HID response state per interface, GET RESPONSE, chaining, HID channels, races between interfaces |
| `tests/oath` | YKOATH security (access code, touch, HOTP window), sessions per interface, OTP slots via yubikit, keyboard typing, sealed records, locked key store |
| `tests/openpgp` | DO access, IMPORT/PSO bounds, PIN retries durable across power cuts, Ed25519/Cv25519, sealed DEK and PIN verifiers, GnuPG 2.4 end to end |
| `tests/piv` | access rules, YubiKey default policies, OpenSC / pkcs11-tool / yubico-piv-tool, yubikit incl. Ed25519/X25519, sealed keys, upgrade |
| `tests/isolation` | application resets and separation, vendor and rescue commands |
| `tests/profiles` | profiles, backups, clones, restore tests, firmware update and rollback, management protocol security, policies, provisioning, HARDENED, GUI (offscreen) |
| `tests/storage` | power cut at every flash operation, damaged copies, parity repair, boot recovery, root key rules, legacy migration |
| `tests/unit` | Reed-Solomon codec, flash record lists (real flash.c/low_flash_v2.c on a model store), Ed25519/X25519 (RFC 8032/7748 vectors, 1200-case differential test against `cryptography`) |
| `tests/tools` | host tools offline: backup format, PC/SC transactions, management client against a simulated device, CLI, GUI |
| `tests/fuzz` | seeded mutation fuzzing of every applet, raw CTAPHID frames and CTAP2 CBOR; the emulator must survive (run it against the ASan build) |
| `tests/bench` | latency benchmark (`bench.py`), emulator or a real device over PC/SC |

## Results of this revision (emulator, 2026-09-24)

| Group | Standard build | ASan + UBSan build |
|---|---|---|
| `pico-fido/tests/pico-fido` | 273 passed | 273 passed |
| `tests/unit`, `tests/storage` | 106 passed, 1 skipped¹ | see below² |
| `tests/profiles`, `tests/tools` | 223 passed, 1 skipped | see below² |
| `tests/openpgp`, `tests/piv`, `tests/isolation` | 65 passed | 58 passed (openpgp, piv) |
| `tests/oath`, `tests/transport`, `tests/fido`, `tests/libfido2` | 74 passed, 5 skipped¹ | 73 passed, 5 skipped¹ |
| `tests/fuzz` (1500 / 3000 / 6000 iterations per target) | 9 passed | 9 passed, no sanitizer report |
| fixed-port tests (earlier-firmware baselines, default ports) | 53 passed, 1 skipped | — |

¹ tests that need fixed ports; they pass in the fixed-port run.
² `tests/storage`, `tests/profiles`, `tests/isolation` under ASan: the run of
this revision collided with an orphaned emulator of another test slot (the
slot runner now removes such orphans) and its re-run was interrupted; the
previous revision's ASan run of these suites had no sanitizer report.

Earlier findings of the fuzzer, fixed: a division by zero reachable without
authentication in the secure-messaging path of OpenPGP/PIV, and a
misaligned 32-bit read of U2F key handles (fatal on the ESP32-S3).

Yubico's CLI against the emulator: `ykman --reader "<reader>"` lists the
applications, adds and calculates OATH TOTP/HOTP accounts (codes match RFC
6238 computed independently), sets and uses an OATH password.

## Hardware

- 2026-09-23, firmware 2.0.0, ESP32-S3 N16R8 dev board, flashed with the
  Windows esptool: enumeration (FIDO HID + CCID), management applet (info,
  health scrub of 128 sectors), OATH/OpenPGP/PIV/management SELECT, FIDO2
  registration and assertion through Windows WebAuthn with the BOOT button,
  profile switch by holding the button 5 s (new USB serial), reboot into the
  ROM loader and back. It found two bugs the emulator could not (main task
  stack overflow on first boot, CCID reader name), both fixed.
- 2026-09-24, firmware 2.0.1 (this revision), same board, flashed over the
  data of 2.0.0 with the Windows esptool (16 MB backup taken first): boots,
  both existing profiles and their identities kept, management protocol 3,
  key store unlocked, storage health scrub of 128 sectors without a single
  error, OATH TOTP added / calculated (equal to RFC 6238 computed on the
  host) / deleted over PC/SC, OpenPGP and PIV selected (corrected PIV
  application template). WebAuthn, the button-driven features and OTP
  typing on this build are still to be checked on the board.
