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
| `tests/fido` | presence policy, secure profiles, held root key, upgrade from 2.0.0 (unconfirmed/confirmed/rollback), HARDENED legacy keys, EdDSA compatibility, non-canonical CBOR (tags, indefinite lengths, truncated or too deeply nested items) in CTAP2 (HID and CCID) and management requests |
| `tests/libfido2` | libfido2 1.17 interop over TCP custom I/O (ES256 and EdDSA) |
| `tests/transport` | CCID/HID response state per interface, GET RESPONSE, chaining, HID channels, races between interfaces |
| `tests/oath` | YKOATH security (access code, touch, HOTP window), sessions per interface, OTP slots via yubikit, keyboard typing, sealed records, locked key store |
| `tests/openpgp` | DO access, IMPORT/PSO bounds, PIN retries durable across power cuts, Ed25519/Cv25519, sealed DEK and PIN verifiers, GnuPG 2.4 end to end |
| `tests/piv` | access rules, YubiKey default policies, OpenSC / pkcs11-tool / yubico-piv-tool, yubikit incl. Ed25519/X25519, sealed keys, upgrade |
| `tests/isolation` | application resets and separation, vendor and rescue commands |
| `tests/profiles` | profiles, backups, clones, restore tests, firmware update and rollback, management protocol security, policies, provisioning, HARDENED, GUI (offscreen) |
| `tests/keys` | single-key transfer ([KEY_TRANSFER.md](KEY_TRANSFER.md)) between emulated devices: KEY_LIST / KEY_EXPORT / KEY_IMPORT per application, records and their validation, paging, touch and PIN order, refusals of secure profiles and HARDENED builds, imported FIDO credentials in use (assertions, hmac-secret, largeBlobKey, credBlob, credential management, excludeList), the OATH / OpenPGP / PIV imports through their applications, the CLI end to end, going back to 2.0.1 (needs its build) |
| `tests/storage` | power cut at every flash operation, damaged copies, parity repair, boot recovery, root key rules, legacy migration |
| `tests/unit` | Reed-Solomon codec, flash record lists (real flash.c/low_flash_v2.c on a model store), Ed25519/X25519 (RFC 8032/7748 vectors, 1200-case differential test against `cryptography`) |
| `tests/tools` | host tools offline: backup format, key file format (`test_keyfile.py`), standard key formats (`test_stdformats.py`: otpauth, Google Authenticator export, QR codes, PEM / DER / PKCS#12, OpenPGP secret keys), PC/SC transactions, management client against a simulated device, CLI, GUI (incl. the key commands and the Keys tab) |
| `tests/fuzz` | seeded mutation fuzzing of every applet, raw CTAPHID frames and CTAP2 CBOR; the emulator must survive (run it against the ASan build) |
| `tests/bench` | latency benchmark (`bench.py`), emulator or a real device over PC/SC |

## Results of this revision (2.1.0, emulator, 2026-09-24/25)

| Group | Standard build | ASan + UBSan build |
|---|---|---|
| `pico-fido/tests/pico-fido` | 273 passed | 273 passed |
| `tests/unit`, `tests/storage` | 71 passed, 1 skipped¹; 35 more passed in a re-run³ | not run this time⁴ |
| `tests/profiles`, `tests/tools` | 638 passed, 2 skipped; 3 more passed in a re-run³ | not run this time⁴ |
| `tests/openpgp`, `tests/piv`, `tests/isolation` | 63 passed; 3 more passed in a re-run³ | 59 passed (openpgp, piv) |
| `tests/oath`, `tests/transport` | 74 passed, 5 skipped¹ with `tests/fido`; 1 more passed in a re-run³ | 74 passed, 5 skipped¹ (with `tests/fido`) |
| `tests/fido`, `tests/libfido2` (after the CBOR validation) | 94 passed, 5 skipped¹ | see above |
| `tests/keys` | 21 passed | 21 passed, no sanitizer report |
| `tests/manager` | 101 passed (with `tests/keys` before the CBOR validation) | — |
| `tests/fuzz` (1500 iterations; ASan 3000) | 9 passed; CTAP2 CBOR seeds 3 and 5 with 6000 iterations passed | 9 passed, no sanitizer report |
| HARDENED binary: `tests/fido/test_cbor_hardening.py`, `tests/keys/test_transfer_policy.py`, `tests/profiles/test_hardened.py` | 89 passed, 1 skipped | — |
| fixed-port tests (earlier-firmware baselines, default ports) | 54 passed, 1 skipped | — |

¹ tests that need fixed ports; they pass in the fixed-port run.
³ the first run of these groups ran at the same time as two ESP32-S3 builds
and seven groups shared six test slots: 21 storage tests failed on a busy
test port and 14 more on timeouts, plus 7 timing-dependent tests in other
groups. Re-run without that load, every one of them passed (storage 44,
profiles 23, openpgp 5, oath 7).
⁴ the storage / profiles / isolation groups take about 40 minutes under
ASan; the previous revisions' ASan runs of them had no sanitizer report.

The last change (CTAP2 CBOR validation, see below) was re-tested with the
upstream suite, `tests/fido`, `tests/libfido2`, `tests/keys`, `tests/fuzz`
and the HARDENED groups; the other groups ran on the tree just before it.

Earlier findings of the fuzzer, fixed: a division by zero reachable without
authentication in the secure-messaging path of OpenPGP/PIV, a misaligned
32-bit read of U2F key handles (fatal on the ESP32-S3), and a CBOR tag as
the value of a member the parser skips (tinycbor counts no tag as an item,
so the parser ran past the end of the map: an assertion, a reboot by any
host; CTAP2 requests and the management applet's CBOR commands are now
validated first, without tags or indefinite lengths).

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
- 2026-09-25, firmware 2.1.0, same board, written from the ROM loader (BOOT
  held while plugging in) after a full 16 MB backup (per-chunk MD5) with the
  Windows esptool; only bootloader, partition table (unchanged), OTA data and
  application: boots 2.1.0, both profiles and the active one kept, INFO key 19
  reports export for all five applications and import for FIDO and OTP,
  health scrub of 128 sectors without an error, OATH TOTP added / calculated
  (equal to RFC 6238) / deleted through the key manager, OTP / OpenPGP / PIV
  status read by the key manager. Found on the board: Windows refuses the
  SELECT of the FIDO application over PC/SC to a program not started as
  administrator (SCARD_E_NO_ACCESS, the device never sees it), so the key
  manager's passkey page needs the GUI started as administrator on Windows
  (now said clearly; the other pages and single-key transfer, which uses the
  management applet, are not affected). Not yet checked on the board: single-
  key export / import (needs the FIDO PIN and a touch), the key manager as
  administrator, WebAuthn.
