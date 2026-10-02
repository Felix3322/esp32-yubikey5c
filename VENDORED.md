# Vendored sources

`pico-keys-sdk`, `pico-fido` and `pico-openpgp` were git submodules of
[librekeys/pico-fido2](https://github.com/librekeys/pico-fido2). LibreFido
changed all three; this repository holds them as plain directories, in the
state of the commits listed below, so that a single repository builds the
firmware. Their licences (AGPL-3.0 for pico-fido and pico-openpgp, see each
directory's LICENSE and file headers; pico-keys-sdk as stated in its files)
apply unchanged. The third-party libraries they use stay submodules:

- `pico-fido/pico-keys-sdk`: https://github.com/librekeys/pico-keys-sdk.git at `fcb453f4596df0967574b203a0c7a3f703ec6051`
- `pico-keys-sdk/mbedtls`: https://github.com/ARMmbed/mbedtls at `e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df`
- `pico-keys-sdk/mlkem`: https://github.com/pq-code-package/mlkem-native/ at `1453da5cd11ea6be7ae83d619d1a72b21e48ec7d`
- `pico-keys-sdk/tinycbor`: https://github.com/intel/tinycbor.git at `c0aad2fb2137a31b9845fbaae3653540c410f215`
- `pico-openpgp/pico-keys-sdk`: https://github.com/librekeys/pico-keys-sdk.git at `fcb453f4596df0967574b203a0c7a3f703ec6051`

## pico-keys-sdk

Upstream: https://github.com/librekeys/pico-keys-sdk (a fork of
https://github.com/polhenarejos/pico-keys-sdk), commit `fcb453f4596df0967574b203a0c7a3f703ec6051`
(Update product name in USB descriptor).

LibreFido changes on top of it, oldest first (commit IDs of the original,
unpublished submodule history):

- 2026-09-23 `a59ea06` build: pin mbedtls 3.6.5, never rewrite submodules at configure time
- 2026-09-23 `5f60a5b` fs: journaled atomic commits and crash-safe record updates
- 2026-09-23 `23cdbb6` apdu: strict ISO 7816-4 parsing and bounded chaining
- 2026-09-23 `88bdce2` core: deterministic AID selection, ordered init, monotonic clock
- 2026-09-23 `103e179` up: debounced user presence that is consumed exactly once
- 2026-09-23 `63e11e4` usb: bounded CCID/HID buffers, CTAPHID channel handling
- 2026-09-23 `8eb4b84` sec: device root key, sealed key store, no automatic eFuse writes
- 2026-09-23 `5257510` fs: Reed-Solomon codec for storage error correction
- 2026-09-23 `c129c97` fs: resilient multi-profile store for ESP32 and the emulator
- 2026-09-23 `9140a8e` emulation: loopback-only HID socket, refuse a busy port
- 2026-09-23 `2546e6c` fs: static files with in-memory data are not store addresses
- 2026-09-23 `593512f` sec: per-profile root key, chip serial for chip binding
- 2026-09-23 `92f40a5` fs: versioned profile backup stream and legacy migration
- 2026-09-23 `97ecbba` profiles: isolated authenticator profiles, button switching
- 2026-09-23 `0846547` mgmt: LibreFido management applet
- 2026-09-23 `c03fdb5` emulation: re-exec reboot friendly sockets, UP timeout override
- 2026-09-23 `39fe92e` mgmt: random boot ID in the SELECT answer
- 2026-09-24 `b8cd8df` emulation: no 40 ms stall per CCID command
- 2026-09-24 `08afe36` fw: firmware update with A/B slots and rollback
- 2026-09-24 `d09de07` esp32: interface strings follow the enabled interfaces
- 2026-09-24 `9dc5eeb` profiles: report a new profile as created, not wiped
- 2026-09-24 `f11dd05` fs: file_wipe_matching() for the reset of one application
- 2026-09-24 `350a22e` rescue: maintenance commands need a touch
- 2026-09-24 `5f9fbd1` hid: CTAPHID_UUID no longer reads past the serial
- 2026-09-24 `85564ea` debug: APDU tracing is a compile error in HARDENED builds
- 2026-09-24 `cf83a96` mgmt: bind the root key to the chip on request
- 2026-09-24 `ac1bb06` usb: never enumerate with Yubico's vendor ID
- 2026-09-24 `9cde79d` build: LIBREFIDO_PROFILE selects the build profile, no Yubico USB identity
- 2026-09-24 `7f88ec9` fs: meta_add() on an empty metadata file (UBSan)
- 2026-09-24 `cbbc701` sec, crypto: sealed-store file helpers, presence policy, Ed25519/X25519
- 2026-09-24 `67d0302` usb, apdu: per-interface transport state, HID channel binding
- 2026-09-24 `40873bb` fs, sec: power-safe record lists, boot recovery, root key rules
- 2026-09-24 `d925c15` mgmt, fw: management protocol 3, storage-format rules, board settings
- 2026-09-24 `4e63f66` mgmt: per-profile AAGUID (PROFILE_AAGUID_SET, INFO profile key 9)
- 2026-09-25 `3c6230c` mgmt: single-key transfer (KEY_LIST, KEY_EXPORT, KEY_IMPORT), firmware 2.1.0

## pico-fido

Upstream: https://github.com/librekeys/pico-fido (a fork of
https://github.com/polhenarejos/pico-fido), commit `1b5342ba3c488f9253678f8601cc90bcb177646d`
(update pico-keys-sdk to v8.5.2-librekeys).

LibreFido changes on top of it, oldest first (commit IDs of the original,
unpublished submodule history):

- 2026-09-23 `b5d0e50` fido: bound CBOR input, check pinUvAuthParam lengths, durable PIN retries
- 2026-09-23 `d81b4a4` fido: fix credential management, keep keys on updateUserInformation
- 2026-09-23 `bfd9291` otp: request touch through wait_button(), also in emulation
- 2026-09-23 `c7e9973` tests: follow real power-cycle and card-reset semantics
- 2026-09-23 `057893a` fido: PIN check for profile export
- 2026-09-24 `c383868` fido: LibreFido AAGUID instead of the Pico FIDO one
- 2026-09-24 `287e8f3` fido: signature counter stored before it is signed
- 2026-09-24 `325c697` fido: user presence works without the PIN after a power cycle
- 2026-09-24 `18e268c` fido: authenticatorReset erases the FIDO state only
- 2026-09-24 `1a4b1ba` fido: replacing the device key through the vendor command needs a touch and the PIN
- 2026-09-24 `b6a9017` fido: no per-site behaviour, self attestation for every relying party
- 2026-09-24 `140dc03` fido: getInfo independent of the USB identity, transports, PIN policy fields
- 2026-09-24 `826d927` fido: empty credBlob without a NULL source pointer (UBSan)
- 2026-09-24 `ae9ed5b` fido: audit fixes, token lifecycle, sealed device key, presence, EdDSA
- 2026-09-24 `a45eb3e` oath, otp: bounded parsing, per-interface sessions, sealed records
- 2026-09-24 `2e976d5` fido: per-profile AAGUID (EF_AAGUID)
- 2026-09-25 `1970cd5` fido: validate CTAP2 requests first, no tags (fuzz finding)
- 2026-09-25 `27f419b` fido, oath, otp: single-key transfer; explicit-key passkeys; OTP touch status

## pico-openpgp

Upstream: https://github.com/librekeys/pico-openpgp (a fork of
https://github.com/polhenarejos/pico-openpgp), commit `f60ac702386d67b85af5346ccfb294689354f940`
(update pico-keys-sdk to v8.5.2-librekeys).

LibreFido changes on top of it, oldest first (commit IDs of the original,
unpublished submodule history):

- 2026-09-23 `d6ce719` openpgp: request touch through wait_button(), also in emulation
- 2026-09-24 `fe3b643` openpgp: GET DATA encodes DOs by their type, not by the client
- 2026-09-24 `15840b1` piv: management key required for administration, key references checked
- 2026-09-24 `eed8872` openpgp: bounded curve lookup and key loading (found by ASan)
- 2026-09-24 `137e221` openpgp, piv: audit fixes, sealed keys and PIN verifiers, Ed25519/X25519
- 2026-09-25 `56c9947` openpgp, piv: single-key export
