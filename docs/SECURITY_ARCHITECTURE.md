# Security architecture

LibreFido favours convenience: keys can be exported, cloned and restored.
This document says precisely what that costs and what is still protected.
An ESP32-S3 is a general-purpose microcontroller, **not a secure element**:
there is no tamper resistance, no certified side-channel protection and no
FIDO certification of any level.

## Threat model

| Attacker | Protected? | By what |
|---|---|---|
| Malicious website / relying party | yes | WebAuthn origin binding, per-RP keys, self attestation (no cross-site identifier) |
| Malicious host software, key plugged in, no touch | mostly | every FIDO registration and assertion, every reset, export, import, firmware update, profile wipe and maintenance write needs a touch collected for that command (exports and updates also the FIDO PIN when one is set); OpenPGP and PIV operations need their PIN, and a touch where the key's touch policy says so |
| Malicious host software with the user touching | **no** | a touch authorizes whatever the host asked for; the PIN limits what can be exported |
| Thief with the key, no PIN known | partly | PIN retry counters (FIDO 8, OpenPGP/PIV 3); but see *flash dump* |
| Thief who dumps the flash (STANDARD build, no provisioning) | **no** | the root key is stored in flash wrapped with a key derived from the chip ID: a dump plus the chip ID reveals everything |
| Thief who dumps the flash (root key bound to the chip) | yes, unless the chip is also attacked | the root key is wrapped with a key derived from an HMAC eFuse key the software cannot read |
| Fault injection, side channels, decapping | **no** | not in scope for this hardware |
| Someone with a backup file | only its passphrase | scrypt (N=2^17) + ChaCha20-Poly1305; an unencrypted backup is the keys |

## Keys

- **Device root key (DRK)**, one per profile (`EF_DEVROOT`). All key
  derivations of the profile hang off it (FIDO device key encryption,
  OpenPGP/PIV data key wrapping via the pico-keys KEK). Stored in flash,
  wrapped with:
  - a key derived from the chip ID (default, "flash, not bound to the chip"),
    or
  - a key derived with the ESP32-S3 HMAC peripheral from an eFuse key that
    is read-protected ("bound to HMAC eFuse key", after
    `librefido provision bind-root-key`).
- **FIDO device key** (`EF_KEY_DEV`): seed of every FIDO credential key
  (non-discoverable credentials are derived from it and the key handle).
  Stored in format 0x01, encrypted with a key derived from the root key. The
  PIN does **not** encrypt it (older firmware did, which broke U2F and
  userVerification="discouraged" after every power cycle; such keys are
  converted when the PIN is next verified).
- **OpenPGP / PIV data keys** (`EF_DEK`): one IV, three copies of the
  OpenPGP key encrypted with PW1/RC/PW3, one PIV key encrypted with the PIV
  PIN. Private keys of these applications are encrypted with them.
- **OATH secrets, OTP slots**: stored in the profile store as they are;
  protection at rest is flash encryption (when enabled) only.

No secret is ever written to PSRAM (PSRAM is disabled), printed to the
console (APDU tracing is off by default and a build error in HARDENED), or
included in a core dump (core dumps are disabled).

## Profiles

Up to four profiles, each a complete authenticator in its own store region:
root key, USB serial (profile 1 uses the chip serial, others a random one),
PINs and retry counters, FIDO credentials and signature counter,
OpenPGP/PIV/OATH/OTP data. Only the active profile is mounted; switching
(5 s button hold while idle, or `librefido profile select`) persists the
choice and restarts the device, so the host sees another key. Nothing of an
inactive profile is readable while another one is active.

Applications inside a profile are isolated too: a FIDO reset erases the FIDO
state only, an OpenPGP TERMINATE DF the OpenPGP state only, a PIV reset the
PIV state only (tests/isolation). PIV and OpenPGP share one file namespace;
every PIV key reference goes through one mapping function so that neither
can reach the other's files.

## Storage

Flash layout (16 MB, `config/esp32/partitions_librefido_16mb.csv`):

| Partition | Offset | Size | Content |
|---|---|---|---|
| nvs, otadata | 0x9000, 0xE000 | | ESP-IDF |
| ota_0 | 0x010000 | 1.94 MB | firmware slot A |
| part0 | 0x200000 | 1 MB | legacy (pre-2.0) store, read only |
| ota_1 | 0x300000 | 1.94 MB | firmware slot B |
| lfsys | 0x4F0000 | 64 KB | system area |
| lfstage | 0x500000 | 512 KB | staging for backups and imports |
| lfr0..lfr4 | 0x580000 + n × 1.5 MB | 1.5 MB each | profile stores (4 profiles + 1 spare) |

**Profile store** (per region, 4 KB sectors): header (2), journal (1),
transaction pool (32), copy A (128), copy B (128), metadata A and B (22
each), counter log (8). The file system sees 128 logical sectors (512 KB).

Every logical sector has two physical copies and a metadata entry per copy:
generation, CRC-32C, erase count and 608 bytes of Reed-Solomon RS(255,223)
parity (corrects up to 16 bytes per 223-byte block).

**Transactions**: changed sectors are written to the pool, a COMMIT record
names them, then copy A and its metadata are written and verified, then copy
B and its metadata, then an APPLIED record. A power cut at any point leaves
either the old or the new state: at boot an unfinished transaction is rolled
forward from the pool (a single-sector update is 14 flash operations; the
emulator test cuts power at every one of them).

**Scrub** (every boot, and `librefido health --scrub`): every sector of both
copies is checked; a copy with a bad CRC is corrected with its parity or
rebuilt from the other copy; the health report counts every repair.

**Counters** (FIDO signature counter): a 16-byte record per increment in a
log of two rings, instead of a file system transaction per signature. The
value is stored *before* it is signed, so a power cut cannot produce two
signatures with the same counter.

**System area**: 8 generations × 2 copies of a record (active profile,
profile table, board settings, pending operation, last result), each with
CRC and Reed-Solomon parity.

**Migration**: a pre-2.0 store in `part0` is copied into profile 1 and
verified; the legacy region is never written. If migration fails the device
boots in safe mode (management applet only) and reports why, instead of
resetting anything.

## Backups, clones, restore tests

A backup is a stream of records (header, root key, files, counters, end with
SHA-256) staged in `lfstage`. Export needs a touch and the FIDO PIN of the
profile when set; it is refused for no-export profiles and in HARDENED
builds. The host file (`.lfbk`) wraps the stream: magic `LFBACKUP`, format
version, firmware version and minimum firmware version, profile UUID,
payload length and SHA-256, optionally encrypted (scrypt + ChaCha20-Poly1305,
the header is authenticated data).

Import writes the stream into the stage; at the next boot it is restored
into a free region, verified record by record and only then switched in
with one system area commit. The target slot is left as it was if anything
fails. A **restore test** does the same into scratch space and erases it
again: it proves the backup can be restored by this firmware without
touching any profile.

A clone is a restore on another device: the root key is re-wrapped by the
target chip. Counters come along; if the original keeps being used, relying
parties that check counters may notice the clone (by design of FIDO).

## Firmware updates

Two application slots. An update is written to the inactive slot, checked
(SHA-256 announced by the host, image validity and with Secure Boot its
signature, the LibreFido descriptor: platform, version, storage formats) and
booted unconfirmed. Unless the host confirms it after the restart (the tools
do, once the device answers with the expected version) the next reset rolls
back. Refused: another platform, storage formats the image cannot open,
downgrades unless explicitly allowed (never in HARDENED), and any update in
a HARDENED build without Secure Boot. Key storage is in its own partitions
and never written by an update.

## Attestation

Self attestation for every relying party: the credential key signs its own
attestation. A profile can be exported and cloned, so a device certificate
would vouch for one device that may exist several times. LibreFido has its
own AAGUIDs (`08c228d9-7ea0-2bc8-d08e-0d22a6d13f7d`, HARDENED
`6c86ea00-e576-2756-4e8a-6234f544e3fd`), is not FIDO certified, and never
uses another vendor's AAGUID, certificates or USB identity.

## Build profiles

See the README table. HARDENED additionally refuses to unlock the key store
unless the chip reports Secure Boot, flash encryption in release mode, JTAG
disabled, secure download mode, anti-rollback, an HMAC eFuse key and a root
key bound to it.
