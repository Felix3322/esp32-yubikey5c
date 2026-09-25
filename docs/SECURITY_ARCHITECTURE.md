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
| Malicious host software, key plugged in, no touch | mostly | every FIDO registration and assertion (unless the owner switched automatic presence on for FIDO, see *Profiles*), every reset, export (of a profile or a single key), import (into any slot, restore tests included; a single FIDO credential or OTP slot), profile creation, switch, wipe or deletion, firmware update or rollback, restart (ROM loader included), eFuse provisioning and maintenance write needs a physical touch collected for that command (exports, updates, rollbacks, the ROM loader and an import into the active slot also the FIDO PIN of the active profile when one is set, even while its key store is locked); OpenPGP and PIV operations need their PIN, and a touch where the key's touch policy says so. Names, colours, button slots and board settings need no touch for 16 changes, then one touch (which renews the allowance); the count is kept in the system area, so restarts do not renew it and the system area cannot be worn out. Checking a backup without importing it writes nothing |
| Malicious host software with the user touching | **no** | a touch authorizes whatever the host asked for; the PIN limits what can be exported. An import into the active slot asks for its PIN, but an import into another slot followed by a switch needs two touches and no PIN. An update asks for the PIN of the active profile only: a host that gets the user to touch for a profile switch first can update from a profile without a PIN |
| Thief with the key, no PIN known | partly | PIN retry counters (FIDO 8, OpenPGP/PIV 3); but see *flash dump* |
| Thief who dumps the flash (root key not bound, no flash encryption) | **no** | the root key of a profile that is not bound to the chip is stored in flash as it is (the chip serial in its record protects nothing): a dump reveals everything |
| Thief who dumps the flash (root key bound to the chip, flash encryption) | yes, unless the chip is also attacked | the root key is wrapped with a key derived from an HMAC eFuse key the software cannot read; the rest of the store (OATH/OTP secrets, the staging area while a transfer runs) only by flash encryption |
| Fault injection, side channels, decapping | **no** | not in scope for this hardware |
| Someone with a backup file or a single-key file | only its passphrase | scrypt (N=2^17) + ChaCha20-Poly1305; an unencrypted backup or key file is the keys |

## Keys

- **Device root key (DRK)**, one per profile (`EF_DEVROOT`). All key
  derivations of the profile hang off it (FIDO device key encryption,
  OpenPGP/PIV data key wrapping via the pico-keys KEK, the FIDO PIN
  verifier). Stored in flash:
  - as it is ("flash, not bound to the chip"): only flash encryption, when
    it is on, keeps it from a flash dump; or
  - wrapped (AES-GCM, the chip serial as associated data) with a key derived
    with the ESP32-S3 HMAC peripheral from an eFuse key that is
    read-protected ("bound to HMAC eFuse key", after
    `librefido provision bind-root-key`). Real protection at rest is this
    binding plus flash encryption.
- **Sealed key store** (`sks`): AES-256-GCM, a fresh nonce per record, a
  key per application namespace derived (HKDF) from the root key, the
  profile serial and a per-namespace epoch, the file id as associated data.
  An application reset rotates its epoch, so old copies no longer open. The
  records below are sealed with it. Records written by firmware 2.0.0 are
  read as they are and sealed only once this firmware is confirmed after an
  update (an automatic rollback must still find them in 2.0.0's format);
  profiles created secure never accept an unsealed record.
- **FIDO device key** (`EF_KEY_DEV`): seed of every FIDO credential key
  (non-discoverable credentials are derived from it and the key handle).
  Sealed; the PIN does **not** encrypt it (older firmware did, which broke U2F
  and userVerification="discouraged" after every power cycle; such keys are
  converted when the PIN is next verified). Resident credentials are
  encrypted (ChaCha20-Poly1305) with keys derived from it.
- **OpenPGP** (`EF_DEK`): an IV, the OpenPGP data key wrapped under
  PW1/RC/PW3, and a slot that only marks PIV as provisioned. The file and
  the PIN verifiers (PW1/RC/PW3, PIV PIN/PUK) are sealed, so an offline PIN
  guess needs the root key; the OpenPGP private keys are encrypted with the
  data key.
- **PIV**: private keys, the management key and the attestation key are
  sealed records (PIV namespace).
- **OATH credentials, OTP slots, static passwords**: sealed records (OATH
  and OTP namespaces).

All of this is only as strong as the root key's protection: without binding
(below) the root key lies in the same flash, and a full flash dump opens
every record.

No secret is ever written to PSRAM (PSRAM is disabled), printed to the
console (APDU tracing is off by default and a build error in HARDENED), or
included in a core dump (core dumps are disabled).

## Profiles

Up to four profiles, each a complete authenticator in its own store region:
root key, USB serial (profile 1 uses the chip serial, others a random one),
PINs and retry counters, FIDO credentials and signature counter,
OpenPGP/PIV/OATH/OTP data. Only the active profile is mounted; switching
(5 s button hold while idle, or `librefido profile select`, which needs a
touch) persists the choice and restarts the device, so the host sees another
key. Until that restart the mounted profile's rules (no-export flag,
policies) still apply, and no export, import or update can start. Nothing
of an inactive profile is readable while another one is active. Creating,
wiping and deleting a profile need a touch too.

Per-profile policies (`lf_policy.h`):

- **Secure profile** (`librefido profile create-secure`, touch): created
  empty, never imported into (an import into its slot is refused until it
  is wiped), keys never leave it (the no-export flag cannot be cleared),
  every presence request needs a press, and its root key is wrapped by the
  chip's HMAC eFuse key from the moment it is generated (so the chip must be
  provisioned first). HARDENED builds have no such command: every profile
  there is treated as secure for exports and presence (keys never leave it,
  every presence needs a press), but a HARDENED profile can be restored from
  a backup. Such a backup can only come from a STANDARD device (HARDENED
  never exports), and its keys also exist in that backup: HARDENED promises
  that keys never leave the device, not that they were generated on it.
  Only a profile created secure on a STANDARD device carries the "never
  imported" promise.
- **Automatic presence** ("my device is safe"): per application (FIDO,
  OATH, OTP, OpenPGP, PIV), a presence request of that application succeeds
  without a press. Switching it on needs a physical press; switching it off
  does not. Never for secure profiles or HARDENED builds, and never for
  destructive or copying operations (resets, exports, imports, updates,
  profile changes), which always need a physical press. Policies never
  travel with a backup.

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
CRC and Reed-Solomon parity. A change that leaves the record as it is writes
nothing; a change whose write fails leaves the record in RAM as it was, so a
later write cannot carry out an operation the host was told had failed.
Every writer of the board settings (the management applet, the rescue
applet, authenticatorConfig, the YubiKey-compatible management WRITE
CONFIG) goes through one function that applies these rules and the change
allowance. In safe mode the record is only written when it was read (never
after a failed migration, which would stop the migration from being tried
again), and board settings are not written at all. After a factory reset
nothing writes it before the restart, which then finds it blank.

**Migration**: a pre-2.0 store in `part0` is copied into profile 1 and
verified; the legacy region is never written. If migration fails the device
boots in safe mode (management applet only) and reports why, instead of
resetting anything.

## Backups, clones, restore tests

A backup is a stream of records (header, root key, files, counters, end with
SHA-256) staged in `lfstage`. Export needs a touch and the FIDO PIN of the
profile when set; it is refused for no-export and secure profiles and in
HARDENED builds. The host file (`.lfbk`) wraps the stream: magic
`LFBACKUP`, format version, firmware version and minimum firmware version,
profile UUID, payload length and SHA-256, optionally encrypted (scrypt +
ChaCha20-Poly1305, the header is authenticated data).

Every transfer (export, import, firmware upload) belongs to the client that
started it: the first command answers a random session ID that every later
command of the transfer must carry, and a command with another ID, or one
arriving on another USB interface (a WebUSB page on the vendor interface
while a PC/SC client transfers), ends the transfer. The PC/SC transaction
the tools hold keeps other PC/SC clients out; the ID keeps out everything
else.

The staged stream holds the root key and every file in the clear, so the
stage is erased whenever a stream is no longer needed: at the end of every
transfer (finished, aborted, or ended by another command), before a new one,
and at every boot (an export or upload cut off by unplugging the key leaves
nothing behind). Only a stream that a pending import or restore test still
needs is kept until the boot that uses it, also when a boot could not write
the system area and retries the operation next time. Only sectors that were
written are erased.

Import needs a touch, whether the slot is empty or not (it installs keys the
host chose). An import into another slot only becomes active through a
profile switch, which needs its own touch; an import into the active slot
replaces the running authenticator at the restart that follows, so it also
asks for the FIDO PIN of that profile when it has one (the same bar as an
update). A secure profile is never imported into; HARDENED builds do take
imports (see *Profiles*). The stream is written
into the stage; at the next boot it is restored into a free region, verified
record by record and only then switched in with one system area commit. The
target slot is left as it was if anything fails. Records for files that are
not kept in the store (data served by a function, or held in RAM) are
refused, names are reduced to valid UTF-8, and policies are not taken over.
A **restore test** (touch) does the same into scratch space and erases it
again: it proves the backup can be restored by this firmware without
touching any profile. The plain check of a stream needs no touch and writes
nothing, not even the stage: the stream is validated as it arrives.

A clone is a restore on another device: the root key is re-wrapped by the
target chip. Counters come along; if the original keeps being used, relying
parties that check counters may notice the clone (by design of FIDO).

**Single keys** (firmware 2.1.0, [KEY_TRANSFER.md](KEY_TRANSFER.md)): one
FIDO discoverable credential, OATH account, OTP slot, OpenPGP key or PIV key
leaves the device under the same bar as a backup (export policy of the
profile, FIDO PIN when set, touch; an OpenPGP key also its Admin PIN) and is
written by the tools into a key file protected like a backup file. A FIDO
credential or an OTP slot comes in through the management applet (FIDO PIN,
touch; FIDO credentials never into a secure profile or a HARDENED build),
OATH, OpenPGP and PIV keys through their own applications and their own
authentication. The copy is a second authenticator with the same key; the
same counter caveat applies.

## Firmware updates

Two application slots. An update is written to the inactive slot, checked
(SHA-256 announced by the host, image validity and with Secure Boot its
signature, the LibreFido descriptor: platform, build profile, version,
storage formats) and booted unconfirmed. The descriptor is only searched in
the part of the image its verification covers, and an image must carry
exactly one. Unless the host confirms it after the restart (the tools do,
once the device answers with the expected version) the next reset rolls
back. Refused: another platform, storage formats the image cannot open,
downgrades and builds of a less restrictive profile (DEVELOPMENT <
STANDARD < HARDENED) unless explicitly allowed (never in HARDENED, which
only installs HARDENED images), any update in a HARDENED build without
Secure Boot (read from the chip, so updates also work in safe mode), a
HARDENED image on a chip that does not already have what HARDENED requires
and cannot do itself (Secure Boot, flash encryption in release mode, JTAG
disabled, restricted download mode, no readable legacy key; such an image
would lock the key store for good and, without Secure Boot, refuse every
update after it), and a new upload while the running firmware is still
unconfirmed (it would overwrite the image a reset goes back to). Key storage
is in its own partitions and never written by an update.

An update needs a touch and the FIDO PIN of the active profile when it has
one (in safe mode no store is open and the touch alone decides, so that a
firmware that cannot open the storage can be replaced). The upload goes into
the slot a rollback would boot; from its first byte on that slot is no
rollback target any more, and an upload that is refused or interrupted
leaves nothing the bootloader or a rollback would start. An explicit
**rollback** installs the previous image, so it asks the same and the image
must pass the same policy (HARDENED: never back to an older version). The
rolled-back image is marked invalid and the previous one boots in the state
it had, so the rollback lasts beyond the next reset. Restarting into the
ESP32 ROM loader (which can read the flash and write any firmware) asks the
same as an update.

**Storage format**: every image states the format of the data it writes
into the profile stores and the oldest it opens (descriptor, `lf_fw.h`
`LF_FW_STORE_FORMAT`). Format 2 (LibreFido 2.0.1) seals the records of the
applications (FIDO device key, PIV keys, OpenPGP data key, OATH and OTP
secrets), which firmware of format 1 cannot read. The applications convert
existing records only once the new firmware is confirmed. From then on a
rollback, or an update (even an explicit downgrade), to an image of an older
format is refused (6986): the sealed keys would be unusable. Before the
confirmation going back always works, explicitly or by the reset that rolls
an unconfirmed update back; keys created while the new firmware was on
trial are written sealed already and are lost by that rollback. 2.1.0 keeps
format 2: it adds one kind of record, the FIDO credential of a single-key
import ([KEY_TRANSFER.md](KEY_TRANSFER.md)), which 2.0.1 keeps but cannot
use. Backups name the oldest firmware that may import them: those made by
2.0.1 need 2.0.1 (2.0.0 refuses them), those made by 2.1.0 need 2.1.0 (the
profile may hold such credentials); backups of 2.0.0 and 2.0.1 still
import.

**Recovery of a HARDENED device**: on a Secure Boot chip, a signed HARDENED
image through `librefido update` (also in safe mode, with a touch only) or a
rollback to an image of the same or a newer version; the ROM loader is
refused there, since it would bypass the update policy. On a chip without
Secure Boot (a HARDENED build flashed before the chip was hardened), where
the key store never unlocked and the ROM loader is reachable with the BOOT
strap anyway: `librefido reboot --bootloader` (PIN and touch) and a reflash,
or a rollback.

**Provisioning** (`librefido provision`, each step irreversible, confirmed by
typing and a physical touch, never automatic): binding the root key to an
HMAC eFuse key generated on the device, and locking debugging (JTAG off,
secure download mode: esptool can still flash but reads nothing). Secure
Boot and flash encryption are enabled with the signed bootloader and host
side eFuse tools.

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
