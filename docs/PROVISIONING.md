# Provisioning

`librefido provision` (tools/librefido) handles chip security on ESP32-S3
devices. Its rules:

1. **Inspect first.** Every action starts from `librefido info`.
2. **Print the plan.** `librefido provision plan` lists every step towards a
   hardened device with what it burns, its effect and its brick risk
   (`--json` for scripts). It changes nothing.
3. **Dry run by default.** `bind-root-key` and `lock-debug` without
   `--apply` check the state and print what would happen.
4. **Explicit confirmation.** `--apply` asks you to type
   `BURN <chip serial>`; anything else aborts.
5. **Metadata backup.** Before any change the non-secret device metadata
   (firmware, serials, build profile, security state, profile UUIDs) is
   saved to `librefido-provision-<chip>-<time>.json` (`--metadata-dir`).
6. **Safe order.** Only the steps without brick risk are automated: binding
   the root key (level 1) and locking debug access (level 2). Secure Boot,
   flash encryption and anti-rollback need a signed bootloader build and
   stay guided manual steps ([ESP32S3_HARDENING.md](ESP32S3_HARDENING.md)).
7. **Verify after each phase.** After burning, the tool reads the state
   again and fails loudly if the device does not report it.
8. **Refuse inconsistent states.** Safe mode, a secure profile whose root
   record is plain or missing, a HARDENED build without a root key, an
   unknown key store state: the tool stops without changing anything. A
   *held* profile (below) is not inconsistent: the tool explains it and
   offers the binding.

## Binding the root key

```bash
librefido provision bind-root-key            # dry run
librefido provision bind-root-key --apply    # type BURN <serial>, touch the key
```

The device generates the HMAC key itself (it never leaves the chip), burns
it into eFuse BLOCK_KEY5 with purpose HMAC_UP, read and write protected, and
re-wraps the root key of the active profile with a key derived from it.
Other profiles are re-wrapped the next time they are mounted, as long as
Secure Boot is off. Once Secure Boot is on, a profile whose root key is
still plain is *held* instead: its key store stays locked (and it cannot be
exported) until `bind-root-key --apply` is run again with that profile
active and the device is restarted. A plain root key found on a Secure Boot
chip could have been planted by someone who wrote the flash, so the device
waits for your confirmation instead of adopting it. Select every profile
once after binding and before enabling Secure Boot to avoid this.
Credentials keep working; backups keep working (they carry the root key,
which the target chip re-wraps).

A HARDENED build requires this step before its key store unlocks.

A profile without any root key (created by the original firmware's legacy
derivation) is recorded the same way: on a Secure Boot chip it is held
(locked) until `bind-root-key --apply` records on the chip that it has no
root key; it unlocks at the next start. `librefido info` shows the key store
state (`key_store: unlocked / LOCKED`).

## Locking debug access

```bash
librefido provision lock-debug               # dry run
librefido provision lock-debug --apply       # type BURN <serial>, touch the key
```

Burns three eFuses, irreversibly: `DIS_PAD_JTAG` and `DIS_USB_JTAG` (no
JTAG debugger can read RAM or flash), and `ENABLE_SECURITY_DOWNLOAD` (the
ROM loader only accepts the secure download command set: `esptool
write-flash` still works, reading the flash or RAM does not). Nothing of
this can brick the board: flashing and recovery through esptool keep
working. Together with the bound root key this is protection level 2; level
3 needs Secure Boot and flash encryption.

## Management applet commands

The management applet (AID `F0 4C 49 42 52 45 46 49 44 4F`, CLA 80, data
and answers CBOR maps with integer keys) is what the tools talk to; the
instructions are listed in `pico-keys-sdk/src/fs/lf_mgmt.h`. Provisioning and
the single-key transfer of firmware 2.1.0:

| INS | Command | Data | Needs | Answer |
|---|---|---|---|---|
| 01 | INFO | none | nothing | device, security and profile state; key 19 (2.1.0): `{1: export mask, 2: import mask}`, bit n for application n (0 FIDO, 1 OATH, 2 OTP, 3 OpenPGP, 4 PIV), absent before 2.1.0 |
| 50 | PROVISION | none (P1 A5, P2 01 / 02) | normal boot, touch | below |
| 60 | KEY_LIST | `{1: app, 2: FIDO PIN, 3: cursor, 4: list session ID}` | FIDO PIN when set; first page: a touch for FIDO without a verified PIN and for OATH with a password or OTP PIN; later pages: the list session ID (docs/KEY_TRANSFER.md) | `{1: entries, 2: exportable, 3: next cursor, 4: list session ID}` |
| 61 | KEY_EXPORT | `{1: app, 2: key ID, 3: FIDO PIN, 4: application secret}` | export allowed by the profile and build, FIDO PIN when set, touch; OpenPGP: Admin PIN | `{1: app, 2: record}` |
| 62 | KEY_IMPORT | `{1: app, 2: record, 3: FIDO PIN, 4: application secret, 5: replace, 6: target}` | FIDO PIN when set, touch; FIDO: not a secure profile or HARDENED build; OTP: the access code of a target slot that has one | `{1: app, 2: key ID}` |

The fields, records and status words of INS 60–62 are in
[KEY_TRANSFER.md](KEY_TRANSFER.md). Automatic presence never replaces the
touch of any of these commands.

`PROVISION`: CLA 80, INS 50, P1 A5, P2 01 (bind the root key) or 02 (lock
debug), no data. Needs a normal boot (not safe mode) and a physical touch
(automatic presence never applies).

- P2 01 answers 9000 (also when repeated before the restart), 6986 (key
  block already used for something else), 6A81 (not supported on this
  platform), 6985 (no touch, or safe mode), 6F00 (the record cannot be
  bound, e.g. a planted plain root on a profile that was bound before).
- P2 02 answers 9000, 6A88 (already locked), 6A81 (not supported), 6985 (no
  touch, or safe mode), 6F00 (the fuses did not read back set).
