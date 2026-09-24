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

## Management applet command

`PROVISION`: CLA 80, INS 50, P1 A5, P2 01 (bind the root key) or 02 (lock
debug), no data. Needs a normal boot (not safe mode) and a physical touch
(automatic presence never applies).

- P2 01 answers 9000 (also when repeated before the restart), 6986 (key
  block already used for something else), 6A81 (not supported on this
  platform), 6985 (no touch, or safe mode), 6F00 (the record cannot be
  bound, e.g. a planted plain root on a profile that was bound before).
- P2 02 answers 9000, 6A88 (already locked), 6A81 (not supported), 6985 (no
  touch, or safe mode), 6F00 (the fuses did not read back set).
