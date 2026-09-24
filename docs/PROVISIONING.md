# Provisioning

`librefido provision` (tools/librefido) handles chip security on ESP32-S3
devices. Its rules:

1. **Inspect first.** Every action starts from `librefido info`.
2. **Print the plan.** `librefido provision plan` lists every step towards a
   hardened device with what it burns, its effect and its brick risk
   (`--json` for scripts). It changes nothing.
3. **Dry run by default.** `bind-root-key` without `--apply` checks the
   state and prints what would happen.
4. **Explicit confirmation.** `--apply` asks you to type
   `BURN <chip serial>`; anything else aborts.
5. **Metadata backup.** Before any change the non-secret device metadata
   (firmware, serials, build profile, security state, profile UUIDs) is
   saved to `librefido-provision-<chip>-<time>.json` (`--metadata-dir`).
6. **Safe order.** Only the step without brick risk is automated; Secure
   Boot, flash encryption, JTAG, download mode and anti-rollback are
   bootloader configuration and stay manual
   ([ESP32S3_HARDENING.md](ESP32S3_HARDENING.md)).
7. **Verify after each phase.** After burning, the tool reads the state
   again and fails loudly if the device does not report the binding.
8. **Refuse inconsistent states.** Safe mode, an HMAC key the root key is
   not bound to, or no root key: the tool stops without changing anything.

## Binding the root key

```bash
librefido provision bind-root-key            # dry run
librefido provision bind-root-key --apply    # type BURN <serial>, touch the key
```

The device generates the HMAC key itself (it never leaves the chip), burns
it into eFuse BLOCK_KEY5 with purpose HMAC_UP, read and write protected, and
re-wraps the root key of the active profile with a key derived from it.
Other profiles are re-wrapped the next time they are mounted. Credentials
keep working; backups keep working (they carry the root key, which the
target chip re-wraps).

A HARDENED build requires this step before its key store unlocks.

## Management applet command

`PROVISION_HMAC`: CLA 80, INS 50, P1 A5, P2 01, no data. Needs a normal boot
(not safe mode) and a touch. Answers 9000, 6986 (key block already used for
something else), 6A81 (not supported on this platform), 6985 (no touch, or
safe mode).
