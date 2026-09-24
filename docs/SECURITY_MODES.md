# Security modes

Every profile (see [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md)) is
either a **standard** profile or a **secure** profile, and each profile has
its own presence policy per application.

## What protects the keys at rest (all profiles)

Every private key, OATH secret, OTP slot secret and static password is
stored sealed: AES-256-GCM with a fresh random nonce per record, a key per
application namespace derived from the profile's root key, and the record's
identity as authenticated data. A record cannot be read, altered or moved to
another application without the root key. This covers the FIDO device key
(from which every credential key is derived), PIV keys and the management
key, the OpenPGP data key (which also stays encrypted under the PINs),
OATH credentials and OTP slots.

Records written by firmware 2.0.0 keep working as they are and are sealed
only once this firmware is *confirmed* after an update: until then an
automatic rollback to 2.0.0 must still find them in its own format.

Without a bound root key (below), the root key itself lies in the flash next
to the records, so this sealing protects nothing against someone who reads
the whole flash; it does protect each application's records from the
others.

How strong that is depends on where the root key lives:

| Root key | A flash dump reveals the keys? | How to get there |
|---|---|---|
| in flash, not bound to the chip | **yes** (the flash dump alone) | default after flashing |
| bound to the chip (HMAC eFuse key, read protected) | no | `librefido provision bind-root-key`, or the GUI button "Protect keys against flash reads" |

Binding burns one eFuse key block (irreversible, does not brick). It is
never done without an explicit request and a touch.

Binding stops *reading* the keys from the flash. It does not stop someone
who holds the device from installing firmware of their own that uses the
chip's HMAC key: that needs Secure Boot (next section).

## Secure profile ("安全模式")

A secure profile behaves like a YubiKey:

- created empty on the device, never imported and never converted from a
  standard profile (its keys have never been outside);
- nothing can be exported, not even with the PIN; the flag cannot be
  cleared (to leave secure mode, wipe the profile);
- every presence request needs a physical press ("my device is safe" is
  not available);
- its root key must be bound to the chip before it can be created.

A HARDENED build treats every profile as secure for exports and presence
(nothing can be exported, automatic presence is not available), but it can
restore a backup made on a STANDARD device: that is the only way to bring
existing credentials to it, and an import cannot take keys out. Only
profiles *created* secure are never imported into.

What a secure profile resists depends on the chip's security state, which
`librefido info` and the GUI show as a protection level:

| Level | Chip state | Keys readable by |
|---|---|---|
| 1 | root key bound (HMAC eFuse key) | anyone who can run their own firmware on the chip (no Secure Boot) |
| 2 | + JTAG disabled + secure download mode | anyone who can install unsigned firmware (no Secure Boot) |
| 3 | + Secure Boot V2 + flash encryption (release) + anti-rollback | only physical attacks on the chip (fault injection, side channels, decapping) |

Level 2 steps are done by `librefido provision` (irreversible, typed
confirmation). Level 3 needs a signed bootloader build and your own signing
key: see [ESP32S3_HARDENING.md](ESP32S3_HARDENING.md). A HARDENED build
refuses to open its key store below level 3.

The ESP32-S3 has no protected ECC engine: during a signature an ECC private
key (FIDO, PIV/OpenPGP ECC) is decrypted into internal RAM (never PSRAM) for
the operation and wiped afterwards. The chip is not a secure element and is
not certified; level 3 is the best this hardware offers.

## Presence per application ("my device is safe")

Per profile and per application (FIDO2/U2F, OATH, OTP challenge-response,
OpenPGP, PIV) a presence request can be confirmed automatically instead of
by a press.

- Off by default. Switching it on for any application needs a physical
  press; switching it off does not.
- Never available to secure profiles or HARDENED builds.
- Never applies to operations that destroy, copy or replace keys or change
  security settings: FIDO/OATH/OpenPGP/PIV resets, device key management,
  exports, imports, wipes, firmware updates and rollbacks, the ROM loader,
  profile switches and chip provisioning always need a physical press.
- It is what the name says: any program on the computer can then use the
  keys of that application without you noticing. Use it only on a machine
  you control.

## LED brightness

`librefido board --led-brightness N` (0–255) or the GUI slider. Stored with
the board settings (shared by all profiles), applied at once. Like names and
colours, board settings can be changed 16 times without a press; after that
a change needs a press, which renews the allowance. Restarts do not renew
it. This protects the flash against wear-out by a host program.
