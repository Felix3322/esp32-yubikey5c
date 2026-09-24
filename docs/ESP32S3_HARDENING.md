# ESP32-S3 hardening

**eFuses are one-time programmable. Every step below except reading is
irreversible.** Nothing in LibreFido burns an eFuse during a build, a flash
or a normal boot. The only eFuse write the firmware can do is the root key
binding, and only through `librefido provision bind-root-key --apply` with a
typed confirmation and a touch.

Read the current state first (read only):

```bash
espefuse --port COM6 summary
librefido provision plan
```

## Steps, in a safe order

| # | Step | What is burned | Brick risk |
|---|---|---|---|
| 1 | Bind the root key (`librefido provision bind-root-key`) | HMAC key in BLOCK_KEY5, purpose HMAC_UP, read and write protected | none |
| 2 | Secure Boot V2 | signing key digest (BLOCK_KEY0..2), SECURE_BOOT_EN | **high** |
| 3 | Flash encryption, release mode | XTS-AES key block, SPI_BOOT_CRYPT_CNT, download-mode encryption disabled | **high** |
| 4 | JTAG off | DIS_PAD_JTAG, DIS_USB_JTAG | low |
| 5 | Secure download mode | ENABLE_SECURITY_DOWNLOAD | medium |
| 6 | Anti-rollback | SECURE_VERSION bits (as versions are confirmed) | medium |

Steps 2 to 6 are configured through the ESP-IDF bootloader (menuconfig:
*Security features*) and a signed build; the provisioning tool only lists
them. Follow the ESP-IDF documentation for your IDF version and do them on a
board you can afford to lose first.

## Before step 2: bind every profile

Step 1 re-wraps the root key of the active profile; every other profile is
re-wrapped the next time it is mounted. Once Secure Boot is on, a root key
still stored unbound is no longer re-wrapped automatically (anyone who could
write the flash could have planted it): that profile's key store stays locked
until the binding command (`PROVISION_HMAC`, touch) is sent again while it is
active, followed by a restart. The same holds for a profile without any root
key (one migrated from a store that had none): the binding records that it
has none. So select every profile once between step 1 and step 2.

A held profile is not exported (its root key would be missing from the
backup): bind it and restart first. A profile whose root key was once bound
and is now found in plain or missing, and a secure profile in the same
state, stay locked for good (the record was planted or removed): wipe the
profile or restore it from a backup.

Until step 1, and until flash encryption (step 3), a profile's root key lies
in flash without protection: a flash dump reveals it. Binding (step 1)
protects the root key; flash encryption protects everything else stored
(OATH and OTP secrets, staged backups).

Secure profiles (created with the key bound, never exported) need step 1
first: their root key is wrapped with the HMAC key from the moment it is
made. If that key cannot be used when such a profile is first started, its
root key is not made and the profile stays locked; it is never stored in
plain.

## Steps 4 and 5 from the device

`PROVISION` with P2 02 (touch) burns DIS_PAD_JTAG, DIS_USB_JTAG and
ENABLE_SECURITY_DOWNLOAD and reads them back. Irreversible: JTAG is gone
for good, and the ROM loader then only takes writes (`esptool --no-stub`),
never reads, so flash backups over USB are no longer possible. Recovery
flashing of the application still works. The firmware never does this on
its own.

## Before step 3: the partition table

Flash encryption only covers partitions flagged `encrypted`. The key storage
partitions (`part0`, `lfsys`, `lfstage`, `lfr0`..`lfr4`) carry that flag in
`config/esp32/partitions_librefido_16mb.csv`; while flash encryption is off,
ESP-IDF ignores it. Devices flashed with an older table lack it, and a normal
update (OTA or `app-flash`) does not rewrite the table. So, before step 3:

1. Export every profile (`librefido export`; a HARDENED build cannot, so
   take this step before installing one) and keep the files. `librefido
   info` must show every profile's root key as bound (or none) after a
   restart: a held profile refuses the export.
2. Write the current partition table (`idf.py partition-table-flash`, or
   `esptool write_flash 0x8000 partition-table.bin`). Offsets and sizes are
   unchanged, so no data moves.
3. Check that the device still boots normally (`librefido info`).

At the first boot with flash encryption the bootloader encrypts the app and
every flagged partition in place (about 8 MB: this takes minutes). **Do not
cut the power during that boot**: an interrupted in-place encryption leaves
the partitions partly encrypted, and only the backups bring the keys back.

A device whose flash encryption was enabled without the flags refuses to use
its key storage (safe mode, "partition table lacks the LibreFido 2 regions or
their 'encrypted' flag") instead of reading plain data through the decrypting
flash cache as garbage. In release mode its table can no longer be rewritten.

## Brick-risk boundaries

- **Before step 2**: anything can be undone by flashing over USB (hold BOOT
  while plugging in, or `librefido reboot --bootloader`). Step 1 consumes a
  key block but never prevents booting.
- **After step 2 (Secure Boot)**: only images signed with your key boot.
  *Losing the signing key = no firmware can ever be installed again.* A
  bootloader signed with the wrong key does not boot at all.
- **After step 3 in release mode**: the ROM loader no longer writes
  plaintext, so USB recovery flashing is gone. Only OTA updates (with
  rollback) remain. *If both firmware slots become unbootable, the device
  cannot be recovered.* Keep the rollback slot healthy: confirm an update
  only when it works.
- **After step 5**: the ROM loader refuses flash reads and stub loading
  (`esptool --no-stub` for writes only); flash backups over USB are no longer
  possible. Before step 3 in release mode, writes still work.
- **Step 6** makes any image with a lower secure version unbootable.

## What the firmware checks

`librefido info` reports what the chip says: Secure Boot, flash encryption
(and release mode), JTAG, restricted download mode, anti-rollback, HMAC key,
root key source. A HARDENED build keeps the key store locked until all of
them are set and the root key is bound; a STANDARD build reports them only.

## Recovery

- USB download mode: hold BOOT while connecting, or
  `librefido reboot --bootloader`. After the firmware has taken over USB
  (TinyUSB), the ROM comes up on the USB-OTG download port (on Windows a new
  COM port, e.g. COM7): use `esptool --before no-reset --after
  watchdog-reset`.
- Recovery flashing writes the application only (`ota_0` at 0x10000) and
  erases `otadata`; it never touches the key storage partitions
  (0x4F0000 and above). Never use `erase-flash` on a device with keys you
  want to keep.
- Rewriting the partition table (0x8000) keeps the key storage as long as
  offsets and sizes stay the same; the `encrypted` flag only matters once
  flash encryption is on (see *Before step 3*).
