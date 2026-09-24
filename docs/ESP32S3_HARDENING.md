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
