/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Firmware update with A/B application slots and rollback.
 *
 * An update is written to the slot that is not running, checked (SHA-256 of
 * the whole image as announced by the host, image validity and signature via
 * the bootloader rules, the LibreFido descriptor inside the image) and then
 * selected for the next boot. The new image boots unconfirmed: unless it is
 * confirmed (the host tools do that once they can talk to it), the next
 * reset goes back to the previous image. Key storage lives in its own
 * partitions and is never written by an update, so a failed or interrupted
 * update cannot take credentials with it.
 *
 * ESP32: esp_ota_* with CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE.
 * Emulator: the image is an executable stored next to the flash file; a
 * small "bootloader" at the start of main() mirrors the ESP-IDF rules
 * (new -> pending verify -> valid, or aborted and rolled back).
 */

#ifndef _LF_FW_H_
#define _LF_FW_H_

#include <stdbool.h>
#include <stdint.h>

#define LF_FW_VERSION_MAJOR     2
#define LF_FW_VERSION_MINOR     1
#define LF_FW_VERSION_PATCH     0

#define LF_FW_PLATFORM_ESP32S3      0x01
#define LF_FW_PLATFORM_EMULATION    0x7F

#define LF_FW_DESC_VERSION      1

/* Format of what the profile stores hold (the descriptor's store_version):
 * the store layout (LF_STORE_FORMAT_VERSION) and the records the
 * applications write into it. Raised whenever either changes.
 *   1  LibreFido 2.0.0
 *   2  2.0.1: the applications seal their records (FIDO device key, PIV,
 *      OpenPGP EF_DEK, OATH, OTP) once the firmware is confirmed
 *      (lf_migrate_ok()); firmware of format 1 cannot read them.
 *      2.1.0 keeps format 2. It adds one kind of record, the explicit-key
 *      FIDO credential of a single-key import (lf_keyio.h), written only
 *      when the user imports one, and changes no existing record. 2.0.1
 *      cannot use those credentials; raising the format would forbid going
 *      back to it on every device for them. Backup streams, which a restore
 *      could carry to 2.0.1, do need 2.1.0 (LFBK_MIN_FW_*).
 * LF_FW_STORE_FORMAT_MIN is the oldest format this firmware opens (it
 * migrates such records after its confirmation). */
#define LF_FW_STORE_FORMAT      2
#define LF_FW_STORE_FORMAT_MIN  1

/* Descriptor embedded in every image and located by its magic followed by
 * the magic's bitwise complement. The host tools read it from image files. */
typedef struct __attribute__((packed)) {
    uint8_t magic[8];           /* "LFFWDSC1" */
    uint8_t magic_inv[8];       /* ~magic */
    uint8_t desc_version;
    uint8_t platform;
    uint8_t build_profile;      /* LF_PROFILE_ID */
    uint8_t version[3];
    uint8_t store_version;      /* storage formats this image writes */
    uint8_t store_version_min;  /* oldest it can open */
    uint8_t sys_version;
    uint8_t sys_version_min;
    char board[16];
    uint8_t reserved[4];
} lf_fw_desc_t;

extern const lf_fw_desc_t lf_fw_desc;

typedef struct {
    uint8_t slot;               /* running slot: 0, 1, or LF_FW_SLOT_FACTORY */
    bool pending;               /* running unconfirmed: a reset rolls back */
    bool rollback_possible;     /* the other slot holds a bootable image */
} lf_fw_status_t;

#define LF_FW_SLOT_FACTORY      0xFF

#define LF_FW_PROFILE_HARDENED      2       /* build_profile of HARDENED images */

/* lf_fw_check_policy(): a HARDENED image for a chip that does not have
 * what HARDENED requires (Secure Boot, flash encryption in release mode,
 * JTAG disabled, download restricted, no readable legacy key). */
#define LF_FW_ERR_CHIP_NOT_HARDENED (-1100)
/* lf_fw_check_policy() / lf_fw_check_recovery(): an image that cannot read
 * the storage format in use (records the confirmed firmware already wrote
 * in a newer format would become unusable). */
#define LF_FW_ERR_OLDER_FORMAT      (-1101)

/* Update session. lf_fw_begin() discards any previous one. The upload goes
 * to the slot a rollback would boot: from the first byte on that slot is no
 * rollback target any more, until the new image is activated. */
extern int lf_fw_begin(uint32_t size, const uint8_t sha256[32]);
extern int lf_fw_write(uint32_t offset, const uint8_t *data, uint16_t len);
/* Completes the upload and checks the image; fills the new descriptor. */
extern int lf_fw_finish(lf_fw_desc_t *desc);
/* Policy checks against the running firmware (PICOKEY_ERR_* codes). */
extern int lf_fw_check_policy(const lf_fw_desc_t *desc, bool allow_downgrade);
/* Only what any image must satisfy to run on this device: platform and the
 * storage formats in use. The store format in use is that of the running
 * firmware once it is confirmed; before, the applications have migrated
 * nothing yet, and the oldest format it opens counts (so going back from an
 * unconfirmed firmware always works). */
extern int lf_fw_check_recovery(const lf_fw_desc_t *desc);
/* Secure Boot is on: the bootloader only runs signed images. */
extern bool lf_fw_images_signed(void);
/* Boots the finished image at the next reset. */
extern int lf_fw_activate(void);
extern void lf_fw_abort(void);
extern bool lf_fw_active(void);

extern void lf_fw_status(lf_fw_status_t *st);
/* Marks the running image valid (no rollback at the next reset). */
extern int lf_fw_confirm(void);
/* True while the running image is unconfirmed or on its way out (rollback
 * requested / new image activated): records must not be migrated to a newer
 * format then. Cheap (otadata only), safe from any task. */
extern bool lf_fw_migration_blocked(void);
/* Descriptor of the image a rollback would boot (for lf_fw_check_policy). */
extern int lf_fw_rollback_desc(lf_fw_desc_t *desc);
/* Goes back to the previous image at the next boot, for good: the running
 * one is marked invalid and the previous one boots in the state it had
 * (the caller restarts). */
extern int lf_fw_rollback(void);

#if !defined(ESP_PLATFORM)
/* Emulator bootloader: chooses the image to run and exec()s it if needed. */
extern void lf_fw_emu_boot(void);
#endif

#endif
