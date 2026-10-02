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
 * Storage bring-up at boot: system area, one-time migration of a legacy
 * store, pending imports / wipes, then mounting the active profile.
 *
 * Nothing here ever destroys data it could not first copy and verify. When
 * something cannot be done safely the device boots into safe mode: only the
 * management applet runs and reports the reason; no store is modified.
 */

#ifndef _LF_BOOT_H_
#define _LF_BOOT_H_

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    LF_BOOT_OK = 0,
    LF_BOOT_ERR_LAYOUT,         /* partition table without the LibreFido 2 regions */
    LF_BOOT_ERR_SYS,            /* system area written but unreadable */
    LF_BOOT_ERR_MIGRATION,      /* legacy store could not be migrated (left untouched) */
    LF_BOOT_ERR_MOUNT,          /* active profile store cannot be mounted */
} lf_boot_status_t;

/* Results of boot-time operations, kept in lf_sys()->last_result. */
enum {
    LF_RESULT_NONE = 0,
    LF_RESULT_MIGRATED,         /* legacy store copied into profile 1 */
    LF_RESULT_IMPORTED,
    LF_RESULT_IMPORT_FAILED,    /* target profile left as it was */
    LF_RESULT_WIPED,
    LF_RESULT_DELETED,
    LF_RESULT_OP_FAILED,
    LF_RESULT_VERIFIED,         /* staged backup restored and read back identically */
    LF_RESULT_VERIFY_FAILED,
    LF_RESULT_CREATED,          /* empty profile made in an unused slot */
};

extern lf_boot_status_t lf_storage_boot(void);
extern lf_boot_status_t lf_boot_status(void);
extern const char *lf_boot_status_str(lf_boot_status_t s);
/* True once a profile store is mounted read-write. */
extern bool lf_storage_ready(void);

/* Index of the active profile (0..LF_MAX_PROFILES-1): the one mounted at
 * boot, or, once a switch was requested, the one the next boot mounts.
 * Code that needs the mounted profile uses lf_profile_mounted(). */
extern uint8_t lf_active_profile(void);

/* Reboots the device (the emulator re-executes itself). */
extern void lf_reboot(void);

/* The mounted profile's system area entry, for the root key (security.c):
 * its LF_PROFILE_F_* flags, and whether its root was seen bound to the chip
 * (recorded once, with a system area commit, and only by confirmed firmware:
 * lf_migrate_ok()). 0 / false without a store. */
extern uint8_t lf_boot_profile_flags(void);
extern bool lf_boot_root_bound(void);
extern void lf_boot_note_root_bound(void);

/* Identity of the mounted profile (EF_PROFILE_ID). lf_identity_apply()
 * creates it on first mount and makes pico_serial present it. */
extern int lf_identity_write(const uint8_t uuid[16], const uint8_t serial[8]);
extern bool lf_identity_read(uint8_t uuid[16], uint8_t serial[8]);
extern void lf_identity_apply(void);

#endif
