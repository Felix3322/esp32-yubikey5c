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
 * System area: which profiles exist, which store region backs each of them,
 * which one is active, board configuration and pending boot-time operations.
 *
 * Every update writes a complete record with a higher generation to two
 * sectors (twin copies) of a ring of 8 slots, never over the current one.
 * Each copy carries a CRC32 and Reed-Solomon parity, and a completion mark
 * written after it. At boot the newest copy that verifies wins, so a torn
 * update falls back to the previous generation and bit rot in one copy is
 * repaired from its twin; copies that never got their mark (an interrupted
 * very first update) do not make the area look damaged.
 */

#ifndef _LF_SYS_H_
#define _LF_SYS_H_

#include <stdbool.h>
#include <stdint.h>
#include "lf_region.h"

/* Layout of the system area record. */
#define LF_SYS_FORMAT_VERSION   1

#define LF_PROFILE_NAME_MAX     24
#define LF_BOARD_MAX            256

#define LF_PROFILE_F_NO_EXPORT  0x01    /* keys of this profile never leave it */

typedef struct __attribute__((packed)) {
    uint8_t used;
    uint8_t region;                 /* store region index 0..LF_STORE_REGIONS-1 */
    uint8_t color[3];               /* RGB shown while the profile is active */
    uint8_t flags;                  /* LF_PROFILE_F_* */
    uint8_t root_bound[2];          /* its root key was seen wrapped by the chip's
                                     * HMAC key: a tag of uuid (lf_boot.c), so any
                                     * import or wipe, also by older firmware (which
                                     * keeps these bytes, 0 in its records), voids it */
    uint8_t uuid[16];
    char name[LF_PROFILE_NAME_MAX]; /* UTF-8, NUL padded */
} lf_profile_entry_t;

enum {
    LF_OP_NONE = 0,
    LF_OP_IMPORT = 1,               /* build profile pending_profile from the staged blob */
    LF_OP_WIPE = 2,                 /* replace profile pending_profile by an empty one */
    LF_OP_DELETE = 3,               /* remove profile pending_profile */
    LF_OP_VERIFY = 4,               /* restore the staged blob into a scratch region, compare, erase */
};

#define LF_SYS_F_MIGRATED       0x01    /* legacy store copied into profile 0 */
#define LF_SYS_F_MARKED         0x02    /* each copy is followed by a completion mark */

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint64_t gen;
    uint8_t active;
    uint8_t flags;                  /* LF_SYS_F_* */
    uint8_t pending_op;             /* LF_OP_* */
    uint8_t pending_profile;
    uint8_t last_result;            /* outcome of the last boot-time operation */
    uint8_t button_slots;           /* profiles the long press cycles through (1..4) */
    uint8_t pending_tries;          /* boots that started pending_op (0 in older records) */
    uint8_t rfu;
    lf_profile_entry_t profile[LF_MAX_PROFILES];
    uint16_t board_len;
    uint8_t board[LF_BOARD_MAX];    /* PHY/board configuration (phy.c TLV) */
    uint32_t repairs;               /* cumulative repaired sectors (all stores) */
    uint32_t uncorrectable;         /* cumulative sectors that could not be repaired */
    uint8_t pending_flags;          /* LF_PENDING_F_SET | the LF_PROFILE_F_* a pending
                                     * WIPE gives the slot once it succeeded (0 in
                                     * older records: the slot keeps its own) */
    uint8_t rfu2[15];
    uint32_t crc;
} lf_sys_t;

#define LF_PENDING_F_SET        0x80

typedef enum {
    LF_SYS_OK = 0,
    LF_SYS_BLANK,                   /* never written (at most an interrupted first
                                     * commit): first boot of this layout */
    LF_SYS_CORRUPT,                 /* a complete record was written, but no copy verifies */
    LF_SYS_NO_REGION,               /* partition missing */
} lf_sys_status_t;

extern lf_sys_status_t lf_sys_load(void);
extern lf_sys_t *lf_sys(void);
/* Fresh record (no profiles, generation continues from the loaded one). */
extern void lf_sys_defaults(void);
/* Writes the RAM record as the next generation and verifies both copies.
 * Refused (PICOKEY_ERR_BLOCKED) unless the RAM record is the one loaded from
 * flash or the one the boot built from lf_sys_defaults(): a record that was
 * not loaded (unreadable area) holds no profiles, and writing it would make
 * the next boot erase every store as unreferenced. */
extern int lf_sys_commit(void);
/* Refuses every further commit of this boot (e.g. after a failed migration:
 * the area must stay blank so the next boot migrates again). */
extern void lf_sys_block(void);
/* Copies that failed verification at load (repaired by the next commit). */
extern uint8_t lf_sys_bad_copies(void);

/* Default LED colour of profile slot i. */
extern void lf_sys_default_color(uint8_t idx, uint8_t rgb[3]);

#endif
