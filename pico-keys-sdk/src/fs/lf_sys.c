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

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "pico_keys.h"
#include "crypto_utils.h"
#include "rs.h"
#include "lf_sys.h"

#define LF_SYS_MAGIC        0x5953464CU     /* "LFSY" */
#define LF_SYS_VERSION      LF_SYS_FORMAT_VERSION
#define LF_SYS_SLOTS        8
#define LF_SYS_PARITY       RS_PARITY_LEN(sizeof(lf_sys_t))
#define LF_SYS_IMAGE        (sizeof(lf_sys_t) + LF_SYS_PARITY)
/* Programmed length: flash encryption writes whole 16-byte blocks (the
 * padding is 0xFF, what an erased sector holds there anyway). */
#define LF_SYS_WRITE        ((LF_SYS_IMAGE + LF_WRITE_ALIGN - 1) & ~(size_t) (LF_WRITE_ALIGN - 1))
#define LF_SYS_TAIL         8
/* Completion mark: its own write after the image, so a copy carries it only
 * if the image was programmed completely (LF_SYS_F_MARKED). */
#define LF_SYS_MARK_OFF     LF_SYS_WRITE
#define LF_SYS_MARK_LEN     16

static const uint8_t sys_mark[LF_SYS_MARK_LEN] = "LFSY complete v1";

_Static_assert(LF_SYS_MARK_OFF + LF_SYS_MARK_LEN <= LF_SECTOR_SIZE, "system record must fit a sector");
_Static_assert(LF_SYS_PARITY >= LF_SYS_TAIL, "the tail check needs parity bytes");

static lf_sys_t sys_rec;
static lf_region_t sys_reg;
static uint8_t bad_copies = 0;
static bool writable = false;       /* sys_rec was loaded or built by the boot */

static uint32_t slot_off(uint8_t slot, uint8_t copy) {
    return (uint32_t) (slot * 2 + copy) * LF_SECTOR_SIZE;
}

static bool rec_valid(const lf_sys_t *r) {
    return r->magic == LF_SYS_MAGIC && r->version == LF_SYS_VERSION && r->size == sizeof(lf_sys_t) &&
           crc32c((const uint8_t *) r, offsetof(lf_sys_t, crc)) == r->crc;
}

/* Reads one copy; bit errors are corrected with its Reed-Solomon parity. */
static bool read_copy(uint32_t off, lf_sys_t *out) {
    uint8_t img[LF_SYS_IMAGE];
    if (lf_region_read(&sys_reg, off, img, sizeof(img)) != PICOKEY_OK) {
        return false;
    }
    memcpy(out, img, sizeof(*out));
    if (rec_valid(out)) {
        return true;
    }
    if (rs_decode(img, sizeof(lf_sys_t), img + sizeof(lf_sys_t)) < 0) {
        return false;
    }
    memcpy(out, img, sizeof(*out));
    return rec_valid(out);
}

/* A copy that does not verify and was never completely programmed.
 *  - Carries the completion mark: it was complete once (damaged since).
 *  - Written by marking firmware (flag set, or still erased where the flags
 *    byte is), without the mark: the image write never finished, wherever
 *    it was cut, also inside its last block.
 *  - Written by earlier firmware (flag clear): the image ends with its parity,
 *    written last, so an interrupted write or erase leaves those bytes erased.
 * Blank sectors the bootloader encrypted in place read erased when
 * decrypted, so they count as never programmed too. */
static bool copy_incomplete(uint32_t off) {
    uint8_t mark[LF_SYS_MARK_LEN], flags = 0;
    if (lf_region_read(&sys_reg, off + LF_SYS_MARK_OFF, mark, sizeof(mark)) == PICOKEY_OK &&
        memcmp(mark, sys_mark, sizeof(mark)) == 0) {
        return false;
    }
    if (lf_region_read(&sys_reg, off + offsetof(lf_sys_t, flags), &flags, 1) == PICOKEY_OK &&
        (flags & LF_SYS_F_MARKED)) {
        return true;
    }
    return lf_region_erased(&sys_reg, off + LF_SYS_IMAGE - LF_SYS_TAIL, LF_SYS_TAIL);
}

lf_sys_status_t lf_sys_load(void) {
    if (!lf_region_open(&sys_reg, LF_REG_SYS) || sys_reg.size < 2 * LF_SYS_SLOTS * LF_SECTOR_SIZE) {
        return LF_SYS_NO_REGION;
    }
    bool damaged = false, found = false;
    lf_sys_t cand;
    uint8_t twins = 0;
    bad_copies = 0;
    writable = false;
    memset(&sys_rec, 0, sizeof(sys_rec));
    for (uint8_t slot = 0; slot < LF_SYS_SLOTS; slot++) {
        for (uint8_t copy = 0; copy < 2; copy++) {
            uint32_t off = slot_off(slot, copy);
            if (lf_region_blank(&sys_reg, off, 64)) {
                continue;
            }
            if (!read_copy(off, &cand)) {
                bad_copies++;
                /* A complete record that no longer verifies was committed
                 * once; an incomplete one never was. */
                damaged |= !copy_incomplete(off);
                continue;
            }
            if (!found || cand.gen > sys_rec.gen) {
                sys_rec = cand;
                found = true;
                twins = 1;
            }
            else if (cand.gen == sys_rec.gen) {
                twins++;
            }
        }
    }
    if (!found) {
        /* Only incomplete copies (the very first commit was interrupted, or
         * the bootloader encrypted the blank area in place): no generation
         * was ever acknowledged, so this is still a first boot. A damaged
         * complete record means profiles existed: never treat it as blank.
         * (A damaged copy of a marked record whose mark is also gone would
         * count as incomplete: two independent damages in every copy.) */
        return damaged ? LF_SYS_CORRUPT : LF_SYS_BLANK;
    }
    if (twins < 2) {
        /* The newest generation lost a copy: the next commit writes two fresh ones. */
        bad_copies++;
    }
    writable = true;
    return LF_SYS_OK;
}

void lf_sys_block(void) {
    writable = false;
}

lf_sys_t *lf_sys(void) {
    return &sys_rec;
}

uint8_t lf_sys_bad_copies(void) {
    return bad_copies;
}

void lf_sys_default_color(uint8_t idx, uint8_t rgb[3]) {
    static const uint8_t colors[LF_MAX_PROFILES][3] = {
        { 0x00, 0xC0, 0x00 },   /* green */
        { 0x00, 0x40, 0xFF },   /* blue */
        { 0xC0, 0x00, 0xC0 },   /* magenta */
        { 0x00, 0xC0, 0xC0 },   /* cyan */
    };
    memcpy(rgb, colors[idx % LF_MAX_PROFILES], 3);
}

void lf_sys_defaults(void) {
    uint64_t gen = sys_rec.gen;
    memset(&sys_rec, 0, sizeof(sys_rec));
    sys_rec.gen = gen;
    sys_rec.button_slots = 2;
    for (uint8_t i = 0; i < LF_MAX_PROFILES; i++) {
        lf_sys_default_color(i, sys_rec.profile[i].color);
        snprintf(sys_rec.profile[i].name, LF_PROFILE_NAME_MAX, "Profile %u", (unsigned) (i + 1));
    }
    writable = true;
}

int lf_sys_commit(void) {
    if (!sys_reg.present) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    if (!writable) {
        /* Not the record of this device (unreadable area, failed
         * migration): writing it would drop every profile. */
        return PICOKEY_ERR_BLOCKED;
    }
    lf_sys_t rec = sys_rec;
    rec.magic = LF_SYS_MAGIC;
    rec.version = LF_SYS_VERSION;
    rec.size = sizeof(lf_sys_t);
    rec.gen = sys_rec.gen + 1;
    rec.flags |= LF_SYS_F_MARKED;
    rec.crc = crc32c((const uint8_t *) &rec, offsetof(lf_sys_t, crc));

    uint8_t img[LF_SYS_WRITE], chk[LF_SYS_IMAGE], mark[LF_SYS_MARK_LEN];
    memset(img, 0xFF, sizeof(img));
    memcpy(img, &rec, sizeof(rec));
    rs_encode(img, sizeof(rec), img + sizeof(rec));

    /* Slot gen % 8 holds generation gen - 8, never the current one. Each
     * copy: image, then the completion mark once the image is in place. */
    uint8_t slot = (uint8_t) (rec.gen % LF_SYS_SLOTS);
    int good = 0;
    for (uint8_t copy = 0; copy < 2; copy++) {
        uint32_t off = slot_off(slot, copy);
        for (int attempt = 0; attempt < 2; attempt++) {
            if (lf_region_erase(&sys_reg, off, LF_SECTOR_SIZE) == PICOKEY_OK &&
                lf_region_write(&sys_reg, off, img, sizeof(img)) == PICOKEY_OK &&
                lf_region_write(&sys_reg, off + LF_SYS_MARK_OFF, sys_mark, sizeof(sys_mark)) == PICOKEY_OK &&
                lf_region_read(&sys_reg, off, chk, sizeof(chk)) == PICOKEY_OK &&
                memcmp(img, chk, sizeof(chk)) == 0 &&
                lf_region_read(&sys_reg, off + LF_SYS_MARK_OFF, mark, sizeof(mark)) == PICOKEY_OK &&
                memcmp(mark, sys_mark, sizeof(mark)) == 0) {
                good++;
                break;
            }
        }
    }
    if (good == 0) {
        printf("[lf_sys] ERROR: system record generation %u could not be written\n", (unsigned) rec.gen);
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    sys_rec = rec;
    bad_copies = good == 2 ? 0 : 1;
    return PICOKEY_OK;
}
