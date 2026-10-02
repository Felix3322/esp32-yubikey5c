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
 * Resilient profile store: the block device under the file system of one
 * profile. A store region holds
 *
 *   header (2 copies) | journal log | journal pool | copy A | copy B |
 *   metadata A | metadata B | counter log (2 rings)
 *
 * The file system sees LF_STORE_LOGICAL_SIZE bytes, served from copy A.
 * Every commit is one atomic transaction: the new sector images and their
 * new metadata (CRC32, generation, erase count, Reed-Solomon parity) are first
 * written to the journal pool and verified, a COMMIT record makes the
 * transaction durable, then copy A, metadata A, copy B and metadata B are
 * rewritten in that order and verified. Nothing live is overwritten before
 * the COMMIT record exists; a power cut is repaired by replaying the journal
 * at the next mount. A copy that cannot be rewritten (worn sector) is
 * bypassed as long as the other copy of the same sector verifies; if neither
 * does, the COMMIT stays open for the next mount and the store refuses
 * further commits until then.
 *
 * Mounting then scrubs every sector: a copy whose CRC does not match its
 * metadata is rebuilt from the other copy, and if both are damaged the
 * Reed-Solomon parity repairs up to 16 bytes per 223 byte block. Results are
 * reported in lf_health_t.
 *
 * Monotonic counters (signature counters) live in an append-only log with two
 * rings instead of the file system, so counting does not wear one sector.
 */

#ifndef _LF_STORE_H_
#define _LF_STORE_H_

#include <stdbool.h>
#include <stdint.h>
#include "lf_region.h"

/* On-flash layout of a profile store; other versions are never guessed. */
#define LF_STORE_FORMAT_VERSION     1

#define LF_STORE_LOGICAL_SECTORS    128
#define LF_STORE_LOGICAL_SIZE       (LF_STORE_LOGICAL_SECTORS * LF_SECTOR_SIZE)
#define LF_STORE_MAX_DIRTY          8       /* sectors per transaction (RAM cache) */

typedef struct {
    uint32_t sectors_checked;
    uint32_t sectors_written;           /* logical sectors holding data */
    uint32_t repaired_from_copy;        /* one copy damaged, rebuilt from the other */
    uint32_t corrected_ecc;             /* both copies damaged, rebuilt with Reed-Solomon */
    uint32_t ecc_bytes_corrected;
    uint32_t uncorrectable;             /* lost sectors */
    uint32_t meta_repaired;             /* metadata entries rebuilt */
    uint32_t served_from_b;             /* sectors whose copy A cannot be rewritten */
    uint32_t journal_replayed;          /* 1 if the last mount replayed a transaction */
    uint32_t journal_corrupt;           /* 1 if a pending transaction could not be replayed */
    uint32_t commit_failures;
    uint32_t max_erase_count;           /* most rewritten logical sector */
    uint32_t total_erase_count;
    uint64_t generation;                /* last committed transaction */
    uint32_t copy_write_failures;       /* copies bypassed because they did not verify */
} lf_health_t;

typedef struct {
    uint32_t lsn;                       /* logical sector */
    const uint8_t *image;               /* LF_SECTOR_SIZE bytes, NULL = erased */
} lf_dirty_t;

/* Formats store region idx (0..LF_STORE_REGIONS-1): everything erased, header
 * written. Destroys its previous content. */
extern int lf_store_format(uint8_t idx, const uint8_t uuid[16]);
/* True if region idx carries a valid store header (uuid copied if not NULL). */
extern bool lf_store_is_formatted(uint8_t idx, uint8_t uuid[16]);
/* True if region idx holds anything of a store: a header, or what an erase
 * that was interrupted by firmware erasing the header first left behind. */
extern bool lf_store_has_content(uint8_t idx);
/* Erases the whole region (wiped or replaced profiles leave no remnants).
 * The header goes last, so an interrupted erase is finished at the next boot. */
extern int lf_store_erase(uint8_t idx);

/* Mounts store region idx for the file system: journal recovery, then scrub.
 * Sets the file system bounds. */
extern int lf_store_mount(uint8_t idx);
/* Read-only mount of the pre-LibreFido-2 store (migration source). Returns
 * PICOKEY_ERR_FILE_NOT_FOUND if there is none, another error if it exists
 * but cannot be read. */
extern int lf_store_mount_legacy(void);
extern void lf_store_unmount(void);
extern bool lf_store_mounted(void);
extern bool lf_store_read_only(void);
extern int lf_store_mounted_region(void);

/* Pointer the file system reads logical address addr through. */
extern uint8_t *lf_store_ptr(uintptr_t addr);
/* Raw blank check of a logical range (flash encryption safe). */
extern bool lf_store_blank(uintptr_t addr, size_t len);
/* Copies one logical sector (as currently stored) into out. */
extern int lf_store_read_sector(uint32_t lsn, uint8_t *out);

/* Atomically persists dirty logical sectors (see file comment). */
extern int lf_store_commit(const lf_dirty_t *dirty, int n);

/* Full verification and repair pass (also run by every mount). */
extern int lf_store_scrub(void);
extern const lf_health_t *lf_store_health(void);

/* Monotonic counters, per store. Values never go down; a set below the
 * current value is ignored. Durable when the call returns. */
#define LF_CTR_MAX_IDS      16
extern int lf_ctr_get(uint8_t id, uint32_t *value);
extern int lf_ctr_set(uint8_t id, uint32_t value);
extern bool lf_ctr_present(uint8_t id);

#endif
