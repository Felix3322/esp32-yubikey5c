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
 * Flash regions of the resilient store (ESP32 partitions, or windows of the
 * emulator's flash file with the same roles):
 *
 *   LF_REG_LEGACY   store of firmware before LibreFido 2 ("part0"), read only,
 *                   migrated once and then left untouched
 *   LF_REG_SYS      system area: profile table, board config (lf_sys.c)
 *   LF_REG_STAGE    staging area for imports, exports and migration
 *   LF_REG_STORE(n) profile stores (lf_store.c); one more than profiles, so an
 *                   import or wipe is built on a spare region and switched in
 *                   atomically
 *
 * Offsets are relative to the region. Writes and erases never leave the region.
 *
 * Flash encryption: the partitions carry the "encrypted" flag. While flash
 * encryption is off ESP-IDF ignores it, so reads, writes and the memory map
 * all see plain data. Once it is on, writes are encrypted, reads and the map
 * decrypt, and every write must be 16-byte aligned with a length that is a
 * multiple of 16 (enforced on every platform so the emulator catches it).
 * Erased flash only reads as 0xFF through the raw path, and sectors the
 * bootloader encrypted in place while blank only read as 0xFF through the
 * decrypting path: lf_region_erased() accepts both.
 */

#ifndef _LF_REGION_H_
#define _LF_REGION_H_

#include <stdbool.h>
#include <stdint.h>

#define LF_SECTOR_SIZE      4096
#define LF_WRITE_ALIGN      16      /* flash encryption block */
#define LF_MAX_PROFILES     4
#define LF_STORE_REGIONS    (LF_MAX_PROFILES + 1)

enum {
    LF_REG_LEGACY = 0,
    LF_REG_SYS,
    LF_REG_STAGE,
    LF_REG_STORE0,
    LF_REG_COUNT = LF_REG_STORE0 + LF_STORE_REGIONS
};
#define LF_REG_STORE(n)     ((uint8_t) (LF_REG_STORE0 + (n)))

typedef struct {
    uint8_t id;
    bool present;
    uint32_t size;
    const uint8_t *map;         /* read view, see lf_region_map() */
#if defined(ESP_PLATFORM)
    const void *part;           /* const esp_partition_t * */
    uint32_t mmap_handle;
#else
    uint32_t offset;            /* offset in the emulator flash file */
#endif
} lf_region_t;

/* Locates a region. Returns false if the partition table has no such region. */
extern bool lf_region_open(lf_region_t *r, uint8_t id);

/* False if flash encryption is enabled but the partition lacks the
 * "encrypted" flag: the memory map would then decrypt plain data into
 * garbage, so such a region must not be used at all. */
extern bool lf_region_crypt_ok(const lf_region_t *r);

extern int lf_region_erase(lf_region_t *r, uint32_t off, uint32_t len);
/* off and len must be multiples of LF_WRITE_ALIGN. */
extern int lf_region_write(lf_region_t *r, uint32_t off, const void *src, uint32_t len);
/* Logical read (decrypted under ESP32 flash encryption). */
extern int lf_region_read(const lf_region_t *r, uint32_t off, void *dst, uint32_t len);
/* Raw read (ciphertext under flash encryption), for blank checks. */
extern int lf_region_read_raw(const lf_region_t *r, uint32_t off, void *dst, uint32_t len);
/* True if every byte in the range is erased (raw check: only this says the
 * range can be programmed without an erase). */
extern bool lf_region_blank(const lf_region_t *r, uint32_t off, uint32_t len);
/* True if the range holds nothing: erased, or reading 0xFF when decrypted
 * (blank sectors the bootloader encrypted in place). */
extern bool lf_region_erased(const lf_region_t *r, uint32_t off, uint32_t len);

/* Memory mapped view of the whole region, for the file system's direct
 * pointers. lf_region_refresh() must be called after writes so the view
 * reflects them (the mapping address may change). lf_region_unmap() releases
 * the view (one mapping per region at a time). */
extern const uint8_t *lf_region_map(lf_region_t *r);
extern void lf_region_refresh(lf_region_t *r);
extern void lf_region_unmap(lf_region_t *r);

#if defined(ENABLE_EMULATION)
/* Emulator only: flushes the flash file and, when LF_FAULT_OPS=N is set,
 * tears the N-th erase/write and terminates the process (power-loss tests).
 * LF_FAULT_CTL names a control file for one boot: "tear <region> <n>" (the
 * n-th operation on that region) or "fail <region> [<sector> <count>]"
 * (erases and writes there fail, as on worn-out flash). */
extern void lf_region_emu_sync(void);
#endif

#endif
