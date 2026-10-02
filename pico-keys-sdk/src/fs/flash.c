/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
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


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pico_keys.h"
#include "mbedtls/platform_util.h"

#if !defined(PICO_PLATFORM)
#define XIP_BASE                0
#define FLASH_SECTOR_SIZE       4096
#ifdef ESP_PLATFORM
uint32_t FLASH_SIZE_BYTES = (1 * 1024 * 1024);
#else
#define FLASH_SIZE_BYTES   (8 * 1024 * 1024)
#endif
#else
uint32_t FLASH_SIZE_BYTES = (2 * 1024 * 1024);
#include "pico/stdlib.h"
#include "hardware/flash.h"
#endif
#include "file.h"
#include "low_flash.h"
#include <stdio.h>

/*
 * ------------------------------------------------------
 * |                                                    |
 * | next_addr | prev_addr | fid | data (len + payload) |
 * |                                                    |
 * ------------------------------------------------------
 *
 * Records form two lists (persistent and data pool), each from a list head
 * downwards: every record lies below the one linking to it. A pointer that
 * leaves its pool or does not go down is damage and ends the list.
 *
 * A record's payload never crosses a sector boundary, so a pointer into it
 * stays valid (the cache and the store work on whole sectors). Records the
 * applications create hold at most FLASH_MAX_PAYLOAD bytes and fit a sector
 * with their header. Earlier firmware stored payloads of up to a whole
 * sector, ending at a sector boundary with only the header in the sector
 * below: those stay readable, rewritable in place and deletable (header
 * fields are written per sector and read byte by byte), and data carried from
 * them (migration, backups: flash_allow_sector_records()) may create records
 * of that size. A stored length that would take the payload past the end of
 * its sector is damage (a length write lost to earlier firmware) and is cut
 * there before anything acts on it.
 *
 * Crash consistency. Each list operation (create, rewrite, delete) declares
 * the sectors it writes to the cache first (low_flash_reserve), so a full
 * cache is committed before the operation and never in the middle of it:
 * every commit, and thus every state a power cut can leave, holds whole
 * operations only. Within an operation a new record is written completely
 * before it is linked, and the record it replaces is unlinked afterwards.
 * The prev pointers are maintained for older firmware but never trusted:
 * the predecessor of a record is looked up from its list head.
 */

#define FLASH_DATA_HEADER_SIZE (sizeof(uintptr_t) + sizeof(uint32_t))
#define FLASH_PERMANENT_REGION (4 * FLASH_SECTOR_SIZE) // 4 sectors (16kb) of permanent memory

#define FLASH_RECORD_HEADER    (2 * sizeof(uintptr_t) + 2 * sizeof(uint16_t))
#define FLASH_MAX_PAYLOAD      (FLASH_SECTOR_SIZE - FLASH_RECORD_HEADER)
#define REC_NEXT(a)            (a)
#define REC_PREV(a)            ((a) + sizeof(uintptr_t))
#define REC_FID(a)             ((a) + 2 * sizeof(uintptr_t))
#define REC_LEN(a)             ((a) + 2 * sizeof(uintptr_t) + sizeof(uint16_t))
#define REC_DATA(a)            ((a) + FLASH_RECORD_HEADER)
#define LIST_GUARD             65536

//To avoid possible future allocations, data region starts at the end of flash and goes upwards to the center region
uintptr_t end_flash, end_rom_pool, start_rom_pool, end_data_pool, start_data_pool;

extern int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len);
extern int flash_program_halfword(uintptr_t addr, uint16_t data);
extern int flash_program_uintptr(uintptr_t, uintptr_t);
extern uintptr_t flash_read_uintptr(uintptr_t addr);
extern uint16_t flash_read_uint16(uintptr_t addr);
extern uint8_t *flash_read(uintptr_t addr);

extern void low_flash_available();

#if !defined(ESP_PLATFORM) && !defined(ENABLE_EMULATION)
/* RP2 builds (low_flash.c) have no bounded sector cache to reserve. */
int low_flash_reserve(const uintptr_t *addrs, int n) {
    (void) addrs;
    (void) n;
    return PICOKEY_OK;
}
void low_flash_op_begin(void) {
}
void low_flash_op_end(void) {
}
/* No transaction can be abandoned there: the caller keeps its own rollback. */
int low_flash_txn_abort(void) {
    return PICOKEY_ERR_BLOCKED;
}
#endif

uintptr_t last_base;
uint32_t num_files = 0;
static bool sector_records = false;

void flash_allow_sector_records(bool on) {
    sector_records = on;
}

/* Largest payload a new record may get. */
static uint16_t new_record_max(void) {
    return sector_records ? FLASH_SECTOR_SIZE : FLASH_MAX_PAYLOAD;
}

void flash_set_bounds(uintptr_t start, uintptr_t end) {
    end_flash = end;
    end_rom_pool = end_flash - FLASH_DATA_HEADER_SIZE - 4;
    start_rom_pool = end_rom_pool - FLASH_PERMANENT_REGION;
    end_data_pool = start_rom_pool - FLASH_DATA_HEADER_SIZE;
    start_data_pool = start;

    last_base = end_data_pool;
}

static void pool_bounds(bool persistent, uintptr_t *startp, uintptr_t *endp) {
    *startp = persistent ? start_rom_pool : start_data_pool;
    *endp = persistent ? end_rom_pool : end_data_pool;
}

static bool in_rom_pool(uintptr_t rec) {
    return rec >= start_rom_pool && rec < end_rom_pool;
}

/* Static files without FILE_DATA_FLASH point at constant data instead. */
static bool in_store(uintptr_t rec) {
    return rec >= start_data_pool && rec < end_rom_pool;
}

/* Programs a range that may cross a sector boundary (fields of records
 * written by earlier firmware) as one write per sector. */
static int program(uintptr_t addr, const uint8_t *data, size_t len) {
    while (len > 0) {
        size_t n = FLASH_SECTOR_SIZE - (addr & (FLASH_SECTOR_SIZE - 1));
        if (n > len) {
            n = len;
        }
        int r = flash_program_block(addr, data, n);
        if (r != PICOKEY_OK) {
            return r;
        }
        addr += n;
        data += n;
        len -= n;
    }
    return PICOKEY_OK;
}

static int program_uintptr(uintptr_t addr, uintptr_t v) {
    return program(addr, (const uint8_t *) &v, sizeof(v));
}

static int program_zeros(uintptr_t addr, size_t len) {
    static const uint8_t zeros[64] = { 0 };
    int r = PICOKEY_OK;
    for (size_t o = 0; r == PICOKEY_OK && o < len; o += sizeof(zeros)) {
        r = program(addr + o, zeros, MIN(sizeof(zeros), len - o));
    }
    return r;
}

/* Sectors an operation is going to write. */
typedef struct {
    uintptr_t addr[16];
    int n;
} touched_t;

static void touch(touched_t *t, uintptr_t addr, size_t len) {
    if (addr == 0 || len == 0 || t->n + 2 > (int) (sizeof(t->addr) / sizeof(t->addr[0]))) {
        return;
    }
    t->addr[t->n++] = addr;
    t->addr[t->n++] = addr + len - 1;
}

/* Room for a new record and its neighbours in the list. */
typedef struct {
    uintptr_t addr;         /* the new record */
    uintptr_t prev;         /* record or list head that is to link to it */
    uintptr_t next;         /* record it is to link to, 0 at the end */
} slot_t;

/* The record rec links to, 0 at the end of the list. A pointer that leaves
 * the pool or does not go down (a write lost to earlier firmware) ends the
 * list too: nothing behind it is reachable, the scan stops there as well. */
static uintptr_t rec_next(uintptr_t rec, uintptr_t startp) {
    uintptr_t n = flash_read_uintptr(REC_NEXT(rec));
    return n >= startp && n < rec ? n : 0;
}

/* Payload length of a stored record, never past the end of the sector its
 * payload starts in: no firmware placed a payload across a sector, so a
 * larger value is a lost length write (earlier firmware refused writes that
 * straddle sectors and ignored the error, leaving 0xFFFF). */
static uint16_t stored_len(uintptr_t rec) {
    uint16_t len = flash_read_uint16(REC_LEN(rec));
    size_t room = FLASH_SECTOR_SIZE - (REC_DATA(rec) & (FLASH_SECTOR_SIZE - 1));
    return len > room ? (uint16_t) room : len;
}

/* Finds room for a record with `size` payload bytes. Writes nothing. A
 * payload that does not fit a sector with its header (only records carried
 * from earlier firmware) goes at the end of the list, ending at a sector
 * boundary: its header then lies in the sector below. */
static bool find_slot(uint16_t size, bool persistent, slot_t *s) {
    if (size > FLASH_SECTOR_SIZE) {
        return false;
    }
    size_t real_size = size + FLASH_RECORD_HEADER; //len+len size+next address+fid+prev_addr size
    uintptr_t startp, endp;
    pool_bounds(persistent, &startp, &endp);
    uint32_t guard = 0;
    for (uintptr_t base = endp; base >= startp && ++guard <= LIST_GUARD; ) {
        uintptr_t addr_alg = base & -FLASH_SECTOR_SIZE; //start address of sector
        uintptr_t potential_addr = base - real_size;
        /* a damaged pointer counts as the end: linking the new record there
         * repairs the list */
        uintptr_t next_base = rec_next(base, startp);
        if (next_base == 0x0) { //we are at the end
            //now we check if we fit in the current sector
            if (real_size <= FLASH_SECTOR_SIZE && addr_alg <= potential_addr && potential_addr >= startp) {
                *s = (slot_t) { potential_addr, base, 0 };
                return true;
            }
            //check whether it fits in the next sector, so we take addr_aligned as the base
            if (addr_alg >= startp + MAX(real_size, (size_t) FLASH_SECTOR_SIZE)) {
                *s = (slot_t) { addr_alg - real_size, base, 0 };
                return true;
            }
            return false;
        }
        //we check if the gap between the end of the next record and base holds us, only if fid != 1xxx (not size blocked)
        uintptr_t next_end = REC_DATA(next_base) + stored_len(next_base);
        if (addr_alg <= potential_addr && potential_addr > next_end &&
            (flash_read_uint16(REC_FID(next_base)) & 0x1000) != 0x1000) {
            *s = (slot_t) { potential_addr, base, next_base };
            return true;
        }
        base = next_base;
    }
    return false;
}

/* Kept for callers that only need an address; writes nothing. */
uintptr_t allocate_free_addr(uint16_t size, bool persistent) {
    slot_t s;
    return find_slot(size, persistent, &s) ? s.addr : 0x0;
}

/* The record or list head whose next is rec, looked up from the list head
 * (the stored prev pointer may be stale after earlier firmware). 0 if rec
 * is not in its list. */
static uintptr_t find_prev(uintptr_t rec) {
    uintptr_t startp, endp;
    pool_bounds(in_rom_pool(rec), &startp, &endp);
    uint32_t guard = 0;
    for (uintptr_t p = endp; ++guard <= LIST_GUARD; ) {
        uintptr_t n = rec_next(p, startp);
        if (n == rec && n != 0) {
            return p;
        }
        if (n == 0) {
            return 0;
        }
        p = n;
    }
    return 0;
}

static uintptr_t record_of(const file_t *file) {
    return (uintptr_t) file->data - sizeof(uintptr_t) - sizeof(uint16_t) - sizeof(uintptr_t);
}

/* Next record of rec for an unlink: a damaged pointer becomes the end of
 * the list (it is never copied into the predecessor). */
static uintptr_t unlink_next(uintptr_t rec) {
    uintptr_t startp, endp;
    pool_bounds(in_rom_pool(rec), &startp, &endp);
    return rec_next(rec, startp);
}

static void touch_unlink(touched_t *t, uintptr_t rec) {
    uintptr_t prev = find_prev(rec), next = unlink_next(rec);
    touch(t, prev, sizeof(uintptr_t));
    if (next) {
        touch(t, REC_PREV(next), sizeof(uintptr_t));
    }
    touch(t, rec, FLASH_RECORD_HEADER + stored_len(rec));
}

/* Unlinks a record and scrubs it so deleted secrets do not survive in the
 * sector. Part of an operation: the caller reserved touch_unlink(). */
static int unlink_record(uintptr_t rec) {
    uintptr_t prev = find_prev(rec), next = unlink_next(rec);
    uint16_t old_len = stored_len(rec);
    int r = PICOKEY_OK;
    if (prev) {
        r = program_uintptr(REC_NEXT(prev), next);
        if (r == PICOKEY_OK && next > 0) {
            r = program_uintptr(REC_PREV(next), prev);
        }
    }
    /* Payload, len, next and prev cleared; the fid stays (unreachable). */
    if (r == PICOKEY_OK) {
        r = program_zeros(REC_DATA(rec), old_len);
    }
    if (r == PICOKEY_OK) {
        r = program_zeros(REC_LEN(rec), sizeof(uint16_t));
    }
    if (r == PICOKEY_OK) {
        r = program_zeros(REC_NEXT(rec), 2 * sizeof(uintptr_t));
    }
    return r;
}

int flash_clear_file(file_t *file) {
    if (file == NULL || file->data == NULL) {
        return PICOKEY_OK;
    }
    uintptr_t rec = record_of(file);
    if (!in_store(rec)) {
        file->data = NULL;
        return PICOKEY_OK;
    }
    bool persistent = in_rom_pool(rec);
    touched_t t = { .n = 0 };
    touch_unlink(&t, rec);
    low_flash_op_begin();
    int r = low_flash_reserve(t.addr, t.n);
    if (r == PICOKEY_OK) {
        r = unlink_record(rec);
    }
    low_flash_op_end();
    if (r != PICOKEY_OK) {
        printf("[flash] ERROR: file %04X cannot be deleted (%d)\n", file->fid, r);
        return r;
    }
    file->data = NULL;
    if (!persistent && num_files > 0) {
        num_files--;
    }
    return PICOKEY_OK;
}

/* Writes a complete record into its free slot (not reachable yet). */
static int write_record(const slot_t *s, uint16_t fid, const uint8_t *data, uint16_t len) {
    uint8_t hdr[FLASH_RECORD_HEADER];
    uintptr_t next = s->next, prev = s->prev;
    memcpy(hdr, &next, sizeof(next));
    memcpy(hdr + sizeof(uintptr_t), &prev, sizeof(prev));
    memcpy(hdr + 2 * sizeof(uintptr_t), &fid, sizeof(fid));
    memcpy(hdr + 2 * sizeof(uintptr_t) + sizeof(uint16_t), &len, sizeof(len));
    int r = program(s->addr, hdr, sizeof(hdr));
    if (r == PICOKEY_OK && data && len) {
        r = program(REC_DATA(s->addr), data, len);
    }
    return r;
}

/* Makes the record reachable: the forward link is the single write that
 * adds it to the list. */
static int link_record(const slot_t *s) {
    int r = PICOKEY_OK;
    if (s->next) {
        r = program_uintptr(REC_PREV(s->next), s->addr);
    }
    if (r == PICOKEY_OK) {
        r = program_uintptr(REC_NEXT(s->prev), s->addr);
    }
    return r;
}

int flash_write_data_to_file_offset(file_t *file, const uint8_t *data, uint16_t len, uint16_t offset) {
    if (!file) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    /* The current record, its length bounded by its sector (never a
     * damaged length to zero or reserve by). */
    uintptr_t cur = file->data && in_store(record_of(file)) ? record_of(file) : 0;
    uint16_t size_file_flash = cur ? stored_len(cur) : (file->data ? flash_read_uint16((uintptr_t) file->data) : 0);
    uint32_t want = (uint32_t) offset + len;
    bool relocate = cur == 0 || want > size_file_flash;
    /* In place, a record keeps the size it has (also one of earlier
     * firmware above the limit); a new record respects the limit. */
    if (offset > size_file_flash || want > (relocate ? new_record_max() : size_file_flash)) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    uint16_t total = (uint16_t) want;
    /* The new content, copied before anything is written: the caller's
     * pointer may point into a cached sector that a write can replace. */
    uint8_t *buf = NULL;
    if (total > 0 && (data || relocate)) {
        buf = (uint8_t *) calloc(1, total);
        if (buf == NULL) {
            return PICOKEY_ERR_NO_MEMORY;
        }
        if (offset > 0) {
            memcpy(buf, flash_read((uintptr_t) (file->data + sizeof(uint16_t))), offset);
        }
        if (data) {
            memcpy(buf + offset, data, len);
        }
    }

    int r = PICOKEY_OK;
    touched_t t = { .n = 0 };
    low_flash_op_begin();
    if (!relocate) {
        /* It fits, no need to move it (the length written also repairs a
         * damaged one). */
        uintptr_t rec = cur;
        touch(&t, rec, FLASH_RECORD_HEADER + size_file_flash);
        r = low_flash_reserve(t.addr, t.n);
        if (r == PICOKEY_OK) {
            r = program((uintptr_t) file->data, (const uint8_t *) &total, sizeof(total));
        }
        if (r == PICOKEY_OK && data && len) {
            r = program((uintptr_t) file->data + sizeof(uint16_t) + offset, buf + offset, len);
        }
        if (r == PICOKEY_OK && total < size_file_flash) {
            /* Do not leave the tail of a shrunk record (possibly secret) behind. */
            r = program_zeros((uintptr_t) file->data + sizeof(uint16_t) + total, size_file_flash - total);
        }
    }
    else {
        bool persistent = (file->type & FILE_PERSISTENT) == FILE_PERSISTENT;
        uintptr_t old = cur;
        slot_t s;
        if (!find_slot(total, persistent, &s)) {
            r = PICOKEY_ERR_NO_MEMORY;
        }
        else {
            touch(&t, s.addr, FLASH_RECORD_HEADER + total);
            touch(&t, s.prev, sizeof(uintptr_t));
            if (s.next) {
                touch(&t, REC_PREV(s.next), sizeof(uintptr_t));
            }
            if (old) {
                touch_unlink(&t, old);
            }
            r = low_flash_reserve(t.addr, t.n);
            /* New record complete, then linked, then the old one unlinked:
             * the list holds the old or the new content, never neither. */
            if (r == PICOKEY_OK) {
                r = write_record(&s, file->fid, buf, total);
            }
            if (r == PICOKEY_OK) {
                r = link_record(&s);
            }
            if (r == PICOKEY_OK && old) {
                r = unlink_record(old);
            }
            if (r == PICOKEY_OK) {
                if (!old && !persistent) {
                    num_files++;
                }
                if (s.addr < last_base) {
                    last_base = s.addr;
                }
                file->data = (uint8_t *) REC_LEN(s.addr);
            }
        }
    }
    low_flash_op_end();
    if (buf) {
        mbedtls_platform_zeroize(buf, total);
        free(buf);
    }
    if (r != PICOKEY_OK) {
        printf("[flash] ERROR: file %04X cannot be written (%d)\n", file->fid, r);
    }
    return r;
}

int flash_write_data_to_file(file_t *file, const uint8_t *data, uint16_t len) {
    return flash_write_data_to_file_offset(file, data, len, 0);
}

uint32_t flash_free_space() {
    return (uint32_t)(last_base - start_data_pool);
}

uint32_t flash_used_space() {
    return (uint32_t)(end_data_pool - last_base);
}

uint32_t flash_total_space() {
    return (uint32_t)(end_data_pool - start_data_pool);
}

uint32_t flash_num_files() {
    return num_files;
}

uint32_t flash_size() {
    return FLASH_SIZE_BYTES;
}
