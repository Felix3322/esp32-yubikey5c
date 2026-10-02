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

/* Resilient profile store, see lf_store.h for the design. */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pico_keys.h"
#include "crypto_utils.h"
#include "rs.h"
#include "lf_store.h"

#if defined(ESP_PLATFORM)
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#else
#include <pthread.h>
#endif

extern void flash_set_bounds(uintptr_t start, uintptr_t end);

#define STORE_MAGIC         0x5453464CU     /* "LFST" */
#define STORE_VERSION       LF_STORE_FORMAT_VERSION
#define META_MAGIC          0x454D464CU     /* "LFME" */
#define JREC_MAGIC          0x334A464CU     /* "LFJ3" */
#define JREC_COMMIT         1
#define JREC_APPLIED        2
#define JREC_SIZE           256
#define JREC_PER_LOG        (LF_SECTOR_SIZE / JREC_SIZE)
#define POOL_SECTORS        32
#define META_PER_SECTOR     6
#define META_SECTORS        ((LF_STORE_LOGICAL_SECTORS + META_PER_SECTOR - 1) / META_PER_SECTOR)
#define CTR_RING_SECTORS    4
#define CTR_SECTORS         (2 * CTR_RING_SECTORS)
#define CTR_MAGIC           0x434C
#define SECTOR_PARITY       RS_PARITY_LEN(LF_SECTOR_SIZE)
#define J_MAX_ENTRIES       (2 * LF_STORE_MAX_DIRTY)

/* Layout, in sectors from the start of the region. */
#define S_HDR               0       /* two copies: sectors 0 and 1 */
#define S_LOG               2
#define S_POOL              3
#define S_A                 (S_POOL + POOL_SECTORS)
#define S_B                 (S_A + LF_STORE_LOGICAL_SECTORS)
#define S_META_A            (S_B + LF_STORE_LOGICAL_SECTORS)
#define S_META_B            (S_META_A + META_SECTORS)
#define S_CTR               (S_META_B + META_SECTORS)
#define S_END               (S_CTR + CTR_SECTORS)

#if defined(ENABLE_EMULATION)
/* Stores written by emulator builds before this layout kept their data at
 * absolute file offsets [4 MiB, 8 MiB). */
#define LEGACY_START        0x400000u
#define LEGACY_END          0x800000u
#endif

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t region_sectors;
    uint16_t logical_sectors, pool_sectors, meta_sectors, ctr_sectors;
    uint16_t s_log, s_pool, s_a, s_b, s_meta_a, s_meta_b, s_ctr, rfu;
    uint8_t uuid[16];
    uint8_t rfu2[8];
    uint32_t crc;
} store_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t lsn;
    uint16_t flags;
    uint64_t gen;
    uint32_t crc;                   /* crc32c of the sector */
    uint32_t erase_count;
    uint8_t parity[SECTOR_PARITY];  /* Reed-Solomon parity of the sector */
    uint32_t entry_crc;
} meta_entry_t;

_Static_assert(META_PER_SECTOR * sizeof(meta_entry_t) <= LF_SECTOR_SIZE, "metadata sector overflow");

enum { J_DATA = 0, J_META = 1 };

typedef struct __attribute__((packed)) {
    uint8_t kind;
    uint8_t rfu;
    uint16_t index;                 /* logical sector or metadata sector */
    uint16_t jslot;
    uint16_t rfu2;
    uint32_t crc;                   /* crc32c of the journaled image */
} jentry_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t type;
    uint8_t count;
    uint16_t rfu;
    uint64_t gen;
    jentry_t e[J_MAX_ENTRIES];
    uint32_t crc;
} jrec_t;

_Static_assert(sizeof(jrec_t) <= JREC_SIZE, "journal record too large");

typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint8_t id;
    uint8_t rfu;
    uint32_t value;
    uint32_t seq;
    uint32_t crc;
} ctr_rec_t;

#define CTR_PER_SECTOR      (LF_SECTOR_SIZE / sizeof(ctr_rec_t))

static struct {
    lf_region_t reg;
    bool mounted;
    bool legacy;
    bool open_commit;               /* a COMMIT could not be applied: no more commits */
    int idx;
    uint64_t gen;
    uint16_t next_pool;
    uint16_t log_next;
    uint8_t served_b[(LF_STORE_LOGICAL_SECTORS + 7) / 8];
    lf_health_t health;
    uint32_t ctr_value[LF_CTR_MAX_IDS];
    uint16_t ctr_present;
    uint32_t ctr_seq;
    uint8_t ring_sector[2];
    uint16_t ring_slot[2];
} st = { .idx = -1 };

/* Sector buffers; every user holds the store lock. */
static uint8_t scratch[LF_SECTOR_SIZE];
static uint8_t verify_buf[LF_SECTOR_SIZE];

/* ------------------------------------------------------------------------ */
/* Locking and memory                                                       */
/* ------------------------------------------------------------------------ */

#if defined(ESP_PLATFORM)
static SemaphoreHandle_t store_mtx = NULL;
static void store_lock(void) {
    if (store_mtx == NULL) {
        store_mtx = xSemaphoreCreateRecursiveMutex();
    }
    xSemaphoreTakeRecursive(store_mtx, portMAX_DELAY);
}
static void store_unlock(void) {
    xSemaphoreGiveRecursive(store_mtx);
}
/* Sector contents are secrets at rest: keep them out of PSRAM. */
static void *alloc_internal(size_t n) {
    return heap_caps_malloc(n, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
}
#else
static pthread_mutex_t store_mtx;
static pthread_once_t store_once = PTHREAD_ONCE_INIT;
static void store_mtx_init(void) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&store_mtx, &attr);
    pthread_mutexattr_destroy(&attr);
}
static void store_lock(void) {
    pthread_once(&store_once, store_mtx_init);
    pthread_mutex_lock(&store_mtx);
}
static void store_unlock(void) {
    pthread_mutex_unlock(&store_mtx);
}
static void *alloc_internal(size_t n) {
    return malloc(n);
}
#endif

static void free_secret(void *p, size_t n) {
    if (p) {
        mbedtls_platform_zeroize(p, n);
        free(p);
    }
}

/* ------------------------------------------------------------------------ */
/* Sector primitives                                                        */
/* ------------------------------------------------------------------------ */

static inline uint32_t soff(uint32_t sector) {
    return sector * LF_SECTOR_SIZE;
}

static bool served_from_b(uint32_t lsn) {
    return (st.served_b[lsn / 8] >> (lsn % 8)) & 1;
}

static void set_served_from_b(uint32_t lsn, bool b) {
    if (b) {
        st.served_b[lsn / 8] |= (uint8_t) (1u << (lsn % 8));
    }
    else {
        st.served_b[lsn / 8] &= (uint8_t) ~(1u << (lsn % 8));
    }
}

/* Erases a sector and, unless img is NULL, programs the full image, then
 * verifies it. Images are always programmed (also all-0xFF ones) so the
 * logical content matches its CRC under flash encryption too. */
static int write_sector(uint32_t sector, const uint8_t *img) {
    uint32_t want = img ? crc32c(img, LF_SECTOR_SIZE) : 0;
    for (int attempt = 0; attempt < 2; attempt++) {
        if (lf_region_erase(&st.reg, soff(sector), LF_SECTOR_SIZE) != PICOKEY_OK) {
            continue;
        }
        if (img == NULL) {
            if (lf_region_blank(&st.reg, soff(sector), LF_SECTOR_SIZE)) {
                return PICOKEY_OK;
            }
            continue;
        }
        if (lf_region_write(&st.reg, soff(sector), img, LF_SECTOR_SIZE) == PICOKEY_OK &&
            lf_region_read(&st.reg, soff(sector), verify_buf, LF_SECTOR_SIZE) == PICOKEY_OK &&
            crc32c(verify_buf, LF_SECTOR_SIZE) == want) {
            return PICOKEY_OK;
        }
    }
    printf("[lf_store] ERROR: sector %u of region %d does not verify\n", (unsigned) sector, st.idx);
    return PICOKEY_ERR_MEMORY_FATAL;
}

/* ------------------------------------------------------------------------ */
/* Header                                                                   */
/* ------------------------------------------------------------------------ */

static void hdr_build(store_hdr_t *h, uint32_t region_sectors, const uint8_t uuid[16]) {
    memset(h, 0, sizeof(*h));
    h->magic = STORE_MAGIC;
    h->version = STORE_VERSION;
    h->size = sizeof(*h);
    h->region_sectors = region_sectors;
    h->logical_sectors = LF_STORE_LOGICAL_SECTORS;
    h->pool_sectors = POOL_SECTORS;
    h->meta_sectors = META_SECTORS;
    h->ctr_sectors = CTR_SECTORS;
    h->s_log = S_LOG;
    h->s_pool = S_POOL;
    h->s_a = S_A;
    h->s_b = S_B;
    h->s_meta_a = S_META_A;
    h->s_meta_b = S_META_B;
    h->s_ctr = S_CTR;
    if (uuid) {
        memcpy(h->uuid, uuid, 16);
    }
    h->crc = crc32c((const uint8_t *) h, offsetof(store_hdr_t, crc));
}

static bool hdr_valid(const store_hdr_t *h) {
    return h->magic == STORE_MAGIC && h->size == sizeof(*h) &&
           crc32c((const uint8_t *) h, offsetof(store_hdr_t, crc)) == h->crc;
}

/* Layout of this firmware; other versions are refused instead of guessed. */
static bool hdr_matches_layout(const store_hdr_t *h) {
    store_hdr_t ref;
    hdr_build(&ref, h->region_sectors, h->uuid);
    return h->version == STORE_VERSION && h->logical_sectors == ref.logical_sectors &&
           h->pool_sectors == ref.pool_sectors && h->meta_sectors == ref.meta_sectors &&
           h->ctr_sectors == ref.ctr_sectors && h->s_log == ref.s_log && h->s_pool == ref.s_pool &&
           h->s_a == ref.s_a && h->s_b == ref.s_b && h->s_meta_a == ref.s_meta_a &&
           h->s_meta_b == ref.s_meta_b && h->s_ctr == ref.s_ctr;
}

/* Returns the valid header (copy 0 preferred); 0 copies valid -> false. */
static bool hdr_read(lf_region_t *reg, store_hdr_t *out, uint8_t *valid_mask) {
    store_hdr_t h[2];
    uint8_t mask = 0;
    for (int c = 0; c < 2; c++) {
        if (lf_region_read(reg, soff(S_HDR + c), &h[c], sizeof(h[c])) == PICOKEY_OK && hdr_valid(&h[c])) {
            mask |= (uint8_t) (1 << c);
        }
    }
    if (valid_mask) {
        *valid_mask = mask;
    }
    if (mask & 1) {
        *out = h[0];
        return true;
    }
    if (mask & 2) {
        *out = h[1];
        return true;
    }
    return false;
}

bool lf_store_is_formatted(uint8_t idx, uint8_t uuid[16]) {
    lf_region_t reg;
    store_hdr_t h;
    if (idx >= LF_STORE_REGIONS || !lf_region_open(&reg, LF_REG_STORE(idx)) || !hdr_read(&reg, &h, NULL)) {
        return false;
    }
    if (uuid) {
        memcpy(uuid, h.uuid, 16);
    }
    return true;
}

bool lf_store_has_content(uint8_t idx) {
    lf_region_t reg;
    if (lf_store_is_formatted(idx, NULL)) {
        return true;
    }
    if (!lf_region_open(&reg, LF_REG_STORE(idx)) || reg.size < soff(S_END)) {
        return false;
    }
    /* Firmware that erased regions from the start could be cut off after the
     * header: whatever is left is the end of the region, and the end of each
     * area there tells. The last metadata sectors of both copies (the file
     * system's list heads live in the last logical sectors, so every store
     * that was ever mounted wrote them), then every counter sector. */
    if (!lf_region_erased(&reg, soff(S_META_B - 1), LF_SECTOR_SIZE) ||
        !lf_region_erased(&reg, soff(S_CTR - 1), LF_SECTOR_SIZE)) {
        return true;
    }
    for (uint32_t s = S_CTR; s < S_END; s++) {
        if (!lf_region_erased(&reg, soff(s), LF_SECTOR_SIZE)) {
            return true;
        }
    }
    return false;
}

/* Erases everything behind the header first and the header copies last: a
 * cut in between leaves a region that still looks formatted, which the next
 * boot erases again (see lf_store_has_content). */
static int erase_region(lf_region_t *reg) {
    uint32_t body = soff(S_HDR + 2);
    int ret = PICOKEY_OK;
    if (reg->size > body) {
        ret = lf_region_erase(reg, body, reg->size - body);
    }
    for (int c = 1; c >= 0 && ret == PICOKEY_OK; c--) {
        ret = lf_region_erase(reg, soff(S_HDR + c), LF_SECTOR_SIZE);
    }
    return ret;
}

int lf_store_erase(uint8_t idx) {
    lf_region_t reg;
    if (idx >= LF_STORE_REGIONS || !lf_region_open(&reg, LF_REG_STORE(idx))) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    store_lock();
    if (st.mounted && st.idx == idx) {
        store_unlock();
        return PICOKEY_ERR_BLOCKED;     /* never wipe the mounted store */
    }
    int ret = erase_region(&reg);
    store_unlock();
    return ret;
}

int lf_store_format(uint8_t idx, const uint8_t uuid[16]) {
    lf_region_t reg;
    if (idx >= LF_STORE_REGIONS || !lf_region_open(&reg, LF_REG_STORE(idx))) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (reg.size < soff(S_END)) {
        printf("[lf_store] ERROR: store region %u is too small\n", idx);
        return PICOKEY_ERR_NO_MEMORY;
    }
    store_lock();
    if (st.mounted && st.idx == idx) {
        store_unlock();
        return PICOKEY_ERR_BLOCKED;
    }
    int ret = erase_region(&reg);
    if (ret == PICOKEY_OK) {
        store_hdr_t h, chk;
        hdr_build(&h, reg.size / LF_SECTOR_SIZE, uuid);
        for (int c = 0; c < 2 && ret == PICOKEY_OK; c++) {
            ret = lf_region_write(&reg, soff(S_HDR + c), &h, sizeof(h));
            if (ret == PICOKEY_OK && (lf_region_read(&reg, soff(S_HDR + c), &chk, sizeof(chk)) != PICOKEY_OK ||
                                      memcmp(&h, &chk, sizeof(h)) != 0)) {
                ret = PICOKEY_ERR_MEMORY_FATAL;
            }
        }
    }
    store_unlock();
    return ret;
}

/* ------------------------------------------------------------------------ */
/* Metadata                                                                 */
/* ------------------------------------------------------------------------ */

static bool meta_valid(const meta_entry_t *e, uint32_t lsn) {
    return e->magic == META_MAGIC && e->lsn == lsn &&
           crc32c((const uint8_t *) e, offsetof(meta_entry_t, entry_crc)) == e->entry_crc;
}

static uint32_t meta_off(uint32_t base_sector, uint32_t lsn) {
    return soff(base_sector + lsn / META_PER_SECTOR) + (lsn % META_PER_SECTOR) * sizeof(meta_entry_t);
}

/* Newest valid metadata of lsn from either copy. */
static bool meta_get(uint32_t lsn, meta_entry_t *out) {
    meta_entry_t a, b;
    bool va = lf_region_read(&st.reg, meta_off(S_META_A, lsn), &a, sizeof(a)) == PICOKEY_OK && meta_valid(&a, lsn);
    bool vb = lf_region_read(&st.reg, meta_off(S_META_B, lsn), &b, sizeof(b)) == PICOKEY_OK && meta_valid(&b, lsn);
    if (va && (!vb || a.gen >= b.gen)) {
        *out = a;
        return true;
    }
    if (vb) {
        *out = b;
        return true;
    }
    return false;
}

static void meta_fill(meta_entry_t *e, uint32_t lsn, const uint8_t *img, uint64_t gen, uint32_t erase_count) {
    memset(e, 0, sizeof(*e));
    e->magic = META_MAGIC;
    e->lsn = (uint16_t) lsn;
    e->flags = 1;
    e->gen = gen;
    e->crc = crc32c(img, LF_SECTOR_SIZE);
    e->erase_count = erase_count;
    rs_encode(img, LF_SECTOR_SIZE, e->parity);
    e->entry_crc = crc32c((const uint8_t *) e, offsetof(meta_entry_t, entry_crc));
}

/* ------------------------------------------------------------------------ */
/* Journal                                                                  */
/* ------------------------------------------------------------------------ */

static bool jrec_valid(const jrec_t *r) {
    return r->magic == JREC_MAGIC && (r->type == JREC_COMMIT || r->type == JREC_APPLIED) &&
           r->count <= J_MAX_ENTRIES && crc32c((const uint8_t *) r, offsetof(jrec_t, crc)) == r->crc;
}

static int jrec_append(jrec_t *r) {
    if (st.log_next >= JREC_PER_LOG) {
        /* Full log and no pending transaction (the last COMMIT has its
         * APPLIED record), so it can be recycled. */
        if (lf_region_erase(&st.reg, soff(S_LOG), LF_SECTOR_SIZE) != PICOKEY_OK) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        st.log_next = 0;
    }
    r->magic = JREC_MAGIC;
    r->crc = crc32c((const uint8_t *) r, offsetof(jrec_t, crc));
    uint8_t buf[JREC_SIZE];
    memset(buf, 0xFF, sizeof(buf));
    memcpy(buf, r, sizeof(*r));
    uint32_t off = soff(S_LOG) + st.log_next * JREC_SIZE;
    st.log_next++;
    jrec_t chk;
    if (lf_region_write(&st.reg, off, buf, JREC_SIZE) != PICOKEY_OK ||
        lf_region_read(&st.reg, off, &chk, sizeof(chk)) != PICOKEY_OK || memcmp(&chk, r, sizeof(chk)) != 0) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    return PICOKEY_OK;
}

static uint32_t target_sector(uint8_t kind, uint16_t index, bool copy_b) {
    if (kind == J_DATA) {
        return (copy_b ? S_B : S_A) + index;
    }
    return (copy_b ? S_META_B : S_META_A) + index;
}

/* Writes a committed transaction to its targets: copy A data, metadata A,
 * copy B data, metadata B. Idempotent (also used by recovery).
 *
 * A copy that cannot be rewritten (worn sector) is bypassed, not fatal, as
 * long as the other copy of the same sector verifies: data then comes from
 * copy B (served_from_b), metadata from the valid copy (meta_get), and the
 * scrub of the next mount tries the bad copy again. The transaction only
 * fails when some sector has no verified copy at all. */
static int apply_rec(const jrec_t *r) {
    uint8_t good[J_MAX_ENTRIES];
    memset(good, 0, sizeof(good));
    for (int pass = 0; pass < 4; pass++) {
        bool copy_b = pass >= 2;
        uint8_t kind = (pass & 1) ? J_META : J_DATA;
        for (uint8_t i = 0; i < r->count; i++) {
            const jentry_t *e = &r->e[i];
            if (e->kind != kind) {
                continue;
            }
            if (lf_region_read(&st.reg, soff(S_POOL + e->jslot), scratch, LF_SECTOR_SIZE) != PICOKEY_OK ||
                crc32c(scratch, LF_SECTOR_SIZE) != e->crc) {
                return PICOKEY_ERR_MEMORY_FATAL;
            }
            int w = write_sector(target_sector(kind, e->index, copy_b), scratch);
            if (w == PICOKEY_OK) {
                good[i] |= copy_b ? 2 : 1;
            }
            else {
                st.health.copy_write_failures++;
            }
            if (kind == J_DATA && !copy_b) {
                set_served_from_b(e->index, w != PICOKEY_OK);
                if (w != PICOKEY_OK) {
                    st.health.served_from_b++;
                }
            }
        }
    }
    for (uint8_t i = 0; i < r->count; i++) {
        if (!good[i]) {
            printf("[lf_store] ERROR: no copy of %s sector %u could be written\n",
                   r->e[i].kind == J_DATA ? "logical" : "metadata", (unsigned) r->e[i].index);
            return PICOKEY_ERR_MEMORY_FATAL;
        }
    }
    return PICOKEY_OK;
}

/* Highest generation any valid metadata entry carries: the last transaction
 * that reached the live copies. */
static uint64_t meta_max_gen(void) {
    uint64_t max = 0;
    for (uint32_t lsn = 0; lsn < LF_STORE_LOGICAL_SECTORS; lsn++) {
        meta_entry_t e;
        for (int c = 0; c < 2; c++) {
            if (lf_region_read(&st.reg, meta_off(c ? S_META_B : S_META_A, lsn), &e, sizeof(e)) == PICOKEY_OK &&
                meta_valid(&e, lsn) && e.gen > max) {
                max = e.gen;
            }
        }
    }
    return max;
}

static void journal_recover(void) {
    jrec_t rec, pending;
    bool have_pending = false, torn = false;
    uint16_t used = 0;
    for (uint16_t i = 0; i < JREC_PER_LOG; i++) {
        uint32_t off = soff(S_LOG) + i * JREC_SIZE;
        if (lf_region_blank(&st.reg, off, JREC_SIZE)) {
            continue;
        }
        used = (uint16_t) (i + 1);
        if (lf_region_read(&st.reg, off, &rec, sizeof(rec)) != PICOKEY_OK || !jrec_valid(&rec)) {
            torn = true;
            continue;
        }
        if (rec.gen > st.gen) {
            st.gen = rec.gen;
        }
        if (rec.type == JREC_COMMIT) {
            pending = rec;
            have_pending = true;
        }
        else if (have_pending && rec.gen == pending.gen) {
            have_pending = false;
        }
    }
    if (have_pending) {
        /* A log erase that was cut off can leave an old COMMIT readable while
         * its APPLIED record and everything after it are damaged or erased.
         * Live data newer than that transaction proves it was applied long
         * ago: replaying it would roll newer transactions back. (A genuine
         * pending transaction is always the newest one.) */
        uint64_t live = meta_max_gen();
        if (pending.gen < live) {
            printf("[lf_store] stale transaction %u in a damaged log ignored (data is at %u)\n",
                   (unsigned) pending.gen, (unsigned) live);
            have_pending = false;
        }
    }
    if (have_pending) {
        bool ok = true;
        for (uint8_t i = 0; ok && i < pending.count; i++) {
            ok = lf_region_read(&st.reg, soff(S_POOL + pending.e[i].jslot), scratch, LF_SECTOR_SIZE) == PICOKEY_OK &&
                 crc32c(scratch, LF_SECTOR_SIZE) == pending.e[i].crc;
        }
        if (ok && apply_rec(&pending) == PICOKEY_OK) {
            st.health.journal_replayed = 1;
            printf("[lf_store] replayed transaction %u (%u sectors)\n", (unsigned) pending.gen, pending.count);
        }
        else {
            /* The journal itself is damaged: the scrub below reconciles the
             * copies sector by sector. */
            st.health.journal_corrupt = 1;
            printf("[lf_store] ERROR: pending transaction %u cannot be replayed\n", (unsigned) pending.gen);
        }
    }
    /* A clean log (every COMMIT closed) is simply appended to, so a normal
     * boot writes nothing. */
    if (have_pending || torn) {
        lf_region_erase(&st.reg, soff(S_LOG), LF_SECTOR_SIZE);
        st.log_next = 0;
    }
    else {
        st.log_next = used;
    }
}

/* ------------------------------------------------------------------------ */
/* Commit                                                                   */
/* ------------------------------------------------------------------------ */

static uint16_t pool_next(void) {
    uint16_t s = st.next_pool;
    st.next_pool = (uint16_t) ((st.next_pool + 1) % POOL_SECTORS);
    return s;
}

int lf_store_commit(const lf_dirty_t *dirty, int n) {
    if (n <= 0) {
        return PICOKEY_OK;
    }
    store_lock();
    if (!st.mounted || st.legacy || st.open_commit || n > LF_STORE_MAX_DIRTY) {
        /* After a transaction that could not be applied, its COMMIT must stay
         * the last one in the log (and its pool images untouched) so the next
         * mount replays it. */
        store_unlock();
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    int ret = PICOKEY_OK;
    uint64_t gen = st.gen + 1;
    jrec_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.type = JREC_COMMIT;
    rec.gen = gen;

    uint8_t *erased = NULL;
    for (int i = 0; i < n; i++) {
        if (dirty[i].lsn >= LF_STORE_LOGICAL_SECTORS) {
            ret = PICOKEY_ERR_MEMORY_FATAL;
            goto out;
        }
        if (dirty[i].image == NULL && erased == NULL) {
            erased = (uint8_t *) alloc_internal(LF_SECTOR_SIZE);
            if (erased == NULL) {
                ret = PICOKEY_ERR_NO_MEMORY;
                goto out;
            }
            memset(erased, 0xFF, LF_SECTOR_SIZE);
        }
    }

    /* 1. New sector images into the journal pool. */
    for (int i = 0; i < n; i++) {
        const uint8_t *img = dirty[i].image ? dirty[i].image : erased;
        uint16_t slot = pool_next();
        if (write_sector(S_POOL + slot, img) != PICOKEY_OK) {
            ret = PICOKEY_ERR_MEMORY_FATAL;
            goto out;
        }
        jentry_t *e = &rec.e[rec.count++];
        e->kind = J_DATA;
        e->index = (uint16_t) dirty[i].lsn;
        e->jslot = slot;
        e->crc = crc32c(img, LF_SECTOR_SIZE);
    }

    /* 2. Their metadata sectors, rebuilt from the best current entries. */
    for (int i = 0; i < n; i++) {
        uint32_t m = dirty[i].lsn / META_PER_SECTOR;
        bool done = false;
        for (int j = 0; j < i; j++) {
            done |= dirty[j].lsn / META_PER_SECTOR == m;
        }
        if (done) {
            continue;
        }
        memset(scratch, 0xFF, LF_SECTOR_SIZE);
        for (uint32_t k = 0; k < META_PER_SECTOR; k++) {
            uint32_t lsn = m * META_PER_SECTOR + k;
            if (lsn >= LF_STORE_LOGICAL_SECTORS) {
                break;
            }
            meta_entry_t *slot_e = (meta_entry_t *) (scratch + k * sizeof(meta_entry_t));
            meta_entry_t cur;
            bool have = meta_get(lsn, &cur);
            int d = -1;
            for (int j = 0; j < n; j++) {
                if (dirty[j].lsn == lsn) {
                    d = j;
                }
            }
            if (d >= 0) {
                meta_entry_t ne;
                meta_fill(&ne, lsn, dirty[d].image ? dirty[d].image : erased, gen, have ? cur.erase_count + 1 : 1);
                memcpy(slot_e, &ne, sizeof(ne));
            }
            else if (have) {
                memcpy(slot_e, &cur, sizeof(cur));
            }
        }
        uint16_t slot = pool_next();
        if (write_sector(S_POOL + slot, scratch) != PICOKEY_OK) {
            ret = PICOKEY_ERR_MEMORY_FATAL;
            goto out;
        }
        jentry_t *e = &rec.e[rec.count++];
        e->kind = J_META;
        e->index = (uint16_t) m;
        e->jslot = slot;
        e->crc = crc32c(scratch, LF_SECTOR_SIZE);
    }

    /* 3. Commit point. */
    if (jrec_append(&rec) != PICOKEY_OK) {
        ret = PICOKEY_ERR_MEMORY_FATAL;
        goto out;
    }
    st.gen = gen;

    /* 4. Live copies. */
    ret = apply_rec(&rec);
    if (ret != PICOKEY_OK) {
        /* Some sector has no verified copy: only the journal holds it. Leave
         * the COMMIT open (no APPLIED) for the next mount to replay, and stop
         * committing until then so nothing overwrites the log or the pool. */
        st.open_commit = true;
        goto out;
    }

    /* 5. Close the transaction. The data is durable at this point: a missing
     * APPLIED record only means the next mount replays it (idempotent). */
    jrec_t done;
    memset(&done, 0, sizeof(done));
    done.type = JREC_APPLIED;
    done.gen = gen;
    if (jrec_append(&done) != PICOKEY_OK) {
        printf("[lf_store] WARNING: transaction %u applied, its log record could not be written\n", (unsigned) gen);
    }
    st.health.generation = gen;

out:
    free_secret(erased, LF_SECTOR_SIZE);
    if (ret != PICOKEY_OK) {
        st.health.commit_failures++;
    }
    lf_region_refresh(&st.reg);
    store_unlock();
    return ret;
}

/* ------------------------------------------------------------------------ */
/* Scrub                                                                    */
/* ------------------------------------------------------------------------ */

static int repair_sector(uint32_t lsn, const meta_entry_t *e, uint8_t *a, uint8_t *b) {
    bool ok_a = crc32c(a, LF_SECTOR_SIZE) == e->crc;
    bool ok_b = crc32c(b, LF_SECTOR_SIZE) == e->crc;
    if (ok_a && ok_b) {
        set_served_from_b(lsn, false);
        return 0;
    }
    if (ok_a) {
        write_sector(S_B + lsn, a);
        set_served_from_b(lsn, false);
        st.health.repaired_from_copy++;
        return 1;
    }
    if (ok_b) {
        bool fixed = write_sector(S_A + lsn, b) == PICOKEY_OK;
        set_served_from_b(lsn, !fixed);
        if (!fixed) {
            st.health.served_from_b++;
        }
        st.health.repaired_from_copy++;
        return 1;
    }
    /* Both copies damaged: Reed-Solomon on each copy in turn. */
    uint8_t parity[SECTOR_PARITY];
    uint8_t *cand[2] = { a, b };
    for (int c = 0; c < 2; c++) {
        memcpy(parity, e->parity, sizeof(parity));
        int fixed = rs_decode(cand[c], LF_SECTOR_SIZE, parity);
        if (fixed >= 0 && crc32c(cand[c], LF_SECTOR_SIZE) == e->crc) {
            bool wa = write_sector(S_A + lsn, cand[c]) == PICOKEY_OK;
            write_sector(S_B + lsn, cand[c]);
            set_served_from_b(lsn, !wa);
            st.health.corrected_ecc++;
            st.health.ecc_bytes_corrected += (uint32_t) fixed;
            return 1;
        }
    }
    st.health.uncorrectable++;
    printf("[lf_store] ERROR: logical sector %u of region %d is unrecoverable\n", (unsigned) lsn, st.idx);
    return -1;
}

static int scrub_locked(void) {
    uint8_t *a = (uint8_t *) alloc_internal(LF_SECTOR_SIZE);
    uint8_t *b = (uint8_t *) alloc_internal(LF_SECTOR_SIZE);
    if (!a || !b) {
        free_secret(a, LF_SECTOR_SIZE);
        free_secret(b, LF_SECTOR_SIZE);
        return PICOKEY_ERR_NO_MEMORY;
    }
    lf_health_t *h = &st.health;
    h->sectors_checked = h->sectors_written = h->repaired_from_copy = h->corrected_ecc = 0;
    h->ecc_bytes_corrected = h->uncorrectable = h->meta_repaired = h->served_from_b = 0;
    h->max_erase_count = h->total_erase_count = 0;
    uint64_t max_gen = st.gen;

    for (uint32_t m = 0; m < META_SECTORS; m++) {
        bool meta_fix = false;
        memset(scratch, 0xFF, LF_SECTOR_SIZE);
        for (uint32_t k = 0; k < META_PER_SECTOR; k++) {
            uint32_t lsn = m * META_PER_SECTOR + k;
            if (lsn >= LF_STORE_LOGICAL_SECTORS) {
                break;
            }
            meta_entry_t ea, eb, *e = NULL;
            bool va = lf_region_read(&st.reg, meta_off(S_META_A, lsn), &ea, sizeof(ea)) == PICOKEY_OK && meta_valid(&ea, lsn);
            bool vb = lf_region_read(&st.reg, meta_off(S_META_B, lsn), &eb, sizeof(eb)) == PICOKEY_OK && meta_valid(&eb, lsn);
            if (va && vb) {
                e = ea.gen >= eb.gen ? &ea : &eb;
                meta_fix |= memcmp(&ea, &eb, sizeof(ea)) != 0;
            }
            else if (va || vb) {
                e = va ? &ea : &eb;
                meta_fix = true;
            }
            h->sectors_checked++;
            if (lf_region_read(&st.reg, soff(S_A + lsn), a, LF_SECTOR_SIZE) != PICOKEY_OK ||
                lf_region_read(&st.reg, soff(S_B + lsn), b, LF_SECTOR_SIZE) != PICOKEY_OK) {
                h->uncorrectable++;
                continue;
            }
            if (e == NULL) {
                if (lf_region_erased(&st.reg, soff(S_A + lsn), LF_SECTOR_SIZE) &&
                    lf_region_erased(&st.reg, soff(S_B + lsn), LF_SECTOR_SIZE)) {
                    continue;   /* never written (or blank when encrypted in place) */
                }
                /* Data without any metadata left: keep copy A (what the file
                 * system has been reading) and rebuild metadata and copy B. */
                meta_fill(&ea, lsn, a, st.gen, 1);
                e = &ea;
                if (memcmp(a, b, LF_SECTOR_SIZE) != 0) {
                    write_sector(S_B + lsn, a);
                }
                meta_fix = true;
                h->meta_repaired++;
            }
            memcpy(scratch + k * sizeof(meta_entry_t), e, sizeof(*e));
            h->sectors_written++;
            h->total_erase_count += e->erase_count;
            if (e->erase_count > h->max_erase_count) {
                h->max_erase_count = e->erase_count;
            }
            if (e->gen > max_gen) {
                max_gen = e->gen;
            }
            repair_sector(lsn, e, a, b);
        }
        if (meta_fix) {
            /* Rewrite the metadata copies one after the other, the one that
             * differs from the rebuilt image (the damaged one) first. */
            h->meta_repaired++;
            for (int c = 1; c >= 0; c--) {
                uint32_t sec = (c ? S_META_B : S_META_A) + m;
                if (lf_region_read(&st.reg, soff(sec), a, LF_SECTOR_SIZE) == PICOKEY_OK &&
                    memcmp(a, scratch, META_PER_SECTOR * sizeof(meta_entry_t)) == 0) {
                    continue;
                }
                write_sector(sec, scratch);
            }
        }
    }
    st.gen = max_gen;
    h->generation = max_gen;
    free_secret(a, LF_SECTOR_SIZE);
    free_secret(b, LF_SECTOR_SIZE);
    lf_region_refresh(&st.reg);
    return h->uncorrectable ? PICOKEY_ERR_MEMORY_FATAL : PICOKEY_OK;
}

int lf_store_scrub(void) {
    store_lock();
    int ret = st.mounted && !st.legacy ? scrub_locked() : PICOKEY_ERR_FILE_NOT_FOUND;
    store_unlock();
    return ret;
}

const lf_health_t *lf_store_health(void) {
    return &st.health;
}

/* ------------------------------------------------------------------------ */
/* Counter log                                                              */
/* ------------------------------------------------------------------------ */

static uint32_t ctr_off(uint8_t ring, uint8_t sector, uint16_t slot) {
    return soff(S_CTR + ring * CTR_RING_SECTORS + sector) + (uint32_t) slot * sizeof(ctr_rec_t);
}

static bool ctr_valid(const ctr_rec_t *r) {
    return r->magic == CTR_MAGIC && r->id < LF_CTR_MAX_IDS &&
           crc32c((const uint8_t *) r, offsetof(ctr_rec_t, crc)) == r->crc;
}

static void ctr_load(void) {
    memset(st.ctr_value, 0, sizeof(st.ctr_value));
    st.ctr_present = 0;
    st.ctr_seq = 0;
    for (uint8_t ring = 0; ring < 2; ring++) {
        uint32_t best_seq = 0;
        uint8_t best_sector = 0;
        bool found = false;
        for (uint8_t s = 0; s < CTR_RING_SECTORS; s++) {
            for (uint16_t i = 0; i < CTR_PER_SECTOR; i++) {
                ctr_rec_t r;
                if (lf_region_read(&st.reg, ctr_off(ring, s, i), &r, sizeof(r)) != PICOKEY_OK || !ctr_valid(&r)) {
                    continue;
                }
                if (!(st.ctr_present & (1u << r.id)) || r.value > st.ctr_value[r.id]) {
                    st.ctr_value[r.id] = r.value;
                }
                st.ctr_present |= (uint16_t) (1u << r.id);
                if (!found || r.seq >= best_seq) {
                    best_seq = r.seq;
                    best_sector = s;
                    found = true;
                }
            }
        }
        st.ring_sector[ring] = best_sector;
        /* Append after the last used slot of the newest sector. */
        uint16_t next = 0;
        for (uint16_t i = CTR_PER_SECTOR; i > 0; i--) {
            if (!lf_region_blank(&st.reg, ctr_off(ring, best_sector, i - 1), sizeof(ctr_rec_t))) {
                next = i;
                break;
            }
        }
        st.ring_slot[ring] = next;
        if (best_seq > st.ctr_seq) {
            st.ctr_seq = best_seq;
        }
    }
}

static int ctr_write(uint8_t ring, uint8_t id, uint32_t value) {
    for (int attempt = 0; attempt < 4; attempt++) {
        if (st.ring_slot[ring] >= CTR_PER_SECTOR) {
            /* Move to the oldest sector of the ring and start it with a
             * checkpoint of every counter, so it alone is complete. */
            uint8_t ns = (uint8_t) ((st.ring_sector[ring] + 1) % CTR_RING_SECTORS);
            if (lf_region_erase(&st.reg, soff(S_CTR + ring * CTR_RING_SECTORS + ns), LF_SECTOR_SIZE) != PICOKEY_OK) {
                return PICOKEY_ERR_MEMORY_FATAL;
            }
            st.ring_sector[ring] = ns;
            st.ring_slot[ring] = 0;
            for (uint8_t cid = 0; cid < LF_CTR_MAX_IDS; cid++) {
                if ((st.ctr_present & (1u << cid)) && cid != id) {
                    int r = ctr_write(ring, cid, st.ctr_value[cid]);
                    if (r != PICOKEY_OK) {
                        return r;
                    }
                }
            }
        }
        ctr_rec_t rec, chk;
        memset(&rec, 0, sizeof(rec));
        rec.magic = CTR_MAGIC;
        rec.id = id;
        rec.value = value;
        rec.seq = ++st.ctr_seq;
        rec.crc = crc32c((const uint8_t *) &rec, offsetof(ctr_rec_t, crc));
        uint32_t off = ctr_off(ring, st.ring_sector[ring], st.ring_slot[ring]);
        st.ring_slot[ring]++;
        if (lf_region_write(&st.reg, off, &rec, sizeof(rec)) == PICOKEY_OK &&
            lf_region_read(&st.reg, off, &chk, sizeof(chk)) == PICOKEY_OK && memcmp(&rec, &chk, sizeof(rec)) == 0) {
            return PICOKEY_OK;
        }
    }
    return PICOKEY_ERR_MEMORY_FATAL;
}

bool lf_ctr_present(uint8_t id) {
    return id < LF_CTR_MAX_IDS && (st.ctr_present & (1u << id));
}

int lf_ctr_get(uint8_t id, uint32_t *value) {
    if (id >= LF_CTR_MAX_IDS) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    store_lock();
    *value = st.ctr_value[id];
    store_unlock();
    return PICOKEY_OK;
}

int lf_ctr_set(uint8_t id, uint32_t value) {
    if (id >= LF_CTR_MAX_IDS) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    store_lock();
    if (!st.mounted || st.legacy) {
        store_unlock();
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    if (lf_ctr_present(id) && value <= st.ctr_value[id]) {
        store_unlock();
        return PICOKEY_OK;
    }
    /* Ring A, then ring B: a cut in between leaves the new value in A and
     * the maximum over both rings is taken at load. */
    int ret = ctr_write(0, id, value);
    if (ret == PICOKEY_OK) {
        st.ctr_value[id] = value;
        st.ctr_present |= (uint16_t) (1u << id);
        if (ctr_write(1, id, value) != PICOKEY_OK) {
            st.health.commit_failures++;
        }
    }
    store_unlock();
    return ret;
}

/* ------------------------------------------------------------------------ */
/* Mounting                                                                 */
/* ------------------------------------------------------------------------ */

void lf_store_unmount(void) {
    store_lock();
    st.mounted = false;
    st.legacy = false;
    st.idx = -1;
    /* One mapping per region: a stale second mapping of the same flash would
     * not see the cache invalidations of later writes. */
    lf_region_unmap(&st.reg);
    store_unlock();
}

bool lf_store_mounted(void) {
    return st.mounted;
}

bool lf_store_read_only(void) {
    return st.mounted && st.legacy;
}

int lf_store_mounted_region(void) {
    return st.mounted && !st.legacy ? st.idx : -1;
}

int lf_store_mount(uint8_t idx) {
    store_hdr_t h;
    uint8_t mask = 0;
    store_lock();
    st.mounted = false;
    lf_region_unmap(&st.reg);
    if (idx >= LF_STORE_REGIONS || !lf_region_open(&st.reg, LF_REG_STORE(idx))) {
        store_unlock();
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (!lf_region_crypt_ok(&st.reg)) {
        store_unlock();
        return PICOKEY_ERR_BLOCKED;     /* the map would decrypt plain data */
    }
    if (!hdr_read(&st.reg, &h, &mask)) {
        store_unlock();
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (!hdr_matches_layout(&h) || st.reg.size < soff(S_END)) {
        printf("[lf_store] ERROR: store region %u has an unsupported layout (version %u)\n", idx, h.version);
        store_unlock();
        return PICOKEY_WRONG_DATA;
    }
    if (mask != 3) {
        /* Rebuild the damaged header copy from the good one. */
        int bad = (mask & 1) ? 1 : 0;
        if (lf_region_erase(&st.reg, soff(S_HDR + bad), LF_SECTOR_SIZE) == PICOKEY_OK) {
            lf_region_write(&st.reg, soff(S_HDR + bad), &h, sizeof(h));
        }
    }
    memset(&st.health, 0, sizeof(st.health));
    memset(st.served_b, 0, sizeof(st.served_b));
    st.idx = idx;
    st.legacy = false;
    st.open_commit = false;
    st.gen = 0;
    st.next_pool = 0;
    if (lf_region_map(&st.reg) == NULL) {
        store_unlock();
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    st.mounted = true;
    journal_recover();
    ctr_load();
    int ret = scrub_locked();
    /* Sector 0 is never used: address 0 means "none" in the file system. */
    flash_set_bounds(LF_SECTOR_SIZE, LF_STORE_LOGICAL_SIZE);
    store_unlock();
    return ret == PICOKEY_ERR_NO_MEMORY ? ret : PICOKEY_OK;
}

int lf_store_mount_legacy(void) {
    store_lock();
    st.mounted = false;
    lf_region_unmap(&st.reg);
    if (!lf_region_open(&st.reg, LF_REG_LEGACY)) {
        store_unlock();
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    /* A store that exists but cannot be read must not look like no store. */
    if (!lf_region_crypt_ok(&st.reg)) {
        store_unlock();
        return PICOKEY_ERR_BLOCKED;
    }
    if (lf_region_map(&st.reg) == NULL) {
        store_unlock();
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    memset(&st.health, 0, sizeof(st.health));
    memset(st.ctr_value, 0, sizeof(st.ctr_value));
    st.ctr_present = 0;     /* legacy stores keep counters in files */
    st.idx = -1;
    st.legacy = true;
    st.mounted = true;
#if defined(ENABLE_EMULATION)
    flash_set_bounds(LEGACY_START, LEGACY_END);
#else
    flash_set_bounds(0, st.reg.size);
#endif
    store_unlock();
    return PICOKEY_OK;
}

/* What a read of an unmounted (unmapped) store sees: zeros, so lengths read
 * as 0 and list pointers as "none"; two sectors, so a field or payload that
 * starts near the end of one stays inside. Never written through. */
static const uint8_t no_store[2 * LF_SECTOR_SIZE];

uint8_t *lf_store_ptr(uintptr_t addr) {
    const uint8_t *map = st.reg.map;
    if (!st.mounted || map == NULL || addr >= (st.legacy ? st.reg.size : LF_STORE_LOGICAL_SIZE)) {
        /* after an unmount (factory reset) file pointers may be left over */
        return (uint8_t *) no_store + (addr & (LF_SECTOR_SIZE - 1));
    }
    if (st.legacy) {
        return (uint8_t *) map + addr;
    }
    uint32_t lsn = (uint32_t) (addr / LF_SECTOR_SIZE);
    uint32_t base = served_from_b(lsn) ? S_B : S_A;
    return (uint8_t *) map + soff(base) + addr;
}

bool lf_store_blank(uintptr_t addr, size_t len) {
    if (len == 0) {
        return true;
    }
    if (st.legacy) {
        /* Old emulator files were zero filled instead of erased. */
        uint8_t buf[64];
        bool ff = true, zero = true;
        for (size_t off = 0; off < len; off += sizeof(buf)) {
            size_t n = len - off < sizeof(buf) ? len - off : sizeof(buf);
            if (lf_region_read_raw(&st.reg, (uint32_t) (addr + off), buf, (uint32_t) n) != PICOKEY_OK) {
                return false;
            }
            for (size_t i = 0; i < n; i++) {
                ff &= buf[i] == 0xFF;
                zero &= buf[i] == 0x00;
            }
        }
#if defined(ENABLE_EMULATION)
        return ff || zero;
#else
        return ff;
#endif
    }
    /* A logical sector is blank until its first commit gives it metadata. */
    for (uint32_t lsn = (uint32_t) (addr / LF_SECTOR_SIZE); lsn <= (addr + len - 1) / LF_SECTOR_SIZE; lsn++) {
        meta_entry_t e;
        if (meta_get(lsn, &e)) {
            return false;
        }
    }
    return true;
}

int lf_store_read_sector(uint32_t lsn, uint8_t *out) {
    if (!st.mounted || st.legacy || lsn >= LF_STORE_LOGICAL_SECTORS) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    memcpy(out, lf_store_ptr((uintptr_t) lsn * LF_SECTOR_SIZE), LF_SECTOR_SIZE);
    return PICOKEY_OK;
}
