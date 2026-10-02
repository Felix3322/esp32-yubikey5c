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

/*
 * Low level flash access with a sector cache and an atomic commit journal.
 *
 * Upper layers modify flash through a RAM cache of whole sectors. A commit
 * persists every dirty sector of the cache as ONE transaction:
 *
 *   1. each dirty sector image is written to a free journal data sector,
 *   2. a COMMIT record listing (target sector, journal sector, CRC) is appended
 *      to the journal log sector  -> this is the atomic commit point,
 *   3. the target sectors are erased and programmed,
 *   4. an APPLIED record is appended to the journal log.
 *
 * At boot, a COMMIT record without a matching APPLIED record is replayed
 * (idempotent), so a power loss at any instant leaves the store either fully
 * in the old or fully in the new state. Nothing in a target sector is touched
 * before the COMMIT record is durable.
 *
 * The journal lives in the lowest sectors of the data region, which the
 * allocator (that grows downwards from the end) uses last. If existing data
 * already occupies that area the journal is disabled and the store keeps the
 * legacy (non atomic) behaviour; low_flash_journal_active() reports it.
 *
 * Blank detection uses raw reads so it also works when the partition is
 * protected by ESP32 flash encryption (decrypted views of erased flash are
 * pseudo random, not 0xFF).
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "pico_keys.h"
#include <string.h>
#include "crypto_utils.h"
#include "low_flash.h"
#ifdef PICO_PLATFORM
 #include "pico/stdlib.h"
 #include "hardware/flash.h"
 #include "hardware/sync.h"
 #include "pico/mutex.h"
 #include "pico/sem.h"
 #include "pico/multicore.h"
 #include "pico/bootrom.h"
 #include "boot/picobin.h"
#else
 #ifdef ESP_PLATFORM
  #include "esp_compat.h"
  #include "esp_partition.h"
  const esp_partition_t *part0;
 #else
  #ifdef _MSC_VER
   #include <windows.h>
   #include <io.h>
   #define O_RDWR _O_RDWR
   #define O_CREAT _O_CREAT
   #define open _open
   #define write _write
   #define mode_t unsigned short
   #define lseek _lseek
   #include "mman.h"
  #else
   #include <unistd.h>
   #include <sys/mman.h>
  #endif
  #include "queue.h"
  #include "board.h"
 #endif
 #define FLASH_SECTOR_SIZE       4096
 #define XIP_BASE 0
 int fd_map = 0;
 uint8_t *map = NULL;
 #include <fcntl.h>
#endif
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
extern uint32_t FLASH_SIZE_BYTES;
#else
#define FLASH_SIZE_BYTES   (8 * 1024 * 1024)
#endif

#if defined(PICO_PLATFORM)
#define TOTAL_FLASH_PAGES 6
#else
#define TOTAL_FLASH_PAGES 8
#endif
#define FLASH_LOCKOUT_RETRIES 5

/* Journal geometry: one log sector plus a round robin pool of data sectors. */
#define JOURNAL_POOL_SECTORS  (2 * TOTAL_FLASH_PAGES)
#define JOURNAL_SECTORS       (1 + JOURNAL_POOL_SECTORS)
#define JOURNAL_SIZE          (JOURNAL_SECTORS * FLASH_SECTOR_SIZE)
#define JREC_SIZE             256
#define JREC_PER_SECTOR       (FLASH_SECTOR_SIZE / JREC_SIZE)
#define JREC_MAGIC            0x324A464CU /* "LFJ2" */
#define JREC_COMMIT           1
#define JREC_APPLIED          2

typedef struct __attribute__((packed)) {
    uint32_t target;    /* absolute sector address (same address space as flash_read) */
    uint16_t jslot;     /* index in the journal pool */
    uint16_t rfu;
    uint32_t crc;       /* crc32 of the sector image */
} jentry_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t type;
    uint8_t count;
    uint16_t rfu;
    uint32_t seq;
    jentry_t e[TOTAL_FLASH_PAGES];
    uint32_t crc;       /* crc32 of all preceding bytes */
} jrec_t;

_Static_assert(sizeof(jrec_t) <= JREC_SIZE, "journal record too large");

extern void flash_set_bounds(uintptr_t start, uintptr_t end);

extern uintptr_t start_data_pool;
extern uintptr_t end_data_pool;
extern uintptr_t end_rom_pool;

typedef struct page_flash {
    uint8_t page[FLASH_SECTOR_SIZE];
    uintptr_t address;
    bool ready;
    bool erase;
    size_t page_size; //this param is for easy erase. It allows to erase with a single call. IT DOES NOT APPLY TO WRITE
} page_flash_t;

static page_flash_t flash_pages[TOTAL_FLASH_PAGES];

static mutex_t mtx_flash;
static semaphore_t sem_flash;

#ifndef ENABLE_EMULATION
static bool locked_out = false;
#else
static bool locked_out = true;
#endif

static uint8_t ready_pages = 0;

bool flash_available = false;

static uintptr_t journal_base = 0;      /* address of the log sector, 0 if disabled */
static bool journal_active = false;
static uint32_t journal_seq = 0;
static uint16_t journal_next_slot = 0;  /* next free record slot in the log sector */
static uint16_t journal_next_pool = 0;  /* round robin cursor in the data pool */
static volatile bool txn_active = false;
static uint32_t commit_failures = 0;

#ifdef PICO_PLATFORM
static volatile bool commit_requested = false;
static semaphore_t sem_commit_done;
#endif

/* ------------------------------------------------------------------------ */
/* Physical primitives. Addresses are in the same space used by flash_read  */
/* ------------------------------------------------------------------------ */

#if defined(ENABLE_EMULATION)
/* Power-loss simulation for host tests: LF_FAULT_OPS=N makes the N-th physical
 * operation tear (random prefix / random garbage) and terminate the process. */
static long fault_countdown = -1;
static void fault_init(void) {
    const char *e = getenv("LF_FAULT_OPS");
    if (e && *e) {
        fault_countdown = strtol(e, NULL, 10);
    }
}
static bool fault_hit(void) {
    if (fault_countdown < 0) {
        return false;
    }
    if (fault_countdown-- == 0) {
        return true;
    }
    return false;
}
static void fault_die(void) {
    msync(map, FLASH_SIZE_BYTES, MS_SYNC);
    fprintf(stderr, "[low_flash] simulated power loss\n");
    _exit(99);
}
#endif

static int phy_erase(uintptr_t addr) {
#if defined(ESP_PLATFORM)
    return esp_partition_erase_range(part0, addr, FLASH_SECTOR_SIZE) == ESP_OK ? 0 : -1;
#elif defined(PICO_PLATFORM)
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(addr - XIP_BASE, FLASH_SECTOR_SIZE);
    restore_interrupts(ints);
    return 0;
#else
    if (fault_hit()) {
        for (size_t i = 0; i < FLASH_SECTOR_SIZE; i += 64) {
            map[addr + i] = (uint8_t)rand();
        }
        fault_die();
    }
    memset(map + addr, 0xFF, FLASH_SECTOR_SIZE);
    return 0;
#endif
}

static int phy_program(uintptr_t addr, const uint8_t *data, size_t len) {
#if defined(ESP_PLATFORM)
    return esp_partition_write(part0, addr, data, len) == ESP_OK ? 0 : -1;
#elif defined(PICO_PLATFORM)
    uint32_t ints = save_and_disable_interrupts();
    flash_range_program(addr - XIP_BASE, data, len);
    restore_interrupts(ints);
    return 0;
#else
    if (fault_hit()) {
        size_t torn = (size_t)rand() % len;
        memcpy(map + addr, data, torn);
        fault_die();
    }
    memcpy(map + addr, data, len);
    return 0;
#endif
}

/* Raw read, bypassing any transparent decryption. */
static int phy_read_raw(uintptr_t addr, uint8_t *out, size_t len) {
#if defined(ESP_PLATFORM)
    return esp_partition_read_raw(part0, addr, out, len) == ESP_OK ? 0 : -1;
#elif defined(PICO_PLATFORM)
    memcpy(out, (const uint8_t *) addr, len);
    return 0;
#else
    memcpy(out, map + addr, len);
    return 0;
#endif
}

/* Decrypted (logical) read. */
static int phy_read(uintptr_t addr, uint8_t *out, size_t len) {
#if defined(ESP_PLATFORM)
    return esp_partition_read(part0, addr, out, len) == ESP_OK ? 0 : -1;
#else
    return phy_read_raw(addr, out, len);
#endif
}

static void phy_sync(void) {
#if defined(ESP_PLATFORM)
    esp_partition_munmap((esp_partition_mmap_handle_t)fd_map);
    esp_partition_mmap(part0, 0, part0->size, ESP_PARTITION_MMAP_DATA, (const void **)&map, (esp_partition_mmap_handle_t *)&fd_map);
#elif !defined(PICO_PLATFORM)
    msync(map, FLASH_SIZE_BYTES, MS_SYNC);
#endif
}

/* Erased state is 0xFF on NOR flash. Freshly created emulation files are
 * zero filled, so all-zero is also accepted there. */
bool low_flash_region_blank(uintptr_t addr, size_t len) {
    uint8_t buf[64];
    bool all_ff = true, all_00 = true;
    for (size_t off = 0; off < len; off += sizeof(buf)) {
        size_t n = MIN(sizeof(buf), len - off);
        if (phy_read_raw(addr + off, buf, n) != 0) {
            return false;
        }
        for (size_t i = 0; i < n; i++) {
            all_ff &= buf[i] == 0xFF;
            all_00 &= buf[i] == 0x00;
        }
        if (!all_ff && !all_00) {
            return false;
        }
    }
#if defined(ENABLE_EMULATION)
    return all_ff || all_00;
#else
    return all_ff;
#endif
}

/* ------------------------------------------------------------------------ */
/* Journal                                                                  */
/* ------------------------------------------------------------------------ */

static uintptr_t jslot_addr(uint16_t slot) {
    return journal_base + FLASH_SECTOR_SIZE * (1 + slot);
}

static uintptr_t jrec_addr(uint16_t idx) {
    return journal_base + (uintptr_t) idx * JREC_SIZE;
}

static bool jrec_valid(const jrec_t *r) {
    if (r->magic != JREC_MAGIC || (r->type != JREC_COMMIT && r->type != JREC_APPLIED)) {
        return false;
    }
    if (r->count > TOTAL_FLASH_PAGES) {
        return false;
    }
    return crc32c((const uint8_t *) r, offsetof(jrec_t, crc)) == r->crc;
}

static int jrec_append(jrec_t *r) {
    if (journal_next_slot >= JREC_PER_SECTOR) {
        /* The log is full and there is no pending transaction (every COMMIT
         * already has its APPLIED record), so it is safe to recycle it. */
        if (phy_erase(journal_base) != 0) {
            return -1;
        }
        journal_next_slot = 0;
    }
    r->magic = JREC_MAGIC;
    r->crc = crc32c((const uint8_t *) r, offsetof(jrec_t, crc));
    uint8_t buf[JREC_SIZE];
    memset(buf, 0xFF, sizeof(buf));
    memcpy(buf, r, sizeof(*r));
    if (phy_program(jrec_addr(journal_next_slot), buf, sizeof(buf)) != 0) {
        return -1;
    }
    journal_next_slot++;
    return 0;
}

static bool image_is_erased(const uint8_t *img) {
    for (size_t i = 0; i < FLASH_SECTOR_SIZE; i++) {
        if (img[i] != 0xFF) {
            return false;
        }
    }
    return true;
}

static int apply_image(uintptr_t target, const uint8_t *img) {
    if (phy_erase(target) != 0) {
        return -1;
    }
    /* An all-0xFF image means "erased": programming it would store encrypted
     * 0xFF under flash encryption instead of leaving the sector blank. */
    if (image_is_erased(img)) {
        return 0;
    }
    return phy_program(target, img, FLASH_SECTOR_SIZE);
}

/* Replays a committed but not applied transaction, if any. */
static void journal_recover(void) {
    jrec_t rec, pending = { 0 };
    bool have_pending = false;
    uint16_t last_used = 0;
    bool log_clean = true;

    for (uint16_t i = 0; i < JREC_PER_SECTOR; i++) {
        uint8_t buf[JREC_SIZE];
        if (phy_read(jrec_addr(i), buf, sizeof(buf)) != 0) {
            break;
        }
        memcpy(&rec, buf, sizeof(rec));
        if (jrec_valid(&rec)) {
            last_used = i + 1;
            if (rec.seq >= journal_seq) {
                journal_seq = rec.seq + 1;
            }
            if (rec.type == JREC_COMMIT) {
                pending = rec;
                have_pending = true;
            }
            else if (have_pending && rec.seq == pending.seq) {
                have_pending = false;
            }
        }
        else if (!low_flash_region_blank(jrec_addr(i), JREC_SIZE)) {
            /* Torn record or stale legacy data: nothing after it is trusted. */
            log_clean = false;
            last_used = i + 1;
        }
    }

    if (have_pending) {
        uint8_t *img = (uint8_t *) calloc(1, FLASH_SECTOR_SIZE);
        bool ok = img != NULL;
        for (uint8_t e = 0; ok && e < pending.count; e++) {
            ok = phy_read(jslot_addr(pending.e[e].jslot), img, FLASH_SECTOR_SIZE) == 0 &&
                 crc32c(img, FLASH_SECTOR_SIZE) == pending.e[e].crc;
        }
        /* A COMMIT record is only written after all images, so a CRC failure
         * here means the journal sector itself went bad. Do not touch targets. */
        for (uint8_t e = 0; ok && e < pending.count; e++) {
            phy_read(jslot_addr(pending.e[e].jslot), img, FLASH_SECTOR_SIZE);
            uint8_t cur[64];
            bool same = true;
            for (size_t off = 0; same && off < FLASH_SECTOR_SIZE; off += sizeof(cur)) {
                phy_read(pending.e[e].target + off, cur, sizeof(cur));
                same = memcmp(cur, img + off, sizeof(cur)) == 0;
            }
            if (!same) {
                apply_image(pending.e[e].target, img);
            }
        }
        if (img) {
            free(img);
        }
        if (ok) {
            printf("[low_flash] replayed journal transaction %u (%u sectors)\n", (unsigned) pending.seq, pending.count);
        }
        else {
            printf("[low_flash] ERROR: journal transaction %u is corrupt\n", (unsigned) pending.seq);
            commit_failures++;
        }
    }

    /* Start the next transaction from a clean log sector. */
    if (have_pending || !log_clean || last_used > 0) {
        phy_erase(journal_base);
    }
    journal_next_slot = 0;
    phy_sync();
}

/* Finds the lowest address referenced by the legacy linked list (data pool)
 * so the journal is never placed over live records. */
static uintptr_t lowest_live_record(uintptr_t start, uintptr_t end_data) {
    uintptr_t lowest = end_data;
    uintptr_t base;
    uint32_t guard = 0;
    uint8_t buf[sizeof(uintptr_t)];
    if (low_flash_region_blank(end_data, sizeof(uintptr_t) * 2)) {
        return end_data; /* never formatted: no records at all */
    }
    if (phy_read(end_data, buf, sizeof(buf)) != 0) {
        return start;
    }
    memcpy(&base, buf, sizeof(base));
    while (base != 0 && base >= start && base < end_data && guard++ < 65536) {
        if (base < lowest) {
            lowest = base;
        }
        if (phy_read(base, buf, sizeof(buf)) != 0) {
            break;
        }
        memcpy(&base, buf, sizeof(base));
    }
    return lowest;
}

/* ------------------------------------------------------------------------ */
/* Commit                                                                   */
/* ------------------------------------------------------------------------ */

static void lockout_start(void) {
#if defined(PICO_PLATFORM)
    for (int retries = 0; retries < FLASH_LOCKOUT_RETRIES && multicore_lockout_start_timeout_us(1000) == false; retries++) {
    }
#endif
    /* ESP-IDF stalls the other CPU inside every flash operation itself. */
}

static void lockout_end(void) {
#if defined(PICO_PLATFORM)
    for (int retries = 0; retries < FLASH_LOCKOUT_RETRIES && multicore_lockout_end_timeout_us(1000) == false; retries++) {
    }
#endif
}

/* Must be called with mtx_flash held. */
static int commit_locked(void) {
    if (ready_pages == 0) {
        return PICOKEY_OK;
    }
    int ret = PICOKEY_OK;
    lockout_start();
    if (journal_active) {
        jrec_t rec;
        memset(&rec, 0, sizeof(rec));
        rec.type = JREC_COMMIT;
        rec.seq = journal_seq;
        for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
            if (!flash_pages[r].ready && !flash_pages[r].erase) {
                continue;
            }
            if (flash_pages[r].erase && flash_pages[r].page_size > FLASH_SECTOR_SIZE) {
                continue; /* multi-sector erases are applied directly below */
            }
            if (flash_pages[r].erase) {
                memset(flash_pages[r].page, 0xFF, FLASH_SECTOR_SIZE);
            }
            uint16_t slot = journal_next_pool;
            journal_next_pool = (uint16_t)((journal_next_pool + 1) % JOURNAL_POOL_SECTORS);
            if (apply_image(jslot_addr(slot), flash_pages[r].page) != 0) {
                ret = PICOKEY_ERR_MEMORY_FATAL;
                goto done;
            }
            rec.e[rec.count].target = (uint32_t) flash_pages[r].address;
            rec.e[rec.count].jslot = slot;
            rec.e[rec.count].crc = crc32c(flash_pages[r].page, FLASH_SECTOR_SIZE);
            rec.count++;
        }
        if (jrec_append(&rec) != 0) { /* atomic commit point */
            ret = PICOKEY_ERR_MEMORY_FATAL;
            goto done;
        }
    }
    for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
        if (flash_pages[r].ready || (flash_pages[r].erase && flash_pages[r].page_size <= FLASH_SECTOR_SIZE)) {
            if (apply_image(flash_pages[r].address, flash_pages[r].page) != 0) {
                ret = PICOKEY_ERR_MEMORY_FATAL;
            }
        }
        else if (flash_pages[r].erase) {
            size_t n = flash_pages[r].page_size / FLASH_SECTOR_SIZE;
            for (size_t s = 0; s < n; s++) {
                if (phy_erase(flash_pages[r].address + s * FLASH_SECTOR_SIZE) != 0) {
                    ret = PICOKEY_ERR_MEMORY_FATAL;
                }
            }
        }
    }
    if (journal_active && ret == PICOKEY_OK) {
        jrec_t done_rec;
        memset(&done_rec, 0, sizeof(done_rec));
        done_rec.type = JREC_APPLIED;
        done_rec.seq = journal_seq;
        if (jrec_append(&done_rec) != 0) {
            ret = PICOKEY_ERR_MEMORY_FATAL;
        }
        journal_seq++;
    }
done:
    lockout_end();
    if (ret == PICOKEY_OK) {
        for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
            flash_pages[r].ready = false;
            flash_pages[r].erase = false;
        }
        ready_pages = 0;
    }
    else {
        commit_failures++;
        printf("[low_flash] ERROR: commit failed (%d)\n", ret);
    }
    phy_sync();
    return ret;
}

int low_flash_commit(void) {
#if defined(PICO_PLATFORM)
    /* On RP2 targets flash can only be written by core 0 with core 1 locked out. */
    if (get_core_num() != 0) {
        commit_requested = true;
        sem_acquire_blocking(&sem_commit_done);
        return commit_failures ? PICOKEY_ERR_MEMORY_FATAL : PICOKEY_OK;
    }
#endif
    mutex_enter_blocking(&mtx_flash);
#if !defined(ESP_PLATFORM) && !defined(PICO_PLATFORM)
    uint32_t t0 = board_millis();
#endif
    int ret = commit_locked();
#if !defined(ESP_PLATFORM) && !defined(PICO_PLATFORM)
    if (board_millis() - t0 > 100) {
        printf("[low_flash] slow commit: %u ms\n", (unsigned) (board_millis() - t0));
    }
#endif
    flash_available = false;
    mutex_exit(&mtx_flash);
    return ret;
}

void low_flash_txn_begin(void) {
    txn_active = true;
}

int low_flash_txn_end(void) {
    txn_active = false;
    return low_flash_commit();
}

bool low_flash_journal_active(void) {
    return journal_active;
}

uint32_t low_flash_commit_failures(void) {
    return commit_failures;
}

//this function has to be called from the core 0
void do_flash() {
    if (mutex_try_enter(&mtx_flash, NULL) == true) {
        bool requested = false;
#ifdef PICO_PLATFORM
        requested = commit_requested;
#endif
        /* While a command is executing its writes form one transaction and are
         * committed by the card thread; never split them here. */
        if (locked_out == true && ready_pages > 0 && ((flash_available == true && !txn_active) || requested)) {
            commit_locked();
        }
        flash_available = false;
        mutex_exit(&mtx_flash);
#ifdef PICO_PLATFORM
        if (requested) {
            commit_requested = false;
            sem_release(&sem_commit_done);
        }
#endif
    }
    sem_release(&sem_flash);
}

#ifdef PICO_RP2040
void phymarker_write();
#endif
//this function has to be called from the core 0
void low_flash_init() {
#ifdef PICO_RP2040
    phymarker_write();
#endif
    memset(flash_pages, 0, sizeof(page_flash_t) * TOTAL_FLASH_PAGES);
    mutex_init(&mtx_flash);
    sem_init(&sem_flash, 0, 1);
#ifdef PICO_PLATFORM
    sem_init(&sem_commit_done, 0, 1);
#endif

    uint32_t data_start_addr;
    uint32_t data_end_addr;
#if defined(ESP_PLATFORM)
    part0 = esp_partition_find_first(0x40, 0x1, "part0");
    esp_partition_mmap(part0, 0, part0->size, ESP_PARTITION_MMAP_DATA, (const void **)&map, (esp_partition_mmap_handle_t *)&fd_map);
    data_start_addr = 0;
    data_end_addr = part0->size;
    FLASH_SIZE_BYTES = part0->size;
#elif defined(PICO_PLATFORM)
    uint8_t txbuf[6] = {0x9f};
    uint8_t rxbuf[6] = {0};
    flash_do_cmd(txbuf, rxbuf, 4);

    FLASH_SIZE_BYTES = (1 << rxbuf[3]);
#ifdef PICO_RP2350
    __attribute__((aligned(4))) uint8_t workarea[4 * 1024];
    int rc = rom_load_partition_table(workarea, sizeof(workarea), false);
    if (rc) {
        reset_usb_boot(0, 0);
    }

    uint8_t boot_partition = 1;
    rc = rom_get_partition_table_info((uint32_t*)workarea, 0x8, PT_INFO_PARTITION_LOCATION_AND_FLAGS | PT_INFO_SINGLE_PARTITION | (boot_partition << 24));

    if (rc != 3) {
        data_start_addr = (FLASH_SIZE_BYTES >> 1);
        data_end_addr = FLASH_SIZE_BYTES;
    } else {
        uint16_t first_sector_number = (((uint32_t*)workarea)[1] & PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_BITS) >> PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_LSB;
        uint16_t last_sector_number = (((uint32_t*)workarea)[1] & PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS) >> PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB;
        data_start_addr = first_sector_number * FLASH_SECTOR_SIZE;
        data_end_addr = (last_sector_number + 1) * FLASH_SECTOR_SIZE;
        if (data_end_addr > FLASH_SIZE_BYTES) {
            data_end_addr = FLASH_SIZE_BYTES;
        }
    }
    data_end_addr -= 2 * FLASH_SECTOR_SIZE;
#else
    data_start_addr = (FLASH_SIZE_BYTES >> 1);
    data_end_addr = FLASH_SIZE_BYTES;
#endif

    data_start_addr += XIP_BASE;
    data_end_addr += XIP_BASE;
#else
    const char *flash_path = getenv("PICO_FLASH_FILE");
    fd_map = open(flash_path && *flash_path ? flash_path : "memory.flash", O_RDWR | O_CREAT, (mode_t) 0600);
    lseek(fd_map, FLASH_SIZE_BYTES - 1, SEEK_SET);
    write(fd_map, "", 1);
    map = mmap(0, FLASH_SIZE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd_map, 0);
    data_start_addr = 0;
    data_end_addr = FLASH_SIZE_BYTES;
    fault_init();
#endif
    flash_set_bounds(data_start_addr, data_end_addr);

    /* Place the journal at the bottom of the data pool if it is free. */
    uintptr_t lowest = lowest_live_record(data_start_addr, end_data_pool);
    if (lowest >= data_start_addr + JOURNAL_SIZE && data_end_addr - data_start_addr > 4 * JOURNAL_SIZE) {
        journal_base = data_start_addr;
        journal_active = true;
        journal_recover();
        flash_set_bounds(data_start_addr + JOURNAL_SIZE, data_end_addr);
    }
    else {
        journal_active = false;
        printf("[low_flash] WARNING: journal disabled, data occupies the journal area\n");
    }
}

void low_flash_init_core1() {
    mutex_enter_blocking(&mtx_flash);
    multicore_lockout_victim_init();
    locked_out = true;
    mutex_exit(&mtx_flash);
}

void wait_flash_finish() {
    sem_acquire_blocking(&sem_flash); //blocks until released
    //wake up
    sem_acquire_blocking(&sem_flash); //decrease permits
}

void low_flash_available() {
    mutex_enter_blocking(&mtx_flash);
    flash_available = true;
    mutex_exit(&mtx_flash);
}

/* Must be called with mtx_flash held. When the cache is full inside a long
 * operation the batch collected so far is committed (atomically) so the
 * operation can continue instead of silently dropping writes. */
static page_flash_t *find_free_page(uintptr_t addr) {
    uintptr_t addr_alg = addr & -FLASH_SECTOR_SIZE;
    for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
        if ((flash_pages[r].ready || flash_pages[r].erase) && flash_pages[r].address == addr_alg) {
            return &flash_pages[r];
        }
    }
    if (ready_pages == TOTAL_FLASH_PAGES) {
#ifdef PICO_PLATFORM
        if (get_core_num() != 0) {
            printf("ERROR: ALL FLASH PAGES CACHED\n");
            return NULL;
        }
#endif
        printf("[low_flash] cache full, committing partial batch\n");
        if (commit_locked() != PICOKEY_OK) {
            return NULL;
        }
    }
    for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
        if (!flash_pages[r].ready && !flash_pages[r].erase) {
            page_flash_t *p = &flash_pages[r];
#ifdef PICO_PLATFORM
            memcpy(p->page, (uint8_t *) addr_alg, FLASH_SECTOR_SIZE);
#else
            if (addr >= start_data_pool && addr <= end_rom_pool + sizeof(uintptr_t)) {
                memcpy(p->page, map + addr_alg, FLASH_SECTOR_SIZE);
            }
            else {
                memcpy(p->page, (uint8_t *) addr_alg, FLASH_SECTOR_SIZE);
            }
#endif
            ready_pages++;
            p->address = addr_alg;
            p->ready = true;
            return p;
        }
    }
    return NULL;
}

int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len) {
    page_flash_t *p = NULL;

    if (!data || len == 0) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    if ((addr & (FLASH_SECTOR_SIZE - 1)) + len > FLASH_SECTOR_SIZE) {
        /* Records never straddle sectors; refuse instead of corrupting. */
        return PICOKEY_ERR_MEMORY_FATAL;
    }

    mutex_enter_blocking(&mtx_flash);
    if (!(p = find_free_page(addr))) {
        mutex_exit(&mtx_flash);
        printf("ERROR: FLASH CANNOT FIND A PAGE\n");
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    if (p->erase) {
        /* Writing into a sector queued for erase turns it into a write of an
         * erased image with this data on top. */
        memset(p->page, 0xFF, FLASH_SECTOR_SIZE);
        p->erase = false;
        p->ready = true;
    }
    memcpy(&p->page[addr & (FLASH_SECTOR_SIZE - 1)], data, len);
    mutex_exit(&mtx_flash);
    return PICOKEY_OK;
}

int flash_program_halfword(uintptr_t addr, uint16_t data) {
    return flash_program_block(addr, (const uint8_t *) &data, sizeof(uint16_t));
}

int flash_program_word(uintptr_t addr, uint32_t data) {
    return flash_program_block(addr,  (const uint8_t *) &data, sizeof(uint32_t));
}

int flash_program_uintptr(uintptr_t addr, uintptr_t data) {
    return flash_program_block(addr,  (const uint8_t *) &data, sizeof(uintptr_t));
}

uint8_t *flash_read(uintptr_t addr) {
    uintptr_t addr_alg = addr & -FLASH_SECTOR_SIZE;
    mutex_enter_blocking(&mtx_flash);
    if (ready_pages > 0) {
        for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
            if (flash_pages[r].ready && flash_pages[r].address == addr_alg) {
                uint8_t *v = &flash_pages[r].page[addr & (FLASH_SECTOR_SIZE - 1)];
                mutex_exit(&mtx_flash);
                return v;
            }
        }
    }
    uint8_t *v = (uint8_t *) addr;
    mutex_exit(&mtx_flash);
#if !defined(PICO_PLATFORM)
    if (addr >= start_data_pool && addr <= end_rom_pool + sizeof(uintptr_t)) {
        v += (uintptr_t) map;
    }
#endif
    return v;
}

uintptr_t flash_read_uintptr(uintptr_t addr) {
    uint8_t *p = flash_read(addr);
    uintptr_t v = 0x0;
    for (size_t i = 0; i < sizeof(uintptr_t); i++) {
        v |= (uintptr_t) p[i] << (8 * i);
    }
    return v;
}
uint16_t flash_read_uint16(uintptr_t addr) {
    uint8_t *p = flash_read(addr);
    uint16_t v = 0x0;
    for (size_t i = 0; i < sizeof(uint16_t); i++) {
        v |= p[i] << (8 * i);
    }
    return v;
}
uint8_t flash_read_uint8(uintptr_t addr) {
    return *flash_read(addr);
}

int flash_erase_page(uintptr_t addr, size_t page_size) {
    page_flash_t *p = NULL;

    mutex_enter_blocking(&mtx_flash);
    if (!(p = find_free_page(addr))) {
        printf("ERROR: FLASH CANNOT FIND A PAGE (rare error)\n");
        mutex_exit(&mtx_flash);
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    p->erase = true;
    p->ready = false;
    p->page_size = page_size;
    mutex_exit(&mtx_flash);

    return PICOKEY_OK;
}

bool flash_check_blank(const uint8_t *p_start, size_t size) {
    const uint8_t *p;

    for (p = p_start; p < p_start + size; p++) {
        if (*p != 0xff) {
            return false;
        }
    }
    return true;
}

#ifdef PICO_RP2040
typedef struct {
    uint64_t magic;
    uint16_t version;
    uint16_t flags;
    uint8_t  uid[PICO_UNIQUE_BOARD_ID_SIZE_BYTES];
    uint32_t crc32;
} __attribute__ ((packed)) phymarker_t;

uintptr_t __phymarker_start = (uintptr_t)0x10100000;

const uint64_t PHYSICAL_MARKER_MAGIC = 0x5049434F4B455953ULL; // "PICOKEYS"

void phymarker_write() {
    const uint64_t magic = *(uint64_t *)__phymarker_start;
    if (magic == PHYSICAL_MARKER_MAGIC) {
        return;
    }
    phymarker_t pm = {
        .magic = PHYSICAL_MARKER_MAGIC, // "PICOKEYS"
        .version = 0x0001,
        .flags = 0x0000,
        .crc32 = 0x00000000
    };
    memcpy(pm.uid, pico_serial.id, PICO_UNIQUE_BOARD_ID_SIZE_BYTES);
    pm.crc32 = crc32c((const uint8_t *)&pm, sizeof(phymarker_t) - sizeof(uint32_t));

    uint8_t buf[FLASH_PAGE_SIZE] = {0};
    memcpy(buf, &pm, sizeof(phymarker_t));
    uint32_t ints = save_and_disable_interrupts();

    flash_range_erase((uint32_t)__phymarker_start - XIP_BASE, FLASH_SECTOR_SIZE);
    flash_range_program((uint32_t)__phymarker_start - XIP_BASE, (const uint8_t *)buf, sizeof(buf));

    restore_interrupts(ints);
}

#endif
