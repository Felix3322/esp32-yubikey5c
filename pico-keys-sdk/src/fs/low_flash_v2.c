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
 * File system flash access for ESP32 and the host emulator.
 *
 * The file system addresses the logical space of the mounted profile store
 * (lf_store.c). Writes land in a RAM cache of whole sectors; a commit hands
 * the dirty sectors to lf_store_commit(), which persists them as one atomic,
 * mirrored and error-corrected transaction. Commands run as one transaction
 * (low_flash_txn_begin/end), durable before their response is released.
 *
 * RP2040/RP2350 builds use low_flash.c instead.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "pico_keys.h"
#include "low_flash.h"
#include "lf_store.h"
#ifdef ESP_PLATFORM
#include "esp_compat.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#else
#include "queue.h"
#include <pthread.h>
#endif

#define TOTAL_FLASH_PAGES   LF_STORE_MAX_DIRTY

typedef struct {
    uint8_t page[LF_SECTOR_SIZE];
    uintptr_t address;
    bool ready;
} page_flash_t;

static page_flash_t flash_pages[TOTAL_FLASH_PAGES];
static mutex_t mtx_flash;
static semaphore_t sem_flash;
static uint8_t ready_pages = 0;
static volatile int txn_depth = 0;
static volatile int op_depth = 0;
static uint32_t commit_failures = 0;
/* The outermost transaction: whether its uncommitted writes are all its own
 * (clean cache at its start) and none of them was committed behind its
 * back (full cache, another task's commit). */
static bool txn_abortable = false;
static bool txn_partial = false;
bool flash_available = false;

extern void scan_flash();

#if defined(ESP_PLATFORM)
typedef TaskHandle_t task_id_t;
static task_id_t task_self(void) {
    return xTaskGetCurrentTaskHandle();
}
static bool task_same(task_id_t a, task_id_t b) {
    return a == b;
}
#else
typedef pthread_t task_id_t;
static task_id_t task_self(void) {
    return pthread_self();
}
static bool task_same(task_id_t a, task_id_t b) {
    return pthread_equal(a, b) != 0;
}
#endif
static task_id_t txn_owner;

/* ------------------------------------------------------------------------ */
/* Operation lock                                                           */
/* ------------------------------------------------------------------------ */

/* Held by the task running a file system operation (low_flash_op_begin to
 * low_flash_op_end) and by every commit: a commit from another task (core 0
 * reboot, profile switch, OTP typing, do_flash) waits until the operation
 * is whole. Recursive: the operation's own task may commit inside it (the
 * reservation does). Order: op lock, then mtx_flash, then the store lock. */
#if defined(ESP_PLATFORM)
static SemaphoreHandle_t op_mtx = NULL;
static void op_init(void) {
    if (op_mtx == NULL) {
        op_mtx = xSemaphoreCreateRecursiveMutex();
    }
}
static void op_lock(void) {
    op_init();
    xSemaphoreTakeRecursive(op_mtx, portMAX_DELAY);
}
static bool op_trylock(void) {
    op_init();
    return xSemaphoreTakeRecursive(op_mtx, 0) == pdTRUE;
}
static void op_unlock(void) {
    xSemaphoreGiveRecursive(op_mtx);
}
#else
static pthread_mutex_t op_mtx;
static pthread_once_t op_once = PTHREAD_ONCE_INIT;
static void op_mtx_init(void) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&op_mtx, &attr);
    pthread_mutexattr_destroy(&attr);
}
static void op_lock(void) {
    pthread_once(&op_once, op_mtx_init);
    pthread_mutex_lock(&op_mtx);
}
static bool op_trylock(void) {
    pthread_once(&op_once, op_mtx_init);
    return pthread_mutex_trylock(&op_mtx) == 0;
}
static void op_unlock(void) {
    pthread_mutex_unlock(&op_mtx);
}
#endif

/* ------------------------------------------------------------------------ */
/* Commit                                                                   */
/* ------------------------------------------------------------------------ */

/* Must be called with mtx_flash held. */
static int commit_locked(void) {
    if (ready_pages == 0) {
        return PICOKEY_OK;
    }
    lf_dirty_t dirty[TOTAL_FLASH_PAGES];
    int n = 0;
    for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
        if (flash_pages[r].ready) {
            dirty[n].lsn = (uint32_t) (flash_pages[r].address / LF_SECTOR_SIZE);
            dirty[n].image = flash_pages[r].page;
            n++;
        }
    }
    int ret = lf_store_commit(dirty, n);
    if (ret == PICOKEY_OK) {
        for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
            flash_pages[r].ready = false;
        }
        ready_pages = 0;
    }
    else {
        /* The pages stay cached (and visible); the next commit retries. */
        commit_failures++;
        printf("[low_flash] ERROR: commit failed (%d)\n", ret);
    }
    return ret;
}

/* Must be called with mtx_flash held: a commit that the running transaction
 * did not ask for (full cache, another task) takes part of it along. */
static int commit_implicit(void) {
    if (txn_depth > 0 && ready_pages > 0) {
        txn_partial = true;
    }
    return commit_locked();
}

/* Waits for a file system operation of another task to end first. */
int low_flash_commit(void) {
    op_lock();
    mutex_enter_blocking(&mtx_flash);
    int ret = txn_depth > 0 && !task_same(task_self(), txn_owner) ? commit_implicit() : commit_locked();
    flash_available = false;
    mutex_exit(&mtx_flash);
    op_unlock();
    return ret;
}

/* Nested or concurrent transactions (the card thread's command, OTP typing
 * on core 0) are counted: the background commit waits for all of them. The
 * outermost one starts with a clean cache (writes left from outside a
 * command are committed first), so it can be abandoned as a whole. */
void low_flash_txn_begin(void) {
    op_lock();
    mutex_enter_blocking(&mtx_flash);
    if (txn_depth == 0) {
        txn_abortable = commit_locked() == PICOKEY_OK;
        txn_partial = false;
        txn_owner = task_self();
    }
    else {
        txn_partial = true;         /* two transactions share the cache */
    }
    txn_depth++;
    mutex_exit(&mtx_flash);
    op_unlock();
}

int low_flash_txn_end(void) {
    mutex_enter_blocking(&mtx_flash);
    if (txn_depth > 0) {
        txn_depth--;
    }
    mutex_exit(&mtx_flash);
    return low_flash_commit();
}

int low_flash_txn_abort(void) {
    op_lock();
    mutex_enter_blocking(&mtx_flash);
    /* Only the caller's own transaction, and only if nothing of it reached
     * the store unasked (a full cache, another task's commit). What it
     * committed itself (retry counters) stays. */
    int ret = txn_depth == 1 && txn_abortable && !txn_partial && task_same(task_self(), txn_owner) ?
              PICOKEY_OK : PICOKEY_ERR_BLOCKED;
    if (ret == PICOKEY_OK) {
        for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
            flash_pages[r].ready = false;
        }
        ready_pages = 0;
        flash_available = false;
    }
    mutex_exit(&mtx_flash);
    if (ret == PICOKEY_OK) {
        /* The file table as the store has it: the transaction's new, moved
         * and deleted records are forgotten. */
        scan_flash();
    }
    op_unlock();
    return ret;
}

bool low_flash_journal_active(void) {
    return lf_store_mounted() && !lf_store_read_only();
}

uint32_t low_flash_commit_failures(void) {
    return commit_failures;
}

bool low_flash_region_blank(uintptr_t addr, size_t len) {
    return lf_store_blank(addr, len);
}

/* Called from the core 0 loop: persists writes made outside commands, never
 * in the middle of a file system operation or a transaction (it tries again
 * at the next loop). */
void do_flash() {
    if (op_trylock()) {
        if (mutex_try_enter(&mtx_flash, NULL) == true) {
            if (ready_pages > 0 && flash_available == true && txn_depth == 0) {
                commit_locked();
            }
            flash_available = false;
            mutex_exit(&mtx_flash);
        }
        op_unlock();
    }
    sem_release(&sem_flash);
}

void low_flash_op_begin(void) {
    op_lock();
    op_depth++;
}

void low_flash_op_end(void) {
    if (op_depth > 0) {
        op_depth--;
    }
    op_unlock();
}

int low_flash_reserve(const uintptr_t *addrs, int n) {
    uintptr_t need[TOTAL_FLASH_PAGES];
    int k = 0;
    for (int i = 0; i < n; i++) {
        uintptr_t a = addrs[i] & -LF_SECTOR_SIZE;
        bool dup = false;
        for (int j = 0; j < k && !dup; j++) {
            dup = need[j] == a;
        }
        if (!dup) {
            if (k == TOTAL_FLASH_PAGES) {
                return PICOKEY_ERR_NO_MEMORY;   /* larger than any transaction */
            }
            need[k++] = a;
        }
    }
    mutex_enter_blocking(&mtx_flash);
    int missing = 0;
    for (int j = 0; j < k; j++) {
        bool cached = false;
        for (int r = 0; r < TOTAL_FLASH_PAGES && !cached; r++) {
            cached = flash_pages[r].ready && flash_pages[r].address == need[j];
        }
        missing += !cached;
    }
    int ret = PICOKEY_OK;
    if (ready_pages + missing > TOTAL_FLASH_PAGES) {
        /* Commit the operations collected so far (a boundary between whole
         * operations), so this one is never split. */
        printf("[low_flash] cache full, committing the operations so far\n");
        ret = commit_implicit();
    }
    mutex_exit(&mtx_flash);
    return ret;
}

void low_flash_init() {
    memset(flash_pages, 0, sizeof(flash_pages));
    mutex_init(&mtx_flash);
    sem_init(&sem_flash, 0, 1);
#if defined(ESP_PLATFORM)
    op_init();          /* before any other task can race to create it */
#endif
}

void low_flash_init_core1() {
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

/* ------------------------------------------------------------------------ */
/* Cache                                                                    */
/* ------------------------------------------------------------------------ */

/* Must be called with mtx_flash held. A full cache commits the batch
 * collected so far (atomically) and continues; the file system reserves its
 * sectors beforehand (low_flash_reserve), so this only happens between its
 * operations. */
static page_flash_t *find_free_page(uintptr_t addr) {
    uintptr_t addr_alg = addr & -LF_SECTOR_SIZE;
    for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
        if (flash_pages[r].ready && flash_pages[r].address == addr_alg) {
            return &flash_pages[r];
        }
    }
    if (ready_pages == TOTAL_FLASH_PAGES) {
        if (op_depth > 0) {
            printf("[low_flash] WARNING: cache full inside an operation\n");
        }
        if (commit_implicit() != PICOKEY_OK) {
            return NULL;
        }
    }
    for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
        if (!flash_pages[r].ready) {
            page_flash_t *p = &flash_pages[r];
            memcpy(p->page, lf_store_ptr(addr_alg), LF_SECTOR_SIZE);
            ready_pages++;
            p->address = addr_alg;
            p->ready = true;
            return p;
        }
    }
    return NULL;
}

static bool addr_valid(uintptr_t addr, size_t len) {
    return lf_store_mounted() && !lf_store_read_only() && addr + len <= LF_STORE_LOGICAL_SIZE;
}

int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len) {
    page_flash_t *p = NULL;
    if (!data || len == 0) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    if (!addr_valid(addr, len) || (addr & (LF_SECTOR_SIZE - 1)) + len > LF_SECTOR_SIZE) {
        /* Outside the store or straddling sectors: refuse, never corrupt. */
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    mutex_enter_blocking(&mtx_flash);
    if (!(p = find_free_page(addr))) {
        mutex_exit(&mtx_flash);
        printf("ERROR: FLASH CANNOT FIND A PAGE\n");
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    memcpy(&p->page[addr & (LF_SECTOR_SIZE - 1)], data, len);
    mutex_exit(&mtx_flash);
    return PICOKEY_OK;
}

int flash_program_halfword(uintptr_t addr, uint16_t data) {
    return flash_program_block(addr, (const uint8_t *) &data, sizeof(uint16_t));
}

int flash_program_word(uintptr_t addr, uint32_t data) {
    return flash_program_block(addr, (const uint8_t *) &data, sizeof(uint32_t));
}

int flash_program_uintptr(uintptr_t addr, uintptr_t data) {
    return flash_program_block(addr, (const uint8_t *) &data, sizeof(uintptr_t));
}

extern uintptr_t start_data_pool, end_flash;

uint8_t *flash_read(uintptr_t addr) {
    if (addr < start_data_pool || addr >= end_flash) {
        /* Static files without FILE_DATA_FLASH carry a pointer to constant
         * data in memory instead of a store address. */
        return (uint8_t *) addr;
    }
    uintptr_t addr_alg = addr & -LF_SECTOR_SIZE;
    mutex_enter_blocking(&mtx_flash);
    if (ready_pages > 0) {
        for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
            if (flash_pages[r].ready && flash_pages[r].address == addr_alg) {
                uint8_t *v = &flash_pages[r].page[addr & (LF_SECTOR_SIZE - 1)];
                mutex_exit(&mtx_flash);
                return v;
            }
        }
    }
    mutex_exit(&mtx_flash);
    return lf_store_ptr(addr);
}

/* Little-endian field of n bytes. A field that crosses a sector boundary
 * (records of earlier firmware) is read byte by byte: the two sectors may
 * come from different places (cache page, copy A or B). */
static uint64_t read_field(uintptr_t addr, size_t n) {
    uint64_t v = 0;
    if ((addr & (LF_SECTOR_SIZE - 1)) + n <= LF_SECTOR_SIZE) {
        const uint8_t *p = flash_read(addr);
        for (size_t i = 0; i < n; i++) {
            v |= (uint64_t) p[i] << (8 * i);
        }
    }
    else {
        for (size_t i = 0; i < n; i++) {
            v |= (uint64_t) *flash_read(addr + i) << (8 * i);
        }
    }
    return v;
}

uintptr_t flash_read_uintptr(uintptr_t addr) {
    return (uintptr_t) read_field(addr, sizeof(uintptr_t));
}

uint16_t flash_read_uint16(uintptr_t addr) {
    return (uint16_t) read_field(addr, sizeof(uint16_t));
}

uint8_t flash_read_uint8(uintptr_t addr) {
    return *flash_read(addr);
}

int flash_erase_page(uintptr_t addr, size_t page_size) {
    uint8_t ff[64];
    memset(ff, 0xFF, sizeof(ff));
    for (size_t off = 0; off < page_size; off += sizeof(ff)) {
        int r = flash_program_block(addr + off, ff, sizeof(ff));
        if (r != PICOKEY_OK) {
            return r;
        }
    }
    return PICOKEY_OK;
}

bool flash_check_blank(const uint8_t *p_start, size_t size) {
    for (const uint8_t *p = p_start; p < p_start + size; p++) {
        if (*p != 0xff) {
            return false;
        }
    }
    return true;
}

/* Drops every cached write (used when switching the mounted store). */
void low_flash_discard_cache(void) {
    mutex_enter_blocking(&mtx_flash);
    for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
        flash_pages[r].ready = false;
    }
    ready_pages = 0;
    flash_available = false;
    mutex_exit(&mtx_flash);
}
