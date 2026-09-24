/*
 * Host harness for the file system records (pico-keys-sdk/src/fs/flash.c)
 * on top of the real write cache (low_flash_v2.c). The profile store below
 * them is a model: lf_store_commit() persists the dirty sectors into a flat
 * image, and every commit checks what a power cut right after it would leave:
 *
 *  - both record lists walk cleanly (every record below the one linking to
 *    it, inside the pool, a payload never across a sector boundary, a small
 *    record not even with its header, fids unique);
 *  - the files they hold are exactly those of the last completed operation
 *    (the test tells the harness which operation has completed): the cache
 *    never persists part of an operation. During a concurrent run, the file
 *    being written may show its old or its new content, nothing else.
 *
 * Records of earlier firmware (payloads up to a whole sector, damaged length
 * fields) are planted straight into the image (h_plant).
 *
 * Built and driven by tests/unit/test_flash_records.py.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "pico_keys.h"
#include "file.h"
#include "low_flash.h"
#include "lf_store.h"

#define STORE_SIZE      LF_STORE_LOGICAL_SIZE
#define MAX_FILES       512
#define REC_HDR         (2 * sizeof(uintptr_t) + 2 * sizeof(uint16_t))
#define MAX_SMALL       (LF_SECTOR_SIZE - REC_HDR)

extern void flash_set_bounds(uintptr_t start, uintptr_t end);
extern int flash_write_data_to_file(file_t *file, const uint8_t *data, uint16_t len);
extern int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len);
extern uintptr_t end_rom_pool, start_rom_pool, end_data_pool, start_data_pool;
extern void low_flash_init(void);

static uint8_t image[STORE_SIZE];

/* Expected content: files as of the last completed operation. */
typedef struct {
    uint16_t fid;
    bool present;
    uint16_t len;
    uintptr_t planted;          /* where h_plant put it (earlier firmware's placement) */
    uint8_t data[LF_SECTOR_SIZE];
} model_t;
static model_t model[MAX_FILES];
static int nmodel = 0;
/* A file whose operation is under way (concurrent run): old or new content. */
static int inflight = -1;
static model_t inflight_old;
static pthread_mutex_t model_mtx = PTHREAD_MUTEX_INITIALIZER;

static file_t files[MAX_FILES];
static int nfiles = 0;

static int commits = 0, failures = 0;
static char last_error[256];

void mbedtls_platform_zeroize(void *p, size_t n) {
    volatile uint8_t *v = p;
    while (n--) {
        *v++ = 0;
    }
}

/* -- model store -------------------------------------------------------- */

bool lf_store_mounted(void) {
    return true;
}

bool lf_store_read_only(void) {
    return false;
}

bool lf_store_blank(uintptr_t addr, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (image[addr + i] != 0xFF) {
            return false;
        }
    }
    return true;
}

uint8_t *lf_store_ptr(uintptr_t addr) {
    return image + addr;
}

static void fail(const char *msg, uintptr_t a, uintptr_t b) {
    failures++;
    snprintf(last_error, sizeof(last_error), "commit %d: %s (%lx, %lx)", commits, msg,
             (unsigned long) a, (unsigned long) b);
}

static uintptr_t rd_ptr(uintptr_t a) {
    uintptr_t v;
    memcpy(&v, image + a, sizeof(v));
    return v;
}

static uint16_t rd_u16(uintptr_t a) {
    uint16_t v;
    memcpy(&v, image + a, sizeof(v));
    return v;
}

static model_t *model_of(uint16_t fid) {
    for (int i = 0; i < nmodel; i++) {
        if (model[i].fid == fid) {
            return &model[i];
        }
    }
    return NULL;
}

static bool content_is(const model_t *m, uintptr_t r, uint16_t len) {
    return m->present && len == m->len && memcmp(image + r + REC_HDR, m->data, len) == 0;
}

/* Walks one list of the persisted image; marks the fids found. */
static void check_list(uintptr_t head, uintptr_t start, bool *seen) {
    uintptr_t above = head;
    int guard = 0;
    for (uintptr_t r = rd_ptr(head); r != 0; above = r, r = rd_ptr(r)) {
        if (r < start || r >= above || ++guard > 4096) {
            fail("list leaves its pool or goes up", above, r);
            return;
        }
        uint16_t fid = rd_u16(r + 2 * sizeof(uintptr_t));
        uint16_t len = rd_u16(r + 2 * sizeof(uintptr_t) + sizeof(uint16_t));
        uintptr_t payload = r + REC_HDR;
        uintptr_t room = LF_SECTOR_SIZE - (payload & (LF_SECTOR_SIZE - 1));
        if (len > room) {
            len = (uint16_t) room;      /* a damaged length, as the firmware reads it */
        }
        model_t *m = model_of(fid);
        if (len > 0 && payload / LF_SECTOR_SIZE != (payload + len - 1) / LF_SECTOR_SIZE) {
            fail("payload crosses a sector", r, len);
        }
        /* only a record of earlier firmware (rewritten in place) may keep
         * its header in the sector below with a small payload */
        if (len <= MAX_SMALL && r / LF_SECTOR_SIZE != (payload + (len ? len : 1) - 1) / LF_SECTOR_SIZE &&
            !(m && m->planted == r)) {
            fail("small record crosses a sector", r, len);
        }
        int idx = m ? (int) (m - model) : -1;
        if (!m) {
            fail("file that should not exist", fid, r);
            continue;
        }
        if (seen[idx]) {
            fail("file linked twice", fid, r);
        }
        seen[idx] = true;
        bool ok = content_is(m, r, len) || (idx == inflight && content_is(&inflight_old, r, len));
        if (!ok) {
            fail(m->present || idx == inflight ? "file content is not that of a completed operation"
                                               : "file that should not exist", fid, len);
        }
    }
}

static void check_image(void) {
    bool seen[MAX_FILES];
    memset(seen, 0, sizeof(seen));
    pthread_mutex_lock(&model_mtx);
    check_list(end_rom_pool, start_rom_pool, seen);
    check_list(end_data_pool, start_data_pool, seen);
    for (int i = 0; i < nmodel; i++) {
        /* the file being written must be there only if both its states have it */
        bool must = i == inflight ? model[i].present && inflight_old.present : model[i].present;
        if (must && !seen[i]) {
            fail("file lost", model[i].fid, 0);
        }
    }
    pthread_mutex_unlock(&model_mtx);
}

int lf_store_commit(const lf_dirty_t *dirty, int n) {
    for (int i = 0; i < n; i++) {
        if (dirty[i].lsn >= LF_STORE_LOGICAL_SECTORS) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        if (dirty[i].image) {
            memcpy(image + dirty[i].lsn * LF_SECTOR_SIZE, dirty[i].image, LF_SECTOR_SIZE);
        }
        else {
            memset(image + dirty[i].lsn * LF_SECTOR_SIZE, 0xFF, LF_SECTOR_SIZE);
        }
    }
    commits++;
    check_image();
    return PICOKEY_OK;
}

/* -- driver -------------------------------------------------------------- */

static file_t *file_of(uint16_t fid, bool persistent) {
    for (int i = 0; i < nfiles; i++) {
        if (files[i].fid == fid) {
            return &files[i];
        }
    }
    if (nfiles == MAX_FILES) {
        return NULL;
    }
    file_t f = {
        .fid = fid, .parent = 0, .name = NULL,
        .type = (uint8_t) (FILE_TYPE_WORKING_EF | FILE_DATA_FLASH | (persistent ? FILE_PERSISTENT : 0)),
        .ef_structure = FILE_EF_TRANSPARENT, .data = NULL, .acl = { 0 }
    };
    memcpy(&files[nfiles], &f, sizeof(f));
    return &files[nfiles++];
}

static model_t *model_new(uint16_t fid) {
    model_t *m = model_of(fid);
    if (!m && nmodel < MAX_FILES) {
        m = &model[nmodel++];
        memset(m, 0, sizeof(*m));
        m->fid = fid;
    }
    return m;
}

void h_init(void) {
    memset(image, 0xFF, sizeof(image));
    memset(model, 0, sizeof(model));
    nmodel = nfiles = commits = failures = 0;
    inflight = -1;
    last_error[0] = 0;
    low_flash_init();
    flash_allow_sector_records(false);
    flash_set_bounds(LF_SECTOR_SIZE, STORE_SIZE);
    uint8_t empty[2 * sizeof(uintptr_t)];
    memset(empty, 0, sizeof(empty));
    flash_program_block(end_data_pool, empty, sizeof(empty));
    flash_program_block(end_rom_pool, empty, sizeof(empty));
    low_flash_commit();
}

void h_allow_sector_records(int on) {
    flash_allow_sector_records(on != 0);
}

/* A write of fid whose outcome a concurrent commit may catch half-way: the
 * model holds the new content during the write, the old one as the
 * alternative. */
static int put(uint16_t fid, int persistent, const uint8_t *data, uint16_t len) {
    file_t *f = file_of(fid, persistent != 0);
    if (!f) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    pthread_mutex_lock(&model_mtx);
    model_t *m = model_new(fid);
    inflight_old = *m;
    inflight = (int) (m - model);
    m->present = true;
    m->len = len;
    memcpy(m->data, data, len);
    pthread_mutex_unlock(&model_mtx);
    int r = flash_write_data_to_file(f, data, len);
    pthread_mutex_lock(&model_mtx);
    if (r != PICOKEY_OK) {
        *m = inflight_old;
    }
    inflight = -1;
    pthread_mutex_unlock(&model_mtx);
    return r;
}

int h_put(uint16_t fid, int persistent, const uint8_t *data, uint16_t len) {
    return put(fid, persistent, data, len);
}

/* Copies one file into another straight from the file system's pointer (it
 * may point into a cached sector the write replaces). */
int h_copy(uint16_t src, uint16_t dst, int persistent) {
    file_t *s = file_of(src, false);
    if (!s || !s->data) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint16_t len = file_get_size(s);
    uint8_t expect[LF_SECTOR_SIZE];
    memcpy(expect, file_get_data(s), len);
    file_t *d = file_of(dst, persistent != 0);
    if (!d) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    int r = flash_write_data_to_file(d, file_get_data(s), len);
    if (r == PICOKEY_OK) {
        pthread_mutex_lock(&model_mtx);
        model_t *m = model_new(dst);
        m->present = true;
        m->len = len;
        memcpy(m->data, expect, len);
        pthread_mutex_unlock(&model_mtx);
    }
    return r;
}

static int del(uint16_t fid) {
    file_t *f = file_of(fid, false);
    if (!f) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    pthread_mutex_lock(&model_mtx);
    model_t *m = model_new(fid);
    inflight_old = *m;
    inflight = (int) (m - model);
    m->present = false;
    pthread_mutex_unlock(&model_mtx);
    int r = flash_clear_file(f);
    pthread_mutex_lock(&model_mtx);
    if (r != PICOKEY_OK) {
        *m = inflight_old;
    }
    inflight = -1;
    pthread_mutex_unlock(&model_mtx);
    return r;
}

int h_delete(uint16_t fid) {
    return del(fid);
}

int h_commit(void) {
    return low_flash_commit();
}

/* A record as earlier firmware stored it, written straight into the image
 * at the end of the data list: len payload bytes ending at a sector
 * boundary (its header may lie in the sector below), stored_len in its
 * length field (a damaged one to test the bounds). Commits first. */
int h_plant(uint16_t fid, const uint8_t *data, uint16_t len, uint16_t stored_len) {
    if (low_flash_commit() != PICOKEY_OK) {
        return -1;
    }
    uintptr_t base = end_data_pool;
    for (uintptr_t n = rd_ptr(base); n != 0; n = rd_ptr(base)) {
        base = n;
    }
    uintptr_t rec = (base & ~(uintptr_t) (LF_SECTOR_SIZE - 1)) - (len + REC_HDR);
    if (rec < start_data_pool) {
        return -1;
    }
    uintptr_t zero = 0;
    memcpy(image + rec, &zero, sizeof(zero));
    memcpy(image + rec + sizeof(uintptr_t), &base, sizeof(base));
    memcpy(image + rec + 2 * sizeof(uintptr_t), &fid, sizeof(fid));
    memcpy(image + rec + 2 * sizeof(uintptr_t) + sizeof(uint16_t), &stored_len, sizeof(stored_len));
    memcpy(image + rec + REC_HDR, data, len);
    memcpy(image + base, &rec, sizeof(rec));
    file_t *f = file_of(fid, false);
    f->data = (uint8_t *) (rec + 2 * sizeof(uintptr_t) + sizeof(uint16_t));
    pthread_mutex_lock(&model_mtx);
    model_t *m = model_new(fid);
    m->present = true;
    m->len = len;
    m->planted = rec;
    memcpy(m->data, data, len);
    pthread_mutex_unlock(&model_mtx);
    return 0;
}

/* Overwrites the next pointer of fid's record in the image (a write lost to
 * earlier firmware). Commits first. */
int h_damage_next(uint16_t fid, uintptr_t value) {
    if (low_flash_commit() != PICOKEY_OK) {
        return -1;
    }
    file_t *f = file_of(fid, false);
    if (!f || !f->data) {
        return -1;
    }
    uintptr_t rec = (uintptr_t) f->data - 2 * sizeof(uintptr_t) - sizeof(uint16_t);
    memcpy(image + rec, &value, sizeof(value));
    return 0;
}

/* Address of fid's record, 0 if it has none. */
uintptr_t h_record(uint16_t fid) {
    file_t *f = file_of(fid, false);
    return f && f->data ? (uintptr_t) f->data - 2 * sizeof(uintptr_t) - sizeof(uint16_t) : 0;
}

/* Copies n bytes of the persisted image at off. */
void h_image(uintptr_t off, uint8_t *out, size_t n) {
    memcpy(out, image + off, n);
}

/* The file system's own view (cache included) matches the model. */
int h_verify_view(void) {
    for (int i = 0; i < nmodel; i++) {
        file_t *f = file_of(model[i].fid, false);
        if (model[i].present != (f && f->data != NULL)) {
            return -1 - i;
        }
        if (model[i].present && (file_get_size(f) != model[i].len ||
                                 memcmp(file_get_data(f), model[i].data, model[i].len) != 0)) {
            return -1 - i;
        }
    }
    return 0;
}

/* -- abandoned transactions ------------------------------------------------ */

static model_t saved_model[MAX_FILES];
static int saved_nmodel = 0;

static void model_save(void) {
    memcpy(saved_model, model, sizeof(model));
    saved_nmodel = nmodel;
}

/* file.c's scan, reduced to the harness's files: every file bound to the
 * record the store holds for it, or to nothing. */
void scan_flash(void) {
    for (int i = 0; i < nfiles; i++) {
        files[i].data = NULL;
    }
    uintptr_t heads[2] = { end_rom_pool, end_data_pool }, starts[2] = { start_rom_pool, start_data_pool };
    for (int l = 0; l < 2; l++) {
        uintptr_t above = heads[l];
        for (uintptr_t r = rd_ptr(heads[l]); r >= starts[l] && r < above; above = r, r = rd_ptr(r)) {
            uint16_t fid = rd_u16(r + 2 * sizeof(uintptr_t));
            for (int i = 0; i < nfiles; i++) {
                if (files[i].fid == fid) {
                    files[i].data = (uint8_t *) (r + 2 * sizeof(uintptr_t) + sizeof(uint16_t));
                }
            }
        }
    }
}

void h_txn_begin(void) {
    low_flash_txn_begin();
    model_save();
}

/* The handler commits something it must keep (a retry counter). */
int h_txn_commit(void) {
    int r = low_flash_commit();
    model_save();
    return r;
}

int h_txn_abort(void) {
    int r = low_flash_txn_abort();
    if (r == PICOKEY_OK) {
        memcpy(model, saved_model, sizeof(model));
        nmodel = saved_nmodel;
    }
    return r;
}

int h_txn_end(void) {
    return low_flash_txn_end();
}

/* -- concurrent commits ---------------------------------------------------- */

static volatile int stress_stop = 0;
static int stress_commits = 0;

static void *committer(void *arg) {
    (void) arg;
    while (!stress_stop) {
        low_flash_commit();
        stress_commits++;
    }
    return NULL;
}

/* ops random creates, rewrites and deletes on this thread while another
 * thread commits without pause (core 0's commit against the card thread's
 * operations). Returns the number of commits the other thread made. */
int h_stress(int ops, unsigned seed) {
    pthread_t t;
    stress_stop = 0;
    stress_commits = 0;
    if (pthread_create(&t, NULL, committer, NULL) != 0) {
        return -1;
    }
    uint8_t buf[2048];
    for (int i = 0; i < ops; i++) {
        seed = seed * 1103515245u + 12345u;
        uint16_t fid = (uint16_t) (0xC000 + (seed >> 16) % 24);
        seed = seed * 1103515245u + 12345u;
        if ((seed >> 16) % 4 == 0) {
            del(fid);
        }
        else {
            uint16_t len = (uint16_t) (1 + (seed >> 8) % sizeof(buf));
            for (uint16_t k = 0; k < len; k++) {
                buf[k] = (uint8_t) (seed + k * 7);
            }
            put(fid, 0, buf, len);
        }
    }
    stress_stop = 1;
    pthread_join(t, NULL);
    return stress_commits;
}

int h_commits(void) {
    return commits;
}

int h_failures(void) {
    return failures;
}

const char *h_last_error(void) {
    return last_error;
}

uint32_t h_free(void) {
    return flash_free_space();
}

/* file.c helpers flash.c relies on */
uint8_t *file_get_data(const file_t *tf) {
    extern uint8_t *flash_read(uintptr_t addr);
    return tf && tf->data ? flash_read((uintptr_t) tf->data + sizeof(uint16_t)) : NULL;
}

uint16_t file_get_size(const file_t *tf) {
    extern uint16_t flash_read_uint16(uintptr_t addr);
    if (!tf || !tf->data) {
        return 0;
    }
    uint16_t len = flash_read_uint16((uintptr_t) tf->data);
    uintptr_t payload = (uintptr_t) tf->data + sizeof(uint16_t);
    uintptr_t room = LF_SECTOR_SIZE - (payload & (LF_SECTOR_SIZE - 1));
    return len > room ? (uint16_t) room : len;
}
