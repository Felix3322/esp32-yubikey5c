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
#include <stdlib.h>
#include <string.h>
#include "pico_keys.h"
#include "crypto_utils.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"
#include "file.h"
#include "phy.h"
#include "low_flash.h"
#include "security.h"
#include "lf_region.h"
#include "lf_store.h"
#include "lf_boot.h"
#include "lf_backup.h"
#include "lf_profile.h"
#include "lf_sys.h"

#if defined(ESP_PLATFORM)
#include "esp_heap_caps.h"
#define lf_malloc(n) heap_caps_malloc((n), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)
#else
#define lf_malloc(n) malloc(n)
#endif

extern uintptr_t end_rom_pool, start_rom_pool, end_data_pool, start_data_pool;
extern uintptr_t flash_read_uintptr(uintptr_t addr);
extern uint16_t flash_read_uint16(uintptr_t addr);

#define STAGE_MAGIC         0x4753464CU     /* "LFSG" */
#define STAGE_VERSION       1
#define STAGE_BUF           256             /* flash encryption needs 16-byte aligned writes */
#define REC_HDR             3
#define REC_MAX             (2 + LF_SECTOR_SIZE)
#define MAX_FIDS            1024

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint8_t purpose;
    uint8_t target;
    uint32_t length;
    uint8_t sha256[32];
    uint32_t crc;
} stage_hdr_t;

static lf_region_t stage;
static bool stage_ready = false;
static uint32_t wr_off = 0, buf_len = 0;
static uint8_t wr_purpose = 0, wr_target = 0;
static uint8_t wr_buf[STAGE_BUF];
static mbedtls_sha256_context wr_sha;
/* Streams hold the root key and every file in the clear. Once the stage has
 * been cleaned in this boot (extent_known), everything past dirty_upto bytes
 * of the data area is known to be erased; before that, anything may be left
 * over from an interrupted stream of an earlier boot. */
static bool extent_known = false;
static uint32_t dirty_upto = 0;

/* ------------------------------------------------------------------------ */
/* Staging area                                                             */
/* ------------------------------------------------------------------------ */

static bool stage_open(void) {
    if (!stage_ready) {
        stage_ready = lf_region_open(&stage, LF_REG_STAGE) && stage.size > 2 * LF_SECTOR_SIZE;
    }
    return stage_ready;
}

uint32_t lf_stage_capacity(void) {
    return stage_open() ? stage.size - LF_SECTOR_SIZE : 0;
}

static uint32_t sectors_up(uint32_t n) {
    return ((n + LF_SECTOR_SIZE - 1) / LF_SECTOR_SIZE) * LF_SECTOR_SIZE;
}

/* Raw check (ciphertext under flash encryption, where erased flash does not
 * decrypt to 0xFF). An unreadable sector counts as used. */
static bool sector_blank(uint32_t off) {
    uint32_t chunk[64];
    for (uint32_t pos = 0; pos < LF_SECTOR_SIZE; pos += sizeof(chunk)) {
        if (lf_region_read_raw(&stage, off + pos, chunk, sizeof(chunk)) != PICOKEY_OK) {
            return false;
        }
        for (size_t i = 0; i < sizeof(chunk) / sizeof(chunk[0]); i++) {
            if (chunk[i] != 0xFFFFFFFFu) {
                return false;
            }
        }
    }
    return true;
}

/* Erases every sector of [off, end) that is not blank: leaves no leftovers
 * whatever the RAM state says, and wears only sectors that were used (a
 * session that wrote nothing costs no erase). */
static int erase_used(uint32_t off, uint32_t end) {
    int ret = PICOKEY_OK;
    if (end > stage.size) {
        end = stage.size;
    }
    for (; off + LF_SECTOR_SIZE <= end; off += LF_SECTOR_SIZE) {
        if (!sector_blank(off) && lf_region_erase(&stage, off, LF_SECTOR_SIZE) != PICOKEY_OK) {
            ret = PICOKEY_ERR_MEMORY_FATAL;
        }
    }
    return ret;
}

int lf_stage_clear(void) {
    if (!stage_open()) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    /* Once the extent is known: the header, and every data sector written
     * since the stage was last clean (longer earlier streams included). */
    int ret = erase_used(0, extent_known ? LF_SECTOR_SIZE + sectors_up(dirty_upto) : stage.size);
    if (ret == PICOKEY_OK) {
        extent_known = true;
        dirty_upto = 0;
    }
    return ret;
}

void lf_stage_boot_cleanup(void) {
    /* Nothing is written until a partition table without the regions (or
     * their "encrypted" flag) is fixed. */
    if (extent_known || lf_boot_status() == LF_BOOT_ERR_LAYOUT || !stage_open()) {
        return;
    }
    /* A stream that a pending import or restore test still needs is kept:
     * the record read from flash names it (also when the boot then failed
     * to write the system area: that boot retries the operation next time).
     * An unreadable record is all zeros here, so it keeps nothing. */
    uint8_t purpose = 0, target = 0;
    uint32_t length = 0;
    const lf_sys_t *s = lf_sys();
    if ((s->pending_op == LF_OP_IMPORT || s->pending_op == LF_OP_VERIFY) &&
        lf_stage_info(&purpose, &target, &length) && purpose == LF_STAGE_IMPORT && target == s->pending_profile) {
        uint32_t used = sectors_up(length);
        if (erase_used(LF_SECTOR_SIZE + used, stage.size) == PICOKEY_OK) {
            extent_known = true;
            dirty_upto = used;
        }
        return;
    }
    if (lf_stage_clear() != PICOKEY_OK) {
        printf("[lf_backup] ERROR: the staging area could not be erased\n");
    }
}

int lf_stage_begin(uint8_t purpose, uint8_t target) {
    if (!stage_open()) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    /* Drops any previous stream (header first, so it is invalid at once)
     * and leaves the whole data area erased for this one. */
    int ret = lf_stage_clear();
    wr_off = buf_len = 0;
    wr_purpose = purpose;
    wr_target = target;
    mbedtls_sha256_init(&wr_sha);
    mbedtls_sha256_starts(&wr_sha, 0);
    return ret;
}

static int stage_flush(bool final) {
    if (buf_len == 0) {
        return PICOKEY_OK;
    }
    uint32_t n = buf_len;
    if (final) {
        uint32_t padded = (n + 15) & ~15u;
        memset(wr_buf + n, 0xFF, padded - n);
        n = padded;
    }
    /* lf_stage_begin() erased the data area: the stream is only written. */
    uint32_t pos = wr_off - buf_len;
    if (pos + n > dirty_upto) {
        dirty_upto = pos + n;
    }
    int r = lf_region_write(&stage, LF_SECTOR_SIZE + pos, wr_buf, n);
    buf_len = 0;
    return r;
}

int lf_stage_append(const uint8_t *p, uint32_t n) {
    if (!stage_open()) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (wr_off + n > lf_stage_capacity()) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    mbedtls_sha256_update(&wr_sha, p, n);
    while (n > 0) {
        uint32_t k = STAGE_BUF - buf_len < n ? STAGE_BUF - buf_len : n;
        memcpy(wr_buf + buf_len, p, k);
        buf_len += k;
        wr_off += k;
        p += k;
        n -= k;
        if (buf_len == STAGE_BUF) {
            int r = stage_flush(false);
            if (r != PICOKEY_OK) {
                return r;
            }
        }
    }
    return PICOKEY_OK;
}

int lf_stage_finish(void) {
    int r = stage_flush(true);
    if (r != PICOKEY_OK) {
        return r;
    }
    stage_hdr_t h, chk;
    memset(&h, 0, sizeof(h));
    h.magic = STAGE_MAGIC;
    h.version = STAGE_VERSION;
    h.purpose = wr_purpose;
    h.target = wr_target;
    h.length = wr_off;
    mbedtls_sha256_finish(&wr_sha, h.sha256);
    mbedtls_sha256_free(&wr_sha);
    h.crc = crc32c((const uint8_t *) &h, offsetof(stage_hdr_t, crc));
    uint8_t blk[64];
    memset(blk, 0xFF, sizeof(blk));
    memcpy(blk, &h, sizeof(h));
    r = lf_region_write(&stage, 0, blk, sizeof(blk));
    if (r == PICOKEY_OK && (lf_region_read(&stage, 0, &chk, sizeof(chk)) != PICOKEY_OK || memcmp(&h, &chk, sizeof(h)) != 0)) {
        r = PICOKEY_ERR_MEMORY_FATAL;
    }
    return r;
}

static bool stage_header(stage_hdr_t *h) {
    if (!stage_open() || lf_region_read(&stage, 0, h, sizeof(*h)) != PICOKEY_OK) {
        return false;
    }
    return h->magic == STAGE_MAGIC && h->version == STAGE_VERSION &&
           crc32c((const uint8_t *) h, offsetof(stage_hdr_t, crc)) == h->crc &&
           h->length <= lf_stage_capacity();
}

bool lf_stage_info(uint8_t *purpose, uint8_t *target, uint32_t *length) {
    stage_hdr_t h;
    if (!stage_header(&h)) {
        return false;
    }
    if (purpose) {
        *purpose = h.purpose;
    }
    if (target) {
        *target = h.target;
    }
    if (length) {
        *length = h.length;
    }
    return true;
}

bool lf_stage_digest(uint8_t out[32]) {
    stage_hdr_t h;
    if (!stage_header(&h)) {
        return false;
    }
    memcpy(out, h.sha256, 32);
    return true;
}

int lf_stage_read(uint32_t off, uint8_t *p, uint32_t n) {
    stage_hdr_t h;
    if (!stage_header(&h) || off > h.length || n > h.length - off) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    return lf_region_read(&stage, LF_SECTOR_SIZE + off, p, n);
}

/* ------------------------------------------------------------------------ */
/* Export                                                                   */
/* ------------------------------------------------------------------------ */

void lf_backup_header_init(lfbk_header_t *hdr) {
    memset(hdr, 0, sizeof(*hdr));
    memcpy(hdr->magic, "LFBK", 4);
    hdr->format = LFBK_FORMAT;
    hdr->fw[0] = LFBK_FW_MAJOR;
    hdr->fw[1] = LFBK_FW_MINOR;
    hdr->fw[2] = LFBK_FW_PATCH;
    hdr->min_fw[0] = LFBK_MIN_FW_MAJOR;
    hdr->min_fw[1] = LFBK_MIN_FW_MINOR;
    hdr->min_fw[2] = LFBK_MIN_FW_PATCH;
}

static int emit(uint8_t type, const uint8_t *a, uint16_t na, const uint8_t *b, uint16_t nb) {
    uint16_t n = (uint16_t) (na + nb);
    uint8_t h[REC_HDR] = { type, (uint8_t) (n & 0xFF), (uint8_t) (n >> 8) };
    int r = lf_stage_append(h, sizeof(h));
    if (r == PICOKEY_OK && na) {
        r = lf_stage_append(a, na);
    }
    if (r == PICOKEY_OK && nb) {
        r = lf_stage_append(b, nb);
    }
    return r;
}

static bool fid_exported(uint16_t fid) {
    /* Board settings are device wide; the root key travels as ROOTKEY and the
     * identity in the header. */
    if (fid == EF_PHY || fid == EF_DEVROOT || fid == EF_PROFILE_ID || fid == 0x0000 || fid == 0xFFFF) {
        return false;
    }
    /* Only files kept in the store. A static entry of another kind holds a
     * function (FILE_DATA_FUNC, e.g. OpenPGP data objects) or data in RAM:
     * writing a record for it would make its pointer point into the store,
     * and the next call through it would crash, at every boot. */
    const file_t *f = search_by_fid(fid, NULL, SPECIFY_EF);
    return f == NULL || (f->type & FILE_DATA_FLASH) == FILE_DATA_FLASH;
}

static int collect_fids(uintptr_t endp, uintptr_t startp, uint16_t *fids, uint32_t *n) {
    uint32_t guard = 0;
    for (uintptr_t base = flash_read_uintptr(endp); base >= startp && base < endp; base = flash_read_uintptr(base)) {
        if (base == 0) {
            break;
        }
        if (++guard > 65536) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        uint16_t fid = flash_read_uint16(base + 2 * sizeof(uintptr_t));
        bool seen = false;
        for (uint32_t i = 0; i < *n && !seen; i++) {
            seen = fids[i] == fid;
        }
        if (!seen) {
            if (*n == MAX_FIDS) {
                return PICOKEY_ERR_NO_MEMORY;
            }
            fids[(*n)++] = fid;
        }
    }
    return PICOKEY_OK;
}

int lf_backup_export(const lfbk_header_t *hdr, const uint8_t root[32], uint8_t root_flags, uint8_t purpose) {
    uint16_t *fids = (uint16_t *) lf_malloc(MAX_FIDS * sizeof(uint16_t));
    if (fids == NULL) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    uint32_t nfids = 0;
    int r = collect_fids(end_rom_pool, start_rom_pool, fids, &nfids);
    if (r == PICOKEY_OK) {
        r = collect_fids(end_data_pool, start_data_pool, fids, &nfids);
    }
    if (r == PICOKEY_OK) {
        r = lf_stage_begin(purpose, 0);
    }
    if (r == PICOKEY_OK) {
        r = emit(LFBK_REC_HEADER, (const uint8_t *) hdr, sizeof(*hdr), NULL, 0);
    }
    if (r == PICOKEY_OK && root) {
        r = emit(LFBK_REC_ROOTKEY, &root_flags, 1, root, 32);
    }
    for (uint32_t i = 0; r == PICOKEY_OK && i < nfids; i++) {
        if (!fid_exported(fids[i])) {
            continue;
        }
        file_t *f = search_file(fids[i]);
        if (!file_has_data(f)) {
            continue;
        }
        uint8_t fb[2] = { (uint8_t) (fids[i] & 0xFF), (uint8_t) (fids[i] >> 8) };
        r = emit(LFBK_REC_FILE, fb, 2, file_get_data(f), file_get_size(f));
    }
    for (uint8_t id = 0; r == PICOKEY_OK && id < LF_CTR_MAX_IDS; id++) {
        uint32_t v = 0;
        if (lf_ctr_present(id) && lf_ctr_get(id, &v) == PICOKEY_OK) {
            uint8_t cb[5] = { id, (uint8_t) v, (uint8_t) (v >> 8), (uint8_t) (v >> 16), (uint8_t) (v >> 24) };
            r = emit(LFBK_REC_COUNTER, cb, sizeof(cb), NULL, 0);
        }
    }
    if (r == PICOKEY_OK) {
        uint8_t digest[32];
        mbedtls_sha256_context c;
        mbedtls_sha256_init(&c);
        mbedtls_sha256_clone(&c, &wr_sha);
        mbedtls_sha256_finish(&c, digest);
        mbedtls_sha256_free(&c);
        r = emit(LFBK_REC_END, digest, sizeof(digest), NULL, 0);
    }
    if (r == PICOKEY_OK) {
        r = lf_stage_finish();
    }
    free(fids);
    return r;
}

/* ------------------------------------------------------------------------ */
/* Validation and import                                                    */
/* ------------------------------------------------------------------------ */

static bool fw_supports(const uint8_t min_fw[3]) {
    uint32_t need = ((uint32_t) min_fw[0] << 16) | ((uint32_t) min_fw[1] << 8) | min_fw[2];
    uint32_t have = ((uint32_t) LFBK_FW_MAJOR << 16) | ((uint32_t) LFBK_FW_MINOR << 8) | LFBK_FW_PATCH;
    return need <= have;
}

int lf_backup_check_begin(lfbk_check_t *c) {
    memset(c, 0, sizeof(*c));
    c->fids = (uint16_t *) lf_malloc(MAX_FIDS * sizeof(uint16_t));
    if (c->fids == NULL) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    mbedtls_sha256_init(&c->all);
    mbedtls_sha256_starts(&c->all, 0);
    c->active = true;
    return PICOKEY_OK;
}

void lf_backup_check_abort(lfbk_check_t *c) {
    if (c->active) {
        mbedtls_sha256_free(&c->all);
        free(c->fids);
    }
    mbedtls_platform_zeroize(c, sizeof(*c));
}

/* One complete record (its first bytes in c->val). */
static int check_record(lfbk_check_t *c) {
    const uint8_t *buf = c->val;
    uint16_t len = c->len;
    lfbk_info_t *info = &c->info;
    if (c->type == LFBK_REC_END) {
        if (len != 32 || memcmp(c->end_digest, buf, 32) != 0) {
            return PICOKEY_WRONG_DATA;
        }
        c->end = true;
    }
    else if (!c->header) {
        const lfbk_header_t *hd = (const lfbk_header_t *) buf;
        if (c->type != LFBK_REC_HEADER || len != sizeof(lfbk_header_t) || memcmp(hd->magic, "LFBK", 4) != 0 ||
            hd->format != LFBK_FORMAT || !fw_supports(hd->min_fw)) {
            return PICOKEY_WRONG_DATA;
        }
        memcpy(&info->hdr, buf, sizeof(info->hdr));
        /* Becomes the profile name: valid UTF-8 only (older firmware could
         * cut a name inside a character). */
        lf_profile_name_sanitize(info->hdr.name, sizeof(info->hdr.name));
        c->header = true;
    }
    else if (c->type == LFBK_REC_ROOTKEY) {
        if (len != 33 || info->has_root) {
            return PICOKEY_WRONG_DATA;
        }
        info->has_root = true;
    }
    else if (c->type == LFBK_REC_FILE) {
        if (len < 2) {
            return PICOKEY_WRONG_DATA;
        }
        uint16_t fid = (uint16_t) (buf[0] | (buf[1] << 8));
        bool dup = false;
        for (uint32_t i = 0; i < info->files && !dup; i++) {
            dup = c->fids[i] == fid;
        }
        if (!fid_exported(fid) || dup || info->files == MAX_FIDS) {
            return PICOKEY_WRONG_DATA;
        }
        c->fids[info->files++] = fid;
        c->payload += (uint32_t) (len - 2) + 32;    /* content + record overhead */
    }
    else if (c->type == LFBK_REC_COUNTER) {
        if (len != 5 || buf[0] >= LF_CTR_MAX_IDS) {
            return PICOKEY_WRONG_DATA;
        }
        info->counters++;
    }
    else {
        return PICOKEY_WRONG_DATA;          /* written by newer firmware */
    }
    return PICOKEY_OK;
}

int lf_backup_check_feed(lfbk_check_t *c, const uint8_t *p, uint32_t n) {
    if (!c->active) {
        return PICOKEY_ERR_BLOCKED;
    }
    if (c->err != PICOKEY_OK) {
        return c->err;
    }
    c->info.length += n;
    while (n > 0) {
        if (c->rh_got < REC_HDR) {
            if (c->end) {
                return c->err = PICOKEY_WRONG_DATA;     /* data after END */
            }
            c->rh[c->rh_got++] = *p++;
            n--;
            if (c->rh_got < REC_HDR) {
                continue;
            }
            c->type = c->rh[0];
            c->len = (uint16_t) (c->rh[1] | (c->rh[2] << 8));
            c->got = 0;
            if (c->len > REC_MAX) {
                return c->err = PICOKEY_WRONG_DATA;
            }
            if (c->type == LFBK_REC_END) {
                /* END carries the SHA-256 of every byte before it. */
                mbedtls_sha256_context pre;
                mbedtls_sha256_init(&pre);
                mbedtls_sha256_clone(&pre, &c->all);
                mbedtls_sha256_finish(&pre, c->end_digest);
                mbedtls_sha256_free(&pre);
            }
            mbedtls_sha256_update(&c->all, c->rh, REC_HDR);
        }
        else {
            uint32_t k = (uint32_t) (c->len - c->got) < n ? (uint32_t) (c->len - c->got) : n;
            mbedtls_sha256_update(&c->all, p, k);
            if (c->got < sizeof(c->val)) {
                uint32_t keep = sizeof(c->val) - c->got < k ? sizeof(c->val) - c->got : k;
                memcpy(c->val + c->got, p, keep);
            }
            c->got = (uint16_t) (c->got + k);
            p += k;
            n -= k;
        }
        if (c->rh_got == REC_HDR && c->got == c->len) {
            int r = check_record(c);
            mbedtls_platform_zeroize(c->val, sizeof(c->val));   /* a ROOTKEY value is the key */
            if (r != PICOKEY_OK) {
                return c->err = r;
            }
            c->rh_got = 0;
        }
    }
    return PICOKEY_OK;
}

int lf_backup_check_end(lfbk_check_t *c, lfbk_info_t *info) {
    memset(info, 0, sizeof(*info));
    if (!c->active) {
        return PICOKEY_ERR_BLOCKED;
    }
    int r = c->err;
    if (r == PICOKEY_OK && (c->rh_got != 0 || !c->header || !c->end)) {
        r = PICOKEY_WRONG_DATA;             /* truncated, or no header / END */
    }
    /* The file system needs room for record headers and fragmentation. */
    if (r == PICOKEY_OK && c->payload > LF_STORE_LOGICAL_SIZE - 64 * 1024) {
        r = PICOKEY_ERR_NO_MEMORY;
    }
    if (r == PICOKEY_OK) {
        mbedtls_sha256_finish(&c->all, c->info.sha256);
        *info = c->info;
    }
    lf_backup_check_abort(c);
    return r;
}

int lf_backup_check(lfbk_info_t *info) {
    memset(info, 0, sizeof(*info));
    stage_hdr_t h;
    if (!stage_header(&h)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    lfbk_check_t *c = (lfbk_check_t *) lf_malloc(sizeof(lfbk_check_t));
    if (c == NULL) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    int r = lf_backup_check_begin(c);
    uint8_t buf[256];
    for (uint32_t off = 0; r == PICOKEY_OK && off < h.length; ) {
        uint32_t n = h.length - off < sizeof(buf) ? h.length - off : (uint32_t) sizeof(buf);
        r = lf_stage_read(off, buf, n);
        if (r == PICOKEY_OK) {
            r = lf_backup_check_feed(c, buf, n);
        }
        off += n;
    }
    mbedtls_platform_zeroize(buf, sizeof(buf));
    if (r == PICOKEY_OK) {
        r = lf_backup_check_end(c, info);
        /* The stream as recorded when it was sealed. */
        if (r == PICOKEY_OK && (info->length != h.length || memcmp(info->sha256, h.sha256, 32) != 0)) {
            r = PICOKEY_WRONG_DATA;
        }
    }
    else {
        lf_backup_check_abort(c);
    }
    free(c);
    if (r != PICOKEY_OK) {
        memset(info, 0, sizeof(*info));
    }
    return r;
}

/* Applies (verify == false) or checks (verify == true) every record. */
static int import_pass(bool verify, uint8_t *buf) {
    stage_hdr_t h;
    if (!stage_header(&h)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint32_t off = 0;
    while (off < h.length) {
        uint8_t rh[REC_HDR];
        if (lf_stage_read(off, rh, REC_HDR) != PICOKEY_OK) {
            return PICOKEY_WRONG_DATA;
        }
        uint16_t len = (uint16_t) (rh[1] | (rh[2] << 8));
        if (lf_stage_read(off + REC_HDR, buf, len) != PICOKEY_OK) {
            return PICOKEY_WRONG_DATA;
        }
        off += REC_HDR + len;
        if (rh[0] == LFBK_REC_HEADER) {
            const lfbk_header_t *hd = (const lfbk_header_t *) buf;
            uint8_t uuid[16], serial[8];
            if (!verify) {
                int r = lf_identity_write(hd->uuid, hd->serial);
                if (r != PICOKEY_OK) {
                    return r;
                }
            }
            else if (!lf_identity_read(uuid, serial) || memcmp(uuid, hd->uuid, 16) != 0 ||
                     memcmp(serial, hd->serial, 8) != 0) {
                return PICOKEY_VERIFICATION_FAILED;
            }
        }
        else if (rh[0] == LFBK_REC_ROOTKEY) {
            if (!verify) {
                int r = security_root_import(buf + 1, buf[0]);
                if (r != PICOKEY_OK) {
                    return r;
                }
            }
            else {
                uint8_t key[32], flags = 0;
                int ok = security_root_export(key, &flags) == PICOKEY_OK && memcmp(key, buf + 1, 32) == 0 && flags == buf[0];
                mbedtls_platform_zeroize(key, sizeof(key));
                if (!ok) {
                    return PICOKEY_VERIFICATION_FAILED;
                }
            }
        }
        else if (rh[0] == LFBK_REC_FILE) {
            uint16_t fid = (uint16_t) (buf[0] | (buf[1] << 8));
            uint16_t n = (uint16_t) (len - 2);
            if (len < 2 || !fid_exported(fid)) {
                return PICOKEY_WRONG_DATA;      /* lf_backup_check() refuses it too */
            }
            file_t *f = search_file(fid);
            if (!verify) {
                if (f == NULL) {
                    f = file_new(fid);
                }
                if (f == NULL || file_put_data(f, buf + 2, n) != PICOKEY_OK) {
                    return PICOKEY_ERR_NO_MEMORY;
                }
            }
            else if (!file_has_data(f) || file_get_size(f) != n || memcmp(file_get_data(f), buf + 2, n) != 0) {
                return PICOKEY_VERIFICATION_FAILED;
            }
        }
        else if (rh[0] == LFBK_REC_COUNTER) {
            uint32_t v = (uint32_t) buf[1] | ((uint32_t) buf[2] << 8) | ((uint32_t) buf[3] << 16) | ((uint32_t) buf[4] << 24);
            if (!verify) {
                int r = lf_ctr_set(buf[0], v);
                if (r != PICOKEY_OK) {
                    return r;
                }
            }
            else {
                uint32_t cur = 0;
                if (!lf_ctr_present(buf[0]) || lf_ctr_get(buf[0], &cur) != PICOKEY_OK || cur < v) {
                    return PICOKEY_VERIFICATION_FAILED;
                }
            }
        }
    }
    return PICOKEY_OK;
}

int lf_backup_import(lfbk_info_t *info) {
    int r = lf_backup_check(info);
    if (r != PICOKEY_OK) {
        return r;
    }
    uint8_t *buf = (uint8_t *) lf_malloc(REC_MAX);
    if (buf == NULL) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    r = import_pass(false, buf);
    if (r == PICOKEY_OK) {
        r = low_flash_commit();
    }
    if (r == PICOKEY_OK) {
        r = import_pass(true, buf);
    }
    mbedtls_platform_zeroize(buf, REC_MAX);
    free(buf);
    return r;
}
