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
#include "profile.h"
#include "security.h"
#include "mbedtls/sha256.h"
#include "lf_boot.h"
#include "lf_fw.h"
#include "low_flash.h"
#include "lf_store.h"
#include "lf_sys.h"

#if defined(ESP_PLATFORM)
#include "esp_image_format.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_secure_boot.h"
#else
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifndef LF_BOARD_NAME
#if defined(ESP_PLATFORM)
#define LF_BOARD_NAME   "esp32s3"
#else
#define LF_BOARD_NAME   "emulation"
#endif
#endif

__attribute__((used)) const lf_fw_desc_t lf_fw_desc = {
    .magic = { 'L', 'F', 'F', 'W', 'D', 'S', 'C', '1' },
    .magic_inv = { (uint8_t) ~'L', (uint8_t) ~'F', (uint8_t) ~'F', (uint8_t) ~'W',
                   (uint8_t) ~'D', (uint8_t) ~'S', (uint8_t) ~'C', (uint8_t) ~'1' },
    .desc_version = LF_FW_DESC_VERSION,
#if defined(ESP_PLATFORM)
    .platform = LF_FW_PLATFORM_ESP32S3,
#else
    .platform = LF_FW_PLATFORM_EMULATION,
#endif
    .build_profile = LF_PROFILE_ID,
    .version = { LF_FW_VERSION_MAJOR, LF_FW_VERSION_MINOR, LF_FW_VERSION_PATCH },
    .store_version = LF_FW_STORE_FORMAT,
    .store_version_min = LF_FW_STORE_FORMAT_MIN,
    .sys_version = LF_SYS_FORMAT_VERSION,
    .sys_version_min = LF_SYS_FORMAT_VERSION,
    .board = LF_BOARD_NAME,
};

/* ------------------------------------------------------------------------ */
/* Descriptor search                                                        */
/* ------------------------------------------------------------------------ */

#define DESC_SIZE   ((uint32_t) sizeof(lf_fw_desc_t))

/* The magic is read through a volatile pointer so that the compiler cannot
 * turn it into immediates: the only copy in an image is the descriptor. */
static bool is_desc(const uint8_t *p) {
    const volatile uint8_t *m = lf_fw_desc.magic;
    for (int i = 0; i < 8; i++) {
        if (p[i] != m[i] || p[8 + i] != (uint8_t) ~m[i]) {
            return false;
        }
    }
    return true;
}

typedef int (*read_fn_t)(void *ctx, uint32_t off, uint8_t *buf, uint32_t len);

/* Scans [0, size) in chunks that overlap by one descriptor. The caller
 * passes the part of the image its verification covers. An image carries
 * exactly one descriptor: a second one could only be there to mislead. */
static int find_desc(read_fn_t rd, void *ctx, uint32_t size, lf_fw_desc_t *out) {
    static uint8_t buf[4096];
    uint32_t off = 0, found = 0;
    while (off + DESC_SIZE <= size) {
        uint32_t n = size - off < sizeof(buf) ? size - off : sizeof(buf);
        if (rd(ctx, off, buf, n) != 0) {
            return PICOKEY_EXEC_ERROR;
        }
        for (uint32_t i = 0; i + DESC_SIZE <= n; i++) {
            if (buf[i] == 'L' && is_desc(buf + i)) {
                if (++found > 1) {
                    return PICOKEY_VERIFICATION_FAILED;
                }
                memcpy(out, buf + i, DESC_SIZE);
            }
        }
        if (off + n >= size) {
            break;
        }
        off += n - DESC_SIZE + 1;
    }
    if (found != 1) {
        return PICOKEY_VERIFICATION_FAILED;
    }
    return out->desc_version == LF_FW_DESC_VERSION ? PICOKEY_OK : PICOKEY_VERIFICATION_FAILED;
}

static int cmp_version(const uint8_t a[3], const uint8_t b[3]) {
    return memcmp(a, b, 3);
}

/* Only a Secure Boot chip vouches for the images it runs. Read from the chip
 * itself on the ESP32 (updates also work in safe mode). */
bool lf_fw_images_signed(void) {
#if defined(ESP_PLATFORM)
    return esp_secure_boot_enabled();
#else
    return security_state()->secure_boot;
#endif
}

#if !defined(LF_PROFILE_HARDENED)
/* What a HARDENED build requires of the chip and cannot do itself (the HMAC
 * key and the root key binding it can do: PROVISION). On any other chip it
 * would lock the key store for good and, without Secure Boot, refuse every
 * update after it. */
static bool chip_ready_for_hardened(void) {
    const security_state_t *ss = security_state();
    return lf_fw_images_signed() && ss->flash_enc_release && ss->jtag_disabled && ss->download_restricted &&
           !ss->legacy_keys_readable;
}
#endif

_Static_assert(LF_STORE_FORMAT_VERSION == 1, "a new store layout needs a new LF_FW_STORE_FORMAT (lf_fw.h)");

/* Store format of the data now: the running firmware's own once it is
 * confirmed (the applications migrate records only then), else the oldest
 * it opens. Read from the descriptor of the running image. */
static bool running_pending(void);

/* Set once this image is on its way out (a rollback was requested, or a new
 * image was activated for the next boot). From then on nothing may be
 * migrated to a format the next image might not read, and the running image
 * can no longer be confirmed: the otadata change is already done, only the
 * delayed restart is missing. */
static volatile bool fw_leaving = false;

bool lf_fw_migration_blocked(void) {
    return fw_leaving || running_pending();
}

static uint8_t store_format_in_use(void) {
    const volatile lf_fw_desc_t *me = &lf_fw_desc;
    return running_pending() ? me->store_version_min : me->store_version;
}

int lf_fw_check_recovery(const lf_fw_desc_t *d) {
    if (d->platform != lf_fw_desc.platform || d->build_profile > LF_FW_PROFILE_HARDENED) {
        return PICOKEY_WRONG_DATA;
    }
    /* The new image must open the storage as it is now: it may not migrate
     * it before it is confirmed, and a rollback needs the old format. */
    uint8_t in_use = store_format_in_use();
    if (in_use < d->store_version_min ||
        LF_SYS_FORMAT_VERSION < d->sys_version_min || LF_SYS_FORMAT_VERSION > d->sys_version) {
        return PICOKEY_WRONG_DATA;
    }
    /* Records the confirmed firmware sealed would be unreadable for it: the
     * keys in them lost (also with an explicit downgrade). */
    if (in_use > d->store_version) {
        return LF_FW_ERR_OLDER_FORMAT;
    }
    return PICOKEY_OK;
}

int lf_fw_check_policy(const lf_fw_desc_t *d, bool allow_downgrade) {
#if defined(LF_PROFILE_HARDENED)
    /* Without Secure Boot nothing vouches for an image: any host with a
     * touch could install firmware that reads the keys. */
    if (!lf_fw_images_signed()) {
        return PICOKEY_ERR_BLOCKED;
    }
    allow_downgrade = false;
#endif
    int r = lf_fw_check_recovery(d);
    if (r != PICOKEY_OK) {
        return r;
    }
    /* Build profiles only restrict (profile.h): an image of a profile that
     * allows more (DEVELOPMENT < STANDARD < HARDENED) is a downgrade. A
     * HARDENED build therefore only ever installs HARDENED images. */
    if (d->build_profile < LF_PROFILE_ID && !allow_downgrade) {
        return PICOKEY_ERR_BLOCKED;
    }
#if !defined(LF_PROFILE_HARDENED)
    if (d->build_profile == LF_FW_PROFILE_HARDENED && !chip_ready_for_hardened()) {
        return LF_FW_ERR_CHIP_NOT_HARDENED;
    }
#endif
    if (cmp_version(d->version, lf_fw_desc.version) < 0 && !allow_downgrade) {
        return PICOKEY_ERR_BLOCKED;
    }
    return PICOKEY_OK;
}

/* ------------------------------------------------------------------------ */
/* Upload session (common part)                                             */
/* ------------------------------------------------------------------------ */

static bool active = false, finished = false;
static uint32_t expect_size = 0, written = 0;
static uint8_t expect_hash[32];
static mbedtls_sha256_context sha;

bool lf_fw_active(void) {
    return active;
}

static void backend_abort(void);
static int backend_begin(uint32_t size);
static int backend_write(const uint8_t *data, uint16_t len);
static int backend_finish(lf_fw_desc_t *desc);
static int backend_activate(void);

void lf_fw_abort(void) {
    if (active) {
        backend_abort();
        mbedtls_sha256_free(&sha);
    }
    active = finished = false;
}

int lf_fw_begin(uint32_t size, const uint8_t sha256[32]) {
    lf_fw_abort();
    if (size < 1024) {
        return PICOKEY_WRONG_LENGTH;
    }
    int r = backend_begin(size);
    if (r != PICOKEY_OK) {
        return r;
    }
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    memcpy(expect_hash, sha256, sizeof(expect_hash));
    expect_size = size;
    written = 0;
    active = true;
    return PICOKEY_OK;
}

int lf_fw_write(uint32_t offset, const uint8_t *data, uint16_t len) {
    if (!active || finished) {
        return PICOKEY_ERR_BLOCKED;
    }
    if (offset != written || len > expect_size - written) {
        return PICOKEY_WRONG_DATA;      /* in order, never past the size */
    }
    int r = backend_write(data, len);
    if (r != PICOKEY_OK) {
        lf_fw_abort();
        return r;
    }
    mbedtls_sha256_update(&sha, data, len);
    written += len;
    return PICOKEY_OK;
}

int lf_fw_finish(lf_fw_desc_t *desc) {
    if (!active || finished || written != expect_size) {
        return PICOKEY_ERR_BLOCKED;
    }
    uint8_t h[32];
    mbedtls_sha256_finish(&sha, h);
    if (memcmp(h, expect_hash, sizeof(h)) != 0) {
        lf_fw_abort();
        return PICOKEY_WRONG_SIGNATURE;
    }
    int r = backend_finish(desc);
    if (r != PICOKEY_OK) {
        lf_fw_abort();
        return r;
    }
    finished = true;
    return PICOKEY_OK;
}

int lf_fw_activate(void) {
    if (!active || !finished) {
        return PICOKEY_ERR_BLOCKED;
    }
    fw_leaving = true;
    int r = backend_activate();
    if (r != PICOKEY_OK) {
        fw_leaving = false;
    }
    mbedtls_sha256_free(&sha);
    active = finished = false;
    return r;
}

#if defined(ESP_PLATFORM)
/* ------------------------------------------------------------------------ */
/* ESP32: esp_ota                                                           */
/* ------------------------------------------------------------------------ */

static const esp_partition_t *target = NULL;
static esp_ota_handle_t handle = 0;

/* An upload that ends without being activated (refused by the policy, a
 * failed check, the session ended) leaves a slot the bootloader must never
 * start: its image header goes. */
static void backend_abort(void) {
    if (handle) {
        esp_ota_abort(handle);
    }
    if (target != NULL) {
        esp_partition_erase_range(target, 0, target->erase_size);
    }
    handle = 0;
    target = NULL;
}

static int backend_begin(uint32_t size) {
    target = esp_ota_get_next_update_partition(NULL);
    if (target == NULL) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (size > target->size) {
        target = NULL;
        return PICOKEY_ERR_NO_MEMORY;
    }
    /* The slot is the rollback target: its otadata entry (confirmed state)
     * goes first, so neither a rollback nor the bootloader can ever start
     * what this upload leaves there unless it is activated (a reset after
     * the last write, a refused image). Nothing to invalidate is fine. */
    esp_ota_invalidate_inactive_ota_data_slot();
    if (esp_ota_check_rollback_is_possible()) {
        target = NULL;
        return PICOKEY_EXEC_ERROR;
    }
    /* Sectors are erased as they are written: no long erase in one APDU. */
    if (esp_ota_begin(target, OTA_WITH_SEQUENTIAL_WRITES, &handle) != ESP_OK) {
        handle = 0;
        target = NULL;
        return PICOKEY_EXEC_ERROR;
    }
    return PICOKEY_OK;
}

static int backend_write(const uint8_t *data, uint16_t len) {
    return esp_ota_write(handle, data, len) == ESP_OK ? PICOKEY_OK : PICOKEY_EXEC_ERROR;
}

static int part_read(void *ctx, uint32_t off, uint8_t *buf, uint32_t len) {
    return esp_partition_read((const esp_partition_t *) ctx, off, buf, len) == ESP_OK ? 0 : -1;
}

/* Descriptor of the image in partition p, searched only in the bytes its
 * verification covers (segments, checksum, appended hash): whatever follows
 * (the signature block, bytes a host appended) is not signed. */
static int part_desc(const esp_partition_t *p, uint32_t limit, lf_fw_desc_t *desc) {
    esp_partition_pos_t pos = { .offset = p->address, .size = p->size };
    esp_image_metadata_t meta;
    if (esp_image_get_metadata(&pos, &meta) != ESP_OK || meta.image_len == 0 || meta.image_len > limit) {
        return PICOKEY_VERIFICATION_FAILED;
    }
    return find_desc(part_read, (void *) p, meta.image_len, desc);
}

static int backend_finish(lf_fw_desc_t *desc) {
    /* Image structure, checksums, appended hash and, with Secure Boot, the
     * signature: the same checks the bootloader applies. */
    esp_err_t e = esp_ota_end(handle);
    handle = 0;
    if (e != ESP_OK) {
        /* target stays set: the abort that follows erases the header. */
        return e == ESP_ERR_OTA_VALIDATE_FAILED ? PICOKEY_VERIFICATION_FAILED : PICOKEY_EXEC_ERROR;
    }
    return part_desc(target, written, desc);
}

static int backend_activate(void) {
    int r = esp_ota_set_boot_partition(target) == ESP_OK ? PICOKEY_OK : PICOKEY_EXEC_ERROR;
    if (r != PICOKEY_OK) {
        esp_partition_erase_range(target, 0, target->erase_size);
    }
    target = NULL;
    return r;
}

static const esp_partition_t *rollback_target(void);

static bool running_pending(void) {
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t s = ESP_OTA_IMG_UNDEFINED;
    return run && esp_ota_get_state_partition(run, &s) == ESP_OK && s == ESP_OTA_IMG_PENDING_VERIFY;
}

void lf_fw_status(lf_fw_status_t *st) {
    const esp_partition_t *run = esp_ota_get_running_partition();
    st->slot = run && run->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MIN && run->subtype <= ESP_PARTITION_SUBTYPE_APP_OTA_MAX ?
               (uint8_t) (run->subtype - ESP_PARTITION_SUBTYPE_APP_OTA_MIN) : LF_FW_SLOT_FACTORY;
    st->pending = running_pending() || fw_leaving;
    st->rollback_possible = !fw_leaving && rollback_target() != NULL;
}

int lf_fw_confirm(void) {
    if (fw_leaving) {
        return PICOKEY_ERR_BLOCKED;     /* this image will not boot again */
    }
    if (!running_pending()) {
        return PICOKEY_OK;
    }
    return esp_ota_mark_app_valid_cancel_rollback() == ESP_OK ? PICOKEY_OK : PICOKEY_EXEC_ERROR;
}

/* The image a rollback goes back to: the other slot (two OTA slots), valid
 * (esp_ota_check_rollback_is_possible() verified it, signature included),
 * and only while the running image is the one selected for boot (an update
 * that is installed but not started yet is not rolled back). */
static const esp_partition_t *rollback_target(void) {
    const esp_partition_t *run = esp_ota_get_running_partition(), *boot = esp_ota_get_boot_partition();
    if (!esp_ota_check_rollback_is_possible() || run == NULL || boot == NULL || run->address != boot->address) {
        return NULL;
    }
    return esp_ota_get_next_update_partition(NULL);
}

int lf_fw_rollback_desc(lf_fw_desc_t *desc) {
    const esp_partition_t *other = rollback_target();
    if (other == NULL) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    return part_desc(other, other->size, desc);
}

int lf_fw_rollback(void) {
    if (rollback_target() == NULL) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    /* The running image is marked invalid, and the bootloader goes back to
     * the previous one in the state it had (confirmed). Selecting the other
     * slot with esp_ota_set_boot_partition() would boot it unconfirmed, and
     * the next reset would return to the image the user rolled back. */
    fw_leaving = true;
    if (esp_ota_mark_app_invalid_rollback() != ESP_OK) {
        fw_leaving = false;
        return PICOKEY_EXEC_ERROR;
    }
    return PICOKEY_OK;
}

#else
/* ------------------------------------------------------------------------ */
/* Emulator: images next to the flash file, a bootloader in main()          */
/* ------------------------------------------------------------------------ */

enum { ST_VALID = 0, ST_NEW, ST_PENDING, ST_ABORTED };

typedef struct __attribute__((packed)) {
    uint8_t magic[4];           /* "LFOT" */
    uint8_t version;
    uint8_t active;             /* slot to boot: 0, 1 or factory */
    uint8_t prev;               /* slot to fall back to */
    uint8_t state;              /* of the active slot */
    uint8_t invalid[2];         /* slot 0/1 image marked invalid */
    char factory[PATH_MAX];     /* the executable started first */
    uint32_t crc;
} otadata_t;

static uint8_t running_slot = LF_FW_SLOT_FACTORY;
static FILE *upload = NULL;
static uint8_t upload_slot = 0;

static const char *flash_base(void) {
    const char *p = getenv("PICO_FLASH_FILE");
    return p && *p ? p : "memory.flash";
}

static void slot_path(uint8_t slot, char *out, size_t n, const otadata_t *od) {
    if (slot == LF_FW_SLOT_FACTORY) {
        snprintf(out, n, "%s", od ? od->factory : "");
    }
    else {
        snprintf(out, n, "%s.app%u", flash_base(), slot);
    }
}

static uint32_t crc32_buf(const uint8_t *p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    while (n--) {
        c ^= *p++;
        for (int k = 0; k < 8; k++) {
            c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
        }
    }
    return ~c;
}

static bool od_load(otadata_t *od) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s.otadata", flash_base());
    FILE *f = fopen(path, "rb");
    if (!f) {
        return false;
    }
    bool ok = fread(od, 1, sizeof(*od), f) == sizeof(*od);
    fclose(f);
    return ok && memcmp(od->magic, "LFOT", 4) == 0 && od->version == 1 &&
           od->crc == crc32_buf((const uint8_t *) od, offsetof(otadata_t, crc));
}

/* Atomic: written aside, then renamed over the old copy. */
static int od_store(otadata_t *od) {
    char path[PATH_MAX], tmp[PATH_MAX + 8];
    memcpy(od->magic, "LFOT", 4);
    od->version = 1;
    od->crc = crc32_buf((const uint8_t *) od, offsetof(otadata_t, crc));
    snprintf(path, sizeof(path), "%s.otadata", flash_base());
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (!f) {
        return PICOKEY_EXEC_ERROR;
    }
    bool ok = fwrite(od, 1, sizeof(*od), f) == sizeof(*od) && fflush(f) == 0 && fsync(fileno(f)) == 0;
    fclose(f);
    if (!ok || rename(tmp, path) != 0) {
        unlink(tmp);
        return PICOKEY_EXEC_ERROR;
    }
    return PICOKEY_OK;
}

static void self_path(char *out, size_t n) {
    ssize_t l = readlink("/proc/self/exe", out, n - 1);
    out[l > 0 ? l : 0] = '\0';
}

void lf_fw_emu_boot(void) {
    const char *booted = getenv("LF_EMU_BOOTED");
    if (booted) {
        /* This image was chosen by the boot step of the previous exec. */
        running_slot = (uint8_t) atoi(booted);
        unsetenv("LF_EMU_BOOTED");
        return;
    }
    otadata_t od;
    if (!od_load(&od)) {
        running_slot = LF_FW_SLOT_FACTORY;
        return;
    }
    uint8_t target = od.active;
    if (od.state == ST_NEW) {
        od.state = ST_PENDING;          /* first boot of the new image */
        od_store(&od);
    }
    else if (od.state == ST_PENDING) {
        /* The new image ran but was never confirmed: roll back. */
        printf("[fw] image in slot %u was not confirmed, rolling back\n", od.active);
        fflush(stdout);
        if (od.active != LF_FW_SLOT_FACTORY) {
            od.invalid[od.active] = 1;
        }
        od.state = ST_ABORTED;
        od.active = od.prev;
        od.prev = LF_FW_SLOT_FACTORY;
        target = od.active;
        od_store(&od);
    }
    char want[PATH_MAX], self[PATH_MAX];
    slot_path(target, want, sizeof(want), &od);
    self_path(self, sizeof(self));
    running_slot = target;
    if (strcmp(want, self) != 0) {
        char arg[8];
        snprintf(arg, sizeof(arg), "%u", target);
        setenv("LF_EMU_BOOTED", arg, 1);
        fflush(stdout);
        execl(want, "pico_fido2", (char *) NULL);
        /* Unbootable image: continue with this one (as the ROM would try the
         * other slot), and never select it again. */
        perror("[fw] exec");
        unsetenv("LF_EMU_BOOTED");
        if (target != LF_FW_SLOT_FACTORY) {
            od.invalid[target] = 1;
        }
        od.active = od.prev;
        od.state = ST_ABORTED;
        od_store(&od);
        running_slot = LF_FW_SLOT_FACTORY;
    }
}

static uint8_t other_slot(void) {
    return running_slot == 0 ? 1 : 0;
}

static void backend_abort(void) {
    char path[PATH_MAX + 8];
    if (upload) {
        fclose(upload);
        upload = NULL;
    }
    slot_path(upload_slot, path, PATH_MAX, NULL);
    strcat(path, ".tmp");
    unlink(path);
}

static int backend_begin(uint32_t size) {
    if (size > 64u * 1024 * 1024) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    char path[PATH_MAX + 8];
    upload_slot = other_slot();
    /* Like the ESP32, where the upload overwrites the slot in place: from
     * now on that slot is no rollback target, until activation. */
    otadata_t od;
    if (od_load(&od) && od.prev == upload_slot && !od.invalid[upload_slot]) {
        od.invalid[upload_slot] = 1;
        if (od_store(&od) != PICOKEY_OK) {
            return PICOKEY_EXEC_ERROR;
        }
    }
    slot_path(upload_slot, path, PATH_MAX, NULL);
    strcat(path, ".tmp");
    upload = fopen(path, "wb");
    return upload ? PICOKEY_OK : PICOKEY_EXEC_ERROR;
}

static int backend_write(const uint8_t *data, uint16_t len) {
    return fwrite(data, 1, len, upload) == len ? PICOKEY_OK : PICOKEY_EXEC_ERROR;
}

static int img_read(void *ctx, uint32_t off, uint8_t *buf, uint32_t len) {
    FILE *f = (FILE *) ctx;
    return fseek(f, (long) off, SEEK_SET) == 0 && fread(buf, 1, len, f) == len ? 0 : -1;
}

static int backend_finish(lf_fw_desc_t *desc) {
    if (fflush(upload) != 0 || fsync(fileno(upload)) != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    fclose(upload);
    upload = NULL;
    char tmp[PATH_MAX + 8], self[PATH_MAX];
    slot_path(upload_slot, tmp, PATH_MAX, NULL);
    strcat(tmp, ".tmp");
    FILE *f = fopen(tmp, "rb"), *me = NULL;
    if (!f) {
        return PICOKEY_EXEC_ERROR;
    }
    /* An executable for this machine, like the running one. */
    uint8_t h[20], mh[20];
    self_path(self, sizeof(self));
    me = fopen(self, "rb");
    int r = PICOKEY_VERIFICATION_FAILED;
    if (me && fread(h, 1, sizeof(h), f) == sizeof(h) && fread(mh, 1, sizeof(mh), me) == sizeof(mh) &&
        memcmp(h, "\x7f" "ELF", 4) == 0 && memcmp(h, mh, 20) == 0) {
        r = find_desc(img_read, f, written, desc);
    }
    if (me) {
        fclose(me);
    }
    fclose(f);
    if (r != PICOKEY_OK) {
        unlink(tmp);
    }
    return r;
}

static int backend_activate(void) {
    char tmp[PATH_MAX + 8], path[PATH_MAX];
    otadata_t od;
    if (!od_load(&od)) {
        memset(&od, 0, sizeof(od));
        /* First update: remember the executable that was started. */
        self_path(od.factory, sizeof(od.factory));
    }
    slot_path(upload_slot, path, sizeof(path), NULL);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    chmod(tmp, 0755);
    if (rename(tmp, path) != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    od.invalid[upload_slot] = 0;
    od.prev = running_slot;
    od.active = upload_slot;
    od.state = ST_NEW;
    return od_store(&od);
}

static bool running_pending(void) {
    otadata_t od;
    return od_load(&od) && od.active == running_slot && od.state == ST_PENDING;
}

void lf_fw_status(lf_fw_status_t *st) {
    otadata_t od;
    bool have = od_load(&od);
    st->slot = running_slot;
    st->pending = (have && od.active == running_slot && od.state == ST_PENDING) || fw_leaving;
    /* The previous image can be booted again if it is still there. */
    st->rollback_possible = false;
    if (!fw_leaving && have && od.active == running_slot && od.prev != running_slot) {
        char p[PATH_MAX];
        slot_path(od.prev, p, sizeof(p), &od);
        st->rollback_possible = (od.prev == LF_FW_SLOT_FACTORY || !od.invalid[od.prev]) && access(p, X_OK) == 0;
    }
}

int lf_fw_confirm(void) {
    otadata_t od;
    if (fw_leaving) {
        return PICOKEY_ERR_BLOCKED;     /* this image will not boot again */
    }
    if (!od_load(&od) || od.active != running_slot || od.state != ST_PENDING) {
        return PICOKEY_OK;
    }
    od.state = ST_VALID;
    return od_store(&od);
}

int lf_fw_rollback_desc(lf_fw_desc_t *desc) {
    lf_fw_status_t st;
    otadata_t od;
    lf_fw_status(&st);
    if (!st.rollback_possible || !od_load(&od)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    char p[PATH_MAX];
    slot_path(od.prev, p, sizeof(p), &od);
    FILE *f = fopen(p, "rb");
    if (!f) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    long size = fseek(f, 0, SEEK_END) == 0 ? ftell(f) : -1;
    int r = size > 0 && size <= 64L * 1024 * 1024 ? find_desc(img_read, f, (uint32_t) size, desc) : PICOKEY_VERIFICATION_FAILED;
    fclose(f);
    return r;
}

/* Like the ESP32 (esp_ota_mark_app_invalid_rollback): the running image is
 * never booted again, the previous one boots as it was (confirmed). */
int lf_fw_rollback(void) {
    lf_fw_status_t st;
    otadata_t od;
    lf_fw_status(&st);
    if (!st.rollback_possible || !od_load(&od)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (running_slot != LF_FW_SLOT_FACTORY) {
        od.invalid[running_slot] = 1;
    }
    od.active = od.prev;
    od.prev = LF_FW_SLOT_FACTORY;
    od.state = ST_VALID;
    fw_leaving = true;
    int r = od_store(&od);
    if (r != PICOKEY_OK) {
        fw_leaving = false;
    }
    return r;
}
#endif
