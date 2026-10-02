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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pico_keys.h"
#include "random.h"
#include "file.h"
#include "phy.h"
#include "low_flash.h"
#include "security.h"
#include "lf_boot.h"
#include "lf_sys.h"
#include "lf_store.h"
#include "lf_backup.h"
#include "lf_profile.h"
#include "lf_policy.h"
#include "crypto_utils.h"

#if defined(ESP_PLATFORM)
#include "esp_system.h"
#else
#include <unistd.h>
#endif

extern void scan_flash(void);
extern void low_flash_discard_cache(void);
extern uintptr_t end_rom_pool, start_rom_pool, end_data_pool, start_data_pool;
extern uintptr_t flash_read_uintptr(uintptr_t addr);

/* Boots that may start a pending import or restore test. */
#define LF_PENDING_TRIES    3

static lf_boot_status_t boot_status = LF_BOOT_OK;
static bool ready = false;

lf_boot_status_t lf_boot_status(void) {
    return boot_status;
}

bool lf_storage_ready(void) {
    return ready;
}

uint8_t lf_active_profile(void) {
    return lf_sys()->active;
}

static lf_profile_entry_t *mounted_entry(void) {
    return ready ? &lf_sys()->profile[lf_profile_mounted() % LF_MAX_PROFILES] : NULL;
}

uint8_t lf_boot_profile_flags(void) {
    const lf_profile_entry_t *p = mounted_entry();
    return p ? p->flags : 0;
}

/* The mark that a profile's root was seen bound belongs to that profile: a
 * tag of its uuid, which every import and wipe replaces (also those of older
 * firmware, which keep the mark's bytes). */
static uint16_t bound_tag(const lf_profile_entry_t *p) {
    uint16_t t = (uint16_t) crc32c(p->uuid, sizeof(p->uuid));
    return t ? t : 1;
}

static void set_bound(lf_profile_entry_t *p, uint16_t tag) {
    p->root_bound[0] = (uint8_t) tag;
    p->root_bound[1] = (uint8_t) (tag >> 8);
}

static bool is_bound(const lf_profile_entry_t *p) {
    return (uint16_t) (p->root_bound[0] | (p->root_bound[1] << 8)) == bound_tag(p);
}

bool lf_boot_root_bound(void) {
    const lf_profile_entry_t *p = mounted_entry();
    return p && is_bound(p);
}

void lf_boot_note_root_bound(void) {
    lf_profile_entry_t *p = mounted_entry();
    /* Not from firmware that may still roll back (lf_migrate_ok()): the one
     * before would keep a mark it does not maintain. */
    if (p && !is_bound(p) && lf_migrate_ok()) {
        uint8_t old[2] = { p->root_bound[0], p->root_bound[1] };
        set_bound(p, bound_tag(p));
        if (lf_sys_commit() != PICOKEY_OK) {
            memcpy(p->root_bound, old, sizeof(old));    /* recorded at a later mount */
        }
    }
}

const char *lf_boot_status_str(lf_boot_status_t s) {
    switch (s) {
        case LF_BOOT_OK: return "ok";
        case LF_BOOT_ERR_LAYOUT: return "partition table lacks the LibreFido 2 regions or their 'encrypted' flag";
        case LF_BOOT_ERR_SYS: return "system area is unreadable";
        case LF_BOOT_ERR_MIGRATION: return "legacy store could not be migrated (left untouched)";
        case LF_BOOT_ERR_MOUNT: return "active profile cannot be mounted";
    }
    return "unknown";
}

void lf_reboot(void) {
#if defined(ESP_PLATFORM)
    esp_restart();
#else
    lf_region_emu_sync();
    fflush(stdout);
    execl("/proc/self/exe", "pico_fido2", (char *) NULL);
    perror("re-exec");
    exit(3);
#endif
}

static void new_uuid(uint8_t uuid[16]) {
    random_gen(NULL, uuid, 16);
    uuid[6] = (uint8_t) ((uuid[6] & 0x0F) | 0x40);  /* RFC 4122 version 4 */
    uuid[8] = (uint8_t) ((uuid[8] & 0x3F) | 0x80);
}

/* ------------------------------------------------------------------------ */
/* Profile identity (EF_PROFILE_ID)                                         */
/* ------------------------------------------------------------------------ */

typedef struct __attribute__((packed)) {
    uint8_t version;
    uint8_t uuid[16];
    uint8_t serial[8];
} lf_identity_t;

int lf_identity_write(const uint8_t uuid[16], const uint8_t serial[8]) {
    lf_identity_t id;
    id.version = 1;
    memcpy(id.uuid, uuid, sizeof(id.uuid));
    memcpy(id.serial, serial, sizeof(id.serial));
    file_t *f = search_file(EF_PROFILE_ID);
    if (f == NULL) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    return file_put_data(f, (const uint8_t *) &id, sizeof(id));
}

bool lf_identity_read(uint8_t uuid[16], uint8_t serial[8]) {
    file_t *f = search_file(EF_PROFILE_ID);
    if (!file_has_data(f) || file_get_size(f) != sizeof(lf_identity_t)) {
        return false;
    }
    const lf_identity_t *id = (const lf_identity_t *) file_get_data(f);
    if (id->version != 1) {
        return false;
    }
    memcpy(uuid, id->uuid, 16);
    memcpy(serial, id->serial, 8);
    return true;
}

void lf_identity_apply(void) {
    uint8_t uuid[16], serial[8];
    if (!lf_identity_read(uuid, serial)) {
        /* First mount: the first profile presents the chip serial (as the
         * device always did), other profiles their own random one. */
        uint8_t mounted = lf_profile_mounted();
        const lf_profile_entry_t *p = &lf_sys()->profile[mounted];
        memcpy(uuid, p->uuid, sizeof(uuid));
        if (mounted == 0) {
            memcpy(serial, pico_chip_serial.id, sizeof(serial));
        }
        else {
            random_gen(NULL, serial, sizeof(serial));
        }
        if (lf_identity_write(uuid, serial) == PICOKEY_OK) {
            low_flash_commit();
        }
    }
    pico_serial_set(serial);
}

/* ------------------------------------------------------------------------ */
/* Regions                                                                  */
/* ------------------------------------------------------------------------ */

static bool region_used(uint8_t r) {
    for (uint8_t p = 0; p < LF_MAX_PROFILES; p++) {
        if (lf_sys()->profile[p].used && lf_sys()->profile[p].region == r) {
            return true;
        }
    }
    return false;
}

/* A store region that backs no profile, or -1. */
static int free_region(void) {
    for (uint8_t r = 0; r < LF_STORE_REGIONS; r++) {
        if (!region_used(r)) {
            return r;
        }
    }
    return -1;
}

/* Formats a free region for profile slot pidx and records it (not committed). */
static int create_profile(uint8_t pidx) {
    int region = free_region();
    if (region < 0) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    lf_profile_entry_t *p = &lf_sys()->profile[pidx];
    uint8_t uuid[16];
    new_uuid(uuid);
    int ret = lf_store_format((uint8_t) region, uuid);
    if (ret != PICOKEY_OK) {
        return ret;
    }
    p->used = 1;
    p->region = (uint8_t) region;
    p->flags = 0;               /* nothing of a policy the slot had before */
    set_bound(p, 0);            /* a new store: its root is made at first mount */
    memcpy(p->uuid, uuid, sizeof(uuid));
    return PICOKEY_OK;
}

/* Regions left formatted but unreferenced (a cut after an operation switched
 * the system area, or during the erase of a deleted profile) still hold a
 * profile's data: erase them. */
static void erase_orphans(void) {
    for (uint8_t r = 0; r < LF_STORE_REGIONS; r++) {
        if (!region_used(r) && lf_store_has_content(r)) {
            printf("[lf_boot] erasing unreferenced store region %u\n", r);
            lf_store_erase(r);
        }
    }
}

/* Leaves the mounted store: drops cached writes and every file pointer into
 * it (a later mount must never see addresses of this one). */
static void leave_store(void) {
    lf_store_unmount();
    low_flash_discard_cache();
    initialize_flash(false);
}

/* Writes the staged stream into the freshly mounted store. Its files may be
 * as large as earlier firmware stored them (a whole sector's payload), which
 * applications cannot create any more: carried data keeps its size. */
static int import_staged(lfbk_info_t *info) {
    scan_flash();
    flash_allow_sector_records(true);
    int r = lf_backup_import(info);
    flash_allow_sector_records(false);
    return r;
}

/* Every region must read back what is written to it: with flash encryption
 * on, a partition without the "encrypted" flag is written in plain but read
 * decrypted through the map (garbage that the next commit would persist). */
static bool regions_readable(void) {
    for (uint8_t id = 0; id < LF_REG_COUNT; id++) {
        lf_region_t reg;
        if (lf_region_open(&reg, id) && !lf_region_crypt_ok(&reg)) {
            printf("[lf_boot] ERROR: flash encryption is on but region %u is not marked encrypted\n", id);
            return false;
        }
    }
    return true;
}

/* ------------------------------------------------------------------------ */
/* Migration of the store of firmware before LibreFido 2                   */
/* ------------------------------------------------------------------------ */

static bool legacy_has_records(void) {
    uintptr_t d = flash_read_uintptr(end_data_pool), r = flash_read_uintptr(end_rom_pool);
    return (d >= start_data_pool && d < end_data_pool) || (r >= start_rom_pool && r < end_rom_pool);
}

/* Copies the legacy store into a new profile 1. The legacy region is only
 * read. Returns PICOKEY_ERR_FILE_NOT_FOUND if there is nothing to migrate. */
static int migrate_legacy(void) {
    int m = lf_store_mount_legacy();
    if (m != PICOKEY_OK) {
        /* No legacy region at all, or one that cannot be read (never taken
         * for "nothing to migrate": that would give up on its keys). */
        return m;
    }
    if (!legacy_has_records()) {
        leave_store();
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    printf("[lf_boot] migrating the legacy store into profile 1\n");
    scan_flash();

    lf_sys_t *sys = lf_sys();
    lfbk_header_t hdr;
    lf_backup_header_init(&hdr);
    hdr.flags = LFBK_F_MIGRATION;
    new_uuid(hdr.uuid);
    memcpy(hdr.serial, pico_chip_serial.id, sizeof(hdr.serial));
    memcpy(hdr.color, sys->profile[0].color, 3);
    memcpy(hdr.name, sys->profile[0].name, sizeof(hdr.name));

    /* Board settings become device wide. */
    file_t *phy = search_file(EF_PHY);
    if (file_has_data(phy) && file_get_size(phy) <= LF_BOARD_MAX) {
        sys->board_len = file_get_size(phy);
        memcpy(sys->board, file_get_data(phy), sys->board_len);
    }

    /* A readable legacy eFuse key protected this data: it becomes the root
     * key of the migrated profile. */
    const uint8_t *root = security_legacy_root();
    int r = lf_backup_export(&hdr, root, DRK_FLAG_LEGACY, LF_STAGE_MIGRATION);
    leave_store();
    if (r != PICOKEY_OK) {
        printf("[lf_boot] ERROR: legacy store cannot be read (%d)\n", r);
        lf_stage_clear();
        return r;
    }

    int region = free_region();
    if (region < 0) {
        lf_stage_clear();
        return PICOKEY_ERR_NO_MEMORY;
    }
    lfbk_info_t info;
    r = lf_store_format((uint8_t) region, hdr.uuid);
    if (r == PICOKEY_OK) {
        r = lf_store_mount((uint8_t) region);
    }
    if (r == PICOKEY_OK) {
        r = import_staged(&info);
    }
    leave_store();
    lf_stage_clear();
    if (r != PICOKEY_OK) {
        printf("[lf_boot] ERROR: migration failed (%d), the legacy store is unchanged\n", r);
        lf_store_erase((uint8_t) region);
        return r;
    }
    lf_profile_entry_t *p = &sys->profile[0];
    p->used = 1;
    p->region = (uint8_t) region;
    set_bound(p, 0);
    memcpy(p->uuid, hdr.uuid, sizeof(p->uuid));
    sys->active = 0;
    sys->flags |= LF_SYS_F_MIGRATED;
    sys->last_result = LF_RESULT_MIGRATED;
    printf("[lf_boot] migrated %u files, %u counters%s\n", (unsigned) info.files, (unsigned) info.counters,
           info.has_root ? ", legacy root key" : "");
    return PICOKEY_OK;
}

/* ------------------------------------------------------------------------ */
/* Pending operations (requested through the management applet)            */
/* ------------------------------------------------------------------------ */

/* The staged stream is the one the pending operation was requested with: a
 * sealed import stream for this very profile. Anything else (an export, or
 * an import for another slot, staged after the request) is refused. */
static int stage_for(uint8_t target) {
    uint8_t purpose = 0, staged = 0;
    if (!lf_stage_info(&purpose, &staged, NULL)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (purpose != LF_STAGE_IMPORT || staged != target) {
        printf("[lf_boot] ERROR: the staged stream (purpose %u, profile %u) is not the requested one\n",
               purpose, staged + 1);
        return PICOKEY_WRONG_DATA;
    }
    return PICOKEY_OK;
}

/* Builds the new content of profile `target` in a free region, verifies it and
 * only then switches the system area to it; the old region is erased last.
 * Returns the result of that switch: if the system area cannot be written,
 * the RAM record is reloaded from flash (which still holds the pending
 * operation and the old mapping) and no region is erased; the next boot
 * does it again. */
static int apply_pending(void) {
    lf_sys_t *sys = lf_sys();
    uint8_t op = sys->pending_op, target = sys->pending_profile;
    if (op == LF_OP_NONE) {
        return PICOKEY_OK;
    }
    int r = PICOKEY_ERR_NULL_PARAM;
    int region = -1;
    uint8_t result = LF_RESULT_OP_FAILED;
    int old = target < LF_MAX_PROFILES && sys->profile[target].used ? sys->profile[target].region : -1;

    /* An import or restore test parses a stream from outside: one that makes
     * the firmware crash must not do so at every boot. Each attempt is
     * recorded before it starts (a power cut also costs one). */
    bool gave_up = false;
    if (op == LF_OP_IMPORT || op == LF_OP_VERIFY) {
        if (sys->pending_tries >= LF_PENDING_TRIES) {
            printf("[lf_boot] ERROR: pending operation %u abandoned after %u attempts\n", op, sys->pending_tries);
            gave_up = true;
        }
        else {
            sys->pending_tries++;
            int c = lf_sys_commit();
            if (c != PICOKEY_OK) {
                lf_sys_load();
                return c;
            }
        }
    }

    if (target < LF_MAX_PROFILES && op == LF_OP_DELETE) {
        if (old >= 0) {
            /* Nothing of the deleted profile stays with the slot: a profile
             * made there later starts without its policies (automatic
             * presence needs its own touch), marks, name or colour. */
            lf_profile_entry_t *d = &sys->profile[target];
            d->used = 0;
            d->flags = 0;
            set_bound(d, 0);
            lf_sys_default_color(target, d->color);
            memset(d->name, 0, sizeof(d->name));
            snprintf(d->name, LF_PROFILE_NAME_MAX, "Profile %u", (unsigned) (target + 1));
            if (sys->active == target) {
                sys->active = 0;
                while (sys->active < LF_MAX_PROFILES && !sys->profile[sys->active].used) {
                    sys->active++;
                }
                if (sys->active == LF_MAX_PROFILES) {
                    sys->active = 0;
                }
            }
            result = LF_RESULT_DELETED;
            r = PICOKEY_OK;
        }
    }
    else if (op == LF_OP_VERIFY) {
        /* A full restore into scratch space: proves the backup can be brought
         * back by this firmware without touching any profile. */
        lfbk_info_t info;
        uint8_t uuid[16];
        memset(&info, 0, sizeof(info));
        r = gave_up ? PICOKEY_ERR_BLOCKED : stage_for(target);
        if (r == PICOKEY_OK) {
            r = lf_backup_check(&info);
        }
        memcpy(uuid, info.hdr.uuid, sizeof(uuid));
        region = free_region();
        if (r == PICOKEY_OK && region < 0) {
            r = PICOKEY_ERR_NO_MEMORY;
        }
        if (r == PICOKEY_OK) {
            r = lf_store_format((uint8_t) region, uuid);
        }
        if (r == PICOKEY_OK) {
            r = lf_store_mount((uint8_t) region);
            if (r == PICOKEY_OK) {
                r = import_staged(&info);
            }
            leave_store();
        }
        if (region >= 0) {
            lf_store_erase((uint8_t) region);
        }
        region = -1;
        old = -1;
        printf("[lf_boot] backup restore test: %s (%d)\n", r == PICOKEY_OK ? "passed" : "FAILED", r);
        result = r == PICOKEY_OK ? LF_RESULT_VERIFIED : LF_RESULT_VERIFY_FAILED;
        r = PICOKEY_OK;
    }
    else if (target < LF_MAX_PROFILES && (op == LF_OP_IMPORT || op == LF_OP_WIPE)) {
        lfbk_info_t info;
        uint8_t uuid[16];
        memset(&info, 0, sizeof(info));
        new_uuid(uuid);
        r = PICOKEY_OK;
        if (op == LF_OP_IMPORT) {
            r = gave_up ? PICOKEY_ERR_BLOCKED : stage_for(target);
            if (r == PICOKEY_OK && sys->profile[target].used && (sys->profile[target].flags & LF_PROFILE_F_SECURE)) {
                /* A secure profile is never replaced by an import (its keys
                 * never existed outside it); only a wipe or delete ends it. */
                printf("[lf_boot] ERROR: profile %u is a secure profile, no import into it\n", target + 1);
                r = PICOKEY_ERR_BLOCKED;
            }
            if (r == PICOKEY_OK) {
                r = lf_backup_check(&info);
            }
            memcpy(uuid, info.hdr.uuid, sizeof(uuid));
        }
        region = free_region();
        if (r == PICOKEY_OK && region < 0) {
            r = PICOKEY_ERR_NO_MEMORY;
        }
        if (r == PICOKEY_OK) {
            r = lf_store_format((uint8_t) region, uuid);
        }
        if (r == PICOKEY_OK && op == LF_OP_IMPORT) {
            r = lf_store_mount((uint8_t) region);
            if (r == PICOKEY_OK) {
                r = import_staged(&info);
            }
            leave_store();
        }
        if (r == PICOKEY_OK) {
            lf_profile_entry_t *p = &sys->profile[target];
            p->used = 1;
            p->region = (uint8_t) region;
            set_bound(p, 0);        /* recorded when its first mount sees it bound */
            memcpy(p->uuid, uuid, sizeof(p->uuid));
            if (op == LF_OP_IMPORT) {
                memcpy(p->color, info.hdr.color, 3);
                memcpy(p->name, info.hdr.name, sizeof(p->name));
                p->name[sizeof(p->name) - 1] = 0;
                /* Only what the owner may set on any device travels with a
                 * backup; policy bits (lf_policy.h) are never imported. */
                p->flags = info.hdr.profile_flags & LF_PROFILE_F_NO_EXPORT;
                result = LF_RESULT_IMPORTED;
            }
            else {
                /* The policy the request gave the new profile applies now
                 * that it exists (pending_flags, e.g. NO_EXPORT | SECURE for
                 * a secure profile); a plain wipe keeps the slot being secure
                 * or not exportable. Automatic presence starts off. */
                if (sys->pending_flags & LF_PENDING_F_SET) {
                    p->flags = sys->pending_flags;
                }
                p->flags &= LF_PROFILE_F_NO_EXPORT | LF_PROFILE_F_SECURE;
                result = old >= 0 ? LF_RESULT_WIPED : LF_RESULT_CREATED;
            }
        }
    }
    if (r != PICOKEY_OK) {
        /* The slot keeps its profile, its flags and its marks as they were
         * (the requested policy was never applied to it). */
        printf("[lf_boot] ERROR: pending operation %u on profile %u failed (%d)\n", op, target + 1, r);
        if (region >= 0) {
            lf_store_erase((uint8_t) region);
        }
        result = op == LF_OP_IMPORT ? LF_RESULT_IMPORT_FAILED : LF_RESULT_OP_FAILED;
        old = -1;
    }
    sys->pending_op = LF_OP_NONE;
    sys->pending_tries = 0;
    sys->pending_flags = 0;
    sys->last_result = result;
    int c = lf_sys_commit();
    if (c != PICOKEY_OK) {
        /* Flash still holds the request: the next boot takes it up again.
         * (Safe mode erases a staged stream, lf_stage_boot_cleanup(), so a
         * retried import then fails and leaves the profile as it was.) */
        printf("[lf_boot] ERROR: the system area cannot record operation %u (%d), taken up at the next boot\n", op, c);
        lf_sys_load();
        return c;
    }
    if (op == LF_OP_IMPORT || op == LF_OP_VERIFY) {
        lf_stage_clear();       /* consumed; the stream holds keys in the clear */
    }
    if (old >= 0 && old != region) {
        lf_store_erase((uint8_t) old);
    }
    return PICOKEY_OK;
}

/* ------------------------------------------------------------------------ */
/* Boot                                                                     */
/* ------------------------------------------------------------------------ */

/* Everything after the system area was read. */
static lf_boot_status_t boot_loaded(lf_sys_status_t s) {
    if (s == LF_SYS_CORRUPT) {
        return LF_BOOT_ERR_SYS;
    }
    lf_sys_t *sys = lf_sys();
    bool dirty = lf_sys_bad_copies() > 0;
    if (s == LF_SYS_BLANK) {
        lf_sys_defaults();
        int r = migrate_legacy();
        if (r == PICOKEY_ERR_FILE_NOT_FOUND) {
            if (create_profile(0) != PICOKEY_OK) {
                return LF_BOOT_ERR_MOUNT;
            }
            sys->active = 0;
        }
        else if (r != PICOKEY_OK) {
            /* Nothing was written, and nothing may be (a record without the
             * migrated profile would end the migration): the next boot tries
             * again. */
            lf_sys_block();
            return LF_BOOT_ERR_MIGRATION;
        }
        dirty = true;
    }
    if (dirty && lf_sys_commit() != PICOKEY_OK) {
        return LF_BOOT_ERR_SYS;
    }
    if (apply_pending() != PICOKEY_OK) {
        /* The regions the flash record references are all intact; erasing
         * "orphans" by the RAM record now could destroy one of them. */
        return LF_BOOT_ERR_SYS;
    }
    erase_orphans();
    if (sys->active >= LF_MAX_PROFILES || !sys->profile[sys->active].used) {
        sys->active = 0;
        while (sys->active < LF_MAX_PROFILES && !sys->profile[sys->active].used) {
            sys->active++;
        }
        if (sys->active == LF_MAX_PROFILES) {
            sys->active = 0;
            if (create_profile(0) != PICOKEY_OK) {
                return LF_BOOT_ERR_MOUNT;
            }
        }
        if (lf_sys_commit() != PICOKEY_OK) {
            return LF_BOOT_ERR_SYS;
        }
    }
    lf_profile_entry_t *p = &sys->profile[sys->active];
    if (lf_store_mount(p->region) != PICOKEY_OK) {
        return LF_BOOT_ERR_MOUNT;
    }
    const lf_health_t *h = lf_store_health();
    printf("[lf_store] profile %u mounted (region %u): %u sectors, %u repaired, %u ecc-corrected, "
           "%u unrecoverable, %u metadata repaired, journal %s\n",
           sys->active + 1, p->region, (unsigned) h->sectors_written, (unsigned) h->repaired_from_copy,
           (unsigned) h->corrected_ecc, (unsigned) h->uncorrectable, (unsigned) h->meta_repaired,
           h->journal_corrupt ? "corrupt" : (h->journal_replayed ? "replayed" : "clean"));
    if (h->repaired_from_copy || h->corrected_ecc || h->uncorrectable) {
        sys->repairs += h->repaired_from_copy + h->corrected_ecc;
        sys->uncorrectable += h->uncorrectable;
        lf_sys_commit();
    }
    ready = true;
    return LF_BOOT_OK;
}

lf_boot_status_t lf_storage_boot(void) {
    ready = false;
    if (!regions_readable()) {
        /* Nothing is read through the map nor written: the plain data stays
         * as it is until the partition table is fixed. */
        return boot_status = LF_BOOT_ERR_LAYOUT;
    }
    lf_sys_status_t s = lf_sys_load();
    if (s == LF_SYS_NO_REGION) {
        return boot_status = LF_BOOT_ERR_LAYOUT;
    }
    boot_status = boot_loaded(s);
    /* Streams left in the staging area hold keys in the clear: erased on
     * every boot, except one that a pending import or restore test still
     * needs (lf_backup.c decides, from the status and the pending op). */
    lf_stage_boot_cleanup();
    return boot_status;
}
