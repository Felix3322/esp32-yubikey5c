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
#include <string.h>
#include "pico_keys.h"
#include "low_flash.h"
#include "usb.h"
#include "lf_boot.h"
#include "lf_backup.h"
#include "lf_profile.h"
#include "lf_region.h"
#include "lf_store.h"
#include "lf_sys.h"

static uint32_t reboot_at = 0;
/* The store mounted at boot, recorded before a switch changes the active
 * profile of the system area (-1: no switch yet, the active one is it). */
static int16_t mounted = -1;

uint8_t lf_profile_led_color(uint8_t idx) {
    const uint8_t *c = lf_sys()->profile[idx % LF_MAX_PROFILES].color;
    uint8_t bits = (uint8_t) (((c[0] > 0x60) << 2) | ((c[1] > 0x60) << 1) | (c[2] > 0x60));
    static const uint8_t palette[8] = {
        LED_COLOR_GREEN, LED_COLOR_BLUE, LED_COLOR_GREEN, LED_COLOR_CYAN,
        LED_COLOR_RED, LED_COLOR_MAGENTA, LED_COLOR_YELLOW, LED_COLOR_WHITE
    };
    return palette[bits];
}

uint8_t lf_profile_mounted(void) {
    return mounted >= 0 ? (uint8_t) mounted : lf_sys()->active;
}

/* Changes made without a touch since the last touch-confirmed one. Kept in
 * the system record (lf_sys_t.rfu, 0 in records of older firmware) and
 * written by the commit of the change itself: a restart, even one the host
 * causes by switching the USB power, does not renew the allowance. */
#define FREE_USED(s)    ((s)->rfu)

bool lf_sys_change_allowed(void) {
    lf_sys_t *s = lf_sys();
    if (FREE_USED(s) < LF_FREE_SYS_CHANGES) {
        FREE_USED(s)++;
        return true;
    }
    if (wait_button() == false) {
        FREE_USED(s) = 0;
        return true;
    }
    return false;
}

void lf_sys_change_confirmed(void) {
    FREE_USED(lf_sys()) = 0;
}

uint8_t lf_sys_free_changes(void) {
    uint8_t used = FREE_USED(lf_sys());
    return used < LF_FREE_SYS_CHANGES ? (uint8_t) (LF_FREE_SYS_CHANGES - used) : 0;
}

int lf_profile_select(uint8_t idx) {
    lf_sys_t *s = lf_sys();
    if (idx >= LF_MAX_PROFILES) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    if (s->pending_op != LF_OP_NONE) {
        return PICOKEY_ERR_BLOCKED;
    }
    if (mounted < 0) {
        mounted = s->active;
    }
    uint8_t active = s->active, op = s->pending_op, target = s->pending_profile, flags = s->profile[idx].flags;
    s->active = idx;
    if (!s->profile[idx].used) {
        s->pending_op = LF_OP_WIPE;     /* creates the empty profile at boot */
        s->pending_profile = idx;
        s->profile[idx].flags = 0;      /* nothing of a deleted profile's policies */
    }
    /* Nothing of the current profile may stay in the cache. */
    low_flash_commit();
    int r = lf_sys_commit();
    if (r != PICOKEY_OK) {
        /* Not recorded: a later, unrelated commit must not carry it out. */
        s->active = active;
        s->pending_op = op;
        s->pending_profile = target;
        s->profile[idx].flags = flags;
    }
    return r;
}

int lf_profile_create(uint8_t idx, uint8_t flags) {
    lf_sys_t *s = lf_sys();
    if (idx >= LF_MAX_PROFILES) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    if (s->pending_op != LF_OP_NONE) {
        return PICOKEY_ERR_BLOCKED;
    }
    uint8_t target = s->pending_profile;
    /* Recorded with the request, not on the slot: the boot applies them to
     * the new profile only once its store is built (lf_boot.c,
     * apply_pending). If that fails, the old profile keeps its own flags
     * (it must not become "secure" without having been created secure). */
    s->pending_flags = (uint8_t) (flags | LF_PENDING_F_SET);
    s->pending_op = LF_OP_WIPE;
    s->pending_profile = idx;
    low_flash_commit();
    int r = lf_sys_commit();
    if (r != PICOKEY_OK) {
        s->pending_flags = 0;
        s->pending_op = LF_OP_NONE;
        s->pending_profile = target;
    }
    return r;
}

int lf_profile_select_next(void) {
    lf_sys_t *s = lf_sys();
    uint8_t slots = s->button_slots;
    if (slots < 1 || slots > LF_MAX_PROFILES) {
        slots = 2;
    }
    uint8_t next = (uint8_t) ((s->active + 1) % slots);
    if (next == s->active) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    return lf_profile_select(next);
}

/* Length of the valid UTF-8 prefix of s[0..n) (RFC 3629: shortest forms,
 * no surrogates, nothing above U+10FFFF), ending at the first NUL. */
static size_t utf8_prefix(const uint8_t *s, size_t n) {
    size_t i = 0;
    while (i < n && s[i] != 0) {
        uint8_t c = s[i];
        size_t k;
        uint32_t cp;
        if (c < 0x80) {
            i++;
            continue;
        }
        if (c >= 0xC2 && c <= 0xDF) {
            k = 1;
            cp = c & 0x1F;
        }
        else if (c >= 0xE0 && c <= 0xEF) {
            k = 2;
            cp = c & 0x0F;
        }
        else if (c >= 0xF0 && c <= 0xF4) {
            k = 3;
            cp = c & 0x07;
        }
        else {
            break;
        }
        if (n - i - 1 < k) {
            break;                      /* cut inside the character */
        }
        size_t j = 1;
        for (; j <= k && (s[i + j] & 0xC0) == 0x80; j++) {
            cp = (cp << 6) | (s[i + j] & 0x3F);
        }
        if (j <= k || (k == 2 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) ||
            (k == 3 && (cp < 0x10000 || cp > 0x10FFFF))) {
            break;
        }
        i += k + 1;
    }
    return i;
}

bool lf_profile_name_valid(const char *name, size_t len) {
    return len < LF_PROFILE_NAME_MAX && utf8_prefix((const uint8_t *) name, len) == len;
}

void lf_profile_name_sanitize(char *name, size_t size) {
    if (size == 0) {
        return;
    }
    size_t n = utf8_prefix((const uint8_t *) name, size - 1);
    memset(name + n, 0, size - n);
}

static void entry_apply(lf_profile_entry_t *p, const char *name, const uint8_t rgb[3], int flags) {
    if (name) {
        memset(p->name, 0, sizeof(p->name));
        memcpy(p->name, name, strnlen(name, sizeof(p->name) - 1));
        lf_profile_name_sanitize(p->name, sizeof(p->name));
    }
    if (rgb) {
        memcpy(p->color, rgb, 3);
    }
    if (flags >= 0) {
        p->flags = (uint8_t) flags;
    }
}

bool lf_profile_differs(uint8_t idx, const char *name, const uint8_t rgb[3], int flags) {
    if (idx >= LF_MAX_PROFILES) {
        return false;
    }
    lf_profile_entry_t e = lf_sys()->profile[idx];
    entry_apply(&e, name, rgb, flags);
    return memcmp(&e, &lf_sys()->profile[idx], sizeof(e)) != 0;
}

int lf_profile_set(uint8_t idx, const char *name, const uint8_t rgb[3], int flags) {
    if (idx >= LF_MAX_PROFILES) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    lf_profile_entry_t *p = &lf_sys()->profile[idx], old = *p;
    entry_apply(p, name, rgb, flags);
    if (memcmp(p, &old, sizeof(old)) == 0) {
        return PICOKEY_OK;              /* the system area is not rewritten */
    }
    int r = lf_sys_commit();
    if (r != PICOKEY_OK) {
        *p = old;
        return r;
    }
    if (idx == lf_sys()->active) {
        led_set_profile_color(lf_profile_led_color(idx));
    }
    return r;
}

int lf_profile_request(uint8_t op, uint8_t idx) {
    lf_sys_t *s = lf_sys();
    if (idx >= LF_MAX_PROFILES ||
        (op != LF_OP_IMPORT && op != LF_OP_WIPE && op != LF_OP_DELETE && op != LF_OP_VERIFY)) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    if (s->pending_op != LF_OP_NONE) {
        return PICOKEY_ERR_BLOCKED;
    }
    if (op == LF_OP_DELETE && !s->profile[idx].used) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint8_t target = s->pending_profile;
    s->pending_op = op;
    s->pending_profile = idx;
    low_flash_commit();
    int r = lf_sys_commit();
    if (r != PICOKEY_OK) {
        /* The host is told that nothing happened: a later commit (a rename)
         * must not record the operation behind its back. */
        s->pending_op = LF_OP_NONE;
        s->pending_profile = target;
    }
    return r;
}

int lf_factory_reset(bool legacy_too) {
    lf_region_t r;
    int ret = PICOKEY_OK;
    /* The RAM record describes the stores about to be erased: nothing may
     * write it back before the reboot (a rename, board settings, the long
     * press), or the next boot would find profiles without stores instead
     * of a blank system area. */
    lf_sys_block();
    low_flash_discard_cache();
    lf_store_unmount();
    /* No file keeps a pointer into the unmounted store until the reboot. */
    initialize_flash(false);
    for (uint8_t i = 0; i < LF_STORE_REGIONS; i++) {
        /* Header last: an interrupted erase is finished at the next boot. */
        if (lf_region_open(&r, LF_REG_STORE(i)) && lf_store_erase(i) != PICOKEY_OK) {
            ret = PICOKEY_ERR_MEMORY_FATAL;
        }
    }
    if (lf_region_open(&r, LF_REG_STAGE) && lf_region_erase(&r, 0, r.size) != PICOKEY_OK) {
        ret = PICOKEY_ERR_MEMORY_FATAL;
    }
    if (legacy_too && lf_region_open(&r, LF_REG_LEGACY) && lf_region_erase(&r, 0, r.size) != PICOKEY_OK) {
        ret = PICOKEY_ERR_MEMORY_FATAL;
    }
    /* Last: without a system area the next boot starts from scratch (and
     * would migrate the legacy store again if it was kept). */
    if (lf_region_open(&r, LF_REG_SYS) && lf_region_erase(&r, 0, r.size) != PICOKEY_OK) {
        ret = PICOKEY_ERR_MEMORY_FATAL;
    }
    return ret;
}

void lf_reboot_later(uint32_t delay_ms) {
    reboot_at = board_millis() + delay_ms;
    if (reboot_at == 0) {
        reboot_at = 1;
    }
}

bool lf_reboot_scheduled(void) {
    return reboot_at != 0;
}

void lf_reboot_poll(void) {
    if (reboot_at != 0 && (int32_t) (board_millis() - reboot_at) >= 0 && !is_busy()) {
        low_flash_commit();
        lf_reboot();
    }
}
