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

#include "pico_keys.h"
#include "lf_policy.h"
#ifdef LF_STORE_V2
#include "lf_boot.h"
#include "lf_fw.h"
#include "lf_profile.h"
#include "lf_sys.h"
#endif

uint8_t lf_auto_flag(uint8_t app) {
#ifdef LF_STORE_V2
    if (app < LF_APP_COUNT) {
        return (uint8_t) (LF_PROFILE_F_AUTO_FIDO << app);
    }
#else
    (void) app;
#endif
    return 0;
}

#if defined(LF_STORE_V2)
/* The profile whose store is mounted, not lf_sys()->active, which already
 * names the next profile once a switch waits for its reboot. */
static const lf_profile_entry_t *active_entry(void) {
    if (!lf_storage_ready()) {
        return NULL;
    }
    uint8_t idx = lf_profile_mounted();
    const lf_sys_t *s = lf_sys();
    if (idx >= LF_MAX_PROFILES || !s->profile[idx].used) {
        return NULL;
    }
    return &s->profile[idx];
}
#endif

bool lf_profile_is_secure(void) {
#if defined(LF_PROFILE_HARDENED)
    return true;
#elif defined(LF_STORE_V2)
    const lf_profile_entry_t *p = active_entry();
    return p && (p->flags & LF_PROFILE_F_SECURE);
#else
    return false;
#endif
}

bool lf_profile_sealed_only(void) {
#if defined(LF_STORE_V2)
    const lf_profile_entry_t *p = active_entry();
    return p && (p->flags & LF_PROFILE_F_SECURE);
#else
    return false;
#endif
}

bool lf_migrate_ok(void) {
#if defined(LF_STORE_V2)
    /* Not while unconfirmed, not once a rollback or a new image is on its
     * way, and not while any restart is scheduled (it may be one of those). */
    return !lf_fw_migration_blocked() && !lf_reboot_scheduled();
#else
    return true;
#endif
}

bool lf_presence_automatic(uint8_t app) {
#if defined(LF_PROFILE_HARDENED) || !defined(LF_STORE_V2)
    (void) app;
    return false;
#else
    uint8_t f = lf_auto_flag(app);
    const lf_profile_entry_t *p = active_entry();
    return f && p && !(p->flags & LF_PROFILE_F_SECURE) && (p->flags & f);
#endif
}

bool lf_wait_presence(uint8_t app) {
    if (lf_presence_automatic(app)) {
        return false;
    }
    return wait_button();
}
