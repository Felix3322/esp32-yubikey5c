/*
 * This file is part of the LibreFido distribution (https://github.com/librekeys/pico-fido2).
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
#include "security.h"
#include "otp.h"
#include <stdio.h>
#include "fido/files.h"
#ifdef LF_STORE_V2
#include "lf_mgmt.h"
#include "lf_keyio.h"
#endif

extern int scan_files_fido();
extern void init_otp();
extern uint16_t fido_export_pin_check(const uint8_t *pin, uint16_t len);
extern void fido_get_aaguid(uint8_t out[16]);
extern int fido_aaguid_set(const uint8_t *in);

#ifdef LF_STORE_V2
static int mgmt_aaguid_get(uint8_t out[16]) {
    fido_get_aaguid(out);
    return PICOKEY_OK;
}
#endif

#ifdef LF_STORE_V2
/* PIN check of the management applet (export, import into the active slot,
 * firmware update, rollback, ROM loader): the FIDO PIN of the mounted
 * profile. It works while the key store is locked too, or a locked store
 * would reduce a firmware update to a touch. The stored verifier is derived
 * from the root key, so it can only be checked with that key loaded
 * (otp_key_1). A root record that is present but not loaded (it cannot be
 * unwrapped, it waits to be bound, or it was bound during this boot) would
 * make even the right PIN mismatch, and every attempt costs a retry before
 * the comparison: refused with 6982 before any retry is used. A legacy
 * NO-OTP profile has no root record and was derived without one. */
static uint16_t mgmt_pin_check(const uint8_t *pin, uint16_t len) {
    if (!file_has_data(ef_pin)) {
        return 0x6A88;
    }
    /* security_root_unavailable(): a root record exists but is not in use.
     * A profile recorded as having no root key (the HMAC-wrapped "no root"
     * marker) is not in that state: its verifier was derived without one. */
    if (security_root_unavailable()) {
        return 0x6982;
    }
    return fido_export_pin_check(pin, len);
}
#endif

/* Runs once at boot, after the store and the device root are up and the
 * USB buffers exist, but before the USB stack starts (main.c): no command
 * can arrive while it runs. Key material is only created or loaded when the
 * key store is unlocked; a HARDENED build on an incompletely provisioned
 * chip stays inert. */
int picokey_init() {
    /* The PIN file is known whether or not the key store unlocks: getInfo
     * reports clientPin from it, and the management PIN check needs it. */
    ef_pin = search_by_fid(EF_PIN, NULL, SPECIFY_EF);
#ifdef LF_STORE_V2
    lf_mgmt_set_pin_verifier(mgmt_pin_check);
    lf_mgmt_set_aaguid_hooks(mgmt_aaguid_get, fido_aaguid_set);
    /* Single-key transfer (lf_keyio.h). The management applet refuses it
     * while the key store is locked, so the hooks may be known either way. */
    lf_keyio_fido_register();
#if defined(ENABLE_OATH_APP) && ENABLE_OATH_APP
    lf_keyio_oath_register();
#endif
#if defined(ENABLE_OTP_APP) && ENABLE_OTP_APP
    lf_keyio_otp_register();
#endif
    lf_keyio_openpgp_piv_register();
#endif
    if (!security_keystore_unlocked()) {
        printf("[librefido] key store locked: chip security state incomplete\n");
        return PICOKEY_ERR_BLOCKED;
    }
    scan_files_fido();
#if defined(ENABLE_OTP_APP) && ENABLE_OTP_APP      /* CMake defines it 0 when off */
    init_otp();
#endif
    return PICOKEY_OK;
}
