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
#include <stdio.h>

extern int scan_files_fido();
extern void init_otp();

/* Runs once at boot, after the store, the device root and USB are up.
 * Key material is only created or loaded when the key store is unlocked;
 * a HARDENED build on an incompletely provisioned chip stays inert. */
int picokey_init() {
    if (!security_keystore_unlocked()) {
        printf("[librefido] key store locked: chip security state incomplete\n");
        return PICOKEY_ERR_BLOCKED;
    }
    scan_files_fido();
#ifdef ENABLE_OTP_APP
    init_otp();
#endif
    return PICOKEY_OK;
}
