/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
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

#include "pico_keys.h"
#include "file.h"
#include "fido.h"
#include "ctap.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#ifdef ESP_PLATFORM
#include "esp_compat.h"
#endif
#include "fs/phy.h"
#include "files.h"
#include "sks.h"
#include "mbedtls/platform_util.h"

extern void scan_all();
extern bool has_keydev_dec;
extern uint8_t keydev_dec[32];
extern void stopUsingPinUvAuthToken();
extern int resetPinUvAuthToken();
extern void reset_gna_state();
extern void cred_mgmt_reset_state(void);
extern void vendor_reset_state(void);
extern void large_blobs_reset_state(void);

/* What authenticatorReset erases: the FIDO (CTAP2 and U2F) state only. The
 * OATH and OTP credentials, OpenPGP and PIV, the device configuration and
 * the profile's identity and root key belong to others. */
static bool fido_owned(uint16_t fid) {
    switch (fid) {
        case EF_KEY_DEV: case EF_KEY_DEV_ENC: case EF_MKEK:
        case EF_EE_DEV: case EF_EE_DEV_EA:
        case EF_COUNTER: case EF_OPTS:
        case EF_PIN: case EF_AUTHTOKEN: case EF_PAUTHTOKEN:
        case EF_MINPINLEN: case EF_PIN_COMPLEXITY_POLICY: case EF_LARGEBLOB:
            return true;
    }
    return (fid & 0xFF00) == EF_CRED || (fid & 0xFF00) == EF_RP;
}

/* Commands that destroy the FIDO keys are only accepted in the first 10 s
 * after power up (CTAP 2.1, 6.6), unless the board option turns this off. */
bool fido_in_power_up_window(void) {
#ifndef ENABLE_EMULATION
#if defined(ENABLE_POWER_ON_RESET) && ENABLE_POWER_ON_RESET == 1
    if (!(phy_data.opts & PHY_OPT_DISABLE_POWER_RESET) && board_millis() > 10000) {
        return false;
    }
#endif
#endif
    return true;
}

/* The same window without the board option: for the commands that move the
 * device key in or out (protect, export, restore). The option can be set by
 * whoever holds an acfg token, the holder these commands are about. */
bool fido_in_strict_power_up_window(void) {
#if !defined(ENABLE_EMULATION) && defined(ENABLE_POWER_ON_RESET) && ENABLE_POWER_ON_RESET == 1
    return board_millis() <= 10000;
#else
    return true;
#endif
}

int cbor_reset() {
    if (!fido_in_power_up_window()) {
        return CTAP2_ERR_NOT_ALLOWED;
    }
    /* Also reached from the management applet: while the root key is not in
     * use a new device key could only be made under the wrong one. */
    if (!fido_keystore_ok()) {
        return CTAP2_ERR_NOT_ALLOWED;
    }
    /* destructive: always a physical press, whatever the presence policy */
    if (fido_wait_physical_press() == true) {
        return fido_up_error();
    }
    /* RAM copies of the old device key and PIN key go first, and the
     * pinUvAuthToken: it was obtained with the PIN that is being erased.
     * So does the command state of the profile being wiped (also when the
     * reset comes from the management applet, not through cbor_parse):
     * getNextAssertion holds decrypted user entities, then credMgmt
     * enumeration, the vendor MSE session, a pending largeBlob write. */
    has_keydev_dec = false;
    mbedtls_platform_zeroize(keydev_dec, sizeof(keydev_dec));
    mbedtls_platform_zeroize(session_pin, sizeof(session_pin));
    stopUsingPinUvAuthToken();
    resetPinUvAuthToken();
    reset_gna_state();
    cred_mgmt_reset_state();
    vendor_reset_state();
    large_blobs_reset_state();
    if (file_wipe_matching(fido_owned) != PICOKEY_OK) {
        return CTAP1_ERR_OTHER;
    }
    /* Crypto-shredding on top of the wipe: whatever copy of a FIDO sks
     * record flash may still hold can no longer be opened. */
    sks_rotate(SKS_NS_FIDO);
    init_fido();
    return 0;
}
