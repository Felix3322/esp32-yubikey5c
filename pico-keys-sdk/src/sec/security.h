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

/*
 * Device root key (DRK) and chip security state.
 *
 * Every at-rest secret is ultimately wrapped with keys derived from the DRK,
 * a 32 byte random value exposed to the rest of the firmware through the
 * historical `otp_key_1` pointer. Its origin, in order of preference:
 *
 *  1. legacy readable eFuse key (devices provisioned by older firmware, kept
 *     so their existing credentials stay valid),
 *  2. the EF_DEVROOT record, wrapped with a KEK computed by the ESP32 HMAC
 *     peripheral from a read-protected eFuse key (HMAC_UP purpose),
 *  3. the EF_DEVROOT record stored in plain (unprovisioned device),
 *  4. none: legacy "NO-OTP" derivations for stores created without any root.
 *
 * Provisioning the HMAC key only re-wraps the DRK, so it never invalidates
 * existing credentials. The firmware never burns eFuses on its own; only an
 * explicit, user-present provisioning command does (see security_provision).
 *
 * A plain record (3) is not protected at rest: it is only as safe as the
 * flash (flash encryption). On a chip with the HMAC key it is re-wrapped when
 * the profile is mounted, except once Secure Boot is on: then a plain record
 * could have been planted by whoever wrote the flash, so it stays unused
 * (key store locked) until security_provision_hmac_key() binds it. The same
 * holds for a profile with files but no root record (4): the binding then
 * records that it has none (an HMAC-wrapped marker). A wrapped record whose
 * key is missing, or that does not authenticate, locks the key store too; it
 * is never replaced by a new root.
 *
 * The system area records per profile that its root was seen bound: such a
 * profile, and a secure profile (lf_policy.h), whose root record turns up
 * in plain or goes missing stays locked for good (planted or removed). A
 * secure profile's root is wrapped with the HMAC key from the moment it is
 * made and never exists in plain; without that key it is not made.
 */

#ifndef _SECURITY_H_
#define _SECURITY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define EF_DEVROOT              0xE021

enum {
    DRK_SOURCE_NONE = 0,         /* legacy NO-OTP derivations */
    DRK_SOURCE_LEGACY_EFUSE,     /* readable legacy eFuse key */
    DRK_SOURCE_FLASH_PLAIN,      /* random DRK, not bound to the chip */
    DRK_SOURCE_FLASH_HMAC,       /* random DRK wrapped by the HMAC eFuse key */
};

typedef struct {
    bool secure_boot;            /* Secure Boot V2 enabled */
    bool flash_encryption;       /* flash encryption enabled */
    bool flash_enc_release;      /* ... in release mode */
    bool jtag_disabled;          /* pad + USB JTAG permanently disabled */
    bool download_restricted;    /* ROM download disabled or secure download */
    bool anti_rollback;          /* firmware built with anti-rollback */
    uint32_t secure_version;     /* eFuse anti-rollback counter */
    bool hmac_key;               /* HMAC_UP key provisioned (read protected) */
    bool legacy_keys_readable;   /* legacy USER eFuse keys still readable */
    uint8_t drk_source;
    bool hardened_ok;            /* every HARDENED requirement is met */
} security_state_t;

extern void security_init(void);
extern const security_state_t *security_state(void);

/* In HARDENED builds the key store is unusable unless hardened_ok. */
extern bool security_keystore_unlocked(void);

/* Serializes the state as TLV for the management/rescue status command. */
extern uint16_t security_status_tlv(uint8_t *out, uint16_t max);

/* Burns a device-generated HMAC_UP key into the configured eFuse block and
 * re-wraps the DRK with it. Irreversible; the caller must have collected user
 * presence. Idempotent once provisioned: then it only binds the root key of
 * the mounted profile (also one held in plain, which unlocks at the next
 * start). Returns PICOKEY_* codes. */
extern int security_provision_hmac_key(void);

/* Emergency erase of the DRK record (full device reset). All data wrapped
 * under the old DRK becomes unrecoverable (crypto-shredding). */
extern int security_rotate_drk(void);

/* The chip holds the HMAC eFuse key root keys are bound to. */
extern bool security_hmac_key_available(void);

/* The mounted profile has a root key that is not in use: held until bound,
 * bound during this boot (in use after a restart), or a record that cannot
 * be unwrapped. Nothing that needs the root (an export) may proceed. */
extern bool security_root_unavailable(void);

/* Burns DIS_PAD_JTAG, DIS_USB_JTAG and ENABLE_SECURITY_DOWNLOAD (secure
 * download mode: flashing still works, reading does not) and verifies them.
 * Irreversible; only the touch-confirmed management command calls it.
 * PICOKEY_OK also when they were set already; PICOKEY_ERR_FILE_NOT_FOUND
 * without eFuses. */
extern int security_lock_debug(void);

/* LibreFido 2 profiles: the DRK is the root key of the mounted profile. Only
 * its wrapping (HMAC eFuse KEK, AAD with the chip serial) is bound to the
 * chip, so a backup carries it in the clear and an import re-wraps it. */
#define DRK_FLAG_LEGACY         0x01    /* value taken from a legacy eFuse key */
extern int security_root_export(uint8_t key[32], uint8_t *flags);
extern int security_root_import(const uint8_t key[32], uint8_t flags);
/* Readable eFuse key of firmware before LibreFido 2 (migration only). */
extern const uint8_t *security_legacy_root(void);

#endif // _SECURITY_H_
