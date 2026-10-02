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
#include "security.h"
#include "profile.h"
#include "otp.h"
#include "random.h"
#include "crypto_utils.h"
#include "low_flash.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#include "soc/soc_caps.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_secure_boot.h"
#include "esp_flash_encrypt.h"
#if SOC_HMAC_SUPPORTED
#include "esp_hmac.h"
#endif
#ifndef CONFIG_LIBREFIDO_HMAC_KEY_BLOCK
#define CONFIG_LIBREFIDO_HMAC_KEY_BLOCK 5
#endif
#elif defined(ENABLE_EMULATION)
#include <stdio.h>
#include <stdlib.h>
#endif

#ifdef LF_STORE_V2
#include "lf_boot.h"
#include "lf_policy.h"
#endif

#define DRK_VERSION         1
#define DRK_WRAP_PLAIN      0
#define DRK_WRAP_HMAC       1
#define DRK_HDR_LEN         4
#define DRK_NONCE_LEN       12
#define DRK_TAG_LEN         16
#define DRK_REC_MAX         (DRK_HDR_LEN + DRK_NONCE_LEN + 32 + DRK_TAG_LEN)
/* Record flag (after DRK_FLAG_LEGACY): not a root key but the HMAC-wrapped
 * mark of a profile that has none (legacy NO-OTP derivations), written by
 * the explicit binding. Never carried by a backup. */
#define DRK_FLAG_NOOTP      0x02

static security_state_t state;
static bool chip_state_read = false;
static uint8_t drk[32];
static uint8_t drk_flags = 0;
static bool drk_valid = false;
static bool drk_error = false;
static bool drk_unbound = false;    /* held until explicitly bound (plain root, or none) */
static bool bound_this_boot = false; /* PROVISION_HMAC bound/recorded the root: repeat = OK */
static bool drk_no_bind = false;    /* held for good: the binding refuses it */
static bool drk_record = false;     /* the profile has a root key record */

extern const uint8_t *otp_key_1;
extern file_t *ef_devroot;

/* ------------------------------------------------------------------------ */
/* Chip security state                                                      */
/* ------------------------------------------------------------------------ */

#if defined(ENABLE_EMULATION)
/* Emulated eFuse for host tests: <PICO_EFUSE_FILE or memory.efuse> holds the
 * HMAC key, <...>.fuses the burned debug locks (EMU_FUSE_*);
 * LF_EMU_CHIP_SECURE=1 reports a fully hardened chip. */
#define EMU_FUSE_JTAG       0x01    /* DIS_PAD_JTAG + DIS_USB_JTAG */
#define EMU_FUSE_DOWNLOAD   0x02    /* ENABLE_SECURITY_DOWNLOAD */

static uint8_t emu_hmac_key[32];
static bool emu_hmac_present = false;

static const char *emu_efuse_path(void) {
    const char *p = getenv("PICO_EFUSE_FILE");
    return p && *p ? p : "memory.efuse";
}

static void emu_efuse_load(void) {
    FILE *f = fopen(emu_efuse_path(), "rb");
    if (f) {
        emu_hmac_present = fread(emu_hmac_key, 1, sizeof(emu_hmac_key), f) == sizeof(emu_hmac_key);
        fclose(f);
    }
}

static void emu_fuses_path(char *path, size_t n) {
    snprintf(path, n, "%s.fuses", emu_efuse_path());
}

static uint8_t emu_fuses_read(void) {
    char path[1024];
    uint8_t v = 0;
    emu_fuses_path(path, sizeof(path));
    FILE *f = fopen(path, "rb");
    if (f) {
        if (fread(&v, 1, 1, f) != 1) {
            v = 0;
        }
        fclose(f);
    }
    return v;
}

/* eFuse bits only ever go from 0 to 1. */
static bool emu_fuses_burn(uint8_t bits) {
    char path[1024];
    uint8_t v = emu_fuses_read() | bits;
    emu_fuses_path(path, sizeof(path));
    FILE *f = fopen(path, "wb");
    if (!f) {
        return false;
    }
    bool ok = fwrite(&v, 1, 1, f) == 1;
    return fclose(f) == 0 && ok;
}
#endif

static void read_chip_state(void) {
#if defined(ESP_PLATFORM)
    state.secure_boot = esp_secure_boot_enabled();
    state.flash_encryption = esp_flash_encryption_enabled();
    state.flash_enc_release = state.flash_encryption && esp_get_flash_encryption_mode() == ESP_FLASH_ENC_MODE_RELEASE;
    state.jtag_disabled = esp_efuse_read_field_bit(ESP_EFUSE_DIS_PAD_JTAG) &&
                          esp_efuse_read_field_bit(ESP_EFUSE_DIS_USB_JTAG);
    state.download_restricted = esp_efuse_read_field_bit(ESP_EFUSE_DIS_DOWNLOAD_MODE) ||
                                esp_efuse_read_field_bit(ESP_EFUSE_ENABLE_SECURITY_DOWNLOAD);
#if defined(CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK)
    state.anti_rollback = true;
#endif
    state.secure_version = esp_efuse_read_secure_version();
#if SOC_HMAC_SUPPORTED
    esp_efuse_block_t blk;
    state.hmac_key = esp_efuse_find_purpose(ESP_EFUSE_KEY_PURPOSE_HMAC_UP, &blk) && esp_efuse_get_key_dis_read(blk);
#endif
    state.legacy_keys_readable = !esp_efuse_key_block_unused(OTP_KEY_1) &&
                                 esp_efuse_get_key_purpose(OTP_KEY_1) == ESP_EFUSE_KEY_PURPOSE_USER &&
                                 !esp_efuse_get_key_dis_read(OTP_KEY_1);
#elif defined(ENABLE_EMULATION)
    emu_efuse_load();
    state.hmac_key = emu_hmac_present;
    uint8_t fuses = emu_fuses_read();
    state.jtag_disabled = (fuses & EMU_FUSE_JTAG) != 0;
    state.download_restricted = (fuses & EMU_FUSE_DOWNLOAD) != 0;
    const char *s = getenv("LF_EMU_CHIP_SECURE");
    if (s && *s == '1') {
        state.secure_boot = state.flash_encryption = state.flash_enc_release = true;
        state.jtag_disabled = state.download_restricted = state.anti_rollback = true;
    }
#endif
}

/* KEK = HMAC(read-protected eFuse key, label || serial). The key never leaves
 * the HMAC peripheral; only code running on this chip can compute the KEK. */
static int hmac_kek(uint8_t kek[32]) {
    uint8_t msg[32 + sizeof(pico_chip_serial.id)];
    const char label[] = "LibreFido/DRK-wrap/v1          "; /* 31 chars + NUL = 32 */
    memcpy(msg, label, 32);
    memcpy(msg + 32, pico_chip_serial.id, sizeof(pico_chip_serial.id));
#if defined(ESP_PLATFORM) && SOC_HMAC_SUPPORTED
    esp_efuse_block_t blk;
    if (!esp_efuse_find_purpose(ESP_EFUSE_KEY_PURPOSE_HMAC_UP, &blk)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    esp_err_t err = esp_hmac_calculate((hmac_key_id_t)(HMAC_KEY0 + (blk - EFUSE_BLK_KEY0)), msg, sizeof(msg), kek);
    return err == ESP_OK ? PICOKEY_OK : PICOKEY_EXEC_ERROR;
#elif defined(ENABLE_EMULATION)
    if (!emu_hmac_present) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), emu_hmac_key, sizeof(emu_hmac_key), msg, sizeof(msg), kek) == 0 ? PICOKEY_OK : PICOKEY_EXEC_ERROR;
#else
    (void) kek;
    return PICOKEY_ERR_FILE_NOT_FOUND;
#endif
}

/* ------------------------------------------------------------------------ */
/* DRK record                                                               */
/* ------------------------------------------------------------------------ */

static void drk_aad(uint8_t *aad, uint8_t wrap) {
    memcpy(aad, "LF-DRK", 6);
    aad[6] = DRK_VERSION;
    aad[7] = wrap;
    memcpy(aad + 8, pico_chip_serial.id, sizeof(pico_chip_serial.id));
}

/* Writes the root key record, wrapped with the chip's HMAC key when there is
 * one. In plain only when allow_plain and the chip has no HMAC key: never
 * for a secure profile, and never on a chip whose key just failed to answer
 * (a plain record there would look planted). */
static int drk_store(uint8_t flags, bool allow_plain) {
    uint8_t rec[DRK_REC_MAX];
    uint16_t len = 0;
    uint8_t kek[32];
    rec[0] = DRK_VERSION;
    rec[2] = flags;
    rec[3] = 0;
    int ret = hmac_kek(kek);
    if (ret != PICOKEY_OK && (!allow_plain || state.hmac_key)) {
        return PICOKEY_ERR_BLOCKED;
    }
    if (ret == PICOKEY_OK) {
        uint8_t aad[8 + sizeof(pico_chip_serial.id)];
        rec[1] = DRK_WRAP_HMAC;
        drk_aad(aad, DRK_WRAP_HMAC);
        random_gen(NULL, rec + DRK_HDR_LEN, DRK_NONCE_LEN);
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, kek, 256);
        if (ret == 0) {
            ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, sizeof(drk), rec + DRK_HDR_LEN, DRK_NONCE_LEN,
                                            aad, sizeof(aad), drk, rec + DRK_HDR_LEN + DRK_NONCE_LEN,
                                            DRK_TAG_LEN, rec + DRK_HDR_LEN + DRK_NONCE_LEN + sizeof(drk));
        }
        mbedtls_gcm_free(&gcm);
        mbedtls_platform_zeroize(kek, sizeof(kek));
        if (ret != 0) {
            return PICOKEY_EXEC_ERROR;
        }
        len = DRK_REC_MAX;
    }
    else {
        rec[1] = DRK_WRAP_PLAIN;
        memcpy(rec + DRK_HDR_LEN, drk, sizeof(drk));
        len = DRK_HDR_LEN + sizeof(drk);
    }
    ret = file_put_data(ef_devroot, rec, len);
    mbedtls_platform_zeroize(rec, sizeof(rec));
    if (ret != PICOKEY_OK) {
        return ret;
    }
    return low_flash_commit();
}

static int drk_load(uint8_t *flags) {
    if (!file_has_data(ef_devroot)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint16_t len = file_get_size(ef_devroot);
    const uint8_t *rec = file_get_data(ef_devroot);
    if (len < DRK_HDR_LEN || rec[0] != DRK_VERSION) {
        return PICOKEY_WRONG_DATA;
    }
    *flags = rec[2];
    if (rec[1] == DRK_WRAP_PLAIN && len == DRK_HDR_LEN + sizeof(drk)) {
        memcpy(drk, rec + DRK_HDR_LEN, sizeof(drk));
        return PICOKEY_OK;
    }
    if (rec[1] == DRK_WRAP_HMAC && len == DRK_REC_MAX) {
        uint8_t kek[32], aad[8 + sizeof(pico_chip_serial.id)];
        int ret = hmac_kek(kek);
        if (ret != PICOKEY_OK) {
            /* A wrapped record without its key (another chip, lost eFuse
             * file) is not a missing record: never replaced, never ignored. */
            return PICOKEY_ERR_BLOCKED;
        }
        drk_aad(aad, DRK_WRAP_HMAC);
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, kek, 256);
        if (ret == 0) {
            ret = mbedtls_gcm_auth_decrypt(&gcm, sizeof(drk), rec + DRK_HDR_LEN, DRK_NONCE_LEN, aad, sizeof(aad),
                                           rec + DRK_HDR_LEN + DRK_NONCE_LEN + sizeof(drk), DRK_TAG_LEN,
                                           rec + DRK_HDR_LEN + DRK_NONCE_LEN, drk);
        }
        mbedtls_gcm_free(&gcm);
        mbedtls_platform_zeroize(kek, sizeof(kek));
        return ret == 0 ? PICOKEY_OK : PICOKEY_WRONG_DKEK;
    }
    return PICOKEY_WRONG_DATA;
}

static bool legacy_key_present(void) {
    if (!otp_key_1) {
        return false;
    }
    for (size_t i = 0; i < 32; i++) {
        if (otp_key_1[i] != 0) {
            return true;
        }
    }
    return false;
}

static void ensure_chip_state(void) {
    if (!chip_state_read) {
        memset(&state, 0, sizeof(state));
        read_chip_state();
        chip_state_read = true;
    }
}

const uint8_t *security_legacy_root(void) {
#if defined(ENABLE_EMULATION)
    /* Emulator builds before LibreFido 2 used this fixed stand-in for the
     * eFuse key; their stores are bound to it. */
    static uint8_t emu_legacy[32];
    memset(emu_legacy, 0xAC, sizeof(emu_legacy));
    return emu_legacy;
#else
    const uint8_t *saved = otp_key_1;
    init_otp_files();
    const uint8_t *legacy = legacy_key_present() ? otp_key_1 : NULL;
    otp_key_1 = saved;
    return legacy;
#endif
}

/* PICOKEY_ERR_FILE_NOT_FOUND only for a profile that has no root key (legacy
 * NO-OTP): a root that exists but is not in use (held, bound during this
 * boot, cannot be unwrapped) is an error, never "no root", and is never
 * handed out (an import would bind it without the explicit binding). */
int security_root_export(uint8_t key[32], uint8_t *flags) {
    if (!drk_valid) {
        return drk_error ? PICOKEY_ERR_BLOCKED : PICOKEY_ERR_FILE_NOT_FOUND;
    }
    memcpy(key, drk, sizeof(drk));
    *flags = drk_flags;
    return PICOKEY_OK;
}

bool security_root_unavailable(void) {
    return drk_error;
}

bool security_hmac_key_available(void) {
    ensure_chip_state();
    return state.hmac_key;
}

/* During an import (lf_backup.c) into the store being built. The record
 * keeps only the flags a backup may carry; it is wrapped with the chip's
 * HMAC key when there is one. */
int security_root_import(const uint8_t key[32], uint8_t flags) {
    ensure_chip_state();
    flags &= DRK_FLAG_LEGACY;
    memcpy(drk, key, sizeof(drk));
    int ret = drk_store(flags, true);
    drk_valid = ret == PICOKEY_OK;
    drk_flags = flags;
    return ret;
}

static void update_hardened(void) {
    state.hardened_ok = state.secure_boot && state.flash_enc_release && state.jtag_disabled &&
                        state.download_restricted && state.anti_rollback && state.hmac_key &&
                        state.drk_source == DRK_SOURCE_FLASH_HMAC && !state.legacy_keys_readable;
}

/* The mounted profile, from the system area (lf_boot.c). */
static bool profile_secure(void) {
#ifdef LF_STORE_V2
    return (lf_boot_profile_flags() & LF_PROFILE_F_SECURE) != 0;
#else
    return false;
#endif
}

static bool profile_was_bound(void) {
#ifdef LF_STORE_V2
    return lf_boot_root_bound();
#else
    return false;
#endif
}

static void note_bound(void) {
#ifdef LF_STORE_V2
    lf_boot_note_root_bound();
#endif
}

/* Keeps the profile's root key out of use: the key store stays locked.
 * bindable: the explicit binding (security_provision_hmac_key) may bind it;
 * otherwise it refuses (the record can only have been planted, removed or
 * replaced). */
static void hold_root(const char *why, bool bindable) {
    printf("[security] root key of this profile %s\n", why);
    drk_unbound = bindable;
    drk_no_bind = !bindable;
    drk_error = true;
    drk_valid = false;
    otp_key_1 = NULL;
    state.hardened_ok = false;
}

void security_init(void) {
    chip_state_read = false;
    ensure_chip_state();
    drk_valid = false;
    drk_error = false;
    drk_unbound = false;
    drk_no_bind = false;
    drk_flags = 0;

    /* Legacy eFuse/OTP keys (never burned here unless explicitly configured). */
    init_otp_files();
#ifdef LF_STORE_V2
    /* Profiles carry their own root (EF_DEVROOT). A readable legacy eFuse key
     * reaches a profile only through the one-time migration, which stores it
     * as that profile's root; it must never become the root of others. */
    otp_key_1 = NULL;
#endif

    uint8_t flags = 0;
    int ret = drk_load(&flags);
    drk_record = ret != PICOKEY_ERR_FILE_NOT_FOUND;
    bool secure = profile_secure(), was_bound = profile_was_bound();
    if (ret == PICOKEY_OK) {
        drk_flags = flags;
    }
    if (legacy_key_present() && !(ret == PICOKEY_OK && (flags & DRK_FLAG_LEGACY))) {
        /* Readable legacy key: it already protects existing data. */
        state.drk_source = DRK_SOURCE_LEGACY_EFUSE;
    }
    else if (ret == PICOKEY_OK && (flags & DRK_FLAG_NOOTP)) {
        /* A profile without root key (legacy NO-OTP derivations) whose state
         * the explicit binding recorded: only on-chip firmware can wrap this
         * marker, so removing the root record does not reproduce it. */
        mbedtls_platform_zeroize(drk, sizeof(drk));
        state.drk_source = DRK_SOURCE_NONE;
        if (file_get_data(ef_devroot)[1] != DRK_WRAP_HMAC || secure) {
            hold_root("marker is not valid here", false);
            return;
        }
        /* Not marked as bound: there is no root key to protect, and without
         * the marker the profile is only held again (bindable). */
    }
    else if (ret == PICOKEY_OK) {
        bool plain = file_get_data(ef_devroot)[1] != DRK_WRAP_HMAC;
        state.drk_source = plain ? DRK_SOURCE_FLASH_PLAIN : DRK_SOURCE_FLASH_HMAC;
        if (plain && (secure || was_bound)) {
            /* A secure profile never had a plain root, and a profile once
             * bound never gets one back: planted (the key would be known). */
            hold_root("was bound to the chip and is now in plain: refused", false);
            return;
        }
        if (plain && state.hmac_key && state.secure_boot) {
            /* The chip holds the HMAC key and only signed firmware runs: a
             * root key in plain is no longer bound on sight, since whoever
             * could write the flash may have planted it (and would know every
             * key derived from it afterwards). It stays loaded but unused
             * until the explicit, touch-confirmed binding binds it
             * (security_provision_hmac_key). Without Secure Boot this check
             * would protect nothing: other firmware could use the HMAC key. */
            hold_root("is not bound to the chip: bind it to use it", true);
            return;
        }
        drk_valid = true;
        otp_key_1 = drk;
        if (plain && state.hmac_key) {
            /* Provisioned after the DRK was created: bind it now. */
            if (drk_store(flags, false) == PICOKEY_OK) {
                state.drk_source = DRK_SOURCE_FLASH_HMAC;
            }
        }
        if (state.drk_source == DRK_SOURCE_FLASH_HMAC) {
            note_bound();
        }
    }
    else if (ret == PICOKEY_ERR_FILE_NOT_FOUND && flash_num_files() == 0) {
        /* Fresh store: create a random root. A secure profile's root is
         * wrapped with the chip's HMAC key from the start, never written in
         * plain; without that key it is not made (locked, nothing written). */
        state.drk_source = DRK_SOURCE_NONE;
        if (secure && !state.hmac_key) {
            printf("[security] secure profile: no HMAC key to bind its root key to, key store locked\n");
            drk_error = true;
            otp_key_1 = NULL;
            state.hardened_ok = false;
            return;
        }
        random_gen(NULL, drk, sizeof(drk));
        if (drk_store(0, !secure) == PICOKEY_OK) {
            drk_valid = true;
            drk_record = true;
            otp_key_1 = drk;
            state.drk_source = state.hmac_key ? DRK_SOURCE_FLASH_HMAC : DRK_SOURCE_FLASH_PLAIN;
            if (state.hmac_key) {
                note_bound();
            }
        }
        else {
            /* Never run without the root that would have protected them. */
            mbedtls_platform_zeroize(drk, sizeof(drk));
            printf("[security] ERROR: root key could not be stored, key store locked\n");
            drk_error = true;
            otp_key_1 = NULL;
            state.hardened_ok = false;
            return;
        }
    }
    else if (ret == PICOKEY_ERR_FILE_NOT_FOUND) {
        /* Files but no root record: a profile migrated from a store without
         * root (legacy NO-OTP derivations), or a removed record. */
        state.drk_source = DRK_SOURCE_NONE;
        if (secure || was_bound) {
            hold_root("was bound to the chip and is missing: refused", false);
            return;
        }
        if (state.hmac_key && state.secure_boot) {
            /* The derivations without root depend on the serial only: held
             * like a plain root until the explicit binding records it. */
            hold_root("is missing: bind to use the profile without one", true);
            return;
        }
    }
    else {
        /* The record exists but cannot be unwrapped (HMAC key missing or
         * tampered record). Never fall back silently to a weaker root. */
        printf("[security] ERROR: device root key cannot be unwrapped (%d)\n", ret);
        otp_key_1 = NULL;
        drk_error = true;
        state.drk_source = DRK_SOURCE_NONE;
        state.hardened_ok = false;
        return;
    }

    update_hardened();
}

/* Also in safe mode, where security_init() does not run: the chip flags are
 * read on first use (the root key fields stay "none"). */
const security_state_t *security_state(void) {
    ensure_chip_state();
    return &state;
}

bool security_keystore_unlocked(void) {
    if (drk_error) {
        /* Using any other root would silently produce wrong keys. */
        return false;
    }
#if LF_REQUIRE_CHIP_SECURITY
    return state.hardened_ok;
#else
    return true;
#endif
}

uint16_t security_status_tlv(uint8_t *out, uint16_t max) {
    if (max < 24) {
        return 0;
    }
    ensure_chip_state();
    uint16_t n = 0, flags = 0;
    flags |= state.secure_boot ? 0x0001 : 0;
    flags |= state.flash_encryption ? 0x0002 : 0;
    flags |= state.flash_enc_release ? 0x0004 : 0;
    flags |= state.jtag_disabled ? 0x0008 : 0;
    flags |= state.download_restricted ? 0x0010 : 0;
    flags |= state.anti_rollback ? 0x0020 : 0;
    flags |= state.hmac_key ? 0x0040 : 0;
    flags |= state.legacy_keys_readable ? 0x0080 : 0;
    flags |= state.hardened_ok ? 0x0100 : 0;
    flags |= low_flash_journal_active() ? 0x0200 : 0;
    flags |= security_keystore_unlocked() ? 0x0400 : 0;
    out[n++] = 0x01; out[n++] = 1; out[n++] = LF_PROFILE_ID;
    out[n++] = 0x02; out[n++] = 2; n += put_uint16_t_be(flags, out + n);
    out[n++] = 0x03; out[n++] = 4; n += put_uint32_t_be(state.secure_version, out + n);
    out[n++] = 0x04; out[n++] = 1; out[n++] = state.drk_source;
    out[n++] = 0x05; out[n++] = 4; n += put_uint32_t_be(low_flash_commit_failures(), out + n);
    return n;
}

int security_provision_hmac_key(void) {
    if (!state.hmac_key) {
#if defined(ESP_PLATFORM) && SOC_HMAC_SUPPORTED
        esp_efuse_block_t blk = (esp_efuse_block_t)(EFUSE_BLK_KEY0 + CONFIG_LIBREFIDO_HMAC_KEY_BLOCK);
        if (!esp_efuse_key_block_unused(blk)) {
            return PICOKEY_ERR_BLOCKED;
        }
        uint8_t key[32];
        random_gen(NULL, key, sizeof(key));
        esp_err_t err = esp_efuse_write_key(blk, ESP_EFUSE_KEY_PURPOSE_HMAC_UP, key, sizeof(key));
        mbedtls_platform_zeroize(key, sizeof(key));
        if (err != ESP_OK) {
            return PICOKEY_EXEC_ERROR;
        }
        if (esp_efuse_get_key_purpose(blk) != ESP_EFUSE_KEY_PURPOSE_HMAC_UP || !esp_efuse_get_key_dis_read(blk) ||
            !esp_efuse_get_key_dis_write(blk)) {
            return PICOKEY_VERIFICATION_FAILED;
        }
#elif defined(ENABLE_EMULATION)
        random_gen(NULL, emu_hmac_key, sizeof(emu_hmac_key));
        FILE *f = fopen(emu_efuse_path(), "wb");
        if (!f) {
            return PICOKEY_EXEC_ERROR;
        }
        fwrite(emu_hmac_key, 1, sizeof(emu_hmac_key), f);
        fclose(f);
        emu_hmac_present = true;
#else
        return PICOKEY_ERR_FILE_NOT_FOUND;
#endif
        state.hmac_key = true;
    }
    if (drk_no_bind) {
        /* A profile once bound (or secure) whose root record is now in plain
         * or gone: planted or removed, never bound on request. */
        return PICOKEY_WRONG_DATA;
    }
    if (bound_this_boot) {
        return PICOKEY_OK;              /* done; it takes effect at the next start */
    }
    /* Bind the root: import a legacy readable key or re-wrap the flash DRK
     * (the record keeps its flags). */
    uint8_t flags = drk_flags;
    bool legacy = state.drk_source == DRK_SOURCE_LEGACY_EFUSE;
    if (legacy) {
        memcpy(drk, otp_key_1, sizeof(drk));
        flags = DRK_FLAG_LEGACY;
    }
    else if (drk_record && (flags & DRK_FLAG_NOOTP)) {
        return PICOKEY_OK;              /* recorded already */
    }
    else if (!drk_record) {
        if (!drk_unbound && (drk_error || flash_num_files() == 0)) {
            /* Nothing to bind yet (a secure profile makes its root at the
             * next start, now that the chip has the key). */
            return PICOKEY_OK;
        }
        /* A profile without root key (legacy NO-OTP derivations): record on
         * the chip that it has none, so a removed root record is told apart
         * (held with Secure Boot, unlocked again at the next start). */
        random_gen(NULL, drk, sizeof(drk));
        flags = DRK_FLAG_NOOTP;
    }
    else if (!drk_valid && !drk_unbound) {
        /* A record that cannot be unwrapped: nothing this can bind. */
        return PICOKEY_WRONG_DATA;
    }
    int ret = drk_store(flags, false);
    if (ret == PICOKEY_OK) {
        drk_record = true;
        drk_flags = flags;
        bound_this_boot = true;
        if (flags & DRK_FLAG_NOOTP) {
            mbedtls_platform_zeroize(drk, sizeof(drk));
        }
        else if (!legacy) {
            state.drk_source = DRK_SOURCE_FLASH_HMAC;
        }
        /* A held root key is bound now. The key store stays locked until the
         * next start: the applications load their keys at boot. */
        drk_unbound = false;
        if (!(flags & DRK_FLAG_NOOTP)) {
            note_bound();
        }
    }
    return ret;
}

int security_rotate_drk(void) {
    if (!drk_valid) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    random_gen(NULL, drk, sizeof(drk));
    return drk_store(0, !profile_secure());
}

/* Burns DIS_PAD_JTAG, DIS_USB_JTAG and ENABLE_SECURITY_DOWNLOAD (unless the
 * ROM download mode is disabled altogether), then reads them back. Only the
 * touch-confirmed management command calls it. */
int security_lock_debug(void) {
    ensure_chip_state();
#if defined(ESP_PLATFORM)
    bool pad = esp_efuse_read_field_bit(ESP_EFUSE_DIS_PAD_JTAG);
    bool usb = esp_efuse_read_field_bit(ESP_EFUSE_DIS_USB_JTAG);
    bool dl = esp_efuse_read_field_bit(ESP_EFUSE_ENABLE_SECURITY_DOWNLOAD) ||
              esp_efuse_read_field_bit(ESP_EFUSE_DIS_DOWNLOAD_MODE);
    if (!pad || !usb || !dl) {
        if (esp_efuse_batch_write_begin() != ESP_OK) {
            return PICOKEY_EXEC_ERROR;
        }
        esp_err_t err = ESP_OK;
        if (!pad) {
            err = esp_efuse_write_field_bit(ESP_EFUSE_DIS_PAD_JTAG);
        }
        if (err == ESP_OK && !usb) {
            err = esp_efuse_write_field_bit(ESP_EFUSE_DIS_USB_JTAG);
        }
        if (err == ESP_OK && !dl) {
            err = esp_efuse_write_field_bit(ESP_EFUSE_ENABLE_SECURITY_DOWNLOAD);
        }
        if (err != ESP_OK) {
            esp_efuse_batch_write_cancel();
            return PICOKEY_EXEC_ERROR;
        }
        if (esp_efuse_batch_write_commit() != ESP_OK) {
            return PICOKEY_EXEC_ERROR;
        }
    }
    state.jtag_disabled = esp_efuse_read_field_bit(ESP_EFUSE_DIS_PAD_JTAG) &&
                          esp_efuse_read_field_bit(ESP_EFUSE_DIS_USB_JTAG);
    state.download_restricted = esp_efuse_read_field_bit(ESP_EFUSE_DIS_DOWNLOAD_MODE) ||
                                esp_efuse_read_field_bit(ESP_EFUSE_ENABLE_SECURITY_DOWNLOAD);
#elif defined(ENABLE_EMULATION)
    if (!emu_fuses_burn(EMU_FUSE_JTAG | EMU_FUSE_DOWNLOAD)) {
        return PICOKEY_EXEC_ERROR;
    }
    uint8_t fuses = emu_fuses_read();
    state.jtag_disabled = state.jtag_disabled || (fuses & EMU_FUSE_JTAG);
    state.download_restricted = state.download_restricted || (fuses & EMU_FUSE_DOWNLOAD);
#else
    return PICOKEY_ERR_FILE_NOT_FOUND;
#endif
    update_hardened();
    return state.jtag_disabled && state.download_restricted ? PICOKEY_OK : PICOKEY_VERIFICATION_FAILED;
}
