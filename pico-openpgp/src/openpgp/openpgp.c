/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
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

#ifdef ESP_PLATFORM
#include "esp_compat.h"
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#else
#include "common.h"
#endif
#include "openpgp.h"
#include "version.h"
#include "random.h"
#include "eac.h"
#include "mbedtls/asn1.h"
#include "usb.h"
#include "ccid/ccid.h"
#include "otp.h"
#include "do.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"
#include "sks.h"
#include "security.h"
#include "lf_policy.h"
#include "low_flash.h"
#ifdef MBEDTLS_EDDSA_C
#include "mbedtls/eddsa.h"
#endif

bool has_pw1 = false;
bool has_pw2 = false;
bool has_pw3 = false;
bool has_rc = false;
uint8_t session_pw1[32];
uint8_t session_rc[32];
uint8_t session_pw3[32];
uint8_t dek[IV_SIZE + 32];
uint16_t algo_dec = EF_ALGO_PRIV2, algo_aut = EF_ALGO_PRIV3, pk_dec = EF_PK_DEC, pk_aut = EF_PK_AUT;

uint8_t openpgp_aid[] = {
    6,
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
};

uint8_t openpgp_aid_full[] = {
    16, 00,
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
    OPGP_VERSION_MAJOR, OPGP_VERSION_MINOR, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00
};

char atr_openpgp[] = {
    21,
    0x3b, 0xda, 0x18, 0xff, 0x81, 0xb1, 0xfe, 0x75, 0x1f, 0x03, 0x00, 0x31, 0xf5, 0x73, 0xc0, 0x01,
    0x60, 0x00, 0x90, 0x00, 0x1c
};

int openpgp_process_apdu();

extern uint32_t board_button_read(void);

/* Collects user presence when the UIF data object of the key asks for it
 * (OpenPGP card 3.4, 4.1.3.6): a press, or automatic presence if the user
 * switched it on for OpenPGP in this profile ("my device is safe"). Returns
 * true if presence was NOT obtained. */
bool wait_button_pressed_fid(uint16_t fid) {
    file_t *ef = search_by_fid(fid, NULL, SPECIFY_ANY);
    if (ef && ef->data && file_get_data(ef)[0] > 0) {
        return lf_wait_presence(LF_APP_OPENPGP);
    }
    return false;
}

void select_file(file_t *pe) {
    if (!pe) {
        currentDF = (file_t *) MF;
        currentEF = NULL;
    }
    else if (pe->type & FILE_TYPE_INTERNAL_EF) {
        currentEF = pe;
        currentDF = &file_entries[pe->parent];
    }
    else {
        currentDF = pe;
    }
    if (currentEF == file_openpgp) {
        selected_applet = currentEF;
        //sc_hsm_unload(); //reset auth status
    }
}

/* Byte idx of the PW status record (EF_PW_PRIV), bounds checked. */
int openpgp_pw_status_set(uint8_t idx, uint8_t val) {
    file_t *ef = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY);
    uint16_t n = file_get_size(ef);
    uint8_t st[16];
    if (idx >= n || n > sizeof(st)) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    if (file_get_data(ef)[idx] == val) {
        return PICOKEY_OK;
    }
    memcpy(st, file_get_data(ef), n);
    st[idx] = val;
    return file_put_data(ef, st, n);
}

bool openpgp_store_locked(void) {
    return !security_keystore_unlocked();
}

/* A new record of ns in ef is sealed once a rollback to firmware that reads
 * plaintext only is no longer possible (confirmed firmware, a profile
 * created secure), or when the record there is sealed already. Until then
 * it keeps the format of earlier firmware, like the OATH and OTP records,
 * and is sealed by the migration once the firmware is confirmed. */
static bool seal_new_record(uint8_t ns, const file_t *ef) {
    return lf_migrate_ok() || lf_profile_sealed_only() ||
           (file_has_data(ef) && sks_is_sealed(ns, file_get_data(ef), file_get_size(ef)));
}

/* ---- EF_DEK, the OpenPGP data key ---------------------------------------
 * IV, then the data key wrapped under PW1, the Reset Code and PW3 (32 bytes
 * each), then, once PIV has been set up, a fourth slot that only marks that
 * (PIV keys are sealed by the secure key store). The file is sealed in the
 * OpenPGP namespace of the secure key store, and so are the PIN verifiers
 * (EF_PW1, EF_RC, EF_PW3; the PIV PIN and PUK in the PIV namespace): with
 * both sealed, guessing a PIN offline from a flash dump needs the profile's
 * root key. Earlier firmware wrote them in plaintext; such files are read
 * as they are and sealed once the running firmware is confirmed (an
 * unconfirmed update may still roll back to firmware that reads only
 * plaintext). Until then a PIN can be guessed offline from a dump of a
 * flash that is not encrypted. */

static file_t *dek_file(void) {
    return search_by_fid(EF_DEK, NULL, SPECIFY_ANY);
}

static bool dek_file_sealed(void) {
    file_t *ef = dek_file();
    return file_has_data(ef) && sks_is_sealed(SKS_NS_OPENPGP, file_get_data(ef), file_get_size(ef));
}

/* Length of the data key record (without the sealing), 0 if none. */
uint16_t dek_file_len(void) {
    file_t *ef = dek_file();
    uint16_t n = file_get_size(ef);
    return dek_file_sealed() ? (uint16_t) (n - SKS_OVERHEAD) : n;
}

/* buf holds DEK_FILE_MAX bytes. */
int dek_file_read(uint8_t *buf, uint16_t *len) {
    size_t n = 0;
    bool legacy = false;
    *len = 0;
    int r = sks_file_get(SKS_NS_OPENPGP, dek_file(), buf, DEK_FILE_MAX, &n, &legacy);
    if (r == PICOKEY_OK && (n < IV_SIZE + 32 * 3 || n > DEK_FILE_MAX)) {
        r = PICOKEY_WRONG_DATA;
    }
    if (r != PICOKEY_OK) {
        mbedtls_platform_zeroize(buf, DEK_FILE_MAX);
        return r;
    }
    *len = (uint16_t) n;
    return PICOKEY_OK;
}

/* Sealed, unless the file still has the format of earlier firmware and a
 * rollback to it is possible (then it stays readable by that firmware). */
int dek_file_write(const uint8_t *buf, uint16_t len) {
    file_t *ef = dek_file();
    if (!ef || len < IV_SIZE + 32 * 3 || len > DEK_FILE_MAX) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (seal_new_record(SKS_NS_OPENPGP, ef)) {
        return sks_file_put(SKS_NS_OPENPGP, ef, buf, len);
    }
    return file_put_data(ef, buf, len);
}

/* ---- PIN verifiers --------------------------------------------------------
 * len || double_hash_pin(PIN) (the length byte of a Reset Code carries
 * RC_MARK), sealed like EF_DEK: in the OpenPGP namespace for PW1, the Reset
 * Code and PW3, in the PIV namespace for the PIV PIN and PUK. The record is
 * bound to its file id. */

static uint8_t pw_rec_ns(const file_t *pw) {
    return (pw->fid == EF_PIV_PIN || pw->fid == EF_PIV_PUK) ? SKS_NS_PIV : SKS_NS_OPENPGP;
}

int pw_rec_read(const file_t *pw, uint8_t rec[PW_REC_LEN]) {
    size_t n = 0;
    bool legacy = false;
    if (!pw) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    int r = sks_file_get(pw_rec_ns(pw), pw, rec, PW_REC_LEN, &n, &legacy);
    if (r == PICOKEY_OK && n != PW_REC_LEN) {
        r = PICOKEY_WRONG_DATA;
    }
    if (r != PICOKEY_OK) {
        mbedtls_platform_zeroize(rec, PW_REC_LEN);
        if (r != PICOKEY_ERR_FILE_NOT_FOUND && r != PICOKEY_ERR_BLOCKED) {
            r = PICOKEY_WRONG_DATA;
        }
    }
    return r;
}

/* Sealed, unless a rollback to firmware that reads plaintext only is still
 * possible (see seal_new_record()). Does not commit. */
int pw_rec_write(file_t *pw, const uint8_t rec[PW_REC_LEN]) {
    if (!pw) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (seal_new_record(pw_rec_ns(pw), pw)) {
        return sks_file_put(pw_rec_ns(pw), pw, rec, PW_REC_LEN);
    }
    return file_put_data(pw, rec, PW_REC_LEN);
}

int pw_rec_set(file_t *pw, const uint8_t *pin, uint16_t len, uint8_t len_byte) {
    uint8_t rec[PW_REC_LEN];
    rec[0] = len_byte;
    double_hash_pin(pin, len, rec + 1);
    int r = pw_rec_write(pw, rec);
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return r;
}

void pw_rec_migrate(file_t *pw) {
    uint8_t rec[PW_REC_LEN];
    if (!file_has_data(pw) || sks_is_sealed(pw_rec_ns(pw), file_get_data(pw), file_get_size(pw)) ||
        !lf_migrate_ok() || !security_keystore_unlocked()) {
        return;
    }
    if (pw_rec_read(pw, rec) == PICOKEY_OK) {
        if (sks_file_put(pw_rec_ns(pw), pw, rec, PW_REC_LEN) == PICOKEY_OK) {
            low_flash_available();
        }
        else {
            printf("PIN verifier %04X could not be sealed\r\n", pw->fid);
        }
    }
    mbedtls_platform_zeroize(rec, sizeof(rec));
}

/* The data key file and the OpenPGP PIN verifiers of earlier firmware are
 * sealed, once that is safe. */
void dek_file_migrate(void) {
    uint8_t buf[DEK_FILE_MAX];
    uint16_t len = 0;
    if (!lf_migrate_ok() || !security_keystore_unlocked()) {
        return;
    }
    if (file_has_data(dek_file()) && !dek_file_sealed() && dek_file_read(buf, &len) == PICOKEY_OK) {
        if (sks_file_put(SKS_NS_OPENPGP, dek_file(), buf, len) == PICOKEY_OK) {
            low_flash_available();
        }
        else {
            printf("DEK could not be sealed\r\n");
        }
    }
    mbedtls_platform_zeroize(buf, sizeof(buf));
    pw_rec_migrate(search_by_fid(EF_PW1, NULL, SPECIFY_EF));
    pw_rec_migrate(search_by_fid(EF_RC, NULL, SPECIFY_EF));
    pw_rec_migrate(search_by_fid(EF_PW3, NULL, SPECIFY_EF));
}

/* A new data key with the default PW1 and PW3 and no Reset Code; keeps
 * the IV and the PIV mark of an existing file of length len (0: none). */
static int dek_file_create(uint8_t *d, uint16_t len) {
    const uint8_t def1[6] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
    const uint8_t def3[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    uint8_t k[32];
    if (len == 0) {
        len = IV_SIZE + 32 * 3;
        random_gen(NULL, d, IV_SIZE);
    }
    random_gen(NULL, d + IV_SIZE, 32);
    memset(d + IV_SIZE + 32, 0, 32);            /* no Reset Code */
    memcpy(d + IV_SIZE + 64, d + IV_SIZE, 32);
    hash_multi(def1, sizeof(def1), k);
    aes_encrypt_cfb_256(k, d, d + IV_SIZE, 32);
    hash_multi(def3, sizeof(def3), k);
    aes_encrypt_cfb_256(k, d, d + IV_SIZE + 64, 32);
    mbedtls_platform_zeroize(k, sizeof(k));
    int r = dek_file_write(d, len);
    mbedtls_platform_zeroize(d, DEK_FILE_MAX);
    return r;
}

/* A Reset Code of this firmware carries RC_MARK in its length byte. Earlier
 * firmware wrapped the data key for the Reset Code in another form (with the
 * device binding applied), and installed 12345678, the default admin PIN, as
 * Reset Code: RESET RETRY COUNTER with such a code would give PW1 a wrong
 * data key. They are dropped, like a record that does not open; the holder
 * sets a new one with PW3. */
static bool rc_is_legacy(const file_t *rc) {
    uint8_t rec[PW_REC_LEN];
    if (!file_has_data(rc)) {
        return false;
    }
    int r = pw_rec_read(rc, rec);
    bool legacy = r == PICOKEY_WRONG_DATA || (r == PICOKEY_OK && !(rec[0] & RC_MARK));
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return legacy;
}

void scan_files_openpgp() {
    scan_flash();
    file_t *ef;
    if ((ef = search_by_fid(EF_FULL_AID, NULL, SPECIFY_ANY))) {
        ef->data = openpgp_aid_full;
        memcpy(ef->data + 12, pico_serial.id, 4);
    }
    /* A locked key store (root key held until it is bound): nothing is
     * provisioned, migrated or dropped; the application refuses what needs
     * its PINs or keys (openpgp_process_apdu()). */
    if (openpgp_store_locked()) {
        return;
    }
    bool reset_dek = false;
    if ((ef = dek_file()) && !file_has_data(ef)) {
        printf("DEK is empty\r\n");
        uint8_t def[DEK_FILE_MAX] = { 0 };
        if (dek_file_create(def, 0) == PICOKEY_OK) {
            reset_dek = true;
        }
    }
    dek_file_migrate();
    if ((ef = search_by_fid(EF_PW1, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PW1 is empty. Initializing with default password\r\n");
            const uint8_t def[6] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
            pw_rec_set(ef, def, sizeof(def), sizeof(def));
        }
    }
    /* No Reset Code until the card holder sets one (PUT DATA D3), as
     * OpenPGP card 3.4 wants: its retry counter then reads 0. */
    bool no_rc = false;
    if ((ef = search_by_fid(EF_RC, NULL, SPECIFY_ANY))) {
        if (file_has_data(ef) && (reset_dek || rc_is_legacy(ef))) {
            printf("RC of earlier firmware. Removing it\r\n");
            /* the code first: a stale slot without its code is harmless */
            if (flash_clear_file(ef) == PICOKEY_OK) {
                dek_store_slot(0, 1, NULL);
            }
        }
        no_rc = !file_has_data(ef);
    }
    if ((ef = search_by_fid(EF_PW3, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PW3 is empty. Initializing with default password\r\n");
            const uint8_t def[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
            pw_rec_set(ef, def, sizeof(def), sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("SigCount is empty. Initializing to zero\r\n");
            const uint8_t def[3] = { 0 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("PW status is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 127, 127, 127, 3, 0, 3 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if (no_rc) {
        openpgp_pw_status_set(3 + (EF_RC & 0xf), 0);
    }
    if ((ef = search_by_fid(EF_UIF_SIG, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("UIF SIG is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x0, 0x20 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_UIF_DEC, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("UIF DEC is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x0, 0x20 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_UIF_AUT, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("UIF AUT is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x0, 0x20 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_KDF, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("KDF is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x81, 0x1, 0x0 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_SEX, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("Sex is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x30 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("PW retries is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 3, 3, 3 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    low_flash_available();
}

/* Files of the OpenPGP application proper, but for the PIN verifiers (they
 * are replaced together with the data key). EF_DEK, EF_PW_PRIV and
 * EF_PW_RETRIES are shared with PIV and are reset field by field. */
static bool openpgp_owned(uint16_t fid) {
    switch (fid) {
        case EF_CH_NAME: case EF_LOGIN_DATA: case EF_SIG_COUNT:
        case EF_KDF: case EF_LANG_PREF: case EF_SEX: case EF_URI_URL: case EF_CH_CERT:
            return true;
    }
    return (fid >= EF_ALGO_PRIV1 && fid <= EF_ALGO_PRIV3) ||
           (fid >= EF_PK_SIG && fid <= EF_PB_AUT) ||
           (fid >= EF_CH_1 && fid <= EF_CH_3) ||
           (fid >= EF_ALGO_SIG && fid <= EF_KEY_INFO && fid != EF_PW_STATUS);
}

/* Factory state of the OpenPGP application (TERMINATE DF). Only its own
 * data goes: PIV, FIDO, OATH and the device keep theirs. The DEK file keeps
 * its IV and its size: its fourth slot is not a key of any use (PIV keys
 * are sealed by the secure key store), only the mark scan_files_piv() uses
 * for "PIV provisioned". The OpenPGP part gets a new key, encrypted with the
 * default PW1 and PW3, and no Reset Code.
 *
 * Writes become durable in this order: the keys and data objects (a large
 * reset commits in several batches, committed here); then together, from
 * an empty write cache, a new epoch of the OpenPGP namespace of the secure
 * key store (as the FIDO, OATH and PIV resets do: stale copies of the
 * sealed data key file and PIN verifiers left in the store no longer open),
 * the new data key file and the default PIN verifiers; last the PW status,
 * so that PW3 stays blocked (TERMINATE possible again) until the rest is
 * durable. Cut short anywhere, the PWs open the data key file that is
 * there. */
int openpgp_reset(void) {
    file_t *ef_dek = dek_file();
    file_t *ef_st = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY);
    file_t *ef_rt = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY);
    file_t *ef_pw1 = search_by_fid(EF_PW1, NULL, SPECIFY_ANY);
    file_t *ef_rc = search_by_fid(EF_RC, NULL, SPECIFY_ANY);
    file_t *ef_pw3 = search_by_fid(EF_PW3, NULL, SPECIFY_ANY);
    if (!ef_dek || !ef_st || !ef_rt || !ef_pw1 || !ef_rc || !ef_pw3) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (openpgp_store_locked()) {
        return PICOKEY_ERR_BLOCKED;
    }
    openpgp_logout();
    int r = file_wipe_matching(openpgp_owned);
    if (r == PICOKEY_OK) {
        r = low_flash_commit();
    }
    if (r != PICOKEY_OK) {
        return r;
    }
    uint8_t d[DEK_FILE_MAX] = { 0 };
    uint16_t len = 0;
    bool readable = dek_file_read(d, &len) == PICOKEY_OK;
    /* A data key file of earlier firmware (plaintext while a rollback to
     * that firmware is possible) has nothing sealed to shred. */
    if (seal_new_record(SKS_NS_OPENPGP, ef_dek)) {
        r = sks_rotate(SKS_NS_OPENPGP);
    }
    if (r == PICOKEY_OK && readable) {
        const uint8_t def1[6] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
        const uint8_t def3[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
        r = dek_file_create(d, len);    /* new key; IV and PIV mark stay */
        if (r == PICOKEY_OK) {
            r = pw_rec_set(ef_pw1, def1, sizeof(def1), sizeof(def1));
        }
        if (r == PICOKEY_OK) {
            r = pw_rec_set(ef_pw3, def3, sizeof(def3), sizeof(def3));
        }
        if (r == PICOKEY_OK && file_has_data(ef_rc)) {
            r = flash_clear_file(ef_rc);
        }
    }
    else if (r == PICOKEY_OK && file_has_data(ef_dek)) {
        /* unreadable: rebuilt from scratch with the default PWs by
         * scan_files_openpgp() */
        r = flash_clear_file(ef_dek);
    }
    mbedtls_platform_zeroize(d, sizeof(d));
    /* PW status and retry limits: the OpenPGP fields only */
    if (r == PICOKEY_OK && file_get_size(ef_st) >= 7) {
        uint8_t st[16];
        uint16_t n = MIN(file_get_size(ef_st), (uint16_t) sizeof(st));
        memcpy(st, file_get_data(ef_st), n);
        const uint8_t def[7] = { 0x1, 127, 127, 127, 3, 0, 3 };
        memcpy(st, def, sizeof(def));
        r = file_put_data(ef_st, st, n);
    }
    if (r == PICOKEY_OK && file_get_size(ef_rt) >= 4) {
        uint8_t rt[16];
        uint16_t n = MIN(file_get_size(ef_rt), (uint16_t) sizeof(rt));
        memcpy(rt, file_get_data(ef_rt), n);
        const uint8_t def[4] = { 0x1, 3, 3, 3 };
        memcpy(rt, def, sizeof(def));
        r = file_put_data(ef_rt, rt, n);
    }
    low_flash_available();
    scan_files_openpgp();       /* default PWs and DOs */
    return r;
}

void release_dek() {
    mbedtls_platform_zeroize(dek, sizeof(dek));
}

/* Ends every OpenPGP authentication: PW1 (81 and 82), PW3, the Reset Code
 * and their key material in RAM. */
void openpgp_logout(void) {
    isUserAuthenticated = false;
    has_pw1 = has_pw2 = has_pw3 = has_rc = false;
    mbedtls_platform_zeroize(session_pw1, sizeof(session_pw1));
    mbedtls_platform_zeroize(session_pw3, sizeof(session_pw3));
    mbedtls_platform_zeroize(session_rc, sizeof(session_rc));
    release_dek();
}

/* The data key from slot 0 (PW1), 1 (Reset Code) or 2 (PW3), opened with
 * the session key of that PW, which must be verified. The PIV PIN does not
 * open it: slot 3 holds no key of use. */
static int load_dek_slot(uint8_t slot) {
    const uint8_t *key = NULL;
    if (slot == 0 && (has_pw1 || has_pw2)) {
        key = session_pw1;
    }
    else if (slot == 1 && has_rc) {
        key = session_rc;
    }
    else if (slot == 2 && has_pw3) {
        key = session_pw3;
    }
    if (!key) {
        return PICOKEY_NO_LOGIN;
    }
    /* The data key is bound to the root key (otp_key_1): while the root
     * is held (otp_key_1 NULL) or the key store locked, any key opened here
     * would be the wrong one, and keys written with it lost. */
    if (openpgp_store_locked()) {
        return PICOKEY_ERR_BLOCKED;
    }
    uint8_t buf[DEK_FILE_MAX];
    uint16_t len = 0;
    int r = dek_file_read(buf, &len);
    if (r != PICOKEY_OK) {
        return r == PICOKEY_ERR_FILE_NOT_FOUND ? r : PICOKEY_EXEC_ERROR;
    }
    memcpy(dek, buf, IV_SIZE);
    memcpy(dek + IV_SIZE, buf + IV_SIZE + 32 * slot, 32);
    mbedtls_platform_zeroize(buf, sizeof(buf));
    if (aes_decrypt_cfb_256(key, dek, dek + IV_SIZE, 32) != 0) {
        release_dek();
        return PICOKEY_EXEC_ERROR;
    }
    if (otp_key_1) {
        for (int i = 0; i < 32; i++) {
            dek[IV_SIZE + i] ^= otp_key_1[i];
        }
    }
    return PICOKEY_OK;
}

/* The data key with the PW the session verified (PW1 first). */
int load_dek() {
    if (has_pw1 || has_pw2) {
        return load_dek_slot(0);
    }
    if (has_pw3) {
        return load_dek_slot(2);
    }
    if (has_rc) {
        return load_dek_slot(1);
    }
    return PICOKEY_NO_LOGIN;
}

int dek_encrypt(uint8_t *data, size_t len) {
    int r;
    if ((r = load_dek()) != PICOKEY_OK) {
        return r;
    }
    r = aes_encrypt_cfb_256(dek + IV_SIZE, dek, data, len);
    release_dek();
    return r;
}

int dek_decrypt(uint8_t *data, size_t len) {
    int r;
    if ((r = load_dek()) != PICOKEY_OK) {
        return r;
    }
    r = aes_decrypt_cfb_256(dek + IV_SIZE, dek, data, len);
    release_dek();
    return r;
}

/* Stores the data key, opened from slot src with the PW the command itself
 * verified (never whichever PW happens to be verified too), in slot 0
 * (PW1), 1 (Reset Code) or 2 (PW3) encrypted under wrap_key, or wipes the
 * slot when wrap_key is NULL. The file keeps its length, so a DEK without
 * PIV part stays one and a PIV part is kept as it is. */
int dek_store_slot(uint8_t src, uint8_t slot, const uint8_t *wrap_key) {
    uint8_t def[DEK_FILE_MAX];
    uint16_t dlen = 0;
    if (slot > 2 || src > 2) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    if (openpgp_store_locked()) {
        return PICOKEY_ERR_BLOCKED;
    }
    int r = dek_file_read(def, &dlen);
    if (r != PICOKEY_OK) {
        return r;
    }
    if (wrap_key) {
        if ((r = load_dek_slot(src)) != PICOKEY_OK) {
            mbedtls_platform_zeroize(def, sizeof(def));
            return r;
        }
        /* the slots hold the key before the device binding of load_dek() */
        if (otp_key_1) {
            for (int i = 0; i < 32; i++) {
                dek[IV_SIZE + i] ^= otp_key_1[i];
            }
        }
        memcpy(def + IV_SIZE + 32 * slot, dek + IV_SIZE, 32);
        release_dek();
        if (aes_encrypt_cfb_256(wrap_key, def, def + IV_SIZE + 32 * slot, 32) != 0) {
            r = PICOKEY_EXEC_ERROR;
        }
    }
    else {
        memset(def + IV_SIZE + 32 * slot, 0, 32);
    }
    if (r == PICOKEY_OK) {
        r = dek_file_write(def, dlen);
    }
    mbedtls_platform_zeroize(def, sizeof(def));
    return r;
}

/* A new PW1 / PW3 / Reset Code (pw) with its data key slot, from the slot
 * of the PW the command verified (src). Two files, and the command's
 * storage transaction commits whatever was written: the data key file is
 * written first and put back as it was if the PW record cannot be written,
 * so the old PW never ends up with a slot it does not open. len_byte is
 * the first byte of the PW record (the length, with RC_MARK for a Reset
 * Code). session, if given, receives the new session key. */
int pw_replace(file_t *pw, uint8_t src, uint8_t slot, const uint8_t *pin, uint16_t len, uint8_t len_byte,
               uint8_t *session) {
    file_t *tf = dek_file();
    uint8_t saved[DEK_FILE_MAX + SKS_OVERHEAD], key[32];
    uint16_t saved_len = file_get_size(tf);
    if (!pw || !file_has_data(tf) || saved_len > sizeof(saved)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    memcpy(saved, file_get_data(tf), saved_len);
    hash_multi(pin, len, key);
    int r = dek_store_slot(src, slot, key);
    if (r == PICOKEY_OK) {
        r = pw_rec_set(pw, pin, len, len_byte);
        if (r != PICOKEY_OK) {
            file_put_data(tf, saved, saved_len);
        }
    }
    if (r == PICOKEY_OK && session) {
        memcpy(session, key, sizeof(key));
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(saved, sizeof(saved));
    return r;
}

/* Authentication state belongs to one selection of the application: it
 * never survives a reselect, a switch to another application or a card
 * reset (PW1 in mode 82 included). */
void init_openpgp() {
    openpgp_logout();
    currentEF = NULL;
    algo_dec = EF_ALGO_PRIV2;
    algo_aut = EF_ALGO_PRIV3;
    pk_dec = EF_PK_DEC;
    pk_aut = EF_PK_AUT;
    scan_files_openpgp();
    //cmd_select();
}

int openpgp_unload() {
    openpgp_logout();
    currentEF = NULL;
    algo_dec = EF_ALGO_PRIV2;
    algo_aut = EF_ALGO_PRIV3;
    pk_dec = EF_PK_DEC;
    pk_aut = EF_PK_AUT;
    return PICOKEY_OK;
}

extern char __StackLimit;
int heapLeft() {
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
    char *p = malloc(256);   // try to avoid undue fragmentation
    int left = &__StackLimit - p;
    free(p);
#else
    int left = 1024 * 1024;
#endif
    return left;
}

int openpgp_select_aid(app_t *a, uint8_t force) {
    (void) force;
    a->process_apdu = openpgp_process_apdu;
    a->unload = openpgp_unload;
    init_openpgp();
    /* FCI with the full AID as DF name (OpenSC reads the serial number
     * from it). process_fci() would describe the application entry of the
     * file table, whose name has the layout of the registered AID. */
    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = 0x6F;
    res_APDU[res_APDU_size++] = 2 + 16;
    res_APDU[res_APDU_size++] = 0x84;
    res_APDU[res_APDU_size++] = 16;
    memcpy(res_APDU + res_APDU_size, openpgp_aid_full + 2, 16);
    res_APDU_size += 16;
    memcpy(res_APDU + res_APDU_size, "\x64\x06\x53\x04", 4);
    res_APDU_size += 4;
    int heap_left = heapLeft();
    res_APDU[res_APDU_size++] = ((heap_left >> 24) & 0xff);
    res_APDU[res_APDU_size++] = ((heap_left >> 16) & 0xff);
    res_APDU[res_APDU_size++] = ((heap_left >> 8) & 0xff);
    res_APDU[res_APDU_size++] = ((heap_left >> 0) & 0xff);
    res_APDU[1] += 8;
    apdu.ne = res_APDU_size;
    return PICOKEY_OK;
}

INITIALIZER( openpgp_ctor ) {
    ccid_atr = (uint8_t *) atr_openpgp;
    register_app(openpgp_select_aid, openpgp_aid);
}

int pin_reset_retries(const file_t *pin, bool force) {
    if (!pin) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    file_t *pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    file_t *pw_retries = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF);
    if (!pw_status || !pw_retries) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint8_t p[16];
    uint16_t n = file_get_size(pw_status), idx = 3 + (pin->fid & 0xf);
    /* the record is 7 bytes (9 with PIV); anything else is corrupt */
    if (idx >= n || n > sizeof(p) || (pin->fid & 0xf) >= file_get_size(pw_retries)) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    memcpy(p, file_get_data(pw_status), n);
    uint8_t retries = p[idx];
    if (retries == 0 && force == false) { //blocked
        return PICOKEY_ERR_BLOCKED;
    }
    uint8_t max_retries = file_get_data(pw_retries)[(pin->fid & 0xf)];
    if (retries == max_retries) {
        return PICOKEY_OK;
    }
    p[idx] = max_retries;
    int r = file_put_data(pw_status, p, n);
    low_flash_available();
    return r;
}

/* Checks a PIN (OpenPGP PW1, PW3, Reset Code; PIV PIN, PUK) against its
 * record. The attempt is counted first and made durable with a commit of
 * its own before the PIN is even hashed: cutting the power when the answer
 * seems late cannot give a wrong guess back, a right and a wrong guess
 * cost the same write, and if the counter cannot be written no PIN is
 * compared at all. A right PIN puts the counter back (in the command's
 * transaction: if that write is lost, the holder only loses one retry).
 * A verifier record that does not open (tampered, or plaintext in a profile
 * created secure) matches no PIN: its PIN can still be blocked, which is
 * what a reset of the application asks for. */
int check_pin(const file_t *pin, const uint8_t *data, size_t len) {
    if (!pin) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!pin->data) {
        return SW_REFERENCE_NOT_FOUND();
    }
    isUserAuthenticated = false;
    /* hash_multi() and double_hash_pin() need at least one byte */
    if (len == 0 || len > 127) {
        return SW_WRONG_LENGTH();
    }
    /* the record: 1 byte for the PIN length and the hash, maybe sealed */
    if (file_get_size(pin) != PW_REC_LEN &&
        !sks_is_sealed(pw_rec_ns(pin), file_get_data(pin), file_get_size(pin))) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    /* no verifier opens while the key store is locked (root key held) */
    if (openpgp_store_locked()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    file_t *pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    uint8_t p[16];
    uint16_t n = file_get_size(pw_status), idx = 3 + (pin->fid & 0xf);
    /* the record is 7 bytes (9 with PIV); anything else is corrupt */
    if (idx >= n || n > sizeof(p)) {
        return SW_MEMORY_FAILURE();
    }
    memcpy(p, file_get_data(pw_status), n);
    if (p[idx] == 0) {
        return SW_PIN_BLOCKED();
    }
    p[idx] -= 1;
    if (file_put_data(pw_status, p, n) != PICOKEY_OK || low_flash_commit() != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }

    uint8_t dhash[32], rec[PW_REC_LEN];
    int rr = pw_rec_read(pin, rec);
    double_hash_pin(data, (uint16_t) len, dhash);
    int neq = mbedtls_ct_memcmp(rec + 1, dhash, sizeof(dhash));
    if (rr != PICOKEY_OK || (rec[0] & ~RC_MARK) == 0) {
        neq = 1;
    }
    mbedtls_platform_zeroize(dhash, sizeof(dhash));
    mbedtls_platform_zeroize(rec, sizeof(rec));
    if (neq != 0) {
        /* a failed verification ends that PW's security status */
        if (pin->fid == EF_PW1) {
            if (P2(apdu) == 0x81) {
                has_pw1 = false;
            }
            else {
                has_pw2 = false;
            }
        }
        else if (pin->fid == EF_PW3) {
            has_pw3 = false;
            mbedtls_platform_zeroize(session_pw3, sizeof(session_pw3));
        }
        if (p[idx] == 0) {
            return SW_PIN_BLOCKED();
        }
        return set_res_sw(0x63, 0xc0 | MIN(p[idx], 15));
    }

    if (pin_reset_retries(pin, true) != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    isUserAuthenticated = true;
    if (pin->fid == EF_PW1) {
        if (P2(apdu) == 0x81) {
            has_pw1 = true;
        }
        else {
            has_pw2 = true;
        }
        hash_multi(data, len, session_pw1);
    }
    else if (pin->fid == EF_PW3) {
        has_pw3 = true;
        hash_multi(data, len, session_pw3);
    }
    return SW_OK();
}

int inc_sig_count() {
    file_t *pw_status;
    if (!(pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF)) || !pw_status->data) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (file_get_data(pw_status)[0] == 0) {
        has_pw1 = false;
    }
    file_t *ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY);
    if (!ef || !ef->data) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint8_t *p = file_get_data(ef);
    uint32_t counter = (p[0] << 16) | (p[1] << 8) | p[2];
    counter++;
    uint8_t q[3] = { (counter >> 16) & 0xff, (counter >> 8) & 0xff, counter & 0xff };
    int r = file_put_data(ef, q, sizeof(q));
    if (r != PICOKEY_OK) {
        return PICOKEY_EXEC_ERROR;
    }
    low_flash_available();
    return PICOKEY_OK;
}

int reset_sig_count() {
    file_t *ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY);
    if (!ef || !ef->data) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint8_t q[3] = { 0 };
    int r = file_put_data(ef, q, sizeof(q));
    if (r != PICOKEY_OK) {
        return PICOKEY_EXEC_ERROR;
    }
    low_flash_available();
    return PICOKEY_OK;
}

/* Writes a private key record: as is, encrypted with the OpenPGP data key,
 * or in PIV mode sealed in the PIV namespace of the secure key store (bound
 * to the file id and the profile's root key; while an update is unconfirmed
 * in plaintext, see seal_new_record()). KEY_MODE_PIV_SEALED always seals (a
 * key that was sealed never goes back to plaintext). kdata is clobbered (DEK
 * mode). */
int key_record_write(file_t *ef, int mode, uint8_t *kdata, uint16_t len) {
    int r = PICOKEY_OK;
    if (!ef) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (openpgp_store_locked()) {
        return PICOKEY_ERR_BLOCKED;     /* no key is written with a held root */
    }
    if (mode == KEY_MODE_PIV_SEALED || (mode == KEY_MODE_PIV && seal_new_record(SKS_NS_PIV, ef))) {
        r = sks_file_put(SKS_NS_PIV, ef, kdata, len);
    }
    else if (mode == KEY_MODE_PIV) {
        r = file_put_data(ef, kdata, len);
    }
    else {
        if (mode == KEY_MODE_DEK) {
            r = dek_encrypt(kdata, len);
        }
        if (r == PICOKEY_OK) {
            r = file_put_data(ef, kdata, len);
        }
    }
    if (r == PICOKEY_OK) {
        low_flash_available();
    }
    return r;
}

/* Reads a private key record into kdata (capacity cap). A PIV record in
 * plaintext (written by firmware before PIV keys were sealed) is read as
 * it is; key_record_migrate() seals it. */
int key_record_read(file_t *ef, int mode, uint8_t *kdata, size_t cap, int *len) {
    *len = 0;
    if (mode == KEY_MODE_PIV) {
        size_t n = 0;
        bool legacy = false;
        int r = sks_file_get(SKS_NS_PIV, ef, kdata, cap, &n, &legacy);
        if (r != PICOKEY_OK) {
            mbedtls_platform_zeroize(kdata, cap);
            return r == PICOKEY_ERR_FILE_NOT_FOUND ? r : PICOKEY_WRONG_DATA;
        }
        *len = (int) n;
        return PICOKEY_OK;
    }
    uint16_t n = file_get_size(ef);
    if (n == 0 || n > cap) {
        return PICOKEY_WRONG_DATA;
    }
    memcpy(kdata, file_get_data(ef), n);
    if (mode == KEY_MODE_DEK && dek_decrypt(kdata, n) != 0) {
        mbedtls_platform_zeroize(kdata, cap);
        return PICOKEY_EXEC_ERROR;
    }
    *len = n;
    return PICOKEY_OK;
}

/* Seals a PIV key record written in plaintext by earlier firmware. Only
 * once the running firmware is confirmed: an unconfirmed update may still
 * roll back to firmware that reads plaintext only. PICOKEY_OK if there is
 * nothing to do (no record, already sealed, or not yet). */
int key_record_migrate(file_t *ef) {
    uint8_t kdata[4096 / 8];
    int len = 0;
    if (!file_has_data(ef) || sks_is_sealed(SKS_NS_PIV, file_get_data(ef), file_get_size(ef)) ||
        !lf_migrate_ok()) {
        return PICOKEY_OK;
    }
    int r = key_record_read(ef, KEY_MODE_PIV, kdata, sizeof(kdata), &len);
    if (r == PICOKEY_OK) {
        r = sks_file_put(SKS_NS_PIV, ef, kdata, (size_t) len);
    }
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
    return r;
}

int store_keys(void *key_ctx, int type, uint16_t key_id, int mode) {
    int r, key_size = 0;
    uint8_t kdata[4096 / 8]; //worst

    file_t *ef = search_by_fid(key_id, NULL, SPECIFY_EF);
    if (!ef) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (type == ALGO_RSA) {
        /* P || Q, each left-padded to the same length (what
         * load_private_key_rsa() reads back), at most RSA-4096 */
        mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) key_ctx;
        size_t half = MAX(mbedtls_mpi_size(&rsa->P), mbedtls_mpi_size(&rsa->Q));
        if (half == 0 || 2 * half > sizeof(kdata)) {
            return PICOKEY_WRONG_DATA;
        }
        if (mbedtls_mpi_write_binary(&rsa->P, kdata, half) != 0 ||
            mbedtls_mpi_write_binary(&rsa->Q, kdata + half, half) != 0) {
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            return PICOKEY_EXEC_ERROR;
        }
        key_size = (int) (2 * half);
    }
    else if (type == ALGO_ECDSA || type == ALGO_ECDH || type == ALGO_EDDSA) {
        mbedtls_ecp_keypair *ecdsa = (mbedtls_ecp_keypair *) key_ctx;
        size_t olen = 0;
        kdata[0] = ecdsa->grp.id & 0xff;
        /* the loaders take at most a 66-byte scalar (P-521) */
        if (mbedtls_ecp_write_key_ext(ecdsa, &olen, kdata + 1, 66) != 0 || olen == 0) {
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            return PICOKEY_EXEC_ERROR;
        }
        key_size = olen + 1;
    }
    else if (type == ALGO_AES_128 || type == ALGO_AES_192 || type == ALGO_AES_256) {
        key_size = type == ALGO_AES_128 ? 16 : (type == ALGO_AES_192 ? 24 : 32);
        memcpy(kdata, key_ctx, key_size);
    }
    else {
        return PICOKEY_WRONG_DATA;
    }
    r = key_record_write(ef, mode, kdata, (uint16_t) key_size);
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
    return r;
}

int load_private_key_rsa(mbedtls_rsa_context *ctx, file_t *fkey, int mode) {
    int key_size = 0;
    uint8_t kdata[4096 / 8];
    int r = key_record_read(fkey, mode, kdata, sizeof(kdata), &key_size);
    if (r != PICOKEY_OK) {
        return r == PICOKEY_EXEC_ERROR ? r : PICOKEY_WRONG_DATA;
    }
    /* P || Q of at most RSA-4096; an empty or odd record is no key */
    if (key_size < 2 || key_size % 2) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return PICOKEY_WRONG_DATA;
    }
    if (mbedtls_mpi_read_binary(&ctx->P, kdata, key_size / 2) != 0) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    if (mbedtls_mpi_read_binary(&ctx->Q, kdata + key_size / 2, key_size / 2) != 0) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
    if (mbedtls_mpi_lset(&ctx->E, 0x10001) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_EXEC_ERROR;
    }
    if (mbedtls_rsa_import(ctx, NULL, &ctx->P, &ctx->Q, NULL, &ctx->E) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    if (mbedtls_rsa_complete(ctx) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    if (mbedtls_rsa_check_privkey(ctx) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    return PICOKEY_OK;
}

int load_private_key_ecdsa(mbedtls_ecp_keypair *ctx, file_t *fkey, int mode) {
    int key_size = 0;
    uint8_t kdata[67]; //Worst case, 521 bit + 1byte
    if (key_record_read(fkey, mode, kdata, sizeof(kdata), &key_size) != PICOKEY_OK) {
        return PICOKEY_WRONG_DATA;
    }
    /* group id byte and at least one byte of key */
    if (key_size < 2) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return PICOKEY_WRONG_DATA;
    }
    mbedtls_ecp_group_id gid = kdata[0];
    int r = mbedtls_ecp_read_key(gid, ctx, kdata + 1, key_size - 1);
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
    if (r != 0) {
        mbedtls_ecp_keypair_free(ctx);
        return PICOKEY_EXEC_ERROR;
    }
#ifdef MBEDTLS_EDDSA_C
    if (ctx->grp.id == MBEDTLS_ECP_DP_ED25519 || ctx->grp.id == MBEDTLS_ECP_DP_ED448) {
        r = mbedtls_ecp_point_edwards(&ctx->grp, &ctx->Q, &ctx->d, random_gen, NULL);
    }
    else
#endif
    {
        r = mbedtls_ecp_mul(&ctx->grp, &ctx->Q, &ctx->d, &ctx->grp.G, random_gen, NULL);
    }
    if (r != 0) {
        mbedtls_ecdsa_free(ctx);
        return PICOKEY_EXEC_ERROR;
    }
    return PICOKEY_OK;
}

/* attr is { length of what follows, algorithm id, OID }. The OID given by the
 * host may carry a trailing 0xFF (public key import format, OpenPGP 3.4).
 * Lengths are compared first: comparing the host's length against a
 * shorter table entry read past it. */
static bool attr_has_oid(const uint8_t *attr, const uint8_t *oid, size_t oid_len) {
    size_t n = (size_t) attr[0] - 1;
    if (oid_len == n + 1 && oid[n] == 0xFF) {
        oid_len = n;
    }
    return oid_len == n && memcmp(attr + 2, oid, n) == 0;
}

mbedtls_ecp_group_id get_ec_group_id_from_attr(const uint8_t *algo, size_t algo_len) {
    static const struct {
        const uint8_t *attr;
        mbedtls_ecp_group_id id;
    } curves[] = {
        { algorithm_attr_p256k1, MBEDTLS_ECP_DP_SECP256K1 },
        { algorithm_attr_p256r1, MBEDTLS_ECP_DP_SECP256R1 },
        { algorithm_attr_p384r1, MBEDTLS_ECP_DP_SECP384R1 },
        { algorithm_attr_p521r1, MBEDTLS_ECP_DP_SECP521R1 },
        { algorithm_attr_bp256r1, MBEDTLS_ECP_DP_BP256R1 },
        { algorithm_attr_bp384r1, MBEDTLS_ECP_DP_BP384R1 },
        { algorithm_attr_bp512r1, MBEDTLS_ECP_DP_BP512R1 },
        /* cv25519 is offered with Curve25519 (lf_25519 or EdDSA mbedTLS);
         * with lf_25519 the callers handle it before this table */
#if defined(MBEDTLS_EDDSA_C) || defined(LF_HAVE_25519)
        { algorithm_attr_cv25519, MBEDTLS_ECP_DP_CURVE25519 },
#endif
#ifdef MBEDTLS_ECP_DP_CURVE448_ENABLED
        { algorithm_attr_x448, MBEDTLS_ECP_DP_CURVE448 },
#endif
#ifdef MBEDTLS_EDDSA_C
        { algorithm_attr_ed25519, MBEDTLS_ECP_DP_ED25519 },
        { algorithm_attr_ed448, MBEDTLS_ECP_DP_ED448 },
#endif
    };
    for (size_t i = 0; i < sizeof(curves) / sizeof(curves[0]); i++) {
        if (attr_has_oid(curves[i].attr, algo, algo_len)) {
            return curves[i].id;
        }
    }
    return MBEDTLS_ECP_DP_NONE;
}

#ifdef LF_HAVE_25519
int lf25519_attr_curve(const uint8_t *algo, uint16_t algo_len) {
    if (!algo || algo_len < 2) {
        return 0;
    }
    if (algo[0] == ALGO_EDDSA && attr_has_oid(algorithm_attr_ed25519, algo + 1, algo_len - 1)) {
        return LF_CURVE_ED25519;
    }
    if (algo[0] == ALGO_ECDH && attr_has_oid(algorithm_attr_cv25519, algo + 1, algo_len - 1)) {
        return LF_CURVE_X25519;
    }
    return 0;
}

int lf25519_public(int curve, const uint8_t secret[32], uint8_t pub[32]) {
    if (curve == LF_CURVE_ED25519) {
        return lf_ed25519_public_key(pub, secret);
    }
    if (curve == LF_CURVE_X25519) {
        return lf_x25519_public_key(pub, secret);
    }
    return -1;
}

void lf25519_generate(int curve, uint8_t secret[32]) {
    random_gen(NULL, secret, 32);
    if (curve == LF_CURVE_X25519) {
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;
    }
}

static uint8_t lf25519_type(int curve) {
    return curve == LF_CURVE_ED25519 ? LF_KEY_ED25519 : LF_KEY_X25519;
}

int lf25519_store(uint16_t fid, int curve, const uint8_t secret[32], int mode) {
    file_t *ef = search_by_fid(fid, NULL, SPECIFY_EF);
    if (!ef) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (curve != LF_CURVE_ED25519 && curve != LF_CURVE_X25519) {
        return PICOKEY_WRONG_DATA;
    }
    uint8_t kdata[1 + 32];
    kdata[0] = lf25519_type(curve);
    memcpy(kdata + 1, secret, 32);
    int r = key_record_write(ef, mode, kdata, sizeof(kdata));
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
    return r;
}

int lf25519_load(file_t *ef, int curve, uint8_t secret[32], int mode) {
    uint8_t kdata[67];
    int len = 0;
    if (!file_has_data(ef)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    int r = key_record_read(ef, mode, kdata, sizeof(kdata), &len);
    if (r == PICOKEY_OK && (len != 1 + 32 || kdata[0] != lf25519_type(curve))) {
        r = PICOKEY_WRONG_DATA;
    }
    if (r == PICOKEY_OK) {
        memcpy(secret, kdata + 1, 32);
    }
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
    return r;
}

void make_25519_response(const uint8_t pub[32]) {
    res_APDU[res_APDU_size++] = 0x7f;
    res_APDU[res_APDU_size++] = 0x49;
    res_APDU[res_APDU_size++] = 2 + 32;
    res_APDU[res_APDU_size++] = 0x86;
    res_APDU[res_APDU_size++] = 32;
    memcpy(res_APDU + res_APDU_size, pub, 32);
    res_APDU_size += 32;
}
#endif

void make_rsa_response(mbedtls_rsa_context *rsa) {
    memcpy(res_APDU, "\x7f\x49\x82\x00\x00", 5);
    res_APDU_size = 5;
    res_APDU[res_APDU_size++] = 0x81;
    res_APDU[res_APDU_size++] = 0x82;
    put_uint16_t_be(mbedtls_mpi_size(&rsa->N), res_APDU + res_APDU_size); res_APDU_size += 2;
    mbedtls_mpi_write_binary(&rsa->N, res_APDU + res_APDU_size, mbedtls_mpi_size(&rsa->N));
    res_APDU_size += mbedtls_mpi_size(&rsa->N);
    res_APDU[res_APDU_size++] = 0x82;
    res_APDU[res_APDU_size++] = mbedtls_mpi_size(&rsa->E) & 0xff;
    mbedtls_mpi_write_binary(&rsa->E, res_APDU + res_APDU_size, mbedtls_mpi_size(&rsa->E));
    res_APDU_size += mbedtls_mpi_size(&rsa->E);
    put_uint16_t_be(res_APDU_size - 5, res_APDU + 3);
}

void make_ecdsa_response(mbedtls_ecp_keypair *ecdsa) {
    uint8_t pt[MBEDTLS_ECP_MAX_PT_LEN];
    size_t plen = 0;
    mbedtls_ecp_point_write_binary(&ecdsa->grp,
                                   &ecdsa->Q,
                                   MBEDTLS_ECP_PF_UNCOMPRESSED,
                                   &plen,
                                   pt,
                                   sizeof(pt));
    res_APDU[res_APDU_size++] = 0x7f;
    res_APDU[res_APDU_size++] = 0x49;
    if (plen >= 128) {
        res_APDU[res_APDU_size++] = 0x81;
    }
    res_APDU[res_APDU_size++] = plen + (plen >= 128 ? 3 : 2);
    res_APDU[res_APDU_size++] = 0x86;
    if (plen >= 128) {
        res_APDU[res_APDU_size++] = 0x81;
    }
    res_APDU[res_APDU_size++] = plen;
    memcpy(res_APDU + res_APDU_size, pt, plen);
    res_APDU_size += plen;
}

int rsa_sign(mbedtls_rsa_context *ctx,
             const uint8_t *data,
             size_t data_len,
             uint8_t *out,
             size_t *out_len) {
    uint8_t *d = (uint8_t *) data, *end = d + data_len, *hsh = NULL;
    size_t seq_len = 0, hash_len = 0;
    int key_size = ctx->len, r = 0;
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;
    if (mbedtls_asn1_get_tag(&d, end, &seq_len,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0) {
        mbedtls_asn1_buf mdb;
        r = mbedtls_asn1_get_alg_null(&d, end, &mdb);
        if (r == 0) {
            if (mbedtls_asn1_get_tag(&d, end, &hash_len, MBEDTLS_ASN1_OCTET_STRING) == 0) {
                if (memcmp(mdb.p, "\x2B\x0E\x03\x02\x1A", 5) == 0) {
                    md = MBEDTLS_MD_SHA1;
                }
                else if (memcmp(mdb.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x04", 9) == 0) {
                    md = MBEDTLS_MD_SHA224;
                }
                else if (memcmp(mdb.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x01", 9) == 0) {
                    md = MBEDTLS_MD_SHA256;
                }
                else if (memcmp(mdb.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x02", 9) == 0) {
                    md = MBEDTLS_MD_SHA384;
                }
                else if (memcmp(mdb.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x03", 9) == 0) {
                    md = MBEDTLS_MD_SHA512;
                }
                hsh = d;
            }
        }
    }
    if (md == MBEDTLS_MD_NONE) {
        if (data_len == 32) {
            md = MBEDTLS_MD_SHA256;
        }
        else if (data_len == 20) {
            md = MBEDTLS_MD_SHA1;
        }
        else if (data_len == 28) {
            md = MBEDTLS_MD_SHA224;
        }
        else if (data_len == 48) {
            md = MBEDTLS_MD_SHA384;
        }
        else if (data_len == 64) {
            md = MBEDTLS_MD_SHA512;
        }
        hash_len = data_len;
        hsh = (uint8_t *) data;
    }
    if (md == MBEDTLS_MD_NONE) {
        if (data_len < key_size) { //needs padding
            memset((uint8_t *) data + data_len, 0, key_size - data_len);
        }
        r = mbedtls_rsa_private(ctx, random_gen, NULL, data, out);
    }
    else {
        uint8_t *signature = (uint8_t *) calloc(key_size, sizeof(uint8_t));
        r = mbedtls_rsa_pkcs1_sign(ctx, random_gen, NULL, md, hash_len, hsh, signature);
        memcpy(out, signature, key_size);
        free(signature);
    }
    *out_len = key_size;
    return r;
}

int ecdsa_sign(mbedtls_ecp_keypair *ctx,
               const uint8_t *data,
               size_t data_len,
               uint8_t *out,
               size_t *out_len) {

    int r = 0;
#ifdef MBEDTLS_EDDSA_C
    if (ctx->grp.id == MBEDTLS_ECP_DP_ED25519 || ctx->grp.id == MBEDTLS_ECP_DP_ED448) {
           r = mbedtls_eddsa_write_signature(ctx, data, data_len, out, 114, out_len, MBEDTLS_EDDSA_PURE, NULL, 0, random_gen, NULL);
    }
    else
#endif
    {
        mbedtls_mpi ri, si;
        mbedtls_mpi_init(&ri);
        mbedtls_mpi_init(&si);
        r = mbedtls_ecdsa_sign(&ctx->grp, &ri, &si, &ctx->d, data, data_len, random_gen, NULL);
        if (r == 0) {
            size_t plen = (ctx->grp.nbits + 7) / 8;
            mbedtls_mpi_write_binary(&ri, out, plen);
            mbedtls_mpi_write_binary(&si, out + plen, plen);
            *out_len = 2 * plen;
        }
        mbedtls_mpi_free(&ri);
        mbedtls_mpi_free(&si);
    }
    return r;
}

extern int cmd_select();
extern int cmd_get_data();
extern int cmd_get_next_data();
extern int cmd_put_data();
extern int cmd_verify();
extern int cmd_select_data();
extern int cmd_version_openpgp();
extern int cmd_import_data();
extern int cmd_change_pin();
extern int cmd_mse();
extern int cmd_internal_aut();
extern int cmd_challenge();
extern int cmd_activate_file();
extern int cmd_terminate_df();
extern int cmd_pso();
extern int cmd_keypair_gen();
extern int cmd_reset_retry();

#define INS_VERIFY          0x20
#define INS_MSE             0x22
#define INS_CHANGE_PIN      0x24
#define INS_PSO             0x2A
#define INS_RESET_RETRY     0x2C
#define INS_ACTIVATE_FILE   0x44
#define INS_KEYPAIR_GEN     0x47
#define INS_CHALLENGE       0x84
#define INS_INTERNAL_AUT    0x88
#define INS_SELECT          0xA4
#define INS_SELECT_DATA     0xA5
#define INS_GET_DATA        0xCA
#define INS_GET_NEXT_DATA   0xCC
#define INS_PUT_DATA        0xDA
#define INS_IMPORT_DATA     0xDB
#define INS_TERMINATE_DF    0xE6
#define INS_VERSION         0xF1

static const cmd_t cmds[] = {
    { INS_GET_DATA, cmd_get_data },
    { INS_SELECT, cmd_select },
    { INS_VERIFY, cmd_verify },
    { INS_PUT_DATA, cmd_put_data },
    { INS_CHANGE_PIN, cmd_change_pin },
    { INS_RESET_RETRY, cmd_reset_retry },
    { INS_KEYPAIR_GEN, cmd_keypair_gen },
    { INS_PSO, cmd_pso },
    { INS_TERMINATE_DF, cmd_terminate_df },
    { INS_ACTIVATE_FILE, cmd_activate_file },
    { INS_CHALLENGE, cmd_challenge },
    { INS_INTERNAL_AUT, cmd_internal_aut },
    { INS_MSE, cmd_mse },
    { INS_IMPORT_DATA, cmd_import_data },
    { INS_VERSION, cmd_version_openpgp },
    { INS_SELECT_DATA, cmd_select_data },
    { INS_GET_NEXT_DATA, cmd_get_next_data },
    { 0x00, 0x0 }
};

/* What runs while the key store is locked (root key held until it is
 * bound): reading the card, nothing that needs a PIN, a key or the data
 * key, and nothing that writes. */
static bool openpgp_ins_without_store(uint8_t ins) {
    return ins == INS_SELECT || ins == INS_GET_DATA || ins == INS_GET_NEXT_DATA || ins == INS_SELECT_DATA ||
           ins == INS_VERSION || ins == INS_CHALLENGE;
}

int openpgp_process_apdu() {
    if (sm_unwrap() != PICOKEY_OK) {
        /* Secure messaging requested but not established or not valid:
         * the command must not run on unverified data. */
        return set_res_sw(0x68, 0x82);
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = openpgp_store_locked() && !openpgp_ins_without_store(cmd->ins) ?
                    SW_CONDITIONS_NOT_SATISFIED() : cmd->cmd_handler();
            sm_wrap();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
