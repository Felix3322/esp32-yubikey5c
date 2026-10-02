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
#include "fido.h"
#include "kek.h"
#include "apdu.h"
#include "ctap.h"
#include "files.h"
#include "usb.h"
#include "random.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/hkdf.h"
#if defined(USB_ITF_CCID)
#include "ccid/ccid.h"
#endif
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#include <math.h>
#include "management.h"
#include "hid/ctap_hid.h"
#include "version.h"
#include "crypto_utils.h"
#include "otp.h"
#include "up/up.h"
#include "sks.h"
#include "lf_policy.h"
#include "security.h"
#ifdef LF_STORE_V2
#include "lf_store.h"
#endif

int fido_process_apdu();
int fido_unload();

pinUvAuthToken_t paut = { 0 };
persistentPinUvAuthToken_t ppaut = { 0 };
uint8_t paut_token[32];
uint8_t ppaut_token[32];

uint8_t keydev_dec[32];
bool has_keydev_dec = false;
uint8_t session_pin[32] = { 0 };

const uint8_t fido_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
};

const uint8_t fido_aid_backup[] = {
    8,
    0xB0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
};

const uint8_t atr_fido[] = {
    23,
    0x3b, 0xfd, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x15, 0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59,
    0x75, 0x62, 0x69, 0x4b, 0x65, 0x79, 0x40
};

uint8_t fido_get_version_major() {
    return PICO_FIDO_VERSION_MAJOR;
}
uint8_t fido_get_version_minor() {
    return PICO_FIDO_VERSION_MINOR;
}

int fido_select(app_t *a, uint8_t force) {
    (void) force;
    if (cap_supported(CAP_FIDO2)) {
        a->process_apdu = fido_process_apdu;
        a->unload = fido_unload;
        return PICOKEY_OK;
    }
    return PICOKEY_ERR_FILE_NOT_FOUND;
}

extern uint8_t (*get_version_major)();
extern uint8_t (*get_version_minor)();

INITIALIZER ( fido_ctor ) {
#if defined(USB_ITF_CCID) || defined(ENABLE_EMULATION)
    ccid_atr = atr_fido;
#endif
    get_version_major = fido_get_version_major;
    get_version_minor = fido_get_version_minor;
    register_app(fido_select, fido_aid);
    register_app(fido_select, fido_aid_backup);
}

int fido_unload() {
    return PICOKEY_OK;
}

mbedtls_ecp_group_id fido_curve_to_mbedtls(int curve) {
    if (curve == FIDO2_CURVE_P256) {
        return MBEDTLS_ECP_DP_SECP256R1;
    }
    else if (curve == FIDO2_CURVE_P384) {
        return MBEDTLS_ECP_DP_SECP384R1;
    }
    else if (curve == FIDO2_CURVE_P521) {
        return MBEDTLS_ECP_DP_SECP521R1;
    }
    else if (curve == FIDO2_CURVE_P256K1) {
        return MBEDTLS_ECP_DP_SECP256K1;
    }
    else if (curve == FIDO2_CURVE_X25519) {
        return MBEDTLS_ECP_DP_CURVE25519;
    }
    else if (curve == FIDO2_CURVE_X448) {
        return MBEDTLS_ECP_DP_CURVE448;
    }
#ifdef MBEDTLS_EDDSA_C
    else if (curve == FIDO2_CURVE_ED25519) {
        return MBEDTLS_ECP_DP_ED25519;
    }
    else if (curve == FIDO2_CURVE_ED448) {
        return MBEDTLS_ECP_DP_ED448;
    }
#endif
    else if (curve == FIDO2_CURVE_BP256R1) {
        return MBEDTLS_ECP_DP_BP256R1;
    }
    else if (curve == FIDO2_CURVE_BP384R1) {
        return MBEDTLS_ECP_DP_BP384R1;
    }
    else if (curve == FIDO2_CURVE_BP512R1) {
        return MBEDTLS_ECP_DP_BP512R1;
    }
    return MBEDTLS_ECP_DP_NONE;
}
int mbedtls_curve_to_fido(mbedtls_ecp_group_id id) {
    if (id == MBEDTLS_ECP_DP_SECP256R1) {
        return FIDO2_CURVE_P256;
    }
    else if (id == MBEDTLS_ECP_DP_SECP384R1) {
        return FIDO2_CURVE_P384;
    }
    else if (id == MBEDTLS_ECP_DP_SECP521R1) {
        return FIDO2_CURVE_P521;
    }
    else if (id == MBEDTLS_ECP_DP_SECP256K1) {
        return FIDO2_CURVE_P256K1;
    }
    else if (id == MBEDTLS_ECP_DP_CURVE25519) {
        return FIDO2_CURVE_X25519;
    }
    else if (id == MBEDTLS_ECP_DP_CURVE448) {
        return FIDO2_CURVE_X448;
    }
#ifdef MBEDTLS_EDDSA_C
    else if (id == MBEDTLS_ECP_DP_ED25519) {
        return FIDO2_CURVE_ED25519;
    }
    else if (id == MBEDTLS_ECP_DP_ED448) {
        return FIDO2_CURVE_ED448;
    }
#endif
    return 0;
}

/* Key path of a credential: its first KEY_PATH_LEN bytes, hardened. */
static void fido_cred_key_path(const uint8_t *cred_id, uint8_t key_path[KEY_PATH_LEN]) {
    /* memcpy, never a uint32_t cast: the buffers are byte arrays and the
     * ESP32-S3 faults on unaligned 32-bit accesses. Same bytes as before
     * (host byte order). */
    memcpy(key_path, cred_id, KEY_PATH_LEN);
    uint32_t v = 0x80000000 | 10022;
    memcpy(key_path, &v, sizeof(v));
    for (size_t i = 1; i < KEY_PATH_ENTRIES; i++) {
        memcpy(&v, key_path + i * sizeof(uint32_t), sizeof(v));
        v |= 0x80000000;
        memcpy(key_path + i * sizeof(uint32_t), &v, sizeof(v));
    }
}

int fido_load_key(int curve, const uint8_t *cred_id, mbedtls_ecp_keypair *key) {
    mbedtls_ecp_group_id mbedtls_curve = fido_curve_to_mbedtls(curve);
    if (mbedtls_curve == MBEDTLS_ECP_DP_NONE) {
        return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }
    uint8_t key_path[KEY_PATH_LEN];
    fido_cred_key_path(cred_id, key_path);
    return derive_key(NULL, false, key_path, mbedtls_curve, key);
}

int x509_create_cert(mbedtls_ecdsa_context *ecdsa, uint8_t *buffer, size_t buffer_size) {
    mbedtls_x509write_cert ctx;
    mbedtls_x509write_crt_init(&ctx);
    mbedtls_x509write_crt_set_version(&ctx, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_validity(&ctx, "20220901000000", "20720831235959");
    mbedtls_x509write_crt_set_issuer_name(&ctx, "C=ES,O=Pico HSM,CN=Pico FIDO");
    mbedtls_x509write_crt_set_subject_name(&ctx, "C=ES,O=Pico HSM,CN=Pico FIDO");
    uint8_t serial[16];
    random_gen(NULL, serial, sizeof(serial));
    mbedtls_x509write_crt_set_serial_raw(&ctx, serial, sizeof(serial));
    /* The pk context borrows the caller's key for the signature; the
     * keypair mbedtls_pk_setup() allocated is put back and freed after, so
     * nothing leaks and the caller's key is not freed twice. */
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    if (mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0) {
        mbedtls_x509write_crt_free(&ctx);
        return PICOKEY_EXEC_ERROR;
    }
    void *owned = key.pk_ctx;
    key.pk_ctx = ecdsa;
    mbedtls_x509write_crt_set_subject_key(&ctx, &key);
    mbedtls_x509write_crt_set_issuer_key(&ctx, &key);
    mbedtls_x509write_crt_set_md_alg(&ctx, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_basic_constraints(&ctx, 0, 0);
    mbedtls_x509write_crt_set_subject_key_identifier(&ctx);
    mbedtls_x509write_crt_set_authority_key_identifier(&ctx);
    mbedtls_x509write_crt_set_key_usage(&ctx,
                                        MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
                                        MBEDTLS_X509_KU_KEY_CERT_SIGN);
    int ret = mbedtls_x509write_crt_der(&ctx, buffer, buffer_size, random_gen, NULL);
    mbedtls_x509write_crt_free(&ctx);
    key.pk_ctx = owned;
    mbedtls_pk_free(&key);
    return ret;
}

/* Device key storage.
 *
 * ef_keydev (EF_KEY_DEV) holds the 32-byte device key as an sks record:
 * AES-256-GCM under a key derived from the profile root key (SKS_NS_FIDO),
 * bound to the file id. The formats of earlier firmware are still read:
 *   33 bytes  0x01 || AES-256-CBC(kbase, IV serial hash)   no integrity
 *   61 bytes  0x02 || the above sealed with the PIN session (needs the PIN)
 *   32 bytes  AES-CFB with the upstream MKEK               (needs the PIN)
 * Only a profile created secure (lf_profile_sealed_only) refuses them: there
 * every record was written sealed, so anything else was injected.
 *
 * Sealing waits for confirmed firmware (lf_migrate_ok): an unconfirmed update
 * can still roll back to firmware that reads only the formats above (2.0.0
 * reads a 64-byte record as no key at all and derives from zeros). Until
 * then a legacy key is only read, a key bound to the PIN session is moved to
 * format 0x01 (as 2.0.0 does on PIN verification) and a new key is written
 * in format 0x01; the first use after confirmation seals it. A profile
 * created secure always seals.
 *
 * While ef_keydev_enc holds a host-sealed device key (AUT_ENABLE, vendor
 * restore), that is the only stored copy: the key is used from RAM once
 * UNLOCK has opened it, and ef_keydev is neither read nor written. */
#define KEYDEV_SKS_LEN  (32 + SKS_OVERHEAD)

bool keydev_is_sealed(void) {
    return file_has_data(ef_keydev_enc);
}

/* The profile root key is in use. Otherwise (a HARDENED key store not yet
 * usable, a root key held until it is bound, or bound during this boot)
 * otp_key_1 is not the root the FIDO records were made with: kbase would
 * fall back to the serial alone and decrypt the unauthenticated format 0x01
 * into a wrong key without any error. Nothing derives or writes then. */
bool fido_keystore_ok(void) {
    return security_keystore_unlocked() && !security_root_unavailable();
}

bool fido_seal_now(void) {
    return lf_migrate_ok() || lf_profile_sealed_only();
}

/* Format 0x01 of earlier firmware (2.0.0 writes and reads it). */
static int keydev_write_f1(const uint8_t key[32]) {
    uint8_t kdata[33] = { 0 }, kbase[32];
    kdata[0] = 0x01;
    memcpy(kdata + 1, key, 32);
    derive_kbase(kbase);
    int ret = aes_encrypt(kbase, pico_serial_hash, 32 * 8, PICO_KEYS_AES_MODE_CBC, kdata + 1, 32);
    mbedtls_platform_zeroize(kbase, sizeof(kbase));
    if (ret == PICOKEY_OK) {
        ret = file_put_data(ef_keydev, kdata, sizeof(kdata));
    }
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
    return ret;
}

static int keydev_write(const uint8_t key[32]) {
    if (!fido_keystore_ok()) {
        return PICOKEY_ERR_BLOCKED;
    }
    int ret = fido_seal_now() ? sks_file_put(SKS_NS_FIDO, ef_keydev, key, 32) : keydev_write_f1(key);
    low_flash_available();
    return ret;
}

static bool keydev_file_is_sks(void) {
    uint16_t size = file_get_size(ef_keydev);
    return size == KEYDEV_SKS_LEN && sks_is_sealed(SKS_NS_FIDO, file_get_data(ef_keydev), size);
}

int keydev_store(const uint8_t key[32]) {
    if (keydev_is_sealed()) {
        return PICOKEY_ERR_BLOCKED;     /* would undo the host sealing */
    }
    return keydev_write(key);
}

int keydev_store_unsealing(const uint8_t key[32]) {
    int ret = keydev_write(key);
    if (ret == PICOKEY_OK) {
        /* Should this fail, both files exist: that still reads as sealed
         * (and UNLOCK removes the plain copy), never as unprotected. */
        ret = file_put_data(ef_keydev_enc, NULL, 0);
    }
    low_flash_available();
    return ret;
}

static int keydev_read_legacy(uint8_t key[32]) {
    uint16_t fid_size = file_get_size(ef_keydev);
    const uint8_t *data = file_get_data(ef_keydev);
    int ret = PICOKEY_OK;
    if (fid_size == 32) {
        memcpy(key, data, 32);
        if (mkek_decrypt(key, 32) != PICOKEY_OK ||
            (otp_key_1 && aes_decrypt(otp_key_1, NULL, 32 * 8, PICO_KEYS_AES_MODE_CBC, key, 32) != PICOKEY_OK)) {
            ret = PICOKEY_EXEC_ERROR;
        }
    }
    else if ((fid_size == 33 && data[0] == 0x01) || (fid_size == 61 && data[0] == 0x02)) {
        if (data[0] == 0x02) {
            uint8_t tmp_key[61];
            memcpy(tmp_key, data, sizeof(tmp_key));
            ret = decrypt_with_aad(session_pin, tmp_key + 1, 60, key);
            mbedtls_platform_zeroize(tmp_key, sizeof(tmp_key));
        }
        else {
            memcpy(key, data + 1, 32);
        }
        if (ret == PICOKEY_OK) {
            uint8_t kbase[32];
            derive_kbase(kbase);
            ret = aes_decrypt(kbase, pico_serial_hash, 32 * 8, PICO_KEYS_AES_MODE_CBC, key, 32);
            mbedtls_platform_zeroize(kbase, sizeof(kbase));
        }
    }
    else {
        ret = PICOKEY_WRONG_DATA;
    }
    if (ret != PICOKEY_OK) {
        mbedtls_platform_zeroize(key, 32);
        return ret == PICOKEY_WRONG_DATA ? ret : PICOKEY_EXEC_ERROR;
    }
    return PICOKEY_OK;
}

int load_keydev(uint8_t key[32]) {
    if (!fido_keystore_ok()) {
        return PICOKEY_ERR_BLOCKED;     /* never a key from the wrong root */
    }
    if (has_keydev_dec == true) {
        memcpy(key, keydev_dec, sizeof(keydev_dec));
        return PICOKEY_OK;
    }
    if (keydev_is_sealed()) {
        return PICOKEY_ERR_BLOCKED;     /* locked until UNLOCK */
    }
    if (!file_has_data(ef_keydev)) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    if (keydev_file_is_sks()) {
        uint8_t tmp[32];
        size_t len = 0;
        bool legacy = false;
        int ret = sks_file_get(SKS_NS_FIDO, ef_keydev, tmp, sizeof(tmp), &len, &legacy);
        if (ret == PICOKEY_OK && (legacy || len != sizeof(tmp))) {
            ret = PICOKEY_WRONG_DATA;
        }
        if (ret == PICOKEY_OK) {
            memcpy(key, tmp, sizeof(tmp));
        }
        mbedtls_platform_zeroize(tmp, sizeof(tmp));
        return ret;
    }
    if (lf_profile_sealed_only()) {
        return PICOKEY_WRONG_DATA;      /* created sealed: anything else was injected */
    }
    int ret = keydev_read_legacy(key);
    /* sealed only once the firmware is confirmed (see above) */
    if (ret == PICOKEY_OK && lf_migrate_ok() && keydev_write(key) != PICOKEY_OK) {
        printf("device key: sealing the legacy format failed, kept as is\n");
    }
    return ret;
}

int keydev_migrate_legacy(void) {
    if (has_keydev_dec || keydev_is_sealed() || !file_has_data(ef_keydev) || keydev_file_is_sks()) {
        return PICOKEY_OK;
    }
    /* The formats bound to the PIN session (61-byte 0x02, 32-byte MKEK) must
     * leave it while it is known, even before confirmation: a PIN change
     * would lose them. Format 0x01 waits for confirmation. */
    uint16_t size = file_get_size(ef_keydev);
    bool pin_bound = size == 32 || size == 61;
    if (!pin_bound && !lf_migrate_ok()) {
        return PICOKEY_OK;
    }
    uint8_t k[32];
    int ret = load_keydev(k);           /* seals it once confirmed */
    if (ret == PICOKEY_OK && pin_bound && !lf_migrate_ok()) {
        ret = keydev_write(k);          /* format 0x01, which 2.0.0 reads too */
    }
    mbedtls_platform_zeroize(k, sizeof(k));
    return ret;
}

int verify_key(const uint8_t *appId, const uint8_t *keyHandle, mbedtls_ecp_keypair *key) {
    for (size_t i = 0; i < KEY_PATH_ENTRIES; i++) {
        uint32_t k;
        memcpy(&k, keyHandle + i * sizeof(uint32_t), sizeof(k));   /* host data, any alignment */
        if (!(k & 0x80000000)) {
            return -1;
        }
    }
    mbedtls_ecdsa_context ctx;
    if (key == NULL) {
        mbedtls_ecdsa_init(&ctx);
        key = &ctx;
        if (derive_key(appId, false, (uint8_t *) keyHandle, MBEDTLS_ECP_DP_SECP256R1, &ctx) != 0) {
            mbedtls_ecdsa_free(&ctx);
            return -3;
        }
    }
    uint8_t hmac[32], d[32];
    size_t olen = 0;
    int ret = mbedtls_ecp_write_key_ext(key, &olen, d, sizeof(d));
    if (key == &ctx) {
        mbedtls_ecdsa_free(&ctx);
    }
    if (ret != 0) {
        return -2;
    }
    uint8_t key_base[CTAP_APPID_SIZE + KEY_PATH_LEN];
    memcpy(key_base, appId, CTAP_APPID_SIZE);
    memcpy(key_base + CTAP_APPID_SIZE, keyHandle, KEY_PATH_LEN);
    ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), d, 32, key_base, sizeof(key_base), hmac);
    mbedtls_platform_zeroize(d, sizeof(d));
    return memcmp(keyHandle + KEY_PATH_LEN, hmac, sizeof(hmac));
}

#define DERIVE_KEY_OUT_LEN  67      /* SECP521R1 key is 66 bytes length */

/* Key material of the path in key_handle: the device key through one
 * HKDF-SHA512 step per path entry (salt: the entry; input: bytes 0..31;
 * info: bytes 32..63). With new_key the path is made first (random,
 * hardened) and its MAC for app_id stored after it. outk is wiped on
 * failure. */
static int derive_key_material(const uint8_t *app_id, bool new_key, uint8_t *key_handle, uint8_t outk[DERIVE_KEY_OUT_LEN]) {
    int r = 0;
    memset(outk, 0, DERIVE_KEY_OUT_LEN);
    if ((r = load_keydev(outk)) != PICOKEY_OK) {
        printf("Error loading keydev: %d\n", r);
        mbedtls_platform_zeroize(outk, DERIVE_KEY_OUT_LEN);
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    for (size_t i = 0; i < KEY_PATH_ENTRIES; i++) {
        if (new_key == true) {
            uint32_t val = 0;
            random_gen(NULL, (uint8_t *) &val, sizeof(val));
            val |= 0x80000000;
            memcpy(&key_handle[i * sizeof(uint32_t)], &val, sizeof(uint32_t));
        }
        r = mbedtls_hkdf(md_info, &key_handle[i * sizeof(uint32_t)], sizeof(uint32_t), outk, 32, outk + 32, 32, outk, DERIVE_KEY_OUT_LEN);
        if (r != 0) {
            mbedtls_platform_zeroize(outk, DERIVE_KEY_OUT_LEN);
            return r;
        }
    }
    if (new_key == true) {
        uint8_t key_base[CTAP_APPID_SIZE + KEY_PATH_LEN];
        memcpy(key_base, app_id, CTAP_APPID_SIZE);
        memcpy(key_base + CTAP_APPID_SIZE, key_handle, KEY_PATH_LEN);
        if ((r = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), outk, 32, key_base, sizeof(key_base), key_handle + 32)) != 0) {
            mbedtls_platform_zeroize(outk, DERIVE_KEY_OUT_LEN);
            return r;
        }
    }
    return 0;
}

int derive_key(const uint8_t *app_id, bool new_key, uint8_t *key_handle, int curve, mbedtls_ecp_keypair *key) {
    uint8_t outk[DERIVE_KEY_OUT_LEN];
    int r = derive_key_material(app_id, new_key, key_handle, outk);
    if (r != 0) {
        return r;
    }
    if (key != NULL) {
        mbedtls_ecp_group_load(&key->grp, curve);
        const mbedtls_ecp_curve_info *cinfo = mbedtls_ecp_curve_info_from_grp_id(curve);
        if (cinfo == NULL) {
            mbedtls_platform_zeroize(outk, sizeof(outk));
            return 1;
        }
        if (cinfo->bit_size % 8 != 0) {
            outk[0] >>= 8 - (cinfo->bit_size % 8);
        }
        r = mbedtls_ecp_read_key(curve, key, outk, (size_t)ceil((float) cinfo->bit_size / 8));
        mbedtls_platform_zeroize(outk, sizeof(outk));
        if (r != 0) {
            return r;
        }
#ifdef MBEDTLS_EDDSA_C
        if (curve == MBEDTLS_ECP_DP_ED25519) {
            return mbedtls_ecp_point_edwards(&key->grp, &key->Q, &key->d, random_gen, NULL);
        }
#endif
        return mbedtls_ecp_mul(&key->grp, &key->Q, &key->d, &key->grp.G, random_gen, NULL);
    }
    mbedtls_platform_zeroize(outk, sizeof(outk));
    return r;
}

#ifdef FIDO_ED25519_LF
/* Ed25519 key of a credential: the first 32 bytes of its key material are
 * the seed (RFC 8032, 5.1.5), and pub its public key. This is the key the
 * mbedTLS EdDSA fork derives from the same bytes (derive_key() reads them as
 * a little-endian d, which the fork writes back unchanged and hashes as the
 * seed), so credentials made by a firmware built with ENABLE_EDDSA keep their
 * keys. The seed is wiped on failure. */
static int fido_ed25519_load(const uint8_t *cred_id, uint8_t seed[LF_ED25519_SEED_LEN], uint8_t pub[LF_ED25519_PUB_LEN]) {
    uint8_t key_path[KEY_PATH_LEN], outk[DERIVE_KEY_OUT_LEN];
    fido_cred_key_path(cred_id, key_path);
    int r = derive_key_material(NULL, false, key_path, outk);
    if (r != 0) {
        return r;
    }
    memcpy(seed, outk, LF_ED25519_SEED_LEN);
    mbedtls_platform_zeroize(outk, sizeof(outk));
    if (lf_ed25519_public_key(pub, seed) != 0) {
        mbedtls_platform_zeroize(seed, LF_ED25519_SEED_LEN);
        return PICOKEY_EXEC_ERROR;
    }
    return PICOKEY_OK;
}
#endif

void fido_cred_key_init(fido_cred_key_t *key) {
    memset(key, 0, sizeof(*key));
    mbedtls_ecp_keypair_init(&key->ec);
}

void fido_cred_key_free(fido_cred_key_t *key) {
    mbedtls_ecp_keypair_free(&key->ec);     /* zeroizes; safe to repeat */
#ifdef FIDO_ED25519_LF
    mbedtls_platform_zeroize(key->ed_seed, sizeof(key->ed_seed));
    mbedtls_platform_zeroize(key->ed_pub, sizeof(key->ed_pub));
#endif
    key->curve = 0;
}

int fido_cred_key_load(fido_cred_key_t *key, int curve, const uint8_t *cred_id) {
    key->curve = curve;
#ifdef FIDO_ED25519_LF
    if (curve == FIDO2_CURVE_ED25519) {
        return fido_ed25519_load(cred_id, key->ed_seed, key->ed_pub);
    }
#endif
    int ret = fido_load_key(curve, cred_id, &key->ec);
    if (ret == 0 && mbedtls_ecp_curve_info_from_grp_id(key->ec.grp.id) == NULL) {
        ret = PICOKEY_EXEC_ERROR;
    }
    return ret;
}

/* Byte length of a private key on curve (FIDO2_CURVE_*) as a single-key
 * transfer carries it, 0 for a curve that is not transferred. Ed25519 only
 * through lf_25519, whose key is its seed; the mbedTLS EdDSA fork keeps its
 * own representation. */
static size_t fido_cred_key_len(int curve) {
#ifdef FIDO_ED25519_LF
    if (curve == FIDO2_CURVE_ED25519) {
        return LF_ED25519_SEED_LEN;
    }
#endif
    if (curve != FIDO2_CURVE_P256 && curve != FIDO2_CURVE_P384 && curve != FIDO2_CURVE_P521 &&
        curve != FIDO2_CURVE_P256K1) {
        return 0;
    }
    const mbedtls_ecp_curve_info *cinfo = mbedtls_ecp_curve_info_from_grp_id(fido_curve_to_mbedtls(curve));
    return cinfo ? (size_t) (cinfo->bit_size + 7) / 8 : 0;
}

int fido_cred_key_import(fido_cred_key_t *key, int curve, const uint8_t *priv, size_t len) {
    size_t want = fido_cred_key_len(curve);
    if (want == 0) {
        return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }
    if (len != want) {
        return PICOKEY_WRONG_DATA;
    }
    key->curve = curve;
#ifdef FIDO_ED25519_LF
    if (curve == FIDO2_CURVE_ED25519) {
        memcpy(key->ed_seed, priv, LF_ED25519_SEED_LEN);
        if (lf_ed25519_public_key(key->ed_pub, key->ed_seed) != 0) {
            fido_cred_key_free(key);
            return PICOKEY_EXEC_ERROR;
        }
        return PICOKEY_OK;
    }
#endif
    /* mbedtls_ecp_read_key() refuses a scalar outside [1, n-1] */
    int ret = mbedtls_ecp_read_key(fido_curve_to_mbedtls(curve), &key->ec, priv, len);
    if (ret != 0) {
        fido_cred_key_free(key);
        return PICOKEY_WRONG_DATA;
    }
    ret = mbedtls_ecp_mul(&key->ec.grp, &key->ec.Q, &key->ec.d, &key->ec.grp.G, random_gen, NULL);
    if (ret != 0) {
        fido_cred_key_free(key);
        return PICOKEY_EXEC_ERROR;
    }
    return PICOKEY_OK;
}

int fido_cred_key_export(const fido_cred_key_t *key, uint8_t *out, size_t cap, size_t *len) {
    size_t want = fido_cred_key_len(key->curve);
    if (want == 0) {
        return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }
    if (cap < want) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
#ifdef FIDO_ED25519_LF
    if (key->curve == FIDO2_CURVE_ED25519) {
        memcpy(out, key->ed_seed, LF_ED25519_SEED_LEN);
        *len = LF_ED25519_SEED_LEN;
        return PICOKEY_OK;
    }
#endif
    size_t olen = 0;
    /* big endian, the curve's full length (leading zeros kept) */
    if (mbedtls_ecp_write_key_ext(&key->ec, &olen, out, cap) != 0 || olen != want) {
        mbedtls_platform_zeroize(out, cap);
        return PICOKEY_EXEC_ERROR;
    }
    *len = olen;
    return PICOKEY_OK;
}

int fido_cred_key_sign(fido_cred_key_t *key, const uint8_t *msg, size_t len,
                       uint8_t *sig, size_t sig_size, size_t *sig_len) {
#ifdef FIDO_ED25519_LF
    if (key->curve == FIDO2_CURVE_ED25519) {
        if (sig_size < LF_ED25519_SIG_LEN || lf_ed25519_sign(sig, msg, len, key->ed_seed, key->ed_pub) != 0) {
            return PICOKEY_EXEC_ERROR;
        }
        *sig_len = LF_ED25519_SIG_LEN;
        return 0;
    }
#endif
    mbedtls_ecp_group_id id = key->ec.grp.id;
#ifdef MBEDTLS_EDDSA_C
    if (id == MBEDTLS_ECP_DP_ED25519 || id == MBEDTLS_ECP_DP_ED448) {
        return mbedtls_eddsa_write_signature(&key->ec, msg, len, sig, sig_size, sig_len, MBEDTLS_EDDSA_PURE, NULL, 0, random_gen, NULL);
    }
#endif
    /* the hash of the curve's ES* algorithm */
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (id == MBEDTLS_ECP_DP_SECP384R1 || id == MBEDTLS_ECP_DP_BP384R1) {
        md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
    }
    else if (id == MBEDTLS_ECP_DP_SECP521R1 || id == MBEDTLS_ECP_DP_BP512R1) {
        md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    }
    uint8_t hash[64];
    int ret = mbedtls_md(md, msg, len, hash);
    if (ret == 0) {
        ret = mbedtls_ecdsa_write_signature(&key->ec, mbedtls_md_get_type(md), hash, mbedtls_md_get_size(md), sig, sig_size, sig_len, random_gen, NULL);
    }
    return ret;
}

/* Self-signed device certificate of the device key key, built in cert
 * (cap bytes, filled from the end); *len is its size. Nothing is written.
 * Fails when key is not a valid P-256 private key. */
int fido_certdev_build(const uint8_t key[32], uint8_t *cert, size_t cap, size_t *len) {
    mbedtls_ecdsa_context ekey;
    mbedtls_ecdsa_init(&ekey);
    int ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &ekey, key, 32);
    if (ret == 0) {
        ret = mbedtls_ecp_mul(&ekey.grp, &ekey.Q, &ekey.d, &ekey.grp.G, random_gen, NULL);
    }
    if (ret == 0) {
        ret = x509_create_cert(&ekey, cert, cap);
        if (ret > 0) {
            *len = (size_t) ret;
            ret = 0;
        }
        else {
            ret = PICOKEY_EXEC_ERROR;
        }
    }
    mbedtls_ecdsa_free(&ekey);
    return ret == 0 ? PICOKEY_OK : PICOKEY_EXEC_ERROR;
}

/* Build default (ctap2_cbor.h): LibreFido's own model identifiers, never a
 * Yubico or other vendor's AAGUID. EF_AAGUID overrides it per profile. */
extern const uint8_t aaguid[16];

void fido_get_aaguid(uint8_t out[16]) {
    file_t *ef = search_by_fid(EF_AAGUID, NULL, SPECIFY_EF);
    if (ef && file_has_data(ef) && file_get_size(ef) == 16) {
        memcpy(out, file_get_data(ef), 16);
        return;
    }
    memcpy(out, aaguid, 16);
}

int fido_aaguid_set(const uint8_t *in) {
    if (!fido_keystore_ok()) {
        return PICOKEY_ERR_BLOCKED;
    }
    file_t *ef = search_by_fid(EF_AAGUID, NULL, SPECIFY_EF);
    if (!ef) {
        return PICOKEY_EXEC_ERROR;
    }
    int ret = in ? file_put_data(ef, in, 16) : file_put_data(ef, NULL, 0);
    low_flash_available();
    return ret;
}

/* Stores the persistent pinUvAuthToken: sealed, or while the firmware is
 * unconfirmed plain as earlier firmware reads it (see the device key). */
int fido_ppaut_store(void) {
    file_t *ef_pauthtoken = search_by_fid(EF_PAUTHTOKEN, NULL, SPECIFY_EF);
    if (!ef_pauthtoken) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (!fido_keystore_ok()) {
        return PICOKEY_ERR_BLOCKED;     /* the stored token stays as it is */
    }
    int ret = fido_seal_now() ? sks_file_put(SKS_NS_FIDO, ef_pauthtoken, ppaut_token, sizeof(ppaut_token))
                              : file_put_data(ef_pauthtoken, ppaut_token, sizeof(ppaut_token));
    if (ret != PICOKEY_OK) {
        file_put_data(ef_pauthtoken, NULL, 0);      /* never keep an older token */
    }
    low_flash_available();
    return ret;
}

int fido_certdev_generate(bool replace) {
    if (ef_certdev == NULL) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (file_has_data(ef_certdev) && !replace) {
        return PICOKEY_OK;
    }
    uint8_t cert[2048], outk[32];
    size_t len = 0;
    memset(outk, 0, sizeof(outk));
    int ret = load_keydev(outk);
    if (ret != PICOKEY_OK) {
        return ret;
    }
    ret = fido_certdev_build(outk, cert, sizeof(cert), &len);
    mbedtls_platform_zeroize(outk, sizeof(outk));
    if (ret == PICOKEY_OK) {
        ret = file_put_data(ef_certdev, cert + sizeof(cert) - len, (uint16_t) len);
        low_flash_available();
    }
    return ret == PICOKEY_OK ? PICOKEY_OK : PICOKEY_EXEC_ERROR;
}

int scan_files_fido() {
    ef_keydev = search_by_fid(EF_KEY_DEV, NULL, SPECIFY_EF);
    ef_keydev_enc = search_by_fid(EF_KEY_DEV_ENC, NULL, SPECIFY_EF);
    ef_mkek = search_by_fid(EF_MKEK, NULL, SPECIFY_EF);
    if (ef_keydev) {
        if (!fido_keystore_ok()) {
            printf("device key: the root key is not in use, FIDO waits for it\n");
        }
        else if (!file_has_data(ef_keydev) && !file_has_data(ef_keydev_enc)) {
            printf("KEY DEVICE is empty. Generating SECP256R1 curve...");
            mbedtls_ecdsa_context ecdsa;
            mbedtls_ecdsa_init(&ecdsa);
            uint8_t index = 0, keydev[32] = {0};
            size_t key_size = 0;
            int ret = mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP256R1, random_gen, &index);
            if (ret == 0) {
                ret = mbedtls_ecp_write_key_ext(&ecdsa, &key_size, keydev, sizeof(keydev));
            }
            if (ret == 0 && key_size == 32) {
                ret = keydev_store(keydev);
            }
            else {
                ret = PICOKEY_EXEC_ERROR;
            }
            mbedtls_platform_zeroize(keydev, sizeof(keydev));
            mbedtls_ecdsa_free(&ecdsa);
            /* The rest of the scan runs anyway (e.g. a key store that is
             * still locked: the key is made on a later boot). */
            if (ret == PICOKEY_OK) {
                printf(" done!\n");
            }
            else {
                printf(" failed (%d)\n", ret);
            }
        }
        else if (file_has_data(ef_keydev) && file_has_data(ef_keydev_enc)) {
            printf("device key: plain copy next to the host-sealed key, ignored (UNLOCK removes it)\n");
        }
    }
    else {
        printf("FATAL ERROR: KEY DEV not found in memory!\r\n");
    }
    ef_certdev = search_by_fid(EF_EE_DEV, NULL, SPECIFY_EF);
    if (ef_certdev) {
        /* A device key protected by a host key (AUT_ENABLE) cannot be read
         * before it is unlocked: the rest of the scan (PIN, tokens) must
         * still run, or the PIN needed to unlock it would look unset. */
        if (fido_certdev_generate(false) != PICOKEY_OK) {
            printf("device certificate not created (device key locked?)\n");
        }
    }
    else {
        printf("FATAL ERROR: CERT DEV not found in memory!\r\n");
    }
    ef_counter = search_by_fid(EF_COUNTER, NULL, SPECIFY_EF);
    if (ef_counter) {
        if (!file_has_data(ef_counter)) {
            uint32_t v = 0;
            file_put_data(ef_counter, (uint8_t *) &v, sizeof(v));
        }
    }
    else {
        printf("FATAL ERROR: Global counter not found in memory!\r\n");
    }
    ef_pin = search_by_fid(EF_PIN, NULL, SPECIFY_EF);
    ef_authtoken = search_by_fid(EF_AUTHTOKEN, NULL, SPECIFY_EF);
    /* The pinUvAuthToken lives in RAM only and is renewed on every power up
     * (CTAP 2.1, 6.5.2.1); a token stored in flash is dropped. */
    if (file_has_data(ef_authtoken)) {
        flash_clear_file(ef_authtoken);
    }
    random_gen(NULL, paut_token, sizeof(paut_token));
    paut.data = paut_token;
    paut.len = sizeof(paut_token);
    /* The persistent token (pcmr) survives power cycles by definition. It is
     * stored as an sks record (a plain one of earlier firmware is re-sealed);
     * the working copy is in RAM so flash cache reuse can never alias it. */
    file_t *ef_pauthtoken = search_by_fid(EF_PAUTHTOKEN, NULL, SPECIFY_EF);
    if (ef_pauthtoken) {
        size_t len = 0;
        bool legacy = false;
        if (!fido_keystore_ok()) {
            /* the stored token is neither read nor replaced */
            random_gen(NULL, ppaut_token, sizeof(ppaut_token));
            ppaut.permissions = 0;
        }
        else if (sks_file_get(SKS_NS_FIDO, ef_pauthtoken, ppaut_token, sizeof(ppaut_token), &len, &legacy) == PICOKEY_OK &&
                 len == sizeof(ppaut_token)) {
            if (legacy && lf_migrate_ok()) {
                sks_file_put(SKS_NS_FIDO, ef_pauthtoken, ppaut_token, sizeof(ppaut_token));
            }
            /* Its only permission is pcmr; a stored token keeps it. A PIN
             * change or setMinPINLength(forceChangePin) replaces the token
             * (resetPersistentPinUvAuthToken). */
            ppaut.permissions = CTAP_PERMISSION_PCMR;
        }
        else {
            random_gen(NULL, ppaut_token, sizeof(ppaut_token));
            fido_ppaut_store();
            ppaut.permissions = 0;
        }
        ppaut.data = ppaut_token;
        ppaut.len = sizeof(ppaut_token);
    }
    else {
        printf("FATAL ERROR: Persistent Auth Token not found in memory!\r\n");
    }
    ef_largeblob = search_by_fid(EF_LARGEBLOB, NULL, SPECIFY_EF);
    if (!file_has_data(ef_largeblob)) {
        file_put_data(ef_largeblob, (const uint8_t *) "\x80\x76\xbe\x8b\x52\x8d\x00\x75\xf7\xaa\xe9\x8d\x6f\xa5\x7a\x6d\x3c", 17);
    }

    low_flash_available();
    return PICOKEY_OK;
}

void scan_all() {
    scan_flash();
    scan_files_fido();
}

extern void init_otp();
extern bool needs_power_cycle;
void init_fido() {
    scan_all();
#ifdef ENABLE_OTP_APP
    init_otp();
#endif
    needs_power_cycle = false;
}

/* User presence. Both block the card thread until the user-presence module
 * reports the outcome and return true when NO presence was obtained
 * (timeout or cancel).
 *
 * fido_wait_everyday_presence(): only for the everyday operations
 * (makeCredential/getAssertion presence, U2F register/authenticate,
 * authenticatorSelection). It honours the per-profile policy: when the user
 * switched automatic presence on for FIDO (non-secure profile, not a
 * HARDENED build), it succeeds without a press.
 *
 * fido_wait_physical_press(): a physical press, whatever the policy. Every
 * destructive, copying or security-setting operation uses this one
 * (authenticatorReset, device key protection, export, restore, UNLOCK,
 * AUT_DISABLE, board option changes). */
bool fido_wait_everyday_presence(void) {
    return lf_wait_presence(LF_APP_FIDO);
}

bool fido_wait_physical_press(void) {
    return wait_button();
}

/* CTAP error for a presence request that did not complete. */
int fido_up_error() {
    return up_last_result() == UP_RESULT_CANCELLED ? CTAP2_ERR_KEEPALIVE_CANCEL : CTAP2_ERR_USER_ACTION_TIMEOUT;
}

uint32_t user_present_time_limit = 0;

/* Everyday presence (see above) as "present": every call collects a fresh
 * one; presence is consumed by the operation that asked for it and never
 * cached across commands. */
bool check_user_presence() {
    return fido_wait_everyday_presence() == false;
}

#ifdef LF_STORE_V2
/* The signature counter lives in the store's counter log (a 16-byte record
 * per increment instead of a file rewrite); EF_COUNTER is only read once to
 * carry over the value of older firmware. */
#define FIDO_SIGN_CTR_ID    0

static void sign_counter_migrate(void) {
    if (!lf_ctr_present(FIDO_SIGN_CTR_ID) && file_has_data(ef_counter) && file_get_size(ef_counter) >= 4) {
        lf_ctr_set(FIDO_SIGN_CTR_ID, get_uint32_t_le(file_get_data(ef_counter)));
    }
}
#endif

uint32_t get_sign_counter() {
#ifdef LF_STORE_V2
    uint32_t v = 0;
    sign_counter_migrate();
    lf_ctr_get(FIDO_SIGN_CTR_ID, &v);
    return v;
#else
    uint8_t *caddr = file_get_data(ef_counter);
    return get_uint32_t_le(caddr);
#endif
}

/* Reserves the counter value for the signature about to be made. The new
 * value is stored before any signature carries it, so a power cut between
 * signing and storing can never give two signatures the same value. */
int fido_next_sign_counter(uint32_t *out) {
    uint32_t v = get_sign_counter();
    if (v == UINT32_MAX) {
        return PICOKEY_ERR_BLOCKED;         /* never wraps around */
    }
    v++;
#ifdef LF_STORE_V2
    int r = lf_ctr_set(FIDO_SIGN_CTR_ID, v);
    if (r != PICOKEY_OK) {
        return r;
    }
#else
    if (file_put_data(ef_counter, (uint8_t *) &v, sizeof(v)) != PICOKEY_OK) {
        return PICOKEY_EXEC_ERROR;
    }
    low_flash_available();
#endif
    *out = v;
    return PICOKEY_OK;
}

int fido_sign_counter_raise(uint32_t min) {
    if (get_sign_counter() >= min) {
        return PICOKEY_OK;
    }
#ifdef LF_STORE_V2
    return lf_ctr_set(FIDO_SIGN_CTR_ID, min);
#else
    uint8_t v[4];
    put_uint32_t_le(min, v);
    if (file_put_data(ef_counter, v, sizeof(v)) != PICOKEY_OK) {
        return PICOKEY_EXEC_ERROR;
    }
    low_flash_available();
    return PICOKEY_OK;
#endif
}

uint8_t get_opts() {
    file_t *ef = search_by_fid(EF_OPTS, NULL, SPECIFY_EF);
    if (file_has_data(ef)) {
        return *file_get_data(ef);
    }
    return 0;
}

void set_opts(uint8_t opts) {
    file_t *ef = search_by_fid(EF_OPTS, NULL, SPECIFY_EF);
    file_put_data(ef, &opts, sizeof(uint8_t));
    low_flash_available();
}

extern int cmd_register();
extern int cmd_authenticate();
extern int cmd_version();
extern int cbor_parse(uint8_t, const uint8_t *, size_t);
extern uint8_t cbor_status_byte(int ret);
extern int cbor_vendor(const uint8_t *data, size_t len);
extern void driver_init_hid();

#define CTAP_CBOR 0x10

/* CTAP over the FIDO applet: runs cmd (a CTAPHID command code) through
 * cbor_parse, like the HID transport, so the vendor commands get the same
 * gates (locked key store, pinUvAuthToken expiry). The response was encoded
 * into the CTAP scratch space (status byte + CTAP_MAX_CBOR_PAYLOAD); a size
 * beyond that is never copied out. */
static int fido_ccid_ctap(uint8_t cmd) {
    uint8_t *old_buf = res_APDU;
    driver_init_hid();
    int ret = cbor_parse(cmd, apdu.data, apdu.nc);
    res_APDU = old_buf;
    if (ret != 0) {
        return set_res_sw(0x64, cbor_status_byte(ret));
    }
    if (res_APDU_size > CTAP_MAX_CBOR_PAYLOAD) {
        mbedtls_platform_zeroize(ctap_resp->init.data, 1 + CTAP_MAX_CBOR_PAYLOAD);
        res_APDU_size = 0;
        return SW_EXEC_ERROR();
    }
    res_APDU_size += 1;
    memcpy(res_APDU, ctap_resp->init.data, res_APDU_size);
    return SW_OK();
}

int cmd_vendor() {
    return fido_ccid_ctap(CTAP_VENDOR_CBOR);
}

int cmd_cbor() {
    return fido_ccid_ctap(CTAPHID_CBOR);
}

static const cmd_t cmds[] = {
    { CTAP_REGISTER, cmd_register },
    { CTAP_AUTHENTICATE, cmd_authenticate },
    { CTAP_VERSION, cmd_version },
    { CTAP_CBOR, cmd_cbor },
    { 0x41, cmd_vendor },
    { 0x00, 0x0 }
};

int fido_process_apdu() {
    if (CLA(apdu) != 0x00 && CLA(apdu) != 0x80) {
        return SW_CLA_NOT_SUPPORTED();
    }
    if (cap_supported(CAP_U2F)) {
        for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
            if (cmd->ins == INS(apdu)) {
                int r = cmd->cmd_handler();
                return r;
            }
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
