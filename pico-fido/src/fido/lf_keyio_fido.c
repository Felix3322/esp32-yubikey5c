/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
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

/* Single-key transfer of discoverable FIDO credentials (lf_keyio.h). The key
 * ID is the resident credential ID relying parties know (CRED_RESIDENT_LEN
 * bytes). Listed and exported: the discoverable credentials this build can
 * sign with, on a curve the record carries (P-256, P-384, P-521, secp256k1,
 * and Ed25519 with lf_25519). An import makes an explicit-key credential
 * (credential.h): same credential ID, user, keys and extensions, so the
 * relying party sees the credential it registered; exporting it again gives
 * the record it came from (the sign counter aside).
 *
 * Record: {1: rpId (text), 2: credential ID (bytes), 3: user ID (bytes),
 * 4: user name (text), 5: user displayName (text), 6: COSE alg (int),
 * 7: COSE curve (int), 8: private key (bytes: EC scalar big endian at the
 * curve's length, Ed25519 seed), 9: credProtect (uint 1..3), 10: hmac-secret
 * key (bytes 64: CredRandomWithoutUV || CredRandomWithUV), 11: largeBlobKey
 * (bytes 32), 12: credBlob (bytes), 13: use sign counter (bool), 14: sign
 * counter of the exporting device (uint), 15: creation time (uint, seconds),
 * 16: thirdPartyPayment (bool)}. 4, 5 and 10..16 are optional on import. */

#include <string.h>
#include "pico_keys.h"
#include "profile.h"
#include "lf_keyio.h"
#include "lf_policy.h"
#include "fido.h"
#include "ctap.h"
#include "files.h"
#include "credential.h"
#include "mbedtls/platform_util.h"

extern void reset_gna_state(void);
extern void cred_mgmt_reset_state(void);

/* Texts of a list entry are cut for display (lf_keyio.h). */
#define FIDO_LIST_TEXT_MAX      64
#define FIDO_LIST_RP_ID_MAX     128
/* User IDs are 1..64 bytes (makeCredential refuses others). */
#define FIDO_USER_ID_MAX        64
/* Highest sign counter a record may bring. The device counter is raised to
 * it and never lowered again, not even by authenticatorReset, so a value
 * near 2^32 (a damaged or hostile file) would leave every credential of the
 * profile a few signatures from the end for good. No device signs 2^31
 * times; this keeps at least that many signatures after any import. */
#define FIDO_IMPORT_COUNTER_MAX 0x7FFFFFFFu

/* A curve the record has a key format for, which this build signs with. */
static bool fido_keyio_curve_ok(int64_t curve) {
    switch (curve) {
        case FIDO2_CURVE_P256:
        case FIDO2_CURVE_P384:
        case FIDO2_CURVE_P521:
        case FIDO2_CURVE_P256K1:
#ifdef FIDO_ED25519_LF
        case FIDO2_CURVE_ED25519:
#endif
            return credential_curve_supported(curve);
        default:
            return false;
    }
}

/* The COSE algorithms makeCredential pairs with each curve. */
static bool fido_keyio_alg_ok(int64_t alg, int64_t curve) {
    switch (curve) {
        case FIDO2_CURVE_P256:
            return alg == FIDO2_ALG_ES256 || alg == FIDO2_ALG_ESP256;
        case FIDO2_CURVE_P384:
            return alg == FIDO2_ALG_ES384 || alg == FIDO2_ALG_ESP384;
        case FIDO2_CURVE_P521:
            return alg == FIDO2_ALG_ES512 || alg == FIDO2_ALG_ESP512;
        case FIDO2_CURVE_P256K1:
            return alg == FIDO2_ALG_ES256K;
        case FIDO2_CURVE_ED25519:
            return alg == FIDO2_ALG_EDDSA || alg == FIDO2_ALG_ED25519;
        default:
            return false;
    }
}

/* The device key can be used. Otherwise (a host-sealed device key not
 * unlocked yet) every credential would look unreadable: refused instead, as
 * credential management does. */
static bool fido_keyio_ready(void) {
    if (!fido_keystore_ok()) {
        return false;
    }
    uint8_t probe[32];
    int r = load_keydev(probe);
    mbedtls_platform_zeroize(probe, sizeof(probe));
    return r == PICOKEY_OK;
}

/* The credential of resident slot i (its record parsed into rec, its RP in
 * rp_id_hash). false: no record, or one that does not load; cred is then
 * empty. */
static bool fido_keyio_load(uint16_t i, resident_record_t *rec, uint8_t rp_id_hash[32], Credential *cred) {
    memset(cred, 0, sizeof(*cred));
    if (credential_resident_parse(search_dynamic_file((uint16_t)(EF_CRED + i)), rec) != 0) {
        return false;
    }
    memcpy(rp_id_hash, rec->rp_id_hash, 32);
    if (credential_load_record(rec, rp_id_hash, cred) != 0 || cred->rpId.present != true ||
        cred->rpId.len == 0 || cred->userId.present != true) {
        credential_free(cred);
        return false;
    }
    return true;
}

/* Without a verified PIN (after a touch): what a getAssertion with user
 * presence alone gives out, as the policy of fido_keyio_list_protected().
 * credProtect 2 and 3 credentials are only used with user verification or
 * their credential ID (getAssertion answers NO_CREDENTIALS without them):
 * left out. The user name and display name are not answered without user
 * verification (CTAP 2.1, getAssertion): the RP ID and user ID only. */
static bool fido_keyio_needs_uv(const Credential *cred) {
    return cred->extensions.present == true &&
           (cred->extensions.credProtect == CRED_PROT_UV_OPTIONAL_WITH_LIST ||
            cred->extensions.credProtect == CRED_PROT_UV_REQUIRED);
}

static uint16_t fido_keyio_list(uint32_t *cursor, bool pin_verified, CborEncoder *arr) {
    if (*cursor >= MAX_RESIDENT_CREDENTIALS) {
        *cursor = LF_KEYIO_END;
        return 0x9000;
    }
    if (!fido_keyio_ready()) {
        return 0x6985;
    }
    uint32_t used = 0;
    CborError e = CborNoError;
    for (uint16_t i = (uint16_t) *cursor; i < MAX_RESIDENT_CREDENTIALS && e == CborNoError; i++) {
        resident_record_t rec;
        uint8_t rp_id_hash[32], cred_idr[CRED_RESIDENT_LEN];
        Credential cred;
        if (!fido_keyio_load(i, &rec, rp_id_hash, &cred)) {
            continue;
        }
        if (!fido_keyio_curve_ok(cred.curve) || (!pin_verified && fido_keyio_needs_uv(&cred))) {
            credential_free(&cred);
            continue;
        }
        credential_resident_id(&rec, cred_idr);
        bool imported = credential_is_explicit(rec.cred_id, rec.cred_id_len);
        bool has_name = pin_verified && cred.userName.present && cred.userName.len > 0;
        bool has_display = pin_verified && cred.userDisplayName.present && cred.userDisplayName.len > 0;
        size_t rp_len = credential_utf8_truncate(cred.rpId.data, cred.rpId.len, FIDO_LIST_RP_ID_MAX);
        size_t name_len = has_name ? credential_utf8_truncate(cred.userName.data, cred.userName.len, FIDO_LIST_TEXT_MAX) : 0;
        size_t display_len = has_display ? credential_utf8_truncate(cred.userDisplayName.data, cred.userDisplayName.len, FIDO_LIST_TEXT_MAX) : 0;
        /* map and keys, the ID, the texts and user ID with 3-byte headers
         * at most, an int of up to 9 bytes and a bool */
        uint32_t need = (uint32_t) (1 + 7 + (2 + CRED_RESIDENT_LEN) + (3 + rp_len) + 9 + (3 + name_len) +
                                    (3 + display_len) + (3 + cred.userId.len) + 1);
        if (used + need > LF_KEYIO_PAGE_BUDGET) {
            credential_free(&cred);
            *cursor = i;
            return 0x9000;
        }
        CborEncoder m;
        e |= cbor_encoder_create_map(arr, &m, 5 + (has_name ? 1 : 0) + (has_display ? 1 : 0));
        e |= cbor_encode_uint(&m, 1);
        e |= cbor_encode_byte_string(&m, cred_idr, sizeof(cred_idr));
        e |= cbor_encode_uint(&m, 2);
        e |= cbor_encode_text_string(&m, cred.rpId.data, rp_len);
        e |= cbor_encode_uint(&m, 3);
        e |= cbor_encode_int(&m, cred.alg);
        if (has_name) {
            e |= cbor_encode_uint(&m, 4);
            e |= cbor_encode_text_string(&m, cred.userName.data, name_len);
        }
        if (has_display) {
            e |= cbor_encode_uint(&m, 5);
            e |= cbor_encode_text_string(&m, cred.userDisplayName.data, display_len);
        }
        e |= cbor_encode_uint(&m, 6);
        e |= cbor_encode_byte_string(&m, cred.userId.data, cred.userId.len);
        e |= cbor_encode_uint(&m, 7);
        e |= cbor_encode_boolean(&m, imported);
        e |= cbor_encoder_close_container(arr, &m);
        used += need;
        credential_free(&cred);
    }
    if (e != CborNoError) {
        return 0x6400;
    }
    *cursor = LF_KEYIO_END;
    return 0x9000;
}

#if LF_ALLOW_SECRET_EXPORT
static CborError fido_keyio_encode(CborEncoder *enc, const Credential *cred, const uint8_t cred_idr[CRED_RESIDENT_LEN],
                                   const uint8_t *key, size_t key_len, const uint8_t *hmac, const uint8_t *large_blob_key) {
    static const uint8_t empty = 0;     /* an empty credBlob: tinycbor copies from a real pointer */
    CborError e = CborNoError;
    CborEncoder m;
    bool has_name = cred->userName.present && cred->userName.len > 0;
    bool has_display = cred->userDisplayName.present && cred->userDisplayName.len > 0;
    bool has_blob = cred->extensions.present && cred->extensions.credBlob.present;
    bool tpp = cred->extensions.present && cred->extensions.thirdPartyPayment == ptrue;
    /* credProtect 0 (none asked for) is the default, 1 */
    uint64_t cred_protect = cred->extensions.present ? cred->extensions.credProtect : 0;
    if (cred_protect < CRED_PROT_UV_OPTIONAL || cred_protect > CRED_PROT_UV_REQUIRED) {
        cred_protect = CRED_PROT_UV_OPTIONAL;
    }
    size_t n = 9 + (has_name ? 1 : 0) + (has_display ? 1 : 0) + (hmac ? 1 : 0) + (large_blob_key ? 1 : 0) +
               (has_blob ? 1 : 0) + (cred->rtc_creation != 0 ? 1 : 0) + (tpp ? 1 : 0);
    e |= cbor_encoder_create_map(enc, &m, n);
    e |= cbor_encode_uint(&m, 1);
    e |= cbor_encode_text_string(&m, cred->rpId.data, cred->rpId.len);
    e |= cbor_encode_uint(&m, 2);
    e |= cbor_encode_byte_string(&m, cred_idr, CRED_RESIDENT_LEN);
    e |= cbor_encode_uint(&m, 3);
    e |= cbor_encode_byte_string(&m, cred->userId.data, cred->userId.len);
    if (has_name) {
        e |= cbor_encode_uint(&m, 4);
        e |= cbor_encode_text_string(&m, cred->userName.data, cred->userName.len);
    }
    if (has_display) {
        e |= cbor_encode_uint(&m, 5);
        e |= cbor_encode_text_string(&m, cred->userDisplayName.data, cred->userDisplayName.len);
    }
    e |= cbor_encode_uint(&m, 6);
    e |= cbor_encode_int(&m, cred->alg);
    e |= cbor_encode_uint(&m, 7);
    e |= cbor_encode_int(&m, cred->curve);
    e |= cbor_encode_uint(&m, 8);
    e |= cbor_encode_byte_string(&m, key, key_len);
    e |= cbor_encode_uint(&m, 9);
    e |= cbor_encode_uint(&m, cred_protect);
    if (hmac) {
        e |= cbor_encode_uint(&m, 10);
        e |= cbor_encode_byte_string(&m, hmac, CRED_HMAC_KEY_LEN);
    }
    if (large_blob_key) {
        e |= cbor_encode_uint(&m, 11);
        e |= cbor_encode_byte_string(&m, large_blob_key, CRED_LARGE_BLOB_KEY_LEN);
    }
    if (has_blob) {
        e |= cbor_encode_uint(&m, 12);
        e |= cbor_encode_byte_string(&m, cred->extensions.credBlob.data ? cred->extensions.credBlob.data : &empty,
                                     cred->extensions.credBlob.len);
    }
    e |= cbor_encode_uint(&m, 13);
    e |= cbor_encode_boolean(&m, cred->use_sign_count != pfalse);
    e |= cbor_encode_uint(&m, 14);
    e |= cbor_encode_uint(&m, get_sign_counter());
    if (cred->rtc_creation != 0) {
        e |= cbor_encode_uint(&m, 15);
        e |= cbor_encode_uint(&m, cred->rtc_creation);
    }
    if (tpp) {
        e |= cbor_encode_uint(&m, 16);
        e |= cbor_encode_boolean(&m, true);
    }
    e |= cbor_encoder_close_container(enc, &m);
    return e;
}
#endif

/* No application secret: the FIDO PIN (checked by the management applet) is
 * the one a platform needs for the credential too. */
static uint16_t fido_keyio_export(const uint8_t *id, size_t id_len, const uint8_t *secret, size_t secret_len,
                                  lf_keyio_confirm_t confirm, CborEncoder *enc) {
    (void) secret;
    (void) secret_len;
#if !LF_ALLOW_SECRET_EXPORT
    /* HARDENED: credential keys never leave the device */
    (void) id;
    (void) id_len;
    (void) confirm;
    (void) enc;
    return 0x6986;
#else
    if (lf_profile_is_secure()) {
        return 0x6986;
    }
    if (id == NULL || id_len != CRED_RESIDENT_LEN) {
        return 0x6A88;
    }
    /* The command data is not read again once the touch was waited for. */
    uint8_t cred_idr[CRED_RESIDENT_LEN];
    memcpy(cred_idr, id, sizeof(cred_idr));
    if (!fido_keyio_ready()) {
        return 0x6985;
    }
    int slot = -1;
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS && slot < 0; i++) {
        resident_record_t rec;
        if (credential_resident_parse(search_dynamic_file((uint16_t)(EF_CRED + i)), &rec) == 0 &&
            credential_resident_matches(&rec, cred_idr, sizeof(cred_idr))) {
            slot = i;
        }
    }
    if (slot < 0) {
        return 0x6A88;
    }
    resident_record_t rec;
    uint8_t rp_id_hash[32];
    Credential cred;
    if (!fido_keyio_load((uint16_t) slot, &rec, rp_id_hash, &cred)) {
        return 0x6A81;
    }
    if (!fido_keyio_curve_ok(cred.curve) || !fido_keyio_alg_ok(cred.alg, cred.curve)) {
        credential_free(&cred);
        return 0x6A81;
    }
    if (!confirm()) {
        credential_free(&cred);
        return 0x6985;
    }
    fido_cred_key_t key;
    fido_cred_key_init(&key);
    uint8_t priv[CRED_KEY_MAX], hmac[CRED_HMAC_KEY_LEN], large_blob_key[CRED_LARGE_BLOB_KEY_LEN];
    size_t priv_len = 0;
    bool has_hmac = credential_hmac_capable(&cred);
    bool has_lbk = cred.extensions.present && cred.extensions.largeBlobKey == ptrue;
    uint16_t sw = 0x9000;
    if (credential_key_load(&cred, rp_id_hash, &key) != 0 ||
        fido_cred_key_export(&key, priv, sizeof(priv), &priv_len) != PICOKEY_OK ||
        (has_hmac && credential_hmac_key(&cred, rp_id_hash, hmac) != 0) ||
        (has_lbk && credential_large_blob_key(&cred, rp_id_hash, large_blob_key) != 0)) {
        sw = 0x6A81;
    }
    else if (fido_keyio_encode(enc, &cred, cred_idr, priv, priv_len, has_hmac ? hmac : NULL,
                               has_lbk ? large_blob_key : NULL) != CborNoError) {
        sw = 0x6400;
    }
    fido_cred_key_free(&key);
    mbedtls_platform_zeroize(priv, sizeof(priv));
    mbedtls_platform_zeroize(hmac, sizeof(hmac));
    mbedtls_platform_zeroize(large_blob_key, sizeof(large_blob_key));
    credential_free(&cred);
    return sw;
#endif
}

/* s is well-formed UTF-8 (RFC 3629) without NUL: it goes back to platforms
 * in CBOR text strings, and credentials made here never hold a NUL (they are
 * stored up to the first one). */
static bool fido_keyio_text_ok(const uint8_t *s, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t c = s[i];
        size_t n = 0;
        uint32_t cp = 0, min = 0;
        if (c == 0) {
            return false;
        }
        if (c < 0x80) {
            i++;
            continue;
        }
        if ((c & 0xE0) == 0xC0) {
            n = 1;
            cp = c & 0x1F;
            min = 0x80;
        }
        else if ((c & 0xF0) == 0xE0) {
            n = 2;
            cp = c & 0x0F;
            min = 0x800;
        }
        else if ((c & 0xF8) == 0xF0) {
            n = 3;
            cp = c & 0x07;
            min = 0x10000;
        }
        else {
            return false;
        }
        if (len - i - 1 < n) {
            return false;
        }
        for (size_t j = 1; j <= n; j++) {
            if ((s[i + j] & 0xC0) != 0x80) {
                return false;
            }
            cp = (cp << 6) | (s[i + j] & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            return false;
        }
        i += n + 1;
    }
    return true;
}

/* A definite-length string of the record, referenced where it is in the
 * command data (the bytes before the next item), and the iterator moved past
 * it. */
static CborError fido_keyio_string(CborValue *it, bool text, const uint8_t **ptr, size_t *len) {
    if (text ? !cbor_value_is_text_string(it) : !cbor_value_is_byte_string(it)) {
        return CborErrorIllegalType;
    }
    if (!cbor_value_is_length_known(it)) {
        return CborErrorUnknownLength;
    }
    CborError e = cbor_value_get_string_length(it, len);
    if (e == CborNoError) {
        e = cbor_value_advance(it);
    }
    if (e == CborNoError) {
        *ptr = cbor_value_get_next_byte(it) - *len;
    }
    return e;
}

static CborError fido_keyio_int(CborValue *it, int64_t *v) {
    if (!cbor_value_is_integer(it)) {
        return CborErrorIllegalType;
    }
    CborError e = cbor_value_get_int64_checked(it, v);
    return e == CborNoError ? cbor_value_advance_fixed(it) : e;
}

static CborError fido_keyio_uint(CborValue *it, uint64_t *v) {
    if (!cbor_value_is_unsigned_integer(it)) {
        return CborErrorIllegalType;
    }
    CborError e = cbor_value_get_uint64(it, v);
    return e == CborNoError ? cbor_value_advance_fixed(it) : e;
}

static CborError fido_keyio_bool(CborValue *it, bool *v) {
    if (!cbor_value_is_boolean(it)) {
        return CborErrorIllegalType;
    }
    CborError e = cbor_value_get_boolean(it, v);
    return e == CborNoError ? cbor_value_advance_fixed(it) : e;
}

#define REC_KEY(k)      (1u << (k))
#define REC_REQUIRED    (REC_KEY(1) | REC_KEY(2) | REC_KEY(3) | REC_KEY(6) | REC_KEY(7) | REC_KEY(8))

/* Reads and checks a record: 0x9000, 6A80 (invalid) or 6A81 (a curve or
 * algorithm this build cannot import). x points into the command data. */
static uint16_t fido_keyio_parse(const CborValue *record, credential_explicit_t *x, uint32_t *counter) {
    CborValue it;
    uint32_t seen = 0;
    uint64_t u = 0;
    memset(x, 0, sizeof(*x));
    x->cred_protect = CRED_PROT_UV_OPTIONAL;
    x->use_sign_count = true;
    *counter = 0;
    if (!cbor_value_is_map(record) || cbor_value_enter_container(record, &it) != CborNoError) {
        return 0x6A80;
    }
    while (!cbor_value_at_end(&it)) {
        uint64_t k = 0;
        const uint8_t *p = NULL;
        size_t n = 0;
        if (fido_keyio_uint(&it, &k) != CborNoError || cbor_value_at_end(&it)) {
            return 0x6A80;
        }
        if (k < 32) {
            if (seen & REC_KEY(k)) {
                return 0x6A80;
            }
            seen |= REC_KEY(k);
        }
        CborError e = CborNoError;
        switch (k) {
            case 1:
                e = fido_keyio_string(&it, true, &p, &n);
                x->rp_id = (const char *) p;
                x->rp_id_len = n;
                break;
            case 2:
                e = fido_keyio_string(&it, false, &p, &n);
                if (e == CborNoError && n != CRED_RESIDENT_LEN) {
                    return 0x6A80;
                }
                x->resident_id = p;
                break;
            case 3:
                e = fido_keyio_string(&it, false, &p, &n);
                x->user_id = p;
                x->user_id_len = n;
                break;
            case 4:
            case 5:
                e = fido_keyio_string(&it, true, &p, &n);
                if (e == CborNoError && !fido_keyio_text_ok(p, n)) {
                    return 0x6A80;
                }
                /* an empty name is no name, as makeCredential stores it */
                if (n > 0 && k == 4) {
                    x->user_name = (const char *) p;
                    x->user_name_len = n;
                }
                else if (n > 0) {
                    x->display_name = (const char *) p;
                    x->display_name_len = n;
                }
                break;
            case 6:
                e = fido_keyio_int(&it, &x->alg);
                break;
            case 7:
                e = fido_keyio_int(&it, &x->curve);
                break;
            case 8:
                e = fido_keyio_string(&it, false, &p, &n);
                x->key = p;
                x->key_len = n;
                break;
            case 9:
                e = fido_keyio_uint(&it, &x->cred_protect);
                if (e == CborNoError && (x->cred_protect < CRED_PROT_UV_OPTIONAL || x->cred_protect > CRED_PROT_UV_REQUIRED)) {
                    return 0x6A80;
                }
                break;
            case 10:
                e = fido_keyio_string(&it, false, &p, &n);
                if (e == CborNoError && n != CRED_HMAC_KEY_LEN) {
                    return 0x6A80;
                }
                x->hmac_key = p;
                break;
            case 11:
                e = fido_keyio_string(&it, false, &p, &n);
                if (e == CborNoError && n != CRED_LARGE_BLOB_KEY_LEN) {
                    return 0x6A80;
                }
                x->large_blob_key = p;
                break;
            case 12:
                e = fido_keyio_string(&it, false, &p, &n);
                if (e == CborNoError && n > MAX_CREDBLOB_LENGTH) {
                    return 0x6A80;
                }
                x->cred_blob = p;
                x->cred_blob_len = n;
                break;
            case 13:
                e = fido_keyio_bool(&it, &x->use_sign_count);
                break;
            case 14:
                e = fido_keyio_uint(&it, &u);
                if (e == CborNoError && u > FIDO_IMPORT_COUNTER_MAX) {
                    return 0x6A80;
                }
                *counter = (uint32_t) u;
                break;
            case 15:
                e = fido_keyio_uint(&it, &x->creation_time);
                break;
            case 16:
                e = fido_keyio_bool(&it, &x->third_party_payment);
                break;
            default:
                /* a later version's field; never a tag (lf_mgmt.c refuses
                 * them), which tinycbor would skip without its item */
                e = cbor_value_is_tag(&it) ? CborErrorIllegalType : cbor_value_advance(&it);
                break;
        }
        if (e != CborNoError) {
            return 0x6A80;
        }
    }
    if ((seen & REC_REQUIRED) != REC_REQUIRED) {
        return 0x6A80;
    }
    if (x->rp_id_len == 0 || x->rp_id_len > CRED_IMPORT_RP_ID_MAX ||
        !fido_keyio_text_ok((const uint8_t *) x->rp_id, x->rp_id_len)) {
        return 0x6A80;
    }
    /* the form every resident ID has, which getAssertion and makeCredential
     * look up in the stored records */
    if (!credential_is_resident(x->resident_id, CRED_RESIDENT_LEN)) {
        return 0x6A80;
    }
    if (x->user_id_len == 0 || x->user_id_len > FIDO_USER_ID_MAX) {
        return 0x6A80;
    }
    if (!fido_keyio_curve_ok(x->curve)) {
        return 0x6A81;
    }
    if (!fido_keyio_alg_ok(x->alg, x->curve)) {
        return 0x6A80;
    }
    return 0x9000;
}

static uint16_t fido_keyio_import(const CborValue *record, const uint8_t *secret, size_t secret_len,
                                  const uint8_t *target, size_t target_len, bool replace,
                                  lf_keyio_confirm_t confirm, uint8_t id[LF_KEYIO_ID_MAX], size_t *id_len) {
    (void) secret;
    (void) secret_len;
    /* FIDO credentials of a secure profile or a HARDENED build are always
     * made on the device (checked by the management applet too). */
    if (lf_profile_is_secure()) {
        return 0x6986;
    }
    if (target != NULL && target_len != 0) {
        return 0x6A80;              /* a single credential store */
    }
    if (!fido_keyio_ready()) {
        return 0x6985;
    }
    credential_explicit_t x;
    uint32_t counter = 0;
    uint16_t sw = fido_keyio_parse(record, &x, &counter);
    if (sw != 0x9000) {
        return sw;
    }
    /* the key is valid for its curve (length, scalar in [1, n-1]) */
    fido_cred_key_t key;
    fido_cred_key_init(&key);
    int r = fido_cred_key_import(&key, (int) x.curve, x.key, x.key_len);
    fido_cred_key_free(&key);
    if (r != PICOKEY_OK) {
        return r == CTAP2_ERR_UNSUPPORTED_ALGORITHM ? 0x6A81 : 0x6A80;
    }
    /* Everything is copied out of the command data before the touch. */
    credential_import_t imp;
    r = credential_import_check(&imp, &x, replace);
    if (r == CTAP2_ERR_CREDENTIAL_EXCLUDED) {
        sw = 0x6A89;
    }
    else if (r == CTAP2_ERR_KEY_STORE_FULL) {
        sw = 0x6A84;
    }
    else if (r == CTAP2_ERR_REQUEST_TOO_LARGE || r == CTAP1_ERR_INVALID_PARAMETER) {
        sw = 0x6A80;                /* more than a credential can hold */
    }
    else if (r != 0) {
        sw = 0x6400;
    }
    else if (!confirm()) {
        sw = 0x6985;
    }
    /* The counter first: should the write fail, a higher counter harms no
     * credential, while an imported credential must never sign below the
     * counter the exporting device had reached. */
    else if (fido_sign_counter_raise(counter) != PICOKEY_OK) {
        sw = 0x6400;
    }
    else {
        /* the record buffer is scratch space once stored */
        memcpy(id, imp.record + 32, CRED_RESIDENT_LEN);
        r = credential_import_store(&imp);
        if (r == 0) {
            *id_len = CRED_RESIDENT_LEN;
        }
        else {
            sw = r == CTAP2_ERR_KEY_STORE_FULL ? 0x6A84 : 0x6400;
        }
        /* The stored credentials changed under any enumeration in progress. */
        reset_gna_state();
        cred_mgmt_reset_state();
    }
    mbedtls_platform_zeroize(&imp, sizeof(imp));
    return sw;
}

/* CTAP lists the RPs and users of discoverable credentials only through
 * credential management, which needs a verified PIN (with no PIN set it is
 * not available at all). Without a verified PIN the listing takes a touch,
 * as getAssertion does, and shows only what a getAssertion with user
 * presence alone reveals (fido_keyio_needs_uv()), naming the RPs a caller
 * of getAssertion would have to know. */
static bool fido_keyio_list_protected(bool pin_verified) {
    return !pin_verified;
}

static const lf_keyio_ops_t fido_keyio_ops = {
    .list = fido_keyio_list,
    .export_key = fido_keyio_export,
    .import_key = fido_keyio_import,
    .list_protected = fido_keyio_list_protected,
};

void lf_keyio_fido_register(void) {
    lf_keyio_register(LF_APP_FIDO, &fido_keyio_ops);
}
