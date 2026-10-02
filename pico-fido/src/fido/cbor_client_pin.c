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
#ifndef ESP_PLATFORM
#include "common.h"
#else
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/sha256.h"
#include "mbedtls/hkdf.h"
#include "cbor.h"
#include "ctap.h"
#include "ctap2_cbor.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#include "hid/ctap_hid.h"
#include "fido.h"
#include "files.h"
#include "random.h"
#include "crypto_utils.h"
#include "apdu.h"
#include "kek.h"
#include "low_flash.h"
#include "sks.h"
#include "security.h"

/* pinUvAuthToken lifetime (CTAP 2.1, 6.5.2.1): initial_usage_time_limit is
 * when the token was issued, usage_timer when it was last used. */
uint32_t usage_timer = 0, initial_usage_time_limit = 0;
uint32_t max_usage_time_period  = 600 * 1000;
static bool paut_used = false;
bool needs_power_cycle = false;
static mbedtls_ecdh_context hkey;
static bool hkey_init = false;
int pinUvAuthTokenUsageTimerObserver();

int beginUsingPinUvAuthToken(bool userIsPresent) {
    paut.user_present = userIsPresent;
    paut.user_verified = true;
    initial_usage_time_limit = board_millis();
    usage_timer = board_millis();
    paut.in_use = true;
    paut_used = false;
    return 0;
}

void clearUserPresentFlag() {
    if (paut.in_use == true) {
        paut.user_present = false;
    }
}

void clearUserVerifiedFlag() {
    if (paut.in_use == true) {
        paut.user_verified = false;
    }
}

/* Keeps lbw only if the token was given it: assigning it granted the
 * large-blob write permission to every token after any assertion. */
void clearPinUvAuthTokenPermissionsExceptLbw() {
    if (paut.in_use == true) {
        paut.permissions &= CTAP_PERMISSION_LBW;
    }
}

void stopUsingPinUvAuthToken() {
    paut.permissions = 0;
    usage_timer = 0;
    paut.in_use = false;
    memset(paut.rp_id_hash, 0, sizeof(paut.rp_id_hash));
    paut.has_rp_id = false;
    initial_usage_time_limit = 0;
    paut.user_present = paut.user_verified = false;
    user_present_time_limit = 0;
}

bool getUserPresentFlagValue() {
    if (paut.in_use != true) {
        paut.user_present = false;
    }
    return paut.user_present;
}

bool getUserVerifiedFlagValue() {
    if (paut.in_use != true) {
        paut.user_verified = false;
    }
    return paut.user_verified;
}

int regenerate() {
    if (hkey_init == true) {
        mbedtls_ecdh_free(&hkey);
    }

    mbedtls_ecdh_init(&hkey);
    hkey_init = true;
    mbedtls_ecdh_setup(&hkey, MBEDTLS_ECP_DP_SECP256R1);
    int ret = mbedtls_ecdh_gen_public(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.d, &hkey.ctx.mbed_ecdh.Q, random_gen, NULL);
    mbedtls_mpi_lset(&hkey.ctx.mbed_ecdh.Qp.Z, 1);
    if (ret != 0) {
        return ret;
    }
    return 0;
}

int kdf(uint8_t protocol, const mbedtls_mpi *z, uint8_t *sharedSecret) {
    int ret = 0;
    uint8_t buf[32];
    ret = mbedtls_mpi_write_binary(z, buf, sizeof(buf));
    if (ret == 0) {
        if (protocol == 1) {
            ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), buf, sizeof(buf), sharedSecret);
        }
        else if (protocol == 2) {
            const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            ret = mbedtls_hkdf(md_info, NULL, 0, buf, sizeof(buf), (uint8_t *) "CTAP2 HMAC key", 14, sharedSecret, 32);
            if (ret == 0) {
                ret = mbedtls_hkdf(md_info, NULL, 0, buf, sizeof(buf), (uint8_t *) "CTAP2 AES key", 13, sharedSecret + 32, 32);
            }
        }
        else {
            ret = -1;
        }
    }
    mbedtls_platform_zeroize(buf, sizeof(buf));
    return ret;
}

/* A failed ECDH (peer point not on the curve, or no key agreement key yet:
 * the platform cannot know one before getKeyAgreement) is an error. It used
 * to go on with z = 0, i.e. the public constant KDF(0^32) as the secret. */
int ecdh(uint8_t protocol, const mbedtls_ecp_point *Q, uint8_t *sharedSecret) {
    if (hkey_init == false) {
        return -1;
    }
    mbedtls_mpi z;
    mbedtls_mpi_init(&z);
    int ret = mbedtls_ecdh_compute_shared(&hkey.ctx.mbed_ecdh.grp, &z, Q, &hkey.ctx.mbed_ecdh.d, random_gen, NULL);
    if (ret == 0) {
        ret = kdf(protocol, &z, sharedSecret);
    }
    mbedtls_mpi_free(&z);
    return ret;
}

int resetPinUvAuthToken() {
    random_gen(NULL, paut_token, sizeof(paut_token));
    paut.permissions = 0;
    paut.data = paut_token;
    paut.len = sizeof(paut_token);
    return 0;
}

int resetPersistentPinUvAuthToken() {
    random_gen(NULL, ppaut_token, sizeof(ppaut_token));
    fido_ppaut_store();                 /* removes the old token on failure */
    ppaut.permissions = 0;
    ppaut.data = ppaut_token;
    ppaut.len = sizeof(ppaut_token);
    return 0;
}

/* Loads the PIN record (retries | length | format | verifier) and persists a
 * decremented retry counter BEFORE the PIN is compared, so cutting the power
 * after a wrong guess can never give the attempt back. */
static int pin_consume_retry(uint8_t pin_data[35], uint16_t *pin_size, uint8_t *retries) {
    uint16_t size = file_get_size(ef_pin);
    if (size < 34 || size > 35) {
        return CTAP2_ERR_PIN_NOT_SET;
    }
    memcpy(pin_data, file_get_data(ef_pin), size);
    if (pin_data[0] == 0) {
        return CTAP2_ERR_PIN_BLOCKED;
    }
    pin_data[0] -= 1;
    if (file_put_data(ef_pin, pin_data, size) != PICOKEY_OK || low_flash_commit() != PICOKEY_OK) {
        return CTAP1_ERR_OTHER;
    }
    *pin_size = size;
    *retries = pin_data[0];
    return CTAP2_OK;
}

extern uint8_t new_pin_mismatches;

/* PIN check for exporting the profile (management applet): same verifier,
 * retry counter and lockout as ClientPIN. Returns an ISO 7816 status word:
 * 9000, 6A88 (no PIN set), 6982 (PIN required: none or an impossible
 * length given, no retry used), 63Cx, 6983 (blocked), 6985 (power cycle). */
uint16_t fido_export_pin_check(const uint8_t *pin, uint16_t len) {
    if (!file_has_data(ef_pin)) {
        return 0x6A88;
    }
    if (*file_get_data(ef_pin) == 0) {
        return 0x6983;
    }
    /* A PIN is 4..63 bytes (setPIN/changePIN). Anything else, including
     * the empty PIN the host tools send when none was entered, cannot be
     * right: it is refused before the retry counter is touched. */
    if (pin == NULL || len < 4 || len > 63) {
        return 0x6982;
    }
    /* The verifier is derived from the root key: while it is held (not in
     * use) a right PIN would not match, and a retry would be lost. (A key
     * store locked by the HARDENED policy has the right root: the PIN of an
     * update is still checked there.) */
    if (security_root_unavailable()) {
        return 0x6985;
    }
    if (needs_power_cycle) {
        return 0x6985;
    }
    uint8_t pin_data[35] = { 0 }, retries = 0;
    uint16_t pin_size = 0;
    int r = pin_consume_retry(pin_data, &pin_size, &retries);
    if (r != CTAP2_OK) {
        mbedtls_platform_zeroize(pin_data, sizeof(pin_data));
        return r == CTAP2_ERR_PIN_BLOCKED ? 0x6983 : (r == CTAP2_ERR_PIN_NOT_SET ? 0x6A88 : 0x6F00);
    }
    uint8_t phash[32], dhash[32], off = 3;
    mbedtls_sha256(pin, len, phash, 0);
    if (pin_size == 34) {
        off = 2;
        double_hash_pin(phash, 16, dhash);
    }
    else {
        pin_derive_verifier(phash, 16, dhash);
    }
    bool ok = ct_memcmp(dhash, pin_data + off, 32) == 0;
    mbedtls_platform_zeroize(phash, sizeof(phash));
    mbedtls_platform_zeroize(dhash, sizeof(dhash));
    if (!ok) {
        mbedtls_platform_zeroize(pin_data, sizeof(pin_data));
        if (retries == 0) {
            return 0x6983;
        }
        if (++new_pin_mismatches >= 3) {
            needs_power_cycle = true;
        }
        return (uint16_t) (0x63C0 | (retries > 15 ? 15 : retries));
    }
    pin_data[0] = MAX_PIN_RETRIES;
    new_pin_mismatches = 0;
    r = file_put_data(ef_pin, pin_data, pin_size);
    mbedtls_platform_zeroize(pin_data, sizeof(pin_data));
    if (r != PICOKEY_OK || low_flash_commit() != PICOKEY_OK) {
        return 0x6F00;
    }
    return 0x9000;
}

int encrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, uint16_t in_len, uint8_t *out) {
    if (protocol == 1) {
        memcpy(out, in, in_len);
        return aes_encrypt(key, NULL, 32 * 8, PICO_KEYS_AES_MODE_CBC, out, in_len);
    }
    else if (protocol == 2) {
        random_gen(NULL, out, IV_SIZE);
        memcpy(out + IV_SIZE, in, in_len);
        return aes_encrypt(key + 32, out, 32 * 8, PICO_KEYS_AES_MODE_CBC, out + IV_SIZE, in_len);
    }

    return -1;
}

int decrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, uint16_t in_len, uint8_t *out) {
    if (protocol == 1) {
        memcpy(out, in, in_len);
        return aes_decrypt(key, NULL, 32 * 8, PICO_KEYS_AES_MODE_CBC, out, in_len);
    }
    else if (protocol == 2) {
        memcpy(out, in + IV_SIZE, in_len - IV_SIZE);
        return aes_decrypt(key + 32, in, 32 * 8, PICO_KEYS_AES_MODE_CBC, out, in_len - IV_SIZE);
    }

    return -1;
}

int authenticate(uint8_t protocol, const uint8_t *key, const uint8_t *data, size_t len, uint8_t *sign) {
    uint8_t hmac[32];
    int ret =
        mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32, data, len, hmac);
    if (ret != 0) {
        return ret;
    }
    if (protocol == 1) {
        memcpy(sign, hmac, 16);
    }
    else if (protocol == 2) {
        memcpy(sign, hmac, 32);
    }
    else {
        return -1;
    }
    return 0;
}

/* Checks an authenticator/pinUvAuthParam; a signature of the wrong length
 * for the protocol is rejected before any byte of it is read. */
int verify(uint8_t protocol, const uint8_t *key, const uint8_t *data, uint16_t len, const uint8_t *sign, size_t sign_len) {
    uint8_t hmac[32];
    size_t expected = protocol == 1 ? 16 : (protocol == 2 ? 32 : 0);
    if (expected == 0 || key == NULL || sign == NULL || sign_len != expected) {
        return -1;
    }
    if (key == paut.data) {
        /* Whatever path reached here (the CCID vendor command skips
         * cbor_parse): an expired or stopped token never passes, and so
         * can never be revived by the timer refresh below. */
        pinUvAuthTokenUsageTimerObserver();
        if (paut.in_use == false) {
            return -1;
        }
    }
    int ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32, data, len, hmac);
    if (ret != 0) {
        return ret;
    }
    ret = ct_memcmp(sign, hmac, expected);
    mbedtls_platform_zeroize(hmac, sizeof(hmac));
    if (ret == 0 && key == paut.data && paut.in_use) {
        /* the pinUvAuthToken was used: its rolling timer restarts */
        paut_used = true;
        usage_timer = board_millis();
    }
    return ret;
}

int initialize() {
    regenerate();
    return resetPinUvAuthToken();
}

int getPublicKey() {
    return 0;
}

/* Runs before every CTAP2 command (cbor_parse). The token stops when it was
 * not used within the initial usage time limit (30 s over USB), or when it
 * has not been used for max_usage_time_period (rolling timer); the user
 * present flag lasts the initial limit only. */
int pinUvAuthTokenUsageTimerObserver() {
    if (paut.in_use == false) {
        return -1;
    }
    uint32_t now = board_millis();
    if (now - usage_timer >= max_usage_time_period ||
        (paut_used == false && now - initial_usage_time_limit >= TRANSPORT_TIME_LIMIT)) {
        stopUsingPinUvAuthToken();
        return 1;
    }
    if (now - initial_usage_time_limit >= TRANSPORT_TIME_LIMIT) {
        clearUserPresentFlag();
    }
    return 0;
}

/* Called once the PIN was verified, while session_pin still belongs to the
 * PIN the device key may have been bound to.
 *
 * Older firmware bound the device key to the PIN (format 0x02, and the
 * upstream MKEK format): after every power up nothing could be signed until
 * the PIN was entered again, not even what needs only user presence (U2F,
 * assertions with userVerification "discouraged", which CTAP 2.1 allows
 * with a PIN set). Such a key is re-sealed here as an sks record under the
 * profile root key; the PIN guards user verification through its retry
 * counter. A key in the current format, or sealed under a host key
 * (AUT_ENABLE, restore; locked or not), is never touched, so a PIN change
 * neither needs the device key nor undoes the host sealing. */
static int check_keydev_encrypted(void) {
    int ret = keydev_migrate_legacy();
    if (ret != PICOKEY_OK) {
        printf("device key: legacy format could not be converted (%d)\n", ret);
    }
    return ret;
}

uint8_t new_pin_mismatches = 0;

int cbor_client_pin(const uint8_t *data, size_t len) {
    size_t resp_size = 0;
    uint64_t subcommand = 0x0, pinUvAuthProtocol = 0, permissions = 0;
    int64_t kty = 0, alg = 0, crv = 0;
    CborParser parser;
    CborEncoder encoder, mapEncoder;
    CborValue map;
    CborError error = CborNoError;
    CborByteString pinUvAuthParam = { 0 }, newPinEnc = { 0 }, pinHashEnc = { 0 }, kax = { 0 }, kay = { 0 };
    CborCharString rpId = { 0 };
    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    if (hkey_init == false) {
        initialize();
    }
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 2 && val_c != val_u) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (val_u < val_c) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x02) {
            CBOR_FIELD_GET_UINT(subcommand, 1);
        }
        else if (val_u == 0x03) {
            CBOR_CHECK(COSE_read_key(&_f1, &kty, &alg, &crv, &kax, &kay));
        }
        else if (val_u == 0x04) {
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
        else if (val_u == 0x05) {
            CBOR_FIELD_GET_BYTES(newPinEnc, 1);
        }
        else if (val_u == 0x06) {
            CBOR_FIELD_GET_BYTES(pinHashEnc, 1);
        }
        else if (val_u == 0x09) {
            CBOR_FIELD_GET_UINT(permissions, 1);
        }
        else if (val_u == 0x0A) {
            CBOR_FIELD_GET_TEXT(rpId, 1);
        }
        else {
            CBOR_ADVANCE(1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);
    if (subcommand == 0x0) {
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    }
    else if (subcommand == 0x1) { //getPINRetries
        /* No PIN set: the full count (there is no PIN record to read). */
        uint8_t retries = file_has_data(ef_pin) ? *file_get_data(ef_pin) : MAX_PIN_RETRIES;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, needs_power_cycle ? 2 : 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, retries));
        if (needs_power_cycle) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, true));
        }
    }
    else if (subcommand == 0x2) { //getKeyAgreement
        if (pinUvAuthProtocol == 1 || pinUvAuthProtocol == 2) {
            CborEncoder mapEncoder2;
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));

            CBOR_CHECK(COSE_key_shared(&hkey, &mapEncoder, &mapEncoder2));
        }
        else if (pinUvAuthProtocol == 0) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        else {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
    }
    else if (subcommand == 0x3) { //setPIN
        if (kax.present == false || kay.present == false || pinUvAuthProtocol == 0 ||
            newPinEnc.present == false || pinUvAuthParam.present == false || alg == 0) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (file_has_data(ef_pin)) {
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        if ((pinUvAuthProtocol == 1 && newPinEnc.len != 64) ||
            (pinUvAuthProtocol == 2 && newPinEnc.len != 64 + IV_SIZE)) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t sharedSecret[64];
        int ret = ecdh((uint8_t)pinUvAuthProtocol, &hkey.ctx.mbed_ecdh.Qp, sharedSecret);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (verify((uint8_t)pinUvAuthProtocol, sharedSecret, newPinEnc.data, (uint16_t)newPinEnc.len, pinUvAuthParam.data, pinUvAuthParam.len) != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t paddedNewPin[64];
        ret = decrypt((uint8_t)pinUvAuthProtocol, sharedSecret, newPinEnc.data, (uint16_t)newPinEnc.len, paddedNewPin);
        mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
        if (ret != 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (paddedNewPin[63] != 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        uint8_t pin_len = 0;
        while (paddedNewPin[pin_len] != 0 && pin_len < sizeof(paddedNewPin)) {
            pin_len++;
        }
        uint8_t minPin = 4;
        file_t *ef_minpin = search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
        if (file_has_data(ef_minpin)) {
            minPin = *file_get_data(ef_minpin);
        }
        if (pin_len < minPin) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        uint8_t hsh[35], dhash[32];
        hsh[0] = MAX_PIN_RETRIES;
        hsh[1] = pin_len;
        hsh[2] = 1; // New format indicator
        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), paddedNewPin, pin_len, dhash);
        mbedtls_platform_zeroize(paddedNewPin, sizeof(paddedNewPin));
        pin_derive_verifier(dhash, 16, hsh + 3);
        file_put_data(ef_pin, hsh, sizeof(hsh));
        low_flash_available();

        pin_derive_session(dhash, 16, session_pin);
        check_keydev_encrypted();       /* best effort: the PIN is set */
        mbedtls_platform_zeroize(hsh, sizeof(hsh));
        mbedtls_platform_zeroize(dhash, sizeof(dhash));
        needs_power_cycle = false;

        goto err; //No return
    }
    else if (subcommand == 0x4) { //changePIN
        if (kax.present == false || kay.present == false || pinUvAuthProtocol == 0 ||
            newPinEnc.present == false || pinUvAuthParam.present == false || alg == 0 ||
            pinHashEnc.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (!file_has_data(ef_pin)) {
            CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
        }
        if (*file_get_data(ef_pin) == 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
        }
        if ((pinUvAuthProtocol == 1 && (newPinEnc.len != 64 || pinHashEnc.len != 16)) ||
            (pinUvAuthProtocol == 2 &&
             (newPinEnc.len != 64 + IV_SIZE || pinHashEnc.len != 16 + IV_SIZE))) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (needs_power_cycle) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
        }
        uint8_t sharedSecret[64];
        int ret = ecdh((uint8_t)pinUvAuthProtocol, &hkey.ctx.mbed_ecdh.Qp, sharedSecret);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t tmp[80 + 32];
        memcpy(tmp, newPinEnc.data, newPinEnc.len);
        memcpy(tmp + newPinEnc.len, pinHashEnc.data, pinHashEnc.len);
        if (verify((uint8_t)pinUvAuthProtocol, sharedSecret, tmp, (uint16_t)(newPinEnc.len + pinHashEnc.len), pinUvAuthParam.data, pinUvAuthParam.len) != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t pin_data[35] = { 0 }, retries = 0;
        uint16_t pin_size = 0;
        ret = pin_consume_retry(pin_data, &pin_size, &retries);
        if (ret != CTAP2_OK) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(ret);
        }
        uint8_t paddedNewPin[64];
        ret = decrypt((uint8_t)pinUvAuthProtocol, sharedSecret, pinHashEnc.data, (uint16_t)pinHashEnc.len, paddedNewPin);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t dhash[32], off = 3;
        if (file_get_size(ef_pin) == 34) {
            off = 2;
            double_hash_pin(paddedNewPin, 16, dhash);
        }
        else {
            pin_derive_verifier(paddedNewPin, 16, dhash);
        }

        if (ct_memcmp(dhash, file_get_data(ef_pin) + off, 32) != 0) {
            regenerate();
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            mbedtls_platform_zeroize(paddedNewPin, sizeof(paddedNewPin));
            mbedtls_platform_zeroize(dhash, sizeof(dhash));
            mbedtls_platform_zeroize(pin_data, sizeof(pin_data));
            if (retries == 0) {
                CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
            }
            if (++new_pin_mismatches >= 3) {
                needs_power_cycle = true;
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
            }
            else {
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
            }
        }
        mbedtls_platform_zeroize(dhash, sizeof(dhash));
        /* The PIN was right: the retries come back first, whatever follows. */
        pin_data[0] = MAX_PIN_RETRIES;
        new_pin_mismatches = 0;
        if (off == 2) {
            /* Legacy PIN record: a device key bound to its session is
             * re-sealed first; the record is upgraded only once that
             * worked, or the key would be lost with the old session. */
            hash_multi(paddedNewPin, 16, session_pin);
            if (check_keydev_encrypted() != PICOKEY_OK) {
                file_put_data(ef_pin, pin_data, pin_size);
                low_flash_available();
                mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
                mbedtls_platform_zeroize(paddedNewPin, sizeof(paddedNewPin));
                mbedtls_platform_zeroize(pin_data, sizeof(pin_data));
                CBOR_ERROR(CTAP2_ERR_PROCESSING);
            }
            pin_data[2] = 1;      // New format indicator
            pin_derive_verifier(paddedNewPin, 16, pin_data + 3);
            pin_size = sizeof(pin_data);
        }
        pin_derive_session(paddedNewPin, 16, session_pin);
        file_put_data(ef_pin, pin_data, pin_size);
        low_flash_available();

        /* A device key bound to the old PIN session is re-sealed now, while
         * that session is known; any other key (current format, or sealed
         * under a host key, locked or not) is left alone. A failure is not
         * a wrong PIN: the PIN is simply not changed. */
        if (check_keydev_encrypted() != PICOKEY_OK) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            mbedtls_platform_zeroize(paddedNewPin, sizeof(paddedNewPin));
            mbedtls_platform_zeroize(pin_data, sizeof(pin_data));
            CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        ret = decrypt((uint8_t)pinUvAuthProtocol, sharedSecret, newPinEnc.data, (uint16_t)newPinEnc.len, paddedNewPin);
        mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
        if (ret != 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (paddedNewPin[63] != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t pin_len = 0;
        while (paddedNewPin[pin_len] != 0 && pin_len < sizeof(paddedNewPin)) {
            pin_len++;
        }
        uint8_t minPin = 4;
        file_t *ef_minpin = search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
        if (file_has_data(ef_minpin)) {
            minPin = *file_get_data(ef_minpin);
        }
        if (pin_len < minPin) {
            mbedtls_platform_zeroize(paddedNewPin, sizeof(paddedNewPin));
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        /* New PIN is valid and verified. The device key does not depend on
         * the PIN (sks record, or sealed under a host key): nothing to
         * re-encrypt, and nothing that needs the key unlocked. */
        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), paddedNewPin, pin_len, dhash);
        mbedtls_platform_zeroize(paddedNewPin, sizeof(paddedNewPin));
        pin_derive_session(dhash, 16, session_pin);

        pin_data[0] = MAX_PIN_RETRIES;
        pin_data[1] = pin_len;
        pin_data[2] = 1; // New format indicator
        pin_derive_verifier(dhash, 16, pin_data + 3);

        if (file_has_data(ef_minpin) && file_get_data(ef_minpin)[1] == 1 && ct_memcmp(pin_data + 3, file_get_data(ef_pin) + 3, 32) == 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        file_put_data(ef_pin, pin_data, sizeof(pin_data));

        mbedtls_platform_zeroize(pin_data, sizeof(pin_data));
        mbedtls_platform_zeroize(dhash, sizeof(dhash));
        if (file_has_data(ef_minpin) && file_get_data(ef_minpin)[1] == 1) {
            uint8_t *tmpf = (uint8_t *) calloc(1, file_get_size(ef_minpin));
            memcpy(tmpf, file_get_data(ef_minpin), file_get_size(ef_minpin));
            tmpf[1] = 0;
            file_put_data(ef_minpin, tmpf, file_get_size(ef_minpin));
            free(tmpf);
        }
        low_flash_available();
        resetPinUvAuthToken();
        resetPersistentPinUvAuthToken();
        needs_power_cycle = false;
        goto err; // No return
    }
    else if (subcommand == 0x9 || subcommand == 0x5) { //getPinUvAuthTokenUsingPinWithPermissions
        if (kax.present == false || kay.present == false || pinUvAuthProtocol == 0 || alg == 0 ||
            pinHashEnc.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        /* pinHashEnc is decrypted into a 64 byte stack buffer below. */
        if (pinHashEnc.len != 16 + (pinUvAuthProtocol == 2 ? IV_SIZE : 0)) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (subcommand == 0x5 && (permissions != 0 || rpId.present == true)) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (subcommand == 0x9) {
            if (permissions == 0) {
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            if ((permissions & CTAP_PERMISSION_BE)) { // Not supported yet
                CBOR_ERROR(CTAP2_ERR_UNAUTHORIZED_PERMISSION);
            }
            if ((permissions & CTAP_PERMISSION_PCMR) && permissions != CTAP_PERMISSION_PCMR) {
                CBOR_ERROR(CTAP2_ERR_UNAUTHORIZED_PERMISSION);
            }
        }
        if (!file_has_data(ef_pin)) {
            CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
        }
        if (*file_get_data(ef_pin) == 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (needs_power_cycle) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
        }
        uint8_t sharedSecret[64];
        int ret = ecdh((uint8_t)pinUvAuthProtocol, &hkey.ctx.mbed_ecdh.Qp, sharedSecret);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t pin_data[35] = { 0 }, retries = 0;
        uint16_t pin_size = 0;
        ret = pin_consume_retry(pin_data, &pin_size, &retries);
        if (ret != CTAP2_OK) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(ret);
        }
        uint8_t paddedNewPin[64], poff = ((uint8_t)pinUvAuthProtocol - 1) * IV_SIZE;
        ret = decrypt((uint8_t)pinUvAuthProtocol, sharedSecret, pinHashEnc.data, (uint16_t)pinHashEnc.len, paddedNewPin);
        if (ret != 0) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint8_t dhash[32], off = 3;
        if (file_get_size(ef_pin) == 34) {
            off = 2;
            double_hash_pin(paddedNewPin, 16, dhash);
        }
        else {
            pin_derive_verifier(paddedNewPin, 16, dhash);
        }
        if (ct_memcmp(dhash, file_get_data(ef_pin) + off, 32) != 0) {
            regenerate();
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            mbedtls_platform_zeroize(dhash, sizeof(dhash));
            if (retries == 0) {
                CBOR_ERROR(CTAP2_ERR_PIN_BLOCKED);
            }
            if (++new_pin_mismatches >= 3) {
                needs_power_cycle = true;
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_BLOCKED);
            }
            else {
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
            }
        }
        mbedtls_platform_zeroize(dhash, sizeof(dhash));

        /* The PIN was right: the retries come back whatever follows. */
        pin_data[0] = MAX_PIN_RETRIES;
        new_pin_mismatches = 0;
        if (off == 2) {
            /* Legacy PIN record: a device key bound to its session is
             * re-sealed first, the record upgraded only once that worked. */
            hash_multi(paddedNewPin, 16, session_pin);
            if (check_keydev_encrypted() != PICOKEY_OK) {
                file_put_data(ef_pin, pin_data, pin_size);
                low_flash_available();
                mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
                mbedtls_platform_zeroize(paddedNewPin, sizeof(paddedNewPin));
                mbedtls_platform_zeroize(pin_data, sizeof(pin_data));
                CBOR_ERROR(CTAP2_ERR_PROCESSING);
            }
            pin_data[2] = 1;      // New format indicator
            pin_derive_verifier(paddedNewPin, 16, pin_data + 3);
            pin_size = sizeof(pin_data);
        }

        pin_derive_session(paddedNewPin, 16, session_pin);
        mbedtls_platform_zeroize(paddedNewPin, sizeof(paddedNewPin));
        file_put_data(ef_pin, pin_data, pin_size);
        mbedtls_platform_zeroize(pin_data, sizeof(pin_data));
        low_flash_available();

        /* A key bound to this PIN's session (format 0x02) is re-sealed; a
         * failure there is not a wrong PIN. A key sealed under a host key
         * is left alone, locked or not. */
        if (check_keydev_encrypted() != PICOKEY_OK) {
            mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
            CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        file_t *ef_minpin = search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
        if (file_has_data(ef_minpin) && file_get_data(ef_minpin)[1] == 1) {
            CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
        }
        uint8_t pinUvAuthToken_enc[32 + IV_SIZE], *pdata = NULL;
        if (permissions & CTAP_PERMISSION_PCMR) {
            ppaut.permissions = CTAP_PERMISSION_PCMR;
            pdata = ppaut.data;
        }
        else {
            resetPinUvAuthToken();
            beginUsingPinUvAuthToken(false);
            if (subcommand == 0x05) {
                permissions = CTAP_PERMISSION_MC | CTAP_PERMISSION_GA;
            }
            paut.permissions = (uint8_t)permissions;
            if (rpId.present == true) {
                mbedtls_sha256((uint8_t *) rpId.data, rpId.len, paut.rp_id_hash, 0);
                paut.has_rp_id = true;
            }
            else {
                paut.has_rp_id = false;
            }
            pdata = paut.data;
        }
        encrypt((uint8_t)pinUvAuthProtocol, sharedSecret, pdata, 32, pinUvAuthToken_enc);
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, pinUvAuthToken_enc, 32 + poff));
        needs_power_cycle = false;
    }
    else {
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(newPinEnc);
    CBOR_FREE_BYTE_STRING(pinHashEnc);
    CBOR_FREE_BYTE_STRING(kax);
    CBOR_FREE_BYTE_STRING(kay);
    CBOR_FREE_BYTE_STRING(rpId);
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    res_APDU_size = (uint16_t)resp_size;
    return 0;
}
