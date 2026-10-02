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
#include "apdu.h"
#include "ctap.h"
#include "random.h"
#include "files.h"
#include "credential.h"

/* A CTAP2 credential ID used as a U2F key handle: only a P-256 credential
 * that does not demand user verification can sign a U2F assertion (whose
 * signed data is a WebAuthn authenticatorData || clientDataHash). */
static int u2f_ctap2_credential_allowed(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *app_id) {
    Credential cred = { 0 };
    int ret = credential_load(cred_id, cred_id_len, app_id, &cred);
    bool ok = ret == 0 && cred.curve == FIDO2_CURVE_P256 &&
              !(cred.extensions.present && cred.extensions.credProtect == CRED_PROT_UV_REQUIRED);
    credential_free(&cred);
    return ok ? 0 : -1;
}

int cmd_authenticate() {
    CTAP_AUTHENTICATE_REQ *req = (CTAP_AUTHENTICATE_REQ *) apdu.data;
    CTAP_AUTHENTICATE_RESP *resp = (CTAP_AUTHENTICATE_RESP *) res_APDU;
    //if (scan_files_fido(true) != PICOKEY_OK)
    //    return SW_EXEC_ERROR();
    if (P1(apdu) != CTAP_AUTH_ENFORCE && P1(apdu) != CTAP_AUTH_CHECK_ONLY && P1(apdu) != CTAP_AUTH_DONT_ENFORCE) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc < CTAP_CHAL_SIZE + CTAP_APPID_SIZE + 1 + 1) {
        return SW_WRONG_LENGTH();
    }
    /* The key handle is exactly what was received: no byte of it may come
     * from whatever an earlier message left in the buffer. */
    if (apdu.nc != CTAP_CHAL_SIZE + CTAP_APPID_SIZE + 1 + req->keyHandleLen) {
        return SW_WRONG_LENGTH();
    }
    if (req->keyHandleLen < KEY_HANDLE_LEN) {
        return SW_INCORRECT_PARAMS();
    }
    /* no key from a root key that is not in use (HID and CCID) */
    if (!fido_keystore_ok()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }

    /* The key handle is checked before any presence is asked for: a
     * foreign one is refused at once (U2F: SW_WRONG_DATA, 6A80). */
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    int ret = 0;
    uint8_t *tmp_kh = (uint8_t *) calloc(1, req->keyHandleLen);
    if (tmp_kh == NULL) {
        return SW_EXEC_ERROR();
    }
    memcpy(tmp_kh, req->keyHandle, req->keyHandleLen);
    if (credential_verify(tmp_kh, req->keyHandleLen, req->appId, false) == 0) {
        if (u2f_ctap2_credential_allowed(req->keyHandle, req->keyHandleLen, req->appId) != 0) {
            mbedtls_platform_zeroize(tmp_kh, req->keyHandleLen);
            free(tmp_kh);
            return SW_INCORRECT_PARAMS();
        }
        ret = fido_load_key(FIDO2_CURVE_P256, req->keyHandle, &key);
    }
    else {
        ret = derive_key(req->appId, false, req->keyHandle, MBEDTLS_ECP_DP_SECP256R1, &key);
        if (ret != PICOKEY_OK || verify_key(req->appId, req->keyHandle, &key) != 0) {
            mbedtls_ecp_keypair_free(&key);
            free(tmp_kh);
            return ret != PICOKEY_OK ? SW_EXEC_ERROR() : SW_INCORRECT_PARAMS();
        }
    }
    /* holds the decrypted CTAP2 credential (user entity, credBlob) */
    mbedtls_platform_zeroize(tmp_kh, req->keyHandleLen);
    free(tmp_kh);
    if (ret != PICOKEY_OK) {
        mbedtls_ecp_keypair_free(&key);
        return SW_EXEC_ERROR();
    }
    if (P1(apdu) == CTAP_AUTH_CHECK_ONLY) {
        mbedtls_ecp_keypair_free(&key);
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (P1(apdu) == CTAP_AUTH_ENFORCE && fido_wait_everyday_presence() == true) {
        mbedtls_ecp_keypair_free(&key);
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    resp->flags = 0;
    resp->flags |= P1(apdu) == CTAP_AUTH_ENFORCE ? CTAP_AUTH_FLAG_TUP : 0x0;
    uint32_t ctr = 0;
    if (fido_next_sign_counter(&ctr) != PICOKEY_OK) {
        mbedtls_ecp_keypair_free(&key);
        return SW_EXEC_ERROR();
    }
    put_uint32_t_be(ctr, resp->ctr);
    uint8_t hash[32], sig_base[CTAP_APPID_SIZE + 1 + 4 + CTAP_CHAL_SIZE];
    memcpy(sig_base, req->appId, CTAP_APPID_SIZE);
    memcpy(sig_base + CTAP_APPID_SIZE, &resp->flags, sizeof(uint8_t));
    memcpy(sig_base + CTAP_APPID_SIZE + 1, resp->ctr, 4);
    memcpy(sig_base + CTAP_APPID_SIZE + 1 + 4, req->chal, CTAP_CHAL_SIZE);
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), sig_base, sizeof(sig_base), hash);
    if (ret != 0) {
        mbedtls_ecp_keypair_free(&key);
        return SW_EXEC_ERROR();
    }
    size_t olen = 0;
    ret = mbedtls_ecdsa_write_signature(&key, MBEDTLS_MD_SHA256, hash, 32, (uint8_t *) resp->sig, CTAP_MAX_EC_SIG_SIZE, &olen, random_gen, NULL);
    mbedtls_ecp_keypair_free(&key);
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }
    res_APDU_size = 1 + 4 + (uint16_t)olen;
    return SW_OK();
}
