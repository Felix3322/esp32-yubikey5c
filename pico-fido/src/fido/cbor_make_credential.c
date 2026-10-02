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
#include "cbor_make_credential.h"
#include "ctap2_cbor.h"
#include "hid/ctap_hid.h"
#include "fido.h"
#include "ctap.h"
#include "files.h"
#include "apdu.h"
#include "credential.h"
#include "mbedtls/sha256.h"
#include "random.h"
#include "crypto_utils.h"

int cbor_make_credential(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    CborByteString clientDataHash = { 0 }, pinUvAuthParam = { 0 };
    PublicKeyCredentialRpEntity rp = { 0 };
    PublicKeyCredentialUserEntity user = { 0 };
    PublicKeyCredentialParameters pubKeyCredParams[MAX_CREDENTIAL_COUNT_IN_LIST] = { 0 };
    size_t pubKeyCredParams_len = 0;
    PublicKeyCredentialDescriptor excludeList[MAX_CREDENTIAL_COUNT_IN_LIST] = { 0 };
    size_t excludeList_len = 0;
    CredOptions options = { 0 };
    uint64_t pinUvAuthProtocol = 0, enterpriseAttestation = 0, hmacSecretPinUvAuthProtocol = 1;
    int64_t kty = 2, hmac_alg = 0, crv = 0;
    CborByteString kax = { 0 }, kay = { 0 }, salt_enc = { 0 }, salt_auth = { 0 };
    bool hmac_secret_mc = false;
    uint8_t *aut_data = NULL;
    size_t resp_size = 0;
    CredExtensions extensions = { 0 };
    fido_cred_key_t ekey;               /* wiped on every way out */
    fido_cred_key_init(&ekey);
    //options.present = true;
    //options.up = ptrue;
    options.uv = pfalse;
    //options.rk = pfalse;

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 4 && val_c != val_u) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (val_u < val_c) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        val_c = val_u + 1;
        if (val_u == 0x01) { // clientDataHash
            CBOR_FIELD_GET_BYTES(clientDataHash, 1);
        }
        else if (val_u == 0x02) { // rp
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_TEXT(2, "id", rp.id);
                CBOR_FIELD_KEY_TEXT_VAL_TEXT(2, "name", rp.parent.name);
                CBOR_ADVANCE(2); /* e.g. the deprecated "icon" member */
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x03) { // user
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_BYTES(2, "id", user.id);
                CBOR_FIELD_KEY_TEXT_VAL_TEXT(2, "name", user.parent.name);
                CBOR_FIELD_KEY_TEXT_VAL_TEXT(2, "displayName", user.displayName);
                CBOR_ADVANCE(2);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x04) { // pubKeyCredParams
            CBOR_PARSE_ARRAY_START(_f1, 2)
            {
                /* The list is controlled by the relying party: keep the first
                 * MAX_CREDENTIAL_COUNT_IN_LIST entries, only validate the rest. */
                PublicKeyCredentialParameters skip = { 0 };
                PublicKeyCredentialParameters *pk = pubKeyCredParams_len < MAX_CREDENTIAL_COUNT_IN_LIST ? &pubKeyCredParams[pubKeyCredParams_len] : &skip;
                CBOR_PARSE_MAP_START(_f2, 3)
                {
                    CBOR_FIELD_GET_KEY_TEXT(3);
                    CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "type", pk->type);
                    CBOR_FIELD_KEY_TEXT_VAL_INT(3, "alg", pk->alg);
                    CBOR_ADVANCE(3);
                }
                CBOR_PARSE_MAP_END(_f2, 3);
                if (pk == &skip) {
                    CBOR_FREE_BYTE_STRING(skip.type);
                }
                else {
                    pubKeyCredParams_len++;
                }
            }
            CBOR_PARSE_ARRAY_END(_f1, 2);
        }
        else if (val_u == 0x05) { // excludeList
            CBOR_PARSE_ARRAY_START(_f1, 2)
            {
                if (excludeList_len >= MAX_CREDENTIAL_COUNT_IN_LIST) {
                    CBOR_ERROR(CTAP2_ERR_LIMIT_EXCEEDED);
                }
                CBOR_CHECK(cbor_parse_cred_descriptor(&_f2, &excludeList[excludeList_len]));
                excludeList_len++;
            }
            CBOR_PARSE_ARRAY_END(_f1, 2);
        }
        else if (val_u == 0x06) { // extensions
            extensions.present = true;
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_KEY_TEXT(2);
                if (strcmp(_fd2, "hmac-secret-mc") == 0) {
                    hmac_secret_mc = true;
                    uint64_t ukey = 0;
                    CBOR_PARSE_MAP_START(_f2, 3)
                    {
                        CBOR_FIELD_GET_UINT(ukey, 3);
                        if (ukey == 0x01) {
                            CBOR_CHECK(COSE_read_key(&_f3, &kty, &hmac_alg, &crv, &kax, &kay));
                        }
                        else if (ukey == 0x02) {
                            CBOR_FIELD_GET_BYTES(salt_enc, 3);
                        }
                        else if (ukey == 0x03) {
                            CBOR_FIELD_GET_BYTES(salt_auth, 3);
                        }
                        else if (ukey == 0x04) {
                            CBOR_FIELD_GET_UINT(hmacSecretPinUvAuthProtocol, 3);
                        }
                        else {
                            CBOR_ADVANCE(3);
                        }
                    }
                    CBOR_PARSE_MAP_END(_f2, 3);
                    continue;
                }
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "hmac-secret", extensions.hmac_secret);
                CBOR_FIELD_KEY_TEXT_VAL_UINT(2, "credProtect", extensions.credProtect);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "minPinLength", extensions.minPinLength);
                CBOR_FIELD_KEY_TEXT_VAL_BYTES(2, "credBlob", extensions.credBlob);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "largeBlobKey", extensions.largeBlobKey);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "thirdPartyPayment", extensions.thirdPartyPayment);
                /* "pinComplexityPolicy" is not supported (no policy is
                 * enforced): ignored like any unknown extension. */
                CBOR_ADVANCE(2);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x07) { // options
            options.present = true;
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "rk", options.rk);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "up", options.up);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "uv", options.uv);
                CBOR_ADVANCE(2);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x08) { // pinUvAuthParam
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
        else if (val_u == 0x09) { // pinUvAuthProtocol
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x0A) { // enterpriseAttestation
            CBOR_FIELD_GET_UINT(enterpriseAttestation, 1);
        }
        else { // e.g. attestationFormatsPreference (0x0B, CTAP 2.2)
            CBOR_ADVANCE(1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    if (!clientDataHash.present || !rp.id.present || !user.id.present) {
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    }
    if (clientDataHash.len != 32 || user.id.len == 0 || user.id.len > 64) {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }
    if (hmac_secret_mc) {
        /* The salts are decrypted into fixed buffers below. */
        size_t poff = (hmacSecretPinUvAuthProtocol == 2) ? IV_SIZE : 0;
        if (hmacSecretPinUvAuthProtocol != 1 && hmacSecretPinUvAuthProtocol != 2) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (!kax.present || !kay.present || !salt_enc.present || !salt_auth.present) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if ((salt_enc.len != 32 + poff && salt_enc.len != 64 + poff) ||
            salt_auth.len != (hmacSecretPinUvAuthProtocol == 1 ? 16 : 32)) {
            CBOR_ERROR(CTAP1_ERR_INVALID_LEN);
        }
    }

    uint8_t flags = FIDO2_AUT_FLAG_AT;
    uint8_t rp_id_hash[32] = {0};
    mbedtls_sha256((uint8_t *) rp.id.data, rp.id.len, rp_id_hash, 0);

    if (pinUvAuthParam.present == true) {
        if (pinUvAuthParam.len == 0 || pinUvAuthParam.data == NULL) {
            if (check_user_presence() == false) {
                CBOR_ERROR(fido_up_error());
            }
            if (!file_has_data(ef_pin)) {
                CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
            }
            else {
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
            }
        }
        else {
            if (pinUvAuthProtocol == 0) {
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            }
            if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
        }
    }

    int curve = -1, alg = 0;
    if (pubKeyCredParams_len == 0) {
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    }

    for (unsigned int i = 0; i < pubKeyCredParams_len; i++) {
        if (pubKeyCredParams[i].type.present == false) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        if (pubKeyCredParams[i].alg == 0) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        if (strcmp(pubKeyCredParams[i].type.data, "public-key") != 0) {
            continue; /* unknown credential types are ignored (CTAP 2.1, 6.1.2) */
        }
        if (pubKeyCredParams[i].alg == FIDO2_ALG_ES256 || pubKeyCredParams[i].alg == FIDO2_ALG_ESP256) {
            if (curve <= 0) {
                curve = FIDO2_CURVE_P256;
            }
        }
        else if (pubKeyCredParams[i].alg == FIDO2_ALG_ES384 || pubKeyCredParams[i].alg == FIDO2_ALG_ESP384) {
            if (curve <= 0) {
                curve = FIDO2_CURVE_P384;
            }
        }
        else if (pubKeyCredParams[i].alg == FIDO2_ALG_ES512 || pubKeyCredParams[i].alg == FIDO2_ALG_ESP512) {
            if (curve <= 0) {
                curve = FIDO2_CURVE_P521;
            }
        }
        /* Brainpool (ESB256/384/512) is not accepted: there is no COSE
         * curve mapping for it, so the public key could not be encoded. */
        else if (pubKeyCredParams[i].alg == FIDO2_ALG_ES256K
#ifndef ENABLE_EMULATION
             && (phy_data.enabled_curves & PHY_CURVE_SECP256K1)
#endif
            ) {
            if (curve <= 0) {
                curve = FIDO2_CURVE_P256K1;
            }
        }
#ifdef FIDO_HAVE_ED25519
        else if (pubKeyCredParams[i].alg == FIDO2_ALG_EDDSA || pubKeyCredParams[i].alg == FIDO2_ALG_ED25519) {
            if (curve <= 0) {
                curve = FIDO2_CURVE_ED25519;
            }
        }
#endif
#ifdef MBEDTLS_EDDSA_C
        else if (pubKeyCredParams[i].alg == FIDO2_ALG_ED448) {
            if (curve <= 0) {
                curve = FIDO2_CURVE_ED448;
            }
        }
#endif
        else if (pubKeyCredParams[i].alg <= FIDO2_ALG_RS256 && pubKeyCredParams[i].alg >= FIDO2_ALG_RS512) {
            // pass
        }
        //else {
        //    CBOR_ERROR(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        //}
        if (curve > 0 && alg == 0) {
            alg = (int)pubKeyCredParams[i].alg;
        }
    }
    if (curve <= 0) {
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_ALGORITHM);
    }

    if (options.present) {
        if (options.uv == ptrue) { //5.3
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }
        if (options.up == pfalse) { //5.6: "up" may only be true
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }
        //5.7: absent "up" means true
    }
    if (pinUvAuthParam.present == false && options.uv == pfalse && file_has_data(ef_pin)) { //8.1
        CBOR_ERROR(CTAP2_ERR_PUAT_REQUIRED);
    }
    if (enterpriseAttestation > 0) {
        if (!(get_opts() & FIDO2_OPT_EA)) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if (enterpriseAttestation != 1 && enterpriseAttestation != 2) { //9.2.1
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }
        //Unfinished. See 6.1.2.9
    }
    if (pinUvAuthParam.present == true) { //11.1
        int ret = verify((uint8_t)pinUvAuthProtocol, paut.data, clientDataHash.data, (uint16_t)clientDataHash.len, pinUvAuthParam.data, pinUvAuthParam.len);
        if (ret != CborNoError) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (!(paut.permissions & CTAP_PERMISSION_MC)) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (paut.has_rp_id == true && memcmp(paut.rp_id_hash, rp_id_hash, 32) != 0) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (getUserVerifiedFlagValue() == false) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        flags |= FIDO2_AUT_FLAG_UV;
        if (paut.has_rp_id == false) {
            memcpy(paut.rp_id_hash, rp_id_hash, 32);
            paut.has_rp_id = true;
        }
    }

    for (size_t e = 0; e < excludeList_len; e++) { //12.1
        if (excludeList[e].type.present == false || excludeList[e].id.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (strcmp(excludeList[e].type.data, (char *)"public-key") != 0) {
            continue;
        }
        Credential ecred = {0};
        if (credential_is_resident(excludeList[e].id.data, excludeList[e].id.len)) {
            for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
                file_t *ef_cred = search_dynamic_file((uint16_t)(EF_CRED + i));
                resident_record_t rec;
                if (credential_resident_parse(ef_cred, &rec) != 0 || memcmp(rec.rp_id_hash, rp_id_hash, 32) != 0) {
                    continue;
                }
                if (credential_resident_matches(&rec, excludeList[e].id.data, excludeList[e].id.len)) {
                    if (credential_load_resident(ef_cred, rp_id_hash, &ecred) == 0 && (ecred.extensions.credProtect != CRED_PROT_UV_REQUIRED || (flags & FIDO2_AUT_FLAG_UV))) {
                        credential_free(&ecred);
                        CBOR_ERROR(CTAP2_ERR_CREDENTIAL_EXCLUDED);
                    }
                }
            }
        }
        else {
            if (credential_load(excludeList[e].id.data, excludeList[e].id.len, rp_id_hash, &ecred) == 0 && (ecred.extensions.credProtect != CRED_PROT_UV_REQUIRED || (flags & FIDO2_AUT_FLAG_UV))) {
                credential_free(&ecred);
                CBOR_ERROR(CTAP2_ERR_CREDENTIAL_EXCLUDED);
            }
        }
        credential_free(&ecred);
    }

    if (extensions.largeBlobKey == pfalse ||
        (extensions.largeBlobKey == ptrue && options.rk != ptrue)) {
        CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
    }

    if (hmac_secret_mc && extensions.hmac_secret != ptrue) {
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    }

    /* "up" is always true here (5.6/5.7). Evidence of user interaction is
     * required whether or not a pinUvAuthParam was supplied, and the token
     * is consumed afterwards: its flags and permissions (except lbw) are
     * cleared, so it cannot make or assert anything else without a new
     * PIN entry (CTAP 2.1, 6.1.2 step 14). */
    if (pinUvAuthParam.present == false || getUserPresentFlagValue() == false) {
        if (check_user_presence() == false) {
            CBOR_ERROR(fido_up_error());
        }
    }
    flags |= FIDO2_AUT_FLAG_UP;
    clearUserPresentFlag();
    clearUserVerifiedFlag();
    clearPinUvAuthTokenPermissionsExceptLbw();

    /* Every relying party is treated alike: no per-site behaviour (the old
     * table of known sites forced full attestation for some and flagged
     * others to drop the signature counter). */
    uint8_t cred_id[MAX_CRED_ID_LENGTH] = {0};
    uint16_t cred_id_len = 0;

    CBOR_CHECK(credential_create(&rp.id, &user.id, &user.parent.name, &user.displayName, &options, &extensions, true, alg, curve, cred_id, &cred_id_len));

    /* UV only comes from the pinUvAuthParam verified above (step 11). */
    size_t ext_len = 0;
    uint8_t ext[512] = {0};
    CborEncoder encoder, mapEncoder, mapEncoder2;
    if (extensions.present == true) {
        cbor_encoder_init(&encoder, ext, sizeof(ext), 0);
        int l = 0;
        uint8_t minPinLen = 0;
        if (extensions.hmac_secret == ptrue) {
            l++;
        }
        if (extensions.credProtect != 0) {
            l++;
        }
        if (extensions.minPinLength == ptrue) {
            file_t *ef_minpin = search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
            if (file_has_data(ef_minpin)) {
                uint8_t *minpin_data = file_get_data(ef_minpin);
                for (int o = 2; o < file_get_size(ef_minpin); o += 32) {
                    if (memcmp(minpin_data + o, rp_id_hash, 32) == 0) {
                        minPinLen = minpin_data[0];
                        if (minPinLen > 0) {
                            l++;
                        }
                        break;
                    }
                }
            }
        }
        if (extensions.credBlob.present == true) {
            l++;
        }
        if (hmac_secret_mc) {
            l++;
        }
        if (l > 0) {
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, l));
            if (extensions.credBlob.present == true) {
                /* stored up to maxCredBlobLength (getInfo 0x0F) included */
                CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, "credBlob"));
                CBOR_CHECK(cbor_encode_boolean(&mapEncoder, extensions.credBlob.len <= MAX_CREDBLOB_LENGTH));
            }
            if (extensions.credProtect != 0) {
                CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, "credProtect"));
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, extensions.credProtect));
            }
            if (extensions.hmac_secret == ptrue) {
                CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, "hmac-secret"));
                CBOR_CHECK(cbor_encode_boolean(&mapEncoder, true));
            }
            if (minPinLen > 0) {
                CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, "minPinLength"));
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, minPinLen));
            }
            if (hmac_secret_mc) {
                CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, "hmac-secret-mc"));

                uint8_t sharedSecret[64] = {0};
                mbedtls_ecp_point Qp;
                mbedtls_ecp_point_init(&Qp);
                mbedtls_mpi_lset(&Qp.Z, 1);
                if (mbedtls_mpi_read_binary(&Qp.X, kax.data, kax.len) != 0) {
                    mbedtls_ecp_point_free(&Qp);
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }
                if (mbedtls_mpi_read_binary(&Qp.Y, kay.data, kay.len) != 0) {
                    mbedtls_ecp_point_free(&Qp);
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }
                int ret = ecdh((uint8_t)hmacSecretPinUvAuthProtocol, &Qp, sharedSecret);
                mbedtls_ecp_point_free(&Qp);
                if (ret != 0) {
                    mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }
                if (verify((uint8_t)hmacSecretPinUvAuthProtocol, sharedSecret, salt_enc.data, (uint16_t)salt_enc.len, salt_auth.data, salt_auth.len) != 0) {
                    mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
                    CBOR_ERROR(CTAP2_ERR_EXTENSION_FIRST);
                }
                uint8_t salt_dec[64] = {0}, poff = ((uint8_t)hmacSecretPinUvAuthProtocol - 1) * IV_SIZE;
                ret = decrypt((uint8_t)hmacSecretPinUvAuthProtocol, sharedSecret, salt_enc.data, (uint16_t)salt_enc.len, salt_dec);
                if (ret != 0) {
                    mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
                    mbedtls_platform_zeroize(salt_dec, sizeof(salt_dec));
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }
                uint8_t cred_random[64] = {0}, *crd = NULL;
                ret = credential_derive_hmac_key(cred_id, cred_id_len, cred_random);
                if (ret != 0) {
                    mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
                    mbedtls_platform_zeroize(salt_dec, sizeof(salt_dec));
                    mbedtls_platform_zeroize(cred_random, sizeof(cred_random));
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }
                /* the same CredRandom getAssertion uses for this UV state */
                if (flags & FIDO2_AUT_FLAG_UV) {
                    crd = cred_random + 32;
                }
                else {
                    crd = cred_random;
                }
                uint8_t out1[64] = {0}, hmac_res[80] = {0};
                mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), crd, 32, salt_dec, 32, out1);
                if ((uint8_t)salt_enc.len == 64 + poff) {
                    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), crd, 32, salt_dec + 32, 32, out1 + 32);
                }
                encrypt((uint8_t)hmacSecretPinUvAuthProtocol, sharedSecret, out1, (uint16_t)(salt_enc.len - poff), hmac_res);
                mbedtls_platform_zeroize(sharedSecret, sizeof(sharedSecret));
                mbedtls_platform_zeroize(salt_dec, sizeof(salt_dec));
                mbedtls_platform_zeroize(cred_random, sizeof(cred_random));
                mbedtls_platform_zeroize(out1, sizeof(out1));
                CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, hmac_res, salt_enc.len));
            }

            CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
            ext_len = cbor_encoder_get_buffer_size(&encoder, ext);
            flags |= FIDO2_AUT_FLAG_ED;
        }
    }
    /* fido_cred_key_load() also checks that the build has the curve */
    int ret = fido_cred_key_load(&ekey, curve, cred_id);
    if (ret != 0) {
        fido_cred_key_free(&ekey);
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }
    size_t olen = 0;
    uint32_t ctr = 0;
    if (fido_next_sign_counter(&ctr) != PICOKEY_OK) {
        fido_cred_key_free(&ekey);
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }
    uint8_t cbor_buf[1024] = {0};
    cbor_encoder_init(&encoder, cbor_buf, sizeof(cbor_buf), 0);
    error = COSE_cred_key(&ekey, alg, &encoder, &mapEncoder);
    if (error != CborNoError) {
        fido_cred_key_free(&ekey);
        goto err;
    }
    size_t rs = cbor_encoder_get_buffer_size(&encoder, cbor_buf);

    size_t aut_data_len = 32 + 1 + 4 + (16 + 2 + (options.rk == ptrue ? CRED_RESIDENT_LEN : cred_id_len) + rs) + ext_len;
    aut_data = (uint8_t *) calloc(1, aut_data_len + clientDataHash.len);
    uint8_t *pa = aut_data;
    memcpy(pa, rp_id_hash, 32); pa += 32;
    *pa++ = flags;
    pa += put_uint32_t_be(ctr, pa);
    fido_get_aaguid(pa); pa += 16;
    if (options.rk == ptrue) {
        uint8_t cred_idr[CRED_RESIDENT_LEN] = {0};
        pa += put_uint16_t_be(sizeof(cred_idr), pa);
        credential_new_resident_id(cred_id, cred_id_len, cred_idr);     /* what credential_store() stores */
        memcpy(pa, cred_idr, sizeof(cred_idr)); pa += sizeof(cred_idr);
    }
    else {
        pa += put_uint16_t_be(cred_id_len, pa);
        memcpy(pa, cred_id, cred_id_len); pa += (uint16_t)cred_id_len;
    }
    memcpy(pa, cbor_buf, rs); pa += (uint16_t)rs;
    memcpy(pa, ext, ext_len); pa += (uint16_t)ext_len;
    if ((size_t)(pa - aut_data) != aut_data_len) {
        fido_cred_key_free(&ekey);
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }

    memcpy(pa, clientDataHash.data, clientDataHash.len);
    uint8_t sig[MBEDTLS_ECDSA_MAX_LEN] = {0};

    /* Self attestation: the credential key signs (packed, "alg" is the
     * credential's; EdDSA signs authData || clientDataHash as is). A profile
     * can be exported and cloned, so a device key certificate would vouch
     * for a single device that may exist several times. Enterprise
     * attestation, which the user has to enable, is the only exception. */
    bool self_attestation = true;
    if (enterpriseAttestation == 2) {
        fido_cred_key_free(&ekey);
        fido_cred_key_init(&ekey);
        uint8_t key[32] = {0};
        if (load_keydev(key) != 0) {
            CBOR_ERROR(CTAP1_ERR_OTHER);
        }
        ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &ekey.ec, key, 32);
        mbedtls_platform_zeroize(key, sizeof(key));
        if (ret != 0) {
            fido_cred_key_free(&ekey);
            CBOR_ERROR(CTAP1_ERR_OTHER);
        }
        /* The attestation key is P-256 (ES256, SHA-256), whatever the
         * credential's algorithm. */
        ekey.curve = FIDO2_CURVE_P256;
        self_attestation = false;
    }
    ret = fido_cred_key_sign(&ekey, aut_data, aut_data_len + clientDataHash.len, sig, sizeof(sig), &olen);
    fido_cred_key_free(&ekey);
    if (ret != 0) {
        CBOR_ERROR(CTAP2_ERR_PROCESSING);
    }

    uint8_t largeBlobKey[32] = {0};
    if (extensions.largeBlobKey == ptrue && options.rk == ptrue) {
        ret = credential_derive_large_blob_key(cred_id, cred_id_len, largeBlobKey);
        if (ret != 0) {
            CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
    }

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);
    uint8_t lparams = 3;
    if (enterpriseAttestation == 2) {
        lparams++;
    }
    if (extensions.largeBlobKey == ptrue && options.rk == ptrue) {
        lparams++;
    }
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, lparams));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
    CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, "packed"));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, aut_data, aut_data_len));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));

    /* x5c only with enterprise attestation (signed by the device key). The
     * Nitrokey HID mode (is_nk) used to add the device certificate to a
     * self attestation too, which then did not verify; is_nk is also a HID
     * state that could still be set when a command comes over CCID. */
    CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, self_attestation == false ? 3 : 2));
    CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "alg"));
    CBOR_CHECK(cbor_encode_negative_int(&mapEncoder2, self_attestation ? -alg : -FIDO2_ALG_ES256));
    CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "sig"));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, sig, olen));
    if (self_attestation == false) {
        CborEncoder arrEncoder;
        file_t *ef_cert = NULL;
        if (enterpriseAttestation == 2) {
            ef_cert = search_by_fid(EF_EE_DEV_EA, NULL, SPECIFY_EF);
        }
        if (!file_has_data(ef_cert)) {
            ef_cert = ef_certdev;
            if (!file_has_data(ef_cert) && fido_certdev_generate(false) != PICOKEY_OK) {
                CBOR_ERROR(CTAP1_ERR_OTHER);
            }
        }
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "x5c"));
        CBOR_CHECK(cbor_encoder_create_array(&mapEncoder2, &arrEncoder, 1));
        CBOR_CHECK(cbor_encode_byte_string(&arrEncoder, file_get_data(ef_cert), file_get_size(ef_cert)));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder2, &arrEncoder));
    }
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));

    if (enterpriseAttestation == 2) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encode_boolean(&mapEncoder, true));
    }

    if (extensions.largeBlobKey == ptrue && options.rk == ptrue) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, largeBlobKey, sizeof(largeBlobKey)));
    }
    mbedtls_platform_zeroize(largeBlobKey, sizeof(largeBlobKey));
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);

    if (options.rk == ptrue) {
        if (credential_store(cred_id, cred_id_len, rp_id_hash) != 0) {
            CBOR_ERROR(CTAP2_ERR_KEY_STORE_FULL);
        }
    }
    low_flash_available();
err:
    fido_cred_key_free(&ekey);
    CBOR_FREE_BYTE_STRING(clientDataHash);
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(rp.id);
    CBOR_FREE_BYTE_STRING(rp.parent.name);
    CBOR_FREE_BYTE_STRING(user.id);
    CBOR_FREE_BYTE_STRING(user.displayName);
    CBOR_FREE_BYTE_STRING(user.parent.name);
    CBOR_FREE_BYTE_STRING(kax);
    CBOR_FREE_BYTE_STRING(kay);
    CBOR_FREE_BYTE_STRING(salt_enc);
    CBOR_FREE_BYTE_STRING(salt_auth);
    if (extensions.present == true) {
        CBOR_FREE_BYTE_STRING(extensions.credBlob);
    }
    for (size_t n = 0; n < MAX_CREDENTIAL_COUNT_IN_LIST; n++) {
        CBOR_FREE_BYTE_STRING(pubKeyCredParams[n].type);
    }

    for (size_t m = 0; m < MAX_CREDENTIAL_COUNT_IN_LIST; m++) {
        CBOR_FREE_BYTE_STRING(excludeList[m].type);
        CBOR_FREE_BYTE_STRING(excludeList[m].id);
        for (size_t n = 0; n < excludeList[m].transports_len; n++) {
            CBOR_FREE_BYTE_STRING(excludeList[m].transports[n]);
        }
    }
    if (aut_data) {
        free(aut_data);
    }
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    res_APDU_size = (uint16_t)resp_size;
    return 0;
}
