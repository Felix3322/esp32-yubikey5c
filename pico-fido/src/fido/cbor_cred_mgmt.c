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
#include "ctap.h"
#include "hid/ctap_hid.h"
#include "cbor_make_credential.h"
#include "files.h"
#include "apdu.h"
#include "credential.h"

/* Enumeration state (CTAP 2.1, 6.8.3 and 6.8.5). It is only valid while the
 * platform keeps issuing credential management commands; any other command
 * drops it through cred_mgmt_reset_state(). */
static uint16_t rp_counter = 1;
static uint16_t rp_total = 0;
static uint16_t cred_counter = 1;
static uint16_t cred_total = 0;
static uint16_t cred_next_slot = 0;
static uint8_t enum_rp_id_hash[32];
static bool enum_rp_valid = false;

/* RP and credential enumeration are independent so a platform can walk
 * them depth first (begin RPs, then the credentials of each RP in turn). */
static void cred_mgmt_reset_rps(void) {
    rp_counter = 1;
    rp_total = 0;
}

static void cred_mgmt_reset_creds(void) {
    cred_counter = 1;
    cred_total = 0;
    cred_next_slot = 0;
    enum_rp_valid = false;
    memset(enum_rp_id_hash, 0, sizeof(enum_rp_id_hash));
}

void cred_mgmt_reset_state(void) {
    cred_mgmt_reset_rps();
    cred_mgmt_reset_creds();
}

/* Validates pinUvAuthParam over subCommand || subCommandParams with the
 * pinUvAuthToken, or with the persistent token for read-only subcommands.
 * The CTAP 2.1-PRE command byte 0x41 gets exactly the same checks as 0x0A:
 * it used to skip the cm permission and the RP binding, so any token (mc/ga
 * only, bound to another RP, or with its permissions already cleared) could
 * enumerate and delete every credential. */
static int cred_mgmt_check_auth(uint8_t protocol, const uint8_t *msg, uint16_t msg_len,
                                const CborByteString *pinUvAuthParam, bool read_only,
                                bool *via_ppaut) {
    *via_ppaut = false;
    if (read_only && verify(protocol, ppaut.data, msg, msg_len, pinUvAuthParam->data, pinUvAuthParam->len) == 0) {
        if (!(ppaut.permissions & CTAP_PERMISSION_PCMR)) {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        *via_ppaut = true;
        return 0;
    }
    if (verify(protocol, paut.data, msg, msg_len, pinUvAuthParam->data, pinUvAuthParam->len) != 0) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!(paut.permissions & CTAP_PERMISSION_CM)) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    return 0;
}

/* A token bound to an RP ID may only reach the credentials of that RP. */
static bool cred_mgmt_rp_allowed(bool via_ppaut, const uint8_t *rp_id_hash) {
    if (via_ppaut || paut.has_rp_id == false) {
        return true;
    }
    return memcmp(paut.rp_id_hash, rp_id_hash, 32) == 0;
}

/* How a stored resident record of the enumerated RP is reported. Every
 * record is reported, so the counts of getCredsMetadata, enumerateRPs and
 * enumerateCredentials agree and every record can be deleted:
 *  - REC_FULL: it decrypts and this build can derive its key (the same rule
 *    as getAssertion): user, credential ID, public key, extensions;
 *  - REC_NO_KEY: it decrypts, but its curve is not in this build (e.g. an
 *    Ed25519 credential without EdDSA): no public key (0x08);
 *  - REC_ID_ONLY: it does not decrypt with the device key (made with
 *    another device key, e.g. before a vendor restore; or damaged): its
 *    stored credential ID only, with an empty user entity.
 * getAssertion never uses the last two. */
enum { REC_FULL, REC_NO_KEY, REC_ID_ONLY };

static int cred_mgmt_load(const file_t *ef, Credential *cred) {
    if (credential_load_resident(ef, enum_rp_id_hash, cred) != 0) {
        credential_free(cred);
        memset(cred, 0, sizeof(*cred));
        return REC_ID_ONLY;
    }
    return credential_curve_supported(cred->curve) ? REC_FULL : REC_NO_KEY;
}

static bool cred_mgmt_matches_rp(const file_t *ef) {
    resident_record_t rec;
    return credential_resident_parse(ef, &rec) == 0 && memcmp(rec.rp_id_hash, enum_rp_id_hash, 32) == 0;
}

static file_t *cred_mgmt_find(const CborByteString *id, resident_record_t *rec) {
    for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        file_t *ef = search_dynamic_file((uint16_t)(EF_CRED + i));
        if (credential_resident_parse(ef, rec) != 0) {
            continue;
        }
        if (credential_resident_matches(rec, id->data, id->len)) {
            return ef;
        }
    }
    return NULL;
}

int cbor_cred_mgmt(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    uint64_t subcommand = 0, pinUvAuthProtocol = 0;
    CborByteString pinUvAuthParam = { 0 }, rpIdHash = { 0 };
    PublicKeyCredentialDescriptor credentialId = { 0 };
    PublicKeyCredentialUserEntity user = { 0 };
    bool user_present = false, via_ppaut = false;
    size_t resp_size = 0;
    CborEncoder encoder, mapEncoder, mapEncoder2;
    uint8_t *raw_subpara = NULL;
    size_t raw_subpara_len = 0;
    Credential cred = { 0 };
    fido_cred_key_t key;
    fido_cred_key_init(&key);

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 1 && val_c != val_u) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (val_u < val_c) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(subcommand, 1);
        }
        else if (val_u == 0x02) {
            uint64_t subpara = 0;
            raw_subpara = (uint8_t *) cbor_value_get_next_byte(&_f1);
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_UINT(subpara, 2);
                if (subpara == 0x01) {
                    CBOR_FIELD_GET_BYTES(rpIdHash, 2);
                }
                else if (subpara == 0x02) {
                    if (credentialId.id.present || credentialId.type.present) {
                        CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
                    }
                    CBOR_CHECK(cbor_parse_cred_descriptor(&_f2, &credentialId));
                }
                else if (subpara == 0x03) {
                    if (user_present) {
                        CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
                    }
                    user_present = true;
                    CBOR_PARSE_MAP_START(_f2, 3)
                    {
                        CBOR_FIELD_GET_KEY_TEXT(3);
                        CBOR_FIELD_KEY_TEXT_VAL_BYTES(3, "id", user.id);
                        CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "name", user.parent.name);
                        CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "displayName", user.displayName);
                        CBOR_ADVANCE(3);
                    }
                    CBOR_PARSE_MAP_END(_f2, 3);
                }
                else {
                    CBOR_ADVANCE(2);
                }
            }
            CBOR_PARSE_MAP_END(_f1, 2);
            raw_subpara_len = cbor_value_get_next_byte(&_f1) - raw_subpara;
        }
        else if (val_u == 0x03) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x04) {
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
        else {
            CBOR_ADVANCE(1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    if (subcommand < 0x01 || subcommand > 0x07) {
        CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
    }
    if (subcommand != 0x03 && subcommand != 0x05) {
        if (pinUvAuthParam.present == false) {
            CBOR_ERROR(CTAP2_ERR_PUAT_REQUIRED);
        }
        if (pinUvAuthProtocol == 0) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
    }
    if (rpIdHash.present && rpIdHash.len != 32) {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);
    if (subcommand == 0x01) {
        int ret = cred_mgmt_check_auth((uint8_t)pinUvAuthProtocol, (const uint8_t *) "\x01", 1, &pinUvAuthParam, true, &via_ppaut);
        if (ret != 0) {
            CBOR_ERROR(ret);
        }
        if (!via_ppaut && paut.has_rp_id == true) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        uint16_t existing = 0;
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            if (file_has_data(search_dynamic_file((uint16_t)(EF_CRED + i)))) {
                existing++;
            }
        }
        /* A credential for a new RP takes two file table entries. */
        uint16_t remaining = (uint16_t)(MAX_RESIDENT_CREDENTIALS - existing);
        uint16_t files_free = (uint16_t)(MAX_DYNAMIC_FILES - dynamic_files);
        if (files_free / 2 < remaining) {
            remaining = files_free / 2;
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 2));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, existing));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, remaining));
    }
    else if (subcommand == 0x02 || subcommand == 0x03) {
        file_t *rp_ef = NULL;
        if (subcommand == 0x02) {
            int ret = cred_mgmt_check_auth((uint8_t)pinUvAuthProtocol, (const uint8_t *) "\x02", 1, &pinUvAuthParam, true, &via_ppaut);
            if (ret != 0) {
                CBOR_ERROR(ret);
            }
            if (!via_ppaut && paut.has_rp_id == true) {
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
            }
            cred_mgmt_reset_rps();
        }
        else {
            if (rp_total == 0 || rp_counter > rp_total) {
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }
        }
        uint16_t skip = 0;
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            file_t *tef = search_dynamic_file((uint16_t)(EF_RP + i));
            if (file_has_data(tef) && file_get_size(tef) >= 1 + 32 && *file_get_data(tef) > 0) {
                if (++skip == rp_counter) {
                    if (rp_ef == NULL) {
                        rp_ef = tef;
                    }
                    if (subcommand == 0x03) {
                        break;
                    }
                }
                if (subcommand == 0x02) {
                    rp_total++;
                }
            }
        }
        if (rp_ef == NULL) {
            cred_mgmt_reset_rps();
            CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);
        }
        rp_counter++;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, subcommand == 0x02 ? 3 : 2));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, 1));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "id"));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder2, (char *) file_get_data(rp_ef) + 33,
                                           file_get_size(rp_ef) - 33));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, file_get_data(rp_ef) + 1, 32));
        if (subcommand == 0x02) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, rp_total));
        }
    }
    else if (subcommand == 0x04 || subcommand == 0x05) {
        if (subcommand == 0x04) {
            if (rpIdHash.present == false || raw_subpara == NULL) {
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            }
            *(raw_subpara - 1) = 0x04;
            int ret = cred_mgmt_check_auth((uint8_t)pinUvAuthProtocol, raw_subpara - 1, (uint16_t)(raw_subpara_len + 1), &pinUvAuthParam, true, &via_ppaut);
            if (ret != 0) {
                CBOR_ERROR(ret);
            }
            if (!cred_mgmt_rp_allowed(via_ppaut, rpIdHash.data)) {
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
            }
            /* While the device key is sealed and locked every record would
             * look undecryptable: refused instead of misreported. */
            uint8_t keydev_probe[32];
            int kret = load_keydev(keydev_probe);
            mbedtls_platform_zeroize(keydev_probe, sizeof(keydev_probe));
            if (kret != PICOKEY_OK) {
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }
            cred_mgmt_reset_creds();
            memcpy(enum_rp_id_hash, rpIdHash.data, 32);
            for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
                if (cred_mgmt_matches_rp(search_dynamic_file((uint16_t)(EF_CRED + i)))) {
                    cred_total++;
                }
            }
        }
        else {
            if (!enum_rp_valid || cred_counter > cred_total) {
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }
        }
        /* The next record after the last one returned; nothing else runs
         * between the calls of one enumeration (any other command resets
         * it), so the slot position stays valid. */
        file_t *cred_ef = NULL;
        while (cred_next_slot < MAX_RESIDENT_CREDENTIALS) {
            file_t *tef = search_dynamic_file((uint16_t)(EF_CRED + cred_next_slot));
            cred_next_slot++;
            if (cred_mgmt_matches_rp(tef)) {
                cred_ef = tef;
                break;
            }
        }
        if (cred_ef == NULL) {
            cred_mgmt_reset_creds();
            CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);
        }
        if (subcommand == 0x04) {
            enum_rp_valid = true;
        }

        cred_counter++;
        int kind = cred_mgmt_load(cred_ef, &cred);
        if (kind == REC_FULL && credential_key_load(&cred, enum_rp_id_hash, &key) != 0) {
            kind = REC_NO_KEY;
        }

        uint8_t l = 2;                  /* user, credentialID */
        if (kind == REC_FULL) {
            l++;                        /* publicKey */
        }
        if (kind != REC_ID_ONLY) {
            l++;                        /* thirdPartyPayment */
        }
        if (subcommand == 0x04) {
            l++;
        }
        if (cred.extensions.present == true) {
            if (cred.extensions.credProtect > 0) {
                l++;
            }
            if (cred.extensions.largeBlobKey == ptrue) {
                l++;
            }
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, l));

        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x06));
        l = 0;
        if (cred.userId.present == true) {
            l++;
        }
        if (cred.userName.present == true) {
            l++;
        }
        if (cred.userDisplayName.present == true) {
            l++;
        }
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, l));
        if (cred.userId.present == true) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "id"));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, cred.userId.data, cred.userId.len));
        }
        if (cred.userName.present == true) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "name"));
            CBOR_CHECK(cbor_encode_text_string(&mapEncoder2, cred.userName.data, cred.userName.len));
        }
        if (cred.userDisplayName.present == true) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "displayName"));
            CBOR_CHECK(cbor_encode_text_string(&mapEncoder2, cred.userDisplayName.data, cred.userDisplayName.len));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));

        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, 2));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "id"));
        uint8_t cred_idr[CRED_RESIDENT_LEN] = {0};
        resident_record_t rec;
        if (credential_resident_parse(cred_ef, &rec) != 0) {
            CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        credential_resident_id(&rec, cred_idr);     /* the ID it was created with */
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, cred_idr, sizeof(cred_idr)));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "type"));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "public-key"));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));

        if (kind == REC_FULL) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
            CBOR_CHECK(COSE_cred_key(&key, (int) cred.alg, &mapEncoder, &mapEncoder2));
        }

        if (subcommand == 0x04) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x09));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, cred_total));
        }
        if (cred.extensions.present == true) {
            if (cred.extensions.credProtect > 0) {
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0A));
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, cred.extensions.credProtect));
            }
            if (cred.extensions.largeBlobKey == ptrue) {
                uint8_t largeBlobKey[32];
                int ret = credential_large_blob_key(&cred, enum_rp_id_hash, largeBlobKey);
                if (ret != 0) {
                    mbedtls_platform_zeroize(largeBlobKey, sizeof(largeBlobKey));
                    CBOR_ERROR(CTAP2_ERR_PROCESSING);
                }
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0B));
                CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, largeBlobKey, sizeof(largeBlobKey)));
                mbedtls_platform_zeroize(largeBlobKey, sizeof(largeBlobKey));
            }
        }
        if (kind != REC_ID_ONLY) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0C));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, cred.extensions.present && cred.extensions.thirdPartyPayment == ptrue));
        }
    }
    else if (subcommand == 0x06) {
        if (credentialId.id.present == false || raw_subpara == NULL) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        *(raw_subpara - 1) = 0x06;
        int ret = cred_mgmt_check_auth((uint8_t)pinUvAuthProtocol, raw_subpara - 1, (uint16_t)(raw_subpara_len + 1), &pinUvAuthParam, false, &via_ppaut);
        if (ret != 0) {
            CBOR_ERROR(ret);
        }
        resident_record_t rec;
        file_t *ef = cred_mgmt_find(&credentialId.id, &rec);
        if (ef == NULL) {
            CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);
        }
        /* Copied first: deleting the record scrubs the data rec points to. */
        uint8_t rp_id_hash[32];
        memcpy(rp_id_hash, rec.rp_id_hash, sizeof(rp_id_hash));
        if (!cred_mgmt_rp_allowed(false, rp_id_hash)) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (delete_file(ef) != 0) {
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        for (int j = 0; j < MAX_RESIDENT_CREDENTIALS; j++) {
            file_t *rp_ef = search_dynamic_file((uint16_t)(EF_RP + j));
            if (file_has_data(rp_ef) && file_get_size(rp_ef) >= 1 + 32 && memcmp(file_get_data(rp_ef) + 1, rp_id_hash, 32) == 0) {
                uint16_t rp_size = file_get_size(rp_ef);
                if (*file_get_data(rp_ef) <= 1) {
                    delete_file(rp_ef);
                }
                else {
                    uint8_t *rp_data = (uint8_t *) calloc(1, rp_size);
                    if (rp_data == NULL) {
                        CBOR_ERROR(CTAP2_ERR_PROCESSING);
                    }
                    memcpy(rp_data, file_get_data(rp_ef), rp_size);
                    rp_data[0] -= 1;
                    file_put_data(rp_ef, rp_data, rp_size);
                    free(rp_data);
                }
                break;
            }
        }
        cred_mgmt_reset_state();
        low_flash_available();
        goto err; //no error
    }
    else if (subcommand == 0x07) {
        if (credentialId.id.present == false || user.id.present == false || raw_subpara == NULL) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        *(raw_subpara - 1) = 0x07;
        int ret = cred_mgmt_check_auth((uint8_t)pinUvAuthProtocol, raw_subpara - 1, (uint16_t)(raw_subpara_len + 1), &pinUvAuthParam, false, &via_ppaut);
        if (ret != 0) {
            CBOR_ERROR(ret);
        }
        resident_record_t rec;
        file_t *ef = cred_mgmt_find(&credentialId.id, &rec);
        if (ef == NULL) {
            CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);
        }
        uint8_t rp_id_hash[32];
        memcpy(rp_id_hash, rec.rp_id_hash, sizeof(rp_id_hash));
        if (!cred_mgmt_rp_allowed(false, rp_id_hash)) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (credential_load_resident(ef, rp_id_hash, &cred) != 0) {
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        if (user.id.len != cred.userId.len || memcmp(user.id.data, cred.userId.data, user.id.len) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        ret = credential_update_user(ef, &user.parent.name, &user.displayName);
        if (ret != 0) {
            CBOR_ERROR(ret);
        }
        cred_mgmt_reset_state();
        goto err; //no error
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
err:
    credential_free(&cred);
    fido_cred_key_free(&key);
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(rpIdHash);
    CBOR_FREE_BYTE_STRING(user.id);
    CBOR_FREE_BYTE_STRING(user.displayName);
    CBOR_FREE_BYTE_STRING(user.parent.name);
    CBOR_FREE_BYTE_STRING(credentialId.type);
    CBOR_FREE_BYTE_STRING(credentialId.id);
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    res_APDU_size = (uint16_t)resp_size;
    return 0;
}
