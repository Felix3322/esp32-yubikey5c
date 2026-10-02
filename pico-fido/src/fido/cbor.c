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
#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#endif
#include "hid/ctap_hid.h"
#include "ctap.h"
#include "fido.h"
#include "usb.h"
#include "apdu.h"
#include "management.h"
#include "ctap2_cbor.h"
#include "cbor_make_credential.h"
#include "version.h"
#include "low_flash.h"
#include "security.h"
#include "profile.h"

const bool _btrue = true, _bfalse = false;

int cbor_reset();
int cbor_get_info();
int cbor_make_credential(const uint8_t *data, size_t len);
int cbor_client_pin(const uint8_t *data, size_t len);
int cbor_get_assertion(const uint8_t *data, size_t len, bool next);
int cbor_get_next_assertion(const uint8_t *data, size_t len);
int cbor_selection();
int cbor_cred_mgmt(const uint8_t *data, size_t len);
int cbor_config(const uint8_t *data, size_t len);
int cbor_vendor(const uint8_t *data, size_t len);
int cbor_large_blobs(const uint8_t *data, size_t len);
extern void reset_gna_state();
extern void cred_mgmt_reset_state(void);
extern int pinUvAuthTokenUsageTimerObserver();

extern int cmd_read_config();

/* LibreFido's own authenticator model identifiers (not FIDO certified):
 * the first 16 bytes of SHA-256("LibreFido 2") and, for HARDENED builds
 * whose keys never leave the device, of SHA-256("LibreFido 2 hardened"). */
#ifdef LF_PROFILE_HARDENED
const uint8_t aaguid[16] = { 0x6C, 0x86, 0xEA, 0x00, 0xE5, 0x76, 0x27, 0x56, 0x4E, 0x8A, 0x62, 0x34, 0xF5, 0x44, 0xE3, 0xFD };
#else
const uint8_t aaguid[16] = { 0x08, 0xC2, 0x28, 0xD9, 0x7E, 0xA0, 0x2B, 0xC8, 0xD0, 0x8E, 0x0D, 0x22, 0xA6, 0xD1, 0x3F, 0x7D };
#endif

const uint8_t *cbor_data = NULL;
size_t cbor_len = 0;
uint8_t cbor_cmd = 0;

/* cbor_parse() result for errors of the CTAPHID message itself (no command
 * byte, command not available), sent as a CTAPHID_ERROR frame. Anything else
 * a handler returns is the status byte of the CBOR response. */
#define CBOR_TRANSPORT_FLAG         0x40000000
#define CBOR_TRANSPORT_ERROR(e)     (CBOR_TRANSPORT_FLAG | (e))

static bool cbor_is_transport_error(int ret) {
    return ((unsigned int) ret & ~0xFFu) == CBOR_TRANSPORT_FLAG;
}

/* CTAP status byte for a cbor_parse() result. The handlers return CTAP codes
 * but also raw tinycbor errors (256 and up, or CborErrorOutOfMemory): those
 * must not be truncated to a byte, which could read as CTAP2_OK. */
uint8_t cbor_status_byte(int ret) {
    if (cbor_is_transport_error(ret)) {
        return (uint8_t) (ret & 0xFF);
    }
    if (ret >= 0 && ret <= 0xFF) {
        return (uint8_t) ret;
    }
    if (ret >= CborErrorGarbageAtEnd && ret < CborErrorDataTooLarge) {
        return CTAP2_ERR_INVALID_CBOR;      /* malformed or unexpected input */
    }
    return CTAP1_ERR_OTHER;
}

/* The parameters of a CTAP2 command (after its command byte): one well-formed
 * CBOR item, in the canonical form of CTAP 2.1 section 8 as far as tags and
 * indefinite lengths go, nested no deeper than tinycbor's recursion limit.
 * Checked once, before any handler walks it: tinycbor does not count a tag
 * as an item of its container, so a tagged value would be taken for the next
 * map key, and a handler's iterator could then run past the end of the map
 * (an assertion, a reboot on the device). No parameters (len 0) are left to
 * the handler, as before. */
bool cbor_request_valid(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue value;
    if (len == 0) {
        return true;
    }
    return cbor_parser_init(data, len, 0, &parser, &value) == CborNoError &&
           cbor_value_validate(&value, CTAP_CBOR_VALIDATION) == CborNoError;
}

int cbor_parse(uint8_t cmd, const uint8_t *data, size_t len) {
    if (len == 0 && (cmd == CTAPHID_CBOR || cmd == CTAP_VENDOR_CBOR)) {
        return CBOR_TRANSPORT_ERROR(CTAP1_ERR_INVALID_LEN);
    }
    if (len > 0) {
        DEBUG_DATA(data + 1, len - 1);
    }
    if (!fido_keystore_ok() && !(cmd == CTAPHID_CBOR && data[0] == CTAP_GET_INFO)) {
        /* Locked key store (HARDENED build on an unprovisioned chip), or a
         * root key held until it is bound: only getInfo is answered. */
        return cmd == CTAPHID_CBOR || cmd == CTAP_VENDOR_CBOR ? CTAP2_ERR_NOT_ALLOWED : CBOR_TRANSPORT_ERROR(CTAP2_ERR_NOT_ALLOWED);
    }
    /* expires the pinUvAuthToken before any command can use it */
    pinUvAuthTokenUsageTimerObserver();
    if (cap_supported(CAP_FIDO2)) {
        if (cmd == CTAPHID_CBOR) {
            if (data[0] != CTAP_GET_NEXT_ASSERTION) {
                reset_gna_state();
            }
            if (data[0] != CTAP_CREDENTIAL_MGMT && data[0] != 0x41) {
                cred_mgmt_reset_state();
            }
            if (!cbor_request_valid(data + 1, len - 1)) {
                return CTAP2_ERR_INVALID_CBOR;
            }
            if (data[0] == CTAP_MAKE_CREDENTIAL) {
                return cbor_make_credential(data + 1, len - 1);
            }
            if (data[0] == CTAP_GET_INFO) {
                return cbor_get_info();
            }
            else if (data[0] == CTAP_RESET) {
                return cbor_reset();
            }
            else if (data[0] == CTAP_CLIENT_PIN) {
                return cbor_client_pin(data + 1, len - 1);
            }
            else if (data[0] == CTAP_GET_ASSERTION) {
                return cbor_get_assertion(data + 1, len - 1, false);
            }
            else if (data[0] == CTAP_GET_NEXT_ASSERTION) {
                return cbor_get_next_assertion(data + 1, len - 1);
            }
            else if (data[0] == CTAP_SELECTION) {
                return cbor_selection();
            }
            else if (data[0] == CTAP_CREDENTIAL_MGMT || data[0] == 0x41) {
                return cbor_cred_mgmt(data + 1, len - 1);
            }
            else if (data[0] == CTAP_CONFIG) {
                return cbor_config(data + 1, len - 1);
            }
            else if (data[0] == CTAP_LARGE_BLOBS) {
                return cbor_large_blobs(data + 1, len - 1);
            }
            /* an unknown authenticator command: a CTAP status */
            return CTAP1_ERR_INVALID_CMD;
        }
        else if (cmd == CTAP_VENDOR_CBOR) {
            /* data[0]: the vendor command, then its CBOR parameters */
            if (!cbor_request_valid(data + 1, len - 1)) {
                return CTAP2_ERR_INVALID_CBOR;
            }
            return cbor_vendor(data, len);
        }
        else if (cmd == 0xC2) {
            if (cmd_read_config() == 0x9000) {
                memmove(res_APDU-1, res_APDU, res_APDU_size);
                res_APDU_size -= 1;
                return 0;
            }
        }
    }
    return CBOR_TRANSPORT_ERROR(CTAP1_ERR_INVALID_CMD);
}

void *cbor_thread(void *arg) {
    (void)arg;
    card_init_core1();
    while (1) {
        uint32_t m;
        queue_remove_blocking(&usb_to_card_q, &m);
        uint32_t flag = m + 1;
        queue_add_blocking(&card_to_usb_q, &flag);

        if (m == EV_EXIT) {
            break;
        }
        if (m != EV_CMD_AVAILABLE) {
            /* A late button event must never re-run the previous command. */
            continue;
        }
        /* The command's writes are one storage transaction, durable before
         * the response leaves the device. */
        low_flash_txn_begin();
        int ret = cbor_parse(cbor_cmd, cbor_data, cbor_len);
        if (low_flash_txn_end() != PICOKEY_OK && ret == 0) {
            ret = CTAP1_ERR_OTHER;
        }
        if (ret == 0 && res_APDU_size > CTAP_MAX_CBOR_PAYLOAD) {
            /* never more than the scratch space the answer was encoded in */
            mbedtls_platform_zeroize(ctap_resp->init.data, 1 + CTAP_MAX_CBOR_PAYLOAD);
            ret = CTAP1_ERR_OTHER;
        }
        apdu.sw = 0;
        if (ret == 0) {
            DEBUG_DATA(res_APDU, res_APDU_size);
        }
        else if (cbor_is_transport_error(ret) || (cbor_cmd != CTAPHID_CBOR && cbor_cmd != CTAP_VENDOR_CBOR)) {
            /* CTAPHID_ERROR frame */
            apdu.sw = cbor_status_byte(ret);
            res_APDU[0] = (uint8_t) apdu.sw;
        }
        else {
            /* Every status of a CBOR command is the response's status byte,
             * those below 0x0B (INVALID_PARAMETER, INVALID_LEN, INVALID_SEQ)
             * included: a CTAPHID_ERROR frame reads as a transport failure. */
            res_APDU[-1] = cbor_status_byte(ret);
            res_APDU_size = 0;
        }

        finished_data_size = res_APDU_size + 1;

        flag = EV_EXEC_FINISHED;
        queue_add_blocking(&card_to_usb_q, &flag);
    }
    return NULL;
}

int cbor_process(uint8_t last_cmd, const uint8_t *data, size_t len) {
    cbor_data = data;
    cbor_len = len;
    cbor_cmd = last_cmd;
    ctap_resp->init.data[0] = 0;
    res_APDU = ctap_resp->init.data + 1;
    res_APDU_size = 0;
    return 2; // CBOR processing
}

CborError cbor_parse_cred_descriptor(CborValue *map, PublicKeyCredentialDescriptor *pc) {
    CborError error = CborNoError;
    CBOR_PARSE_MAP_START(*map, 9)
    {
        CBOR_FIELD_GET_KEY_TEXT(9);
        CBOR_FIELD_KEY_TEXT_VAL_BYTES(9, "id", pc->id);
        CBOR_FIELD_KEY_TEXT_VAL_TEXT(9, "type", pc->type);
        /* "transports" and future members carry nothing we act on. */
        CBOR_ADVANCE(9);
    }
    CBOR_PARSE_MAP_END(*map, 9);
    if (pc->id.present && pc->id.len > MAX_CRED_ID_LENGTH) {
        CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
    }
err:
    return error;
}

/* COSE (IANA) curve identifiers of the brainpool curves. */
#define COSE_CRV_BRAINPOOLP256R1    256
#define COSE_CRV_BRAINPOOLP384R1    258
#define COSE_CRV_BRAINPOOLP512R1    259

CborError COSE_key_params(int crv, int alg, mbedtls_ecp_group *grp, mbedtls_ecp_point *Q, CborEncoder *mapEncoderParent, CborEncoder *mapEncoder) {
    CborError error = CborNoError;
    int kty = 1;
    if (crv == FIDO2_CURVE_P256 || crv == FIDO2_CURVE_P384 || crv == FIDO2_CURVE_P521 ||
        crv == FIDO2_CURVE_P256K1 || crv == COSE_CRV_BRAINPOOLP256R1 ||
        crv == COSE_CRV_BRAINPOOLP384R1 || crv == COSE_CRV_BRAINPOOLP512R1) {
        kty = 2;
    }

    CBOR_CHECK(cbor_encoder_create_map(mapEncoderParent, mapEncoder, kty == 2 ? 5 : 4));

    CBOR_CHECK(cbor_encode_uint(mapEncoder, 1));
    CBOR_CHECK(cbor_encode_uint(mapEncoder, kty));

    CBOR_CHECK(cbor_encode_uint(mapEncoder, 3));
    CBOR_CHECK(cbor_encode_negative_int(mapEncoder, -alg));

    CBOR_CHECK(cbor_encode_negative_int(mapEncoder, 1));
    CBOR_CHECK(cbor_encode_uint(mapEncoder, crv));


    CBOR_CHECK(cbor_encode_negative_int(mapEncoder, 2));
    uint8_t pkey[67];
    if (kty == 2) {
        size_t plen = mbedtls_mpi_size(&grp->P);
        CBOR_CHECK(mbedtls_mpi_write_binary(&Q->X, pkey, plen));
        CBOR_CHECK(cbor_encode_byte_string(mapEncoder, pkey, plen));

        CBOR_CHECK(cbor_encode_negative_int(mapEncoder, 3));

        CBOR_CHECK(mbedtls_mpi_write_binary(&Q->Y, pkey, plen));
        CBOR_CHECK(cbor_encode_byte_string(mapEncoder, pkey, plen));
    }
    else {
        size_t olen = 0;
        CBOR_CHECK(mbedtls_ecp_point_write_binary(grp, Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, pkey,
                                                  sizeof(pkey)));
        CBOR_CHECK(cbor_encode_byte_string(mapEncoder, pkey, olen));
    }

    CBOR_CHECK(cbor_encoder_close_container(mapEncoderParent, mapEncoder));
err:
    return error;
}
/* alg: the algorithm the credential was created for (e.g. ESP256, -9, is
 * a P-256 key like ES256, -7), so the key's "alg" matches the attestation
 * statement; 0 derives it from the curve. */
CborError COSE_key(mbedtls_ecp_keypair *key, int cred_alg, CborEncoder *mapEncoderParent,
                   CborEncoder *mapEncoder) {
    int crv = mbedtls_curve_to_fido(key->grp.id), alg = 0;
    /* Brainpool: no new credentials (makeCredential refuses ESB*), but those
     * earlier firmware made stay listable, as proper EC2 keys. */
    if (key->grp.id == MBEDTLS_ECP_DP_BP256R1) {
        crv = COSE_CRV_BRAINPOOLP256R1;
        alg = FIDO2_ALG_ESB256;
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_BP384R1) {
        crv = COSE_CRV_BRAINPOOLP384R1;
        alg = FIDO2_ALG_ESB384;
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_BP512R1) {
        crv = COSE_CRV_BRAINPOOLP512R1;
        alg = FIDO2_ALG_ESB512;
    }
    if (crv == 0) {
        return CborErrorUnsupportedType;    /* no COSE curve */
    }
    if (cred_alg != 0) {
        alg = cred_alg;
    }
    else if (alg != 0) {
        /* brainpool, set above */
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_SECP256R1) {
        alg = FIDO2_ALG_ES256;
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_SECP384R1) {
        alg = FIDO2_ALG_ES384;
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_SECP521R1) {
        alg = FIDO2_ALG_ES512;
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_SECP256K1) {
        alg = FIDO2_ALG_ES256K;
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_CURVE25519) {
        alg = FIDO2_ALG_ECDH_ES_HKDF_256;
    }
#ifdef MBEDTLS_EDDSA_C
    else if (key->grp.id == MBEDTLS_ECP_DP_ED25519) {
        alg = FIDO2_ALG_EDDSA;
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_ED448) {
        alg = FIDO2_ALG_ED448;
    }
#endif
    return COSE_key_params(crv, alg, &key->grp, &key->Q, mapEncoderParent, mapEncoder);
}
#ifdef FIDO_ED25519_LF
/* OKP key (RFC 9053, 7.2): {1: 1, 3: alg, -1: crv, -2: x}. */
static CborError COSE_key_okp(int crv, int alg, const uint8_t *x, size_t x_len, CborEncoder *mapEncoderParent, CborEncoder *mapEncoder) {
    CborError error = CborNoError;
    CBOR_CHECK(cbor_encoder_create_map(mapEncoderParent, mapEncoder, 4));
    CBOR_CHECK(cbor_encode_uint(mapEncoder, 1));
    CBOR_CHECK(cbor_encode_uint(mapEncoder, 1));
    CBOR_CHECK(cbor_encode_uint(mapEncoder, 3));
    CBOR_CHECK(cbor_encode_negative_int(mapEncoder, -alg));
    CBOR_CHECK(cbor_encode_negative_int(mapEncoder, 1));
    CBOR_CHECK(cbor_encode_uint(mapEncoder, crv));
    CBOR_CHECK(cbor_encode_negative_int(mapEncoder, 2));
    CBOR_CHECK(cbor_encode_byte_string(mapEncoder, x, x_len));
    CBOR_CHECK(cbor_encoder_close_container(mapEncoderParent, mapEncoder));
err:
    return error;
}
#endif
CborError COSE_cred_key(struct fido_cred_key *key, int cred_alg, CborEncoder *mapEncoderParent,
                        CborEncoder *mapEncoder) {
#ifdef FIDO_ED25519_LF
    if (key->curve == FIDO2_CURVE_ED25519) {
        /* -8 (EdDSA) or -19 (Ed25519), as the credential was created */
        return COSE_key_okp(FIDO2_CURVE_ED25519, cred_alg != 0 ? cred_alg : FIDO2_ALG_EDDSA,
                            key->ed_pub, sizeof(key->ed_pub), mapEncoderParent, mapEncoder);
    }
#endif
    return COSE_key(&key->ec, cred_alg, mapEncoderParent, mapEncoder);
}
CborError COSE_key_shared(mbedtls_ecdh_context *key,
                          CborEncoder *mapEncoderParent,
                          CborEncoder *mapEncoder) {
    int crv = mbedtls_curve_to_fido(key->ctx.mbed_ecdh.grp.id), alg = FIDO2_ALG_ECDH_ES_HKDF_256;
    return COSE_key_params(crv, alg, &key->ctx.mbed_ecdh.grp, &key->ctx.mbed_ecdh.Q, mapEncoderParent, mapEncoder);
}
CborError COSE_public_key(int alg, CborEncoder *mapEncoderParent, CborEncoder *mapEncoder) {
    CborError error = CborNoError;
    CBOR_CHECK(cbor_encoder_create_map(mapEncoderParent, mapEncoder, 2));
    CBOR_CHECK(cbor_encode_text_stringz(mapEncoder, "alg"));
    CBOR_CHECK(cbor_encode_negative_int(mapEncoder, -alg));
    CBOR_CHECK(cbor_encode_text_stringz(mapEncoder, "type"));
    CBOR_CHECK(cbor_encode_text_stringz(mapEncoder, "public-key"));
    CBOR_CHECK(cbor_encoder_close_container(mapEncoderParent, mapEncoder));
err:
    return error;
}
CborError COSE_read_key(CborValue *f, int64_t *kty, int64_t *alg, int64_t *crv, CborByteString *kax, CborByteString *kay) {
    int64_t kkey = 0;
    CborError error = CborNoError;
    CBOR_PARSE_MAP_START(*f, 0)
    {
        CBOR_FIELD_GET_INT(kkey, 0);
        if (kkey == 1) {
            CBOR_FIELD_GET_INT(*kty, 0);
        }
        else if (kkey == 3) {
            CBOR_FIELD_GET_INT(*alg, 0);
        }
        else if (kkey == -1) {
            CBOR_FIELD_GET_INT(*crv, 0);
        }
        else if (kkey == -2) {
            CBOR_FIELD_GET_BYTES(*kax, 0);
        }
        else if (kkey == -3) {
            CBOR_FIELD_GET_BYTES(*kay, 0);
        }
        else {
            CBOR_ADVANCE(0);
        }
    }
    CBOR_PARSE_MAP_END(*f, 0);
err:
    return error;
}
