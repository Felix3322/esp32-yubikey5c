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

#ifndef _CTAP2_CBOR_H_
#define _CTAP2_CBOR_H_

#include "cbor.h"
#ifndef ESP_PLATFORM
#include "common.h"
#else
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"

extern uint8_t *driver_prepare_response();
extern void driver_exec_finished(size_t size_next);
extern int cbor_process(uint8_t, const uint8_t *data, size_t len);
extern const uint8_t aaguid[16];

extern const bool _btrue, _bfalse;
#define ptrue (&_btrue)
#define pfalse (&_bfalse)

#define CBOR_CHECK(f)           \
    do                          \
    {                           \
        error = f;      \
        if (error != CborNoError) \
        {                       \
            printf("Cannot encode CBOR [%s:%d]: %s (%d)\n", __FILE__, __LINE__, #f, error); \
            goto err; \
        } \
    } while (0)

#define CBOR_FREE(x) \
    do               \
    {                \
        if (x)       \
        {            \
            free(x); \
            x = NULL; \
        }            \
    } while (0)

#define CBOR_ERROR(e) \
    do                \
    {                 \
        error = e;    \
        printf("Cbor ERROR [%s:%d]: %x\n", __FILE__, __LINE__, e); \
        goto err;     \
    } while (0)

#define CBOR_ASSERT(c)                      \
    do                                      \
    {                                       \
        if (!c)                             \
        {                                   \
            error = CborErrorImproperValue; \
            printf("Cbor ASSERT [%s:%d]: %s\n", __FILE__, __LINE__, #c); \
            goto err;                       \
        }                                   \
    } while (0)

#define PINUVAUTHTOKEN_MC           0x1
#define PINUVAUTHTOKEN_GA           0x2
#define PINUVAUTHTOKEN_CM           0x4
#define PINUVAUTHTOKEN_BE           0x8
#define PINUVAUTHTOKEN_LBW         0x10
#define PINUVAUTHTOKEN_ACFG        0x20

typedef struct CborByteString {
    uint8_t *data;
    size_t len;
    bool present;
    bool nofree;
} CborByteString;

typedef struct CborCharString {
    char *data;
    size_t len;
    bool present;
    bool nofree;
} CborCharString;

#define CBOR_FREE_BYTE_STRING(v) \
    do                           \
    {                            \
        if ((v).nofree != true) \
        CBOR_FREE((v).data);  \
        else \
        (v).data = NULL; \
        (v).len = 0; \
        (v).present = false; \
    } while (0)

#define CBOR_PARSE_MAP_START(_p, _n)                   \
    CBOR_ASSERT(cbor_value_is_map(&(_p)) == true); \
    CborValue _f##_n; \
    CBOR_CHECK(cbor_value_enter_container(&(_p), &(_f##_n))); \
    while (cbor_value_at_end(&(_f##_n)) == false)

#define CBOR_PARSE_ARRAY_START(_p, _n)                   \
    CBOR_ASSERT(cbor_value_is_array(&(_p)) == true); \
    CborValue _f##_n; \
    CBOR_CHECK(cbor_value_enter_container(&(_p), &(_f##_n))); \
    while (cbor_value_at_end(&(_f##_n)) == false)

#define CBOR_FIELD_GET_UINT(v, _n) \
    do { \
        CBOR_ASSERT(cbor_value_is_unsigned_integer(&(_f##_n)) == true); \
        CBOR_CHECK(cbor_value_get_uint64(&(_f##_n), &(v))); \
        CBOR_CHECK(cbor_value_advance_fixed(&(_f##_n))); \
    } while (0)

#define CBOR_FIELD_GET_INT(v, _n) \
    do { \
        CBOR_ASSERT(cbor_value_is_integer(&(_f##_n)) == true); \
        CBOR_CHECK(cbor_value_get_int64(&(_f##_n), &(v))); \
        CBOR_CHECK(cbor_value_advance_fixed(&(_f##_n))); \
    } while (0)

/* A key seen twice in a map is invalid CBOR for CTAP (canonical encoding);
 * rejecting it also prevents leaking the first duplicated buffer. */
#define CBOR_REJECT_DUPLICATE(v) \
    do { \
        if ((v).present) { \
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR); \
        } \
    } while (0)

#define CBOR_FIELD_GET_BYTES(v, _n) \
    do { \
        CBOR_ASSERT(cbor_value_is_byte_string(&(_f##_n)) == true); \
        CBOR_REJECT_DUPLICATE(v); \
        CBOR_CHECK(cbor_value_dup_byte_string(&(_f##_n), &(v).data, &(v).len, &(_f##_n))); \
        (v).present = true; \
    } while (0)

#define CBOR_FIELD_GET_TEXT(v, _n) \
    do { \
        CBOR_ASSERT(cbor_value_is_text_string(&(_f##_n)) == true); \
        CBOR_REJECT_DUPLICATE(v); \
        CBOR_CHECK(cbor_value_dup_text_string(&(_f##_n), &(v).data, &(v).len, &(_f##_n))); \
        (v).present = true; \
    } while (0)

#define CBOR_FIELD_GET_BOOL(v, _n) \
    do { \
        CBOR_ASSERT(cbor_value_is_boolean(&(_f##_n)) == true); \
        bool val; \
        CBOR_CHECK(cbor_value_get_boolean(&(_f##_n), &val)); \
        v = (val == true ? ptrue : pfalse); \
        CBOR_CHECK(cbor_value_advance_fixed(&(_f##_n))); \
    } while (0)

/* A key too long for the buffer matches no known key: it is skipped and
 * left empty, so the caller's final CBOR_ADVANCE skips its value (it used
 * to fail the whole command with CborErrorOutOfMemory). */
#define CBOR_FIELD_GET_KEY_TEXT(_n) \
    CBOR_ASSERT(cbor_value_is_text_string(&(_f##_n)) == true); \
    char _fd##_n[64] = {0}; \
    size_t _fdl##_n = sizeof(_fd##_n); \
    do { \
        size_t _fkl##_n = 0; \
        CBOR_CHECK(cbor_value_calculate_string_length(&(_f##_n), &_fkl##_n)); \
        if (_fkl##_n >= sizeof(_fd##_n)) { \
            CBOR_CHECK(cbor_value_advance(&(_f##_n))); \
        } \
        else { \
            CBOR_CHECK(cbor_value_copy_text_string(&(_f##_n), _fd##_n, &_fdl##_n, &(_f##_n))); \
        } \
    } while (0)

#define CBOR_FIELD_KEY_TEXT_VAL_TEXT(_n, _t, _v) \
    if (strcmp(_fd##_n, _t) == 0) { \
        CBOR_ASSERT(cbor_value_is_text_string(&_f##_n) == true); \
        CBOR_REJECT_DUPLICATE(_v); \
        CBOR_CHECK(cbor_value_dup_text_string(&(_f##_n), &(_v).data, &(_v).len, &(_f##_n))); \
        (_v).present = true; \
        continue; \
    }

#define CBOR_FIELD_KEY_TEXT_VAL_BYTES(_n, _t, _v) \
    if (strcmp(_fd##_n, _t) == 0) { \
        CBOR_ASSERT(cbor_value_is_byte_string(&_f##_n) == true); \
        CBOR_REJECT_DUPLICATE(_v); \
        CBOR_CHECK(cbor_value_dup_byte_string(&(_f##_n), &(_v).data, &(_v).len, &(_f##_n))); \
        (_v).present = true; \
        continue; \
    }

#define CBOR_FIELD_KEY_TEXT_VAL_INT(_n, _t, _v) \
    if (strcmp(_fd##_n, _t) == 0) { \
        CBOR_FIELD_GET_INT(_v, _n); \
        continue; \
    }

#define CBOR_FIELD_KEY_TEXT_VAL_UINT(_n, _t, _v) \
    if (strcmp(_fd##_n, _t) == 0) { \
        CBOR_FIELD_GET_UINT(_v, _n); \
        continue; \
    }

#define CBOR_FIELD_KEY_TEXT_VAL_BOOL(_n, _t, _v) \
    if (strcmp(_fd##_n, _t) == 0) { \
        CBOR_FIELD_GET_BOOL(_v, _n); \
        continue; \
    }

#define CBOR_PARSE_MAP_END(_p, _n)  \
    CBOR_CHECK(cbor_value_leave_container(&(_p), &(_f##_n)))

#define CBOR_PARSE_ARRAY_END(_p, _n)  CBOR_PARSE_MAP_END(_p, _n)

/* Skips a value the handler does not read. cbor_parse() validated the
 * request, but an iterator at the end of its container (a key without a
 * value) or on a tag (not counted as an item: tinycbor would stop at the
 * tagged item, then read as the next key) never reaches tinycbor, whose
 * cbor_value_advance() asserts on the first. */
#define CBOR_ADVANCE(_n) \
    do { \
        if (cbor_value_at_end(&_f##_n) || cbor_value_is_tag(&_f##_n)) { \
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR); \
        } \
        CBOR_CHECK(cbor_value_advance(&_f##_n)); \
    } while (0);

/* Validation of a CTAP2 request (cbor.c): canonical CBOR has neither tags
 * nor indefinite lengths (CTAP 2.1, section 8). */
#define CTAP_CBOR_VALIDATION \
    (CborValidateBasic | CborValidateNoTags | CborValidateNoIndeterminateLength)
extern bool cbor_request_valid(const uint8_t *data, size_t len);

#define CBOR_APPEND_KEY_UINT_VAL_BYTES(p, k, v) \
    do { \
        if ((v).data && (v).len > 0) { \
            CBOR_CHECK(cbor_encode_uint(&(p), (k))); \
            CBOR_CHECK(cbor_encode_byte_string(&(p), (v).data, (v).len)); \
        } } while (0)

#define CBOR_APPEND_KEY_UINT_VAL_STRING(p, k, v) \
    do { \
        if ((v).data && (v).len > 0) { \
            CBOR_CHECK(cbor_encode_uint(&(p), (k))); \
            CBOR_CHECK(cbor_encode_text_stringz(&(p), (v).data)); \
        } } while (0)


#define CBOR_APPEND_KEY_UINT_VAL_UINT(p, k, v) \
    do { \
        CBOR_CHECK(cbor_encode_uint(&(p), (k))); \
        CBOR_CHECK(cbor_encode_uint(&(p), (v))); \
    } while (0)

#define CBOR_APPEND_KEY_UINT_VAL_INT(p, k, v) \
    do { \
        CBOR_CHECK(cbor_encode_int(&(p), (k))); \
        CBOR_CHECK(cbor_encode_int(&(p), (v))); \
    } while (0)

#define CBOR_APPEND_KEY_UINT_VAL_BOOL(p, k, v) \
    do { \
        CBOR_CHECK(cbor_encode_uint(&(p), (k))); \
        CBOR_CHECK(cbor_encode_boolean(&(p), (v))); \
    } while (0)

#define CBOR_APPEND_KEY_UINT_VAL_PBOOL(p, k, v) \
    do { \
        if (v != NULL) { \
            CBOR_CHECK(cbor_encode_uint(&(p), (k))); \
            CBOR_CHECK(cbor_encode_boolean(&(p), v == ptrue ? true : false)); \
        } } while (0)

struct PublicKeyCredentialDescriptor;
/* Parses one PublicKeyCredentialDescriptor map ("id", "type"; transports and
 * unknown members are skipped) with duplicate and type checks. */
extern CborError cbor_parse_cred_descriptor(CborValue *map, struct PublicKeyCredentialDescriptor *pc);

extern CborError COSE_key(mbedtls_ecp_keypair *, int alg, CborEncoder *, CborEncoder *);
struct fido_cred_key;
/* COSE public key of a credential key (fido.h), alg as for COSE_key(). */
extern CborError COSE_cred_key(struct fido_cred_key *, int alg, CborEncoder *, CborEncoder *);
extern CborError COSE_key_shared(mbedtls_ecdh_context *key,
                                 CborEncoder *mapEncoderParent,
                                 CborEncoder *mapEncoder);
extern CborError COSE_public_key(int alg, CborEncoder *mapEncoderParent, CborEncoder *mapEncoder);
extern CborError COSE_read_key(CborValue *f,
                               int64_t *kty,
                               int64_t *alg,
                               int64_t *crv,
                               CborByteString *kax,
                               CborByteString *kay);

#endif //_CTAP2_CBOR_H_
