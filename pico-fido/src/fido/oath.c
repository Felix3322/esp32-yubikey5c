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
#include "files.h"
#include "random.h"
#include "version.h"
#include "asn1.h"
#include "crypto_utils.h"
#include "management.h"
#include "usb.h"
#include "sks.h"
#include "lf_policy.h"
#include "security.h"
#include "mbedtls/platform_util.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
extern bool is_nk;

#define MAX_OATH_CRED   255
#define CHALLENGE_LEN   8
#define MAX_OTP_COUNTER 3

/* Limits of what PUT stores. Names follow YKOATH (64 bytes); the key is the
 * type/algorithm byte, the digits and the secret, which clients shorten to
 * the HMAC block size (at most 128 bytes, SHA-512). */
#define OATH_NAME_MAX       64
#define OATH_SECRET_MAX     128
#define OATH_PWS_MAX        128     /* password-safe login, password, metadata */
#define OATH_IMF_MAX        8
#define OATH_CODE_KEY_MAX   64      /* access code key (SET CODE) */
#define OATH_PIN_MAX        64      /* OTP PIN */
#define OATH_CHAL_MAX       64      /* CALCULATE ALL challenge, kept for paging */
#define OATH_VERIFY_WINDOW  10      /* VERIFY CODE look-ahead over HOTP counters */
#define OATH_VERIFY_TRIES   10      /* VERIFY CODE misses before it refuses until a reboot */
#define OATH_VALIDATE_TRIES 10      /* wrong VALIDATE answers before it refuses until a reboot */
#define OATH_HID_IDLE_MS    15000   /* an authorization on the HID vendor command ends after this idle time */

/* Largest answer returned at once: what one transfer of the smart card and of
 * the HID transport carries (their response buffers are 4 KB and 2 KB), so an
 * answer never has to be split by the transport. Longer LIST and CALCULATE
 * ALL answers are paged by the applet: 61xx, then SEND REMAINING. */
#if defined(USB_HID_MAX_RESP_DATA) && defined(USB_CCID_MAX_RESP_DATA)
#define OATH_RES_CHUNK      (USB_HID_MAX_RESP_DATA < USB_CCID_MAX_RESP_DATA ? USB_HID_MAX_RESP_DATA : USB_CCID_MAX_RESP_DATA)
#else
#define OATH_RES_CHUNK      (USB_BUFFER_SIZE - 128)
#endif

#define TAG_NAME            0x71
#define TAG_NAME_LIST       0x72
#define TAG_KEY             0x73
#define TAG_CHALLENGE       0x74
#define TAG_RESPONSE        0x75
#define TAG_T_RESPONSE      0x76
#define TAG_NO_RESPONSE     0x77
#define TAG_PROPERTY        0x78
#define TAG_T_VERSION       0x79
#define TAG_IMF             0x7a
#define TAG_ALGO            0x7b
#define TAG_TOUCH_RESPONSE  0x7c
#define TAG_PASSWORD        0x80
#define TAG_NEW_PASSWORD    0x81
#define TAG_PIN_COUNTER     0x82
#define TAG_PWS_LOGIN       0x83
#define TAG_PWS_PASSWORD    0x84
#define TAG_PWS_METADATA    0x85
#define TAG_SERIAL_NUMBER   0x8F

/* Credential records written by this version keep the property as a regular
 * TLV under this private tag. A 0x78 in a record is the YKOATH bare form
 * (tag and value byte, no length) that older firmware stored verbatim. */
#define TAG_REC_PROPERTY    0x8E

#define ALG_HMAC_SHA1       0x01
#define ALG_HMAC_SHA256     0x02
#define ALG_HMAC_SHA512     0x03
#define ALG_MASK            0x0f

#define OATH_TYPE_HOTP      0x10
#define OATH_TYPE_TOTP      0x20
#define OATH_TYPE_MASK      0xf0

#define PROP_INC            0x01
#define PROP_TOUCH          0x02
#define PROP_PIN            0x03

#define INS_PUT             0x01
#define INS_DELETE          0x02
#define INS_SET_CODE        0x03
#define INS_RESET           0x04
#define INS_RENAME          0x05
#define INS_LIST            0xa1
#define INS_CALCULATE       0xa2
#define INS_VALIDATE        0xa3
#define INS_CALC_ALL        0xa4
#define INS_SEND_REMAINING  0xa5
#define INS_VERIFY_CODE     0xb1
#define INS_VERIFY_PIN      0xb2
#define INS_CHANGE_PIN      0xb3
#define INS_SET_PIN         0xb4
#define INS_GET_CREDENTIAL  0xb5

int oath_process_apdu();
int oath_unload();

/* ------------------------------------------------------------------------ */
/* Sessions                                                                 */
/* ------------------------------------------------------------------------ */

/* One session per way the applet is reached: the smart card interfaces
 * (CCID, WCID: one application slot) and the HID vendor command (CTAPHID_OTP).
 * A session starts with a SELECT command, the first selection of the applet on
 * its transport, or (HID) a new client; it ends when the applet is deselected
 * or the card is reset. Nothing one session does changes another one, except
 * a change of the access code, the OTP PIN or a RESET, which concern all.
 * Within the smart card session VALIDATE and VERIFY PIN only count for the
 * interface they arrived on. On HID an authorization also ends after
 * OATH_HID_IDLE_MS without an OATH command: HID has no card reset that tells
 * when a client is gone. */
enum { OATH_SESS_SC = 0, OATH_SESS_HID, OATH_SESSIONS };

typedef struct {
    uint8_t ins;            /* INS_LIST or INS_CALC_ALL, 0: nothing pending */
    uint8_t itf;
    uint8_t p2;
    bool ext;
    uint16_t next;          /* credential slot to continue with */
    uint16_t chal_len;
    uint8_t chal[OATH_CHAL_MAX];
} oath_page_t;

typedef struct {
    uint8_t code_itf;       /* access code validated on this interface */
    uint8_t pin_itf;        /* OTP PIN verified on this interface */
    bool chal_ok;           /* a challenge was issued */
    uint32_t last_ms;       /* last command (HID idle limit) */
    uint8_t challenge[CHALLENGE_LEN];
    oath_page_t page;       /* LIST / CALCULATE ALL answer continued by SEND REMAINING */
} oath_sess_t;

static oath_sess_t sess[OATH_SESSIONS] = {
    { .code_itf = ITF_INVALID, .pin_itf = ITF_INVALID },
    { .code_itf = ITF_INVALID, .pin_itf = ITF_INVALID },
};
static uint8_t verify_misses = 0;          /* VERIFY CODE failures since the last match */
static uint8_t validate_misses = 0;        /* VALIDATE failures since the last success */
static bool migrated = false;              /* plaintext records of older firmware sealed */

/* USB interface family of the application slot the SDK bound last (smart
 * card, HID, keyboard). Provided by the SDK where available: an application
 * is selected and unloaded outside a command (HID transport, card reset). */
extern uint8_t apdu_bound_itf(void) __attribute__((weak));

const uint8_t oath_aid[] = {
    7,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01
};

static int sess_of_itf(uint8_t itf) {
#ifdef USB_ITF_HID
    if (itf != ITF_INVALID && itf == ITF_HID) {
        return OATH_SESS_HID;
    }
#endif
    (void) itf;
    return OATH_SESS_SC;
}

/* Session of the running command. */
static oath_sess_t *cur_sess(void) {
    return &sess[sess_of_itf(card_current_itf())];
}

/* The Nitrokey extensions of the SELECT answer: only for a command that came
 * over the HID vendor command (is_nk is the HID transport's last message
 * type, stale for smart card commands). */
static bool oath_nk(void) {
#ifdef USB_ITF_HID
    return is_nk && ITF_HID != ITF_INVALID && card_current_itf() == ITF_HID;
#else
    return false;
#endif
}

/* Session of a selection or unload: -1 when it cannot be told. */
static int ctx_sess(void) {
    if (apdu_bound_itf) {
        return sess_of_itf(apdu_bound_itf());
    }
    if (is_busy()) {
        return sess_of_itf(card_current_itf());
    }
    return -1;
}

static uint32_t oath_hid_idle_ms(void) {
#ifdef ENABLE_EMULATION
    const char *e = getenv("LF_EMU_OATH_IDLE_MS");
    if (e && *e) {
        return (uint32_t) strtoul(e, NULL, 10);
    }
#endif
    return OATH_HID_IDLE_MS;
}

static void page_reset(oath_sess_t *s) {
    memset(&s->page, 0, sizeof(s->page));
}

static void sess_logout(oath_sess_t *s) {
    s->code_itf = ITF_INVALID;
    s->pin_itf = ITF_INVALID;
    page_reset(s);
}

static void sess_reset(oath_sess_t *s) {
    sess_logout(s);
    random_gen(NULL, s->challenge, sizeof(s->challenge));
    s->chal_ok = true;
    s->last_ms = board_millis();
}

static bool oath_has_code(void) {
    return file_has_data(search_dynamic_file(EF_OATH_CODE));
}

static bool oath_has_pin(void) {
    return file_has_data(search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF));
}

/* The access code, when set, was validated in this session on this interface. */
static bool code_ok(void) {
    oath_sess_t *s = cur_sess();
    return !oath_has_code() || (s->code_itf != ITF_INVALID && s->code_itf == card_current_itf());
}

/* The OTP PIN, when set, was verified in this session on this interface. */
static bool pin_ok(void) {
    oath_sess_t *s = cur_sess();
    return !oath_has_pin() || (s->pin_itf != ITF_INVALID && s->pin_itf == card_current_itf());
}

/* Every command that reads or changes credentials needs both. VERIFY PIN
 * never stands in for the access code. */
static bool oath_authorized(void) {
    return code_ok() && pin_ok();
}

/* ------------------------------------------------------------------------ */
/* Storage                                                                  */
/* ------------------------------------------------------------------------ */

/* Records are sealed (sks, OATH namespace). Plaintext records of older
 * firmware are read as they are and sealed once the running firmware is
 * confirmed: an unconfirmed update can still roll back to firmware that
 * cannot read sealed records. A sealed record is never written back in
 * plaintext. */
static bool oath_seal_new(void) {
    return lf_migrate_ok() || lf_profile_sealed_only();
}

/* Opens a stored record into a heap buffer (plaintext, len bytes). */
static int oath_read(const file_t *ef, uint8_t **out, uint16_t *out_len, bool *sealed) {
    *out = NULL;
    *out_len = 0;
    *sealed = false;
    if (!file_has_data(ef)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint16_t n = file_get_size(ef);
    uint8_t *buf = (uint8_t *) calloc(1, n);
    if (buf == NULL) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    size_t len = 0;
    bool legacy = false;
    int r = sks_file_get(SKS_NS_OATH, ef, buf, n, &len, &legacy);
    if (r != PICOKEY_OK) {
        mbedtls_platform_zeroize(buf, n);
        free(buf);
        return r;
    }
    *out = buf;
    *out_len = (uint16_t) len;
    *sealed = !legacy;
    return PICOKEY_OK;
}

static void oath_free(uint8_t *buf, uint16_t len) {
    if (buf) {
        mbedtls_platform_zeroize(buf, len);
        free(buf);
    }
}

static int oath_write(file_t *ef, const uint8_t *data, uint16_t len, bool seal) {
    if (ef == NULL) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    int r = seal ? sks_file_put(SKS_NS_OATH, ef, data, len) : file_put_data(ef, data, len);
    if (r == PICOKEY_OK) {
        low_flash_available();
    }
    return r;
}

/* Seals what older firmware stored in plaintext (credentials, access code,
 * OTP PIN), once per boot and only once the firmware is confirmed. In a
 * profile created secure plaintext can only be injected: it is left alone
 * (and never read). */
static void oath_migrate(void) {
    if (migrated || !lf_migrate_ok()) {
        return;
    }
    if (lf_profile_sealed_only()) {
        migrated = true;
        return;
    }
    bool ok = true;
    for (int i = 0; i <= MAX_OATH_CRED + 1; i++) {
        file_t *ef = i < MAX_OATH_CRED ? search_dynamic_file((uint16_t)(EF_OATH_CRED + i)) :
                     (i == MAX_OATH_CRED ? search_dynamic_file(EF_OATH_CODE) : search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF));
        if (!file_has_data(ef) || sks_is_sealed(SKS_NS_OATH, file_get_data(ef), file_get_size(ef))) {
            continue;
        }
        uint16_t n = file_get_size(ef);
        uint8_t *buf = (uint8_t *) malloc(n);
        if (buf == NULL) {
            ok = false;
            continue;
        }
        memcpy(buf, file_get_data(ef), n);
        if (oath_write(ef, buf, n, true) != PICOKEY_OK) {
            ok = false;
        }
        oath_free(buf, n);
    }
    migrated = ok;
}

/* ------------------------------------------------------------------------ */
/* Messages and records                                                     */
/* ------------------------------------------------------------------------ */

/* Next element of a YKOATH message or credential record. Every length is
 * checked against the buffer. The property (0x78) is the YKOATH bare form:
 * tag and one value byte, no length. 0x81 and 0x82 introduce BER long
 * lengths; any other length byte is the length itself, as the previous
 * firmware read it (clients that encode lengths in one byte, tlv8). */
static bool oath_tlv_next(const uint8_t **pp, const uint8_t *end, uint8_t *tag, const uint8_t **val, uint16_t *len) {
    const uint8_t *p = *pp;
    if (p >= end) {
        return false;
    }
    uint8_t t = *p++;
    uint16_t l = 1;
    if (t != TAG_PROPERTY) {
        if (p >= end) {
            return false;
        }
        l = *p++;
        if (l == 0x81) {
            if (p >= end) {
                return false;
            }
            l = *p++;
        }
        else if (l == 0x82) {
            if (end - p < 2) {
                return false;
            }
            l = get_uint16_t_be(p);
            p += 2;
        }
    }
    if (l > end - p) {
        return false;
    }
    *tag = t;
    *val = p;
    *len = l;
    *pp = p + l;
    return true;
}

/* The elements from p on end exactly at end. */
static bool oath_walk_clean(const uint8_t *p, const uint8_t *end) {
    const uint8_t *v = NULL;
    uint8_t t = 0;
    uint16_t l = 0;
    while (p < end) {
        if (!oath_tlv_next(&p, end, &t, &v, &l)) {
            return false;
        }
    }
    return true;
}

/* First element with this tag in a command's data. */
static bool oath_find(const uint8_t *data, uint32_t len, uint8_t tag, const uint8_t **val, uint16_t *vlen) {
    if (data == NULL) {
        return false;
    }
    const uint8_t *p = data, *end = data + len, *v = NULL;
    uint8_t t = 0;
    uint16_t l = 0;
    while (oath_tlv_next(&p, end, &t, &v, &l)) {
        if (t == tag) {
            *val = v;
            *vlen = l;
            return true;
        }
    }
    return false;
}

typedef struct {
    const uint8_t *name, *key, *imf, *login, *pw, *meta;
    uint16_t name_len, key_len, imf_len, login_len, pw_len, meta_len;
    bool has_prop;
    uint8_t prop;
    const uint8_t *tail;    /* stored record: bytes that are no clean element (older firmware) */
    uint16_t tail_len;
} oath_cred_t;

/* Next element of a command or stored record. With record true (records and
 * PUT data) the property may also be in the length form (78 01 xx), which
 * the previous firmware read and some clients send: it is taken when the
 * bare form does not fit the rest of the data and the length form does. */
static bool oath_elem_next(const uint8_t **pp, const uint8_t *end, bool record, uint8_t *t, const uint8_t **v, uint16_t *l) {
    const uint8_t *p = *pp;
    if (record && end - p >= 3 && p[0] == TAG_PROPERTY && p[1] == 0x01 &&
        !oath_walk_clean(p, end) && oath_walk_clean(p + 3, end)) {
        *t = TAG_PROPERTY;
        *v = p + 2;
        *l = 1;
        *pp = p + 3;
        return true;
    }
    return oath_tlv_next(pp, end, t, v, l);
}

/* Splits a credential (PUT data, or a stored record when record is true).
 * The first element of a tag counts. Returns false when the buffer is not a
 * clean sequence of elements; what was found before is kept and the rest is
 * in tail, so records written by older firmware stay readable and are
 * rewritten without loss. */
static bool oath_parse(const uint8_t *data, uint32_t len, oath_cred_t *c, bool record) {
    memset(c, 0, sizeof(*c));
    if (data == NULL) {
        return len == 0;
    }
    const uint8_t *p = data, *end = data + len, *v = NULL;
    uint8_t t = 0;
    uint16_t l = 0;
    while (p < end) {
        const uint8_t *at = p;
        if (!oath_elem_next(&p, end, record, &t, &v, &l)) {
            c->tail = at;
            c->tail_len = (uint16_t)(end - at);
            return false;
        }
        switch (t) {
            case TAG_NAME:
                if (!c->name) { c->name = v; c->name_len = l; }
                break;
            case TAG_KEY:
                if (!c->key) { c->key = v; c->key_len = l; }
                break;
            case TAG_IMF:
                if (!c->imf) { c->imf = v; c->imf_len = l; }
                break;
            case TAG_PWS_LOGIN:
                if (!c->login) { c->login = v; c->login_len = l; }
                break;
            case TAG_PWS_PASSWORD:
                if (!c->pw) { c->pw = v; c->pw_len = l; }
                break;
            case TAG_PWS_METADATA:
                if (!c->meta) { c->meta = v; c->meta_len = l; }
                break;
            case TAG_PROPERTY:
            case TAG_REC_PROPERTY:
                if (!c->has_prop && l >= 1) { c->has_prop = true; c->prop = v[0]; }
                break;
            default:
                break;
        }
    }
    return true;
}

static bool oath_touch(const oath_cred_t *c) {
    return c->has_prop && (c->prop & PROP_TOUCH);
}

static uint64_t oath_imf(const oath_cred_t *c) {
    uint64_t v = 0;
    for (uint16_t i = 0; c->imf && i < c->imf_len && i < OATH_IMF_MAX; i++) {
        v = (v << 8) | c->imf[i];
    }
    return v;
}

static uint16_t tlv_size(uint16_t len) {
    return 1 + format_tlv_len(len, NULL) + len;
}

static uint16_t put_tlv(uint8_t *out, uint8_t tag, const uint8_t *v, uint16_t len) {
    out[0] = tag;
    uint8_t l = format_tlv_len(len, out + 1);
    if (len > 0) {
        memcpy(out + 1 + l, v, len);
    }
    return 1 + l + len;
}

/* A stored credential, opened into RAM. */
typedef struct {
    file_t *ef;
    uint8_t *buf;
    uint16_t len;
    bool sealed;
    oath_cred_t c;          /* points into buf */
} oath_rec_t;

static bool oath_rec_open(file_t *ef, oath_rec_t *r) {
    memset(r, 0, sizeof(*r));
    if (oath_read(ef, &r->buf, &r->len, &r->sealed) != PICOKEY_OK) {
        return false;
    }
    r->ef = ef;
    oath_parse(r->buf, r->len, &r->c, true);
    return true;
}

static void oath_rec_close(oath_rec_t *r) {
    oath_free(r->buf, r->len);
    memset(r, 0, sizeof(*r));
}

/* Writes a credential as a normalized, sealed record: name, key, property
 * (private tag), moving factor (HOTP, 8 bytes), password-safe fields, then
 * whatever an older record held that is no clean element (kept verbatim). */
static int oath_store_sealed(file_t *ef, const oath_cred_t *c, uint64_t imf) {
    const bool seal = true;
    bool hotp = c->key_len > 0 && (c->key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP;
    uint32_t size = tlv_size(c->name_len) + tlv_size(c->key_len);
    size += c->has_prop ? 3 : 0;
    size += hotp ? tlv_size(OATH_IMF_MAX) : 0;
    size += c->login ? tlv_size(c->login_len) : 0;
    size += c->pw ? tlv_size(c->pw_len) : 0;
    size += c->meta ? tlv_size(c->meta_len) : 0;
    size += c->tail_len;
    if (ef == NULL || size + SKS_OVERHEAD > UINT16_MAX) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    uint8_t *buf = (uint8_t *) calloc(1, size);
    if (buf == NULL) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    uint8_t *p = buf;
    p += put_tlv(p, TAG_NAME, c->name, c->name_len);
    p += put_tlv(p, TAG_KEY, c->key, c->key_len);
    if (c->has_prop) {
        p += put_tlv(p, TAG_REC_PROPERTY, &c->prop, 1);
    }
    if (hotp) {
        uint8_t v[OATH_IMF_MAX];
        put_uint64_t_be(imf, v);
        p += put_tlv(p, TAG_IMF, v, sizeof(v));
    }
    if (c->login) {
        p += put_tlv(p, TAG_PWS_LOGIN, c->login, c->login_len);
    }
    if (c->pw) {
        p += put_tlv(p, TAG_PWS_PASSWORD, c->pw, c->pw_len);
    }
    if (c->meta) {
        p += put_tlv(p, TAG_PWS_METADATA, c->meta, c->meta_len);
    }
    if (c->tail_len > 0) {
        memcpy(p, c->tail, c->tail_len);
        p += c->tail_len;
    }
    int r = oath_write(ef, buf, (uint16_t) size, seal);
    oath_free(buf, (uint16_t) size);
    return r;
}

/* Writes a credential in plaintext, in the form the previous firmware reads
 * (an unconfirmed update may still go back to it): the elements of src (the
 * PUT data or the stored record) as they are, the property in its stored form,
 * with the name of c and, for HOTP, the moving factor as one 8-byte element.
 * A property under the private tag (plaintext of an earlier build of this
 * firmware) is written in the length form, which the previous firmware
 * reads. */
static int oath_store_plain(file_t *ef, const oath_cred_t *c, uint64_t imf, const uint8_t *src, uint16_t src_len,
                            bool record) {
    bool hotp = c->key_len > 0 && (c->key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP;
    uint32_t cap = (uint32_t) src_len + tlv_size(c->name_len) + tlv_size(OATH_IMF_MAX) + 3;
    if (ef == NULL || cap > UINT16_MAX) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    uint8_t *buf = (uint8_t *) calloc(1, cap);
    if (buf == NULL) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    uint8_t *o = buf, ctr[OATH_IMF_MAX];
    put_uint64_t_be(imf, ctr);
    const uint8_t *p = src, *end = src + src_len, *v = NULL;
    uint8_t t = 0;
    uint16_t l = 0;
    bool name_done = false, imf_done = false;
    while (p < end) {
        const uint8_t *at = p;
        if (!oath_elem_next(&p, end, record, &t, &v, &l)) {
            p = at;
            break;
        }
        if (t == TAG_NAME && !name_done) {
            o += put_tlv(o, TAG_NAME, c->name, c->name_len);
            name_done = true;
        }
        else if (t == TAG_IMF && hotp && !imf_done) {
            o += put_tlv(o, TAG_IMF, ctr, sizeof(ctr));
            imf_done = true;
        }
        else if (t == TAG_REC_PROPERTY && l >= 1) {
            *o++ = TAG_PROPERTY;
            *o++ = 1;
            *o++ = v[0];
        }
        else {
            memcpy(o, at, (size_t)(p - at));
            o += p - at;
        }
    }
    if (!name_done) {
        o += put_tlv(o, TAG_NAME, c->name, c->name_len);
    }
    if (hotp && !imf_done) {
        o += put_tlv(o, TAG_IMF, ctr, sizeof(ctr));
    }
    memcpy(o, p, (size_t)(end - p));      /* what is no clean element, verbatim */
    o += end - p;
    uint16_t size = (uint16_t)(o - buf);
    int r = oath_write(ef, buf, size, false);
    oath_free(buf, (uint16_t) cap);
    return r;
}

/* Rewrites a stored credential: a sealed one stays sealed; a plaintext one
 * is sealed (and normalized) only once the firmware is confirmed, until then
 * it keeps the form the previous firmware reads. */
static int oath_rec_store(oath_rec_t *r, const oath_cred_t *c, uint64_t imf) {
    if (r->sealed || oath_seal_new()) {
        return oath_store_sealed(r->ef, c, imf);
    }
    return oath_store_plain(r->ef, c, imf, r->buf, r->len, true);
}

/* Finds and opens the credential with this name. */
static bool find_oath_cred(const uint8_t *name, uint16_t name_len, oath_rec_t *out) {
    for (int i = 0; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file((uint16_t)(EF_OATH_CRED + i));
        if (!file_has_data(ef) || !oath_rec_open(ef, out)) {
            continue;
        }
        if (out->c.name && out->c.name_len == name_len && memcmp(out->c.name, name, name_len) == 0) {
            return true;
        }
        oath_rec_close(out);
    }
    return false;
}

/* A copy of the command data: a command that waits for a touch never reads
 * the transport buffer again afterwards. */
static uint8_t *oath_cmd_copy(uint16_t *len) {
    *len = (uint16_t) apdu.nc;
    uint8_t *c = (uint8_t *) malloc(apdu.nc ? apdu.nc : 1);
    if (c && apdu.nc) {
        memcpy(c, apdu.data, apdu.nc);
    }
    return c;
}

/* ------------------------------------------------------------------------ */
/* Selection                                                                */
/* ------------------------------------------------------------------------ */

int oath_select(app_t *a, uint8_t force) {
    if (!cap_supported(CAP_OATH)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    a->process_apdu = oath_process_apdu;
    a->unload = oath_unload;
    /* A SELECT command runs on the card thread (is_busy()); like a first
     * selection it starts a new session. Outside a command only the HID
     * transport selects the applet (before each CTAPHID_OTP message): that
     * keeps the session of that transport and answers nothing (res_APDU is
     * not this command's buffer then). */
    bool cmd = is_busy();
    int s = ctx_sess();
    if (s < 0) {
        s = OATH_SESS_HID;
    }
    if (force || cmd) {
        sess_reset(&sess[s]);
    }
    if (!cmd) {
        return PICOKEY_OK;
    }
    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = TAG_T_VERSION;
    res_APDU[res_APDU_size++] = 3;
    res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0;
    res_APDU[res_APDU_size++] = TAG_NAME;
    res_APDU[res_APDU_size++] = 8;
    memcpy(res_APDU + res_APDU_size, pico_serial_str, 8); res_APDU_size += 8;
    /* With the key store locked SELECT still answers, but opens no record. */
    bool unlocked = security_keystore_unlocked();
    if (oath_has_code()) {
        uint8_t *code = NULL, alg = ALG_HMAC_SHA1;
        uint16_t code_len = 0;
        bool sealed = false;
        if (unlocked && oath_read(search_dynamic_file(EF_OATH_CODE), &code, &code_len, &sealed) == PICOKEY_OK &&
            code_len > 0) {
            alg = code[0] & ALG_MASK;
        }
        oath_free(code, code_len);
        res_APDU[res_APDU_size++] = TAG_CHALLENGE;
        res_APDU[res_APDU_size++] = CHALLENGE_LEN;
        memcpy(res_APDU + res_APDU_size, sess[s].challenge, CHALLENGE_LEN);
        res_APDU_size += CHALLENGE_LEN;
        res_APDU[res_APDU_size++] = TAG_ALGO;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = alg;
    }
    if (oath_nk()) {
        res_APDU[res_APDU_size++] = TAG_SERIAL_NUMBER;
        res_APDU[res_APDU_size++] = 8;
        memcpy(res_APDU + res_APDU_size, pico_serial_str, 8);
        res_APDU_size += 8;
        uint8_t *pin = NULL;
        uint16_t pin_len = 0;
        bool sealed = false;
        if (unlocked && oath_read(search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF), &pin, &pin_len, &sealed) == PICOKEY_OK &&
            pin_len > 0) {
            res_APDU[res_APDU_size++] = TAG_PIN_COUNTER;
            res_APDU[res_APDU_size++] = 1;
            res_APDU[res_APDU_size++] = pin[0];
        }
        oath_free(pin, pin_len);
    }
    apdu.ne = res_APDU_size;
    return PICOKEY_OK;
}

INITIALIZER ( oath_ctor ) {
    register_app(oath_select, oath_aid);
}

/* The applet leaves its slot (another application selected, card reset, a
 * new HID client): that session ends. Outside a command it cannot always be
 * told which slot (SDK without apdu_bound_itf()): then it is the HID one. A
 * card reset of the smart card slot needs no reset here: that slot is left
 * empty and only a SELECT, which starts a new session, uses OATH again. */
int oath_unload() {
    int s = ctx_sess();
    sess_reset(&sess[s < 0 ? OATH_SESS_HID : s]);
    return PICOKEY_OK;
}

/* ------------------------------------------------------------------------ */
/* Responses                                                                */
/* ------------------------------------------------------------------------ */

static uint16_t res_limit(void) {
    uint16_t lim = OATH_RES_CHUNK;
    uintptr_t r = (uintptr_t) apdu.rdata, b = (uintptr_t) apdu_res_buf;
    if (r >= b && r < b + APDU_RES_BUF_SIZE) {
        uintptr_t room = b + APDU_RES_BUF_SIZE - r;
        room = room > 2 ? room - 2 : 0;         /* the status word follows */
        if (room < lim) {
            lim = (uint16_t) room;
        }
    }
    return lim;
}

static bool res_fits(uint32_t n) {
    return (uint32_t) res_APDU_size + n <= res_limit();
}

static void res_put_tlv(uint8_t tag, const uint8_t *v, uint16_t len) {
    res_APDU_size += put_tlv(res_APDU + res_APDU_size, tag, v, len);
}

/* GET CREDENTIAL answers the Nitrokey client, which reads one-byte lengths
 * (tlv8) as the previous firmware wrote them. */
static uint16_t tlv8_size(uint16_t len) {
    return (len <= 0xff ? 2 : 4) + len;
}

static void res_put_tlv8(uint8_t tag, const uint8_t *v, uint16_t len) {
    if (len > 0xff) {
        res_put_tlv(tag, v, len);
        return;
    }
    res_APDU[res_APDU_size++] = tag;
    res_APDU[res_APDU_size++] = (uint8_t) len;
    memcpy(res_APDU + res_APDU_size, v, len);
    res_APDU_size += len;
}

/* The answer continues: 61xx with the data so far (set_res_sw() would drop
 * it), the rest comes with SEND REMAINING (YKOATH). */
static int oath_more_data(oath_sess_t *s) {
    s->page.itf = card_current_itf();
    apdu.ne = res_APDU_size;
    apdu.sw = 0x6100;
    return apdu.sw;
}

const mbedtls_md_info_t *get_oath_md_info(uint8_t alg) {
    if ((alg & ALG_MASK) == ALG_HMAC_SHA1) {
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    }
    else if ((alg & ALG_MASK) == ALG_HMAC_SHA256) {
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    }
    else if ((alg & ALG_MASK) == ALG_HMAC_SHA512) {
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    }
    return NULL;
}

/* HMAC of a credential key (type/algorithm, digits, secret) over msg.
 * Returns its size, 0 for a key that cannot be used. */
static size_t oath_hmac(const uint8_t *key, uint16_t key_len, const uint8_t *msg, uint16_t msg_len, uint8_t out[64]) {
    if (key == NULL || key_len < 2) {
        return 0;
    }
    const mbedtls_md_info_t *md_info = get_oath_md_info(key[0]);
    if (md_info == NULL) {
        return 0;
    }
    if (mbedtls_md_hmac(md_info, key + 2, key_len - 2, msg, msg_len, out) != 0) {
        mbedtls_platform_zeroize(out, 64);
        return 0;
    }
    return mbedtls_md_get_size(md_info);
}

/* RFC 4226 dynamic truncation (31 bits). */
static uint32_t oath_truncate(const uint8_t *hmac, size_t hmac_len) {
    uint8_t offset = hmac[hmac_len - 1] & 0x0f;
    return get_uint32_t_be(hmac + offset) & 0x7fffffff;
}

/* Size of the response value calculate_oath() appends after its tag. */
static uint16_t oath_value_size(uint8_t truncate, const uint8_t *key) {
    const mbedtls_md_info_t *md_info = get_oath_md_info(key[0]);
    return 1 + 1 + (truncate == 0x01 ? 4 : (md_info ? mbedtls_md_get_size(md_info) : 0));
}

/* Appends the YKOATH response value to res_APDU: length, digits, then the
 * full HMAC (truncate == 0) or its dynamic truncation (truncate == 1). The
 * caller made sure it fits. */
static int calculate_oath(uint8_t truncate, const uint8_t *key, uint16_t key_len, const uint8_t *chal, uint16_t chal_len) {
    uint8_t hmac[64];
    size_t hmac_size = oath_hmac(key, key_len, chal, chal_len, hmac);
    if (hmac_size == 0) {
        return PICOKEY_EXEC_ERROR;
    }
    if (truncate == 0x01) {
        res_APDU[res_APDU_size++] = 4 + 1;
        res_APDU[res_APDU_size++] = key[1];
        put_uint32_t_be(oath_truncate(hmac, hmac_size), res_APDU + res_APDU_size);
        res_APDU_size += 4;
    }
    else {
        res_APDU[res_APDU_size++] = (uint8_t)(hmac_size + 1);
        res_APDU[res_APDU_size++] = key[1];
        memcpy(res_APDU + res_APDU_size, hmac, hmac_size);
        res_APDU_size += (uint16_t) hmac_size;
    }
    mbedtls_platform_zeroize(hmac, sizeof(hmac));
    return PICOKEY_OK;
}

/* A key PUT may store: type/algorithm, digits and a secret of bounded size.
 * OATH credentials need a known algorithm and 6 to 8 digits. */
static bool oath_key_valid(const uint8_t *key, uint16_t key_len) {
    if (key_len < 2 || key_len > 2 + OATH_SECRET_MAX) {
        return false;
    }
    uint8_t type = key[0] & OATH_TYPE_MASK;
    if (type == OATH_TYPE_HOTP || type == OATH_TYPE_TOTP) {
        return get_oath_md_info(key[0]) != NULL && key[1] >= 6 && key[1] <= 8;
    }
    return true;
}

/* A credential that requires touch is only used after a fresh press, unless
 * the profile gives OATH automatic presence. */
static int oath_presence(const oath_cred_t *c) {
    if (oath_touch(c) && lf_wait_presence(LF_APP_OATH) == true) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    return PICOKEY_OK;
}

/* ------------------------------------------------------------------------ */
/* Commands                                                                 */
/* ------------------------------------------------------------------------ */

int cmd_put() {
    if (!oath_authorized()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    /* The property is also taken in the length form (78 01 xx), which the
     * previous firmware accepted. */
    oath_cred_t c;
    if (!oath_parse(apdu.data, apdu.nc, &c, true)) {
        return SW_INCORRECT_PARAMS();
    }
    if (c.key == NULL || c.name == NULL) {
        return SW_INCORRECT_PARAMS();
    }
    if (c.name_len == 0 || c.name_len > OATH_NAME_MAX || !oath_key_valid(c.key, c.key_len)) {
        return SW_WRONG_DATA();
    }
    if ((c.imf && c.imf_len > OATH_IMF_MAX) || (c.login && c.login_len > OATH_PWS_MAX) ||
        (c.pw && c.pw_len > OATH_PWS_MAX) || (c.meta && c.meta_len > OATH_PWS_MAX)) {
        return SW_WRONG_DATA();
    }
    oath_rec_t old;
    file_t *ef = NULL;
    bool created = false, seal = oath_seal_new();
    if (find_oath_cred(c.name, c.name_len, &old)) {
        ef = old.ef;
        seal = seal || old.sealed;
        oath_rec_close(&old);
    }
    else {
        for (int i = 0; i < MAX_OATH_CRED && ef == NULL; i++) {
            if (!file_has_data(search_dynamic_file((uint16_t)(EF_OATH_CRED + i)))) {
                ef = file_new((uint16_t)(EF_OATH_CRED + i));
                created = true;
            }
        }
        if (ef == NULL) {
            return SW_FILE_FULL();
        }
    }
    /* Unconfirmed firmware: stored as sent (the previous firmware's form). */
    int r = seal ? oath_store_sealed(ef, &c, oath_imf(&c)) :
            oath_store_plain(ef, &c, oath_imf(&c), apdu.data, (uint16_t) apdu.nc, true);
    if (r != PICOKEY_OK) {
        if (created) {
            delete_file(ef);
        }
        return SW_MEMORY_FAILURE();
    }
    return SW_OK();
}

int cmd_delete() {
    if (!oath_authorized()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    const uint8_t *name = NULL;
    uint16_t name_len = 0;
    if (oath_find(apdu.data, apdu.nc, TAG_NAME, &name, &name_len) == true) {
        oath_rec_t r;
        if (find_oath_cred(name, name_len, &r)) {
            file_t *ef = r.ef;
            oath_rec_close(&r);
            delete_file(ef);
            return SW_OK();
        }
        return SW_DATA_INVALID();
    }
    return SW_INCORRECT_PARAMS();
}

/* HMAC-response check against the access code key (algorithm byte and
 * key): exact length, constant time. */
static bool oath_code_response_ok(const mbedtls_md_info_t *md_info, const uint8_t *key, uint16_t key_len,
                                  const uint8_t *msg, uint16_t msg_len, const uint8_t *resp, uint16_t resp_len) {
    uint8_t hmac[64];
    size_t hlen = mbedtls_md_get_size(md_info);
    bool ok = false;
    if (mbedtls_md_hmac(md_info, key, key_len, msg, msg_len, hmac) == 0) {
        ok = resp_len == hlen && ct_memcmp(hmac, resp, hlen) == 0;
    }
    mbedtls_platform_zeroize(hmac, sizeof(hmac));
    return ok;
}

int cmd_set_code() {
    if (!oath_authorized()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    const uint8_t *key = NULL, *chal = NULL, *resp = NULL;
    uint16_t key_len = 0, chal_len = 0, resp_len = 0;
    if (apdu.nc > 0 && oath_find(apdu.data, apdu.nc, TAG_KEY, &key, &key_len) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (apdu.nc == 0 || key_len == 0) {
        delete_file(search_dynamic_file(EF_OATH_CODE));
        for (int i = 0; i < OATH_SESSIONS; i++) {
            sess[i].code_itf = ITF_INVALID;
        }
        return SW_OK();
    }
    if (oath_find(apdu.data, apdu.nc, TAG_CHALLENGE, &chal, &chal_len) == false || chal_len == 0) {
        return SW_INCORRECT_PARAMS();
    }
    if (oath_find(apdu.data, apdu.nc, TAG_RESPONSE, &resp, &resp_len) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (key_len < 2 || key_len > 1 + OATH_CODE_KEY_MAX) {
        return SW_WRONG_DATA();
    }
    const mbedtls_md_info_t *md_info = get_oath_md_info(key[0]);
    if (md_info == NULL) {
        return SW_INCORRECT_PARAMS();
    }
    /* The host proves it computed the HMAC with the new key. */
    if (!oath_code_response_ok(md_info, key + 1, key_len - 1, chal, chal_len, resp, resp_len)) {
        return SW_DATA_INVALID();
    }
    file_t *ef = search_dynamic_file(EF_OATH_CODE);
    bool seal = oath_seal_new() || (file_has_data(ef) && sks_is_sealed(SKS_NS_OATH, file_get_data(ef), file_get_size(ef)));
    if (ef == NULL) {
        ef = file_new(EF_OATH_CODE);
    }
    if (oath_write(ef, key, key_len, seal) != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    /* Every other session needs the new code; the one that set it stays
     * authorized, as on a YubiKey (it just proved the new key). The old
     * challenges are void. */
    for (int i = 0; i < OATH_SESSIONS; i++) {
        sess[i].code_itf = ITF_INVALID;
        random_gen(NULL, sess[i].challenge, CHALLENGE_LEN);
    }
    cur_sess()->code_itf = card_current_itf();
    return SW_OK();
}

/* RESET wipes every OATH credential, the access code and the OTP PIN, and
 * renews the namespace key (what the store may still hold of them cannot be
 * opened any more). Wiping needs a physical press, whatever the presence
 * policy says. */
int cmd_reset() {
    if (P1(apdu) != 0xde || P2(apdu) != 0xad) {
        return SW_INCORRECT_P1P2();
    }
    if (wait_button() == true) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    for (int i = 0; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file((uint16_t)(EF_OATH_CRED + i));
        if (file_has_data(ef)) {
            delete_file(ef);
        }
    }
    delete_file(search_dynamic_file(EF_OATH_CODE));
    flash_clear_file(search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF));
    sks_rotate(SKS_NS_OATH);
    low_flash_available();
    for (int i = 0; i < OATH_SESSIONS; i++) {
        sess_reset(&sess[i]);
    }
    verify_misses = 0;
    validate_misses = 0;
    return SW_OK();
}

static int oath_list_page(oath_sess_t *s) {
    for (uint16_t i = s->page.next; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file((uint16_t)(EF_OATH_CRED + i));
        oath_rec_t r;
        if (!file_has_data(ef) || !oath_rec_open(ef, &r)) {
            continue;
        }
        const oath_cred_t *c = &r.c;
        if (c->name == NULL || c->key == NULL || c->key_len == 0) {
            oath_rec_close(&r);
            continue;
        }
        uint16_t vlen = 1 + c->name_len + (s->page.ext ? 1 : 0);
        if (!res_fits(tlv_size(vlen))) {
            oath_rec_close(&r);
            if (res_APDU_size == 0) {
                continue;       /* can never fit (a record of older firmware) */
            }
            s->page.next = i;
            return oath_more_data(s);
        }
        res_APDU[res_APDU_size++] = TAG_NAME_LIST;
        res_APDU_size += format_tlv_len(vlen, res_APDU + res_APDU_size);
        res_APDU[res_APDU_size++] = c->key[0];
        memcpy(res_APDU + res_APDU_size, c->name, c->name_len);
        res_APDU_size += c->name_len;
        if (s->page.ext) {
            uint8_t props = 0x0;
            if (c->login || c->pw || c->meta) {
                props |= 0x4;
            }
            if (oath_touch(c)) {
                props |= 0x1;
            }
            res_APDU[res_APDU_size++] = props;
        }
        oath_rec_close(&r);
    }
    page_reset(s);
    apdu.ne = res_APDU_size;
    return SW_OK();
}

int cmd_list() {
    if (!oath_authorized()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    oath_sess_t *s = cur_sess();
    page_reset(s);
    s->page.ins = INS_LIST;
    s->page.ext = (apdu.nc == 1 && apdu.data[0] == 0x01);
    res_APDU_size = 0;
    return oath_list_page(s);
}

int cmd_validate() {
    oath_sess_t *s = cur_sess();
    const uint8_t *chal = NULL, *resp = NULL;
    uint16_t chal_len = 0, resp_len = 0;
    if (oath_find(apdu.data, apdu.nc, TAG_CHALLENGE, &chal, &chal_len) == false || chal_len == 0) {
        return SW_INCORRECT_PARAMS();
    }
    if (oath_find(apdu.data, apdu.nc, TAG_RESPONSE, &resp, &resp_len) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (!oath_has_code() || !s->chal_ok) {
        return SW_DATA_INVALID();
    }
    /* Online guessing of the password is limited per power cycle. */
    if (validate_misses >= OATH_VALIDATE_TRIES) {
        return SW_PIN_BLOCKED();
    }
    uint8_t *key = NULL;
    uint16_t key_len = 0;
    bool sealed = false;
    if (oath_read(search_dynamic_file(EF_OATH_CODE), &key, &key_len, &sealed) != PICOKEY_OK || key_len < 2) {
        oath_free(key, key_len);
        return SW_EXEC_ERROR();
    }
    int ret;
    uint8_t hmac[64];
    const mbedtls_md_info_t *md_info = get_oath_md_info(key[0]);
    if (md_info == NULL) {
        ret = SW_INCORRECT_PARAMS();
    }
    else if (!oath_code_response_ok(md_info, key + 1, key_len - 1, s->challenge, CHALLENGE_LEN, resp, resp_len)) {
        s->code_itf = ITF_INVALID;
        validate_misses++;
        ret = SW_DATA_INVALID();
    }
    else if (mbedtls_md_hmac(md_info, key + 1, key_len - 1, chal, chal_len, hmac) != 0) {
        ret = SW_EXEC_ERROR();
    }
    else {
        validate_misses = 0;
        /* One answer per challenge: the next VALIDATE needs a new SELECT. */
        random_gen(NULL, s->challenge, CHALLENGE_LEN);
        s->code_itf = card_current_itf();
        res_APDU_size = 0;
        res_put_tlv(TAG_RESPONSE, hmac, mbedtls_md_get_size(md_info));
        apdu.ne = res_APDU_size;
        ret = SW_OK();
    }
    mbedtls_platform_zeroize(hmac, sizeof(hmac));
    oath_free(key, key_len);
    return ret;
}

int cmd_calculate() {
    uint8_t p2 = P2(apdu);
    if (p2 != 0x0 && p2 != 0x1) {
        return SW_INCORRECT_P1P2();
    }
    if (!oath_authorized()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint16_t cmd_len = 0;
    uint8_t *cmd = oath_cmd_copy(&cmd_len);
    if (cmd == NULL) {
        return SW_MEMORY_FAILURE();
    }
    const uint8_t *name = NULL, *chal = NULL;
    uint16_t name_len = 0, chal_len = 0;
    oath_rec_t r;
    memset(&r, 0, sizeof(r));
    int ret;
    /* HOTP ignores the challenge; some clients send a bare tag for it. */
    bool has_chal = oath_find(cmd, cmd_len, TAG_CHALLENGE, &chal, &chal_len);
    if (oath_find(cmd, cmd_len, TAG_NAME, &name, &name_len) == false) {
        ret = SW_INCORRECT_PARAMS();
    }
    else if (!find_oath_cred(name, name_len, &r)) {
        ret = SW_DATA_INVALID();
    }
    else if (r.c.key == NULL || r.c.key_len < 2 || (r.c.imf && r.c.imf_len > OATH_IMF_MAX)) {
        ret = SW_DATA_INVALID();
    }
    else if ((r.c.key[0] & OATH_TYPE_MASK) != OATH_TYPE_HOTP && !has_chal) {
        ret = SW_INCORRECT_PARAMS();
    }
    else if ((ret = oath_presence(&r.c)) == PICOKEY_OK) {
        /* Only copies are used from here on: the record in RAM, the command
         * data and P2 (the transport may have received frames meanwhile). */
        bool hotp = (r.c.key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP;
        uint64_t imf = oath_imf(&r.c);
        uint8_t ctr[8];
        if (hotp) {
            put_uint64_t_be(imf, ctr);
            chal = ctr;
            chal_len = sizeof(ctr);
        }
        res_APDU_size = 0;
        res_APDU[res_APDU_size++] = TAG_RESPONSE + p2;
        if (calculate_oath(p2, r.c.key, r.c.key_len, chal, chal_len) != PICOKEY_OK) {
            ret = SW_EXEC_ERROR();
        }
        /* A HOTP code is only released once the next counter is stored. */
        else if (hotp && oath_rec_store(&r, &r.c, imf + 1) != PICOKEY_OK) {
            ret = SW_MEMORY_FAILURE();
        }
        else {
            apdu.ne = res_APDU_size;
            ret = SW_OK();
        }
    }
    oath_rec_close(&r);
    free(cmd);
    return ret;
}

static int oath_calc_all_page(oath_sess_t *s) {
    for (uint16_t i = s->page.next; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file((uint16_t)(EF_OATH_CRED + i));
        oath_rec_t r;
        if (!file_has_data(ef) || !oath_rec_open(ef, &r)) {
            continue;
        }
        const oath_cred_t *c = &r.c;
        if (c->name == NULL || c->key == NULL || c->key_len == 0) {
            oath_rec_close(&r);
            continue;
        }
        uint8_t digits = c->key_len >= 2 ? c->key[1] : 0;
        uint8_t rtag = TAG_RESPONSE + s->page.p2;
        uint16_t vsize = 2;     /* length and digits: no code */
        if ((c->key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
            rtag = TAG_NO_RESPONSE;
        }
        else if (oath_touch(c)) {
            /* never computed here: the host asks with CALCULATE, which waits for the touch */
            rtag = TAG_TOUCH_RESPONSE;
        }
        else if (c->key_len >= 2 && get_oath_md_info(c->key[0]) != NULL) {
            vsize = oath_value_size(s->page.p2, c->key);
        }
        if (!res_fits((uint32_t) tlv_size(c->name_len) + 1 + vsize)) {
            oath_rec_close(&r);
            if (res_APDU_size == 0) {
                continue;       /* can never fit (a record of older firmware) */
            }
            s->page.next = i;
            return oath_more_data(s);
        }
        res_put_tlv(TAG_NAME, c->name, c->name_len);
        res_APDU[res_APDU_size++] = rtag;
        if (vsize == 2 || calculate_oath(s->page.p2, c->key, c->key_len, s->page.chal, s->page.chal_len) != PICOKEY_OK) {
            res_APDU[res_APDU_size++] = 1;
            res_APDU[res_APDU_size++] = digits;
        }
        oath_rec_close(&r);
    }
    page_reset(s);
    apdu.ne = res_APDU_size;
    return SW_OK();
}

int cmd_calculate_all() {
    if (P2(apdu) != 0x0 && P2(apdu) != 0x1) {
        return SW_INCORRECT_P1P2();
    }
    if (!oath_authorized()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    const uint8_t *chal = NULL;
    uint16_t chal_len = 0;
    if (oath_find(apdu.data, apdu.nc, TAG_CHALLENGE, &chal, &chal_len) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (chal_len > OATH_CHAL_MAX) {
        return SW_WRONG_LENGTH();
    }
    oath_sess_t *s = cur_sess();
    page_reset(s);
    s->page.ins = INS_CALC_ALL;
    s->page.p2 = P2(apdu);
    s->page.chal_len = chal_len;
    memcpy(s->page.chal, chal, chal_len);
    res_APDU_size = 0;
    return oath_calc_all_page(s);
}

int cmd_send_remaining() {
    oath_sess_t *s = cur_sess();
    if (s->page.ins == 0 || s->page.itf != card_current_itf()) {
        page_reset(s);
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (!oath_authorized()) {
        page_reset(s);
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    res_APDU_size = 0;
    if (s->page.ins == INS_LIST) {
        return oath_list_page(s);
    }
    return oath_calc_all_page(s);
}

/* OTP PIN record: retry counter, then the PIN hash. */
#define OTP_PIN_REC_SIZE    33

/* Checks the OTP PIN. A try is spent (and stored) before the comparison; a
 * blocked PIN is never compared. Returns PICOKEY_OK or the status word. */
static int otp_pin_check(const uint8_t *pin, uint16_t pin_len) {
    oath_sess_t *s = cur_sess();
    file_t *ef = search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
    uint8_t rec[OTP_PIN_REC_SIZE] = { 0 }, hsh[32];
    uint8_t *stored = NULL;
    uint16_t stored_len = 0;
    bool sealed = false;
    if (oath_read(ef, &stored, &stored_len, &sealed) != PICOKEY_OK) {
        return file_has_data(ef) ? SW_EXEC_ERROR() : SW_CONDITIONS_NOT_SATISFIED();
    }
    memcpy(rec, stored, MIN(stored_len, sizeof(rec)));
    oath_free(stored, stored_len);
    sealed = sealed || oath_seal_new();
    int ret;
    if (rec[0] == 0) {
        s->pin_itf = ITF_INVALID;
        ret = SW_PIN_BLOCKED();
    }
    else {
        rec[0]--;
        if (oath_write(ef, rec, sizeof(rec), sealed) != PICOKEY_OK) {
            ret = SW_MEMORY_FAILURE();
        }
        else {
            double_hash_pin(pin, pin_len, hsh);
            bool ok = ct_memcmp(rec + 1, hsh, sizeof(hsh)) == 0;
            mbedtls_platform_zeroize(hsh, sizeof(hsh));
            if (!ok) {
                s->pin_itf = ITF_INVALID;
                ret = SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            else {
                rec[0] = MAX_OTP_COUNTER;
                ret = oath_write(ef, rec, sizeof(rec), sealed) != PICOKEY_OK ? SW_MEMORY_FAILURE() : PICOKEY_OK;
            }
        }
    }
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return ret;
}

static int otp_pin_store(const uint8_t *pin, uint16_t pin_len) {
    file_t *ef = search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
    bool seal = oath_seal_new() || (file_has_data(ef) && sks_is_sealed(SKS_NS_OATH, file_get_data(ef), file_get_size(ef)));
    uint8_t rec[OTP_PIN_REC_SIZE];
    rec[0] = MAX_OTP_COUNTER;
    double_hash_pin(pin, pin_len, rec + 1);
    int r = oath_write(ef, rec, sizeof(rec), seal);
    mbedtls_platform_zeroize(rec, sizeof(rec));
    if (r != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    for (int i = 0; i < OATH_SESSIONS; i++) {
        sess[i].pin_itf = ITF_INVALID;
    }
    return SW_OK();
}

static bool otp_pin_len_ok(uint16_t len) {
    return len >= 1 && len <= OATH_PIN_MAX;
}

int cmd_set_otp_pin() {
    if (!code_ok()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (oath_has_pin()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    const uint8_t *pw = NULL;
    uint16_t pw_len = 0;
    if (oath_find(apdu.data, apdu.nc, TAG_PASSWORD, &pw, &pw_len) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (!otp_pin_len_ok(pw_len)) {
        return SW_WRONG_LENGTH();
    }
    return otp_pin_store(pw, pw_len);
}

int cmd_change_otp_pin() {
    if (!code_ok()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (!oath_has_pin()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    const uint8_t *pw = NULL, *new_pw = NULL;
    uint16_t pw_len = 0, new_pw_len = 0;
    if (oath_find(apdu.data, apdu.nc, TAG_PASSWORD, &pw, &pw_len) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (oath_find(apdu.data, apdu.nc, TAG_NEW_PASSWORD, &new_pw, &new_pw_len) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (!otp_pin_len_ok(pw_len) || !otp_pin_len_ok(new_pw_len)) {
        return SW_WRONG_LENGTH();
    }
    int r = otp_pin_check(pw, pw_len);
    if (r != PICOKEY_OK) {
        return r;
    }
    return otp_pin_store(new_pw, new_pw_len);
}

int cmd_verify_otp_pin() {
    if (!oath_has_pin()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    const uint8_t *pw = NULL;
    uint16_t pw_len = 0;
    if (oath_find(apdu.data, apdu.nc, TAG_PASSWORD, &pw, &pw_len) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (!otp_pin_len_ok(pw_len)) {
        return SW_WRONG_LENGTH();
    }
    int r = otp_pin_check(pw, pw_len);
    if (r != PICOKEY_OK) {
        return r;
    }
    cur_sess()->pin_itf = card_current_itf();
    return SW_OK();
}

/* Verifies a HOTP code sent by the host (Nitrokey "reverse HOTP"). A match
 * within the look-ahead window moves the counter past it, so a code is
 * accepted once. */
int cmd_verify_hotp() {
    if (!oath_authorized()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint16_t cmd_len = 0;
    uint8_t *cmd = oath_cmd_copy(&cmd_len);
    if (cmd == NULL) {
        return SW_MEMORY_FAILURE();
    }
    const uint8_t *name = NULL, *code = NULL;
    uint16_t name_len = 0, code_len = 0;
    oath_rec_t r;
    memset(&r, 0, sizeof(r));
    int ret;
    if (oath_find(cmd, cmd_len, TAG_NAME, &name, &name_len) == false ||
        oath_find(cmd, cmd_len, TAG_RESPONSE, &code, &code_len) == false || code_len != 4) {
        ret = SW_INCORRECT_PARAMS();
    }
    else if (verify_misses >= OATH_VERIFY_TRIES) {
        ret = SW_PIN_BLOCKED();
    }
    else if (!find_oath_cred(name, name_len, &r)) {
        ret = SW_DATA_INVALID();
    }
    else if (r.c.key == NULL || r.c.key_len < 2 || (r.c.key[0] & OATH_TYPE_MASK) != OATH_TYPE_HOTP ||
             r.c.key[1] < 6 || r.c.key[1] > 8 || (r.c.imf && r.c.imf_len > OATH_IMF_MAX)) {
        ret = SW_DATA_INVALID();
    }
    else if ((ret = oath_presence(&r.c)) == PICOKEY_OK) {
        uint32_t mod = r.c.key[1] == 6 ? 1000000 : (r.c.key[1] == 7 ? 10000000 : 100000000);
        uint32_t want = get_uint32_t_be(code);
        uint64_t imf = oath_imf(&r.c);
        uint8_t hmac[64], ctr[8];
        int found = -1;
        ret = PICOKEY_OK;
        for (int w = 0; w <= OATH_VERIFY_WINDOW && ret == PICOKEY_OK; w++) {
            put_uint64_t_be(imf + w, ctr);
            size_t hlen = oath_hmac(r.c.key, r.c.key_len, ctr, sizeof(ctr), hmac);
            if (hlen == 0) {
                ret = SW_EXEC_ERROR();
            }
            else if (found < 0 && oath_truncate(hmac, hlen) % mod == want) {
                found = w;
            }
        }
        mbedtls_platform_zeroize(hmac, sizeof(hmac));
        if (ret != PICOKEY_OK) {
            /* ret holds the status word */
        }
        else if (found < 0) {
            verify_misses++;
            ret = SW_WRONG_DATA();
        }
        else if (oath_rec_store(&r, &r.c, imf + (uint64_t) found + 1) != PICOKEY_OK) {
            ret = SW_MEMORY_FAILURE();
        }
        else {
            verify_misses = 0;
            res_APDU_size = 0;
            apdu.ne = 0;
            ret = SW_OK();
        }
    }
    oath_rec_close(&r);
    free(cmd);
    return ret;
}

int cmd_rename() {
    if (!oath_authorized()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    /* Old name, then new name. */
    const uint8_t *p = apdu.data, *end = apdu.data + apdu.nc, *name = NULL, *new_name = NULL;
    uint16_t name_len = 0, new_name_len = 0;
    uint8_t tag = 0;
    if (apdu.nc == 0 || !oath_tlv_next(&p, end, &tag, &name, &name_len) || tag != TAG_NAME) {
        return SW_WRONG_DATA();
    }
    if (oath_find(p, (uint32_t)(end - p), TAG_NAME, &new_name, &new_name_len) == false) {
        return SW_WRONG_DATA();
    }
    if (new_name_len == 0 || new_name_len > OATH_NAME_MAX) {
        return SW_WRONG_DATA();
    }
    if (new_name_len == name_len && memcmp(name, new_name, name_len) == 0) {
        return SW_WRONG_DATA();
    }
    oath_rec_t r;
    if (find_oath_cred(new_name, new_name_len, &r)) {
        oath_rec_close(&r);
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (!find_oath_cred(name, name_len, &r)) {
        return SW_DATA_INVALID();
    }
    int ret;
    if (r.c.name == NULL || r.c.key == NULL) {
        ret = SW_DATA_INVALID();
    }
    else {
        oath_cred_t c = r.c;
        c.name = new_name;
        c.name_len = new_name_len;
        ret = oath_rec_store(&r, &c, oath_imf(&r.c)) != PICOKEY_OK ? SW_MEMORY_FAILURE() : SW_OK();
    }
    oath_rec_close(&r);
    return ret;
}

int cmd_get_credential() {
    if (!oath_authorized()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.nc < 3) {
        return SW_INCORRECT_PARAMS();
    }
    if (apdu.data[0] != TAG_NAME) {
        return SW_WRONG_DATA();
    }
    uint16_t cmd_len = 0;
    uint8_t *cmd = oath_cmd_copy(&cmd_len);
    if (cmd == NULL) {
        return SW_MEMORY_FAILURE();
    }
    const uint8_t *name = NULL;
    uint16_t name_len = 0;
    oath_rec_t r;
    memset(&r, 0, sizeof(r));
    int ret;
    if (oath_find(cmd, cmd_len, TAG_NAME, &name, &name_len) == false) {
        ret = SW_WRONG_DATA();
    }
    else if (!find_oath_cred(name, name_len, &r)) {
        ret = SW_DATA_INVALID();
    }
    /* The password-safe fields are the secret of such an entry: touch
     * protects them like a code. */
    else if ((ret = oath_presence(&r.c)) == PICOKEY_OK) {
        const oath_cred_t *c = &r.c;
        uint32_t size = (c->name ? tlv8_size(c->name_len) : 0) + (c->login ? tlv8_size(c->login_len) : 0) +
                        (c->pw ? tlv8_size(c->pw_len) : 0) + (c->meta ? tlv8_size(c->meta_len) : 0) +
                        (c->has_prop ? 3 : 0);
        res_APDU_size = 0;
        if (!res_fits(size)) {
            ret = SW_WRONG_LENGTH();
        }
        else {
            if (c->name) {
                res_put_tlv8(TAG_NAME, c->name, c->name_len);
            }
            if (c->login) {
                res_put_tlv8(TAG_PWS_LOGIN, c->login, c->login_len);
            }
            if (c->pw) {
                res_put_tlv8(TAG_PWS_PASSWORD, c->pw, c->pw_len);
            }
            if (c->meta) {
                res_put_tlv8(TAG_PWS_METADATA, c->meta, c->meta_len);
            }
            if (c->has_prop) {
                res_put_tlv8(TAG_PROPERTY, &c->prop, 1);
            }
            apdu.ne = res_APDU_size;
            ret = SW_OK();
        }
    }
    oath_rec_close(&r);
    free(cmd);
    return ret;
}

/* ------------------------------------------------------------------------ */
/* Single-key transfer (lf_keyio_oath.c)                                    */
/* ------------------------------------------------------------------------ */

/* The credentials a transfer carries: HOTP and TOTP accounts that PUT would
 * store as they are (their name is the key ID of the transfer). Entries of
 * the password safe without an OATH key are no OATH accounts, and a record
 * of older firmware that PUT would refuse could not be added anywhere. */
static bool oath_keyio_usable(const oath_cred_t *c) {
    if (c->name == NULL || c->name_len == 0 || c->name_len > OATH_NAME_MAX || c->key == NULL ||
        !oath_key_valid(c->key, c->key_len) || (c->imf && c->imf_len > OATH_IMF_MAX)) {
        return false;
    }
    uint8_t type = c->key[0] & OATH_TYPE_MASK;
    return type == OATH_TYPE_HOTP || type == OATH_TYPE_TOTP;
}

/* The transferable credential in credential file *index or the first one
 * after it: name (at most name_cap bytes), type/algorithm byte, digits and
 * touch property. *index is left at its file. false: there is none. */
bool oath_keyio_next(uint16_t *index, uint8_t *name, uint16_t name_cap, uint16_t *name_len, uint8_t *type_alg,
                     uint8_t *digits, bool *touch) {
    for (uint16_t i = *index; i < MAX_OATH_CRED; i++) {
        file_t *ef = search_dynamic_file((uint16_t)(EF_OATH_CRED + i));
        oath_rec_t r;
        if (!file_has_data(ef) || !oath_rec_open(ef, &r)) {
            continue;
        }
        bool found = oath_keyio_usable(&r.c) && r.c.name_len <= name_cap;
        if (found) {
            memcpy(name, r.c.name, r.c.name_len);
            *name_len = r.c.name_len;
            *type_alg = r.c.key[0];
            *digits = r.c.key[1];
            *touch = oath_touch(&r.c);
            *index = i;
        }
        oath_rec_close(&r);
        if (found) {
            return true;
        }
    }
    *index = MAX_OATH_CRED;
    return false;
}

/* LIST needs a secret: the OATH password or the OTP PIN is set. */
bool oath_keyio_protected(void) {
    return oath_has_code() || oath_has_pin();
}

/* Credential file of the credential with this name: PICOKEY_OK, or
 * PICOKEY_ERR_FILE_NOT_FOUND, or PICOKEY_WRONG_DATA when it is no
 * transferable credential. Nothing of the record is kept. */
int oath_keyio_find(const uint8_t *name, uint16_t name_len, uint16_t *index) {
    oath_rec_t r;
    if (name_len == 0 || name_len > OATH_NAME_MAX || !find_oath_cred(name, name_len, &r)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    bool usable = oath_keyio_usable(&r.c);
    *index = (uint16_t)(r.ef->fid - EF_OATH_CRED);
    oath_rec_close(&r);
    return usable ? PICOKEY_OK : PICOKEY_WRONG_DATA;
}

/* The credential in file index, when it (still) has this name: its key as
 * stored (type/algorithm, digits, secret; at most key_cap bytes), the HOTP
 * moving factor (0 for TOTP) and the touch property. The caller wipes key. */
int oath_keyio_read(uint16_t index, const uint8_t *name, uint16_t name_len, uint8_t *key, uint16_t key_cap,
                    uint16_t *key_len, uint64_t *imf, bool *touch) {
    file_t *ef = index < MAX_OATH_CRED ? search_dynamic_file((uint16_t)(EF_OATH_CRED + index)) : NULL;
    oath_rec_t r;
    if (!file_has_data(ef) || !oath_rec_open(ef, &r)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    int ret = PICOKEY_OK;
    if (!oath_keyio_usable(&r.c) || r.c.name_len != name_len || memcmp(r.c.name, name, name_len) != 0) {
        ret = PICOKEY_ERR_FILE_NOT_FOUND;
    }
    else if (r.c.key_len > key_cap) {
        ret = PICOKEY_ERR_NO_MEMORY;
    }
    else {
        memcpy(key, r.c.key, r.c.key_len);
        *key_len = r.c.key_len;
        *imf = (r.c.key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP ? oath_imf(&r.c) : 0;
        *touch = oath_touch(&r.c);
    }
    oath_rec_close(&r);
    return ret;
}

static const cmd_t cmds[] = {
    { INS_PUT, cmd_put },
    { INS_DELETE, cmd_delete },
    { INS_SET_CODE, cmd_set_code },
    { INS_RESET, cmd_reset },
    { INS_RENAME, cmd_rename },
    { INS_LIST, cmd_list },
    { INS_VALIDATE, cmd_validate },
    { INS_CALCULATE, cmd_calculate },
    { INS_CALC_ALL, cmd_calculate_all },
    { INS_SEND_REMAINING, cmd_send_remaining },
    { INS_SET_PIN, cmd_set_otp_pin },
    { INS_CHANGE_PIN, cmd_change_otp_pin },
    { INS_VERIFY_PIN, cmd_verify_otp_pin },
    { INS_VERIFY_CODE, cmd_verify_hotp },
    { INS_GET_CREDENTIAL, cmd_get_credential },
    { 0x00, 0x0 }
};

int oath_process_apdu() {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    /* Key store locked (chip not ready in a HARDENED build, root key held):
     * no record is used, not even one of earlier firmware in plaintext. */
    if (!security_keystore_unlocked()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    oath_sess_t *s = cur_sess();
    bool hid = s == &sess[OATH_SESS_HID];
    if (hid && board_millis() - s->last_ms > oath_hid_idle_ms()) {
        sess_logout(s);
    }
    /* A pending LIST / CALCULATE ALL answer only survives until the next command. */
    if (INS(apdu) != INS_SEND_REMAINING) {
        page_reset(s);
    }
    const cmd_t *handler = NULL;
    if (cap_supported(CAP_OATH)) {
        for (const cmd_t *cmd = cmds; cmd->ins != 0x00 && handler == NULL; cmd++) {
            if (cmd->ins == INS(apdu)) {
                handler = cmd;
            }
        }
    }
    int r;
    if (handler) {
        oath_migrate();
        r = handler->cmd_handler();
    }
    else {
        r = SW_INS_NOT_SUPPORTED();
    }
    if (hid) {
        s->last_ms = board_millis();
    }
    return r;
}
