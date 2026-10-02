/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
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

#include <stdio.h>
#include <string.h>
#include "pico_keys.h"
#include "apdu.h"
#include "usb.h"
#include "cbor.h"
#include "crypto_utils.h"
#include "profile.h"
#include "security.h"
#include "phy.h"
#include "mbedtls/platform_util.h"
#include "lf_backup.h"
#include "lf_boot.h"
#include "lf_fw.h"
#include "lf_keyio.h"
#include "low_flash.h"
#include "lf_mgmt.h"
#include "lf_policy.h"
#include "lf_profile.h"
#include "lf_store.h"
#include "lf_sys.h"
#include "random.h"

#if defined(ESP_PLATFORM)
#include "esp_system.h"
#include "soc/rtc_cntl_reg.h"
#endif

extern uint32_t flash_free_space(void);
extern uint32_t flash_used_space(void);
extern uint32_t flash_total_space(void);
extern uint32_t flash_num_files(void);

#define LF_MGMT_PROTOCOL    3
#define RESP_MAX            (APDU_RES_BUF_SIZE - 16)
#define SESS_ID_LEN         8
#define PIN_MAX             64
#define KEY_SECRET_MAX      127     /* longest application secret: an OpenPGP PW3 */
#define AUTO_MASK_ALL       ((1u << LF_APP_COUNT) - 1)
#define LED_BRIGHTNESS_FULL 255

static const uint8_t mgmt_aid[] = {
    10, 0xF0, 'L', 'I', 'B', 'R', 'E', 'F', 'I', 'D', 'O'
};

static lf_mgmt_pin_cb_t pin_cb = NULL;
static lf_mgmt_aaguid_get_cb_t aaguid_get_cb = NULL;
static lf_mgmt_aaguid_set_cb_t aaguid_set_cb = NULL;

enum { SESS_NONE, SESS_EXPORT, SESS_IMPORT, SESS_FW, SESS_LIST };
static uint8_t sess = SESS_NONE;
static uint8_t sess_itf = 0;                /* USB interface that started it */
static uint8_t sess_id[SESS_ID_LEN];        /* random, answered by the BEGIN */
static uint8_t list_app = 0;                /* SESS_LIST: the application listed */
static uint32_t list_next = 0;              /* SESS_LIST: the only page that may follow */
static uint32_t list_opened_ms = 0;         /* SESS_LIST: when its first page was answered */
static bool list_pin_verified = false;      /* SESS_LIST: its first page had a verified FIDO PIN */
static uint8_t import_target = 0;
static bool import_verify_only = false;
static bool import_restore_test = false;
static bool import_plain = false;           /* checked on the fly, nothing staged */
static uint32_t import_next = 0;
static lfbk_check_t import_check;
static bool fw_allow_downgrade = false;

void lf_mgmt_set_pin_verifier(lf_mgmt_pin_cb_t cb) {
    pin_cb = cb;
}

void lf_mgmt_set_aaguid_hooks(lf_mgmt_aaguid_get_cb_t get_cb, lf_mgmt_aaguid_set_cb_t set_cb) {
    aaguid_get_cb = get_cb;
    aaguid_set_cb = set_cb;
}

/* The system area was read (normal boot, or safe mode after a failed
 * migration/mount): what it holds can be reported. */
static bool sys_usable(void) {
    lf_boot_status_t b = lf_boot_status();
    return b != LF_BOOT_ERR_LAYOUT && b != LF_BOOT_ERR_SYS;
}

/* The system area may be changed: after a normal boot, or when only the
 * active profile cannot be mounted (another one can be selected, the broken
 * one wiped). After a failed migration it holds defaults that were never
 * written; writing them would stop the migration from ever being tried
 * again, and the legacy credentials would stay out of reach. */
static bool sys_writable(void) {
    lf_boot_status_t b = lf_boot_status();
    return b == LF_BOOT_OK || b == LF_BOOT_ERR_MOUNT;
}

static void end_session(void) {
    if (sess == SESS_FW) {
        lf_fw_abort();
    }
    else if (sess == SESS_IMPORT && import_plain) {
        lf_backup_check_abort(&import_check);
    }
    else if (sess == SESS_EXPORT || sess == SESS_IMPORT) {
        lf_stage_clear();       /* exports and imports hold keys in the clear */
    }
    sess = SESS_NONE;           /* a listing (SESS_LIST) holds nothing but its ID */
    import_plain = false;
    list_app = 0;
    list_next = 0;
    list_opened_ms = 0;
    list_pin_verified = false;
    mbedtls_platform_zeroize(sess_id, sizeof(sess_id));
}

/* The transfer (or the listing) belongs to the client that started it: its
 * interface, and the random ID the BEGIN (the first KEY_LIST page)
 * answered (a second client on the same reader cannot know it). */
static void open_session(uint8_t kind) {
    sess = kind;
    sess_itf = card_current_itf();
    random_gen(NULL, sess_id, sizeof(sess_id));
}

static bool session_id_ok(const uint8_t *id) {
    return ct_memcmp(id, sess_id, SESS_ID_LEN) == 0;
}

static int update_authorized(const uint8_t *pin, uint16_t pin_len);

/* A physical touch collected for this command only (up.h): never granted
 * by automatic presence (lf_policy.h). */
static bool touched(void) {
    return wait_button() == false;
}

/* A profile switch, import or wipe waits for its reboot: the mounted profile
 * is about to change, so no transfer may start. */
static bool reboot_pending(void) {
    return lf_reboot_scheduled() || (sys_usable() && lf_sys()->pending_op != LF_OP_NONE);
}

static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
}

/* PINs travel in the command data: not left in the receive buffer. */
static void wipe_data(void) {
    if (apdu.data && apdu.nc) {
        mbedtls_platform_zeroize(apdu.data, apdu.nc);
    }
}

static int finish_cbor(CborEncoder *enc, CborError err) {
    if (err != CborNoError) {
        res_APDU_size = 0;
        return SW_EXEC_ERROR();
    }
    res_APDU_size = (uint16_t) cbor_encoder_get_buffer_size(enc, res_APDU);
    return SW_OK();
}

/* Answer of IMPORT_BEGIN and FW_BEGIN: {1: session ID}. */
static int answer_session_id(void) {
    CborEncoder enc, map;
    CborError e = CborNoError;
    cbor_encoder_init(&enc, res_APDU, RESP_MAX, 0);
    e |= cbor_encoder_create_map(&enc, &map, 1);
    e |= cbor_encode_uint(&map, 1);
    e |= cbor_encode_byte_string(&map, sess_id, sizeof(sess_id));
    e |= cbor_encoder_close_container(&enc, &map);
    return finish_cbor(&enc, e);
}

/* ------------------------------------------------------------------------ */

static bool profile_secure(uint8_t idx) {
    const lf_profile_entry_t *p = &lf_sys()->profile[idx];
    return p->used && (p->flags & LF_PROFILE_F_SECURE);
}

static uint8_t auto_mask(uint8_t flags) {
    return (uint8_t) ((flags & LF_PROFILE_F_AUTO_ALL) / LF_PROFILE_F_AUTO_FIDO);
}

static CborError encode_profile(CborEncoder *arr, uint8_t i) {
    CborError e = CborNoError;
    CborEncoder m;
    const lf_profile_entry_t *p = &lf_sys()->profile[i];
    /* A text string must be valid UTF-8 (strict decoders refuse the whole
     * answer otherwise); older firmware could store a cut character. */
    char name[LF_PROFILE_NAME_MAX];
    memcpy(name, p->name, sizeof(name));
    lf_profile_name_sanitize(name, sizeof(name));
    /* Key 9 (AAGUID) is the mounted profile's own file, so it can only be
     * read while that profile's store is mounted: an empty byte string for
     * every other slot, and for the mounted one when no hook is registered
     * (a build without the application's FIDO applet). */
    uint8_t aaguid[16];
    bool have_aaguid = aaguid_get_cb && i == lf_profile_mounted() &&
                       aaguid_get_cb(aaguid) == PICOKEY_OK;
    e |= cbor_encoder_create_map(arr, &m, 9);
    e |= cbor_encode_uint(&m, 1);
    e |= cbor_encode_uint(&m, i);
    e |= cbor_encode_uint(&m, 2);
    e |= cbor_encode_boolean(&m, p->used != 0);
    e |= cbor_encode_uint(&m, 3);
    e |= cbor_encode_text_stringz(&m, name);
    e |= cbor_encode_uint(&m, 4);
    e |= cbor_encode_byte_string(&m, p->color, 3);
    e |= cbor_encode_uint(&m, 5);
    e |= cbor_encode_byte_string(&m, p->uuid, 16);
    e |= cbor_encode_uint(&m, 6);
    e |= cbor_encode_uint(&m, p->flags);
    e |= cbor_encode_uint(&m, 7);
    e |= cbor_encode_uint(&m, auto_mask(p->flags));
    e |= cbor_encode_uint(&m, 8);
    e |= cbor_encode_boolean(&m, (p->flags & LF_PROFILE_F_SECURE) != 0);
    e |= cbor_encode_uint(&m, 9);
    e |= cbor_encode_byte_string(&m, aaguid, have_aaguid ? sizeof(aaguid) : 0);
    e |= cbor_encoder_close_container(arr, &m);
    return e;
}

/* The export is of the mounted profile, even after a switch was recorded. */
static bool export_allowed(void) {
    uint8_t flags = lf_sys()->profile[lf_profile_mounted()].flags;
    return LF_ALLOW_SECRET_EXPORT && !(flags & (LF_PROFILE_F_NO_EXPORT | LF_PROFILE_F_SECURE));
}

static CborError encode_fw(CborEncoder *map) {
    CborError e = CborNoError;
    CborEncoder fw;
    lf_fw_status_t st;
    lf_fw_status(&st);
    e |= cbor_encode_uint(map, 16);
    e |= cbor_encoder_create_map(map, &fw, 6);
    e |= cbor_encode_uint(&fw, 1);
    e |= cbor_encode_byte_string(&fw, lf_fw_desc.version, 3);
    e |= cbor_encode_uint(&fw, 2);
    e |= cbor_encode_uint(&fw, lf_fw_desc.platform);
    e |= cbor_encode_uint(&fw, 3);
    e |= cbor_encode_text_string(&fw, lf_fw_desc.board, strnlen(lf_fw_desc.board, sizeof(lf_fw_desc.board)));
    e |= cbor_encode_uint(&fw, 4);
    e |= cbor_encode_uint(&fw, st.slot);
    e |= cbor_encode_uint(&fw, 5);
    e |= cbor_encode_boolean(&fw, st.pending);
    e |= cbor_encode_uint(&fw, 6);
    e |= cbor_encode_boolean(&fw, st.rollback_possible);
    e |= cbor_encoder_close_container(map, &fw);
    return e;
}

/* Board settings as recorded in the system area. */
static CborError encode_board(CborEncoder *map) {
    CborError e = CborNoError;
    CborEncoder b;
    phy_data_t rec;
    memset(&rec, 0, sizeof(rec));
    const lf_sys_t *s = lf_sys();
    if (s->board_len > 0 && s->board_len <= LF_BOARD_MAX) {
        phy_unserialize_data(s->board, s->board_len, &rec);
    }
    e |= cbor_encode_uint(map, 17);
    e |= cbor_encoder_create_map(map, &b, 1);
    e |= cbor_encode_uint(&b, 1);
    e |= cbor_encode_uint(&b, rec.led_brightness_present ? rec.led_brightness : LED_BRIGHTNESS_FULL);
    e |= cbor_encoder_close_container(map, &b);
    return e;
}

/* Single-key transfer (lf_keyio.h): {1: export mask, 2: import mask}, bit n
 * for application n with the hook. Older firmware has no key 19. */
static CborError encode_keyio(CborEncoder *map) {
    CborError e = CborNoError;
    CborEncoder k;
    uint8_t exp = 0, imp = 0;
    for (uint8_t a = 0; a < LF_APP_COUNT; a++) {
        const lf_keyio_ops_t *ops = lf_keyio_ops(a);
        if (ops && ops->export_key) {
            exp |= (uint8_t) (1u << a);
        }
        if (ops && ops->import_key) {
            imp |= (uint8_t) (1u << a);
        }
    }
    e |= cbor_encode_uint(map, 19);
    e |= cbor_encoder_create_map(map, &k, 2);
    e |= cbor_encode_uint(&k, 1);
    e |= cbor_encode_uint(&k, exp);
    e |= cbor_encode_uint(&k, 2);
    e |= cbor_encode_uint(&k, imp);
    e |= cbor_encoder_close_container(map, &k);
    return e;
}

static int cmd_info(void) {
    CborEncoder enc, map, arr, sec;
    CborError e = CborNoError;
    const security_state_t *ss = security_state();
    const char *boot = lf_boot_status_str(lf_boot_status());
    bool sys = sys_usable();
    cbor_encoder_init(&enc, res_APDU, RESP_MAX, 0);
    char version[12];
    snprintf(version, sizeof(version), "%u.%u.%u", lf_fw_desc.version[0], lf_fw_desc.version[1], lf_fw_desc.version[2]);
    e |= cbor_encoder_create_map(&enc, &map, sys ? 19 : 10);
    e |= cbor_encode_uint(&map, 1);
    e |= cbor_encode_text_stringz(&map, version);
    e |= cbor_encode_uint(&map, 2);
    e |= cbor_encode_uint(&map, LF_MGMT_PROTOCOL);
    e |= cbor_encode_uint(&map, 3);
    e |= cbor_encode_byte_string(&map, pico_chip_serial.id, sizeof(pico_chip_serial.id));
    e |= cbor_encode_uint(&map, 4);
    e |= cbor_encode_byte_string(&map, pico_serial.id, sizeof(pico_serial.id));
    e |= cbor_encode_uint(&map, 5);
    e |= cbor_encode_uint(&map, lf_boot_status());
    e |= cbor_encode_uint(&map, 6);
    e |= cbor_encode_text_stringz(&map, boot);
    e |= cbor_encode_uint(&map, 7);
    e |= cbor_encode_text_stringz(&map, LF_PROFILE_NAME);
    e |= cbor_encode_uint(&map, 8);
    e |= cbor_encoder_create_map(&map, &sec, 9);
    e |= cbor_encode_uint(&sec, 1);
    e |= cbor_encode_boolean(&sec, ss->secure_boot);
    e |= cbor_encode_uint(&sec, 2);
    e |= cbor_encode_boolean(&sec, ss->flash_encryption);
    e |= cbor_encode_uint(&sec, 3);
    e |= cbor_encode_boolean(&sec, ss->flash_enc_release);
    e |= cbor_encode_uint(&sec, 4);
    e |= cbor_encode_boolean(&sec, ss->jtag_disabled);
    e |= cbor_encode_uint(&sec, 5);
    e |= cbor_encode_boolean(&sec, ss->download_restricted);
    e |= cbor_encode_uint(&sec, 6);
    e |= cbor_encode_boolean(&sec, ss->anti_rollback);
    e |= cbor_encode_uint(&sec, 7);
    e |= cbor_encode_boolean(&sec, ss->hmac_key);
    e |= cbor_encode_uint(&sec, 8);
    e |= cbor_encode_uint(&sec, ss->drk_source);
    /* 9: the key store of the mounted profile is unlocked (a held or
     * unwrappable root key, or an incomplete HARDENED chip, locks it) */
    e |= cbor_encode_uint(&sec, 9);
    e |= cbor_encode_boolean(&sec, security_keystore_unlocked());
    e |= cbor_encoder_close_container(&map, &sec);
    e |= encode_fw(&map);
    if (sys) {
        lf_sys_t *s = lf_sys();
        e |= cbor_encode_uint(&map, 9);
        e |= cbor_encode_uint(&map, s->active);
        e |= cbor_encode_uint(&map, 10);
        e |= cbor_encode_uint(&map, s->button_slots);
        e |= cbor_encode_uint(&map, 11);
        e |= cbor_encode_uint(&map, s->last_result);
        e |= cbor_encode_uint(&map, 12);
        e |= cbor_encode_uint(&map, s->pending_op);
        e |= cbor_encode_uint(&map, 13);
        e |= cbor_encode_boolean(&map, (s->flags & LF_SYS_F_MIGRATED) != 0);
        e |= cbor_encode_uint(&map, 14);
        e |= cbor_encode_boolean(&map, export_allowed());
        e |= cbor_encode_uint(&map, 15);
        e |= cbor_encoder_create_array(&map, &arr, LF_MAX_PROFILES);
        for (uint8_t i = 0; i < LF_MAX_PROFILES; i++) {
            e |= encode_profile(&arr, i);
        }
        e |= cbor_encoder_close_container(&map, &arr);
        e |= encode_board(&map);
        e |= cbor_encode_uint(&map, 18);
        e |= cbor_encode_uint(&map, lf_sys_free_changes());
    }
    e |= encode_keyio(&map);
    e |= cbor_encoder_close_container(&enc, &map);
    return finish_cbor(&enc, e);
}

static int cmd_health(void) {
    if (P1(apdu) == 1 && lf_storage_ready()) {
        lf_store_scrub();
    }
    const lf_health_t *h = lf_store_health();
    bool ready = lf_storage_ready();
    CborEncoder enc, map;
    CborError e = CborNoError;
    cbor_encoder_init(&enc, res_APDU, RESP_MAX, 0);
    e |= cbor_encoder_create_map(&enc, &map, 20);
    const uint64_t vals[] = {
        h->generation, h->sectors_checked, h->sectors_written, h->repaired_from_copy, h->corrected_ecc,
        h->ecc_bytes_corrected, h->uncorrectable, h->meta_repaired, h->served_from_b, h->journal_replayed,
        h->journal_corrupt, h->commit_failures, h->max_erase_count, h->total_erase_count,
        sys_usable() ? lf_sys()->repairs : 0, sys_usable() ? lf_sys()->uncorrectable : 0,
        ready ? flash_used_space() : 0, ready ? flash_total_space() : 0, ready ? flash_num_files() : 0,
        sys_usable() ? lf_sys_bad_copies() : 0
    };
    for (uint8_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        e |= cbor_encode_uint(&map, i + 1);
        e |= cbor_encode_uint(&map, vals[i]);
    }
    e |= cbor_encoder_close_container(&enc, &map);
    return finish_cbor(&enc, e);
}

/* ------------------------------------------------------------------------ */

/* Commands that change the system area: P1 is a profile slot. After a
 * factory reset (or anything else that waits for its reboot) nothing is
 * written any more (the record in RAM may describe erased stores). */
static int sys_command_check(uint8_t idx) {
    if (!sys_writable() || idx >= LF_MAX_PROFILES) {
        return SW_INCORRECT_P1P2();
    }
    if (lf_reboot_scheduled()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    return SW_OK();
}

/* Switching changes which keys the host talks to, so the user confirms it:
 * otherwise a host could make an imported profile, or a new one without the
 * PIN, the active one. Selecting the active profile does nothing. */
static int cmd_profile_select(void) {
    uint8_t idx = P1(apdu);
    int sw = sys_command_check(idx);
    if (sw != 0x9000) {
        return sw;
    }
    const lf_sys_t *s = lf_sys();
    if (idx == s->active && s->profile[idx].used) {
        return SW_OK();
    }
    if (s->pending_op != LF_OP_NONE) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (!touched()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    int r = lf_profile_select(idx);
    if (r != PICOKEY_OK) {
        return r == PICOKEY_ERR_BLOCKED ? SW_CONDITIONS_NOT_SATISFIED() : SW_MEMORY_FAILURE();
    }
    lf_reboot_later(300);
    return SW_OK();
}

/* The data of a command that takes a CBOR map: exactly one well-formed map,
 * without tags or indefinite lengths, entered (it: at its first key). A tag
 * is no item of its own for tinycbor: a tagged value would be read as the
 * next key, and an iterator could then run past the end of the map. The
 * records of KEY_IMPORT (lf_keyio.h) are inside, so checked too. */
static bool mgmt_cbor_open(CborParser *parser, CborValue *map, CborValue *it) {
    return cbor_parser_init(apdu.data, apdu.nc, 0, parser, map) == CborNoError &&
           cbor_value_validate(map, CborValidateBasic | CborValidateNoTags |
                               CborValidateNoIndeterminateLength) == CborNoError &&
           cbor_value_is_map(map) && cbor_value_enter_container(map, it) == CborNoError;
}

/* Skips the value of a key the command does not take: never a tag, never
 * past the end of the map (a key without a value). */
static bool mgmt_cbor_skip(CborValue *it) {
    return !cbor_value_at_end(it) && !cbor_value_is_tag(it) && cbor_value_advance(it) == CborNoError;
}

/* Data: CBOR {1: name (UTF-8, at most 23 bytes), 2: RGB (3 bytes),
 * 3: flags (only LF_PROFILE_F_NO_EXPORT is taken), 4: automatic presence
 * (bit i: application i of lf_app_t)}. Allowing export again and switching
 * automatic presence on for an application need a physical touch, and are
 * refused (6986) for a secure profile and in HARDENED builds; the rest
 * counts against the free allowance. */
static int cmd_profile_set(void) {
    uint8_t idx = P1(apdu);
    int sw = sys_command_check(idx);
    if (sw != 0x9000) {
        return sw;
    }
    CborParser parser;
    CborValue map, it;
    char name[LF_PROFILE_NAME_MAX + 1];
    uint8_t rgb[3];
    bool have_name = false, have_rgb = false;
    int no_export = -1;
    int64_t presence = -1;
    if (!mgmt_cbor_open(&parser, &map, &it)) {
        return SW_WRONG_DATA();
    }
    while (!cbor_value_at_end(&it)) {
        uint64_t k = 0;
        if (!cbor_value_is_unsigned_integer(&it) || cbor_value_get_uint64(&it, &k) != CborNoError ||
            cbor_value_advance_fixed(&it) != CborNoError) {
            return SW_WRONG_DATA();
        }
        if (k == 1 && cbor_value_is_text_string(&it)) {
            size_t n = sizeof(name);
            if (cbor_value_copy_text_string(&it, name, &n, &it) != CborNoError || n >= LF_PROFILE_NAME_MAX) {
                return SW_WRONG_DATA();     /* longer than a profile name */
            }
            if (!lf_profile_name_valid(name, n)) {
                return SW_INCORRECT_PARAMS();   /* not UTF-8, or a NUL inside */
            }
            name[n] = 0;
            have_name = true;
        }
        else if (k == 2 && cbor_value_is_byte_string(&it)) {
            size_t n = sizeof(rgb);
            if (cbor_value_copy_byte_string(&it, rgb, &n, &it) != CborNoError || n != 3) {
                return SW_WRONG_DATA();
            }
            have_rgb = true;
        }
        else if ((k == 3 || k == 4) && cbor_value_is_unsigned_integer(&it)) {
            uint64_t f = 0;
            cbor_value_get_uint64(&it, &f);
            if (k == 3) {
                no_export = (f & LF_PROFILE_F_NO_EXPORT) != 0;
            }
            else if (f & ~(uint64_t) AUTO_MASK_ALL) {
                return SW_INCORRECT_PARAMS();   /* no such application */
            }
            else {
                presence = (int64_t) f;
            }
            cbor_value_advance_fixed(&it);
        }
        else if (!mgmt_cbor_skip(&it)) {
            return SW_WRONG_DATA();
        }
    }
    const lf_profile_entry_t *p = &lf_sys()->profile[idx];
    bool secure = (p->flags & LF_PROFILE_F_SECURE) != 0;
    uint8_t flags = p->flags;
    bool needs_touch = false;
    if (no_export >= 0) {
        if (!no_export && (p->flags & LF_PROFILE_F_NO_EXPORT)) {
            if (secure) {
                return SW_COMMAND_NOT_ALLOWED();    /* keys never leave it */
            }
            needs_touch = true;
        }
        flags = (uint8_t) ((flags & ~LF_PROFILE_F_NO_EXPORT) | (no_export ? LF_PROFILE_F_NO_EXPORT : 0));
    }
    if (presence >= 0) {
        uint8_t bits = (uint8_t) (presence * LF_PROFILE_F_AUTO_FIDO);
        if (bits & ~p->flags) {
#if defined(LF_PROFILE_HARDENED)
            return SW_COMMAND_NOT_ALLOWED();
#else
            if (secure) {
                return SW_COMMAND_NOT_ALLOWED();    /* every presence is a press */
            }
            needs_touch = true;
#endif
        }
        flags = (uint8_t) ((flags & ~LF_PROFILE_F_AUTO_ALL) | bits);
    }
    int new_flags = no_export >= 0 || presence >= 0 ? flags : -1;
    const char *nm = have_name ? name : NULL;
    const uint8_t *col = have_rgb ? rgb : NULL;
    if (!lf_profile_differs(idx, nm, col, new_flags)) {
        return SW_OK();                     /* nothing to write */
    }
    if (needs_touch) {
        if (!touched()) {
            return SW_CONDITIONS_NOT_SATISFIED();
        }
        lf_sys_change_confirmed();
    }
    else if (!lf_sys_change_allowed()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (lf_profile_set(idx, nm, col, new_flags) != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    return SW_OK();
}

/* Both destroy a profile or make one (and restart): always a touch. */
static int cmd_profile_wipe_delete(void) {
    uint8_t idx = P1(apdu);
    int sw = sys_command_check(idx);
    if (sw != 0x9000) {
        return sw;
    }
    bool del = INS(apdu) == LF_MGMT_INS_PROFILE_DELETE;
    const lf_sys_t *s = lf_sys();
    bool used = s->profile[idx].used;
    if (del && !used) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (s->pending_op != LF_OP_NONE) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (!touched()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    /* A new profile in an empty slot starts without any policy; a wiped one
     * keeps being secure if it was (lf_boot.c). */
    int r = del ? lf_profile_request(LF_OP_DELETE, idx) :
            (used ? lf_profile_request(LF_OP_WIPE, idx) : lf_profile_create(idx, 0));
    if (r == PICOKEY_ERR_BLOCKED) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (r != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    lf_reboot_later(300);
    return SW_OK();
}

/* P1: slot. A new, empty secure profile (lf_policy.h), replacing what the
 * slot holds: keys never leave it, it is never imported into, every
 * presence request needs a press, and its root key is wrapped by the chip's
 * HMAC eFuse key from the moment it is made (hence 6982 without that key:
 * PROVISION first). HARDENED builds refuse (6986): there every profile is
 * treated as secure for exports and presence already, and none carries the
 * "never imported" promise (see cmd_import_begin()). */
static int cmd_profile_create_secure(void) {
    uint8_t idx = P1(apdu);
    int sw = sys_command_check(idx);
    if (sw != 0x9000) {
        return sw;
    }
#if defined(LF_PROFILE_HARDENED)
    return SW_COMMAND_NOT_ALLOWED();
#else
    if (lf_sys()->pending_op != LF_OP_NONE) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (!security_hmac_key_available()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (!touched()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    int r = lf_profile_create(idx, LF_PROFILE_F_NO_EXPORT | LF_PROFILE_F_SECURE);
    if (r == PICOKEY_ERR_BLOCKED) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (r != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    lf_reboot_later(300);
    return SW_OK();
#endif
}

static int cmd_button_slots(void) {
    uint8_t n = P1(apdu);
    if (n < 1 || n > LF_MAX_PROFILES) {
        return SW_INCORRECT_P1P2();
    }
    int sw = sys_command_check(0);
    if (sw != 0x9000) {
        return sw;
    }
    lf_sys_t *s = lf_sys();
    if (s->button_slots == n) {
        return SW_OK();                     /* nothing to write */
    }
    if (!lf_sys_change_allowed()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    uint8_t old = s->button_slots;
    s->button_slots = n;
    if (lf_sys_commit() != PICOKEY_OK) {
        s->button_slots = old;
        return SW_MEMORY_FAILURE();
    }
    return SW_OK();
}

/* Data: CBOR {1: LED brightness 0..255}. Board settings are device wide
 * and applied at once; written through phy_save() (only a real change,
 * counted against the free allowance). */
static int cmd_board_set(void) {
    int sw = sys_command_check(0);
    if (sw != 0x9000) {
        return sw;
    }
    if (lf_boot_status() != LF_BOOT_OK) {
        return SW_CONDITIONS_NOT_SATISFIED();   /* settings were not loaded */
    }
    CborParser parser;
    CborValue map, it;
    int brightness = -1;
    if (!mgmt_cbor_open(&parser, &map, &it)) {
        return SW_WRONG_DATA();
    }
    while (!cbor_value_at_end(&it)) {
        uint64_t k = 0;
        if (!cbor_value_is_unsigned_integer(&it) || cbor_value_get_uint64(&it, &k) != CborNoError ||
            cbor_value_advance_fixed(&it) != CborNoError) {
            return SW_WRONG_DATA();
        }
        if (k == 1) {
            uint64_t v = 0;
            if (!cbor_value_is_unsigned_integer(&it) || cbor_value_get_uint64(&it, &v) != CborNoError || v > 255) {
                return SW_INCORRECT_PARAMS();
            }
            brightness = (int) v;
            cbor_value_advance_fixed(&it);
        }
        else if (!mgmt_cbor_skip(&it)) {
            return SW_WRONG_DATA();
        }
    }
    if (brightness < 0) {
        return SW_OK();
    }
    phy_ensure_loaded();
    phy_data.led_brightness = (uint8_t) brightness;
    phy_data.led_brightness_present = true;
    int r = phy_save();
    if (r != PICOKEY_OK) {
        return r == PICOKEY_ERR_BLOCKED ? SW_CONDITIONS_NOT_SATISFIED() : SW_MEMORY_FAILURE();
    }
    return SW_OK();
}

/* Data: CBOR {1: bytes(16)}, or {} (key 1 absent) to go back to the
 * application's default. Changes the AAGUID the mounted profile reports in
 * every attestation from now on: always a touch, whatever the profile's
 * export policy (identity, not a secret). The application (pico-fido)
 * decides where the value is kept; here it is only forwarded. */
static int cmd_profile_aaguid_set(void) {
    if (!aaguid_set_cb) {
        return SW_INS_NOT_SUPPORTED();
    }
    if (lf_reboot_scheduled()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (!security_keystore_unlocked()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    CborParser parser;
    CborValue map, it;
    uint8_t aaguid[16];
    bool have_aaguid = false;
    if (cbor_parser_init(apdu.data, apdu.nc, 0, &parser, &map) != CborNoError || !cbor_value_is_map(&map) ||
        cbor_value_enter_container(&map, &it) != CborNoError) {
        return SW_WRONG_DATA();
    }
    while (!cbor_value_at_end(&it)) {
        uint64_t k = 0;
        if (!cbor_value_is_unsigned_integer(&it) || cbor_value_get_uint64(&it, &k) != CborNoError ||
            cbor_value_advance_fixed(&it) != CborNoError) {
            return SW_WRONG_DATA();
        }
        if (k == 1) {
            size_t n = sizeof(aaguid);
            if (!cbor_value_is_byte_string(&it) ||
                cbor_value_copy_byte_string(&it, aaguid, &n, &it) != CborNoError || n != sizeof(aaguid)) {
                return SW_WRONG_DATA();
            }
            have_aaguid = true;
        }
        else if (cbor_value_advance(&it) != CborNoError) {
            return SW_WRONG_DATA();
        }
    }
    if (!touched()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    int r = aaguid_set_cb(have_aaguid ? aaguid : NULL);
    if (r == PICOKEY_OK) {
        return SW_OK();
    }
    return r == PICOKEY_ERR_BLOCKED ? SW_SECURITY_STATUS_NOT_SATISFIED() : SW_EXEC_ERROR();
}

/* ------------------------------------------------------------------------ */

/* Data: the FIDO PIN (UTF-8) when the profile has one. The answer carries
 * the length and SHA-256 of the stream and the export ID that EXPORT_READ
 * must present: only the client that started the export (after the touch
 * and the PIN) can read it, not another one sharing the reader or using
 * another interface. */
static int cmd_export_begin(void) {
    end_session();
    if (!lf_storage_ready() || reboot_pending()) {
        wipe_data();
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (!export_allowed()) {
        wipe_data();
        return SW_COMMAND_NOT_ALLOWED();
    }
    if (security_root_unavailable()) {
        /* The backup would lack the root key, and every key sealed with it
         * would be lost with the device: never an incomplete backup. */
        wipe_data();
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (pin_cb) {
        uint16_t sw = pin_cb(apdu.data, (uint16_t) apdu.nc);
        wipe_data();
        if (sw != 0x9000 && sw != 0x6A88) {
            return set_res_sw((uint8_t) (sw >> 8), (uint8_t) sw);
        }
    }
    wipe_data();
    if (!touched()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    const lf_profile_entry_t *p = &lf_sys()->profile[lf_profile_mounted()];
    lfbk_header_t hdr;
    lf_backup_header_init(&hdr);
    if (!lf_identity_read(hdr.uuid, hdr.serial)) {
        return SW_EXEC_ERROR();
    }
    memcpy(hdr.color, p->color, 3);
    /* Policies (lf_policy.h) never travel with a backup. */
    hdr.profile_flags = p->flags & LF_PROFILE_F_NO_EXPORT;
    memcpy(hdr.name, p->name, sizeof(hdr.name));
    lf_profile_name_sanitize(hdr.name, sizeof(hdr.name));
    uint8_t root[32], flags = 0;
    bool has_root = security_root_export(root, &flags) == PICOKEY_OK;
    int r = lf_backup_export(&hdr, has_root ? root : NULL, flags, LF_STAGE_EXPORT);
    mbedtls_platform_zeroize(root, sizeof(root));
    if (r != PICOKEY_OK) {
        lf_stage_clear();
        return r == PICOKEY_ERR_NO_MEMORY ? SW_FILE_FULL() : SW_EXEC_ERROR();
    }
    open_session(SESS_EXPORT);
    uint32_t length = 0;
    uint8_t digest[32];
    lf_stage_info(NULL, NULL, &length);
    lf_stage_digest(digest);
    CborEncoder enc, map;
    CborError e = CborNoError;
    cbor_encoder_init(&enc, res_APDU, RESP_MAX, 0);
    e |= cbor_encoder_create_map(&enc, &map, 3);
    e |= cbor_encode_uint(&map, 1);
    e |= cbor_encode_uint(&map, length);
    e |= cbor_encode_uint(&map, 2);
    e |= cbor_encode_byte_string(&map, digest, sizeof(digest));
    e |= cbor_encode_uint(&map, 3);
    e |= cbor_encode_byte_string(&map, sess_id, sizeof(sess_id));
    e |= cbor_encoder_close_container(&enc, &map);
    return finish_cbor(&enc, e);
}

/* Data: offset (4 bytes, big endian) and the export ID. A wrong ID ends
 * the export (the stream is erased). */
static int cmd_export_read(void) {
    uint32_t length = 0;
    if (sess != SESS_EXPORT || !lf_stage_info(NULL, NULL, &length)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (apdu.nc != 4 + SESS_ID_LEN) {
        return SW_WRONG_LENGTH();
    }
    if (!session_id_ok(apdu.data + 4)) {
        end_session();
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint32_t off = get_be32(apdu.data);
    if (off > length) {
        return SW_INCORRECT_PARAMS();
    }
    uint32_t n = apdu.ne ? apdu.ne : 256;
    if (n > 1024) {
        n = 1024;
    }
    if (n > length - off) {
        n = length - off;
    }
    if (n && lf_stage_read(off, res_APDU, n) != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    res_APDU_size = (uint16_t) n;
    return SW_OK();
}

static int cmd_export_end(void) {
    end_session();
    return SW_OK();
}

/* P1: target slot. P2 bit 0: only check the stream, bit 1 (with bit 0): and
 * restore it into scratch space at the next boot (restore test). Data: the
 * FIDO PIN of the mounted profile for an import into the active slot (it
 * replaces the running authenticator: the same bar as an update). An import
 * (it installs keys the host chose) and a restore test (it rebuilds a spare
 * store) need a touch; a secure profile is never imported into (6986, wipe
 * it first). The plain check writes nothing, not even the staging area: the
 * stream is validated as it arrives. Answer: {1: import ID}.
 * HARDENED builds import too: what HARDENED promises is that keys never
 * leave the device (no export, no automatic presence), not that they were
 * born on it. A backup can only come from a STANDARD device (HARDENED never
 * exports), and restoring it is the documented way to move to a HARDENED
 * device or to recover a profile; its keys also exist in that backup. */
static int cmd_import_begin(void) {
    end_session();
    uint8_t idx = P1(apdu);
    int sw = sys_command_check(idx);
    if (sw == 0x9000 && reboot_pending()) {
        sw = SW_CONDITIONS_NOT_SATISFIED();
    }
    if (sw == 0x9000 && apdu.nc > PIN_MAX) {
        sw = SW_WRONG_LENGTH();
    }
    import_verify_only = (P2(apdu) & 1) != 0;
    import_restore_test = import_verify_only && (P2(apdu) & 2) != 0;
    bool plain = import_verify_only && !import_restore_test;
    if (sw == 0x9000 && !import_verify_only) {
        if (profile_secure(idx)) {
            sw = SW_COMMAND_NOT_ALLOWED();
        }
        else if (idx == lf_sys()->active || idx == lf_profile_mounted()) {
            sw = update_authorized(apdu.data, (uint16_t) apdu.nc);
        }
        else if (!touched()) {
            sw = SW_CONDITIONS_NOT_SATISFIED();
        }
    }
    else if (sw == 0x9000 && import_restore_test && !touched()) {
        sw = SW_CONDITIONS_NOT_SATISFIED();
    }
    wipe_data();
    if (sw != 0x9000) {
        return sw;
    }
    int r = plain ? lf_backup_check_begin(&import_check) : lf_stage_begin(LF_STAGE_IMPORT, idx);
    if (r != PICOKEY_OK) {
        if (plain) {
            lf_backup_check_abort(&import_check);
        }
        return r == PICOKEY_ERR_NO_MEMORY ? SW_FILE_FULL() : SW_MEMORY_FAILURE();
    }
    import_plain = plain;
    import_target = idx;
    import_next = 0;
    open_session(SESS_IMPORT);
    return answer_session_id();
}

/* Data: offset (4 bytes, big endian), import ID, chunk. Chunks arrive in
 * order; a wrong ID or offset ends the transfer. */
static int cmd_import_write(void) {
    if (sess != SESS_IMPORT) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (apdu.nc < 4 + SESS_ID_LEN) {
        return SW_WRONG_LENGTH();
    }
    if (!session_id_ok(apdu.data + 4)) {
        end_session();
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (get_be32(apdu.data) != import_next) {
        end_session();
        return SW_INCORRECT_PARAMS();
    }
    const uint8_t *chunk = apdu.data + 4 + SESS_ID_LEN;
    uint32_t n = apdu.nc - 4 - SESS_ID_LEN;
    int r;
    if (import_plain) {
        r = lf_backup_check_feed(&import_check, chunk, n);
        if (r == PICOKEY_OK && import_check.info.length > lf_stage_capacity()) {
            r = PICOKEY_ERR_NO_MEMORY;      /* could never be imported */
        }
    }
    else {
        r = lf_stage_append(chunk, n);
    }
    if (r != PICOKEY_OK) {
        /* The status first: ending the session forgets what kind it was. */
        int sw = r == PICOKEY_ERR_NO_MEMORY ? SW_FILE_FULL() : (import_plain ? SW_DATA_INVALID() : SW_MEMORY_FAILURE());
        end_session();
        return sw;
    }
    import_next += n;
    return SW_OK();
}

/* Data: the import ID. */
static int cmd_import_end(void) {
    if (sess != SESS_IMPORT) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (apdu.nc != SESS_ID_LEN || !session_id_ok(apdu.data)) {
        end_session();
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    lfbk_info_t info;
    int r;
    if (import_plain) {
        r = lf_backup_check_end(&import_check, &info);  /* end_session() then writes nothing */
    }
    else {
        r = lf_stage_finish();
        if (r == PICOKEY_OK) {
            r = lf_backup_check(&info);
        }
    }
    if (r != PICOKEY_OK) {
        end_session();
        return r == PICOKEY_ERR_NO_MEMORY ? SW_FILE_FULL() : SW_DATA_INVALID();
    }
    CborEncoder enc, map;
    CborError e = CborNoError;
    cbor_encoder_init(&enc, res_APDU, RESP_MAX, 0);
    e |= cbor_encoder_create_map(&enc, &map, 11);
    e |= cbor_encode_uint(&map, 1);
    e |= cbor_encode_uint(&map, info.files);
    e |= cbor_encode_uint(&map, 2);
    e |= cbor_encode_uint(&map, info.counters);
    e |= cbor_encode_uint(&map, 3);
    e |= cbor_encode_boolean(&map, info.has_root);
    e |= cbor_encode_uint(&map, 4);
    e |= cbor_encode_uint(&map, info.length);
    e |= cbor_encode_uint(&map, 5);
    e |= cbor_encode_byte_string(&map, info.hdr.uuid, 16);
    e |= cbor_encode_uint(&map, 6);
    e |= cbor_encode_byte_string(&map, info.hdr.serial, 8);
    e |= cbor_encode_uint(&map, 7);
    e |= cbor_encode_text_string(&map, info.hdr.name, strnlen(info.hdr.name, sizeof(info.hdr.name)));
    e |= cbor_encode_uint(&map, 8);
    e |= cbor_encode_byte_string(&map, info.hdr.fw, 3);
    e |= cbor_encode_uint(&map, 9);
    e |= cbor_encode_byte_string(&map, info.hdr.min_fw, 3);
    e |= cbor_encode_uint(&map, 10);
    e |= cbor_encode_uint(&map, info.hdr.flags);
    e |= cbor_encode_uint(&map, 11);
    e |= cbor_encode_byte_string(&map, info.sha256, 32);
    e |= cbor_encoder_close_container(&enc, &map);
    if (import_verify_only && import_restore_test) {
        /* Restore it for real into scratch space at the next boot. */
        sess = SESS_NONE;
        r = lf_profile_request(LF_OP_VERIFY, import_target);
        if (r != PICOKEY_OK) {
            lf_stage_clear();
            return r == PICOKEY_ERR_BLOCKED ? SW_CONDITIONS_NOT_SATISFIED() : SW_MEMORY_FAILURE();
        }
        lf_reboot_later(300);
    }
    else if (import_verify_only) {
        end_session();                      /* checked, nothing was written */
    }
    else {
        /* The stream stays staged for the boot that imports it. */
        sess = SESS_NONE;
        r = lf_profile_request(LF_OP_IMPORT, import_target);
        if (r != PICOKEY_OK) {
            lf_stage_clear();
            return r == PICOKEY_ERR_BLOCKED ? SW_CONDITIONS_NOT_SATISFIED() : SW_MEMORY_FAILURE();
        }
        lf_reboot_later(300);
    }
    mbedtls_platform_zeroize(sess_id, sizeof(sess_id));
    return finish_cbor(&enc, e);
}

/* ------------------------------------------------------------------------ */
/* Single-key transfer (lf_keyio.h)                                         */
/* ------------------------------------------------------------------------ */

/* Fields of the KEY_* requests. Each command has a table: key n of its
 * request map is field table[n] (KF_NONE: no such key). */
enum { KF_NONE, KF_APP, KF_PIN, KF_CURSOR, KF_ID, KF_SECRET, KF_RECORD, KF_REPLACE, KF_TARGET, KF_SESSION };
#define KF_BIT(f)           ((uint16_t) (1u << (f)))

static const uint8_t key_list_fields[] = { KF_NONE, KF_APP, KF_PIN, KF_CURSOR, KF_SESSION };
static const uint8_t key_export_fields[] = { KF_NONE, KF_APP, KF_ID, KF_PIN, KF_SECRET };
static const uint8_t key_import_fields[] = {
    KF_NONE, KF_APP, KF_RECORD, KF_PIN, KF_SECRET, KF_REPLACE, KF_TARGET
};

typedef struct {
    uint16_t seen;                      /* KF_BIT() of the fields present */
    uint8_t app;
    uint32_t cursor;
    bool replace;
    CborValue record;                   /* a map, still in apdu.data */
    uint8_t id[LF_KEYIO_ID_MAX];
    size_t id_len;
    uint8_t target[LF_KEYIO_ID_MAX];
    size_t target_len;
    uint8_t pin[PIN_MAX];
    size_t pin_len;
    uint8_t secret[KEY_SECRET_MAX];
    size_t secret_len;
    uint8_t sid[SESS_ID_LEN];           /* KEY_LIST: list session ID */
    size_t sid_len;
} key_req_t;

static bool key_get_uint(CborValue *it, uint64_t max, uint64_t *v) {
    return cbor_value_is_unsigned_integer(it) && cbor_value_get_uint64(it, v) == CborNoError && *v <= max &&
           cbor_value_advance_fixed(it) == CborNoError;
}

/* A byte string of min..size bytes, copied: the hooks never read PINs or
 * secrets from the receive buffer, which is wiped after them. */
static bool key_get_bytes(CborValue *it, uint8_t *buf, size_t size, size_t min, size_t *len) {
    *len = size;
    return cbor_value_is_byte_string(it) && cbor_value_copy_byte_string(it, buf, len, it) == CborNoError &&
           *len >= min;
}

/* Parses the request map of a KEY_* command (fields: its table, required:
 * KF_BIT() of the fields it cannot do without). Anything else than exactly
 * one map of known keys, each once and of its type, answers 6A80. */
static int key_parse(const uint8_t *fields, size_t n_fields, uint16_t required, CborParser *parser, key_req_t *r) {
    CborValue map, it;
    if (!mgmt_cbor_open(parser, &map, &it)) {
        return SW_INCORRECT_PARAMS();
    }
    while (!cbor_value_at_end(&it)) {
        uint64_t k = 0, v = 0;
        if (!cbor_value_is_unsigned_integer(&it) || cbor_value_get_uint64(&it, &k) != CborNoError ||
            cbor_value_advance_fixed(&it) != CborNoError) {
            return SW_INCORRECT_PARAMS();
        }
        uint8_t f = k < n_fields ? fields[k] : KF_NONE;
        if (f == KF_NONE || (r->seen & KF_BIT(f))) {
            return SW_INCORRECT_PARAMS();       /* unknown or repeated key */
        }
        r->seen |= KF_BIT(f);
        bool ok;
        switch (f) {
            case KF_APP:
                ok = key_get_uint(&it, LF_APP_COUNT - 1, &v);
                r->app = (uint8_t) v;
                break;
            case KF_CURSOR:
                /* never LF_KEYIO_END: that is no page, and no answer gives it */
                ok = key_get_uint(&it, LF_KEYIO_END - 1, &v);
                r->cursor = (uint32_t) v;
                break;
            case KF_ID:
                ok = key_get_bytes(&it, r->id, sizeof(r->id), 1, &r->id_len);
                break;
            case KF_TARGET:
                ok = key_get_bytes(&it, r->target, sizeof(r->target), 1, &r->target_len);
                break;
            case KF_PIN:
                /* empty: the host tools' "no PIN entered", refused by pin_cb
                 * without a retry when the profile has one */
                ok = key_get_bytes(&it, r->pin, sizeof(r->pin), 0, &r->pin_len);
                break;
            case KF_SECRET:
                ok = key_get_bytes(&it, r->secret, sizeof(r->secret), 0, &r->secret_len);
                break;
            case KF_SESSION:
                ok = key_get_bytes(&it, r->sid, sizeof(r->sid), sizeof(r->sid), &r->sid_len);
                break;
            case KF_REPLACE:
                ok = cbor_value_is_boolean(&it) && cbor_value_get_boolean(&it, &r->replace) == CborNoError &&
                     cbor_value_advance_fixed(&it) == CborNoError;
                break;
            default:                            /* KF_RECORD: its contents are the application's */
                r->record = it;
                ok = cbor_value_is_map(&it) && cbor_value_advance(&it) == CborNoError;
                break;
        }
        if (!ok) {
            return SW_INCORRECT_PARAMS();
        }
    }
    if (cbor_value_leave_container(&map, &it) != CborNoError ||
        cbor_value_get_next_byte(&map) != apdu.data + apdu.nc || (r->seen & required) != required) {
        return SW_INCORRECT_PARAMS();
    }
    return SW_OK();
}

/* The FIDO PIN of the mounted profile, as for EXPORT_BEGIN: 9000 or 6A88
 * (none set) pass. verified (may be NULL): the PIN was given and verified
 * (9000), not merely absent from the profile. */
static int key_pin_check(const key_req_t *r, bool *verified) {
    if (verified) {
        *verified = false;
    }
    if (pin_cb) {
        uint16_t sw = pin_cb((r->seen & KF_BIT(KF_PIN)) ? r->pin : NULL, (uint16_t) r->pin_len);
        if (sw != 0x9000 && sw != 0x6A88) {
            return set_res_sw((uint8_t) (sw >> 8), (uint8_t) sw);
        }
        if (verified) {
            *verified = sw == 0x9000;
        }
    }
    return SW_OK();
}

/* The confirmation an export or import hook asks for (lf_keyio_confirm_t):
 * touched(), once per command. A second request is refused without asking
 * (one touch never confirms two things), and a hook that reports success
 * without the touch is not answered: the rule is kept here too, not only in
 * each application. */
enum { KEY_TOUCH_NOT_ASKED, KEY_TOUCH_GIVEN, KEY_TOUCH_REFUSED };
static uint8_t key_touch = KEY_TOUCH_NOT_ASKED;

static bool key_confirm(void) {
    if (key_touch != KEY_TOUCH_NOT_ASKED) {
        return false;
    }
    key_touch = touched() ? KEY_TOUCH_GIVEN : KEY_TOUCH_REFUSED;
    return key_touch == KEY_TOUCH_GIVEN;
}

/* The answer of KEY_LIST starts with a map of 2 or 4 pairs and key 1 (2
 * bytes); keys 2, 3 and 4 follow the entries (at most 18 bytes: key 2 and
 * its bool, key 3 and a 32-bit uint, key 4 and an 8-byte string). */
#define KEY_LIST_HEAD       2
#define KEY_LIST_TAIL       (2 + 6 + 2 + SESS_ID_LEN)
/* How long a list session lasts from its first page (its touch or PIN):
 * enough for a host to read every page at once, too short to keep a
 * touch-opened view of the keys around. */
#define KEY_LIST_SESSION_MS 10000

/* {1: entries, 2: exportable, 3: next cursor, 4: list session ID}. The
 * hook appends to an indefinite-length array; whether keys 3 and 4 are
 * there (the list goes on) is only known afterwards, so the array is
 * encoded first, behind room for the map header. A first page that does
 * not complete the list opens the list session (paging: the same ID on
 * every page), which then only accepts the page after the one answered;
 * a complete one ends it. */
static int answer_key_list(const lf_keyio_ops_t *ops, uint8_t app, uint32_t cursor, bool paging,
                           bool pin_verified) {
    CborEncoder enc, arr, head, map, tail;
    CborError e = CborNoError;
    uint8_t *entries = res_APDU + KEY_LIST_HEAD;
    uint32_t next = cursor;
    cbor_encoder_init(&enc, entries, RESP_MAX - KEY_LIST_HEAD - KEY_LIST_TAIL, 0);
    if (cbor_encoder_create_array(&enc, &arr, CborIndefiniteLength) != CborNoError) {
        return SW_EXEC_ERROR();
    }
    uint16_t sw = ops->list(&next, pin_verified, &arr);
    if (sw != 0x9000) {
        return set_res_sw((uint8_t) (sw >> 8), (uint8_t) sw);
    }
    if (next == cursor) {
        return SW_EXEC_ERROR();     /* no progress: the host would ask for this page forever */
    }
    if (cbor_encoder_close_container(&enc, &arr) != CborNoError) {
        return SW_EXEC_ERROR();
    }
    bool more = next != LF_KEYIO_END;
    if (!more) {
        end_session();
    }
    else {
        if (!paging) {
            open_session(SESS_LIST);
            list_app = app;
            list_pin_verified = pin_verified;
            list_opened_ms = board_millis();
        }
        list_next = next;
    }
    cbor_encoder_init(&head, res_APDU, KEY_LIST_HEAD, 0);
    e |= cbor_encoder_create_map(&head, &map, more ? 4 : 2);
    e |= cbor_encode_uint(&map, 1);
    cbor_encoder_init(&tail, entries + cbor_encoder_get_buffer_size(&enc, entries), KEY_LIST_TAIL, 0);
    e |= cbor_encode_uint(&tail, 2);
    e |= cbor_encode_boolean(&tail, export_allowed());
    if (more) {
        e |= cbor_encode_uint(&tail, 3);
        e |= cbor_encode_uint(&tail, next);
        e |= cbor_encode_uint(&tail, 4);
        e |= cbor_encode_byte_string(&tail, sess_id, sizeof(sess_id));
    }
    return finish_cbor(&tail, e);
}

/* Data: {1: app, 2: FIDO PIN (optional), 3: cursor (optional, 0: the
 * first page), 4: list session ID (the pages after the first)}.
 * Descriptors only, never a secret, and never more than the application
 * itself reveals with the same credentials: when its listing needs a
 * secret there (list_protected: FIDO without a verified PIN, OATH with a
 * password), the first page needs a touch, and the hook leaves out what
 * needs user verification (list: FIDO without a verified PIN). The pages
 * after it carry the list session ID the first answered and need neither
 * the PIN nor a touch again; the session belongs to the interface, the
 * application and the command stream (any other management command ends
 * it), moves forward only (a page names the cursor the one before
 * answered) and lasts KEY_LIST_SESSION_MS from its first page; a wrong ID
 * or cursor, a late page, or none on a later page of a listing that needs
 * a touch, ends it (6982). A listing that needs no touch may also be paged
 * without the ID, each page then checked like a first one. Answer:
 * {1: entries, 2: exportable, 3: next cursor (absent once complete), 4:
 * list session ID (with key 3)}. */
static int cmd_key_list(void) {
    /* mgmt_process_apdu() ended every session but a listing of this
     * interface: one still open is this client's. */
    bool listing = sess == SESS_LIST, paging = false, pin_verified = false;
    CborParser parser;
    key_req_t r;
    const lf_keyio_ops_t *ops;
    int sw;
    memset(&r, 0, sizeof(r));
    if (!lf_storage_ready() || reboot_pending() || !security_keystore_unlocked()) {
        sw = SW_CONDITIONS_NOT_SATISFIED();
        goto out;
    }
    sw = key_parse(key_list_fields, sizeof(key_list_fields), KF_BIT(KF_APP), &parser, &r);
    if (sw != 0x9000) {
        goto out;
    }
    paging = (r.seen & KF_BIT(KF_SESSION)) != 0;
    if (paging && r.cursor == 0) {
        sw = SW_INCORRECT_PARAMS();         /* the first page starts a listing */
        goto out;
    }
    ops = lf_keyio_ops(r.app);
    if (!ops || !ops->list) {
        sw = SW_FUNC_NOT_SUPPORTED();
        goto out;
    }
    if (paging) {
        /* The first page of this listing passed the checks below. Its touch
         * covers one pass over the keys, soon after: no page again, none
         * skipped, none late. */
        if (!listing || r.app != list_app || !session_id_ok(r.sid) || r.cursor != list_next ||
            board_millis() - list_opened_ms > KEY_LIST_SESSION_MS) {
            sw = SW_SECURITY_STATUS_NOT_SATISFIED();
            goto out;
        }
        pin_verified = list_pin_verified;
    }
    else {
        end_session();
        sw = key_pin_check(&r, &pin_verified);
        if (sw != 0x9000) {
            goto out;
        }
        if (ops->list_protected && ops->list_protected(pin_verified)) {
            if (r.cursor != 0) {
                sw = SW_SECURITY_STATUS_NOT_SATISFIED();    /* a later page without the ID */
                goto out;
            }
            if (!touched()) {
                sw = SW_CONDITIONS_NOT_SATISFIED();
                goto out;
            }
        }
    }
    sw = answer_key_list(ops, r.app, r.cursor, paging, pin_verified);
out:
    if (sw != 0x9000) {
        end_session();
    }
    mbedtls_platform_zeroize(&r, sizeof(r));
    wipe_data();
    return sw;
}

/* {1: app, 2: record}: the hook encodes the record. */
static int answer_key_export(const lf_keyio_ops_t *ops, const key_req_t *r) {
    CborEncoder enc, map;
    CborError e = CborNoError;
    int sw;
    cbor_encoder_init(&enc, res_APDU, RESP_MAX, 0);
    e |= cbor_encoder_create_map(&enc, &map, 2);
    e |= cbor_encode_uint(&map, 1);
    e |= cbor_encode_uint(&map, r->app);
    e |= cbor_encode_uint(&map, 2);
    if (e != CborNoError) {
        return SW_EXEC_ERROR();
    }
    key_touch = KEY_TOUCH_NOT_ASKED;
    uint16_t hsw = ops->export_key(r->id, r->id_len, (r->seen & KF_BIT(KF_SECRET)) ? r->secret : NULL,
                                   r->secret_len, key_confirm, &map);
    if (hsw != 0x9000) {
        sw = set_res_sw((uint8_t) (hsw >> 8), (uint8_t) hsw);
    }
    else if (key_touch != KEY_TOUCH_GIVEN) {
        sw = SW_EXEC_ERROR();
    }
    else {
        e |= cbor_encoder_close_container(&enc, &map);
        sw = finish_cbor(&enc, e);
    }
    if (sw != 0x9000) {
        /* What the hook encoded before it failed may be key material. */
        mbedtls_platform_zeroize(res_APDU, RESP_MAX);
    }
    return sw;
}

/* Data: {1: app, 2: key ID, 3: FIDO PIN (optional), 4: application secret
 * (optional)}. A key leaves the device in the clear: the bar of
 * EXPORT_BEGIN (the export policy of the mounted profile, its FIDO PIN, a
 * touch), which the application may raise (its own secret); it asks for
 * the touch once its own checks passed. Answer: {1: app, 2: record}. */
static int cmd_key_export(void) {
    end_session();
    CborParser parser;
    key_req_t r;
    const lf_keyio_ops_t *ops;
    int sw;
    memset(&r, 0, sizeof(r));
    if (!lf_storage_ready() || reboot_pending()) {
        sw = SW_CONDITIONS_NOT_SATISFIED();
        goto out;
    }
    if (!export_allowed()) {
        sw = SW_COMMAND_NOT_ALLOWED();
        goto out;
    }
    if (security_root_unavailable()) {
        sw = SW_SECURITY_STATUS_NOT_SATISFIED();
        goto out;
    }
    if (!security_keystore_unlocked()) {
        sw = SW_CONDITIONS_NOT_SATISFIED();
        goto out;
    }
    sw = key_parse(key_export_fields, sizeof(key_export_fields), KF_BIT(KF_APP) | KF_BIT(KF_ID), &parser, &r);
    if (sw != 0x9000) {
        goto out;
    }
    ops = lf_keyio_ops(r.app);
    if (!ops || !ops->export_key) {
        sw = SW_FUNC_NOT_SUPPORTED();
        goto out;
    }
    sw = key_pin_check(&r, NULL);
    if (sw != 0x9000) {
        goto out;
    }
    sw = answer_key_export(ops, &r);
out:
    mbedtls_platform_zeroize(&r, sizeof(r));
    wipe_data();
    return sw;
}

/* A secure profile, and every profile of a HARDENED build, only gets FIDO
 * credentials generated on the device (makeCredential): none is added from
 * outside one at a time. */
static bool fido_import_allowed(void) {
#if defined(LF_PROFILE_HARDENED)
    return false;
#else
    return !profile_secure(lf_profile_mounted());
#endif
}

/* {1: app, 2: key ID}. */
static int answer_key_import(const lf_keyio_ops_t *ops, const key_req_t *r) {
    uint8_t id[LF_KEYIO_ID_MAX];
    size_t id_len = 0;
    key_touch = KEY_TOUCH_NOT_ASKED;
    uint16_t hsw = ops->import_key(&r->record, (r->seen & KF_BIT(KF_SECRET)) ? r->secret : NULL, r->secret_len,
                                   (r->seen & KF_BIT(KF_TARGET)) ? r->target : NULL, r->target_len, r->replace,
                                   key_confirm, id, &id_len);
    if (hsw != 0x9000) {
        return set_res_sw((uint8_t) (hsw >> 8), (uint8_t) hsw);
    }
    if (key_touch != KEY_TOUCH_GIVEN || id_len == 0 || id_len > sizeof(id)) {
        return SW_EXEC_ERROR();
    }
    CborEncoder enc, map;
    CborError e = CborNoError;
    cbor_encoder_init(&enc, res_APDU, RESP_MAX, 0);
    e |= cbor_encoder_create_map(&enc, &map, 2);
    e |= cbor_encode_uint(&map, 1);
    e |= cbor_encode_uint(&map, r->app);
    e |= cbor_encode_uint(&map, 2);
    e |= cbor_encode_byte_string(&map, id, id_len);
    e |= cbor_encoder_close_container(&enc, &map);
    return finish_cbor(&enc, e);
}

/* Data: {1: app, 2: record, 3: FIDO PIN (optional), 4: application secret
 * (optional), 5: replace (optional), 6: target (optional)}. The key goes
 * into the mounted profile: its FIDO PIN (the host chose the key, as for an
 * import into the active slot) and a touch, which the application asks for
 * once it checked the record and its own secret. Answer: {1: app, 2: key
 * ID}. */
static int cmd_key_import(void) {
    end_session();
    CborParser parser;
    key_req_t r;
    const lf_keyio_ops_t *ops;
    int sw;
    memset(&r, 0, sizeof(r));
    if (!lf_storage_ready() || !sys_writable() || reboot_pending() || !security_keystore_unlocked()) {
        sw = SW_CONDITIONS_NOT_SATISFIED();
        goto out;
    }
    if (security_root_unavailable()) {
        sw = SW_SECURITY_STATUS_NOT_SATISFIED();
        goto out;
    }
    sw = key_parse(key_import_fields, sizeof(key_import_fields), KF_BIT(KF_APP) | KF_BIT(KF_RECORD), &parser, &r);
    if (sw != 0x9000) {
        goto out;
    }
    ops = lf_keyio_ops(r.app);
    if (!ops || !ops->import_key) {
        sw = SW_FUNC_NOT_SUPPORTED();
        goto out;
    }
    if (r.app == LF_APP_FIDO && !fido_import_allowed()) {
        sw = SW_COMMAND_NOT_ALLOWED();
        goto out;
    }
    sw = key_pin_check(&r, NULL);
    if (sw != 0x9000) {
        goto out;
    }
    sw = answer_key_import(ops, &r);
out:
    mbedtls_platform_zeroize(&r, sizeof(r));
    wipe_data();
    return sw;
}

/* ------------------------------------------------------------------------ */

static int cmd_factory_reset(void) {
    end_session();
    if (P1(apdu) != 0x5A) {                 /* guards against a stray command */
        return SW_INCORRECT_P1P2();
    }
    if (!touched()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (lf_factory_reset((P2(apdu) & 1) != 0) != PICOKEY_OK) {
        lf_reboot_later(300);               /* the system area refuses writes now */
        return SW_MEMORY_FAILURE();
    }
    lf_reboot_later(300);
    return SW_OK();
}

/* ------------------------------------------------------------------------ */
/* Firmware update                                                          */
/* ------------------------------------------------------------------------ */

static int fw_sw(int r) {
    switch (r) {
        case PICOKEY_WRONG_SIGNATURE:
        case PICOKEY_VERIFICATION_FAILED: return SW_DATA_INVALID();
        /* 6A80: the image does not fit this device (SW_WRONG_DATA is 6700) */
        case PICOKEY_WRONG_DATA: return SW_INCORRECT_PARAMS();
        case PICOKEY_ERR_BLOCKED: return SW_COMMAND_NOT_ALLOWED();
        /* 6986 too: it cannot read the records the confirmed firmware wrote */
        case LF_FW_ERR_OLDER_FORMAT: return SW_COMMAND_NOT_ALLOWED();
        /* 6982: a HARDENED image, and this chip is not hardened */
        case LF_FW_ERR_CHIP_NOT_HARDENED: return SW_SECURITY_STATUS_NOT_SATISFIED();
        case PICOKEY_ERR_NO_MEMORY: return SW_FILE_FULL();
        case PICOKEY_WRONG_LENGTH: return SW_WRONG_LENGTH();
        case PICOKEY_ERR_FILE_NOT_FOUND: return SW_REFERENCE_NOT_FOUND();
        default: return SW_EXEC_ERROR();
    }
}

/* New firmware can read every key, and so can whatever the ROM loader is
 * made to write or read: the same bar as an export. The FIDO PIN of the
 * mounted profile when it has one (checked even while its key store is
 * locked, see librefido_init.c), then a touch collected for this command.
 * Without a mounted store (safe mode) there is no PIN to check and the
 * touch alone decides, so that a firmware that cannot open the storage can
 * be replaced. */
static int update_authorized(const uint8_t *pin, uint16_t pin_len) {
    if (pin_cb && lf_storage_ready()) {
        uint16_t sw = pin_cb(pin, pin_len);
        if (sw != 0x9000 && sw != 0x6A88) {
            return set_res_sw((uint8_t) (sw >> 8), (uint8_t) sw);
        }
    }
    if (!touched()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    return SW_OK();
}

/* Data: CBOR {1: image size, 2: SHA-256 of the image, 3: FIDO PIN (optional)}.
 * P2 bit 0 allows an older version or a less restrictive build profile
 * (never in HARDENED builds). Refused while the running firmware is not
 * confirmed: the upload would overwrite the image a reset goes back to.
 * Works in safe mode too, see update_authorized(). Answer: {1: FW ID}. */
static int cmd_fw_begin(void) {
    end_session();
    CborParser parser;
    CborValue map, it;
    uint64_t size = 0;
    uint8_t hash[32], pin[PIN_MAX];
    size_t hash_len = 0, pin_len = 0;
    int sw = 0x9000;
    if (!mgmt_cbor_open(&parser, &map, &it)) {
        sw = SW_WRONG_DATA();
        goto out;
    }
    while (!cbor_value_at_end(&it)) {
        uint64_t k = 0;
        if (!cbor_value_is_unsigned_integer(&it) || cbor_value_get_uint64(&it, &k) != CborNoError ||
            cbor_value_advance_fixed(&it) != CborNoError) {
            sw = SW_WRONG_DATA();
            goto out;
        }
        if (k == 1 && cbor_value_is_unsigned_integer(&it)) {
            cbor_value_get_uint64(&it, &size);
            cbor_value_advance_fixed(&it);
        }
        else if (k == 2 && cbor_value_is_byte_string(&it)) {
            hash_len = sizeof(hash);
            if (cbor_value_copy_byte_string(&it, hash, &hash_len, &it) != CborNoError) {
                sw = SW_WRONG_DATA();
                goto out;
            }
        }
        else if (k == 3 && cbor_value_is_byte_string(&it)) {
            pin_len = sizeof(pin);
            if (cbor_value_copy_byte_string(&it, pin, &pin_len, &it) != CborNoError) {
                sw = SW_WRONG_DATA();
                goto out;
            }
        }
        else if (!mgmt_cbor_skip(&it)) {
            sw = SW_WRONG_DATA();
            goto out;
        }
    }
    if (hash_len != sizeof(hash) || size == 0 || size > UINT32_MAX) {
        sw = SW_WRONG_DATA();
        goto out;
    }
    lf_fw_status_t st;
    lf_fw_status(&st);
    if (reboot_pending() || st.pending) {
        sw = SW_CONDITIONS_NOT_SATISFIED();
        goto out;
    }
    sw = update_authorized(pin, (uint16_t) pin_len);
    if (sw != 0x9000) {
        goto out;
    }
    int r = lf_fw_begin((uint32_t) size, hash);
    if (r != PICOKEY_OK) {
        sw = fw_sw(r);
        goto out;
    }
    fw_allow_downgrade = (P2(apdu) & 1) != 0;
    open_session(SESS_FW);
    sw = answer_session_id();
out:
    mbedtls_platform_zeroize(pin, sizeof(pin));
    wipe_data();
    return sw;
}

/* Data: offset (4 bytes, big endian), FW ID, chunk. */
static int cmd_fw_write(void) {
    if (sess != SESS_FW) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (apdu.nc < 4 + SESS_ID_LEN) {
        return SW_WRONG_LENGTH();
    }
    if (!session_id_ok(apdu.data + 4)) {
        end_session();
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    int r = lf_fw_write(get_be32(apdu.data), apdu.data + 4 + SESS_ID_LEN, (uint16_t) (apdu.nc - 4 - SESS_ID_LEN));
    if (r != PICOKEY_OK) {
        end_session();
        return r == PICOKEY_WRONG_DATA ? SW_INCORRECT_PARAMS() : fw_sw(r);
    }
    return SW_OK();
}

/* Data: the FW ID. */
static int cmd_fw_end(void) {
    if (sess != SESS_FW) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (apdu.nc != SESS_ID_LEN || !session_id_ok(apdu.data)) {
        end_session();
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    lf_fw_desc_t d;
    int r = lf_fw_finish(&d);
    if (r == PICOKEY_OK) {
        r = lf_fw_check_policy(&d, fw_allow_downgrade);
    }
    if (r == PICOKEY_OK) {
        r = lf_fw_activate();
    }
    end_session();
    if (r != PICOKEY_OK) {
        return fw_sw(r);
    }
    lf_reboot_later(300);
    CborEncoder enc, map;
    CborError e = CborNoError;
    cbor_encoder_init(&enc, res_APDU, RESP_MAX, 0);
    e |= cbor_encoder_create_map(&enc, &map, 4);
    e |= cbor_encode_uint(&map, 1);
    e |= cbor_encode_byte_string(&map, d.version, 3);
    e |= cbor_encode_uint(&map, 2);
    e |= cbor_encode_uint(&map, d.platform);
    e |= cbor_encode_uint(&map, 3);
    e |= cbor_encode_uint(&map, d.build_profile);
    e |= cbor_encode_uint(&map, 4);
    e |= cbor_encode_text_string(&map, d.board, strnlen(d.board, sizeof(d.board)));
    e |= cbor_encoder_close_container(&enc, &map);
    return finish_cbor(&enc, e);
}

/* Only a firmware that booted normally (storage mounted) is kept. */
static int cmd_fw_confirm(void) {
    end_session();
    if (lf_boot_status() != LF_BOOT_OK || !lf_storage_ready()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    /* 6985 while a rollback / a new image is on its way: this image will
     * not boot again, confirming it would be a lie. */
    int r = lf_fw_confirm();
    if (r == PICOKEY_ERR_BLOCKED) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    return r == PICOKEY_OK ? SW_OK() : SW_EXEC_ERROR();
}

/* Data: the FIDO PIN (UTF-8, optional). Going back installs the previous
 * image: it must pass the update policy (HARDENED: never an older version
 * or another build profile; storage formats it can open), and the same PIN
 * and touch as an update are asked. A HARDENED build on a chip without
 * Secure Boot never unlocked its key store and is a recovery case: only
 * platform and storage formats are checked there. */
static int cmd_fw_rollback(void) {
    end_session();
    int sw = 0x9000;
    lf_fw_status_t st;
    lf_fw_desc_t d;
    int r;
    if (apdu.nc > PIN_MAX) {
        sw = SW_WRONG_LENGTH();
        goto out;
    }
    if (reboot_pending()) {
        sw = SW_CONDITIONS_NOT_SATISFIED();
        goto out;
    }
    lf_fw_status(&st);
    if (!st.rollback_possible) {
        sw = SW_REFERENCE_NOT_FOUND();
        goto out;
    }
    r = lf_fw_rollback_desc(&d);
    if (r == PICOKEY_OK) {
#if defined(LF_PROFILE_HARDENED)
        r = lf_fw_images_signed() ? lf_fw_check_policy(&d, true) : lf_fw_check_recovery(&d);
#else
        r = lf_fw_check_policy(&d, true);
#endif
    }
    if (r != PICOKEY_OK) {
        sw = fw_sw(r);
        goto out;
    }
    sw = update_authorized(apdu.data, (uint16_t) apdu.nc);
    if (sw != 0x9000) {
        goto out;
    }
    if (lf_fw_rollback() != PICOKEY_OK) {
        sw = SW_EXEC_ERROR();
        goto out;
    }
    lf_reboot_later(300);
out:
    wipe_data();
    return sw;
}

/* P1 0xA5 (guard value), P2: 0x01 binds the device root key to this chip:
 * an HMAC key generated on the device is burned into a free eFuse key block
 * (read protected, never leaves the chip) and the root key is re-wrapped
 * with a key derived from it. 0x02 locks debugging: burns the eFuses that
 * disable JTAG (pad and USB) and enable the secure download mode (esptool
 * can still flash, but reads nothing). Both are irreversible, hence the
 * guard value and the physical touch, and are never done automatically.
 * The host tool (librefido provision) checks the state first and verifies
 * it afterwards. */
static int cmd_provision(void) {
    end_session();
    if (P1(apdu) != 0xA5 || (P2(apdu) != 0x01 && P2(apdu) != 0x02)) {
        return SW_INCORRECT_P1P2();
    }
    if (lf_boot_status() != LF_BOOT_OK || !lf_storage_ready()) {
        return SW_CONDITIONS_NOT_SATISFIED();   /* the root key must be there */
    }
    if (P2(apdu) == 0x02) {
        const security_state_t *ss = security_state();
        if (ss->jtag_disabled && ss->download_restricted) {
            return SW_REFERENCE_NOT_FOUND();    /* 6A88: already done */
        }
        if (!touched()) {
            return SW_CONDITIONS_NOT_SATISFIED();
        }
        int r = security_lock_debug();
        if (r == PICOKEY_ERR_BLOCKED) {
            return SW_REFERENCE_NOT_FOUND();
        }
        if (r == PICOKEY_ERR_FILE_NOT_FOUND) {
            return SW_FUNC_NOT_SUPPORTED();
        }
        return r == PICOKEY_OK ? SW_OK() : SW_EXEC_ERROR();
    }
    if (!touched()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    int r = security_provision_hmac_key();
    if (r == PICOKEY_ERR_BLOCKED) {
        return SW_COMMAND_NOT_ALLOWED();        /* key block already in use */
    }
    if (r == PICOKEY_ERR_FILE_NOT_FOUND) {
        return SW_FUNC_NOT_SUPPORTED();
    }
    if (r != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    low_flash_commit();
    return SW_OK();
}

/* P1 0: restart (touch). P1 1: restart into the ROM download mode
 * (USB-Serial/JTAG) for a recovery flash; data: the FIDO PIN (optional).
 * The ROM loader of a chip without Secure Boot and secure download mode
 * reads the whole flash and writes any firmware, so it asks what an update
 * asks. HARDENED builds refuse it on a Secure Boot chip (it would bypass
 * the update policy; they are updated with FW_BEGIN, in safe mode too), but
 * keep it on a chip without Secure Boot: there the loader is reachable with
 * the BOOT strap anyway and the key store never unlocked, and it is the way
 * back from an image such a chip cannot run. */
static int cmd_reboot(void) {
    end_session();
    if (P1(apdu) > 1) {
        return SW_INCORRECT_P1P2();
    }
    if (P1(apdu) == 1) {
#if !defined(ESP_PLATFORM)
        return SW_FUNC_NOT_SUPPORTED();
#else
#if defined(LF_PROFILE_HARDENED)
        if (lf_fw_images_signed()) {
            wipe_data();
            return SW_COMMAND_NOT_ALLOWED();
        }
#endif
        if (apdu.nc > PIN_MAX) {
            wipe_data();
            return SW_WRONG_LENGTH();
        }
        int sw = update_authorized(apdu.data, (uint16_t) apdu.nc);
        wipe_data();
        if (sw != 0x9000) {
            return sw;
        }
        /* Key storage partitions are not touched by flashing the app. */
        REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
#endif
    }
    else if (!touched()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    lf_reboot_later(300);
    return SW_OK();
}

static const cmd_t cmds[] = {
    { LF_MGMT_INS_INFO, cmd_info },
    { LF_MGMT_INS_HEALTH, cmd_health },
    { LF_MGMT_INS_PROFILE_SELECT, cmd_profile_select },
    { LF_MGMT_INS_PROFILE_SET, cmd_profile_set },
    { LF_MGMT_INS_PROFILE_WIPE, cmd_profile_wipe_delete },
    { LF_MGMT_INS_PROFILE_DELETE, cmd_profile_wipe_delete },
    { LF_MGMT_INS_BUTTON_SLOTS, cmd_button_slots },
    { LF_MGMT_INS_PROFILE_CREATE_SECURE, cmd_profile_create_secure },
    { LF_MGMT_INS_BOARD_SET, cmd_board_set },
    { LF_MGMT_INS_PROFILE_AAGUID_SET, cmd_profile_aaguid_set },
    { LF_MGMT_INS_EXPORT_BEGIN, cmd_export_begin },
    { LF_MGMT_INS_EXPORT_READ, cmd_export_read },
    { LF_MGMT_INS_EXPORT_END, cmd_export_end },
    { LF_MGMT_INS_IMPORT_BEGIN, cmd_import_begin },
    { LF_MGMT_INS_IMPORT_WRITE, cmd_import_write },
    { LF_MGMT_INS_IMPORT_END, cmd_import_end },
    { LF_MGMT_INS_FACTORY_RESET, cmd_factory_reset },
    { LF_MGMT_INS_FW_BEGIN, cmd_fw_begin },
    { LF_MGMT_INS_FW_WRITE, cmd_fw_write },
    { LF_MGMT_INS_FW_END, cmd_fw_end },
    { LF_MGMT_INS_FW_CONFIRM, cmd_fw_confirm },
    { LF_MGMT_INS_FW_ROLLBACK, cmd_fw_rollback },
    { LF_MGMT_INS_PROVISION_HMAC, cmd_provision },
    { LF_MGMT_INS_KEY_LIST, cmd_key_list },
    { LF_MGMT_INS_KEY_EXPORT, cmd_key_export },
    { LF_MGMT_INS_KEY_IMPORT, cmd_key_import },
    { LF_MGMT_INS_REBOOT, cmd_reboot },
    { 0x00, 0x0 }
};

static bool continues_session(uint8_t ins) {
    return (sess == SESS_EXPORT && (ins == LF_MGMT_INS_EXPORT_READ || ins == LF_MGMT_INS_EXPORT_END)) ||
           (sess == SESS_IMPORT && (ins == LF_MGMT_INS_IMPORT_WRITE || ins == LF_MGMT_INS_IMPORT_END)) ||
           (sess == SESS_FW && (ins == LF_MGMT_INS_FW_WRITE || ins == LF_MGMT_INS_FW_END)) ||
           (sess == SESS_LIST && ins == LF_MGMT_INS_KEY_LIST);
}

static int mgmt_process_apdu(void) {
    if (CLA(apdu) != 0x80) {
        return SW_CLA_NOT_SUPPORTED();
    }
    uint8_t ins = INS(apdu);
    if (sess != SESS_NONE) {
        if (card_current_itf() != sess_itf) {
            /* Another USB interface (a WebUSB page on WCID while a PC/SC
             * client transfers over CCID) never takes part in a transfer:
             * it ends it (the stage is cleared). A KEY_LIST may also start
             * a listing of its own: cmd_key_list() refuses its later pages,
             * the session they name is gone. */
            bool part = continues_session(ins) && sess != SESS_LIST;
            end_session();
            if (part) {
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
        }
        else if (!continues_session(ins)) {
            end_session();      /* any other command ends a transfer */
        }
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == ins) {
            return cmd->cmd_handler();
        }
    }
    return SW_INS_NOT_SUPPORTED();
}

/* A card reset or another application selected on the smart card
 * interfaces (HID never unloads it: apdu.c keeps its applications apart). */
static int mgmt_unload(void) {
    end_session();
    return PICOKEY_OK;
}

/* Random per boot: lets a host tell a restarted device from the old one. */
static uint8_t boot_id[4];
static bool boot_id_set = false;

static int mgmt_select(app_t *a, uint8_t force) {
    (void) force;
    a->process_apdu = mgmt_process_apdu;
    a->unload = mgmt_unload;
    if (!boot_id_set) {
        random_gen(NULL, boot_id, sizeof(boot_id));
        boot_id_set = true;
    }
    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = 'L';
    res_APDU[res_APDU_size++] = 'F';
    res_APDU[res_APDU_size++] = LF_MGMT_PROTOCOL;
    res_APDU[res_APDU_size++] = (uint8_t) lf_boot_status();
    memcpy(res_APDU + res_APDU_size, boot_id, sizeof(boot_id));
    res_APDU_size += sizeof(boot_id);
    apdu.ne = res_APDU_size;
    return PICOKEY_OK;
}

INITIALIZER ( lf_mgmt_ctor ) {
    register_app(mgmt_select, mgmt_aid);
}
