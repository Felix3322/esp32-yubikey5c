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
#include "hid/ctap_hid.h"
#include "usb.h"
#include "low_flash.h"
#include "crypto_utils.h"
#include "sks.h"
#include "lf_policy.h"
#include "security.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#ifdef ENABLE_EMULATION
/* The emulator has no keyboard. With LF_EMU_KEYBOARD_LOG=1 it logs what a
 * slot types (tests read the emulator log); nothing is logged otherwise. */
static void emul_keyboard_log(const uint8_t *buf, size_t len, bool encode) {
    const char *e = getenv("LF_EMU_KEYBOARD_LOG");
    if (!e || strcmp(e, "1") != 0) {
        return;
    }
    printf("[otp] keyboard: ");
    for (size_t i = 0; i < len; i++) {
        if (encode && buf[i] >= 0x20 && buf[i] < 0x7f) {
            printf("%c", buf[i]);
        }
        else {
            printf("<%02x>", buf[i]);
        }
    }
    printf("\n");
    fflush(stdout);
}
void add_keyboard_buffer(const uint8_t *buf, size_t len, bool encode) {
    emul_keyboard_log(buf, len, encode);
}
void append_keyboard_buffer(const uint8_t *buf, size_t len) {
    emul_keyboard_log(buf, len, false);
}
#else
#include "tusb.h"
#endif
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "management.h"

#define FIXED_SIZE          16
#define KEY_SIZE            16
#define UID_SIZE            6
#define KEY_SIZE_OATH       20
#define ACC_CODE_SIZE       6
#define OTP_CTR_SIZE        8
#define OTP_SLOTS           4

#define CONFIG1_VALID       0x01
#define CONFIG2_VALID       0x02
#define CONFIG1_TOUCH       0x04
#define CONFIG2_TOUCH       0x08
#define CONFIG_LED_INV      0x10
#define CONFIG_STATUS_MASK  0x1f

#define CONFIG3_VALID       0x01
#define CONFIG4_VALID       0x02
#define CONFIG3_TOUCH       0x04
#define CONFIG4_TOUCH       0x08

/* Keyboard status report, byte 7 */
#define SLOT_WRITE_FLAG     0x80    // A command is being processed: the host waits
#define RESP_PENDING_FLAG   0x40    // Response frame
#define RESP_TIMEOUT_WAIT   0x20    // Waiting for a touch

/* EXT Flags */
#define SERIAL_BTN_VISIBLE  0x01    // Serial number visible at startup (button press)
#define SERIAL_USB_VISIBLE  0x02    // Serial number visible in USB iSerial field
#define SERIAL_API_VISIBLE  0x04    // Serial number visible via API call
#define USE_NUMERIC_KEYPAD  0x08    // Use numeric keypad for digits
#define FAST_TRIG           0x10    // Use fast trig if only cfg1 set
#define ALLOW_UPDATE        0x20    // Allow update of existing configuration (selected flags + access code)
#define DORMANT             0x40    // Dormant config (woken up, flag removed, requires update flag)
#define LED_INV             0x80    // LED idle state is off rather than on
#define EXTFLAG_UPDATE_MASK (SERIAL_BTN_VISIBLE | SERIAL_USB_VISIBLE | SERIAL_API_VISIBLE | \
                             USE_NUMERIC_KEYPAD | FAST_TRIG | ALLOW_UPDATE | DORMANT | LED_INV)

/* TKT Flags */
#define TAB_FIRST       0x01    // Send TAB before first part
#define APPEND_TAB1     0x02    // Send TAB after first part
#define APPEND_TAB2     0x04    // Send TAB after second part
#define APPEND_DELAY1   0x08    // Add 0.5s delay after first part
#define APPEND_DELAY2   0x10    // Add 0.5s delay after second part
#define APPEND_CR       0x20    // Append CR as final character
#define OATH_HOTP       0x40    // OATH HOTP mode
#define CHAL_RESP       0x40    // Challenge-response enabled (both must be set)
#define PROTECT_CFG2    0x80    // Block update of config 2 unless config 2 is configured and has this bit set
#define TKTFLAG_UPDATE_MASK (TAB_FIRST | APPEND_TAB1 | APPEND_TAB2 | APPEND_DELAY1 | APPEND_DELAY2 | \
                             APPEND_CR)

/* CFG Flags */
#define SEND_REF            0x01    // Send reference string (0..F) before data
#define PACING_10MS         0x04    // Add 10ms intra-key pacing
#define PACING_20MS         0x08    // Add 20ms intra-key pacing
#define STATIC_TICKET       0x20    // Static ticket generation
// Static
#define SHORT_TICKET        0x02    // Send truncated ticket (half length)
#define STRONG_PW1          0x10    // Strong password policy flag #1 (mixed case)
#define STRONG_PW2          0x40    // Strong password policy flag #2 (subtitute 0..7 to digits)
#define MAN_UPDATE          0x80    // Allow manual (local) update of static OTP
// Challenge (no keyboard)
#define HMAC_LT64           0x04    // Set when HMAC message is less than 64 bytes
#define CHAL_BTN_TRIG       0x08    // Challenge-response operation requires button press
#define CHAL_YUBICO         0x20    // Challenge-response enabled - Yubico OTP mode
#define CHAL_HMAC           0x22    // Challenge-response enabled - HMAC-SHA1
// OATH
#define OATH_HOTP8          0x02    // Generate 8 digits HOTP rather than 6 digits
#define OATH_FIXED_MODHEX1  0x10    // First byte in fixed part sent as modhex
#define OATH_FIXED_MODHEX2  0x40    // First two bytes in fixed part sent as modhex
#define OATH_FIXED_MODHEX   0x50    // Fixed part sent as modhex
#define OATH_FIXED_MASK     0x50    // Mask to get out fixed flags
#define CFGFLAG_UPDATE_MASK (PACING_10MS | PACING_20MS)

static uint8_t config_seq = { 1 };

PACK(
typedef struct otp_config {
    uint8_t fixed_data[FIXED_SIZE];
    uint8_t uid[UID_SIZE];
    uint8_t aes_key[KEY_SIZE];
    uint8_t acc_code[ACC_CODE_SIZE];
    uint8_t fixed_size;
    uint8_t ext_flags;
    uint8_t tkt_flags;
    uint8_t cfg_flags;
    uint8_t rfu[2];
    uint16_t crc;
}) otp_config_t;

#define otp_config_size sizeof(otp_config_t)

/* A stored slot is the 52-byte configuration followed by an 8-byte counter
 * area: the Yubico OTP usage counter (16 bit, big endian) or the OATH-HOTP
 * moving factor (64 bit, big endian). Older firmware left 52-byte records
 * after a slot update; they read as a zero counter. Slots are sealed (sks,
 * OTP namespace); plaintext slots of older firmware are read as they are. */
#define OTP_REC_SIZE        (otp_config_size + OTP_CTR_SIZE)
#define OTP_REC_MAX         128     /* largest slot record read (older firmware) */

uint16_t otp_status(bool is_otp);

int otp_process_apdu();
int otp_unload();

extern int (*hid_set_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t const *, uint16_t);
extern uint16_t (*hid_get_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t *, uint16_t);
int otp_hid_set_report_cb(uint8_t, uint8_t, hid_report_type_t, uint8_t const *, uint16_t);
uint16_t otp_hid_get_report_cb(uint8_t, uint8_t, hid_report_type_t, uint8_t *, uint16_t);

/* management.c: device information into a buffer of the given size. */
extern int man_get_config_buf(uint8_t *out, uint16_t cap);

const uint8_t otp_aid[] = {
    7,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01
};

/* ------------------------------------------------------------------------ */
/* Slot storage                                                             */
/* ------------------------------------------------------------------------ */

typedef enum { OTP_SLOT_EMPTY = 0, OTP_SLOT_OK, OTP_SLOT_BAD } otp_slot_state_t;

/* Public part of every slot (flags, Yubico OTP public ID), kept in RAM so the
 * status the keyboard interface reads at any time never opens a record. */
typedef struct {
    bool valid;
    uint8_t ext_flags, tkt_flags, cfg_flags;
    uint8_t fixed[6];
} otp_meta_t;

static otp_meta_t otp_meta[OTP_SLOTS];
static bool otp_meta_loaded = false;
static bool otp_migrated = false;

/* New records are sealed once the running firmware is confirmed (an
 * unconfirmed update may still roll back to firmware that reads plaintext
 * only); a sealed record is never written back in plaintext. */
static bool otp_seal_new(void) {
    return lf_migrate_ok() || lf_profile_sealed_only();
}

static void otp_meta_set(uint8_t n, const uint8_t *rec) {
    const otp_config_t *c = (const otp_config_t *) rec;
    otp_meta[n].valid = true;
    otp_meta[n].ext_flags = c ? c->ext_flags : 0;
    otp_meta[n].tkt_flags = c ? c->tkt_flags : 0;
    otp_meta[n].cfg_flags = c ? c->cfg_flags : 0;
    memset(otp_meta[n].fixed, 0, sizeof(otp_meta[n].fixed));
    if (c) {
        memcpy(otp_meta[n].fixed, c->fixed_data, sizeof(otp_meta[n].fixed));
    }
}

static void otp_meta_clear(uint8_t n) {
    memset(&otp_meta[n], 0, sizeof(otp_meta[n]));
}

/* Copies slot n (0..3) into rec, zero padded. */
static otp_slot_state_t otp_slot_load(uint8_t n, uint8_t rec[OTP_REC_SIZE], bool *sealed) {
    memset(rec, 0, OTP_REC_SIZE);
    if (sealed) {
        *sealed = false;
    }
    if (n >= OTP_SLOTS) {
        return OTP_SLOT_EMPTY;
    }
    file_t *ef = search_dynamic_file(EF_OTP_SLOT1 + n);
    if (!file_has_data(ef)) {
        return OTP_SLOT_EMPTY;
    }
    uint8_t buf[OTP_REC_MAX];
    size_t len = 0;
    bool legacy = false;
    int r = sks_file_get(SKS_NS_OTP, ef, buf, sizeof(buf), &len, &legacy);
    otp_slot_state_t st = OTP_SLOT_BAD;
    if (r == PICOKEY_OK && len >= otp_config_size) {
        memcpy(rec, buf, MIN(len, OTP_REC_SIZE));
        if (sealed) {
            *sealed = !legacy;
        }
        st = OTP_SLOT_OK;
    }
    mbedtls_platform_zeroize(buf, sizeof(buf));
    return st;
}

static int otp_slot_store(uint8_t n, const uint8_t rec[OTP_REC_SIZE], bool seal) {
    file_t *ef = file_new(EF_OTP_SLOT1 + n);
    if (ef == NULL) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    int r = seal ? sks_file_put(SKS_NS_OTP, ef, rec, OTP_REC_SIZE) : file_put_data(ef, rec, OTP_REC_SIZE);
    if (r == PICOKEY_OK) {
        low_flash_available();
        otp_meta_set(n, rec);
    }
    return r;
}

static void otp_slot_delete(uint8_t n) {
    delete_file(search_dynamic_file(EF_OTP_SLOT1 + n));
    otp_meta_clear(n);
}

static void otp_meta_load(void) {
    if (!security_keystore_unlocked()) {
        /* Key store locked: no record is opened, the status only tells
         * which slots are programmed. */
        for (uint8_t n = 0; n < OTP_SLOTS; n++) {
            if (file_has_data(search_dynamic_file(EF_OTP_SLOT1 + n))) {
                otp_meta_set(n, NULL);
            }
            else {
                otp_meta_clear(n);
            }
        }
        return;
    }
    for (uint8_t n = 0; n < OTP_SLOTS; n++) {
        uint8_t rec[OTP_REC_SIZE];
        otp_slot_state_t st = otp_slot_load(n, rec, NULL);
        if (st == OTP_SLOT_OK) {
            otp_meta_set(n, rec);
        }
        else if (st == OTP_SLOT_BAD) {
            otp_meta_set(n, NULL);      /* programmed, but cannot be opened */
        }
        else {
            otp_meta_clear(n);
        }
        mbedtls_platform_zeroize(rec, sizeof(rec));
    }
    otp_meta_loaded = true;
}

/* Seals the slots older firmware stored in plaintext, once the firmware is
 * confirmed. Plaintext in a profile created secure is injected: never read,
 * never sealed. */
static void otp_migrate(void) {
    if (otp_migrated || !lf_migrate_ok() || !security_keystore_unlocked()) {
        return;
    }
    bool ok = true;
    if (!lf_profile_sealed_only()) {
        for (uint8_t n = 0; n < OTP_SLOTS; n++) {
            file_t *ef = search_dynamic_file(EF_OTP_SLOT1 + n);
            if (!file_has_data(ef) || sks_is_sealed(SKS_NS_OTP, file_get_data(ef), file_get_size(ef))) {
                continue;
            }
            uint8_t rec[OTP_REC_SIZE];
            if (otp_slot_load(n, rec, NULL) != OTP_SLOT_OK || otp_slot_store(n, rec, true) != PICOKEY_OK) {
                ok = false;
            }
            mbedtls_platform_zeroize(rec, sizeof(rec));
        }
    }
    otp_migrated = ok;
}

/* OATH_HOTP and CHAL_RESP are the same ticket flag: a challenge-response
 * slot also has CHAL_YUBICO (both of its modes), an OATH-HOTP slot never. */
static bool otp_flags_chalresp(uint8_t tkt_flags, uint8_t cfg_flags) {
    return (tkt_flags & CHAL_RESP) && (cfg_flags & CHAL_YUBICO);
}

static bool otp_is_chalresp(const otp_config_t *cfg) {
    return otp_flags_chalresp(cfg->tkt_flags, cfg->cfg_flags);
}

static bool otp_is_hotp(const otp_config_t *cfg) {
    return (cfg->tkt_flags & OATH_HOTP) && !(cfg->cfg_flags & CHAL_YUBICO);
}

static bool otp_is_static(const otp_config_t *cfg) {
    return (cfg->cfg_flags & SHORT_TICKET) || (cfg->cfg_flags & STATIC_TICKET);
}

int otp_select(app_t *a, uint8_t force) {
    (void) force;
    if (cap_supported(CAP_OTP)) {
        a->process_apdu = otp_process_apdu;
        a->unload = otp_unload;
        if (file_has_data(search_dynamic_file(EF_OTP_SLOT1)) ||
            file_has_data(search_dynamic_file(EF_OTP_SLOT2))) {
            config_seq = 1;
        }
        else {
            config_seq = 0;
        }
        if (is_busy()) {
            /* A SELECT command (card thread): records may be written. */
            otp_migrate();
        }
        otp_status(false);
        return PICOKEY_OK;
    }
    return PICOKEY_ERR_FILE_NOT_FOUND;
}

uint8_t modhex_tab[] =
{ 'c', 'b', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'n', 'r', 't', 'u', 'v' };
int encode_modhex(const uint8_t *in, size_t len, uint8_t *out) {
    for (size_t l = 0; l < len; l++) {
        *out++ = modhex_tab[in[l] >> 4];
        *out++ = modhex_tab[in[l] & 0xf];
    }
    return 0;
}

static void otp_status_publish(void);

static bool scanned = false;
extern void scan_all();
void init_otp() {
    /* Key store locked: the slots (also plaintext ones of earlier firmware)
     * are not used, their counters not moved. */
    if (scanned == false && security_keystore_unlocked()) {
        scan_all();
        otp_migrate();
        for (uint8_t i = 0; i < OTP_SLOTS; i++) {
            uint8_t rec[OTP_REC_SIZE];
            bool sealed = false;
            const otp_config_t *cfg = (const otp_config_t *) rec;
            /* Yubico OTP: the usage counter moves on at every power up. */
            if (otp_slot_load(i, rec, &sealed) == OTP_SLOT_OK && !(cfg->tkt_flags & OATH_HOTP) && !otp_is_static(cfg)) {
                uint16_t counter = get_uint16_t_be(rec + otp_config_size);
                if (++counter <= 0x7fff) {
                    put_uint16_t_be(counter, rec + otp_config_size);
                    otp_slot_store(i, rec, sealed || otp_seal_new());
                }
            }
            mbedtls_platform_zeroize(rec, sizeof(rec));
        }
        otp_meta_load();
        scanned = true;
        low_flash_available();
        usb_lock();
        otp_status_publish();
        usb_unlock();
    }
}

uint16_t calculate_crc(const uint8_t *data, size_t data_len) {
    uint16_t crc = 0xFFFF;
    for (size_t idx = 0; idx < data_len; idx++) {
        crc ^= data[idx];
        for (uint8_t i = 0; i < 8; i++) {
            uint16_t j = crc & 0x1;
            crc >>= 1;
            if (j == 1) {
                crc ^= 0x8408;
            }
        }
    }
    return crc & 0xFFFF;
}

/* RFC 4226 HOTP of an OATH-HOTP slot. The 20-byte secret is packed as the
 * AES key field and the first 4 bytes of the UID field (yubikit/ykpers). */
static bool otp_hotp(const otp_config_t *cfg, uint64_t counter, uint32_t *code) {
    uint8_t key[KEY_SIZE_OATH], msg[8], hmac[20];
    memcpy(key, cfg->aes_key, KEY_SIZE);
    memcpy(key + KEY_SIZE, cfg->uid, KEY_SIZE_OATH - KEY_SIZE);
    put_uint64_t_be(counter, msg);
    int r = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), key, sizeof(key), msg, sizeof(msg), hmac);
    if (r == 0) {
        uint8_t offset = hmac[sizeof(hmac) - 1] & 0x0f;
        uint32_t number = get_uint32_t_be(hmac + offset) & 0x7fffffff;
        *code = number % ((cfg->cfg_flags & OATH_HOTP8) ? 100000000 : 1000000);
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(hmac, sizeof(hmac));
    return r == 0;
}

/* Stores a slot inside its own storage transaction: whatever is typed after
 * this (an OTP, a HOTP code) was durable first and is never typed twice. */
static bool otp_slot_commit(uint8_t n, const uint8_t rec[OTP_REC_SIZE], bool seal) {
    low_flash_txn_begin();
    int r = otp_slot_store(n, rec, seal);
    if (low_flash_txn_end() != PICOKEY_OK) {
        r = PICOKEY_EXEC_ERROR;
    }
    return r == PICOKEY_OK;
}

static uint8_t session_counter[OTP_SLOTS] = { 0 };

/* Button event while idle: slot n (0..3) types. */
static int otp_slot_type(uint8_t n) {
    uint8_t rec[OTP_REC_SIZE];
    bool sealed = false;
    if (otp_slot_load(n, rec, &sealed) != OTP_SLOT_OK) {
        return 1;
    }
    bool seal = sealed || otp_seal_new();
    const otp_config_t *otp_config = (const otp_config_t *) rec;
    int ret = 0;
    if (otp_is_chalresp(otp_config)) {
        ret = 2;
    }
    else if (otp_is_hotp(otp_config)) {
        uint64_t imf = get_uint64_t_be(rec + otp_config_size);
        if (imf == 0) {
            /* Initial moving factor, stored divided by 16 in the UID field. */
            imf = (uint64_t) get_uint16_t_be(otp_config->uid + 4) << 4;
        }
        uint32_t number = 0;
        if (otp_hotp(otp_config, imf, &number)) {
            put_uint64_t_be(imf + 1, rec + otp_config_size);
            if (otp_slot_commit(n, rec, seal)) {
                char number_str[12];
                if (otp_config->cfg_flags & OATH_HOTP8) {
                    snprintf(number_str, sizeof(number_str), "%08lu", (long unsigned int) number);
                    add_keyboard_buffer((const uint8_t *) number_str, 8, true);
                }
                else {
                    snprintf(number_str, sizeof(number_str), "%06lu", (long unsigned int) number);
                    add_keyboard_buffer((const uint8_t *) number_str, 6, true);
                }
                mbedtls_platform_zeroize(number_str, sizeof(number_str));
                if (otp_config->tkt_flags & APPEND_CR) {
                    append_keyboard_buffer((const uint8_t *) "\r", 1);
                }
            }
        }
    }
    else if (otp_is_static(otp_config)) {
        uint8_t fixed_size = FIXED_SIZE + UID_SIZE + KEY_SIZE;
        if (otp_config->cfg_flags & SHORT_TICKET) { // Not clear which is the purpose of SHORT_TICKET
            //fixed_size /= 2;
        }
        add_keyboard_buffer(otp_config->fixed_data, fixed_size, false);
        if (otp_config->tkt_flags & APPEND_CR) {
            append_keyboard_buffer((const uint8_t *) "\x28", 1);
        }
    }
    else {
        uint8_t otpk[22], *po = otpk;
        bool update_counter = false;
        uint16_t counter = get_uint16_t_be(rec + otp_config_size), crc = 0;
        uint32_t ts = board_millis() / 1000;
        if (counter == 0) {
            update_counter = true;
            counter = 1;
        }
        memcpy(po, otp_config->fixed_data, 6);
        po += 6;
        memcpy(po, otp_config->uid, UID_SIZE);
        po += UID_SIZE;
        po += put_uint16_t_le(counter, po);
        ts >>= 1;
        *po++ = ts & 0xff;
        *po++ = ts >> 8;
        *po++ = ts >> 16;
        *po++ = session_counter[n];
        random_gen(NULL, po, 2);
        po += 2;
        crc = calculate_crc(otpk + 6, 14);
        po += put_uint16_t_le(~crc, po);
        mbedtls_aes_context ctx;
        mbedtls_aes_init(&ctx);
        mbedtls_aes_setkey_enc(&ctx, otp_config->aes_key, 128);
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, otpk + 6, otpk + 6);
        mbedtls_aes_free(&ctx);
        if (++session_counter[n] == 0) {
            if (++counter <= 0x7fff) {
                update_counter = true;
            }
        }
        bool durable = true;
        if (update_counter == true) {
            put_uint16_t_be(counter, rec + otp_config_size);
            durable = otp_slot_commit(n, rec, seal);
        }
        if (durable) {
            uint8_t otp_out[44];
            encode_modhex(otpk, sizeof(otpk), otp_out);
            add_keyboard_buffer((const uint8_t *) otp_out, sizeof(otp_out), true);
            if (otp_config->tkt_flags & APPEND_CR) {
                append_keyboard_buffer((const uint8_t *) "\r", 1);
            }
            mbedtls_platform_zeroize(otp_out, sizeof(otp_out));
        }
        mbedtls_platform_zeroize(otpk, sizeof(otpk));
    }
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return ret;
}

/* Called from the core 0 loop for button presses while idle (1 press: slot
 * 1, ...). It runs under usb_lock and only while no command runs, so the
 * slots, the storage transaction and the keyboard buffer are its own. */
int otp_button_pressed(uint8_t slot) {
    if (slot < 1 || slot > OTP_SLOTS) {
        return 1;
    }
    usb_lock();
    int ret = 3;
    /* Nothing is typed while the key store is locked. */
    if (!is_busy() && security_keystore_unlocked()) {
        init_otp();
        if (cap_supported(CAP_OTP)) {
            ret = otp_slot_type(slot - 1);
        }
    }
    usb_unlock();
    return ret;
}

INITIALIZER( otp_ctor ) {
    register_app(otp_select, otp_aid);
    button_pressed_cb = otp_button_pressed;
    hid_set_report_cb = otp_hid_set_report_cb;
    hid_get_report_cb = otp_hid_get_report_cb;
}

int otp_unload() {
    return PICOKEY_OK;
}

/* ------------------------------------------------------------------------ */
/* Status                                                                   */
/* ------------------------------------------------------------------------ */

/* Status flags (0x20 while a challenge-response waits for a touch). */
static volatile uint8_t status_byte = 0x0;
/* Status the keyboard interface reports while a command runs: written in the
 * USB context only (usb_lock), never by the card thread. */
static uint8_t otp_status_cache[7];

uint16_t otp_status_ext() {
    if (!otp_meta_loaded) {
        otp_meta_load();
    }
    for (uint8_t i = 0; i < OTP_SLOTS; i++) {
        const otp_meta_t *m = &otp_meta[i];
        if (m->valid) {
            res_APDU[res_APDU_size++] = 0xB0 + i;
            res_APDU[res_APDU_size++] = 0; // Filled later
            uint8_t *p = res_APDU + res_APDU_size;
            *p++ = 0xA0;
            *p++ = 2;
            *p++ = m->tkt_flags;
            *p++ = m->cfg_flags;
            if (!otp_flags_chalresp(m->tkt_flags, m->cfg_flags) && !(m->tkt_flags & OATH_HOTP) &&
                !((m->cfg_flags & SHORT_TICKET) || (m->cfg_flags & STATIC_TICKET))) {
                *p++ = 0xC0;
                *p++ = 6;
                memcpy(p, m->fixed, 6);
                p += 6;
            }
            uint8_t len = (uint8_t)(p - (res_APDU + res_APDU_size));
            res_APDU[res_APDU_size - 1] = len;
            res_APDU_size += len;
        }
    }
    return SW_OK();
}

/* Status: version (3 bytes), programming sequence, touch level (slot 1 and 2
 * flags, 2 bytes), status flags. */
static void otp_status_build(uint8_t out[7]) {
    if (!otp_meta_loaded) {
        otp_meta_load();
    }
    out[0] = PICO_FIDO_VERSION_MAJOR;
    out[1] = PICO_FIDO_VERSION_MINOR;
    out[2] = 0;
    out[3] = config_seq;
    uint8_t opts = 0;
    for (uint8_t i = 0; i < 2; i++) {
        const otp_meta_t *m = &otp_meta[i];
        if (m->valid) {
            opts |= i == 0 ? CONFIG1_VALID : CONFIG2_VALID;
            /* Touch triggered: a slot that types on a press (Yubico OTP,
             * OATH-HOTP, static password). A challenge-response slot is not,
             * even one that waits for the button (CHAL_BTN_TRIG): a press
             * types nothing, and yubikit's is_touch_triggered means "triggered
             * by touch (not challenge-response)". */
            if (!otp_flags_chalresp(m->tkt_flags, m->cfg_flags)) {
                opts |= i == 0 ? CONFIG1_TOUCH : CONFIG2_TOUCH;
            }
        }
    }
    out[4] = opts;
    out[5] = 0;
    out[6] = status_byte;
}

/* USB context only, while no command runs. */
static void otp_status_publish(void) {
    otp_status_build(otp_status_cache);
}

uint16_t otp_status(bool is_otp) {
    if (scanned == false) {
        scan_all();
        scanned = true;
    }
    if (is_otp) {
        /* The keyboard interface reads the status with a feature report. */
        res_APDU_size = 0;
        return SW_OK();
    }
    otp_status_build(res_APDU);
    res_APDU_size = 7;
    apdu.ne = res_APDU_size;
    return SW_OK();
}

bool check_crc(const otp_config_t *data) {
    uint16_t crc = calculate_crc((const uint8_t *) data, otp_config_size);
    return crc == 0xF0B8;
}

/* ------------------------------------------------------------------------ */
/* Slot commands                                                            */
/* ------------------------------------------------------------------------ */

static bool _is_otp = false;

/* Slot index (0..3) of a slot command: base 0 (slot 1) or 1 (slot 2), P2
 * an offset from slot 1 (slots 3 and 4). */
static int otp_slot_index(uint8_t base, uint8_t p2) {
    if (base == 1 && p2 != 0) {
        return -1;
    }
    if (base + p2 >= OTP_SLOTS) {
        return -1;
    }
    return base + p2;
}

/* A slot without access code (all zero) is free; otherwise one of the codes
 * sent must match it. */
static bool otp_acc_free_or_ok(const uint8_t cur[OTP_REC_SIZE], const uint8_t *given, const uint8_t *given2) {
    static const uint8_t zero[ACC_CODE_SIZE] = { 0 };
    const otp_config_t *c = (const otp_config_t *) cur;
    if (ct_memcmp(c->acc_code, zero, ACC_CODE_SIZE) == 0) {
        return true;
    }
    return (given && ct_memcmp(c->acc_code, given, ACC_CODE_SIZE) == 0) ||
           (given2 && ct_memcmp(c->acc_code, given2, ACC_CODE_SIZE) == 0);
}

/* Writes need the slot's current access code, sent after the configuration. */
static bool otp_acc_ok(const uint8_t cur[OTP_REC_SIZE]) {
    const otp_config_t *c = (const otp_config_t *) cur;
    return ct_memcmp(c->acc_code, apdu.data + otp_config_size, ACC_CODE_SIZE) == 0;
}

static int otp_configure(uint8_t n) {
    if (apdu.nc < otp_config_size + ACC_CODE_SIZE) {
        return SW_WRONG_LENGTH();
    }
    uint8_t cur[OTP_REC_SIZE], rec[OTP_REC_SIZE];
    int ret;
    bool sealed = false;
    const otp_config_t *odata = (const otp_config_t *) apdu.data;
    bool erase = true;
    for (size_t c = 0; c < otp_config_size; c++) {
        if (apdu.data[c] != 0) {
            erase = false;
            break;
        }
    }
    memset(rec, 0, sizeof(rec));
    otp_slot_state_t st = otp_slot_load(n, cur, &sealed);
    if (st == OTP_SLOT_BAD) {
        ret = SW_EXEC_ERROR();                      /* its access code cannot be checked */
    }
    else if (st == OTP_SLOT_OK && !otp_acc_ok(cur)) {
        ret = SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    else if (erase) {
        otp_slot_delete(n);
        config_seq++;
        ret = otp_status(_is_otp);
    }
    else if (odata->rfu[0] != 0 || odata->rfu[1] != 0 || check_crc(odata) == false) {
        ret = SW_WRONG_DATA();
    }
    else {
        memcpy(rec, apdu.data, otp_config_size);     /* the counter area starts at zero */
        if (otp_slot_store(n, rec, sealed || otp_seal_new()) != PICOKEY_OK) {
            ret = SW_MEMORY_FAILURE();
        }
        else {
            config_seq++;
            ret = otp_status(_is_otp);
        }
    }
    mbedtls_platform_zeroize(cur, sizeof(cur));
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return ret;
}

static int otp_update(uint8_t n) {
    if (apdu.nc < otp_config_size + ACC_CODE_SIZE) {
        return SW_WRONG_LENGTH();
    }
    const otp_config_t *odata = (const otp_config_t *) apdu.data;
    if (odata->rfu[0] != 0 || odata->rfu[1] != 0 || check_crc(odata) == false) {
        return SW_WRONG_DATA();
    }
    uint8_t cur[OTP_REC_SIZE];
    int ret;
    bool sealed = false;
    const otp_config_t *otpc = (const otp_config_t *) cur;
    otp_slot_state_t st = otp_slot_load(n, cur, &sealed);
    if (st == OTP_SLOT_EMPTY) {
        ret = otp_status(_is_otp);
    }
    else if (st == OTP_SLOT_BAD) {
        ret = SW_EXEC_ERROR();
    }
    else if (!otp_acc_ok(cur)) {
        ret = SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    else if (!(otpc->ext_flags & ALLOW_UPDATE)) {
        ret = SW_CONDITIONS_NOT_SATISFIED();
    }
    else {
        /* Secrets, fixed part, UID and the counter area stay; the flags that
         * may change and the new access code come from the host. */
        uint8_t rec[OTP_REC_SIZE];
        otp_config_t *r = (otp_config_t *) rec;
        memcpy(rec, cur, sizeof(rec));
        memcpy(r->acc_code, odata->acc_code, ACC_CODE_SIZE);
        r->ext_flags = (otpc->ext_flags & ~EXTFLAG_UPDATE_MASK) | (odata->ext_flags & EXTFLAG_UPDATE_MASK);
        r->tkt_flags = (otpc->tkt_flags & ~TKTFLAG_UPDATE_MASK) | (odata->tkt_flags & TKTFLAG_UPDATE_MASK);
        if (!(otpc->tkt_flags & CHAL_RESP)) {
            r->cfg_flags = (otpc->cfg_flags & ~CFGFLAG_UPDATE_MASK) | (odata->cfg_flags & CFGFLAG_UPDATE_MASK);
        }
        if (otp_slot_store(n, rec, sealed || otp_seal_new()) != PICOKEY_OK) {
            ret = SW_MEMORY_FAILURE();
        }
        else {
            config_seq++;
            ret = otp_status(_is_otp);
        }
        mbedtls_platform_zeroize(rec, sizeof(rec));
    }
    mbedtls_platform_zeroize(cur, sizeof(cur));
    return ret;
}

/* Swaps two slots. Accepted forms:
 * - no data, or the 6-byte access code field yubikit and ykpers send (a
 *   configuration frame with the code after it, over the keyboard the code
 *   at the start or after an empty configuration): slots 1 and 2;
 * - smart card interface, 2 bytes (+ 6 bytes of access code): slot 1 +
 *   data[0] and slot 2 + data[1].
 * A slot protected by an access code only moves when that code is sent, as
 * it could not be changed or deleted otherwise. */
static int otp_swap(void) {
    const uint8_t *given = NULL, *given2 = NULL;
    uint8_t a = 0, b = 1;
    if (_is_otp) {
        given = apdu.data;
        given2 = apdu.data + otp_config_size;
    }
    else if (apdu.nc == 0) {
    }
    else if (apdu.nc == ACC_CODE_SIZE) {
        given = apdu.data;
    }
    else if (apdu.nc == otp_config_size + ACC_CODE_SIZE) {
        given = apdu.data + otp_config_size;
    }
    else if (apdu.nc == 2 || apdu.nc == 2 + ACC_CODE_SIZE) {
        a = apdu.data[0];
        b = 1 + apdu.data[1];
        if (apdu.data[1] >= OTP_SLOTS || a >= OTP_SLOTS || b >= OTP_SLOTS || a == b) {
            return SW_WRONG_DATA();
        }
        if (apdu.nc == 2 + ACC_CODE_SIZE) {
            given = apdu.data + 2;
        }
    }
    else {
        return SW_WRONG_LENGTH();
    }
    uint8_t ra[OTP_REC_SIZE], rb[OTP_REC_SIZE];
    bool sealed_a = false, sealed_b = false;
    otp_slot_state_t sa = otp_slot_load(a, ra, &sealed_a), sb = otp_slot_load(b, rb, &sealed_b);
    int ret;
    if (sa == OTP_SLOT_BAD || sb == OTP_SLOT_BAD) {
        ret = SW_EXEC_ERROR();
    }
    else if ((sa == OTP_SLOT_OK && !otp_acc_free_or_ok(ra, given, given2)) ||
             (sb == OTP_SLOT_OK && !otp_acc_free_or_ok(rb, given, given2))) {
        ret = SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    else {
        int r = PICOKEY_OK;
        bool seal = otp_seal_new();
        if (sb == OTP_SLOT_OK) {
            r = otp_slot_store(a, rb, sealed_b || seal);
        }
        else {
            otp_slot_delete(a);
        }
        if (r == PICOKEY_OK) {
            if (sa == OTP_SLOT_OK) {
                r = otp_slot_store(b, ra, sealed_a || seal);
            }
            else {
                otp_slot_delete(b);
            }
        }
        if (r != PICOKEY_OK) {
            ret = SW_MEMORY_FAILURE();
        }
        else {
            low_flash_available();
            config_seq++;
            ret = otp_status(_is_otp);
        }
    }
    mbedtls_platform_zeroize(ra, sizeof(ra));
    mbedtls_platform_zeroize(rb, sizeof(rb));
    return ret;
}

static int otp_calculate(uint8_t p1, uint8_t n) {
    uint8_t rec[OTP_REC_SIZE];
    otp_slot_state_t st = otp_slot_load(n, rec, NULL);
    if (st == OTP_SLOT_EMPTY) {
        return SW_OK();
    }
    if (st == OTP_SLOT_BAD) {
        return SW_EXEC_ERROR();
    }
    const otp_config_t *otp_config = (const otp_config_t *) rec;
    bool hmac = p1 == 0x30 || p1 == 0x38;
    /* The challenge is copied before any wait for a touch. */
    uint8_t chal[64];
    uint16_t chal_len = (uint16_t) MIN(apdu.nc, sizeof(chal));
    memcpy(chal, apdu.data, chal_len);
    int ret;
    if (!(otp_config->tkt_flags & CHAL_RESP)) {
        ret = SW_WRONG_DATA();
    }
    else if ((otp_config->cfg_flags & CHAL_HMAC) != (hmac ? CHAL_HMAC : CHAL_YUBICO)) {
        ret = SW_WRONG_DATA();              /* the slot is in the other challenge-response mode */
    }
    else if (hmac ? chal_len == 0 : chal_len < 6) {
        ret = SW_WRONG_LENGTH();
    }
    else if ((otp_config->cfg_flags & CHAL_BTN_TRIG) && _is_otp && !lf_presence_automatic(LF_APP_OTP)) {
        /* The keyboard interface is served in the USB stack's context, which
         * cannot wait for the button: a slot that needs a touch answers over
         * the smart card interface only, unless the profile gives OTP
         * automatic presence (no wait). */
        printf("[otp] challenge-response with touch refused on the keyboard interface\n");
        ret = SW_CONDITIONS_NOT_SATISFIED();
    }
    else {
        ret = PICOKEY_OK;
        if ((otp_config->cfg_flags & CHAL_BTN_TRIG) && !_is_otp) {
            status_byte = RESP_TIMEOUT_WAIT;
            bool no_press = lf_wait_presence(LF_APP_OTP);
            status_byte = 0x00;
            if (no_press) {
                ret = SW_CONDITIONS_NOT_SATISFIED();
            }
        }
        if (ret == PICOKEY_OK && hmac) {
            uint8_t aes_key[KEY_SIZE + UID_SIZE];
            memcpy(aes_key, otp_config->aes_key, KEY_SIZE);
            memcpy(aes_key + KEY_SIZE, otp_config->uid, UID_SIZE);
            /* A shorter challenge is padded to 64 bytes with its last byte
             * repeated (HMAC_LT64); over CCID Lc gives the length directly. */
            if (chal_len == 64 && (otp_config->cfg_flags & HMAC_LT64)) {
                uint8_t last = chal[63];
                while (chal_len > 0 && chal[chal_len - 1] == last) {
                    chal_len--;
                }
            }
            int r = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), aes_key, sizeof(aes_key), chal, chal_len, res_APDU);
            mbedtls_platform_zeroize(aes_key, sizeof(aes_key));
            if (r != 0) {
                ret = SW_EXEC_ERROR();
            }
            else {
                res_APDU_size = 20;
                ret = SW_OK();
            }
        }
        else if (ret == PICOKEY_OK) {
            uint8_t challenge[16];
            memcpy(challenge, chal, 6);
            memcpy(challenge + 6, pico_serial_str, 10);
            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            int r = mbedtls_aes_setkey_enc(&ctx, otp_config->aes_key, 128);
            if (r == 0) {
                r = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, challenge, res_APDU);
            }
            mbedtls_aes_free(&ctx);
            if (r != 0) {
                ret = SW_EXEC_ERROR();
            }
            else {
                res_APDU_size = 16;
                ret = SW_OK();
            }
        }
    }
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return ret;
}

int cmd_otp() {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    int n;
    if (p1 == 0x01 || p1 == 0x03) { // Configure slot
        if ((n = otp_slot_index(p1 == 0x01 ? 0 : 1, p2)) < 0) {
            return SW_INCORRECT_P1P2();
        }
        return otp_configure((uint8_t) n);
    }
    else if (p1 == 0x04 || p1 == 0x05) { // Update slot
        if ((n = otp_slot_index(p1 == 0x04 ? 0 : 1, p2)) < 0) {
            return SW_INCORRECT_P1P2();
        }
        return otp_update((uint8_t) n);
    }
    else if (p1 == 0x06) { // Swap slots
        return otp_swap();
    }
    else if (p1 == 0x10) {
        memcpy(res_APDU, pico_serial.id, 4);
        res_APDU[0] &= ~0xFC; // Force 8-digit serial number
        res_APDU_size = 4;
    }
    else if (p1 == 0x13) { // Get config
        /* On the keyboard interface the answer has to fit its frames. */
        int len = _is_otp ? man_get_config_buf(res_APDU, 70 - 2) : man_get_config();
        if (len < 0) {
            return SW_WRONG_LENGTH();
        }
        if (_is_otp) {
            res_APDU_size = (uint16_t) len;
        }
    }
    else if (p1 == 0x14) {
        otp_status_ext();
    }
    else if (p1 == 0x30 || p1 == 0x38 || p1 == 0x20 || p1 == 0x28) { // Calculate OTP
        if ((n = otp_slot_index(p1 == 0x30 || p1 == 0x20 ? 0 : 1, p2)) < 0) {
            return SW_INCORRECT_P1P2();
        }
        return otp_calculate(p1, (uint8_t) n);
    }
    return SW_OK();
}

#define INS_OTP             0x01

static const cmd_t cmds[] = {
    { INS_OTP, cmd_otp },
    { 0x00, 0x0 }
};

int otp_process_apdu() {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    /* Key store locked (chip not ready in a HARDENED build, root key held):
     * no slot is used or written, also over the keyboard interface. */
    if (!security_keystore_unlocked()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (cap_supported(CAP_OTP)) {
        for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
            if (cmd->ins == INS(apdu)) {
                int r = cmd->cmd_handler();
                return r;
            }
        }
    }
    return SW_INS_NOT_SUPPORTED();
}

/* ------------------------------------------------------------------------ */
/* Single-key transfer (lf_keyio_otp.c)                                     */
/* ------------------------------------------------------------------------ */

/* The transfer carries the configuration and the counter area of a slot
 * (docs/KEY_TRANSFER.md). */
_Static_assert(otp_config_size == 52 && OTP_CTR_SIZE == 8, "the slot record of the single-key transfer");

/* Mode of a configuration, told apart in the order otp_slot_type() uses. */
static const char *otp_mode_name(const otp_config_t *c) {
    if (otp_is_chalresp(c)) {
        return (c->cfg_flags & CHAL_HMAC) == CHAL_HMAC ? "chal-hmac" : "chal-yubico";
    }
    if (otp_is_hotp(c)) {
        return "hotp";
    }
    if (otp_is_static(c)) {
        return "static";
    }
    return "yubico-otp";
}

static bool otp_acc_set(const otp_config_t *c) {
    static const uint8_t zero[ACC_CODE_SIZE] = { 0 };
    return ct_memcmp(c->acc_code, zero, ACC_CODE_SIZE) != 0;
}

/* Slot n (0..3) for a transfer: its configuration (52 bytes) and counter
 * area (8 bytes) as stored, whether an access code protects it, its mode.
 * cfg and ctr may be NULL. PICOKEY_OK, PICOKEY_ERR_FILE_NOT_FOUND (not
 * programmed) or PICOKEY_WRONG_DATA (programmed, cannot be opened). The
 * caller wipes cfg and ctr. */
int otp_keyio_get(uint8_t n, uint8_t *cfg, uint8_t *ctr, bool *acc_set, const char **mode) {
    uint8_t rec[OTP_REC_SIZE];
    otp_slot_state_t st = otp_slot_load(n, rec, NULL);
    int ret = st == OTP_SLOT_OK ? PICOKEY_OK : (st == OTP_SLOT_EMPTY ? PICOKEY_ERR_FILE_NOT_FOUND : PICOKEY_WRONG_DATA);
    if (st == OTP_SLOT_OK) {
        const otp_config_t *c = (const otp_config_t *) rec;
        if (cfg) {
            memcpy(cfg, rec, otp_config_size);
        }
        if (ctr) {
            memcpy(ctr, rec + otp_config_size, OTP_CTR_SIZE);
        }
        *acc_set = otp_acc_set(c);
        *mode = otp_mode_name(c);
    }
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return ret;
}

/* Whether the configuration cfg (52 bytes) may be imported into slot n
 * (0..3): the checks of the slot write (a configuration, not the erase
 * form; RFU bytes zero, CRC), then a configuration already in the slot is
 * only replaced when replace is set and, if it has an access code, with
 * that code (code, code_len). Answers the status word: 9000, 6A80 (invalid
 * configuration), 6A89 (slot programmed, replace not set), 6982 (access
 * code missing or wrong), 6400 (the slot cannot be opened: its access code
 * cannot be checked). Changes nothing. */
uint16_t otp_keyio_check(uint8_t n, const uint8_t *cfg, bool replace, const uint8_t *code, size_t code_len) {
    const otp_config_t *c = (const otp_config_t *) cfg;
    bool erase = true;
    for (size_t i = 0; i < otp_config_size && erase; i++) {
        erase = cfg[i] == 0;
    }
    if (n >= OTP_SLOTS || erase || c->rfu[0] != 0 || c->rfu[1] != 0 || check_crc(c) == false) {
        return 0x6A80;
    }
    uint8_t cur[OTP_REC_SIZE];
    otp_slot_state_t st = otp_slot_load(n, cur, NULL);
    const otp_config_t *oc = (const otp_config_t *) cur;
    uint16_t sw = 0x9000;
    if (st != OTP_SLOT_EMPTY && !replace) {
        sw = 0x6A89;
    }
    else if (st == OTP_SLOT_BAD) {
        sw = 0x6400;
    }
    else if (st == OTP_SLOT_OK && otp_acc_set(oc) &&
             (code == NULL || code_len != ACC_CODE_SIZE || ct_memcmp(oc->acc_code, code, ACC_CODE_SIZE) != 0)) {
        sw = 0x6982;
    }
    mbedtls_platform_zeroize(cur, sizeof(cur));
    return sw;
}

/* Stores an imported slot n (0..3), checked with otp_keyio_check(): as a
 * slot write stores it (sealed unless the slot and the firmware still use
 * the previous firmware's plaintext), with the imported counter area, and
 * moves the programming sequence on. A Yubico OTP slot starts a new
 * session, as at power up (init_otp()): the usage counter moves on and the
 * session counter starts over, so no OTP the exporting device typed with
 * the stored usage counter is typed again. The HOTP moving factor stays as
 * imported. Answers 9000, 6A80 (no such slot) or 6581. */
uint16_t otp_keyio_put(uint8_t n, const uint8_t *cfg, const uint8_t *ctr) {
    if (n >= OTP_SLOTS) {
        return 0x6A80;
    }
    /* The form of the record replaced, without opening it. */
    file_t *ef = search_dynamic_file(EF_OTP_SLOT1 + n);
    bool sealed = file_has_data(ef) && sks_is_sealed(SKS_NS_OTP, file_get_data(ef), file_get_size(ef));
    uint8_t rec[OTP_REC_SIZE];
    memcpy(rec, cfg, otp_config_size);
    memcpy(rec + otp_config_size, ctr, OTP_CTR_SIZE);
    const otp_config_t *c = (const otp_config_t *) rec;
    bool yubico_otp = !otp_is_chalresp(c) && !otp_is_hotp(c) && !otp_is_static(c);
    if (yubico_otp) {
        uint16_t counter = get_uint16_t_be(rec + otp_config_size);
        if (counter < 0x7fff) {
            put_uint16_t_be(counter + 1, rec + otp_config_size);
        }
    }
    uint16_t sw = 0x9000;
    if (otp_slot_store(n, rec, sealed || otp_seal_new()) != PICOKEY_OK) {
        sw = 0x6581;
    }
    else {
        if (yubico_otp) {
            session_counter[n] = 0;
        }
        config_seq++;
    }
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return sw;
}

/* ------------------------------------------------------------------------ */
/* Keyboard interface (OTP HID feature reports)                             */
/* ------------------------------------------------------------------------ */

/* The transport of ykpers and of yubikit's OTP backend: a command comes in
 * 10 frames of 7 bytes (64 data bytes, the slot command, a CRC), an answer
 * goes out in frames of 7 bytes, the status otherwise. The callbacks run in
 * the USB stack's context with usb_lock held, also while the card thread
 * runs a command of another interface. Frames are only collected into
 * private buffers then; a complete command waits (status SLOT_WRITE_FLAG, the
 * host keeps polling) and runs from the next status read once the card
 * thread is idle. It runs with its own header and buffers, and the shared
 * APDU state is restored after it. While a command runs the status comes
 * from a cache made in this context. */
static uint8_t otp_frame_rx[70] = {0};
static uint8_t otp_frame_tx[70] = {0};
static uint8_t otp_kb_hdr[5] = {0};
static uint8_t otp_kb_res[sizeof(otp_frame_tx)] = {0};
static uint8_t otp_exp_seq = 0, otp_curr_seq = 0;
static uint16_t otp_tx_left = 0;
static bool otp_kb_pending = false;         /* a complete command waits for the card thread */

static bool otp_kb_itf(uint8_t itf) {
#ifdef USB_ITF_HID
    return ITF_HID_KB != ITF_INVALID && itf == ITF_HID_KB;
#else
    (void) itf;
    return false;
#endif
}

static void otp_tx_reset(void) {
    otp_tx_left = 0;
    otp_curr_seq = otp_exp_seq = 0;
    mbedtls_platform_zeroize(otp_frame_tx, sizeof(otp_frame_tx));
}

static void otp_kb_drop(void) {
    otp_kb_pending = false;
    mbedtls_platform_zeroize(otp_frame_rx, sizeof(otp_frame_rx));
}

/* Queues the first len bytes of otp_frame_tx (plus CRC) for GET_REPORT. */
static void otp_send_frame(uint16_t len) {
    uint16_t crc = calculate_crc(otp_frame_tx, len);
    len += put_uint16_t_le(~crc, otp_frame_tx + len);
    otp_tx_left = len;
    otp_exp_seq = (uint8_t)((len + 6) / 7);
    otp_curr_seq = 0;
}

/* Runs the command in otp_frame_rx. Only while no command runs (USB context
 * under usb_lock: none can start meanwhile). */
static void otp_kb_command(void) {
    struct apdu saved = apdu;
    otp_kb_hdr[0] = 0x00;
    otp_kb_hdr[1] = INS_OTP;
    otp_kb_hdr[2] = otp_frame_rx[64];
    otp_kb_hdr[3] = 0x00;
    otp_kb_hdr[4] = 0x00;
    apdu.header = otp_kb_hdr;
    apdu.data = otp_frame_rx;
    apdu.nc = 64;
    apdu.ne = 0;
    apdu.rdata = otp_kb_res;
    apdu.rlen = 0;
    apdu.sw = 0;
    _is_otp = true;
    low_flash_txn_begin();
    otp_process_apdu();
    bool durable = low_flash_txn_end() == PICOKEY_OK;
    _is_otp = false;
    uint16_t sw = apdu.sw, rlen = apdu.rlen;
    apdu = saved;
    otp_tx_reset();
    if (durable && sw == 0x9000 && rlen > 0 && rlen + 2 <= sizeof(otp_frame_tx)) {
        memcpy(otp_frame_tx, otp_kb_res, rlen);
        otp_send_frame(rlen);
    }
    mbedtls_platform_zeroize(otp_kb_res, sizeof(otp_kb_res));
    otp_kb_drop();
    otp_status_publish();
}

int otp_hid_set_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize) {
    (void) report_id;
    if (report_type != 3) { /* feature reports only */
        return 0;
    }
    if (!otp_kb_itf(itf) || bufsize < 8) {
        return 1;           /* not the keyboard interface: dropped */
    }
    DEBUG_PAYLOAD(buffer, bufsize);
    if (buffer[7] == 0xFF) { // reset
        otp_tx_reset();
        otp_kb_drop();
    }
    else if (buffer[7] & 0x80) { // a frame
        uint8_t rseq = buffer[7] & 0x1F;
        if (rseq < 10) {
            if (rseq == 0) {
                /* Hosts skip frames of zeros, so start from a clean buffer. */
                otp_kb_drop();
            }
            memcpy(otp_frame_rx + rseq * 7, buffer, 7);
            if (rseq == 9) {
                uint16_t residual_crc = calculate_crc(otp_frame_rx, 64), rcrc = get_uint16_t_le(otp_frame_rx + 65);
                if (residual_crc != rcrc) {
                    printf("[OTP] Bad CRC!\n");
                    otp_kb_drop();
                }
                else if (is_busy()) {
                    otp_kb_pending = true;      /* runs from a status read once idle */
                }
                else {
                    otp_kb_command();
                }
            }
        }
    }
    return 1;
}

uint16_t otp_hid_get_report_cb(uint8_t itf,
                               uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t *buffer,
                               uint16_t reqlen) {
    (void) report_id;
    if (report_type != 3 || !otp_kb_itf(itf) || reqlen < 8) {
        return reqlen;
    }
    memset(buffer, 0, 8);
    if (otp_kb_pending && !is_busy()) {
        otp_kb_command();
    }
    if (otp_tx_left > 0) {
        uint8_t seq = otp_curr_seq++;
        uint16_t off = 7 * seq, n = MIN(7, otp_tx_left);
        if (off + n <= sizeof(otp_frame_tx)) {
            memcpy(buffer, otp_frame_tx + off, n);
        }
        buffer[7] = RESP_PENDING_FLAG | seq;
        DEBUG_DATA(buffer, 8);
        otp_tx_left -= n;
    }
    else if (otp_curr_seq == otp_exp_seq && otp_exp_seq > 0) {
        buffer[7] = RESP_PENDING_FLAG;
        DEBUG_DATA(buffer, 8);
        otp_tx_reset();
    }
    else {
        /* While a command runs the slots are not read from here. */
        if (!is_busy()) {
            otp_status_publish();
        }
        memcpy(buffer + 1, otp_status_cache, sizeof(otp_status_cache));
        buffer[7] = otp_kb_pending ? SLOT_WRITE_FLAG : status_byte;
        DEBUG_DATA(buffer, 8);
    }
    return reqlen;
}
