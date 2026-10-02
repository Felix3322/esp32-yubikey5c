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
#include "version.h"
#include "files.h"
#include "asn1.h"
#include "ctap.h"
#include "management.h"

/* Largest READ CONFIG answer (fixed part and the stored settings) and the
 * largest stored settings. */
#define MAN_CONFIG_MAX  64
#define MAN_CONF_MAX    32

bool is_gpg = true;

int man_process_apdu();
int man_unload();

const uint8_t man_aid[] = {
    8,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17
};
extern void scan_all();
extern void init_otp();
int man_select(app_t *a, uint8_t force) {
    a->process_apdu = man_process_apdu;
    a->unload = man_unload;
    sprintf((char *) res_APDU, "%d.%d.0", PICO_FIDO_VERSION_MAJOR, PICO_FIDO_VERSION_MINOR);
    res_APDU_size = (uint16_t)strlen((char *) res_APDU);
    apdu.ne = res_APDU_size;
    if (force) {
        scan_all();
#ifdef ENABLE_OTP_APP
        init_otp();
#endif
    }
    is_gpg = false;
    return PICOKEY_OK;
}

INITIALIZER ( man_ctor ) {
    register_app(man_select, man_aid);
}

int man_unload() {
    return PICOKEY_OK;
}

/* Next element of the device settings (one byte tag, one byte length);
 * false at the end or when the element does not fit the buffer. */
static bool conf_next(const uint8_t *buf, uint16_t len, uint16_t *off, uint8_t *tag, const uint8_t **val, uint8_t *vlen) {
    if (buf == NULL || *off + 2 > len) {
        return false;
    }
    uint8_t l = buf[*off + 1];
    if (l > len - *off - 2) {
        return false;
    }
    *tag = buf[*off];
    *val = buf + *off + 2;
    *vlen = l;
    *off += 2 + l;
    return true;
}

/* The settings WRITE CONFIG stores, with their valid lengths. */
static bool conf_stored_tag(uint8_t tag, uint8_t len) {
    switch (tag) {
        case TAG_USB_ENABLED:
        case TAG_NFC_ENABLED:
            return len == 1 || len == 2;
        case TAG_AUTO_EJECT_TIMEOUT:
            return len == 2;
        case TAG_CHALRESP_TIMEOUT:
        case TAG_DEVICE_FLAGS:
            return len == 1;
    }
    return false;
}

/* Applications enabled by device settings: all without TAG_USB_ENABLED. */
static uint16_t conf_caps(const uint8_t *data, uint16_t len) {
    const uint8_t *v = NULL;
    uint16_t off = 0;
    uint8_t tag = 0, l = 0;
    while (conf_next(data, len, &off, &tag, &v, &l)) {
        if (tag == TAG_USB_ENABLED && l >= 1) {
            return l == 2 ? get_uint16_t_be(v) : v[0];
        }
    }
    return 0xFFFF;
}

bool cap_supported(uint16_t cap) {
    file_t *ef = search_dynamic_file(EF_DEV_CONF);
    if (file_has_data(ef)) {
        return (conf_caps(file_get_data(ef), file_get_size(ef)) & cap) != 0;
    }
    return true;
}

static uint8_t _openpgp_aid[] = {
    6,
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
};
static uint8_t _piv_aid[] = {
    5,
    0xA0, 0x00, 0x00, 0x03, 0x8,
};

/* Device information (READ CONFIG) into out, which holds cap bytes. Only the
 * known settings of the stored configuration are reported. Returns the
 * length, or -1 when it does not fit. */
int man_get_config_buf(uint8_t *out, uint16_t cap) {
    uint8_t buf[MAN_CONFIG_MAX];
    uint16_t n = 0;
    file_t *ef = search_dynamic_file(EF_DEV_CONF);
    buf[n++] = 0; // Overall length. Filled later
    buf[n++] = TAG_USB_SUPPORTED;
    buf[n++] = 2;
    uint16_t caps = CAP_FIDO2 | CAP_OTP | CAP_U2F | CAP_OATH;
    if (app_exists(_openpgp_aid + 1, _openpgp_aid[0])) {
        caps |= CAP_OPENPGP;
    }
    if (app_exists(_piv_aid + 1, _piv_aid[0])) {
        caps |= CAP_PIV;
    }
    buf[n++] = caps >> 8;
    buf[n++] = caps & 0xFF;
    buf[n++] = TAG_SERIAL;
    buf[n++] = 4;
    memcpy(buf + n, pico_serial.id, 4);
    buf[n] &= ~0xFC; // Force 8-digit serial number
    n += 4;
    buf[n++] = TAG_FORM_FACTOR;
    buf[n++] = 1;
    buf[n++] = 0x01;
    buf[n++] = TAG_VERSION;
    buf[n++] = 3;
    buf[n++] = PICO_FIDO_VERSION_MAJOR;
    buf[n++] = PICO_FIDO_VERSION_MINOR;
    buf[n++] = 0;
    if (!file_has_data(ef)) {
        buf[n++] = TAG_USB_ENABLED;
        buf[n++] = 2;
        caps = 0;
        if (cap_supported(CAP_FIDO2)) {
            caps |= CAP_FIDO2;
        }
        if (cap_supported(CAP_OTP)) {
            caps |= CAP_OTP;
        }
        if (cap_supported(CAP_U2F)) {
            caps |= CAP_U2F;
        }
        if (cap_supported(CAP_OATH)) {
            caps |= CAP_OATH;
        }
        if (cap_supported(CAP_OPENPGP)) {
            caps |= CAP_OPENPGP;
        }
        if (cap_supported(CAP_PIV)) {
            caps |= CAP_PIV;
        }
        buf[n++] = caps >> 8;
        buf[n++] = caps & 0xFF;
        buf[n++] = TAG_DEVICE_FLAGS;
        buf[n++] = 1;
        buf[n++] = FLAG_EJECT;
        buf[n++] = TAG_CONFIG_LOCK;
        buf[n++] = 1;
        buf[n++] = 0x00;
    }
    else {
        const uint8_t *data = file_get_data(ef), *v = NULL;
        uint16_t len = file_get_size(ef), off = 0;
        uint8_t tag = 0, l = 0;
        while (conf_next(data, len, &off, &tag, &v, &l)) {
            if (conf_stored_tag(tag, l) && n + 2 + l <= sizeof(buf)) {
                buf[n++] = tag;
                buf[n++] = l;
                memcpy(buf + n, v, l);
                n += l;
            }
        }
    }
    buf[0] = (uint8_t)(n - 1);
    if (n > cap) {
        return -1;
    }
    memcpy(out, buf, n);
    return n;
}

/* READ CONFIG into res_APDU: every response buffer of the transports is far
 * larger than MAN_CONFIG_MAX. Returns the length or -1. */
int man_get_config() {
    int n = man_get_config_buf(res_APDU, MAN_CONFIG_MAX);
    res_APDU_size = n < 0 ? 0 : (uint16_t) n;
    return n;
}

int cmd_read_config() {
    if (man_get_config() < 0) {
        return SW_EXEC_ERROR();
    }
    return SW_OK();
}

/* WRITE CONFIG: length byte, then settings. Settings that are not sent keep
 * their value. A configuration lock is not supported: setting a lock code is
 * refused rather than accepted and ignored. */
int cmd_write_config() {
    if (apdu.nc < 1 || apdu.data[0] != apdu.nc - 1) {
        return SW_WRONG_DATA();
    }
    const uint8_t *in = apdu.data + 1, *v = NULL;
    uint16_t in_len = (uint16_t)(apdu.nc - 1), off = 0;
    uint8_t tag = 0, l = 0;
    const uint8_t *new_val[16] = { NULL };
    uint8_t new_len[16] = { 0 };
    while (off < in_len) {
        if (!conf_next(in, in_len, &off, &tag, &v, &l)) {
            return SW_WRONG_DATA();
        }
        if ((tag == TAG_REBOOT && l == 0) || (tag == TAG_UNLOCK && l == 16)) {
            continue;       /* no lock code is ever set; settings apply at the next power up */
        }
        if (tag == TAG_CONFIG_LOCK && l == 16) {
            for (uint8_t i = 0; i < l; i++) {
                if (v[i] != 0) {
                    return SW_CONDITIONS_NOT_SATISFIED();
                }
            }
            continue;       /* clearing the (absent) lock code */
        }
        if (!conf_stored_tag(tag, l) || new_val[tag] != NULL) {
            return SW_WRONG_DATA();
        }
        new_val[tag] = v;
        new_len[tag] = l;
    }
    uint8_t conf[MAN_CONF_MAX];
    uint16_t n = 0;
    bool seen[16] = { false };
    file_t *ef = search_dynamic_file(EF_DEV_CONF);
    if (file_has_data(ef)) {
        const uint8_t *data = file_get_data(ef);
        uint16_t len = file_get_size(ef);
        off = 0;
        while (conf_next(data, len, &off, &tag, &v, &l)) {
            if (conf_stored_tag(tag, l) && new_val[tag] == NULL && !seen[tag] && n + 2 + l <= sizeof(conf)) {
                seen[tag] = true;
                conf[n++] = tag;
                conf[n++] = l;
                memcpy(conf + n, v, l);
                n += l;
            }
        }
    }
    for (uint8_t t = 0; t < 16; t++) {
        if (new_val[t] != NULL && n + 2 + new_len[t] <= sizeof(conf)) {
            conf[n++] = t;
            conf[n++] = new_len[t];
            memcpy(conf + n, new_val[t], new_len[t]);
            n += new_len[t];
        }
    }
    /* The board settings first: the keyboard interface follows OTP when the
     * USB interfaces are recorded there. Only a real change goes through
     * their guarded write; when it is refused (not a normal boot, the free
     * changes used up without a touch, a restart pending) or fails, the
     * configuration stays as it was too (phy_save() restores phy_data). */
    phy_ensure_loaded();
    if (phy_data.enabled_usb_itf_present) {
        uint8_t itf = phy_data.enabled_usb_itf;
        if (conf_caps(conf, n) & CAP_OTP) {
            itf |= PHY_USB_ITF_KB;
        }
        else {
            itf &= ~PHY_USB_ITF_KB;
        }
        if (itf != phy_data.enabled_usb_itf) {
            phy_data.enabled_usb_itf = itf;
            int r = phy_save();
            if (r == PICOKEY_ERR_BLOCKED) {
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            if (r != PICOKEY_OK) {
                return SW_MEMORY_FAILURE();
            }
        }
    }
    if (n == 0) {
        delete_file(ef);
    }
    else {
        ef = file_new(EF_DEV_CONF);
        if (ef == NULL || file_put_data(ef, conf, n) != PICOKEY_OK) {
            return SW_MEMORY_FAILURE();
        }
    }
    low_flash_available();
    return SW_OK();
}

extern int cbor_reset();
/* FIDO reset. A refusal (power-on window over, no presence) or a failed wipe
 * is reported, never a success. */
int cmd_factory_reset() {
    int ret = cbor_reset();
    if (ret == 0) {
        return SW_OK();
    }
    if (ret == CTAP1_ERR_OTHER) {
        return SW_EXEC_ERROR();
    }
    return SW_CONDITIONS_NOT_SATISFIED();
}

#define INS_READ_CONFIG             0x1D
#define INS_WRITE_CONFIG            0x1C
#define INS_RESET                   0x1E    // Reset device

static const cmd_t cmds[] = {
    { INS_READ_CONFIG, cmd_read_config },
    { INS_WRITE_CONFIG, cmd_write_config },
    { INS_RESET, cmd_factory_reset },
    { 0x00, 0x0 }
};

int man_process_apdu() {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
