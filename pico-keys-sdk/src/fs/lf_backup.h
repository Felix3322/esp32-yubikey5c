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

/*
 * Profile backup stream, format 1. Used for export, import (clones, restore
 * from file) and the migration of stores of older firmware.
 *
 *   record := type (u8) | length (u16, little endian) | value
 *
 *   0x01 HEADER   lfbk_header_t (always first)
 *   0x02 ROOTKEY  flags (u8), key (32): the profile root key, unwrapped
 *   0x03 FILE     fid (u16 LE), content
 *   0x04 COUNTER  id (u8), value (u32 LE)
 *   0x7F END      SHA-256 over every preceding byte (always last)
 *
 * The stream carries every file of the profile except the board settings
 * (device wide) and the chip-wrapped root key (carried as ROOTKEY instead),
 * so importing it rebuilds the same profile on any device. The files keep the
 * formats of the applications that wrote them; like data kept in flash across
 * firmware updates, they are upgraded by the applications themselves, so a
 * stream stays importable by later firmware. Record types unknown to a
 * firmware make it refuse the stream rather than drop data.
 *
 * Plaintext by design: optional encryption with a passphrase is done by the
 * host tool around this stream (see tools/librefido).
 */

#ifndef _LF_BACKUP_H_
#define _LF_BACKUP_H_

#include <stdbool.h>
#include <stdint.h>
#include "mbedtls/sha256.h"

#define LFBK_FORMAT             1
#define LFBK_REC_HEADER         0x01
#define LFBK_REC_ROOTKEY        0x02
#define LFBK_REC_FILE           0x03
#define LFBK_REC_COUNTER        0x04
#define LFBK_REC_END            0x7F

#define LFBK_F_MIGRATION        0x0001  /* produced from a legacy store */

/* LibreFido firmware version written into new streams (the firmware's own;
 * a stream whose min_fw is newer is refused). */
#define LFBK_FW_MAJOR           2
#define LFBK_FW_MINOR           1
#define LFBK_FW_PATCH           0

/* Oldest firmware able to import the streams this firmware writes: 2.1.0.
 * A profile of 2.1.0 may hold explicit-key FIDO credentials (single-key
 * import, lf_keyio.h), whose sealed record carries the private key in a
 * format 2.0.x does not know: a restore there would silently leave them
 * unusable, so it refuses the stream by this. (2.0.1 streams already
 * carried records in the sealed formats that 2.0.0 would misread.) Streams
 * of 2.0.0 and 2.0.1 still import here. */
#define LFBK_MIN_FW_MAJOR       2
#define LFBK_MIN_FW_MINOR       1
#define LFBK_MIN_FW_PATCH       0

typedef struct __attribute__((packed)) {
    char magic[4];                  /* "LFBK" */
    uint16_t format;                /* LFBK_FORMAT */
    uint16_t flags;                 /* LFBK_F_* */
    uint8_t fw[3];                  /* firmware that wrote the stream */
    uint8_t min_fw[3];              /* oldest firmware able to import it */
    uint8_t uuid[16];               /* profile */
    uint8_t serial[8];              /* profile serial (USB / card serials) */
    uint8_t color[3];
    uint8_t profile_flags;
    char name[24];
    uint8_t schema[8];              /* reserved for per-application versions */
} lfbk_header_t;

typedef struct {
    lfbk_header_t hdr;
    bool has_root;
    uint32_t files;
    uint32_t counters;
    uint32_t length;                /* stream bytes */
    uint8_t sha256[32];             /* of the whole stream */
} lfbk_info_t;

/* Staging area (LF_REG_STAGE): one stream at a time. Streams hold keys in
 * the clear, so the stage is erased whenever a stream is no longer needed:
 * at the end of every session, before a new stream, and at every boot. */
enum {
    LF_STAGE_EMPTY = 0,
    LF_STAGE_EXPORT = 1,            /* stream of the active profile */
    LF_STAGE_IMPORT = 2,            /* stream received for an import */
    LF_STAGE_MIGRATION = 3,         /* stream of the legacy store */
};

extern uint32_t lf_stage_capacity(void);
/* Starts a new stream: every previous one is erased first. */
extern int lf_stage_begin(uint8_t purpose, uint8_t target);
extern int lf_stage_append(const uint8_t *p, uint32_t n);
/* Seals the stream: length and SHA-256 are recorded in the stage header. */
extern int lf_stage_finish(void);
extern int lf_stage_read(uint32_t off, uint8_t *p, uint32_t n);
/* Purpose / target / length of a sealed stream; false if none. */
extern bool lf_stage_info(uint8_t *purpose, uint8_t *target, uint32_t *length);
/* SHA-256 of the whole sealed stream (transfer integrity). */
extern bool lf_stage_digest(uint8_t out[32]);
/* Erases every stream written since the stage was last clean (the first
 * time in a boot: every sector that is not blank). */
extern int lf_stage_clear(void);
/* Once per boot, after the system area is loaded (lf_storage_boot()):
 * erases whatever an interrupted export, import or migration left, except
 * a stream that the pending import or restore test of the record read
 * from flash still needs. Writes nothing in LF_BOOT_ERR_LAYOUT. Does
 * nothing afterwards. */
extern void lf_stage_boot_cleanup(void);

/* Serializes the mounted profile into the staging area. root may be NULL. */
extern int lf_backup_export(const lfbk_header_t *hdr, const uint8_t root[32], uint8_t root_flags, uint8_t purpose);

/* Fully validates the sealed stream in the staging area without changing
 * anything. */
extern int lf_backup_check(lfbk_info_t *info);

/* The same validation, fed with the stream as it arrives: the plain check
 * of an upload ("verify without importing") runs it without writing
 * anything to flash. begin, any number of feed, then end or abort (both
 * free the context; end fills info when the stream is valid). */
typedef struct {
    bool active;
    int err;
    mbedtls_sha256_context all;     /* every byte so far */
    uint16_t *fids;                 /* files seen (duplicates are refused) */
    uint32_t payload;
    uint8_t rh[3];                  /* record header being received */
    uint8_t rh_got;
    uint8_t type;
    uint16_t len, got;              /* record value length, bytes received */
    uint8_t val[sizeof(lfbk_header_t)];     /* first bytes of the value */
    uint8_t end_digest[32];
    bool header, end;
    lfbk_info_t info;
} lfbk_check_t;
extern int lf_backup_check_begin(lfbk_check_t *c);
extern int lf_backup_check_feed(lfbk_check_t *c, const uint8_t *p, uint32_t n);
extern int lf_backup_check_end(lfbk_check_t *c, lfbk_info_t *info);
extern void lf_backup_check_abort(lfbk_check_t *c);

/* Writes the staged stream into the mounted, freshly formatted profile and
 * verifies every record against what was stored. */
extern int lf_backup_import(lfbk_info_t *info);

extern void lf_backup_header_init(lfbk_header_t *hdr);

#endif
