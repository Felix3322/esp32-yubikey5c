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

#ifndef _LOW_FLASH_H_
#define _LOW_FLASH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Persists every pending write as one atomic transaction and returns only
 * when it is durable. Security relevant state (retry counters, counters that
 * must never repeat) must be committed with this BEFORE acting on it. */
extern int low_flash_commit(void);

/* A command handler's writes form one transaction: the card thread opens it
 * before dispatching and commits it before the response is released. */
extern void low_flash_txn_begin(void);
extern int low_flash_txn_end(void);
/* Abandons the running command's transaction as a whole: nothing it wrote
 * through the file system is committed and the file table is rebuilt from
 * the store (pointers to dynamic files the caller holds are void). Only an
 * explicit call by a handler, never implied by an error status. Refused
 * (PICOKEY_ERR_BLOCKED, nothing dropped: txn_end commits it all) when part
 * of the transaction already reached the store (a full cache, a commit of
 * another task or an explicit low_flash_commit(), e.g. a PIN retry counter:
 * write those before anything that may be abandoned, and commit them) or
 * another transaction runs. Monotonic counters (lf_ctr_set) are written
 * directly and are not rolled back. */
extern int low_flash_txn_abort(void);

/* One file system operation (flash.c): its writes reach the store together.
 * low_flash_reserve() declares the sectors it will write before the first
 * write; if they do not fit next to the pages already cached, those are
 * committed first, so a full cache never splits an operation. Between
 * op_begin and op_end every commit of another task (low_flash_commit,
 * txn_end, do_flash) waits for the operation to end. */
extern void low_flash_op_begin(void);
extern void low_flash_op_end(void);
extern int low_flash_reserve(const uintptr_t *addrs, int n);

extern bool low_flash_journal_active(void);
extern uint32_t low_flash_commit_failures(void);

/* True if the raw (not decrypted) flash content is in erased state. */
extern bool low_flash_region_blank(uintptr_t addr, size_t len);

/* Resilient store builds: drops cached writes when the mounted store changes. */
extern void low_flash_discard_cache(void);

/* Lets new records take a whole sector's payload, the size earlier firmware
 * stored (flash.c): only while data carried from such firmware is written
 * (migration, backup imports). */
extern void flash_allow_sector_records(bool on);

#endif // _LOW_FLASH_H_
