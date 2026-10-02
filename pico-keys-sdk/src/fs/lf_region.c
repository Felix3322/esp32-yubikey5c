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
#include <stdlib.h>
#include <string.h>
#include "pico_keys.h"
#include "lf_region.h"

#if defined(ESP_PLATFORM)

#include "esp_partition.h"
#include "esp_flash_encrypt.h"

/* Partition type used by pico-keys-sdk for its data partitions. */
#define LF_PART_TYPE        0x40

static const esp_partition_t *find_part(uint8_t id) {
    if (id == LF_REG_LEGACY) {
        return esp_partition_find_first(LF_PART_TYPE, 0x01, "part0");
    }
    if (id == LF_REG_SYS) {
        return esp_partition_find_first(LF_PART_TYPE, 0x10, "lfsys");
    }
    if (id == LF_REG_STAGE) {
        return esp_partition_find_first(LF_PART_TYPE, 0x11, "lfstage");
    }
    if (id >= LF_REG_STORE0 && id < LF_REG_COUNT) {
        return esp_partition_find_first(LF_PART_TYPE, 0x20 + (id - LF_REG_STORE0), NULL);
    }
    return NULL;
}

bool lf_region_open(lf_region_t *r, uint8_t id) {
    memset(r, 0, sizeof(*r));
    r->id = id;
    const esp_partition_t *p = find_part(id);
    if (p == NULL) {
        return false;
    }
    r->part = p;
    r->size = p->size;
    r->present = true;
    return true;
}

/* ESP-IDF ignores the partition's "encrypted" flag while flash encryption is
 * off (reads, writes and the map all see plain data), and honours it once it
 * is on. Without the flag, an encrypted chip would write plain data but
 * decrypt it through the map. */
bool lf_region_crypt_ok(const lf_region_t *r) {
    if (!r->present) {
        return true;
    }
    return !esp_flash_encryption_enabled() || ((const esp_partition_t *) r->part)->encrypted;
}

static bool in_range(const lf_region_t *r, uint32_t off, uint32_t len) {
    return r->present && off <= r->size && len <= r->size - off;
}

int lf_region_erase(lf_region_t *r, uint32_t off, uint32_t len) {
    if (!in_range(r, off, len) || (off | len) % LF_SECTOR_SIZE) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    return esp_partition_erase_range(r->part, off, len) == ESP_OK ? PICOKEY_OK : PICOKEY_ERR_MEMORY_FATAL;
}

int lf_region_write(lf_region_t *r, uint32_t off, const void *src, uint32_t len) {
    if (!in_range(r, off, len) || (off | len) % LF_WRITE_ALIGN) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    return esp_partition_write(r->part, off, src, len) == ESP_OK ? PICOKEY_OK : PICOKEY_ERR_MEMORY_FATAL;
}

int lf_region_read(const lf_region_t *r, uint32_t off, void *dst, uint32_t len) {
    if (!in_range(r, off, len)) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    return esp_partition_read(r->part, off, dst, len) == ESP_OK ? PICOKEY_OK : PICOKEY_ERR_MEMORY_FATAL;
}

int lf_region_read_raw(const lf_region_t *r, uint32_t off, void *dst, uint32_t len) {
    if (!in_range(r, off, len)) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    return esp_partition_read_raw(r->part, off, dst, len) == ESP_OK ? PICOKEY_OK : PICOKEY_ERR_MEMORY_FATAL;
}

const uint8_t *lf_region_map(lf_region_t *r) {
    if (!r->present) {
        return NULL;
    }
    if (r->map == NULL) {
        const void *ptr = NULL;
        esp_partition_mmap_handle_t h;
        if (esp_partition_mmap(r->part, 0, r->size, ESP_PARTITION_MMAP_DATA, &ptr, &h) != ESP_OK) {
            return NULL;
        }
        r->map = ptr;
        r->mmap_handle = (uint32_t) h;
    }
    return r->map;
}

void lf_region_refresh(lf_region_t *r) {
    /* A fresh mapping guarantees the cache holds no pre-write lines. */
    if (r->map != NULL) {
        esp_partition_munmap((esp_partition_mmap_handle_t) r->mmap_handle);
        r->map = NULL;
        lf_region_map(r);
    }
}

void lf_region_unmap(lf_region_t *r) {
    if (r->map != NULL) {
        esp_partition_munmap((esp_partition_mmap_handle_t) r->mmap_handle);
        r->map = NULL;
    }
}

#else /* host emulation */

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* Emulated silicon ID, read from <eFuse file>.chipid (the test harness
 * gives every emulated device its own). Without that file it is all zeros,
 * the ID of earlier emulator builds, whose stores are bound to it. */
void emu_chip_id(uint8_t id[8]) {
    const char *e = getenv("PICO_EFUSE_FILE");
    char path[1024];
    snprintf(path, sizeof(path), "%s.chipid", e && *e ? e : "memory.efuse");
    memset(id, 0, 8);
    FILE *f = fopen(path, "rb");
    if (f) {
        if (fread(id, 1, 8, f) != 8) {
            memset(id, 0, 8);
        }
        fclose(f);
    }
}

/* Emulator flash file layout. The first 8 MiB keep the layout of earlier
 * emulator builds, whose store lived at [4 MiB, 8 MiB) with absolute
 * addresses, so their files are picked up by the migration code. */
#define EMU_LEGACY_OFF      0x000000u
#define EMU_LEGACY_SIZE     0x800000u
#define EMU_SYS_OFF         0x800000u
#define EMU_SYS_SIZE        0x010000u
#define EMU_STAGE_OFF       0x810000u
#define EMU_STAGE_SIZE      0x080000u
#define EMU_STORE_OFF       0x890000u
#define EMU_STORE_SIZE      0x180000u
#define EMU_FLASH_SIZE      (EMU_STORE_OFF + LF_STORE_REGIONS * EMU_STORE_SIZE)

static uint8_t *emu_map = NULL;
static long fault_countdown = -1;
static int fault_region = -1;           /* -1: every region counts */
static long fault_bytes = -1;           /* bytes a torn write programs, -1: random */
static int fail_region = -1;
static uint32_t fail_first = 0, fail_count = 0;

/* Fault control file (LF_FAULT_CTL), read once per process start, including
 * the re-exec of a reboot, and removed so it applies to that boot only:
 *   tear <region> <n> [<bytes>]      the n-th erase/write (from 0) of that
 *                                    region tears (a write after <bytes>
 *                                    bytes), the process dies
 *   fail <region> [<sector> <count>] every erase/write of the region (or of
 *                                    those sectors) fails: worn-out flash */
static void fault_ctl_load(void) {
    const char *path = getenv("LF_FAULT_CTL");
    if (!path || !*path) {
        return;
    }
    FILE *f = fopen(path, "r");
    if (!f) {
        return;
    }
    char mode[8] = { 0 };
    long a = -1, b = -1, c = -1;
    int n = fscanf(f, "%7s %ld %ld %ld", mode, &a, &b, &c);
    fclose(f);
    unlink(path);
    if (n >= 3 && strcmp(mode, "tear") == 0) {
        fault_region = (int) a;
        fault_countdown = b;
        fault_bytes = n >= 4 ? c : -1;
    }
    else if (n >= 2 && strcmp(mode, "fail") == 0) {
        fail_region = (int) a;
        fail_first = n >= 4 ? (uint32_t) b : 0;
        fail_count = n >= 4 ? (uint32_t) c : UINT32_MAX;
    }
    fprintf(stderr, "[lf_region] fault control: %s %ld %ld %ld\n", mode, a, b, c);
}

static void emu_open(void) {
    if (emu_map) {
        return;
    }
    const char *path = getenv("PICO_FLASH_FILE");
    int fd = open(path && *path ? path : "memory.flash", O_RDWR | O_CREAT, (mode_t) 0600);
    if (fd < 0) {
        perror("flash file");
        exit(1);
    }
    struct stat st;
    fstat(fd, &st);
    if ((size_t) st.st_size < EMU_FLASH_SIZE) {
        /* New space reads as erased NOR flash. */
        uint8_t ff[4096];
        memset(ff, 0xFF, sizeof(ff));
        lseek(fd, st.st_size, SEEK_SET);
        for (size_t pos = (size_t) st.st_size; pos < EMU_FLASH_SIZE; pos += sizeof(ff)) {
            size_t n = EMU_FLASH_SIZE - pos < sizeof(ff) ? EMU_FLASH_SIZE - pos : sizeof(ff);
            if (write(fd, ff, n) != (ssize_t) n) {
                perror("flash file");
                exit(1);
            }
        }
    }
    emu_map = mmap(NULL, EMU_FLASH_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (emu_map == MAP_FAILED) {
        perror("mmap flash file");
        exit(1);
    }
    const char *e = getenv("LF_FAULT_OPS");
    if (e && *e) {
        fault_countdown = strtol(e, NULL, 10);
    }
    fault_ctl_load();
}

void lf_region_emu_sync(void) {
    if (emu_map) {
        msync(emu_map, EMU_FLASH_SIZE, MS_SYNC);
    }
}

static bool fault_hit(const lf_region_t *r) {
    if (fault_countdown < 0 || (fault_region >= 0 && r->id != fault_region)) {
        return false;
    }
    return fault_countdown-- == 0;
}

static bool fail_hit(const lf_region_t *r, uint32_t off, uint32_t len) {
    if (fail_region < 0 || r->id != fail_region || len == 0) {
        return false;
    }
    uint32_t s0 = off / LF_SECTOR_SIZE, s1 = (off + len - 1) / LF_SECTOR_SIZE;
    return s1 >= fail_first && (uint64_t) s0 < (uint64_t) fail_first + fail_count;
}

static void fault_die(void) {
    lf_region_emu_sync();
    fprintf(stderr, "[lf_region] simulated power loss\n");
    _exit(99);
}

bool lf_region_open(lf_region_t *r, uint8_t id) {
    emu_open();
    memset(r, 0, sizeof(*r));
    r->id = id;
    if (id == LF_REG_LEGACY) {
        r->offset = EMU_LEGACY_OFF;
        r->size = EMU_LEGACY_SIZE;
    }
    else if (id == LF_REG_SYS) {
        r->offset = EMU_SYS_OFF;
        r->size = EMU_SYS_SIZE;
    }
    else if (id == LF_REG_STAGE) {
        r->offset = EMU_STAGE_OFF;
        r->size = EMU_STAGE_SIZE;
    }
    else if (id >= LF_REG_STORE0 && id < LF_REG_COUNT) {
        r->offset = EMU_STORE_OFF + (uint32_t) (id - LF_REG_STORE0) * EMU_STORE_SIZE;
        r->size = EMU_STORE_SIZE;
    }
    else {
        return false;
    }
    r->present = true;
    r->map = emu_map + r->offset;
    return true;
}

/* LF_EMU_FE_UNFLAGGED=1 plays a chip with flash encryption on and a
 * partition table without the "encrypted" flags. */
bool lf_region_crypt_ok(const lf_region_t *r) {
    const char *e = getenv("LF_EMU_FE_UNFLAGGED");
    return !r->present || !(e && *e == '1');
}

static bool in_range(const lf_region_t *r, uint32_t off, uint32_t len) {
    return r->present && off <= r->size && len <= r->size - off;
}

int lf_region_erase(lf_region_t *r, uint32_t off, uint32_t len) {
    if (!in_range(r, off, len) || (off | len) % LF_SECTOR_SIZE) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    for (uint32_t s = 0; s < len; s += LF_SECTOR_SIZE) {
        uint8_t *p = emu_map + r->offset + off + s;
        if (fail_hit(r, off + s, LF_SECTOR_SIZE)) {
            return PICOKEY_ERR_MEMORY_FATAL;
        }
        if (fault_hit(r)) {
            for (size_t i = 0; i < LF_SECTOR_SIZE; i += 64) {
                p[i] = (uint8_t) rand();
            }
            fault_die();
        }
        memset(p, 0xFF, LF_SECTOR_SIZE);
    }
    return PICOKEY_OK;
}

int lf_region_write(lf_region_t *r, uint32_t off, const void *src, uint32_t len) {
    /* Same alignment rule as encrypted ESP32 flash, so tests catch misuse. */
    if (!in_range(r, off, len) || (off | len) % LF_WRITE_ALIGN) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    uint8_t *p = emu_map + r->offset + off;
    if (fail_hit(r, off, len)) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    if (fault_hit(r)) {
        size_t n = fault_bytes >= 0 ? (size_t) fault_bytes : (len ? (size_t) rand() % len : 0);
        memcpy(p, src, n < len ? n : len);
        fault_die();
    }
    /* NOR programming only clears bits. */
    const uint8_t *s = src;
    for (uint32_t i = 0; i < len; i++) {
        p[i] &= s[i];
    }
    return PICOKEY_OK;
}

int lf_region_read(const lf_region_t *r, uint32_t off, void *dst, uint32_t len) {
    if (!in_range(r, off, len)) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    memcpy(dst, emu_map + r->offset + off, len);
    return PICOKEY_OK;
}

int lf_region_read_raw(const lf_region_t *r, uint32_t off, void *dst, uint32_t len) {
    return lf_region_read(r, off, dst, len);
}

const uint8_t *lf_region_map(lf_region_t *r) {
    return r->present ? emu_map + r->offset : NULL;
}

void lf_region_refresh(lf_region_t *r) {
    (void) r;
}

void lf_region_unmap(lf_region_t *r) {
    /* The flash file stays mapped, but the region's view goes away as on
     * the chip, so a read through a stale view shows up in tests. */
    r->map = NULL;
}

#endif

static bool all_ff(const lf_region_t *r, uint32_t off, uint32_t len, bool raw) {
    uint8_t buf[64];
    for (uint32_t pos = 0; pos < len; pos += sizeof(buf)) {
        uint32_t n = len - pos < sizeof(buf) ? len - pos : (uint32_t) sizeof(buf);
        int ret = raw ? lf_region_read_raw(r, off + pos, buf, n) : lf_region_read(r, off + pos, buf, n);
        if (ret != PICOKEY_OK) {
            return false;
        }
        for (uint32_t i = 0; i < n; i++) {
            if (buf[i] != 0xFF) {
                return false;
            }
        }
    }
    return true;
}

bool lf_region_blank(const lf_region_t *r, uint32_t off, uint32_t len) {
    return all_ff(r, off, len, true);
}

bool lf_region_erased(const lf_region_t *r, uint32_t off, uint32_t len) {
    return all_ff(r, off, len, true) || all_ff(r, off, len, false);
}
