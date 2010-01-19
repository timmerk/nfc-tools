/*
 * Copyright (C) 2010, Romain Tartiere, Romuald Conty.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * $Id$
 */

#ifndef __FREEFARE_INTERNAL_H__
#define __FREEFARE_INTERNAL_H__

struct mad_sector_0x00;
struct mad_sector_0x10;

void		 crc8 (uint8_t *crc, const uint8_t value);
uint8_t		 sector_0x00_crc8 (Mad mad);
uint8_t		 sector_0x10_crc8 (Mad mad);

#define MIFARE_ULTRALIGHT_PAGE_COUNT 16

struct mifare_ultralight_tag {
    nfc_device_t *device;
    nfc_iso14443a_info_t info;
    int active;

    /* mifare_ultralight_read() reads 4 pages at a time (wrapping) */
    MifareUltralightPage cache[MIFARE_ULTRALIGHT_PAGE_COUNT + 3];
    uint8_t cached_pages[MIFARE_ULTRALIGHT_PAGE_COUNT];
};

#define ASSERT_ACTIVE(tag) do { if (!tag->active) return errno = ENXIO, -1; } while (0)
#define ASSERT_INACTIVE(tag) do  { if (tag->active) return errno = ENXIO, -1; } while (0)

#endif /* !__FREEFARE_INTERNAL_H__ */
