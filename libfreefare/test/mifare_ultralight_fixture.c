/*-
 * Copyright (C) 2010, Romain Tartiere.
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

#include <cutter.h>
#include <freefare.h>

static nfc_device_t *device = NULL;
static MifareUltralightTag *tags = NULL;
MifareUltralightTag tag = NULL;

void
setup ()
{
    int res;

    device = nfc_connect (NULL);
    cut_assert_not_null (device, "No device found");

    tags = mifare_ultralight_get_tags (device);
    cut_assert_not_null (tags ,"Error enumerating NFC tags");

    cut_assert_not_null (tags[0], "No MIFARE CLassic tag on NFC device");

    tag = tags[0];

    res = mifare_ultralight_connect (tag);
    cut_assert_equal_int (0, res);
}

void
teardown ()
{
    if (tag)
	mifare_ultralight_disconnect (tag);

    if (tags)
	mifare_ultralight_free_tags (tags);

    if (device)
	nfc_disconnect (device);
}

