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

#include <stdlib.h>
#include <string.h>

#include <freefare.h>
#include "freefare_internal.h"

MifareDESFireKey
mifare_desfire_des_key_new (uint8_t value[8])
{
    uint8_t data[8];
    memcpy (data, value, 8);
    for (int n=0; n < 8; n++)
	data[n] &= 0xfe;
    return mifare_desfire_des_key_new_with_version (data);
}

MifareDESFireKey
mifare_desfire_des_key_new_with_version (uint8_t value[8])
{
    MifareDESFireKey key;

    if ((key = malloc (sizeof (struct mifare_desfire_key)))) {
	memcpy (key->data, value, 8);
	memcpy (key->data+8, value, 8);
	key->type = T_DES;
    }
    return key;
}

MifareDESFireKey
mifare_desfire_3des_key_new (uint8_t value[16])
{
    uint8_t data[16];
    memcpy (data, value, 16);
    for (int n=0; n < 8; n++)
	data[n] |= 0x01;
    for (int n=8; n < 16; n++)
	data[n] &= 0xfe;
    return mifare_desfire_3des_key_new_with_version (data);
}

MifareDESFireKey
mifare_desfire_3des_key_new_with_version (uint8_t value[16])
{
    MifareDESFireKey key;

    if ((key = malloc (sizeof (struct mifare_desfire_key)))) {
	memcpy (key->data, value, 16);
	key->type = T_3DES;
    }
    return key;
}

uint8_t
mifare_desfire_key_get_version (MifareDESFireKey key)
{
    uint8_t version = 0;
    int base = 0;

    if (key->type == T_3DES)
	base = 8;

    for (int n = 0; n < 8; n++) {
	version |= ((key->data[n + base] & 1) << (7 - n));
    }

    return version;
}

void
mifare_desfire_key_set_version (MifareDESFireKey key, uint8_t version)
{
    for (int n = 0; n < 8; n++) {
	key->data[n] &= 0xfe;
	key->data[n] |= ((version & (1 << (7-n))) >> (7-n));
	if (key->type == T_DES) {
	    key->data[8+n] = key->data[n];
	} else {
	    // Write ~version to avoid turning a 3DES key into a DES key
	    key->data[8+n] &= 0xfe;
	    key->data[8+n] |= !((version & (1 << (7-n))) >> (7-n));
	}
    }
}

void
mifare_desfire_key_free (MifareDESFireKey key)
{
    free (key);
}
