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

#include "config.h"

#include <openssl/des.h>

#include <string.h>

#include <freefare.h>
#include "freefare_internal.h"

static void	 xor8 (uint8_t *ivect, uint8_t *data);

static void
xor8 (uint8_t *ivect, uint8_t *data)
{
    for (int i = 0; i < 8; i++) {
	data[i] ^= ivect[i];
    }
}

void
rol8(uint8_t *data)
{
    uint8_t first = data[0];
    for (int i = 0; i < 7; i++) {
	data[i] = data[i+1];
    }
    data[7] = first;
}

void
mifare_cbc_des (MifareDESFireKey key, uint8_t *data, uint8_t *ivect, MifareDirection direction)
{
    /*
     * FIXME Should we change the way errors traverse this function?
     */
    uint8_t ovect[8];

    if (direction == MD_SEND) {
	xor8 (ivect, data);
    } else {
	memcpy (ovect, data, 8);
    }

    DES_key_schedule ks;
    DES_set_key ((DES_cblock *)(key->data), &ks);

    uint8_t edata[8];
    DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &ks, DES_DECRYPT);
//    stat = ecb_crypt (key->data, data, 8, DES_HW | DES_DECRYPT);
//
    memcpy (data, edata, 8);

    if (direction == MD_SEND) {
	memcpy (ivect, data, 8);
    } else {
	xor8 (ivect, data);
	memcpy (ivect, ovect, 8);
    }
}
