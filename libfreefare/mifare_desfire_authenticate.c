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
#include <strings.h>

#include <freefare.h>
#include "freefare_internal.h"

static void	 xor8 (uint8_t *ivect, uint8_t *data);
void		 mifare_des (MifareDESFireKey key, uint8_t *data, uint8_t *ivect, MifareDirection direction, int mac);

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
mifare_des (MifareDESFireKey key, uint8_t *data, uint8_t *ivect, MifareDirection direction, int mac)
{
    uint8_t ovect[8];

    if (direction == MD_SEND) {
	xor8 (ivect, data);
    } else {
	memcpy (ovect, data, 8);
    }
    uint8_t edata[8];

    switch (key->type) {
	case T_DES:
	    if (mac) {
		DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
	    } else {
	    DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
	    }
	    memcpy (data, edata, 8);
	    break;
	case T_3DES:
	    if (mac) {
		DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
		DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_DECRYPT);
		DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
	    } else {
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
	    DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_ENCRYPT);
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
	    }
	    memcpy (data, edata, 8);
	    break;
    }

    if (direction == MD_SEND) {
	memcpy (ivect, data, 8);
    } else {
	xor8 (ivect, data);
	memcpy (ivect, ovect, 8);
    }
}

void
mifare_cbc_des (MifareDESFireKey key, uint8_t *data, size_t data_size, MifareDirection direction, int mac)
{
    size_t offset = 0;
    uint8_t ivect[8];
    bzero (ivect, sizeof (ivect));

    while (offset < data_size) {
	mifare_des (key, data + offset, ivect, direction, mac);
	offset += 8;
    }

}
