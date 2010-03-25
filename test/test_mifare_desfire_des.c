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
#include "freefare_internal.h"

void
test_mifare_rol8 (void)
{
    uint8_t data[8] = "01234567";
    rol8 (data);
    cut_assert_equal_memory ("12345670", 8, data, 8, cut_message ("Wrong data"));
}

void
test_mifare_desfire_des_receive (void)
{
    uint8_t data[8]  = { 0xd6, 0x59, 0xe1, 0x70, 0x43, 0xa8, 0x40, 0x68 };
    uint8_t key_data[8]   = { 1, 1, 1, 1, 1, 1, 1, 1 };
    MifareDESFireKey key = mifare_desfire_des_key_new_with_version (key_data);
    uint8_t ivect[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

    uint8_t expected_data[8]  = { 0x73, 0x0d, 0xdf, 0xad, 0xa4, 0xd2, 0x07, 0x89 };
    uint8_t expected_key[8]   = { 1, 1, 1, 1, 1, 1, 1, 1 };
    uint8_t expected_ivect[8] = { 0xd6, 0x59, 0xe1, 0x70, 0x43, 0xa8, 0x40, 0x68 };

    mifare_cbc_des (key, data, ivect, MD_RECEIVE);

    cut_assert_equal_memory (&expected_data,  8, &data,       8, cut_message ("Wrong data"));
    cut_assert_equal_memory (&expected_key,   8, key->data,   8, cut_message ("Wrong key"));
    cut_assert_equal_memory (&expected_ivect, 8, &ivect,      8, cut_message ("Wrong ivect"));

    mifare_desfire_key_free (key);
}


void
test_mifare_desfire_des_send (void)
{
    uint8_t data[8]  = { 0x0d, 0xdf, 0xad, 0xa4, 0xd2, 0x07, 0x89, 0x73 };
    uint8_t key_data[8]   = { 1, 1, 1, 1, 1, 1, 1, 1 };
    MifareDESFireKey key = mifare_desfire_des_key_new_with_version (key_data);
    uint8_t ivect[8] = { 0xf4, 0xcd, 0x0c, 0x06, 0x4e, 0x06, 0x87, 0x83 };

    uint8_t expected_data[8]  = { 0x5d, 0xe5, 0x9f, 0xa5, 0x9e, 0x46, 0xad, 0x10 };
    uint8_t expected_key[8]   = { 1, 1, 1, 1, 1, 1, 1, 1 };
    uint8_t expected_ivect[8] = { 0x5d, 0xe5, 0x9f, 0xa5, 0x9e, 0x46, 0xad, 0x10 };

    mifare_cbc_des (key, data, ivect, MD_SEND);

    cut_assert_equal_memory (&expected_data,  8, &data,       8, cut_message ("Wrong data"));
    cut_assert_equal_memory (&expected_key,   8, key->data,   8, cut_message ("Wrong key"));
    cut_assert_equal_memory (&expected_ivect, 8, &ivect,      8, cut_message ("Wrong ivect"));

    mifare_desfire_key_free (key);
}
