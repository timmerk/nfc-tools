/*-
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

/*
 * http://ridrix.wordpress.com/2009/09/19/mifare-desfire-communication-example/
 */

#include <openssl/des.h>
#include <sys/types.h>

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <freefare.h>
#include "freefare_internal.h"

// TODO Remove this
#include <libutil.h>

// TODO Check this.
#define MAX_RES_SIZE 58

#define NOAUTH 255

#define ASSERT_AUTHENTICATED(tag) \
    do { \
	if (MIFARE_DESFIRE (tag)->authenticated_key_no == NOAUTH) \
	    return errno = EINVAL, -1;\
    } while (0);

#define DESFIRE_TRANSCEIVE(tag, msg, msg_len, res, res_len) \
    do { \
	MIFARE_DESFIRE (tag)->last_picc_error = OPERATION_OK; \
        hexdump (msg, msg_len, "---> ", 0); \
	if (!(nfc_initiator_transceive_dep_bytes (tag->device, msg, msg_len, res, &res_len))) \
	    return errno = EIO, -1; \
        hexdump (res, res_len, "<--- ", 0); \
	if ((1 == res_len) && (OPERATION_OK != res[0])) \
	    return MIFARE_DESFIRE (tag)->last_picc_error = res[0], -1; \
    } while (0)

void		*memdup(void *p, size_t n);
void *
memdup(void *p, size_t n)
{
    void *res;
    if ((res = malloc (n))) {
	memcpy (res, p, n);
    }
    return res;
}

enum mifare_desfire_application_type {
    standard_data_file,
    backup_data_file,
    value_file_with_backup,
    linear_record_file_with_backup,
    cyclic_record_file_with_backup
};


/*
 * Memory management functions.
 */

/*
 * Allocates and initialize a MIFARE DESFire tag.
 */
MifareTag
mifare_desfire_tag_new (void)
{
    MifareTag tag;
    if ((tag= malloc (sizeof (struct mifare_desfire_tag)))) {
	MIFARE_DESFIRE (tag)->last_picc_error = OPERATION_OK;
	MIFARE_DESFIRE (tag)->last_pcd_error = NULL;
    }
    return tag;
}

/*
 * Free the provided tag.
 */
void
mifare_desfire_tag_free (MifareTag tag)
{
    free (MIFARE_DESFIRE (tag)->last_pcd_error);
    free (tag);
}


/*
 * MIFARE card communication preparation functions
 *
 * The following functions send NFC commands to the initiator to prepare
 * communication with a MIFARE card, and perform required cleannups after using
 * the target.
 */

/*
 * Establish connection to the provided tag.
 */
int
mifare_desfire_connect (MifareTag tag)
{
    ASSERT_INACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    nfc_target_info_t pnti;
    if (nfc_initiator_select_tag (tag->device, NM_ISO14443A_106, tag->info.abtUid, 7, &pnti)) {
	tag->active = 1;
	MIFARE_DESFIRE (tag)->last_picc_error = OPERATION_OK;
	MIFARE_DESFIRE (tag)->last_pcd_error = NULL;
	MIFARE_DESFIRE (tag)->authenticated_key_no = NOAUTH;
    } else {
	errno = EIO;
	return -1;
    }
    return 0;
}

/*
 * Terminate connection with the provided tag.
 */
int
mifare_desfire_disconnect (MifareTag tag)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    if (nfc_initiator_deselect_tag (tag->device)) {
	tag->active = 0;
    }
    return 0;
}



uint8_t
mifare_desfire_get_last_error (MifareTag tag)
{
    return MIFARE_DESFIRE (tag)->last_picc_error;
}



int
mifare_desfire_authenticate (MifareTag tag, uint8_t key_no, MifareDESFireKey key)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    MIFARE_DESFIRE (tag)->last_picc_error = OPERATION_OK;

    MIFARE_DESFIRE (tag)->authenticated_key_no = NOAUTH;
    MIFARE_DESFIRE (tag)->current_key = NULL;

    //uint8_t key[8];
    //memset (key, '\0', sizeof (key));
    uint8_t ivec[8];

#if 0
    /*
     * Parity bits of DES keys are used for key versionning.
     */
    DES_set_odd_parity ((DES_cblock *)&key);
#endif

    memset (ivec, '\0', sizeof (ivec));

    hexdump (key, 8, "key                   ", 0);
    hexdump (ivec, 8, "ivec                  ", 0);

    uint8_t command[2];
    command[0] = 0x0A;
    command[1] = key_no;

    uint8_t status[9];
    size_t n;
#if 0
    hexdump (command, sizeof (command), "<---                  ", 0);
    if (!(nfc_initiator_transceive_dep_bytes (tag->device, command, sizeof (command), status, &n))) {
	tag->active = false; /* Tag is no more active if authentication failed. */
	errno = EIO;
	return -1;
    }

    if (n == 1) {
	tag->last_picc_error = status[0];
	return -1;
    }

    hexdump (status, n, "--->                  ", 0);
#endif
    DESFIRE_TRANSCEIVE (tag, command, sizeof (command), status, n);


    uint8_t PICC_E_RndB[8];
    memcpy (PICC_E_RndB, status+1, 8);
    hexdump (PICC_E_RndB, sizeof (PICC_E_RndB), "e(PICC_RndB)          ", 0);

    uint8_t PICC_RndB[8];
    memcpy (PICC_RndB, PICC_E_RndB, 8);
    mifare_cbc_des (key, PICC_RndB, ivec, MD_RECEIVE);
    hexdump (PICC_RndB, sizeof (PICC_RndB), "  PICC_RndB           ", 0);

    uint8_t PCD_RndA[8];
    DES_random_key ((DES_cblock*)&PCD_RndA);
    hexdump (PCD_RndA, sizeof (PCD_RndA), "  PCD_RndA            ", 0);

    uint8_t PCD_r_RndB[8];
    memcpy (PCD_r_RndB, PICC_RndB, 8);
    rol8 (PCD_r_RndB);

    uint8_t token[16];
    memcpy (token, PCD_RndA, 8);
    memcpy (token+8, PCD_r_RndB, 8);

    hexdump (token, sizeof (token), "  PCD_RndA+PCD_RndB'  ", 0);

    memset (ivec, '\0', sizeof (ivec));
    mifare_cbc_des (key, token, ivec, MD_SEND);
    mifare_cbc_des (key, token+8, ivec, MD_SEND);

    hexdump (token, sizeof (token), "d(PCD_RndA+PCD_RndB') ", 0);

    uint8_t msg[17];
    msg[0] = 0xAF;
    memcpy (msg + 1, token, 16);

#if 0
    hexdump (msg, sizeof (msg), "<---                  ", 0);

    if (!(nfc_initiator_transceive_dep_bytes (tag->device, msg, sizeof (msg), status, &n))) {
	tag->active = false; /* Tag is no more active if authentication failed. */
	errno = EIO;
	return -1;
    }

    hexdump (status, n, "--->                  ", 0);

    if (n == 1) {
	tag->last_picc_error = status[0];
	return -1;
    }
#endif
    DESFIRE_TRANSCEIVE (tag, msg, sizeof (msg), status, n);

    uint8_t PICC_E_RndA_s[8];
    memcpy (PICC_E_RndA_s, status+1, 8);
    hexdump (PICC_E_RndA_s, sizeof (PICC_E_RndA_s), "e(PICC_RndA')         ", 0);

    uint8_t PICC_RndA_s[8];
    memcpy (PICC_RndA_s, PICC_E_RndA_s, 8);
    memset (ivec, '\0', sizeof (ivec));
    mifare_cbc_des (key, PICC_RndA_s, ivec, MD_RECEIVE);
    hexdump (PICC_RndA_s, sizeof (PICC_RndA_s), "  PICC_RndA'          ", 0);

    uint8_t PCD_RndA_s[8];
    memcpy (PCD_RndA_s, PCD_RndA, 8);
    rol8 (PCD_RndA_s);
    hexdump (PCD_RndA_s, sizeof (PCD_RndA_s), "  PCD_RndA'           ", 0);


    if (0 != memcmp (PCD_RndA_s, PICC_RndA_s, 8)) {
	return -1;
    }

    MIFARE_DESFIRE (tag)->authenticated_key_no = key_no;
    MIFARE_DESFIRE (tag)->current_key = key;

    return 0;
}

int
mifare_desfire_change_key_settings (MifareTag tag)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    /* TODO */

    errno = ENOTSUP;
    return -1;
}

int
mifare_desfire_get_key_settings (MifareTag tag, uint8_t *settings, uint8_t *max_keys)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    uint8_t cmd[1] = { 0x45 };
    uint8_t res[3];
    size_t n;

    DESFIRE_TRANSCEIVE(tag, cmd, sizeof (cmd), res, n);

    if (settings)
	*settings = res[1];
    if (max_keys)
	*max_keys = res[2];

    return 0;
}

int
mifare_desfire_change_key (MifareTag tag, uint8_t key_no, MifareDESFireKey key)
{
    uint8_t cmd[1+1+24];

    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_AUTHENTICATED (tag);

    cmd[0] = 0xC4;
    cmd[1] = key_no;

    uint8_t *data = cmd + 2;
    uint8_t res[1];
    size_t n;

    if ((MIFARE_DESFIRE (tag)->authenticated_key_no != key_no) /* FIXME && (ChangeKey key != 0x0E)*/) {
	memcpy (data, MIFARE_DESFIRE (tag)->current_key->data, 16);
	for (int n=0; n<16; n++) {
	    data[n] ^= key->data[n];
	}
	// Append XORed data CRC
	iso14443a_crc (data, 16, data+16);
	// Append new key CRC
	iso14443a_crc (key->data, 16, data+18);
	// Padding
	for (int n=20; n<24; n++) {
	    data[n] = 0x00;
	}
    } else {
	memcpy (data, key->data, 16);
	// Append new key CRC
	iso14443a_crc (data, 16, data+16);

	// Padding
	for (int n=18; n<24; n++) {
	    data[n] = 0x00;
	}
    }

    hexdump (cmd, sizeof (cmd), "mifare_desfire_change_key (raw): ", 0);

    uint8_t ivec[8];
    memset (ivec, '\0', sizeof (ivec));

    mifare_cbc_des (MIFARE_DESFIRE (tag)->current_key, data,    ivec, MD_SEND);
    mifare_cbc_des (MIFARE_DESFIRE (tag)->current_key, data+8,  ivec, MD_SEND);
    mifare_cbc_des (MIFARE_DESFIRE (tag)->current_key, data+16, ivec, MD_SEND);
    
    hexdump (cmd, sizeof (cmd), "mifare_desfire_change_key (des): ", 0);

    DESFIRE_TRANSCEIVE(tag, cmd, sizeof (cmd), res, n);


    
    return 0;
}


int
mifare_desfire_get_key_version (MifareTag tag, uint8_t key_no, uint8_t *version)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    unsigned char cmd[2] = { 0x64, key_no };
    unsigned char res[2];
    size_t n;

    DESFIRE_TRANSCEIVE(tag, cmd, sizeof (cmd), res, n);

    *version = res[1];

    return 0;
}



int
mifare_desfire_create_application (MifareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    unsigned char cmd[6] = { 0xCA };
    memcpy (cmd + 1, aid->data, 3);
    cmd[4] = settings;
    cmd[5] = key_no;
    unsigned char res[1];
    size_t n;

    DESFIRE_TRANSCEIVE(tag, cmd, sizeof (cmd), res, n);

    return 0;
}

int
mifare_desfire_delete_application (MifareTag tag, MifareDESFireAID aid)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    unsigned char cmd[4] = { 0xDA };
    memcpy (cmd + 1, aid, 3);
    unsigned char res[1];
    size_t n;

    DESFIRE_TRANSCEIVE(tag, cmd, sizeof (cmd), res, n);

    return 0;
}

int
mifare_desfire_get_application_ids (MifareTag tag, MifareDESFireAID *aids, size_t *count)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    unsigned char cmd[1] = { 0x6A };
    unsigned char res[MAX_RES_SIZE];
    size_t n;

    DESFIRE_TRANSCEIVE(tag, cmd, sizeof (cmd), res, n);
    *count = (n-1)/3;
    aids = malloc ((*count) * sizeof (MifareDESFireAID));
    for (int i = 0; (3*i + 1) < n; i++) {
	aids[i] = memdup (res + 3*i + 1, 3);
    }

    if (n == 1+19*3) {
	cmd[1] = 0xAF;
	DESFIRE_TRANSCEIVE(tag, cmd, sizeof (cmd), res, n);
	*count += (n-1) / 3;

	MifareDESFireAID *p;
	if ((p = realloc (aids, (*count) * sizeof (MifareDESFireAID)))) {
	    aids = p;

	    for (int i = 0; (3*i + 1) < n; i++) {
		aids[19+i] = memdup (res + 3*i + 1, 3);
	    }
	}
    }

    return 0;
    
}

void
mifare_desfire_free_application_ids (MifareDESFireAID *aids)
{

}

int
mifare_desfire_select_application (MifareTag tag, MifareDESFireAID aid)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    unsigned char cmd[4] = { 0x5A };
    memcpy (cmd+1, aid->data, sizeof (aid->data));
    unsigned char res[1];
    size_t n;

    DESFIRE_TRANSCEIVE (tag, cmd, sizeof (cmd), res, n);

    return 0;
}
