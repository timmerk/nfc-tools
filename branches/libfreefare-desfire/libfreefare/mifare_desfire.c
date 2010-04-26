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

static int	 create_file1 (MifareTag tag, uint8_t command, uint8_t file_no, uint8_t communication_settings, uint16_t access_right, uint32_t file_size);
static int	 create_file2 (MifareTag tag, uint8_t command, uint8_t file_no, uint8_t communication_settings, uint16_t access_right, uint32_t record_size, uint32_t max_number_of_records);

// TODO Check this.
#define MAX_RES_SIZE 60

#define NOAUTH 255

#define ASSERT_AUTHENTICATED(tag) \
    do { \
	if (MIFARE_DESFIRE (tag)->authenticated_key_no == NOAUTH) \
	    return errno = EINVAL, -1;\
    } while (0);

#define ASSERT_NOT_NULL(argument) \
    do { \
	if (!argument) \
	    return errno = EINVAL, -1; \
    } while (0);


/*
 * Buffer management macros.
 * 
 * The following macros ease setting-up and using buffers:
 * BUFFER_INIT (data, 5);      // data -> [ xx, xx, xx, xx, xx ]
 * BUFFER_SIZE (data);         // size -> 0
 * BUFFER_APPEND (data, 0x12); // data -> [ 12, xx, xx, xx, xx ]
 * BUFFER_SIZE (data);         // size -> 1
 * uint16_t x = 0x3456;        // We suppose we are little endian
 * BUFFER_APPEND_BYTES (data, x, 2);
 *                             // data -> [ 12, 56, 34, xx, xx ]
 * BUFFER_SIZE (data);         // size -> 3
 * BUFFER_APPEND_LE (data, x, 2, 2);
 *                             // data -> [ 12, 56, 34, 34, 56 ]
 * BUFFER_SIZE (data);         // size -> 5
 */

/*
 * Initialise a buffer named buffer_name of size bytes.
 */
#define BUFFER_INIT(buffer_name, size) \
    uint8_t buffer_name[size]; \
    size_t __##buffer_name##_n = 0

#define BUFFER_SIZE(buffer_name) (__##buffer_name##_n)

/*
 * Append one byte of data to the buffer buffer_name.
 */
#define BUFFER_APPEND(buffer_name, data) \
    do { \
	buffer_name[__##buffer_name##_n++] = data; \
    } while (0)

/*
 * Append size bytes of data to the buffer buffer_name.
 */
#define BUFFER_APPEND_BYTES(buffer_name, data, size) \
    do { \
	size_t __n = 0; \
	while (__n < size) { \
	    buffer_name[__##buffer_name##_n++] = data[__n++]; \
	} \
    } while (0)

/*
 * Append data_size bytes of data at the end of the buffer.  Since data is
 * copied as a little endian value, the storage size of the value has to be
 * passed as the field_size parameter.
 *
 * Example: to copy 24 bits of data from a 32 bits value:
 * BUFFER_APPEND_LE (buffer, data, 3, 4);
 */

// FIXME: remove debugging stuff
#if _BYTE_ORDER != _LITTLE_ENDIAN
#define BUFFER_APPEND_LE(buffer, data, data_size, field_size) \
    do { \
	printf ("append (%p, %lu, %p, %d (%d))\n", buffer, __##buffer##_n, data, (int) data_size, (int) field_size); \
	size_t __data_size = data_size; \
	size_t __field_size = field_size; \
	while (__field_size--, __data_size--) { \
	    printf ("  buffer[%lu] <- %02x\n", __##buffer##_n, ((uint8_t *)&data)[__field_size]); \
	    buffer[__##buffer##_n++] = ((uint8_t *)&data)[__field_size]; \
	} \
    } while (0)
#else
#define BUFFER_APPEND_LE(buffer, data, data_size, field_size) \
    do { \
	memcpy (buffer + __##buffer##_n, &data, data_size); \
	__##buffer##_n += data_size; \
    } while (0)
#endif


/*
 * Convenience macros.
 */

/*
 * Transmit the message msg to the NFC tag and receive the response res.  The
 * response buffer's size is set according to the quantity od data received.
 */
// FIXME: remove debugging stuff
#define DESFIRE_TRANSCEIVE(tag, msg, res) \
    do { \
	MIFARE_DESFIRE (tag)->last_picc_error = OPERATION_OK; \
        hexdump (msg, __##msg##_n, "---> ", 0); \
	if (!(nfc_initiator_transceive_dep_bytes (tag->device, msg, __##msg##_n, res, &__##res##_n))) \
	    return errno = EIO, -1; \
        hexdump (res, __##res##_n, "<--- ", 0); \
	if ((1 == __##res##_n) && (OPERATION_OK != res[0])) \
	    return MIFARE_DESFIRE (tag)->last_picc_error = res[0], -1; \
    } while (0)


/*
 * Miscellaneous low-level memory manipulation functions.
 */

static void	*memdup(void *p, size_t n);

static void *
memdup(void *p, size_t n)
{
    void *res;
    if ((res = malloc (n))) {
	memcpy (res, p, n);
    }
    return res;
}


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
	MIFARE_DESFIRE (tag)->session_key = NULL;
    }
    return tag;
}

/*
 * Free the provided tag.
 */
void
mifare_desfire_tag_free (MifareTag tag)
{
    free (MIFARE_DESFIRE (tag)->session_key);
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
	free (MIFARE_DESFIRE (tag)->session_key);
	MIFARE_DESFIRE (tag)->session_key = NULL;
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

    free (MIFARE_DESFIRE (tag)->session_key);
    MIFARE_DESFIRE(tag)->session_key = NULL;

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
    free (MIFARE_DESFIRE (tag)->session_key);
    MIFARE_DESFIRE (tag)->session_key = NULL;

    BUFFER_INIT (cmd1, 2);
    BUFFER_INIT (res, 9);

    BUFFER_APPEND (cmd1, 0x0A);
    BUFFER_APPEND (cmd1, key_no);

    DESFIRE_TRANSCEIVE (tag, cmd1, res);


    uint8_t PICC_E_RndB[8];
    memcpy (PICC_E_RndB, res+1, 8);

    uint8_t PICC_RndB[8];
    memcpy (PICC_RndB, PICC_E_RndB, 8);
    mifare_cbc_des (key, PICC_RndB, 8, MD_RECEIVE);

    uint8_t PCD_RndA[8];
    DES_random_key ((DES_cblock*)&PCD_RndA);

    uint8_t PCD_r_RndB[8];
    memcpy (PCD_r_RndB, PICC_RndB, 8);
    rol8 (PCD_r_RndB);

    uint8_t token[16];
    memcpy (token, PCD_RndA, 8);
    memcpy (token+8, PCD_r_RndB, 8);

    mifare_cbc_des (key, token, 16, MD_SEND);

    BUFFER_INIT (cmd2, 17);

    BUFFER_APPEND (cmd2, 0xAF);
    BUFFER_APPEND_BYTES (cmd2, token, 16);

    DESFIRE_TRANSCEIVE (tag, cmd2, res);

    uint8_t PICC_E_RndA_s[8];
    memcpy (PICC_E_RndA_s, res+1, 8);

    uint8_t PICC_RndA_s[8];
    memcpy (PICC_RndA_s, PICC_E_RndA_s, 8);
    mifare_cbc_des (key, PICC_RndA_s, 8, MD_RECEIVE);

    uint8_t PCD_RndA_s[8];
    memcpy (PCD_RndA_s, PCD_RndA, 8);
    rol8 (PCD_RndA_s);


    if (0 != memcmp (PCD_RndA_s, PICC_RndA_s, 8)) {
	return -1;
    }

    MIFARE_DESFIRE (tag)->authenticated_key_no = key_no;
    MIFARE_DESFIRE (tag)->session_key = mifare_desfire_session_key_new (PCD_RndA, PICC_RndB, key);

    return 0;
}

int
mifare_desfire_change_key_settings (MifareTag tag, uint8_t settings)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_AUTHENTICATED (tag);

    BUFFER_INIT (cmd, 9);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0x54);

    uint8_t data[8];

    data[0] = settings;
    iso14443a_crc (data, 1, data + 1);
    memset (data+3, '\0', 5);

    mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, data, 8, MD_SEND);

    BUFFER_APPEND_BYTES (cmd, data, 8);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

int
mifare_desfire_get_key_settings (MifareTag tag, uint8_t *settings, uint8_t *max_keys)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 3);

    BUFFER_APPEND (cmd, 0x45);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    if (settings)
	*settings = res[1];
    if (max_keys)
	*max_keys = res[2];

    return 0;
}

int
mifare_desfire_change_key (MifareTag tag, uint8_t key_no, MifareDESFireKey new_key, MifareDESFireKey old_key)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_AUTHENTICATED (tag);

    BUFFER_INIT (cmd, 1+1+24);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xC4);
    BUFFER_APPEND (cmd, key_no);

    uint8_t data[24];

    if ((MIFARE_DESFIRE (tag)->authenticated_key_no != key_no) /* FIXME && (ChangeKey key != 0x0E)*/) {
	if (old_key) {
	    memcpy (data, old_key->data, 16);
	} else {
	    memset (data, '\0', 16);
	}
	for (int n=0; n<16; n++) {
	    data[n] ^= new_key->data[n];
	}
	// Append XORed data CRC
	iso14443a_crc (data, 16, data+16);
	// Append new key CRC
	iso14443a_crc (new_key->data, 16, data+18);
	// Padding
	for (int n=20; n<24; n++) {
	    data[n] = 0x00;
	}
    } else {
	memcpy (data, new_key->data, 16);
	// Append new key CRC
	iso14443a_crc (data, 16, data+16);

	// Padding
	for (int n=18; n<24; n++) {
	    data[n] = 0x00;
	}
    }

    mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, data, 24, MD_SEND);

    BUFFER_APPEND_BYTES (cmd, data, 24);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

/*
 * Retrieve version information for a given key.
 */
int
mifare_desfire_get_key_version (MifareTag tag, uint8_t key_no, uint8_t *version)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    ASSERT_NOT_NULL (version);

    BUFFER_INIT (cmd, 2);
    BUFFER_APPEND (cmd, 0x64);
    BUFFER_APPEND (cmd, key_no);

    BUFFER_INIT (res, 2);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    *version = res[1];

    return 0;
}



int
mifare_desfire_create_application (MifareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 6);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xCA);
    BUFFER_APPEND_LE (cmd, aid->data, 3, 3);
    BUFFER_APPEND (cmd, settings);
    BUFFER_APPEND (cmd, key_no);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

int
mifare_desfire_delete_application (MifareTag tag, MifareDESFireAID aid)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 4);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xDA);
    BUFFER_APPEND_LE (cmd, aid->data, 3, 3);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

int
mifare_desfire_get_application_ids (MifareTag tag, MifareDESFireAID *aids[], size_t *count)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, MAX_RES_SIZE);

    BUFFER_APPEND (cmd, 0x6A);

    DESFIRE_TRANSCEIVE (tag, cmd, res);
    *count = (BUFFER_SIZE (res)-1)/3;
    *aids = malloc ((*count + 1) * sizeof (MifareDESFireAID));
    for (size_t i = 0; (3*i + 1) < BUFFER_SIZE (res); i++) {
	(*aids)[i] = memdup (res + 3*i + 1, 3);
    }

    if (res[0] == 0xAF) {
	cmd[0] = 0xAF;
	DESFIRE_TRANSCEIVE (tag, cmd, res);
	*count += (BUFFER_SIZE (res)-1) / 3;

	MifareDESFireAID *p;
	if ((p = realloc (*aids, (*count + 1) * sizeof (MifareDESFireAID)))) {
	    *aids = p;

	    for (size_t i = 0; (3*i + 1) < BUFFER_SIZE (res); i++) {
		(*aids)[19+i] = memdup (res + 3*i + 1, 3);
	    }
	}
    }

    (*aids)[*count] = NULL;

    return 0;
}

void
mifare_desfire_free_application_ids (MifareDESFireAID aids[])
{
    for (int i = 0; aids[i]; i++)
	free (aids[i]);
    free (aids);
}

/*
 * Select the application specified by aid for further operation.  If aid is
 * NULL, the master application is selected (equivalent to aid = 0x00000).
 */
int
mifare_desfire_select_application (MifareTag tag, MifareDESFireAID aid)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    struct mifare_desfire_aid null_aid = { .data = { 0x00, 0x00, 0x00 } };

    if (!aid) {
	aid = &null_aid;
    }

    BUFFER_INIT (cmd, 4);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0x5A);
    BUFFER_APPEND_LE (cmd, aid->data, sizeof (aid->data), sizeof (aid->data));

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

int
mifare_desfire_format_picc (MifareTag tag)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_AUTHENTICATED (tag);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xFC);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

/*
 * Retrieve version information form the PICC.
 */
int
mifare_desfire_get_version (MifareTag tag, struct mifare_desfire_version_info *version_info)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    ASSERT_NOT_NULL (version_info);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 15); /* 8, 8, then 15 byte results */

    BUFFER_APPEND (cmd, 0x60);

    DESFIRE_TRANSCEIVE (tag, cmd, res);
    memcpy (&(version_info->hardware), res+1, 7);

    cmd[0] = 0xAF;
    DESFIRE_TRANSCEIVE (tag, cmd, res);
    memcpy (&(version_info->software), res+1, 7);

    DESFIRE_TRANSCEIVE (tag, cmd, res);
    memcpy (&(version_info->uid), res+1, 14);

    return 0;
}



/* Application level commands */

int
mifare_desfire_get_file_ids (MifareTag tag, uint8_t *files[], size_t *count)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 16);

    BUFFER_APPEND (cmd, 0x6F);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    *count = BUFFER_SIZE (res) - 1;

    if (!(*files = malloc (*count))) {
	errno = ENOMEM;
	return -1;
    }
    memcpy (*files, res+1, *count);

    return 0;
}

int
mifare_desfire_get_file_settings (MifareTag tag, uint8_t file_no, struct mifare_desfire_file_settings *settings)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 2);
    BUFFER_INIT (res, 18);

    BUFFER_APPEND (cmd, 0xF5);
    BUFFER_APPEND (cmd, file_no);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    memcpy (settings, cmd+1, BUFFER_SIZE (res)-1);  // FIXME endianness (loads!)
    return 0;
}

int
mifare_desfire_change_file_settings (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_right)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 5);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0x5F);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND (cmd, communication_settings);
    BUFFER_APPEND_LE (cmd, access_right, 2, 2);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

static int
create_file1 (MifareTag tag, uint8_t command, uint8_t file_no, uint8_t communication_settings, uint16_t access_right, uint32_t file_size)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 8);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, command);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND (cmd, communication_settings);
    BUFFER_APPEND_LE (cmd, access_right, 2, 2);
    BUFFER_APPEND_LE (cmd, file_size, 3, 4);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

int
mifare_desfire_create_std_data_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_right, uint32_t file_size)
{
    return create_file1 (tag, 0xCD, file_no, communication_settings, access_right, file_size);
}

int
mifare_desfire_create_backup_data_file  (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_right, uint32_t file_size)
{
    return create_file1 (tag, 0xCB, file_no, communication_settings, access_right, file_size);
}

int
mifare_desfire_create_value_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_right, int32_t lower_limit, int32_t upper_limit, int32_t value, uint8_t limited_credit_enable)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 18);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xCC);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND (cmd, communication_settings);
    BUFFER_APPEND_LE (cmd, access_right, 2, 2);
    BUFFER_APPEND_LE (cmd, lower_limit, 4, 4);
    BUFFER_APPEND_LE (cmd, upper_limit, 4, 4);
    BUFFER_APPEND_LE (cmd, value, 4, 4);
    BUFFER_APPEND (cmd, limited_credit_enable);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

static int
create_file2 (MifareTag tag, uint8_t command, uint8_t file_no, uint8_t communication_settings, uint16_t access_right, uint32_t record_size, uint32_t max_number_of_records)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 11);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, command);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND (cmd, communication_settings);
    BUFFER_APPEND_LE (cmd, access_right, 2, 2);
    BUFFER_APPEND_LE (cmd, record_size, 3, 4);
    BUFFER_APPEND_LE (cmd, max_number_of_records, 3, 4);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

int
mifare_desfire_create_linear_record_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_right, uint32_t record_size, uint32_t max_number_of_records)
{
    return create_file2 (tag, 0xC1, file_no, communication_settings, access_right, record_size, max_number_of_records);
}

int
mifare_desfire_create_cyclic_record_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_right, uint32_t record_size, uint32_t max_number_of_records)
{
    return create_file2 (tag, 0xC0, file_no, communication_settings, access_right, record_size, max_number_of_records);
}

int
mifare_desfire_delete_file (MifareTag tag, uint8_t file_no)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 2);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xDF);
    BUFFER_APPEND (cmd, file_no);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}



/*
 * UID accessor
 */
char*
mifare_desfire_get_uid(MifareTag tag)
{
  char* uid = malloc((7 * 2) + 1);
  snprintf(uid, 15, "%02x%02x%02x%02x%02x%02x%02x", tag->info.abtUid[0], tag->info.abtUid[1], tag->info.abtUid[2], tag->info.abtUid[3], tag->info.abtUid[4], tag->info.abtUid[5], tag->info.abtUid[6]);
  return uid;
}
