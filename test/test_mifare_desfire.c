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
#include <errno.h>
#include <string.h>

#include <freefare.h>
#include "freefare_internal.h"

#include "mifare_desfire_fixture.h"

uint8_t key_data_null[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t key_data_des[8]   = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' };
uint8_t key_data_3des[16] = { 'C', 'a', 'r', 'd', ' ', 'M', 'a', 's', 't', 'e', 'r', ' ', 'K', 'e', 'y', '!' };

#define cut_assert_success(last_command) \
    do { \
	if ((res < 0) || (MIFARE_DESFIRE (tag)->last_picc_error != OPERATION_OK)) { \
	    cut_fail ("%s returned %d, error: %s, errno: %s\n", last_command, res, desfire_error_lookup (MIFARE_DESFIRE (tag)->last_picc_error), strerror (errno)); \
	} \
    } while (0);

void
test_mifare_desfire (void)
{
    int res;

    /* Select the master application */
    res = mifare_desfire_select_application (tag, NULL);
    cut_assert_success ("mifare_desfire_select_application()");

    /* Get version information */
    struct mifare_desfire_version_info version_info;
    res = mifare_desfire_get_version (tag, &version_info);
    cut_assert_success ("mifare_desfire_get_version()");

    /* Determine which key is currently the master one */
    uint8_t key_version;
    res = mifare_desfire_get_key_version (tag, 0, &key_version);
    cut_assert_success ("mifare_desfire_get_key_version()");

    MifareDESFireKey key;

    switch (key_version) {
	case 0x00:
	    key = mifare_desfire_des_key_new_with_version (key_data_null);
	    break;
	case 0xAA:
	    key = mifare_desfire_des_key_new_with_version (key_data_des);
	    break;
	case 0xCF:
	    key = mifare_desfire_3des_key_new_with_version (key_data_3des);
	    break;
	default:
	    cut_fail ("Unknown master key.");
    }

    cut_assert_not_null (key, cut_message ("Cannot allocate key"));

    /* Authenticate with this key */
    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");

    mifare_desfire_key_free (key);

    /*
     * This unit test change key settings to more restrictive ones, so reset
     * them to factory defaults in case the previous run failed unexpectedly.
     */
    res = mifare_desfire_change_key_settings (tag, 0xF);
    cut_assert_success ("mifare_desfire_change_key_settings()");

    /* Change master key to DES */
    key = mifare_desfire_des_key_new_with_version (key_data_des);
    mifare_desfire_change_key (tag, 0, key, NULL);
    cut_assert_success ("mifare_desfire_change_key()");

    res = mifare_desfire_get_key_version (tag, 0, &key_version);
    cut_assert_success ("mifare_desfire_get_key_version()");
    cut_assert_equal_int (0xAA, key_version, cut_message ("Wrong key_version value."));

    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

#if 0
    /* Change master key to 3DES */
    key = mifare_desfire_3des_key_new_with_version (key_data_3des);
    mifare_desfire_change_key (tag, 0, key, NULL);
    cut_assert_success ("mifare_desfire_change_key()");

    res = mifare_desfire_get_key_version (tag, 0, &key_version);
    cut_assert_success ("mifare_desfire_get_key_version()");
    cut_assert_equal_int (0xCF, key_version, cut_message ("Wrong key_version value."));

    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");

    mifare_desfire_key_free (key);
#endif

    /* Wipeout the card */
    res = mifare_desfire_format_picc (tag);
    cut_assert_success ("mifare_desfire_format_picc()");

#if 0

    /* Create a test application */
    MifareDESFireAID aid = mifare_desfire_aid_new (0x12, 0x34, 0x5);
    res = mifare_desfire_create_application (tag, aid, 0x0F, 1);
    cut_assert_success ("mifare_desfire_create_application()");

    /* Select the new application */
    res = mifare_desfire_select_application (tag, aid);
    cut_assert_success ("mifare_desfire_select_application()");

    /* Authenticate on the new application */
    key = mifare_desfire_des_key_new_with_version (key_data_null);
    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    /* Change the key for a 3DES one */
    key = mifare_desfire_3des_key_new (key_data_3des);
    res = mifare_desfire_change_key (tag, 0, key, NULL);
    cut_assert_success ("mifare_desfire_change_key()");

    /* Authenticate using the 3DES key */
    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");

    mifare_desfire_key_free (key);

    free (aid);

    return;

#endif

    /* Create 3 applications */
    res = mifare_desfire_select_application (tag, NULL);
    cut_assert_success ("mifare_desfire_select_application()");

    MifareDESFireAID aid_a = mifare_desfire_aid_new (0xAA, 0xAA, 0xA);
    cut_assert_not_null (aid_a, cut_message ("Cannot allocate AID"));
    // FIXME: For some reason, 0xFF fails
    res = mifare_desfire_create_application (tag, aid_a, 0xEF, 0);
    cut_assert_success ("mifare_desfire_create_application()");

    MifareDESFireAID aid_b = mifare_desfire_aid_new (0xBB, 0xBB, 0xB);
    cut_assert_not_null (aid_b, cut_message ("Cannot allocate AID"));
    res = mifare_desfire_create_application (tag, aid_b, 0xEF, 6);
    cut_assert_success ("mifare_desfire_create_application()");

    // FIXME: For some reason 0xCC CC C fails when authenticating
    MifareDESFireAID aid_c = mifare_desfire_aid_new (0x12, 0x34, 0x5);
    cut_assert_not_null (aid_c, cut_message ("Cannot allocate AID"));
    res = mifare_desfire_create_application (tag, aid_c, 0xC0, 14);
    cut_assert_success ("mifare_desfire_create_application()");

    MifareDESFireAID *aids = NULL;
    size_t aid_count;
    res = mifare_desfire_get_application_ids (tag, &aids, &aid_count);
    cut_assert_success ("mifare_desfire_get_application_ids()");

    cut_assert_equal_int (3, aid_count, cut_message ("Wrong application count"));

    res = mifare_desfire_select_application (tag, aid_a);
    cut_assert_success ("mifare_desfire_select_application()");

    uint8_t std_data_file_id = 15;

    res = mifare_desfire_create_std_data_file (tag, std_data_file_id, MDCM_PLAIN, 0xEEEE, 100);
    cut_assert_success ("mifare_desfire_create_std_data_file()");

    res = mifare_desfire_create_backup_data_file (tag, 5, MDCM_PLAIN, 0xEEEE, 64);
    cut_assert_success ("mifare_desfire_create_backup_data_file()");

    res = mifare_desfire_create_value_file (tag, 4, MDCM_PLAIN, 0xEEEE, 0, 1000, 0, 0);
    cut_assert_success ("mifare_desfire_create_value_file()");

    res = mifare_desfire_create_cyclic_record_file (tag, 0, MDCM_PLAIN, 0xEEEE, 4, 10);
    cut_assert_success ("mifare_desfire_create_cyclic_record_file()");

    res = mifare_desfire_write_data (tag, std_data_file_id, 0, 30, (uint8_t *)"Some data to write to the card");
    cut_assert_success ("mifare_desfire_write_data()");
    cut_assert_equal_int (30, res, cut_message ("Wrong number of bytes writen"));

    res = mifare_desfire_write_data (tag, std_data_file_id, 34, 22, (uint8_t *)"Another block of data.");
    cut_assert_success ("mifare_desfire_write_data()");
    cut_assert_equal_int (22, res, cut_message ("Wrong number of bytes writen"));

    res = mifare_desfire_change_file_settings (tag, std_data_file_id, MDCM_PLAIN, 0xEFFF);
    cut_assert_success ("mifare_desfire_change_file_settings()");

    uint8_t buffer[120];
    res = mifare_desfire_read_data (tag, std_data_file_id, 10, 50, &buffer);
    cut_assert_success ("mifare_desfire_read_data()");
    cut_assert_equal_int (50, res, cut_message ("Wrong number of bytes read"));
    cut_assert_equal_memory ("to write to the card\0\0\0\0Another block of data.\0\0\0\0", 50, buffer, 50, cut_message ("Wrong data"));

    res = mifare_desfire_read_data (tag, std_data_file_id, 0, 0, &buffer);
    cut_assert_success ("mifare_desfire_read_data()");
    cut_assert_equal_int (100, res, cut_message ("Wrong number of bytes read"));
    cut_assert_equal_memory ("Some data to write to the"
			     " card\0\0\0\0Another block of"
			     " data.\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
			     "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 100, buffer, 100, cut_message ("Wrong data"));

    res = mifare_desfire_write_data (tag, std_data_file_id, 20, 5, (char *)"Test!");
    cut_assert_equal_int (-1, res, cut_message ("Wrong return value"));
    cut_assert_equal_int (PERMISSION_ERROR, MIFARE_DESFIRE (tag)->last_picc_error, cut_message ("Wrong PICC error"));

    int32_t expected_value = 0;
    for (int transaction = 0; transaction < 15; transaction++) {
	
	char data_buffer[3];

	sprintf (data_buffer, "%02d", transaction);

	res = mifare_desfire_write_data (tag, 5, 3*transaction, 3, data_buffer);
	cut_assert_success ("mifare_desfire_write_data()");
	
	res = mifare_desfire_credit (tag, 4, 100);
	cut_assert_success ("mifare_desfire_credit()");

	res = mifare_desfire_debit (tag, 4, 97);
	cut_assert_success ("mifare_desfire_debit()");

	res = mifare_desfire_write_record (tag, 0, 2, 2, data_buffer);
	cut_assert_success ("mifare_desfire_write_record()");

	res = mifare_desfire_write_record (tag, 0, 0, 2, (char *)"r ");
	cut_assert_success("mifare_desfire_write_record()");

	res = mifare_desfire_read_data (tag, 5, 0, 0, buffer);
	cut_assert_success ("mifare_desfire_read_data()");

	char ref_buffer[64];
	bzero (ref_buffer, sizeof (ref_buffer));
	for (int n = 0; n < transaction; n++) {
	    sprintf (ref_buffer + 3 * n, "%02d", n);
	}

	cut_assert_equal_int (64, res, cut_message ("Wrong number of bytes read"));
	cut_assert_equal_memory (buffer, 64, ref_buffer, 64, cut_message ("Wrong data"));

	int32_t value;
	res = mifare_desfire_get_value (tag, 4, &value);
	cut_assert_success ("mifare_desfire_get_value()");
	cut_assert_equal_int (expected_value, value, cut_message ("Wrong value"));
	
	res = mifare_desfire_commit_transaction (tag);
	cut_assert_success ("mifare_desfire_commit_transaction()");

	expected_value += 3;

	res = mifare_desfire_get_value (tag, 4, &value);
	cut_assert_success ("mifare_desfire_get_value()");
	cut_assert_equal_int (expected_value, value, cut_message ("Wrong value"));
    }

    uint8_t *files;
    size_t file_count;
    res = mifare_desfire_get_file_ids (tag, &files, &file_count);
    cut_assert_success ("mifare_desfire_get_file_ids()");
    cut_assert_equal_int (4, file_count, cut_message ("Wrong number of files"));

    for (size_t i=0; i<file_count;i++) {
	if ((files[i] != 0) && (files[i] != 4) &&
	    (files[i] != 5) && (files[i] != 15)) {
	    cut_fail ("File %d should not exist.", files[i]);
	}

	struct mifare_desfire_file_settings settings;
	res = mifare_desfire_get_file_settings (tag, files[i], &settings);
	cut_assert_success ("mifare_desfire_get_file_settings()");
	
	switch (files[i]) {
	    case 0:
		cut_assert_equal_int (MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP, settings.file_type, cut_message ("Wrong file type"));
		cut_assert_equal_int (MDCM_PLAIN, settings.communication_settings, cut_message ("Wrong communication settings"));
		cut_assert_equal_int (4, settings.settings.linear_record_file.record_size, cut_message ("Wrong record size"));
		cut_assert_equal_int (10, settings.settings.linear_record_file.max_number_of_records, cut_message ("Wrong max number of records"));
		cut_assert_equal_int (9, settings.settings.linear_record_file.current_number_of_records, cut_message ("Wrong current number of records"));
		break;
	    case 4:
		cut_assert_equal_int (MDFT_VALUE_FILE_WITH_BACKUP, settings.file_type, cut_message ("Wrong file type"));
		cut_assert_equal_int (MDCM_PLAIN, settings.communication_settings, cut_message ("Wrong communication settings"));

		cut_assert_equal_int (0, settings.settings.value_file.lower_limit, cut_message ("Wrong lower limit"));
		cut_assert_equal_int (1000, settings.settings.value_file.upper_limit, cut_message ("Wrong upper limit"));
		cut_assert_equal_int (97, settings.settings.value_file.limited_credit_value, cut_message ("Wrong limited_credit value"));
		cut_assert_equal_int (0, settings.settings.value_file.limited_credit_enabled, cut_message ("Wrong limited_credit enable state"));
		break;
	    case 5:
		cut_assert_equal_int (MDFT_BACKUP_DATA_FILE, settings.file_type, cut_message ("Wrong file type"));
		cut_assert_equal_int (MDCM_PLAIN, settings.communication_settings, cut_message ("Wrong communication settings"));
		cut_assert_equal_int (64, settings.settings.standard_file.file_size, cut_message ("Wrong file size"));
		break;
	    case 15:
		cut_assert_equal_int (MDFT_STANDARD_DATA_FILE, settings.file_type, cut_message ("Wrong file type"));
		cut_assert_equal_int (MDCM_PLAIN, settings.communication_settings, cut_message ("Wrong communication settings"));
		cut_assert_equal_int (100, settings.settings.standard_file.file_size, cut_message ("Wrong file size"));
		break;
	    default:
		cut_fail ("Wow!  Cosmic ray!");
	}

	res = mifare_desfire_delete_file (tag, files[i]);
	cut_assert_success ("mifare_desfire_delete_file()");
    }

    free (files);

    res = mifare_desfire_select_application (tag, 0);
    cut_assert_success ("mifare_desfire_select_application()");

    key = mifare_desfire_des_key_new_with_version (key_data_des);
    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    res = mifare_desfire_delete_application (tag, aid_a);
    cut_assert_success ("mifare_desfire_delete_application()");

    res = mifare_desfire_get_application_ids (tag, &aids, &aid_count);
    cut_assert_success ("mifare_desfire_get_application_ids()");
    cut_assert_equal_int (2, aid_count, cut_message ("Wrong application count"));

    res = mifare_desfire_select_application (tag, aid_b);
    cut_assert_success ("mifare_desfire_select_application()");

    // Change KEY
    key = mifare_desfire_des_key_new_with_version (key_data_null);
    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    key = mifare_desfire_3des_key_new_with_version ((uint8_t *) "App.B Master Key");
    res = mifare_desfire_change_key (tag, 0, key, NULL);
    cut_assert_success ("mifare_desfire_change_key()");
    mifare_desfire_key_free (key);

    /* Authenticate with the new master key */
    /* (Reversed arity bits this time) */
    key = mifare_desfire_3des_key_new_with_version ((uint8_t *) "@pp/C!L`ruds!Kdx");
    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    /* Change key #1 */
    key = mifare_desfire_des_key_new_with_version (key_data_null);
    res = mifare_desfire_authenticate (tag, 1, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    key = mifare_desfire_des_key_new_with_version ((uint8_t *) "SglDES_1");
    res = mifare_desfire_change_key (tag, 1, key, NULL);
    cut_assert_success ("mifare_desfire_change_key()");
    mifare_desfire_key_free (key);

    /* Change key #5 */
    key = mifare_desfire_des_key_new_with_version (key_data_null);
    res = mifare_desfire_authenticate (tag, 5, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    key = mifare_desfire_3des_key_new_with_version ((uint8_t *) "B's Chg Keys Key");
    res = mifare_desfire_change_key (tag, 5, key, NULL);
    cut_assert_success ("mifare_desfire_change_key()");
    mifare_desfire_key_free (key);

    /* Set key #5 as the change key */
    key = mifare_desfire_3des_key_new_with_version ((uint8_t *) "App.B Master Key");
    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    res = mifare_desfire_change_key_settings (tag, 0x5F);
    cut_assert_success ("mifare_desfire_change_key_settings()");

    uint8_t key_settings;
    uint8_t max_keys;
    res = mifare_desfire_get_key_settings (tag, &key_settings, &max_keys);
    cut_assert_success ("mifare_desfire_get_key_settings()");

    cut_assert_equal_int (0x5F, key_settings, cut_message ("Wrong key settings"));
    cut_assert_equal_int (6, max_keys, cut_message ("Wrong maximum number of keys"));

    /* Change key #1 to #4 using the three key procedure. */
    key = mifare_desfire_3des_key_new_with_version ((uint8_t *) "B's Chg Keys Key");
    res = mifare_desfire_authenticate (tag, 5, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    key = mifare_desfire_3des_key_new_with_version ((uint8_t *)"App.B Key #1.   ");
    MifareDESFireKey key1 = mifare_desfire_des_key_new_with_version ((uint8_t *) "SglDES_1");
    res = mifare_desfire_change_key (tag, 1, key, key1);
    cut_assert_success ("mifare_desfire_change_key()");
    mifare_desfire_key_free (key);
    mifare_desfire_key_free (key1);
    key = mifare_desfire_3des_key_new_with_version ((uint8_t *)"App.B Key #2..  ");
    res = mifare_desfire_change_key (tag, 2, key, NULL);
    cut_assert_success ("mifare_desfire_change_key()");
    mifare_desfire_key_free (key);
    key = mifare_desfire_3des_key_new_with_version ((uint8_t *)"App.B Key #3... ");
    res = mifare_desfire_change_key (tag, 3, key, NULL);
    cut_assert_success ("mifare_desfire_change_key()");
    mifare_desfire_key_free (key);
    key = mifare_desfire_3des_key_new_with_version ((uint8_t *)"App.B Key #4....");
    res = mifare_desfire_change_key (tag, 4, key, NULL);
    cut_assert_success ("mifare_desfire_change_key()");
    mifare_desfire_key_free (key);





    /* Delete application B */
    key = mifare_desfire_3des_key_new_with_version ((uint8_t *) "App.B Master Key");
    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    res = mifare_desfire_delete_application (tag, aid_b);
    cut_assert_success ("mifare_desfire_delete_application()");

    res = mifare_desfire_get_application_ids (tag, &aids, &aid_count);
    cut_assert_success ("mifare_desfire_get_application_ids()");
    cut_assert_equal_int (1, aid_count, cut_message ("Wrong AID count"));

    /* Tests using application C */

    res = mifare_desfire_select_application (tag, aid_c);
    cut_assert_success ("mifare_desfire_select_application()");

    key = mifare_desfire_des_key_new_with_version (key_data_null);
    res = mifare_desfire_authenticate (tag, 12, key);
    cut_assert_success ("mifare_desfire_authenticate()");

    MifareDESFireKey new_key = mifare_desfire_3des_key_new_with_version ((uint8_t *)"App.C Key #1.   ");
    res = mifare_desfire_change_key (tag, 1, new_key, key);
    cut_assert_success ("mifare_desfire_change_key()");
    mifare_desfire_key_free (new_key);

    new_key = mifare_desfire_3des_key_new_with_version ((uint8_t *)"App.C Key #2..  ");
    res = mifare_desfire_change_key (tag, 2, new_key, key);
    cut_assert_success ("mifare_desfire_change_key()");
    mifare_desfire_key_free (new_key);

    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

#if 0
    res = mifare_desfire_create_cyclic_record_file (tag, 6, 0, 0x12E0, 100, 22);
#endif


    /*
     * Change master key settings to require master key authentication for all
     * card operations.  Only allow to revert this.
     */
    res = mifare_desfire_select_application (tag, 0);
    cut_assert_success ("mifare_desfire_select_application()");

    key = mifare_desfire_des_key_new_with_version (key_data_des);
    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    res = mifare_desfire_change_key_settings (tag, 0x08);
    cut_assert_success ("mifare_desfire_change_key_settings()");

    /* Clear authentication */
    res = mifare_desfire_select_application (tag, 0);
    cut_assert_success ("mifare_desfire_select_application()");

    /* We should not be able to list applications now */
    res = mifare_desfire_get_application_ids (tag, &aids, &aid_count);
    cut_assert_equal_int (-1, res, cut_message ("Wrong return value"));
    cut_assert_equal_int (AUTHENTICATION_ERROR, MIFARE_DESFIRE (tag)->last_picc_error, cut_message ("Wrong PICC error"));

    /* Deleting an application should not be possible */
    res = mifare_desfire_delete_application (tag, aid_c);
    cut_assert_equal_int (-1, res, cut_message ("Wrong return value"));
    cut_assert_equal_int (AUTHENTICATION_ERROR, MIFARE_DESFIRE (tag)->last_picc_error, cut_message ("Wrong PICC error"));

    /* Creating an application should also be forbidden */
    MifareDESFireAID aid_d = mifare_desfire_aid_new (0xDD, 0xDD, 0xD);
    res = mifare_desfire_create_application (tag, aid_d, 0xEF, 0);
    cut_assert_equal_int (-1, res, cut_message ("Wrong return value"));
    cut_assert_equal_int (AUTHENTICATION_ERROR, MIFARE_DESFIRE (tag)->last_picc_error, cut_message ("Wrong PICC error"));

    /*
     * Now we retry authenticated with the master key.
     */
    key = mifare_desfire_des_key_new_with_version (key_data_des);
    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    /* We should be able to list applications again */
    res = mifare_desfire_get_application_ids (tag, &aids, &aid_count);
    cut_assert_success ("mifare_desfire_get_application_ids()");
    cut_assert_equal_int (1, aid_count, cut_message ("Wrong AID count"));

    /* Deleting an application should be possible again */
    res = mifare_desfire_delete_application (tag, aid_c);
    cut_assert_success ("mifare_desfire_delete_application()");

    /* Creating an application should also be possible */
    res = mifare_desfire_create_application (tag, aid_d, 0xEF, 0);
    cut_assert_success ("mifare_desfire_create_application()");

    /* Revert master key settings to default */
    res = mifare_desfire_change_key_settings (tag, 0xF);
    cut_assert_success ("mifare_desfire_change_key_settings()");

    /* Change the master key back to the default one */
    key = mifare_desfire_des_key_new_with_version (key_data_des);
    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    key = mifare_desfire_des_key_new_with_version (key_data_null);
    res = mifare_desfire_change_key (tag, 0, key, NULL);
    cut_assert_success ("mifare_desfire_change_key()");

    /*
     * Delete everything from the card
     */

    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate()");
    mifare_desfire_key_free (key);

    res = mifare_desfire_format_picc (tag);
    cut_assert_success ("mifare_desfire_format_picc()");

    free (aid_a);
    free (aid_b);
    free (aid_c);
    free (aid_d);

    /* Reset the default NULL key */
#if 0

    key = mifare_desfire_des_key_new_with_version (key_data_null);
    mifare_desfire_change_key (tag, 0, key);
    cut_assert_success ("mifare_desfire_change_key()");
    mifare_desfire_key_free (key);
#endif
}
