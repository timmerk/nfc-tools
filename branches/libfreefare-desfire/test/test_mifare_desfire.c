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

#include "mifare_desfire_fixture.h"

uint8_t null_key_data[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

#define cut_assert_success(tag, last_command) \
    do { \
	if ((res < 0) || (MIFARE_DESFIRE (tag)->last_picc_error != OPERATION_OK)) { \
	    cut_fail ("%s returned %d, error: %s\n", last_command, res, desfire_error_lookup (MIFARE_DESFIRE (tag)->last_picc_error)); \
	} \
    } while (0);

void
test_mifare_desfire_authenticate (void)
{
    int res;

    MifareDESFireKey key = mifare_desfire_des_key_new_with_version (null_key_data);

    res = mifare_desfire_authenticate (tag, 0, key);
    cut_assert_equal_int (0, res, cut_message ("mifare_desfire_authenticate() failed"));
}

void
test_mifare_desfire_change_key_settings (void)
{
    int res;

    MifareDESFireKey default_key = mifare_desfire_des_key_new_with_version (null_key_data);
    MifareDESFireAID aid = mifare_desfire_aid_new (1, 2, 0);

    res = mifare_desfire_authenticate (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");

    res = mifare_desfire_create_application (tag, aid, 0x0f, 1);
    if (res < 0)
	cut_notify ("mifare_desfire_create_application() failed");

    res = mifare_desfire_select_application (tag, aid);
    cut_assert_success (tag, "mifare_desfire_select_application()");

    // Authenticate on the application
    res = mifare_desfire_authenticate (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");

    uint8_t settings;
    res = mifare_desfire_get_key_settings (tag, &settings, NULL);
    cut_assert_success (tag, "mifare_desfire_get_key_settings()");

    res = mifare_desfire_change_key_settings (tag, settings);
    cut_assert_success (tag, "mifare_desfire_change_key_settings()");

    res = mifare_desfire_delete_application (tag, aid);
    cut_assert_success (tag, "mifare_desfire_delete_application()");

    free (aid);
    mifare_desfire_key_free (default_key);
}

void
test_mifare_desfire_get_key_settings (void)
{

    int res;

    uint8_t settings, max_keys;

    res = mifare_desfire_get_key_settings (tag, &settings, &max_keys);
    cut_assert_equal_int (0, res, cut_message ("mifare_desfire_get_key_settings() failed"));

    cut_assert_equal_int (0x0f, settings, cut_message ("Wrong settings"));
    cut_assert_equal_int (0x01, max_keys, cut_message ("Wrong max_keys"));
}

void
test_mifare_desfire_create_application (void)
{
    int res;

    // Create an AID
    MifareDESFireAID aid = mifare_desfire_aid_new (1, 2, 0);
    cut_assert_not_null (aid, cut_message ("mifare_desfire_aid_new() failed"));

    // Authenticate
    MifareDESFireKey default_key = mifare_desfire_des_key_new_with_version (null_key_data);
    res = mifare_desfire_authenticate (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");
    
    // Create an application
    res = mifare_desfire_create_application (tag, aid, 0x0f, 1);
    cut_assert_success (tag, "mifare_desfire_create_application()");

    // Select the application
    res = mifare_desfire_select_application (tag, aid);
    cut_assert_success (tag, "mifare_desfire_create_application()");

    // Authenticate on the application
    res = mifare_desfire_authenticate (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");

    // Select the master plop
    MifareDESFireAID root = mifare_desfire_card_level_aid_new ();
    res = mifare_desfire_select_application (tag, root);
    cut_assert_success (tag, "mifare_desfire_select_application()");

    // Authenticate on the application
    res = mifare_desfire_authenticate (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");
    
    // Delete application
    res = mifare_desfire_delete_application (tag, aid);
    cut_assert_success (tag, "mifare_desfire_delete_application()");

    free (root);
    free (aid);
}

void
test_mifare_desfire_change_key (void)
{
    int res;



    MifareDESFireKey default_key = mifare_desfire_des_key_new_with_version (null_key_data);

    uint8_t new_key_data[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    MifareDESFireKey new_key = mifare_desfire_des_key_new_with_version (new_key_data);

    // Create an AID
    MifareDESFireAID aid = mifare_desfire_aid_new (1, 2, 0);
    cut_assert_not_null (aid, cut_message ("mifare_desfire_aid_new() failed"));

    // Authenticate with the default key
    res = mifare_desfire_authenticate (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");
    
    // Create an application
    res = mifare_desfire_create_application (tag, aid, 0x0f, 1);
    cut_assert_success (tag, "mifare_desfire_create_application()");

    // Select the new application
    res = mifare_desfire_select_application (tag, aid);
    cut_assert_success (tag, "mifare_desfire_select_application()");

    // Authenticate on the new application with default key
    res = mifare_desfire_authenticate (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");

    // Change the authentication key
    res = mifare_desfire_change_key (tag, 0, new_key);
    cut_assert_success (tag, "mifare_desfire_change_key()");

    // Select the new application
    res = mifare_desfire_select_application (tag, aid);
    cut_assert_success (tag, "mifare_desfire_select_application()");

    // Authenticate with the new key
    res = mifare_desfire_authenticate (tag, 0, new_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");

    // Change to authentication key to the default one
    res = mifare_desfire_change_key (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_change_key()");

    // Authenticate with the new key
    res = mifare_desfire_authenticate (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");

    // Select the master plop
    MifareDESFireAID root = mifare_desfire_card_level_aid_new ();
    res = mifare_desfire_select_application (tag, root);
    cut_assert_success (tag, "mifare_desfire_select_application()");

    // Authenticate on the application
    res = mifare_desfire_authenticate (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");
    
    // Delete application
    res = mifare_desfire_delete_application (tag, aid);
    cut_assert_success (tag, "mifare_desfire_delete_application()");

    free (aid);
    free (root);
    mifare_desfire_key_free (new_key);
    mifare_desfire_key_free (default_key);
}

void
test_mifare_desfire_get_key_version (void)
{
    int res;

    uint8_t version;

    res = mifare_desfire_get_key_version (tag, 0, &version);
    cut_assert_equal_int (0, res, cut_message ("mifare_desfire_authenticate() failed"));

    cut_assert_equal_int (0, version, cut_message ("Wrong default key version"));
}

void
test_mifare_desfire_get_application_ids (void)
{
    int res;

    MifareDESFireAID *aids;
    size_t count;

    /* TODO Check everything is fine with more applications. */

    res = mifare_desfire_get_application_ids (tag, &aids, &count);
    cut_assert_equal_int (0, res, cut_message ("mifare_desfire_get_application_ids() failed"));

    cut_assert_equal_int (0, count, cut_message ("No application should exist"));

    mifare_desfire_free_application_ids (aids);

    // Create an AID
    MifareDESFireAID aid = mifare_desfire_aid_new (1, 2, 0);
    cut_assert_not_null (aid, cut_message ("mifare_desfire_aid_new() failed"));

    // Authenticate
    MifareDESFireKey default_key = mifare_desfire_des_key_new_with_version (null_key_data);
    res = mifare_desfire_authenticate (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");
    
    // Create an application
    res = mifare_desfire_create_application (tag, aid, 0x0f, 1);
    cut_assert_success (tag, "mifare_desfire_create_application()");

    // Select the application
    res = mifare_desfire_select_application (tag, aid);
    cut_assert_success (tag, "mifare_desfire_create_application()");

    // Authenticate on the application
    res = mifare_desfire_authenticate (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");

    // Select the master plop
    MifareDESFireAID root = mifare_desfire_card_level_aid_new ();
    res = mifare_desfire_select_application (tag, root);
    cut_assert_success (tag, "mifare_desfire_select_application()");

    res = mifare_desfire_get_application_ids (tag, &aids, &count);
    cut_assert_equal_int (0, res, cut_message ("mifare_desfire_get_application_ids() failed"));

    cut_assert_equal_int (1, count, cut_message ("One application should exist"));

    cut_assert_equal_memory (aids[0], sizeof (MifareDESFireAID), aid, sizeof (MifareDESFireAID), cut_message ("Wrong UID"));

    mifare_desfire_free_application_ids (aids);

    // Authenticate on the application
    res = mifare_desfire_authenticate (tag, 0, default_key);
    cut_assert_success (tag, "mifare_desfire_authenticate()");
    
    // Delete application
    res = mifare_desfire_delete_application (tag, aid);
    cut_assert_success (tag, "mifare_desfire_delete_application()");

    free (root);
    free (aid);
}
