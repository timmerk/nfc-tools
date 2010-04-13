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
 * $Id: mifare-classic-format.c 189 2010-03-01 14:04:47Z romain.tartiere $
 */

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <freefare.h>

uint8_t null_key_data[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

int
main(int argc, char *argv[])
{
    int error = EXIT_SUCCESS;
    nfc_device_t *device = NULL;
    MifareTag *tags = NULL;

    device = nfc_connect (NULL);
    if (!device)
        errx (EXIT_FAILURE, "No NFC device found.");

    tags = freefare_get_tags (device);
    if (!tags) {
        nfc_disconnect (device);
        errx (EXIT_FAILURE, "Error listing tags.");
    }

    for (int i = 0; (!error) && tags[i]; i++) {
        switch (freefare_get_tag_type (tags[i])) {
            case DESFIRE_4K:
                break;
            default:
                continue;
        }
	        
        char *tag_uid = mifare_desfire_get_uid (tags[i]);
	char buffer[BUFSIZ];
        
        printf ("Found %s with UID %s.  Format [yN] ", freefare_get_tag_friendly_name (tags[i]), tag_uid);
        fgets (buffer, BUFSIZ, stdin);
        bool format = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
        
        if (format) {
	    int res;
	    MifareDESFireKey default_key = mifare_desfire_des_key_new_with_version (null_key_data);

	    res = mifare_desfire_connect (tags[i]);
	    if (res < 0) {
		warnx ("Can't connect to Mifare DESFire target.");
		error = 1;
		break;
	    }

	    res = mifare_desfire_authenticate (tags[i], 0, default_key);
	    if (res < 0) {
		warnx ("Can't authenticate on Mifare DESFire target.");
		error = 1;
		break;
	    }

	    res = mifare_desfire_format_picc (tags[i]);
	    if (res < 0) {
		warn ("Can't format PICC.");
		error = 1;
		break;
	    }
	}

	free (tag_uid);
    }

    freefare_free_tags (tags);
    nfc_disconnect (device);

    exit (error);
} /* main() */

