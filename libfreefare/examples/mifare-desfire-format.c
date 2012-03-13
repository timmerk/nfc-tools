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

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nfc/nfc.h>

#include <freefare.h>

// TODO: allow to read non-default key from options, also for the other mifare-desfire* tools
uint8_t null_key_data[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

struct {
    bool interactive;
} format_options = {
    .interactive = true
};

void
usage(char *progname)
{
    fprintf (stderr, "usage: %s [-y]\n", progname);
    fprintf (stderr, "\nOptions:\n");
    fprintf (stderr, "  -y     Do not ask for confirmation (dangerous)\n");
}

int
main(int argc, char *argv[])
{
    int ch;
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    MifareTag *tags = NULL;

    while ((ch = getopt (argc, argv, "hy")) != -1) {
	switch (ch) {
	    case 'h':
		usage(argv[0]);
		exit (EXIT_SUCCESS);
		break;
	    case 'y':
		format_options.interactive = false;
		break;
	    default:
		usage(argv[0]);
		exit (EXIT_FAILURE);
	}
    }
    argc -= optind;
    argv += optind;

    nfc_connstring devices[8];
    size_t device_count;
    
    nfc_init(NULL);

    device_count = nfc_list_devices (NULL, devices, 8);
    if (device_count <= 0)
	errx (EXIT_FAILURE, "No NFC device found.");

    for (size_t d = 0; (!error) && (d < device_count); d++) {
        device = nfc_open (NULL, devices[d]);
        if (!device) {
            warnx ("nfc_open() failed.");
            error = EXIT_FAILURE;
            continue;
        }

	tags = freefare_get_tags (device);
	if (!tags) {
	    nfc_close (device);
	    errx (EXIT_FAILURE, "Error listing Mifare DESFire tags.");
	}

	for (int i = 0; (!error) && tags[i]; i++) {
	    if (DESFIRE != freefare_get_tag_type (tags[i]))
		continue;

	    char *tag_uid = freefare_get_tag_uid (tags[i]);
	    char buffer[BUFSIZ];

	    printf ("Found %s with UID %s. ", freefare_get_tag_friendly_name (tags[i]), tag_uid);
	    bool format = true;
	    if (format_options.interactive) {
		printf ("Format [yN] ");
		fgets (buffer, BUFSIZ, stdin);
		format = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
	    } else {
		printf ("\n");
	    }

	    if (format) {
		int res;

		res = mifare_desfire_connect (tags[i]);
		if (res < 0) {
		    warnx ("Can't connect to Mifare DESFire target.");
		    error = EXIT_FAILURE;
		    break;
		}

		MifareDESFireKey default_key = mifare_desfire_des_key_new_with_version (null_key_data);
		res = mifare_desfire_authenticate (tags[i], 0, default_key);
		if (res < 0) {
		    warnx ("Can't authenticate on Mifare DESFire target.");
		    error = EXIT_FAILURE;
		    break;
		}
		mifare_desfire_key_free (default_key);

		res = mifare_desfire_format_picc (tags[i]);
		if (res < 0) {
		    warn ("Can't format PICC.");
		    error = EXIT_FAILURE;
		    break;
		}

		mifare_desfire_disconnect (tags[i]);
	    }

	    free (tag_uid);
	}

	freefare_free_tags (tags);
	nfc_close (device);
    }
    nfc_exit(NULL);
    exit (error);
} /* main() */

