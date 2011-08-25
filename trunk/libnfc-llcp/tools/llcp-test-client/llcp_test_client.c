/*-
 * Copyright (C) 2011, Romain Tartière
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
 */

/*
 * $Id$
 */

#include "config.h"
#include <err.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "llc_link.h"
#include "llcp.h"
#include "mac.h"

struct mac_link *mac_link;

static struct option longopts[] = {
    { "help",     no_argument,       NULL, 'h' },
    { "quiet",    no_argument,       NULL, 'q' },
    { "debug",    required_argument, NULL, 'd' },
    { "filename", required_argument, NULL, 'f' },
    { "link-miu", required_argument, NULL, 'l' },
    { "device",   required_argument, NULL, 'D' },
    { "mode",     required_argument, NULL, 'm' },
    { "quirks",   required_argument, NULL, 'Q' },
    { "test",     required_argument, NULL, 't' },
    { "tests-list", no_argument,     NULL, 'T' },
};

struct {
    int link_miu;
    char *device;
    enum {M_NONE, M_INITIATOR, M_TARGET} mode;
    enum {Q_NONE, Q_ANDROID} quirks;
} options = {
    128,
    NULL,
    M_NONE,
    Q_NONE,
};

int	test_01 (struct llc_link *link);
int	test_02 (struct llc_link *link);

struct {
    int enabled;
    char *description;
    int (*fn)(struct llc_link *);
} tests[] = {
    { 0, "Link activation, symmetry and desactivation", test_01 },
    { 0, "Connection-less information transfer", test_02 },
};

void
usage (const char *progname)
{
    fprintf (stderr,"Usage: %s [options]\n", progname);
    fprintf(stderr, "\nOptions:\n"
	    "  -h, --help       show this help message and exit\n"
	    "  --tests-list     show available tests\n"
	    "  --link-miu=MIU   set maximum information unit size to MIU\n"
	    "  --device=NAME    use this device ('ipsim' for TCP/IP simulation)\n"
	    "  --mode=MODE      restrict mode to 'target' or 'initiator'\n"
	    "  --quirks=MODE    quirks mode, choices are 'android'\n"
	    );
}

int
activate_link (struct llc_link *llc_link)
{
    int res;
    struct mac_link *mac_link = llc_link->mac_link;
    switch (options.mode) {
    case M_NONE:
	res = mac_link_activate (mac_link);
	break;
    case M_INITIATOR:
	res = mac_link_activate_as_initiator (mac_link);
	break;
    case M_TARGET:
	res = mac_link_activate_as_target (mac_link);
	break;
    }

    if (res <= 0) {
	errx (EXIT_FAILURE, "Cannot activate link");
    }

    return res;
}

void
stop_mac_link (int sig)
{
    (void) sig;

    if (mac_link && mac_link->device)
	nfc_abort_command (mac_link->device);
}

int
main (int argc, char *argv[])
{
    int ret = 0;
    int ch;
    int testno;
    const int testcount = sizeof (tests) / sizeof (*tests);
    char junk;

    if (llcp_init () < 0)
	errx (EXIT_FAILURE, "llcp_init()");

    signal (SIGINT, stop_mac_link);

    while ((ch = getopt_long(argc, argv, "qd:f:l:D:m:Q:ht:T", longopts, NULL)) != -1) {
	switch (ch) {
	case 'q':
	case 'd':
	case 'f':
	    warnx ("ignored option -- %c (hint: edit log4crc)", ch);
	    break;
	case 'l':
	    if (1 != sscanf (optarg, "%d%c", &options.link_miu, &junk)) {
		errx (EXIT_FAILURE, "“%s” is not a valid link MIU value", optarg);
	    }
	    break;
	case 'D':
	    options.device = optarg;
	    break;
	case 'm':
	    if (0 == strcasecmp ("initiator", optarg))
		options.mode = M_INITIATOR;
	    else if (0 == strcasecmp ("target", optarg))
		options.mode = M_TARGET;
	    else
		errx (EXIT_FAILURE, "“%s” is not a supported mode", optarg);
	    break;
	case 'Q':
	    if (0 == strcasecmp ("android", optarg))
		options.quirks = Q_ANDROID;
	    else
		errx (EXIT_FAILURE, "“%s” is not a support quirks mode", optarg);
	    break;
	case 't':

	    if (1 != sscanf (optarg, "%d%c", &testno, &junk)) {
		errx (EXIT_FAILURE, "“%s” is not a valid test number", optarg);
	    }
	    if ((testno < 1) || (testno > testcount)) {
		errx (EXIT_FAILURE, "Test number %d is not in the [1..%d] range", testno, (int) testcount);
	    }
	    tests[testno-1].enabled = 1;
	    break;
	case 'T':
	    fprintf (stderr, "Available tests:\n");
	    for (size_t i = 0; i < sizeof (tests) / sizeof (*tests); i++) {
		fprintf (stderr, "%3d - %s\n", (int) i+1, tests[i].description);
	    }
	    exit (EXIT_SUCCESS);
	    break;
	case 'h':
	default:
	    usage (basename (argv[0]));
	    exit (EXIT_FAILURE);
	    break;

	}
    }
    argc -= optind;
    argv += optind;

    nfc_device_desc_t device_description[1];

    size_t n;
    nfc_list_devices (device_description, 1, &n);

    if (n < 1)
	errx (EXIT_FAILURE, "No NFC device found");

    nfc_device_t *device;
    if (!(device = nfc_connect (device_description))) {
	errx (EXIT_FAILURE, "Cannot connect to NFC device");
    }

    struct llc_link *llc_link = llc_link_new ();
    if (!llc_link) {
	errx (EXIT_FAILURE, "Cannot allocate LLC link data structures");
    }

    mac_link= mac_link_new (device, llc_link);
    if (!mac_link)
	errx (EXIT_FAILURE, "Cannot create MAC link");

    for (int i = 0; i < testcount; i++) {
	if (tests[i].enabled) {
	    ret += tests[i].fn (llc_link);
	}
    }

    void *err;
    mac_link_wait (mac_link, &err);

    switch (llc_link->role & 0x01) {
    case LLC_INITIATOR:
	printf ("I was the Initiator\n");
	break;
    case LLC_TARGET:
	printf ("I was the Target\n");
	break;
    }

    mac_link_free (mac_link);
    llc_link_free (llc_link);

    nfc_disconnect (device);

    llcp_fini ();
    exit (ret);
}

int
test_01 (struct llc_link *link)
{

    activate_link (link);

    printf ("===> Sleeping for a while\n");
    sleep (3);

    printf ("===> Deactivating link\n");
    llc_link_deactivate (link);
    return 0;
}

int
test_02 (struct llc_link *link)
{
    (void) link;
    return 1;
}
