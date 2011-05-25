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

#include <sys/types.h>

#include <assert.h>
#include <mqueue.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "llcp.h"
#include "llcp_log.h"
#include "llcp_parameters.h"
#include "llcp_pdu.h"
#include "llc_service.h"

#define LOG_LLC_LINK "libnfc-llcp.llc.link"
#define LLC_LINK_MSG(priority, message) llcp_log_log (LOG_LLC_LINK, priority, "%s", message)
#define LLC_LINK_LOG(priority, format, ...) llcp_log_log (LOG_LLC_LINK, priority, format, __VA_ARGS__)

#define MIN(a, b) ((a < b) ? a : b)

int
llcp_init (void)
{
    return llcp_log_init ();
}

int
llcp_fini (void)
{
    return llcp_log_fini ();
}

void llcp_thread_cleanup (void *arg);
void
llcp_thread_cleanup (void *arg)
{
    (void)arg;
    LLC_LINK_LOG (LLC_PRIORITY_DEBUG, "(%p) Link deactivating", (void *)pthread_self ());
    LLC_LINK_LOG (LLC_PRIORITY_INFO, "(%p) Link deactivated", (void *)pthread_self ());
}

void *
llcp_thread (void *arg)
{
    //struct llc_link *link = (struct llc_link *)arg;

    pthread_cleanup_push (llcp_thread_cleanup, arg);
    LLC_LINK_LOG (LLC_PRIORITY_INFO, "(%p) Link activated", (void *)pthread_self ());
    for (;;) {
	sleep (1);
	//struct pdu *pdu;
	//uint8_t data[BUFSIZ];
	// Wait for data from MAC layer
	// pdu = ...

	//pdu = pdu_unpack (data, BUFSIZ);
	//pdu_dispatch (pdu);
    }
    pthread_cleanup_pop (1);
    return NULL;
}

struct llc_link *
llc_link_new (void)
{
    struct llc_link *link;

    if ((link = malloc (sizeof (*link)))) {
	memset (link->services, '\0', sizeof (link->services));
	if (llc_service_new (link, 0, llcp_thread) < 0) {
	    llc_link_free (link);
	    link = NULL;
	}
    }

    return link;
}

int
llc_link_activate (struct llc_link *link, uint8_t flags, const uint8_t *parameters, size_t length)
{
    assert (link);
    assert (flags == (flags & 0x03));

	link->role = flags & 0x01;
	link->version.major = LLCP_VERSION_MAJOR;
	link->version.minor = LLCP_VERSION_MINOR;
	link->local_miu  = LLC_DEFAULT_MIU;
	link->remote_miu = LLC_DEFAULT_MIU;
	uint16_t wks = 0x0000;
	for (int i = 0; i < 16; i++) {
	    wks |= (link->services[i] ? 1 : 0) << i;
	}
	link->local_wks  = wks;
	link->remote_wks = 0x0001;
	link->local_lto.tv_sec  = 0;
	link->local_lto.tv_nsec = 100000000;
	link->remote_lto.tv_sec  = 0;
	link->remote_lto.tv_nsec = 100000000;
	link->local_lsc  = 3;
	link->remote_lsc = 3;

	if (llc_link_configure (link, parameters, length) < 0) {
	    LLC_LINK_MSG (LLC_PRIORITY_ERROR, "Link configuration failed");
	    llc_link_deactivate (link);
	    return -1;
	}

	switch (flags & 0x01) {
	case LLC_INITIATOR:
	case LLC_TARGET:
	    break;
	}

	if (!(flags & LLC_PAX_PDU_PROHIBITED)) {
	    /* FIXME: Exchange PAX PDU */
	}

	LLC_LINK_LOG (LLC_PRIORITY_INFO, "Starting service %d", 0);
	llc_service_start (link, 0);

    return 0;
}

int
llc_link_configure (struct llc_link *link, const uint8_t *parameters, size_t length)
{
    struct llcp_version version;
    uint16_t miux;
    uint8_t lto;
    uint8_t opt;

    size_t offset = 0;
    while (offset < length) {
	if (offset > length - 2) {
	    LLC_LINK_MSG (LLC_PRIORITY_ERROR, "Incomplete TLV field in parameters list");
	    return -1;
	}
	if (offset + 2 + parameters[offset+1] > length) {
	    LLC_LINK_MSG (LLC_PRIORITY_ERROR, "Incomplete TLV value in parameters list");
	    return -1;
	}
	switch (parameters[offset]) {
	case LLCP_PARAMETER_VERSION:
	    if (parameter_decode_version (parameters + offset, 2 + parameters[offset+1], &version) < 0) {
		LLC_LINK_MSG (LLC_PRIORITY_ERROR, "Invalid Version TLV parameter");
		return -1;
	    }
	    if (llcp_version_agreement (link, version) < 0) {
		LLC_LINK_MSG (LLC_PRIORITY_WARN, "LLCP Version Agreement Procedure failed");
		return -1;
	    }
	    break;
	case LLCP_PARAMETER_MIUX:
	    if (parameter_decode_miux (parameters + offset, 2 + parameters[offset+1], &miux) < 0) {
		LLC_LINK_MSG (LLC_PRIORITY_ERROR, "Invalid MIUX TLV parameter");
		return -1;
	    }
	    link->remote_miu = miux + 128;
	    break;
	case LLCP_PARAMETER_WKS:
	    if (parameter_decode_wks (parameters + offset, 2 + parameters[offset+1], &link->remote_wks) < 0) {
		LLC_LINK_MSG (LLC_PRIORITY_ERROR, "Invalid WKS TLV parameter");
		return -1;
	    }
	    break;
	case LLCP_PARAMETER_LTO:
	    if (parameter_decode_lto (parameters + offset, 2 + parameters[offset+1], &lto) < 0) {
		LLC_LINK_MSG (LLC_PRIORITY_ERROR, "Invalid LTO TLV parameter");
		return -1;
	    }
	    link->remote_lto.tv_sec = (lto * 10 * 1000000) / 1000000000;
	    link->remote_lto.tv_nsec = (lto * 10 * 1000000) % 1000000000;
	    break;
	case LLCP_PARAMETER_OPT:
	    if (parameter_decode_opt (parameters + offset, 2 + parameters[offset+1], &opt) < 0) {
		LLC_LINK_MSG (LLC_PRIORITY_ERROR, "Invalid OPT TLV parameter");
		return -1;
	    }
	    link->remote_lsc = opt & 0x03;
	    break;
	}
	offset += 2 + parameters[offset+1];
    }
    if (offset != length) {
	LLC_LINK_MSG (LLC_PRIORITY_ERROR, "Unprocessed TLV parameters");
	return -1;
    }
    return 0;
}

int
llcp_version_agreement (struct llc_link *link, struct llcp_version version)
{
    int res = -1;

    if (link->version.major == version.major) {
	link->version.minor = MIN (link->version.minor, version.minor);
	res = 0;
    } else if (link->version.major > version.major) {
	if (version.major >= 1) {
	    link->version = version;
	    res = 0;
	}
    } else {
	/* Let the remote LLC component perform version agreement */
	res = 0;
    }

    return res;
}

void
llc_link_deactivate (struct llc_link *link)
{
    assert (link);

    for (int i = MAX_LLC_LINK_SERVICE; i >= 0; i--) {
	if (link->services[i]) {
	    LLC_LINK_LOG (LLC_PRIORITY_INFO, "Stopping service %d", i);
	    llc_service_stop (link, i);
	}
    }
}

void
llc_link_free (struct llc_link *link)
{
    assert (link);

    for (int i = MAX_LLC_LINK_SERVICE; i >= 0; i--) {
	if (link->services[i]) {
	    LLC_LINK_LOG (LLC_PRIORITY_INFO, "Freeing service %d", i);
	    llc_service_free (link, i);
	}
    }

    free (link);
}
