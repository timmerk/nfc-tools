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

#ifndef _LLCP_H
#define _LLCP_H

#include <mqueue.h>

/*
 * Logical Link Control Protocol
 * Technical Specification
 * NFC ForumTM
 * LLCP 1.0
 * NFCForum-TS-LLCP_1.0
 * 2009-12-11
 */


#define LLCP_VERSION_MAJOR 1
#define LLCP_VERSION_MINOR 0

struct llc_service;

struct llcp_version {
    uint8_t major;
    uint8_t minor;
};

struct data_link_connection_state {
    uint8_t s;	    /* Send State Variable */
    uint8_t sa;	    /* Send Acknowledgement State Variable */
    uint8_t r;	    /* Receive State Variable */
    uint8_t ra;	    /* Receive Acknowledgement State Variable */
};

struct data_link_connection_parameters {
    uint8_t miu;    /* Maximum Information Unit Size for I PDUs */
    uint8_t rwl;    /* Local Receive Window Size */
    uint8_t rwr;    /* Remote Receive Window Size */
};

struct data_link_connection {
    struct data_link_connection_state state;
    struct data_link_connection_parameters parameters;
};

int		 llcp_init (void);
int		 llcp_fini (void);
struct llc_link	*llc_link_new (void);
int		 llc_link_service_bind (struct llc_link *link, struct llc_service *service, int8_t sap);
void		 llc_link_service_unbind (struct llc_link *link, uint8_t sap);
int		 llc_link_activate (struct llc_link *link, uint8_t flags, const uint8_t *parameters, size_t length);
int		 llc_link_configure (struct llc_link *link, const uint8_t *parameters, size_t length);
int		 llc_link_encode_parameters (const struct llc_link *link, uint8_t *parameters, size_t length);
void		 llc_link_deactivate (struct llc_link *link);
void		 llc_link_free (struct llc_link *link);

int		 llcp_version_agreement (struct llc_link *link, struct llcp_version version);

#define MAX_LLC_LINK_SERVICE 0x3F
#define SAP_AUTO -1

struct llc_link {
    uint8_t role;
    struct llcp_version version;
    uint16_t local_miu;
    uint16_t remote_miu;
    uint16_t remote_wks;
    struct timespec local_lto;
    struct timespec remote_lto;
    uint8_t local_lsc;
    uint8_t remote_lsc;

    struct llc_service *services[MAX_LLC_LINK_SERVICE + 1];

    /* Unit tests metadata */
    void *cut_test_context;
};
/* LLC Operating modes */
#define LLC_INITIATOR 0
#define LLC_TARGET    1

#define LLC_PAX_PDU_PROHIBITED 0x02

#define LLC_DEFAULT_MIU 128

#endif /* !_LLCP_H */
