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

#ifndef _LLC_LINK_H
#define _LLC_LINK_H

#include "llcp.h"

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
    uint8_t opt;

    struct llc_service *services[MAX_LLC_LINK_SERVICE + 1];

    /* Unit tests metadata */
    void *cut_test_context;
};

struct llc_link	*llc_link_new (void);
int		 llc_link_service_bind (struct llc_link *link, struct llc_service *service, int8_t sap);
void		 llc_link_service_unbind (struct llc_link *link, uint8_t sap);
int		 llc_link_activate (struct llc_link *link, uint8_t flags, const uint8_t *parameters, size_t length);
int		 llc_link_configure (struct llc_link *link, const uint8_t *parameters, size_t length);
int		 llc_link_encode_parameters (const struct llc_link *link, uint8_t *parameters, size_t length);
void		 llc_link_deactivate (struct llc_link *link);
void		 llc_link_free (struct llc_link *link);

#endif /* !_LLC_LINK_H */
