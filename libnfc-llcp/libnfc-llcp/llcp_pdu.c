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

#include <sys/endian.h>
#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#include "llcp_pdu.h"

uint8_t _pdu_ptype_sequence_field[] = {
    0, /* PDU_SYMM */
    0, /* PDU_PAX */
    0, /* PDU_AGF */
    0, /* PDU_UI */
    0, /* PDU_CONNECT */
    0, /* PDU_DISC */
    0, /* PDU_CC */
    0, /* PDU_DM */
    0, /* PDU_FRMR */
    0, /* reserved */
    0, /* reserved */
    0, /* reserved */
    1, /* PDU_I */
    1, /* PDU_RR */
    1, /* PDU_RNR */
    0  /* reserved */
};

#define pdu_has_sequence_field(pdu) (_pdu_ptype_sequence_field[(pdu)->ptype])

int
pdu_pack (const struct pdu *pdu, uint8_t *buffer, size_t len)
{
    if (len < 2 + (pdu_has_sequence_field(pdu) ? 1 : 0) + pdu->payload_size)
	return -1;

    int n = 0;
    buffer[n++] = (pdu->dsap << 2) | (pdu->ptype >> 2);
    buffer[n++] = (pdu->ptype << 6) | (pdu->ssap);

    if (pdu_has_sequence_field (pdu)) {
	buffer[n++] = (pdu->n_s << 4) | pdu->n_r;
    }

    for (size_t i = 0; i < pdu->payload_size; i++)
	buffer[n++] = pdu->payload[i];

    return n;
}

struct pdu *
pdu_unpack (const uint8_t *buffer, size_t len)
{
    struct pdu *pdu;

    if ((pdu = malloc (sizeof *pdu))) {
	pdu->dsap = buffer[0] >> 2;
	pdu->ptype = ((buffer[0] & 0x03) << 2) | (buffer[1] >> 6);
	pdu->ssap = buffer[1] & 0x3F;

	int n = 2;

	if (pdu_has_sequence_field (pdu)) {
	    pdu->n_s = buffer[n] >> 4;
	    pdu->n_r = buffer[n++] & 0x0F;
	}

	pdu->payload_size = len - n;
	if (pdu->payload_size) {
	    if (!(pdu->payload = malloc (pdu->payload_size))) {
		free (pdu);
		return NULL;
	    }

	    memcpy (pdu->payload, buffer + n, pdu->payload_size);
	} else {
	    pdu->payload = NULL;
	}
    }

    return pdu;
}

int
pdu_size (struct pdu *pdu)
{
    return 2 + (pdu_has_sequence_field (pdu) ? 1 : 0) + pdu->payload_size;
}

struct pdu *
pdu_aggregate (struct pdu **pdus)
{
    struct pdu *res = NULL;
    struct pdu **pdu = pdus;

    size_t len = 0;
    while (*pdu) {
	len += 2 + pdu_size (*pdu);
	pdu++;
    }

    if ((res = malloc (sizeof (*res)))) {
	res->ssap = 0;
	res->dsap = 0;
	res->ptype = PDU_AGF;

	res->payload_size = len;
	if (!(res->payload = malloc (len))) {
	    free (res);
	    return NULL;
	}

	off_t offset = 0;
	pdu = pdus;
	while (*pdu) {
	    *(uint16_t *)(res->payload + offset) = htobe16 (pdu_size (*pdu));
	    offset += 2;
	    offset += pdu_pack (*pdu, res->payload + offset, len - offset);
	    pdu++;
	}
    }

    return res;
}

struct pdu **
pdu_dispatch (struct pdu *pdu)
{
    struct pdu **pdus = NULL;

    if ((pdu->ssap != 0) || (pdu->ptype != PDU_AGF) || (pdu->dsap != 0))
	return NULL;

    size_t pdu_count = 0;
    size_t offset = 0;

    while (offset < pdu->payload_size) {
	if (offset + 2 > pdu->payload_size)
	    return NULL;

	uint16_t pdu_length = be16toh (*(uint16_t *)(pdu->payload + offset));
	offset += 2;
	offset += pdu_length;
	pdu_count++;
    }

    if (offset != pdu->payload_size)
	return NULL;


    pdus = malloc ((pdu_count + 1) * sizeof (*pdus));
    offset = 0;
    pdu_count = 0;

    while (offset < pdu->payload_size) {
	uint16_t pdu_length = be16toh (*(uint16_t *)(pdu->payload + offset));
	offset += 2;
	pdus[pdu_count++] = pdu_unpack (pdu->payload + offset, pdu_length);
	offset += pdu_length;
    }

    pdus[pdu_count] = NULL;

    return pdus;
}

void
pdu_free (struct pdu *pdu)
{
    free (pdu->payload);
    free (pdu);
}
