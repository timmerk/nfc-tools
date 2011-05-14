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

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "llcp.h"
#include "llcp_parameters.h"

/*
 * Parameters management for LLCP TLV parameters.
 *
 * Encoding functions returns the number of bytes written in buffer, and -1 on
 * error.  Ddecoding functions returns 0 on success, and -1 on failure.
 *
 * TODO: Write unit tests for these functions to check all requirements
 * detailed in the LLCP specifications.
 */

int
parameter_encode_version (uint8_t buffer[], size_t buffer_len,
		    struct llcp_version version)
{
    if (buffer_len < 3)
	return -1;

    buffer[0] = LLCP_PARAMETER_VERSION;
    buffer[1] = 0x01;
    buffer[2] = ((version.major & 0x0F) << 4) | (version.minor & 0x0F);
    return 3;
}

int
parameter_decode_version (const uint8_t buffer[], size_t buffer_len,
		    struct llcp_version *version)
{
    if (buffer_len != 3)
	return -1;
    if (!version)
	return -1;
    if ((buffer[0] != LLCP_PARAMETER_VERSION) ||
	(buffer[1] != 0x01))
	return -1;

    version->major = buffer[2] >> 4;
    version->minor = buffer[2] & 0x0F;

    return 0;
}

int
parameter_encode_miux (uint8_t buffer[], size_t buffer_len, uint16_t miux)
{
    if (buffer_len < 4)
	return -1;
    if (miux > 0x07FF)
	return -1;

    buffer[0] = LLCP_PARAMETER_MIUX;
    buffer[1] = 0x02;
    buffer[2] = miux >> 8;
    buffer[3] = miux;

    return 4;
}

int
parameter_decode_miux (const uint8_t buffer[], size_t buffer_len, uint16_t *miux)
{
    if (buffer_len != 4)
	return -1;
    if (!miux)
	return -1;
    if ((buffer[0] != LLCP_PARAMETER_MIUX) ||
	(buffer[1] != 0x02))
	return -1;

    *miux = (buffer[2] << 8 | buffer[3]) & 0x07FF;

    return 0;
}

int
parameter_encode_wks (uint8_t buffer[], size_t buffer_len, uint16_t wks)
{
    if (buffer_len < 4)
	return -1;

    wks |= 0x01;

    buffer[0] = LLCP_PARAMETER_WKS;
    buffer[1] = 0x02;
    buffer[2] = wks >> 8;
    buffer[3] = wks;

    return 4;
}

int
parameter_decode_wks (const uint8_t buffer[], size_t buffer_len, uint16_t *wks)
{
    if (buffer_len != 4)
	return -1;
    if (!wks)
	return -1;
    if ((buffer[0] != LLCP_PARAMETER_WKS) ||
	(buffer[1] != 0x02))
	return -1;

    *wks = buffer[2] << 8 | buffer[3];

    *wks |= 0x01;

    return 0;
}

int
parameter_encode_lto (uint8_t buffer[], size_t buffer_len, uint8_t lto)
{
    if (buffer_len < 3)
	return -1;

    buffer[0] = LLCP_PARAMETER_LTO;
    buffer[1] = 0x01;
    buffer[2] = lto;

    return 3;
}

int
parameter_decode_lto (const uint8_t buffer[], size_t buffer_len, uint8_t *lto)
{
    if (buffer_len != 3)
	return -1;
    if (!lto)
	return -1;
    if ((buffer[0] != LLCP_PARAMETER_LTO) ||
	(buffer[1] != 0x01))
	return -1;

    *lto = buffer[2];

    return 0;
}

int
parameter_encode_rw (uint8_t buffer[], size_t buffer_len, uint8_t rw)
{
    if (buffer_len < 3)
	return -1;
    if (rw > 0x0F)
	return -1;

    buffer[0] = LLCP_PARAMETER_RW;
    buffer[1] = 0x01;
    buffer[2] = rw;

    return 3;
}

int
parameter_decode_rw (const uint8_t buffer[], size_t buffer_len, uint8_t *rw)
{
    if (buffer_len != 3)
	return -1;
    if (!rw)
	return -1;
    if ((buffer[0] != LLCP_PARAMETER_RW) ||
	(buffer[1] != 0x01))
	return -1;

    *rw = buffer[2];

    return 0;
}

int
parameter_encode_sn (uint8_t buffer[], size_t buffer_len, const char *sn)
{
    size_t sn_len = strlen (sn);
    if (buffer_len < 2 + sn_len)
	return -1;
    if (sn_len > UINT8_MAX)
	return -1;

    buffer[0] = LLCP_PARAMETER_SN;
    buffer[1] = sn_len;
    memcpy (buffer + 2, sn, sn_len);

    return 2 + sn_len;
}

int
parameter_decode_sn (const uint8_t buffer[], size_t buffer_len, char *sn,
		     size_t sn_max_len)
{
    if (buffer_len < 2)
	return -1;
    if (!sn)
	return -1;
    if (buffer[0] != LLCP_PARAMETER_SN)
	return -1;
    if (buffer_len != 2u + buffer[1])
	return -1;
    if (sn_max_len < buffer[1] + 1u)
	return -1;

    memcpy (sn, buffer + 2, buffer[1]);
    sn[buffer[1]] = '\0';

    return 0;
}

int
parameter_encode_opt (uint8_t buffer[], size_t buffer_len, uint8_t opt)
{
    if (buffer_len < 3)
	return -1;
    if (opt > 0x03)
	return -1;

    buffer[0] = LLCP_PARAMETER_OPT;
    buffer[1] = 0x01;
    buffer[2] = opt;

    return 3;
}

int
parameter_decode_opt (const uint8_t buffer[], size_t buffer_len, uint8_t *opt)
{
    if (buffer_len != 3)
	return -1;
    if (!opt)
	return -1;
    if ((buffer[0] != LLCP_PARAMETER_OPT) ||
	(buffer[1] != 0x01))
	return -1;

    *opt = buffer[2];

    return 0;
}

