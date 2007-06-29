/* call-scd.c - Interface to Scdaemon
 *	Copyright (C) 2007 g10code GmbH. 
 *
 * This file is part of Poldi.
 *
 * Poldi is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Poldi is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef POLDI_SCD_SUPPORT_H
#define POLDI_SCD_SUPPORT_H

#include <scd/scd.h>
#include <common/support.h>

struct pin_querying_parm
{
  conversation_cb_t conv;
  void *conv_opaque;
};


int getpin_cb (void *opaque, const char *info, char *buf, size_t maxbuf);

gpg_error_t wait_for_card (scd_context_t ctx,
			   unsigned int timeout, conversation_cb_t conv, void *opaque);

#endif
