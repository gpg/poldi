/* poldi-dirmngr.h - Poldi Interface to Dirmngr
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

#ifndef POLDI_DIRMNGR_H
#define POLDI_DIRMNGR_H

#include <gpg-error.h>
#include <ksba.h>

#include "common/poldi-ctx-opaque.h"

gpg_error_t poldi_dirmngr_connect (poldi_ctx_t ctx,
				   const char *infostr,
				   const char *path,
				   unsigned int flags);

gpg_error_t poldi_dirmngr_lookup_url (poldi_ctx_t ctx,
				      const char *url,
				      ksba_cert_t *cert);

gpg_error_t poldi_dirmngr_validate (poldi_ctx_t ctx,
				    ksba_cert_t cert);

gpg_error_t poldi_dirmngr_disconnect (poldi_ctx_t ctx);

#endif
