/* dirmngr.h - Poldi dirmngr access layer
 *	Copyright (C) 2007, 2008 Free Software Foundation, Inc.
 *
 * This file is part of Poldi.
 *
 * Poldi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Poldi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DIRMNGR_H
#define DIRMNGR_H

#include <gpg-error.h>
#include <stdio.h>
#include <ksba.h>

#include <util/simplelog.h>

/* Handle for accessing the dirmngr. */
typedef struct dirmngr_ctx_s *dirmngr_ctx_t;

/* Connect to a running dirmngr through the local socket named by
   SOCK, using LOG_HANDLE as logging handle and flags FLAGS. The new
   context is stored in *CTX.  Returns proper error code. */
gpg_error_t dirmngr_connect (dirmngr_ctx_t *ctx,
			     const char *sock,
			     unsigned int flags,
			     log_handle_t log_handle);

/* Close the dirmngr connection associated with CTX and release all
   related resources. */
void dirmngr_disconnect (dirmngr_ctx_t ctx);

/* Retrieve the certificate stored under the url URL through the
   dirmngr context CTX and store it in *CERTIFICATE.  Returns proper
   error code. */
gpg_error_t dirmngr_lookup_url (dirmngr_ctx_t ctx,
				const char *url, ksba_cert_t *cert);

/* Validate the certificate CERT through the dirmngr context
   CTX. Returns zero in case the certificate is considered valid, an
   appropriate error code otherwise. */
gpg_error_t dirmngr_validate (dirmngr_ctx_t ctx, ksba_cert_t cert);

#endif
