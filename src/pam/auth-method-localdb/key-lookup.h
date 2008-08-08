/* key-lookup.c - Lookup keys for localdb authentication
   Copyright (C) 2004, 2005, 2007, 2008 g10 Code GmbH
 
   This file is part of Poldi.
 
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with this program; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef KEY_LOOKUP_H
#define KEY_LOOKUP_H

#include <gpg-error.h>
#include <gcrypt.h>

#include <auth-support/ctx.h>

/* Lookup the key belonging the card specified by SERIALNO.  Returns a
   proper error code.  */
gpg_error_t key_lookup_by_serialno (poldi_ctx_t ctx,
				    const char *serialno, gcry_sexp_t *key);

#endif
