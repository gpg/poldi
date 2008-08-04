/* poldi.h - Main include file for PAM Poldi
   Copyright (C) 2008 g10 Code GmbH
 
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

/* This is the main Poldi include file. It is to be included by all
   Poldi components. */

#ifndef INCLUDED_POLDI_H
#define INCLUDED_POLDI_H

#include <config.h>

/* Throughout Poldi we use the gpg_error_t datatype for error code
   propagation. */
#include <gpg-error.h>

/* We use the Libgcrypt memory allocator. */

#include <gcrypt.h>
#define xtrymalloc(n)        gcry_malloc(n)
#define xtrymalloc_secure(n) gcry_malloc_secure(n)
#define xtrystrdup(p)        gcry_strdup(p)
#define xtryrealloc(p,n)     gcry_realloc(p,n)
#define xfree(p)             gcry_free(p)

/* Poldi allows for NLS. */

#include <libintl.h>
#define _(String) dgettext (PACKAGE, String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

#endif	/* INCLUDED_POLDI_H */
