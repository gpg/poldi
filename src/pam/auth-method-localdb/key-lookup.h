/* key-lookup.h - Lookup keys for localdb authentication
   Copyright (C) 2008 g10 Code GmbH
 
   This file is part of Poldi.
  
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef KEY_LOOKUP_H
#define KEY_LOOKUP_H

#include <gpg-error.h>
#include <gcrypt.h>

/* Lookup the key belonging the card specified by SERIALNO.  Returns a
   proper error code.  */
gpg_error_t key_lookup_by_serialno (const char *serialno, gcry_sexp_t *key);

#endif
