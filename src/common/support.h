/* support.h - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004, 2005 g10 Code GmbH
 
   This file is part of Poldi.
  
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef SUPPORT_H
#define SUPPORT_H

#include <gcrypt.h>

gpg_error_t challenge_generate (unsigned char **challenge, size_t *challenge_n);
gpg_error_t challenge_verify (gcry_sexp_t key,
			      unsigned char *challenge, size_t challenge_n,
			      unsigned char *respone, size_t response_n);
gpg_error_t usersdb_lookup_by_serialno (const char *serialno, char **username);
gpg_error_t usersdb_lookup_by_username (const char *username, char **serialno);
gpg_error_t usersdb_remove_entry (const char *username, const char *serialno);
gpg_error_t usersdb_add_entry (const char *username, const char *serialno);
gpg_error_t sexp_to_string (gcry_sexp_t sexp, char **sexp_string);
gpg_error_t file_to_string (const char *filename, char **string);
gpg_error_t string_to_sexp (gcry_sexp_t *sexp, char *string);

#endif
