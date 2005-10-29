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
gpg_error_t usersdb_remove_entry (const char *username, const char *serialno,
				  unsigned int *nentries);
gpg_error_t usersdb_add_entry (const char *username, const char *serialno);

/* This function converts the given S-Expression SEXP into it's
   `ADVANCED' string representation, using newly-allocated memory,
   storing the resulting NUL-terminated string in *SEXP_STRING.
   Returns a proper error code.  */
gpg_error_t sexp_to_string (gcry_sexp_t sexp, char **sexp_string);

/* This function retrieves the content from the file specified by
   FILENAMED and writes it into a newly allocated chunk of memory,
   which is then stored in *STRING.  Returns proper error code.  */
gpg_error_t file_to_string (const char *filename, char **string);

/* This functions converts the given string-representation of an
   S-Expression into a new S-Expression object, which is to be stored
   in *SEXP.  Returns proper error code.  */
gpg_error_t string_to_sexp (gcry_sexp_t *sexp, char *string);

/* This functions construct a new C-string containing the absolute
   path for the file, which is to expected to contain the public key
   for the card identified by SERIALNO.  Returns proper error
   code.  */
gpg_error_t key_filename_construct (char **filename, const char *serialno);

/* This function retrieves the username of the user associated with
   the current process and stores it *USERNAME.

   Note: the username is contained in statically (!) allocated memory,
   which may be overwritten by calls to this functions or
   getpwuid().  */
gpg_error_t lookup_own_username (const char **username);

#endif
