/* support.h - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004, 2005, 2007 g10 Code GmbH
 
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
#include <dirent.h>

#include <scd/scd.h>

/* This function generates a challenge; the challenge will be stored
   in newly allocated memory, which is to be stored in *CHALLENGE;
   it's length in bytes is to be stored in *CHALLENGE_N.  Returns
   proper error code.  */
gpg_error_t challenge_generate (unsigned char **challenge, size_t *challenge_n);

/* This functions verifies that the signature contained in RESPONSE of
   size RESPONSE_N (in bytes) is indeed the result of signing the
   challenge given in CHALLENGE of size CHALLENGE_N (in bytes) with
   the secret key belonging to the public key given as PUBLIC_KEY.
   Returns proper error code.  */
gpg_error_t challenge_verify (gcry_sexp_t public_key,
			      unsigned char *challenge, size_t challenge_n,
			      unsigned char *response, size_t response_n);

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

void convert_to_hex (unsigned char *data, size_t data_n, char *data_printable);

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

/* Lookup the key belonging the card specified by SERIALNO.  Returns a
   proper error code.  */
gpg_error_t key_lookup_by_serialno (const char *serialno, gcry_sexp_t *key);

/* List of ``conversations types''; these are passed to functions of
   type ``conversation_cb_t''.  */
typedef enum
  {
    CONVERSATION_TELL,		/* Inform the user about
				   something.  */
    CONVERSATION_ASK_SECRET	/* Retrieve a secret from the
				   user.  */
  }
conversation_type_t;

/* A function of this type is passed to authenticate().  */
/* FIXME: encoding/utf8 - is there a problem? -mo */
typedef gpg_error_t (*conversation_cb_t) (conversation_type_t type,
					  void *opaque,
					  const char *info, char **response);

typedef gpg_error_t (*directory_process_cb_t) (void *opaque,
					       struct dirent *dirent);

gpg_error_t directory_process (const char *name,
			       directory_process_cb_t callback, void *opaque);

#endif

/* END */
