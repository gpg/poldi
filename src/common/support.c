/* support.c - PAM authentication via OpenPGP smartcards.
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
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <pwd.h>

#include <gcrypt.h>

#include "support.h"
#include "defs.h"

#include <jnlib/stringhelp.h>
#include <jnlib/xmalloc.h>
#include <jnlib/logging.h>

#include <common/card.h>



#define CHALLENGE_MD_ALGORITHM GCRY_MD_SHA1



/* This function generates a challenge; the challenge will be stored
   in newly allocated memory, which is to be stored in *CHALLENGE;
   it's length in bytes is to be stored in *CHALLENGE_N.  Returns
   proper error code.  */
gpg_error_t
challenge_generate (unsigned char **challenge, size_t *challenge_n)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  unsigned char *challenge_new = NULL;
  size_t challenge_new_n = gcry_md_get_algo_dlen (CHALLENGE_MD_ALGORITHM);

  challenge_new = malloc (challenge_new_n);
  if (! challenge_new)
    err = gpg_err_code_from_errno (errno);
  else
    {
      gcry_create_nonce (challenge_new, challenge_new_n);
      *challenge = challenge_new;
      *challenge_n = challenge_new_n;
    }

  return err;
}

static gpg_error_t
challenge_verify_sexp (gcry_sexp_t sexp_key,
		       unsigned char *challenge, size_t challenge_n,
		       unsigned char *response, size_t response_n)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  gcry_sexp_t sexp_signature = NULL;
  gcry_sexp_t sexp_data = NULL;
  gcry_mpi_t mpi_signature = NULL;

  /* Convert buffers into MPIs.  */
  if (! err)
    {
      if (gcry_mpi_scan (&mpi_signature, GCRYMPI_FMT_USG, response, response_n,
			 NULL))
	err = gpg_error (GPG_ERR_BAD_MPI);
    }

  /* Create according S-Expressions.  */
  if (! err)
    err = gcry_sexp_build (&sexp_data, NULL,
			   "(data (flags pkcs1) (hash sha1 %b))",
			   challenge_n, challenge);
  if (! err)
    err = gcry_sexp_build (&sexp_signature, NULL, "(sig-val (rsa (s %m)))",
			   mpi_signature);

  /* Verify.  */
  if (! err)
    err = gcry_pk_verify (sexp_signature, sexp_data, sexp_key);

  if (sexp_data)
    gcry_sexp_release (sexp_data);
  if (sexp_signature)
    gcry_sexp_release (sexp_signature);
  if (mpi_signature)
    gcry_mpi_release (mpi_signature);

  return err;
}

/* This functions verifies that the signature contained in RESPONSE of
   size RESPONSE_N (in bytes) is indeed the result of signing the
   challenge given in CHALLENGE of size CHALLENGE_N (in bytes) with
   the secret key belonging to the public key given as PUBLIC_KEY.
   Returns proper error code.  */
gpg_error_t
challenge_verify (gcry_sexp_t public_key,
		  unsigned char *challenge, size_t challenge_n,
		  unsigned char *response, size_t response_n)
{
  gpg_error_t err;

  err = challenge_verify_sexp (public_key,
			       challenge, challenge_n, response, response_n);

  return err;
}



/*
 * S-Expression conversion.
 */

/* This function converts the given S-Expression SEXP into it's
   `ADVANCED' string representation, using newly-allocated memory,
   storing the resulting NUL-terminated string in *SEXP_STRING.
   Returns a proper error code.  */
gpg_error_t
sexp_to_string (gcry_sexp_t sexp, char **sexp_string)
{
  const int fmt = GCRYSEXP_FMT_ADVANCED;
  gpg_error_t err;
  size_t buffer_n;
  char *buffer;

  assert (sexp);

  buffer = NULL;

  /* Figure out amount of memory required for
     string-representation.  */
  buffer_n = gcry_sexp_sprint (sexp, fmt, NULL, 0);
  if (! buffer_n)
    {
      err = gpg_error (GPG_ERR_INV_SEXP); /* ? */
      goto out;
    }

  /* Allocate memory.  */
  buffer = malloc (buffer_n);
  if (! buffer)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  /* And write string-representation into buffer.  */
  buffer_n = gcry_sexp_sprint (sexp, fmt, buffer, buffer_n);
  if (! buffer_n)
    {
      err = gpg_error (GPG_ERR_INV_SEXP); /* ? */
      goto out;
    }

  *sexp_string = buffer;
  err = 0;
  
 out:

  if (err)
    free (buffer);

  return err;
}

/* This functions converts the given string-representation of an
   S-Expression into a new S-Expression object, which is to be stored
   in *SEXP.  Returns proper error code.  */
gpg_error_t
string_to_sexp (gcry_sexp_t *sexp, char *string)
{
  gpg_error_t err;

  err = gcry_sexp_sscan (sexp, NULL, string, strlen (string));

  return err;
}

/* This function retrieves the content from the file specified by
   FILENAMED and writes it into a newly allocated chunk of memory,
   which is then stored in *STRING.  Returns proper error code.  */
gpg_error_t
file_to_string (const char *filename, char **string)
{
  struct stat statbuf;
  char *string_new;
  gpg_error_t err;
  FILE *fp;
  int ret;

  string_new = NULL;
  fp = NULL;

  /* Retrieve file size.  */
  ret = stat (filename, &statbuf);
  if (ret)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  if (statbuf.st_size)
    {
      fp = fopen (filename, "r");
      if (! fp)
	{
	  err = gpg_error_from_errno (errno);
	  goto out;
	}
      string_new = malloc (statbuf.st_size + 1);
      if (! string_new)
	{
	  err = gpg_error_from_errno (errno);
	  goto out;
	}
      ret = fread (string_new, statbuf.st_size, 1, fp);
      if (ret != 1)
	{
	  err = gpg_error_from_errno (errno);
	  goto out;
	}
      string_new[statbuf.st_size] = 0;
    }

  err = 0;
  *string = string_new;

 out:

  if (fp)
    fclose (fp);

  if (err)
    free (string_new);

  return err;
}



/* This functions construct a new C-string containing the absolute
   path for the file, which is to expected to contain the public key
   for the card identified by SERIALNO.  Returns proper error
   code.  */
gpg_error_t
key_filename_construct (char **filename, const char *serialno)
{
  char *path;

  path = make_filename (POLDI_KEY_DIRECTORY, serialno, NULL);
  *filename = path;

  return 0;
}

/* This function retrieves the username of the user associated with
   the current process and stores it *USERNAME.

   Note: the username is contained in statically (!) allocated memory,
   which may be overwritten by calls to this functions or
   getpwuid().  */
gpg_error_t
lookup_own_username (const char **username)
{
  struct passwd *pwent;
  gpg_error_t err;
  uid_t uid;

  uid = getuid ();
  pwent = getpwuid (uid);
  if (! pwent)
    err = gpg_error_from_errno (errno);
  else
    {
      *username = pwent->pw_name;
      err = 0;
    }

  return err;
}

/* Lookup the key belonging the card specified by SERIALNO.  Returns a
   proper error code.  */
gpg_error_t
key_lookup_by_serialno (const char *serialno, gcry_sexp_t *key)
{
  gcry_sexp_t key_sexp;
  char *key_string;
  char *key_path;
  gpg_error_t err;

  key_path = NULL;
  key_string = NULL;

  err = key_filename_construct (&key_path, serialno);
  if (err)
    {
      log_error ("Error: failed to construct key file path "
		 "for serial number `%s': %s\n",
		 serialno, gpg_strerror (err));
      goto out;
    }

  err = file_to_string (key_path, &key_string);
  if ((! err) && (! key_string))
    err = gpg_error (GPG_ERR_NO_PUBKEY);
  if (err)
    {
      log_error ("Error: failed to retrieve key from key file `%s': %s\n",
		 key_path, gpg_strerror (err));
      goto out;
    }

  err = string_to_sexp (&key_sexp, key_string);
  if (err)
    {
      log_error ("Error: failed to convert key "
		 "from `%s' into S-Expression: %s\n",
		 key_path, gpg_strerror (err));
      goto out;
    }

  *key = key_sexp;

 out:

  free (key_path);
  free (key_string);

  return err;
}



/* This function implements the core authentication mechanism.
   CARD_SLOT is the slot ID, which is used for interaction with the
   smartcard; KEY is the public key; CONV is the conversation function
   to use for interaction with the user and OPAQUE is the opaque
   argument to pass to the conversation functions.  Returns proper
   error code: in case it returns zero, authentication was
   successful.  */
gpg_error_t
authenticate (int card_slot, gcry_sexp_t key,
	      conversation_cb_t conv, void *opaque)
{
  unsigned char *challenge;
  unsigned char *response;
  size_t challenge_n;
  size_t response_n;
  gpg_error_t err;
  char *pin;

  challenge = NULL;
  response = NULL;
  pin = NULL;

  /* Query user for PIN.  */
  err = (*conv) (CONVERSATION_ASK_SECRET, opaque, POLDI_PIN2_QUERY_MSG, &pin);
  if (err)
    {
      log_error ("Error: failed to retrieve PIN from user: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Send PIN to card.  */
  err = card_pin_provide (card_slot, 2, pin);
  if (err)
    {
      log_error ("Error: failed to send PIN to card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* FIXME: size of challenge should be provieded.  */

  /* Generate challenge.  */
  err = challenge_generate (&challenge, &challenge_n);
  if (err)
    {
      log_error ("Error: failed to generate challenge: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Let card sign the challenge.  */
  err = card_sign (card_slot, challenge, challenge_n, &response, &response_n);
  if (err)
    {
      log_error ("Error: failed to retrieve challenge signature "
		 "from card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Verify response.  */
  err = challenge_verify (key, challenge, challenge_n, response, response_n);

 out:

  /* Release resources.  */

  free (challenge);
  free (response);
  free (pin);

  return err;
}



/* Wait for insertion of a card in slot specified by SLOT,
   communication with the user through the PAM conversation function
   CONV.  If REQUIRE_CARD_SWITCH is TRUE, require a card switch.

   The serial number of the inserted card will be stored in a newly
   allocated string in **SERIALNO, it's version will be stored in
   *VERSION and the fingerprint of the signing key on the card will be
   stored in newly allocated memory in *FINGERPRINT.

   Returns proper error code.  */
gpg_error_t
wait_for_card (int slot, int require_card_switch, unsigned int timeout,
	       conversation_cb_t conv, void *opaque, char **serialno,
	       unsigned int *card_version,
	       card_key_t type, char **fingerprint)
{
  gpg_error_t err;

  err = (*conv) (CONVERSATION_TELL, opaque, "Insert card ...", NULL);
  if (err)
    /* FIXME.  */
    goto out;

  err = card_init (slot, 1, timeout, require_card_switch);
  if (err)
    {
      if (gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT)
	(*conv) (CONVERSATION_TELL, opaque, "Timeout inserting card", NULL);
      else
	log_error ("Error: failed to initialize card: %s\n",
		   gpg_strerror (err));
      goto out;
    }

  err = card_info (slot, serialno, card_version, type, fingerprint);
  if (err)
    {
      log_error ("Error: failed to retrieve card information: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* FIXME: error checking?  */

 out:

  return err;
}

/* END */
