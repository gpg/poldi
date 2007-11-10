/* support.c - PAM authentication via OpenPGP smartcards.
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
#include <dirent.h>

#include <gcrypt.h>

#include "support.h"
#include "defs.h"

#include <jnlib/stringhelp.h>
#include <jnlib/xmalloc.h>
#include <jnlib/logging.h>

#include <scd/scd.h>



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





/* FIXME: need to comment; another candidate for inclusion in a
   central code repository.  */
gpg_error_t
directory_process (const char *name,
		   directory_process_cb_t callback, void *opaque)
{
  struct dirent *dirent;
  gpg_error_t err;
  DIR *dir;

  err = 0;

  dir = opendir (name);
  if (! dir)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  while (1)
    {
      dirent = readdir (dir);
      if (! dirent)
	break;

      err = (*callback) (opaque, dirent);
      if (err)
	break;
    }

 out:

  if (dir)
    closedir (dir);

  return err;
}



void
convert_to_hex (unsigned char *data, size_t data_n, char *data_printable)
{
  int i;

  for (i = 0; i < data_n; i++)
    sprintf (&data_printable[2*i], "%02X", data[i]);
}

gpg_error_t
char_vector_dup (int len, const char **a, char ***b)
{
  char **c;
  gpg_error_t err;
  int i;

  c = NULL;
  err = 0;

  c = malloc (sizeof (*c) * (len + 1));
  if (!c)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  for (i = 0; i < len + 1; i++)
    c[i] = NULL;

  for (i = 0; i < len; i++)
    {
      c[i] = strdup (a[i]);
      if (!c[i])
	{
	  err = gpg_error_from_errno (errno);
	  goto out;
	}
    }
  c[i] = NULL;

 out:

  if (err)
    {
      if (c)
	{
	  for (i = 0; c[i]; i++)
	    free (c[i]);
	  free (c);
	}
      *b = NULL;
    }
  else
    *b = c;

  return err;
}

void
char_vector_free (char **a)
{
  int i;

  if (a)
    {
      for (i = 0; a[i]; i++)
	free (a[i]);
      free (a);
    }
}


/* END */
