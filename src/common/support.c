/* support.c - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004 g10 Code GmbH
 
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

#include <gcrypt.h>

#include "support.h"
#include "defs.h"

#include <../jnlib/xmalloc.h>

#define CHALLENGE_MD_ALGORITHM GCRY_MD_SHA1

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
	err = GPG_ERR_INTERNAL;	/* FIXME.  */
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

gpg_error_t
challenge_verify (gcry_sexp_t key,
		  unsigned char *challenge, size_t challenge_n,
		  unsigned char *response, size_t response_n)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = challenge_verify_sexp (key,
			       challenge, challenge_n, response, response_n);

  return err;
}

gpg_error_t
serialno_to_username (char *serialno, char **username)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  const char *delimiters = "\t\n ";
  FILE *usersdb = NULL;
  char *line = NULL, *line_serialno = NULL, *line_username = NULL;;
  char *username_cp = NULL;
  size_t line_n = 0;
  ssize_t ret = 0;

  usersdb = fopen (POLDI_USERS_DB_FILE, "r");
  if (usersdb)
    {
      do
	{
	  /* Get next line.  */
	  line = NULL;
	  line_n = 0;
	  ret = getline (&line, &line_n, usersdb);
	  if (ret != -1)
	    {
	      line_serialno = strtok (line, delimiters);
	      if (line_serialno)
		{
		  line_username = strtok (NULL, delimiters);
		  if (line_username)
		    {
		      if ((! strtok (NULL, delimiters))
			  && (! strcmp (serialno, line_serialno)))
			{
			  /* Match.  */
			  username_cp = strdup (line_username);
			  if (! username_cp)
			    break;
			}
		    }
		}

	      free (line);
	    }
	}
      while ((! username_cp) && (ret != -1));

      fclose (usersdb);
    }

  if (username_cp)
    *username = username_cp;
  else
    err = gpg_error (GPG_ERR_INTERNAL);

  return err;
}

gpg_error_t
sexp_to_string (gcry_sexp_t sexp, char **sexp_string)
{
  gpg_error_t err;
  char *buffer;
  size_t buffer_n;
  int fmt;

  buffer = NULL;
  fmt = GCRYSEXP_FMT_ADVANCED;

  buffer_n = gcry_sexp_sprint (sexp, fmt, NULL, 0);
  if (! buffer_n)
    {
      err = gpg_error (GPG_ERR_INTERNAL); /* ? */
      goto out;
    }

  buffer = malloc (buffer_n);
  if (! buffer)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  buffer_n = gcry_sexp_sprint (sexp, fmt, buffer, buffer_n);
  if (! buffer_n)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      goto out;
    }

  *sexp_string = buffer;
  err = 0;
  
 out:

  if (err)
    free (buffer);

  return err;
}

gpg_error_t
string_to_sexp (gcry_sexp_t *sexp, char *string)
{
  gpg_error_t err;

  err = gcry_sexp_sscan (sexp, NULL, string, strlen (string));

  return err;
}

gpg_error_t
file_to_string (const char *filename, char **string)
{
  gpg_error_t err;
  struct stat statbuf;
  char *string_new;
  FILE *fp;
  int ret;

  fp = NULL;
  string_new = NULL;

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
      string_new = malloc (statbuf.st_size);
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
      fclose (fp);		/* FIXME?  */
      fp = NULL;
    }

  err = 0;

 out:

  if (fp)
    fclose (fp);

  if (! err)
    *string = string_new;
  else
    free (string_new);

  return err;
}
