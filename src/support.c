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

#define _GNU_SOURCE		/* FIXME, makes use of getline().  */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include <gcrypt.h>

#include "support.h"
#include "defs.h"

struct poldi_key
{
  gcry_sexp_t key_sexp;
};

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
challenge_verify (poldi_key_t key,
		  unsigned char *challenge, size_t challenge_n,
		  unsigned char *response, size_t response_n)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (key->key_sexp)
    err = challenge_verify_sexp (key->key_sexp,
				 challenge, challenge_n, response, response_n);
  else
    err = GPG_ERR_INTERNAL;	/* FIXME.  */

  return err;
}

static gpg_error_t
key_get_sexp (gcry_sexp_t *key, unsigned char *key_id)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  gcry_sexp_t key_new = NULL;
  char *filename = NULL;
  void *buffer = MAP_FAILED;
  struct stat statbuf;
  int fd = -1, ret = 0;

  memset (&statbuf, 0, sizeof (statbuf));

  filename = malloc (sizeof (POLDI_KEY_DIRECTORY) + strlen (key_id) + 5);
  if (! filename)
    err = gpg_err_code_from_errno (errno);
  else
    sprintf (filename, "%s/%s.key", POLDI_KEY_DIRECTORY, key_id);

  if (! err)
    {
      fd = open (filename, O_RDONLY);
      if (fd == -1)
	err = gpg_err_code_from_errno (errno);
    }
  if (! err)
    {
      ret = fstat (fd, &statbuf);
      if (ret == -1)
	err = gpg_err_code_from_errno (errno);
    }
  if (! err)
    {
      buffer = mmap (NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
      if (buffer == MAP_FAILED)
	err = gpg_err_code_from_errno (errno);
    }

  if (! err)
    err = gcry_sexp_new (&key_new, buffer, statbuf.st_size, 0);

  if (buffer != MAP_FAILED)
    munmap (buffer, statbuf.st_size);
  if (fd)
    close (fd);
  if (filename)
    free (filename);

  if (! err)
    *key = key_new;
  
  return err;
}
	       
static void
key_destroy_sexp (gcry_sexp_t key)
{
  gcry_sexp_release (key);
}

gpg_error_t
key_get (poldi_key_t *key, unsigned char *key_id)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  poldi_key_t key_new = NULL;

  key_new = malloc (sizeof (*key_new));
  if (! key_new)
    err = gpg_err_code_from_errno (errno);
  else
    {
      key_new->key_sexp = NULL;
      err = key_get_sexp (&key_new->key_sexp, key_id);
    }

  if (! err)
    *key = key_new;
  else
    {
      if (key_new)
	{
	  if (key_new->key_sexp)
	    key_destroy_sexp (key_new->key_sexp);
	}
    }

  return err;
}

void
key_destroy (poldi_key_t key)
{
  if (key)
    {
      if (key->key_sexp)
	key_destroy_sexp (key->key_sexp);
    }
}

gpg_error_t
keyid_to_username (unsigned char *key_id, unsigned char **username)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  const char *delimiters = "\t\n ";
  FILE *usersdb = NULL;
  char *line = NULL, *line_key_id = NULL, *line_username = NULL;;
  unsigned char *username_cp = NULL;
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
	      line_key_id = strtok (line, delimiters);
	      if (*line_key_id)
		{
		  line_username = strtok (NULL, delimiters);
		  if (*line_username)
		    {
		      if ((! strtok (NULL, delimiters))  && (! strcmp (key_id, line_key_id)))
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
