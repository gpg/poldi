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

#include <jnlib/xmalloc.h>
#include <jnlib/stringhelp.h>

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

static gpg_error_t
usersdb_translate (const char *serialno, const char *username, char **found)
{
  const char *delimiters = "\t\n ";
  gpg_error_t err;
  FILE *usersdb;
  char *line;
  char *line_serialno;
  char *line_username;
  char *token_found;
  size_t line_n;
  ssize_t ret;

  err = 0;
  line = NULL;
  token_found = NULL;
  line_serialno = NULL;
  line_username = NULL;

  usersdb = fopen (POLDI_USERS_DB_FILE, "r");
  if (! usersdb)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  while (1)
    {
      /* Get next line.  */
      line = NULL;
      line_n = 0;
      ret = getline (&line, &line_n, usersdb);
      if (ret == -1)
	{
	  if (ferror (usersdb))
	    err = gpg_error_from_errno (errno);
	  else
	    err = gpg_error (GPG_ERR_NOT_FOUND);
	  break;
	}

      line_serialno = strtok (line, delimiters);
      if (! line_serialno)
	{
	  err = gpg_error (GPG_ERR_INTERNAL); /* FIXME?  */
	  break;
	}

      line_username = strtok (NULL, delimiters);
      if (! line_username)
	{
	  err = gpg_error (GPG_ERR_INTERNAL); /* FIXME?  */
	  break;
	}

      if (serialno)
	{
	  if (! strcmp (serialno, line_serialno))
	    {
	      if (found)
		{
		  token_found = strdup (line_username);
		  if (! token_found)
		    err = gpg_error_from_errno (errno);
		}
	      break;
	    }
	}
      else
	{
	  if (! strcmp (username, line_username))
	    {
	      if (found)
		{
		  token_found = strdup (line_serialno);
		  if (! token_found)
		    err = gpg_error_from_errno (errno);
		}
	      break;
	    }
	}

      free (line);
    }
  if (err)
    goto out;

  if (found)
    *found = token_found;

 out:

  if (usersdb)
    fclose (usersdb);
  free (line);

  return err;
}

gpg_error_t
usersdb_lookup_by_serialno (const char *serialno, char **username)
{
  return usersdb_translate (serialno, NULL, username);
}

gpg_error_t
usersdb_lookup_by_username (const char *username, char **serialno)
{
  return usersdb_translate (NULL, username, serialno);
}

gpg_error_t
usersdb_add_entry (const char *username, const char *serialno)
{
  char users_file[] = POLDI_USERS_DB_FILE;
  FILE *users_file_fp;
  gpg_error_t err;
  int ret;

  users_file_fp = NULL;
  
  users_file_fp = fopen (users_file, "a");
  if (! users_file_fp)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  fprintf (users_file_fp, "%s\t%s\n", serialno, username);
  if (ferror (users_file_fp))
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }
  
  ret = fclose (users_file_fp);
  users_file_fp = NULL;
  if (ret)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }
  
  err = 0;

 out:

  if (users_file_fp)
    fclose (users_file_fp);

  return err;
}

gpg_error_t
usersdb_remove_entry (const char *username, const char *serialno,
		      unsigned int *nentries)
{
  char users_file_old[] = POLDI_USERS_DB_FILE;
  char users_file_new[] = POLDI_USERS_DB_FILE ".new";
  unsigned int nentries_removed;
  char delimiters[] = "\t\n ";
  FILE *users_file_old_fp;
  FILE *users_file_new_fp;
  char *line;
  char *line_serialno;
  char *line_username;
  size_t line_n;
  ssize_t ret;
  gpg_error_t err;

  line_n = 0;
  line = NULL;
  users_file_old_fp = NULL;
  users_file_new_fp = NULL;

  assert (username || serialno);

  users_file_old_fp = fopen (users_file_old, "r");
  if (! users_file_old_fp)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }
  users_file_new_fp = fopen (users_file_new, "w");
  if (! users_file_new_fp)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  nentries_removed = 0;
  err = 0;

  while (1)
    {
      ret = getline (&line, &line_n, users_file_old_fp);
      if (ret == -1)
	{
	  if (ferror (users_file_old_fp))
	    err = gpg_error_from_errno (errno);
	  break;
	}

      line_serialno = strtok (line, delimiters);
      if (! line_serialno)
	{
	  err = gpg_error (GPG_ERR_INTERNAL); /* FIXME?  */
	  break;
	}

      line_username = strtok (NULL, delimiters);
      if (! line_username)
	{
	  err = gpg_error (GPG_ERR_INTERNAL); /* FIXME?  */
	  break;
	}

      if ((username && strcmp (username, line_username))
	  || (serialno && strcmp (serialno, line_serialno)))
	fprintf (users_file_new_fp, "%s\t%s\n", line_serialno, line_username);
      else
	nentries_removed++;

      free (line);
      line = NULL;
      line_n = 0;
    }

  fclose (users_file_old_fp);	/* FIXME: it's alright to ignore
				   errors here, right?  */
  users_file_old_fp = NULL;
  
  ret = fclose (users_file_new_fp);
  users_file_new_fp = NULL;
  if (ret)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  ret = rename (users_file_new, users_file_old);
  if (ret == -1)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  *nentries = nentries_removed;

 out:

  free (line);
  if (users_file_old_fp)
    fclose (users_file_old_fp);
  if (users_file_new_fp)
    fclose (users_file_new_fp);

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
      fclose (fp);		/* FIXME?  */
      fp = NULL;
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



gpg_error_t
key_filename_construct (char **filename, const char *serialno)
{
  char *path;

  path = make_filename (POLDI_KEY_DIRECTORY, serialno, NULL);
  *filename = path;

  return 0;
}

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

/* END */
