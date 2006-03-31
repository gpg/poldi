/* usersdb.c - PAM authentication via OpenPGP smartcards.
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
#include <errno.h>

#include <gcrypt.h>

#include "usersdb.h"
#include "defs.h"

#include <jnlib/stringhelp.h>



/* This is the type for callbacks functions, which need to be passed
   to usersdb_process().  The callback function receives the one
   (SERIALNO, USERNAME) pair per invocation.  OPAQUE is the opaque
   arugment passed to usersdb_process().  The return code of such a
   callback functions has the following meanings:

   0: Continue processing the users database.
   1: Stop processing.  */
typedef int (*usersdb_cb_t) (const char *serialno, const char *username,
			     void *opaque);

/* This functions processes the users database.  For each read pair of
   a card serial number and a account, the callback function specified
   as (CB, OPAQUE) is called.  Depending on CB's return code,
   processing is continued or aborted.  */
static gcry_error_t
usersdb_process (usersdb_cb_t cb, void *opaque)
{
  const char *delimiters = "\t\n ";
  gpg_error_t err;
  FILE *usersdb;
  char *line;
  char *line_serialno;
  char *line_username;
  size_t line_n;
  ssize_t ret;
  int cb_ret;

  line_serialno = NULL;
  line_username = NULL;
  line = NULL;
  err = 0;

  /* Open users database.  */
  usersdb = fopen (POLDI_USERS_DB_FILE, "r");
  if (! usersdb)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  /* Process lines.  */

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
	  /* else EOF.  */
	  break;
	}

      line_serialno = strtok (line, delimiters);
      line_username = strtok (NULL, delimiters);

      if (line_serialno && line_username)
	{
	  /* Looks like a valid entry, pass to callback function.  */
	  cb_ret = (*cb) (line_serialno, line_username, opaque);
	  if (cb_ret)
	    /* Callback functions wants us to stop.  */
	    break;
	}

      free (line);
    }
  if (err)
    goto out;

  /* Finalize.  */
  (*cb) (NULL, NULL, opaque);

 out:

  if (usersdb)
    fclose (usersdb);
  free (line);

  return err;
}



/*
 * Implementation of "usersdb_check" function.  usersdb_check()
 * figures out wether a given serial number is assocated with a given
 * username or not.
 */

/* Type for opaque callback argument.  */
typedef struct check_cb_s
{
  /* This is the pair we are looking for. */
  const char *serialno;
  const char *username;

  /* If found, this is set to TRUE by the callback function.  */
  int match;
} *check_cb_t;

/* Callback function.  */
static int
usersdb_check_cb (const char *serialno, const char *username, void *opaque)
{
  check_cb_t ctx = opaque;

  if (! (serialno || username))
    /* Finalizing */;
  else
    {
      /* Regular entry.  */

      if ((! strcmp (ctx->serialno, serialno))
	  && (! strcmp (ctx->username, username)))
	{
	  /* The current entry is exactly the one we were looking
	     for.  */
	  ctx->match = 1;
	  return 1;
	}
    }

  return 0;
}

/* This functions figures out wether the provided (SERIALNO, USERNAME)
   pair is contained in the users database.  */
gcry_error_t
usersdb_check (const char *serialno, const char *username)
{
  struct check_cb_s ctx = { serialno, username, 0 };
  gcry_error_t err;

  err = usersdb_process (usersdb_check_cb, &ctx);
  if (! err)
    {
      /* Now we have a result in CTX.  */

      if (! ctx.match)
	err = gcry_error (GPG_ERR_NOT_FOUND); /* FIXME: not the best
						 return code...  */
    }

  return err;
}



/*
 *
 */

/* Looking up a username for a given serial number.  */

typedef struct lookup_cb_s
{
  const char *serialno;
  const char *username;
  int matches;
  char *found;
  gcry_error_t err;
} *lookup_cb_t;

static int
usersdb_lookup_cb (const char *serialno, const char *username, void *opaque)
{
  lookup_cb_t ctx = opaque;
  char *str;

  if (! (serialno || username))
    goto out;

  /* FIXME: this function is not nice.  */

  if (ctx->serialno)
    {
      if (! strcmp (ctx->serialno, serialno))
	{
	  if (! ctx->matches)
	    {
	      str = strdup (username);
	      if (! str)
		{
		  ctx->err = gcry_error_from_errno (errno);
		  return 1;
		}

	      ctx->found = str;
	      ctx->matches++;
	    }
	  else
	    {
	      if (strcmp (ctx->found, username))
		ctx->matches++;
	    }
	}
    }
  else
    {
      if (! strcmp (ctx->username, username))
	{
	  if (! ctx->matches)
	    {
	      str = strdup (serialno);
	      if (! str)
		{
		  ctx->err = gcry_error_from_errno (errno);
		  return 1;
		}

	      ctx->found = str;
	      ctx->matches++;
	    }
	  else
	    {
	      if (strcmp (ctx->found, serialno))
		ctx->matches++;
	    }
	}
    }

 out:

  return 0;
}

/* This function tries to lookup a username by it's serial number;
   this is only possible in case the specified serial number SERIALNO
   is associated with exactly one username.  The username will be
   stored in newly allocated memory in *USERNAME.  Returns proper
   error code.  */
gcry_error_t
usersdb_lookup_by_serialno (const char *serialno, char **username)
{
  struct lookup_cb_s ctx = { serialno, NULL, 0, NULL, 0 };
  gcry_error_t err;

  err = usersdb_process (usersdb_lookup_cb, &ctx);
  if (err)
    goto out;

  /* Now we have a result in CTX.  */

  if (ctx.err)
    {
      err = ctx.err;
      goto out;
    }

  if (! ctx.matches)
    {
      err = gcry_error (GPG_ERR_NOT_FOUND);
      goto out;
    }
  else if (ctx.matches > 1)
    {
      err = gcry_error (GPG_ERR_AMBIGUOUS_NAME);
      goto out;
    }
  else if (ctx.matches == 1)
    {
      *username = ctx.found;
      ctx.found = NULL;
    }

 out:

  free (ctx.found);

  return err;
}

/* This function tries to lookup a serial number by it's username;
   this is only possible in case the specified username USERNAME is
   associated with exactly one serial number.  The serial number will
   be stored in newly allocated memory in *SERIALNO.  Returns proper
   error code.  */
gcry_error_t
usersdb_lookup_by_username (const char *username, char **serialno)
{
  struct lookup_cb_s ctx = { NULL, username, 0, NULL, 0 };
  gcry_error_t err;

  err = usersdb_process (usersdb_lookup_cb, &ctx);
  if (err)
    goto out;

  /* Now we have a result in CTX.  */

  if (ctx.err)
    {
      err = ctx.err;
      goto out;
    }

  if (! ctx.matches)
    {
      err = gcry_error (GPG_ERR_NOT_FOUND);
      goto out;
    }
  else if (ctx.matches > 1)
    {
      err = gcry_error (GPG_ERR_AMBIGUOUS_NAME);
      goto out;
    }
  else if (ctx.matches == 1)
    {
      *serialno = ctx.found;
      ctx.found = NULL;
    }

 out:

  free (ctx.found);

  return err;
}



/*
 *
 */

/* Usersdb, entry add.  */

/* Type for opaque callback argument.  */
typedef struct add_cb_s
{
  /* This is the pair we intend to add. */
  const char *serialno;
  const char *username;

  /* If found, this is set to TRUE by the callback function.  */
  int found;

  /*  */
  FILE *fp;
} *add_cb_t;

/* Callback function.  */
static int
usersdb_add_cb (const char *serialno, const char *username, void *opaque)
{
  add_cb_t ctx = opaque;

  if (! (serialno && username))
    {
      /* Finalizing.  */
      if (! ctx->found)
	fprintf (ctx->fp, "%s\t%s\n", ctx->serialno, ctx->username);
    }
  else
    {
      /* Regular invocation.  */

      int skip = 0;

      if ((! strcmp (ctx->serialno, serialno))
	  && (! strcmp (ctx->username, username)))
	{
	  if (ctx->found)
	    /* Duplicate entry; ignore it this time.  */
	    skip = 1;
	  else
	    /* Entry is already contained, fine.  */
	    ctx->found = 1;
	}

      if (! skip)
	fprintf (ctx->fp, "%s\t%s\n", serialno, username);
    }

  return 0;
}

/* This function adds an entry to the users database; USERNAME and
   SERIALNO must not be NULL.  This is a no-operation in case USERNAME
   is already associated with SERIALNO.  */
gpg_error_t
usersdb_add (const char *username, const char *serialno)
{
  struct add_cb_s ctx = { serialno, username, 0, NULL };
  char users_file[] = POLDI_USERS_DB_FILE ".new";
  FILE *users_file_fp;
  gpg_error_t err;
  int ret;

  /* Open.  */
  users_file_fp = fopen (users_file, "a");
  if (! users_file_fp)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  ctx.fp = users_file_fp;

  /* Process.  */
  err = usersdb_process (usersdb_add_cb, &ctx);
  if (err)
    goto out;

  /* Close.  */
  ret = fclose (users_file_fp);
  users_file_fp = NULL;
  if (ret)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  /* Rename file.  */

  ret = rename (users_file, POLDI_USERS_DB_FILE);
  if (ret == -1)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

 out:

  if (users_file_fp)
    fclose (users_file_fp);

  return err;
}



/*
 * Implementation of the "usersdb_remove" function.
 */

/* Usersdb, entry remove.  */

typedef struct remove_cb_s
{
  /* These specify the entry to remove.  */
  const char *username;
  const char *serialno;

  /* The persistent entries are written here.  */
  FILE *fp;
} *remove_cb_t;

/* Callback.   */
static int
usersdb_remove_cb (const char *serialno, const char *username, void *opaque)
{
  remove_cb_t ctx = opaque;
  int skip = 0;

  if (! (serialno || username))
    /* Finalizing.  */;
  else
    {
      /* Regular entry.  */
      
      if (ctx->serialno && ctx->username)
	{
	  if ((! strcmp (ctx->serialno, serialno))
	      && (! strcmp (ctx->username, username)))
	    skip = 1;
	}
      else if (ctx->serialno)
	{
	  if (! strcmp (ctx->serialno, serialno))
	    skip = 1;
	}
      else if (ctx->username)
	{
	  if (! strcmp (ctx->username, username))
	    skip = 1;
	}

      if (! skip)
	/* FIXME: error checking? */
	fprintf (ctx->fp, "%s\t%s\n", serialno, username);
    }

  return 0;
}

/* This function removes entries from the users database.  Either
   USERNAME or SERIALNO must be non-NULL.  If USERNAME is non-NULL and
   serialno is NULL, remove all entries for the given username; if
   USERNAME is NULL and serialno is non-NULL, remove all entries fot
   the specified serial number; if USERNAME and SERIALNO are non-NULL,
   remove exactly this entry.  Returns proper error code.  */
gpg_error_t
usersdb_remove (const char *username, const char *serialno)
{
  struct remove_cb_s ctx = { username, serialno, NULL };
  char users_file_new[] = POLDI_USERS_DB_FILE ".new";
  FILE *users_file_new_fp;
  gpg_error_t err;
  int ret;

  assert (username || serialno);

  users_file_new_fp = NULL;

  /* Open temporary file for new database.  */

  users_file_new_fp = fopen (users_file_new, "w");
  if (! users_file_new_fp)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  ctx.fp = users_file_new_fp;

  /* Filter.  */

  err = usersdb_process (usersdb_remove_cb, &ctx);
  if (err)
    goto out;

  /* Close temporary file.  */
  ret = fclose (users_file_new_fp);
  users_file_new_fp = NULL;
  if (ret)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  /* Rename file.  */

  ret = rename (users_file_new, POLDI_USERS_DB_FILE);
  if (ret == -1)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

 out:

  if (users_file_new_fp)
    fclose (users_file_new_fp);

  return err;
}



/*
 * Implementation of the "usersbd_list" function.
 */

typedef struct list_cb_s
{
  FILE *fp;
} *list_cb_t;

static int
usersdb_list_cb (const char *serialno, const char *username, void *opaque)
{
  list_cb_t ctx = opaque;

  if (serialno && username)
    {
      fprintf (ctx->fp, "Account: %s; Serial No: %s\n",
	       username, serialno);
      /* FIXME: error checking?  */
    }

  return 0;
}

/* This functions lists information from the users database to the
   stream STREAM.  Returns proper error code.  */
gcry_error_t
usersdb_list (FILE *stream)
{
  struct list_cb_s ctx = { stream };
  gcry_error_t err;

  err = usersdb_process (usersdb_list_cb, &ctx);

  return err;
}
  
/* END */
