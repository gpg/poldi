/* poldi-ctrl.c - Poldi maintaince tool
   Copyright (C) 2004, 2005 g10 Code GmbH.
 
   This file is part of Poldi.
  
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU general Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <config.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>

#include <gcrypt.h>

#include <jnlib/argparse.h>
#include <jnlib/xmalloc.h>
#include <jnlib/logging.h>
#include <common/options.h>
#include <common/card.h>
#include <common/support.h>
#include <common/defs.h>
#include <libscd/scd.h>



/* Global flags.  */
struct poldi_ctrl_opt
{
  unsigned int debug; /* debug flags (DBG_foo_VALUE) */
  int debug_sc;     /* OpenSC debug level */
  int verbose;      /* verbosity level */
  char *ctapi_driver; /* Library to access the ctAPI. */
  char *pcsc_driver;  /* Library to access the PC/SC system. */
  char *reader_port;  /* NULL or reder port to use. */
  int disable_opensc;  /* Disable the use of the OpenSC framework. */
  int disable_ccid;    /* Disable the use of the internal CCID driver. */
  int debug_ccid_driver;	/* Debug the internal CCID driver.  */
  char *config_file;
  char *account;
  char *serialno;
  int require_card_switch;
  int cmd_test;
  int cmd_dump;
  int cmd_set_key;
  int cmd_show_key;
  int cmd_add_user;
  int cmd_remove_user;
  int cmd_list_users;
  unsigned int wait_timeout;
} poldi_ctrl_opt;

/* Set defaults.  */
struct poldi_ctrl_opt poldi_ctrl_opt =
  {
    0,
    0,
    0,
    NULL,
    NULL,
    NULL,
    0,
    0,
    0,
    POLDI_CONF_FILE,
    NULL,
    NULL,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };

enum arg_opt_ids
  {
    arg_test = 't',
    arg_dump = 'd',
    arg_set_key = 's',
    arg_show_key = 'k',
    arg_add_user  = 'a',
    arg_remove_user  = 'r',
    arg_list_users  = 'l',
    arg_config_file = 'c',
    arg_ctapi_driver = 500,
    arg_account,
    arg_serialno,
    arg_pcsc_driver,
    arg_reader_port,
    arg_disable_ccid,
    arg_disable_opensc,
    arg_debug,
    arg_debug_ccid_driver,
    arg_require_card_switch,
    arg_wait_timeout
  };

static ARGPARSE_OPTS arg_opts[] =
  {
    /* Commands:  */

    { 300, NULL, 0, "@Commands:\n " },
    { arg_test,
      "test",        256, "Test authentication"                },
    { arg_dump,
      "dump",        256, "Dump certain card information"      },
    { arg_add_user,
      "add-user",    256, "Add account to users db"            },
    { arg_remove_user,
      "remove-user",    256, "Remove account from users db"    },
    { arg_list_users,
      "list-users",    256, "List accounts from users db"      },
    { arg_set_key,
      "set-key",     256, "Set key for calling user"           },
    { arg_show_key,
      "show-key",     256, "Show key of calling user"          },

    /* Options:  */
    { 301, NULL, 0, "@\nOptions:\n " },
    { arg_config_file,
      "config-file",   2, "|FILE|Specify configuration file"   },
    { arg_debug,
      "debug", 256, "Enable debugging mode" },
    { arg_account,
      "account",       2, "|NAME|Specify Unix account"         },
    { arg_serialno,
      "serialno",      2, "|NAME|Specify card serial number"   },
    { arg_ctapi_driver,
      "ctapi-driver", 2, "|NAME|use NAME as ct-API driver"     },
    { arg_pcsc_driver,
      "pcsc-driver", 2, "|NAME|use NAME as PC/SC driver"       },
    { arg_reader_port,
      "reader-port", 2, "|N|connect to reader at port N"       },
#ifdef HAVE_LIBUSB
    { arg_disable_ccid,
      "disable-ccid", 0, "do not use the internal CCID driver" },
    { arg_debug_ccid_driver,
      "debug-ccid-driver", 0, "debug the  internal CCID driver" },
#endif
#ifdef HAVE_OPENSC
    { arg_disable_opensc,
      "disable-opensc", 0, "do not use the OpenSC layer"       },
#endif
    { arg_require_card_switch,
      "require-card-switch", 0, "Require re-insertion of card" },
    { arg_wait_timeout,
      "wait-timeout", 1, "|SEC|Specify timeout for waiting" },
    { 0,
      NULL,            0, NULL                                 }
  };



/* Callback function printing program usage information used through
   jnlib.  */
static const char *
my_strusage (int level)
{
  const char *p;

  switch (level)
    {
    case 11:
      p = "poldi-ctrl (Poldi)";
      break;

    case 13:
      p = VERSION;
      break;

    case 19:
      p = "Please report bugs to <" PACKAGE_BUGREPORT ">\n";
      break;

    case 1:
    case 40:
      p = "Usage: poldi-ctrl <command> [options]";
      break;

    case 41:
      p = "Syntax: poldi-ctrl <command> [options]\n";
      break;

    default:
      p = NULL;
    }

  return p;
}

/* Option parser callback by options_parse_argv() and
   options_parse_conf(), which are jnlib wrappers.  */
static gpg_error_t
poldi_ctrl_options_cb (ARGPARSE_ARGS *parg, void *opaque)
{
  int parsing_stage = *((int *) opaque);
  gpg_error_t err = 0;

  switch (parg->r_opt)
    {
    case arg_config_file:
      if (! parsing_stage)
	poldi_ctrl_opt.config_file = xstrdup (parg->r.ret_str);
      break;

    case arg_test:
      if (parsing_stage)
	poldi_ctrl_opt.cmd_test = 1;
      break;

    case arg_set_key:
      if (parsing_stage)
	poldi_ctrl_opt.cmd_set_key = 1;
      break;

    case arg_show_key:
      if (parsing_stage)
	poldi_ctrl_opt.cmd_show_key = 1;
      break;

    case arg_dump:
      if (parsing_stage)
	poldi_ctrl_opt.cmd_dump = 1;
      break;

    case arg_add_user:
      if (parsing_stage)
	poldi_ctrl_opt.cmd_add_user = 1;
      break;

    case arg_remove_user:
      if (parsing_stage)
	poldi_ctrl_opt.cmd_remove_user = 1;
      break;

    case arg_list_users:
      if (parsing_stage)
	poldi_ctrl_opt.cmd_list_users = 1;
      break;

    case arg_account:
      if (parsing_stage)
	poldi_ctrl_opt.account = xstrdup (parg->r.ret_str);
      break;
      
    case arg_serialno:
      if (parsing_stage)
	poldi_ctrl_opt.serialno = xstrdup (parg->r.ret_str);
      break;
      
    case arg_ctapi_driver:
      if (parsing_stage)
	poldi_ctrl_opt.ctapi_driver = xstrdup (parg->r.ret_str);
      break;

    case arg_pcsc_driver:
      if (parsing_stage)
	poldi_ctrl_opt.pcsc_driver = xstrdup (parg->r.ret_str);
      break;

    case arg_reader_port:
      if (parsing_stage)
	poldi_ctrl_opt.reader_port = xstrdup (parg->r.ret_str);
      break;

    case arg_disable_ccid:
      if (parsing_stage)
	poldi_ctrl_opt.disable_ccid = 1;
      break;

    case arg_disable_opensc:
      if (parsing_stage)
	poldi_ctrl_opt.disable_opensc = 1;
      break;

    case arg_debug:
      if (parsing_stage)
	{
	  poldi_ctrl_opt.debug = ~0;
	  poldi_ctrl_opt.debug_sc = 1;
	  poldi_ctrl_opt.verbose = 1;
	  poldi_ctrl_opt.debug_ccid_driver = 1;
	}
      break;

    case arg_debug_ccid_driver:
      if (parsing_stage)
	poldi_ctrl_opt.debug_ccid_driver = 1;
      break;

    case arg_require_card_switch:
      if (parsing_stage)
	poldi_ctrl_opt.require_card_switch = 1;
      break;

    case arg_wait_timeout:
      if (parsing_stage)
	poldi_ctrl_opt.wait_timeout = parg->r.ret_int;
      break;

    default:
      parg->err = 2;
      break;
    }

  return gpg_error (err);
}



/*
 * Key file management.
 */

/* Create a key file for user ACCOUNT and card serial number SERIALNO.
   Return proper error code.  */
static gpg_error_t
key_file_create (struct passwd *pwent, const char *serialno)
{
  struct stat statbuf;
  gpg_error_t err;
  char *path;
  int ret;
  int fd;

  path = NULL;

  err = key_filename_construct (&path, serialno);
  if (err)
    {
      log_error ("Error: failed to construct key file path "
		 "for serial number `%s': %s\n",
		 serialno, gpg_strerror (err));
      goto out;
    }

  fd = open (path, O_WRONLY | O_CREAT, 0644);
  if (fd == -1)
    {
      err = gpg_error_from_errno (errno);
      log_error ("Error: failed to open key file `%s': %s\n",
		 path, gpg_strerror (err));
      goto out;
    }

  ret = close (fd);
  if (ret == -1)
    {
      err = gpg_error_from_errno (errno);
      log_error ("Error: failed to close key file `%s': %s\n",
		 path, gpg_strerror (err));
      goto out;
    }

  ret = stat (path, &statbuf);
  if (ret == -1)
    {
      err = gpg_error_from_errno (errno);
      log_error ("Error: failed to stat key file `%s': %s\n",
		 path, gpg_strerror (err));
      goto out;
    }

  ret = chown (path, pwent->pw_uid, statbuf.st_gid);
  if (ret == -1)
    {
      err = gpg_error_from_errno (errno);
      log_error ("Error: failed to chown key file `%s' to (%i, %i): %s\n",
		 path, pwent->pw_uid, statbuf.st_gid, gpg_strerror (err));
      goto out;
    }

  err = 0;

 out:

  free (path);

  return err;
}

/* Remove the key file for card serial number SERIALNO.  Return proper
   error code.  */
static gpg_error_t
key_file_remove (const char *serialno)
{
  gpg_error_t err;
  char *path;
  int ret;

  err = key_filename_construct (&path, serialno);
  if (err)
    {
      log_error ("Error: failed to construct key file path "
		 "for serial number `%s': %s\n",
		 serialno, gpg_strerror (err));
      goto out;
    }

  ret = unlink (path);
  if ((ret == -1) && (errno != ENOENT))
    {
      err = gpg_error_from_errno (errno);
      log_error ("Error: failed to unlink key file `%s': %s\n",
		 path, gpg_strerror (err));
      goto out;
    }

  err = 0;

 out:

  free (path);

  return err;
}



/*
 * Command functions.
 */

static gpg_error_t
conversation (conversation_type_t type, void *opaque,
	      const char *info, char **response)
{
  gpg_error_t err;

  switch (type)
    {
    case CONVERSATION_TELL:
      printf ("%s\n", info);
      err = 0;
      break;

    case CONVERSATION_ASK_SECRET:
      {
	char *secret;

	secret = getpass (info);
	if (! secret)
	  {
	    err = gpg_error_from_errno (errno);
	    log_error ("Error: getpass() returned NULL: %s\n",
		       gpg_strerror (err));
	  }
	else
	  {
	    *response = secret;
	    err = 0;
	  }
      }
      break;

    default:
      /* This CANNOT happen.  */
      abort ();
    }

  return err;
}

/* Implementation of `test' command; test authentication
   mechanism.  */
static gpg_error_t
cmd_test (void)
{
  gpg_error_t err;
  int slot;
  char *serialno;
  char *account;
  gcry_sexp_t key;
  unsigned int version;

  slot = -1;
  key = NULL;
  account = NULL;
  serialno = NULL;
  version = 0;

  /* Open and initialize card.  */

  err = card_open (NULL, &slot);
  if (err)
    {
      log_error ("Error: failed to open card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  if (poldi_ctrl_opt.account)
    {
      /* Trying authentication for a given username.  */

      /* We do not need the key right now already, but it seems to be
	 a good idea to make the login fail before waiting for card in
	 case no key has been installed for that card.  */
      err = key_lookup_by_username (poldi_ctrl_opt.account, &key);
      if (err)
	goto out;

      err = wait_for_card (slot, poldi_ctrl_opt.require_card_switch,
			   poldi_ctrl_opt.wait_timeout,
			   conversation, NULL, &serialno,
			   &version, NULL);

      printf ("Serial No: %s\n", serialno);
      printf ("Card version: %u\n", version);

      /* Converting card serial number into account, through user
	 database.  */

      err = usersdb_lookup_by_serialno (serialno, &account);
      if (err || strcmp (account, poldi_ctrl_opt.account))
	{
	  /* Either the account could not be found or it is not the
	     expected one -> fail.  */

	  if (! err)
	    {
	      fprintf (stderr, "Serial no %s is not associated with %s\n",
		       serialno, poldi_ctrl_opt.account);
	      err = gpg_error (GPG_ERR_INV_NAME);
	    }
	  else
	    log_error ("Error: failed to lookup username for "
		       "serial number `%s': %s\n",
		       serialno, gpg_strerror (err));
	}
      if (err)
	goto out;

      err = authenticate (slot, key, conversation, NULL);
      if (err)
	goto out;
    }
  else
    {
      /* No username has been provided by PAM, thus we accept any
	 card.  */

      err = wait_for_card (slot, poldi_ctrl_opt.require_card_switch,
			   poldi_ctrl_opt.wait_timeout, conversation, NULL,
			   &serialno, &version, NULL);
      if (err)
	/* FIXME */
	goto out;

      /* Lookup account for inserted card.  */
      err = usersdb_lookup_by_serialno (serialno, &account);
      if (err)
	{
	  log_error ("Error: failed to lookup username for "
		     "serial number `%s': %s\n",
		     serialno, gpg_strerror (err));
	  goto out;
	}

      /* Inform user about looked up account.  */
      printf ("Account: %s\n", account);

      /* Lookup key for looked up account.  */
      err = key_lookup_by_username (account, &key);
      if (err)
	goto out;

      /* Try authentication with looked up key.  */
      err = authenticate (slot, key, conversation, NULL);
      if (err)
	goto out;
    }

  printf ("Account: %s\n", account);

  if (err)
    printf ("Authentication failed (%s)\n", gpg_strerror (err));
  else
    printf ("Authentication succeeded\n");

 out:

  /* Deallocate resources.  */

  if (slot != -1)
    card_close (slot);
  free (account);
  free (serialno);
  gcry_sexp_release (key);

  return err;
}



/* Implementation of `dump' command; dumps information from card.  */
static gpg_error_t
cmd_dump (void)
{
  gcry_sexp_t key;
  char *key_s;
  char *serialno;
  gpg_error_t err;
  int slot;
  char *pin;
  unsigned int version;

  slot = -1;
  serialno = NULL;
  key = NULL;
  key_s = NULL;
  pin = NULL;

  /* Open and initialize card.  */

  err = card_open (NULL, &slot);
  if (err)
    {
      log_error ("Error: failed to open card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  err = card_init (slot, 0, 0, 0);
  if (err)
    {
      /* FIXME: wording.  */
      log_error ("Error: failed to initialize card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Retrieve more card information.  */

  err = card_info (slot, &serialno, &version, NULL);
  if (err)
    {
      log_error ("Error: failed to retreive basic information"
		 "from card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  if (version <= 0x0100)
    {
      /* These cards contain a bug, which makes it necessary to pass
	 CHV3 to the card before reading out the public key.  */

      printf (POLDI_OLD_CARD_KEY_RETRIVAL_EXPLANATION, version);

      pin = getpass (POLDI_PIN3_QUERY_MSG);
      if (! pin)
	{
	  /* FIXME: correct error handling?  */
	  err = gpg_error_from_errno (errno);
	  log_error ("Error: failed to retrieve PIN from user: %s\n",
		     gpg_strerror (err));
	  goto out;
	}
	
      err = card_pin_provide (slot, 3, pin);
      if (err)
	{
	  log_error ("Error: failed to send PIN to card: %s\n",
		     gpg_strerror (err));
	  goto out;
	}
    }

  /* Retrieve key from card.  */

  err = card_read_key (slot, &key);
  if (err)
    {
      log_error ("Error: failed to retrieve key from card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Convert key into a string.  */

  err = sexp_to_string (key, &key_s);
  if (err)
    {
      log_error ("Error: failed to convert key S-Expression "
		 "into C-String: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  printf ("Slot: %i\n", slot);
  printf ("Serial number: %s\n", serialno);
  printf ("Version: 0x%X\n", version);
  printf ("Key:\n%s\n", key_s);

 out:

  if (slot != -1)
    card_close (slot);
  gcry_sexp_release (key);
  gcry_free (key_s);
  free (serialno);
  free (pin);

  return err;
}



/* Implementation of `list-users' command; dump information from user
   database.  */
static gpg_error_t
cmd_list_users (void)
{
  char users_file[] = POLDI_USERS_DB_FILE;
  FILE *users_file_fp;
  char delimiters[] = "\t\n ";
  gpg_error_t err;
  char *line;
  size_t line_n;
  size_t line_number;
  char *serialno;
  char *account;
  int ret;

  line = NULL;

  /* Open user database file.  */

  users_file_fp = fopen (users_file, "r");
  if (! users_file_fp)
    {
      err = gpg_error_from_errno (errno);
      log_error ("Error: failed to open user database `%s': %s\n",
		 users_file, gpg_strerror (err));
      goto out;
    }

  line_number = 1;
  err = 0;

  /* Iterate over file.  */

  while (1)
    {
      free (line);
      line = NULL;

      /* Read next line.  */

      ret = getline (&line, &line_n, users_file_fp);
      if (ret == -1)
	{
	  if (ferror (users_file_fp))
	    {
	      err = gpg_error_from_errno (errno);
	      log_error ("Error: getline() failed: %s\n",
			 gpg_strerror (err));
	    }
	  /* else must be EOF.  */

	  break;
	}

      /* Parse line.  */

      serialno = strtok (line, delimiters);
      if (! serialno)
	log_error ("Error: user database seems to be corrupt; "
		   "serial number missing in line: %i\n",
		   line_number);
      account = strtok (NULL, delimiters);
      if (! account)
	log_error ("Error: user database seems to be corrupt; "
		   "account missing in line: %i\n",
		   line_number);

      if (account && serialno)
	printf ("Account: %s; Serial No: %s\n", account, serialno);

      line_number++;
    }

 out:

  free (line);
  if (users_file_fp)
    fclose (users_file_fp);

  return err;
}



/* Implementation of `add-user' command; add a user for Poldi
   authentication.  */
static gpg_error_t
cmd_add_user (void)
{
  struct passwd *pwent;
  gpg_error_t err;
  char *serialno;
  char *account;
  int skip_userdb;

  serialno = poldi_ctrl_opt.serialno;
  account = poldi_ctrl_opt.account;

  if (! (serialno && account))
    {
      log_error ("Error: serial number and accounts needs to be given\n");
      exit (EXIT_FAILURE);
    }

  /* Lookup user in password database.  */

  pwent = getpwnam (account);
  if (! pwent)
    {
      log_error ("Error: unknown user `%s'\n", account);
      exit (EXIT_FAILURE);
    }

  /* Make sure that given serial number is not already associated with
     a different account and that the given account is not already
     associated with a different serial number.  */

  skip_userdb = 0;

  err = usersdb_lookup_by_serialno (serialno, &account);
  if (! err)
    {
      /* Entry found; serial number IS already associated with an
	 account.  */

      if (strcmp (account, pwent->pw_name))
	{
	  /* It is associated with a DIFFERENT account.  */
	  log_error ("Error: serial number `%s' "
		     "already associated with user `%s'\n",
		     serialno, account);
	  exit (EXIT_FAILURE);
	}
      else
	{
	  /* It is already associated with the SPECIFIED account.  */
	  log_info ("Note: serial number `%s' is already associated with "
		    "user `%s'\n",
		    serialno, account);
	  skip_userdb = 1;
	}
    }
  else if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    /* This is not an error in this context.  */
    err = 0;
  else
    {
      /* Unexpected error occured.  */
      log_error ("Error: unexpected failure during user database lookup: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  err = usersdb_lookup_by_username (pwent->pw_name, &serialno);
  if (! err)
    {
      /* Entry found; username is already associated with a serial
	 number.  */

      if (strcmp (serialno, poldi_ctrl_opt.serialno))
	{
	  /* It is associated with a DIFFERENT serial number.  */
	  log_error ("Error: user `%s' is already "
		     "associated with serial number `%s'\n",
		     pwent->pw_name, serialno);
	  exit (EXIT_FAILURE);
	}
      else
	{
	  /* It is already associated with the SPECIFIED account.  */
	  log_info ("Note: user `%s' is aleady associated with "
		    " serial number `%s'\n",
		    pwent->pw_name, serialno);
	  skip_userdb = 1;
	}
    }
  else if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    /* This is not an error in this context.  */
    err = 0;
  else
    {
      /* Unexpected error occured.  */
      log_error ("Error: unexpected failure during user database lookup: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  if (skip_userdb)
    log_info ("Note: not modifying user database\n");
  else
    {
      /* No such entry found in user database, add entry.  */
  
      err = usersdb_add_entry (account, serialno);
      if (err)
	{
	  log_error ("Error: failed to add entry to user database: %s\n",
		     gpg_strerror (err));
	  goto out;
	}
    }

  /* Create empty key file.  */

  err = key_file_create (pwent, serialno);
  if (err)
    {
      log_error ("Error: failed to create key file for "
		 "serial number: %s\n",
		 serialno);
      goto out;
    }

 out:

  return err;
}



/* Implementation of `remove-user' command; removes a user.  */
static gpg_error_t
cmd_remove_user (void)
{
  unsigned int nentries_removed;
  gpg_error_t err;
  char *serialno;

  /* Make sure that required information are given (serialno OR
     account).  */

  if (! (poldi_ctrl_opt.serialno || poldi_ctrl_opt.account))
    {
      fprintf (stderr, "Error: account or serial number needs to be given\n");
      exit (EXIT_FAILURE);
    }

  /* Make sure to have the serial number.  */

  if (poldi_ctrl_opt.serialno)
    serialno = poldi_ctrl_opt.serialno;
  else
    {
      serialno = NULL;
      err = usersdb_lookup_by_username (poldi_ctrl_opt.account, &serialno);
      if (err)
	{
	  log_error ("Warning: failed to lookup serial number "
		     "for username `%s': %s; thus cannot remove key file\n",
		     poldi_ctrl_opt.account, gpg_strerror (err));
	  err = 0;
	}
    }

  /* Try to remove entry from user database.  */

  err = usersdb_remove_entry (poldi_ctrl_opt.account, poldi_ctrl_opt.serialno,
			      &nentries_removed);
  if (err)
    {
      log_error ("Error: failed to remove entry for user `%s' "
		 "or serial number `%s' from user database: %s\n",
		 poldi_ctrl_opt.account, poldi_ctrl_opt.serialno,
		 gpg_strerror (err));
      goto out;
    }
  else if (! nentries_removed)
    log_info ("Note: no entries removed from user database\n");

  /* FIXME: skip step of key file removal in case key file does not
     exist (for whatever reasons).  */

  /* Remove key file.  */

  if (serialno)
    {
      err = key_file_remove (serialno);
      if (err)
	{
	  log_error ("Error: failed to remove key file for "
		     "serial number `%s': %s\n",
		     serialno, gpg_strerror (err));
	  goto out;
	}
    }

 out:

  if (serialno != poldi_ctrl_opt.serialno)
    free (serialno);

  return err;
}



/* Implementation of `set-key' command; install key of currently
   inserted card for user requesting this action.  */

static gpg_error_t
cmd_set_key (void)
{
  gpg_error_t err;
  char *path;
  FILE *path_fp;
  int slot;
  char *key_string;
  char *serialno;
  char *pin;
  gcry_sexp_t key_sexp;
  unsigned int version;
  int ret;

  slot = -1;
  pin = NULL;
  path = NULL;
  path_fp = NULL;
  serialno = NULL;
  key_sexp = NULL;
  key_string = NULL;
  version = 0;

  /* Open and initialize card.  */

  err = card_open (NULL, &slot);
  if (err)
    {
      log_error ("Error: failed to open card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  err = card_init (slot, 0, 0, 0);
  if (err)
    {
      /* FIXME: wording.  */
      log_error ("Error: failed to initialize card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Retrieve more information from card.  */

  err = card_info (slot, &serialno, &version, NULL);
  if (err)
    {
      log_error ("Error: failed to retreive basic information"
		 "from card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Construct key path.  */

  err = key_filename_construct (&path, serialno);
  if (err)
    {
      log_error ("Error: failed to construct key filename: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  if (version <= 0x0100)
    {
      /* Special handling necessary.
	 .
	 These cards contain a bug, which makes it necessary to pass
	 CHV3 to the card before reading out the public key.  */

      log_info (POLDI_OLD_CARD_KEY_RETRIVAL_EXPLANATION, version);

      /* Retrieve PIN from user.  */

      pin = getpass (POLDI_PIN3_QUERY_MSG);
      if (! pin)
	{
	  /* FIXME: correct error handling?  */
	  err = gpg_error_from_errno (errno);
	  log_error ("Error: failed to retrieve PIN from user: %s\n",
		     gpg_strerror (err));
	  goto out;
	}

      /* Send PIN to card.  */

      err = card_pin_provide (slot, 3, pin);
      if (err)
	{
	  log_error ("Error: failed to send PIN to card: %s\n",
		     gpg_strerror (err));
	  goto out;
	}
    }

  /* Retrieve key from card.  */

  err = card_read_key (slot, &key_sexp);
  if (err)
    {
      log_error ("Error: failed to retrieve key from card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Convert key into a string.  */

  err = sexp_to_string (key_sexp, &key_string);
  if (err)
    {
      log_error ("Error: failed to convert key S-Expression "
		 "into C-String: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Write key to key file.  */

  path_fp = fopen (path, "w");
  if (! path_fp)
    {
      err = gpg_error_from_errno (errno);
      log_error ("Error: failed to open key file `%s': %s\n",
		 path, gpg_strerror (err));
      goto out;
    }

  fprintf (path_fp, "%s", key_string);

  ret = fclose (path_fp);
  path_fp = NULL;
  if (ret)
    {
      err = gpg_error_from_errno (errno);
      log_error ("Error: failed to successfully close key file `%s' "
		 "buffered data might have not been flushed correctly: %s\n",
		 path, gpg_strerror (err));
      goto out;
    }

 out:

  free (pin);
  free (path);
  free (serialno);
  if (path_fp)
    fclose (path_fp);
  free (key_string);
  gcry_sexp_release (key_sexp);
  if (slot != -1)
    card_close (slot);

  return err;
}



/* Implementation of `show-key' command; sends to content of key file
   to standard output.  */
static gpg_error_t
cmd_show_key (void)
{
  gpg_error_t err;
  char *path;
  char *key_string;
  char *serialno;
  const char *username;
  gcry_sexp_t key_sexp;

  path = NULL;
  serialno = NULL;
  key_sexp = NULL;
  key_string = NULL;

  /* Retrieve username of caller.  */

  err = lookup_own_username (&username);
  if (err)
    {
      log_error ("Error: failed to lookup own username: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Lookup serial number for username.  */

  err = usersdb_lookup_by_username (username, &serialno);
  if (err)
    {
      log_error ("Error: failed to lookup serial number "
		 "for user `%s': %s\n",
		 username, gpg_strerror (err));
      goto out;
    }

  /* Construct key path.  */

  err = key_filename_construct (&path, serialno);
  if (err)
    {
      log_error ("Error: failed to construct key file path "
		 "for serial number `%s': %s\n",
		 serialno, gpg_strerror (err));
      goto out;
    }

  /* Read key file content into string.  */

  err = file_to_string (path, &key_string);
  if (err)
    {
      log_error ("Error: key could not be read from key file `%s': %s\n",
		 path, gpg_strerror (err));
      goto out;
    }

  /* Convert into S-Expression.  */

  err = string_to_sexp (&key_sexp, key_string);
  if (err)
    {
      log_error ("Error: failed to convert key into S-Expression: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* And back into C-string.  */

  free (key_string);
  key_string = NULL;
  err = sexp_to_string (key_sexp, &key_string);
  if (err)
    {
      log_error ("Error: failed to convert key S-Expression "
		 "into C-String: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* And print key string.  */

  if (key_string)
    printf ("%s", key_string);

 out:

  free (path);
  free (key_string);
  free (serialno);
  gcry_sexp_release (key_sexp);

  return err;
}



/* Main.  */
int
main (int argc, char **argv)
{
  unsigned int parsing_stage;
  unsigned int ncommands;
  gpg_error_t err;

  /* Initialize jnlib subsystems.  */

  set_strusage (my_strusage);
  log_set_prefix ("poldi-ctrl", 1);

  /* Parse argument vector, looking for a file config-file
     paramater.  */

  parsing_stage = 0;

  err = options_parse_argv (poldi_ctrl_options_cb, &parsing_stage,
			    arg_opts, argc, argv);
  if (err)
    {
      log_error ("Error: parsing argument vector (stage: %u) failed: %s\n",
		 parsing_stage, gpg_strerror (err));
      goto out;
    }

  /* Parse config file.  */

  parsing_stage++;
  err = options_parse_conf (poldi_ctrl_options_cb, &parsing_stage,
			    arg_opts, poldi_ctrl_opt.config_file);
  if (err)
    {
      log_error ("Error: parsing config file failed: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* And finally the argument vector, overwriting values from config
     file.  */
  parsing_stage++;
  err = options_parse_argv (poldi_ctrl_options_cb, &parsing_stage,
			    arg_opts, argc, argv);
  if (err)
    {
      log_error ("Error: parsing argument vector (stage: %u) failed: %s\n",
		 parsing_stage, gpg_strerror (err));
      goto out;
    }

  /* Initialize libscd.  */

  scd_init (poldi_ctrl_opt.debug,
	    poldi_ctrl_opt.debug_sc,
	    poldi_ctrl_opt.verbose,
	    poldi_ctrl_opt.ctapi_driver,
	    poldi_ctrl_opt.reader_port,
	    poldi_ctrl_opt.pcsc_driver,
	    poldi_ctrl_opt.disable_opensc,
	    poldi_ctrl_opt.disable_ccid,
	    poldi_ctrl_opt.debug_ccid_driver);

  ncommands = (0
	       + poldi_ctrl_opt.cmd_test
	       + poldi_ctrl_opt.cmd_set_key
	       + poldi_ctrl_opt.cmd_show_key
	       + poldi_ctrl_opt.cmd_add_user
	       + poldi_ctrl_opt.cmd_remove_user
	       + poldi_ctrl_opt.cmd_list_users
	       + poldi_ctrl_opt.cmd_dump);
  if (ncommands > 1)
    {
      log_error ("Error: more than one command specified (try --help)\n");
      exit (EXIT_FAILURE);
    }
  else if (! ncommands)
    {
      log_error ("Error: no command specified (try --help)\n");
      exit (EXIT_FAILURE);
    }

  if (poldi_ctrl_opt.cmd_test)
    err = cmd_test ();
  else if (poldi_ctrl_opt.cmd_dump)
    err = cmd_dump ();
  else if (poldi_ctrl_opt.cmd_set_key)
    err = cmd_set_key ();
  else if (poldi_ctrl_opt.cmd_show_key)
    err = cmd_show_key ();
  else if (poldi_ctrl_opt.cmd_add_user)
    err = cmd_add_user ();
  else if (poldi_ctrl_opt.cmd_remove_user)
    err = cmd_remove_user ();
  else if (poldi_ctrl_opt.cmd_list_users)
    err = cmd_list_users ();

 out:
  
  return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* END. */
