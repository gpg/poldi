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
#include <jnlib/stringhelp.h>
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
  int fake_wait_for_card;
  int require_card_switch;
  int cmd_test;
  int cmd_dump;
  int cmd_dump_shadowed_key;
  int cmd_set_key;
  int cmd_show_key;
  int cmd_add_user;
  int cmd_remove_user;
  int cmd_list_users;
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
    0,
    0
  };

enum arg_opt_ids
  {
    arg_test = 't',
    arg_dump = 'd',
    arg_dump_shadowed_key = 'D',
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
    arg_fake_wait_for_card,
    arg_require_card_switch
  };

static ARGPARSE_OPTS arg_opts[] =
  {
    { arg_debug,
      "debug", 256, "Enable debugging mode" },
    { arg_test,
      "test",        256, "Test authentication"                },
    { arg_dump,
      "dump",        256, "Dump certain card information"      },
    { arg_dump_shadowed_key,
      "dump-shadowed-key", 256, "Dump shadowed key from card"  },
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
    { arg_config_file,
      "config-file",   2, "|FILE|Specify configuration file"   },
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
    { arg_fake_wait_for_card,
      "fake-wait-for-card", 0, "Fake wait-for-card feature"    },
    { arg_require_card_switch,
      "require-card-switch", 0, "Require re-insertion of card" },
    { 0,
      NULL,            0, NULL                                 }
  };

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
      p = "Usage: poldi-ctrl [options] [command]";
      break;
    case 41:
      p = "Syntax: poldi-ctrl [options] [command]\n";
      break;

    default:
      p = NULL;
    }

  return p;
}

static gpg_error_t
poldi_ctrl_options_cb (ARGPARSE_ARGS *parg, void *opaque)
{
  int parsing_stage = *((int *) opaque);
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

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

    case arg_dump_shadowed_key:
      if (parsing_stage)
	poldi_ctrl_opt.cmd_dump_shadowed_key = 1;
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

    case arg_fake_wait_for_card:
      if (parsing_stage)
	poldi_ctrl_opt.fake_wait_for_card = 1;
      break;

    case arg_require_card_switch:
      if (parsing_stage)
	poldi_ctrl_opt.require_card_switch = 1;
      break;

    default:
      parg->err = 2;
      break;
    }

  return gpg_error (err);
}

static gpg_error_t
cmd_test (void)
{
  unsigned char *challenge;
  unsigned char *signature;
  size_t challenge_n;
  size_t signature_n;
  gpg_error_t err;
  int slot;
  char *serialno;
  char *account;
  char *pin;
  struct passwd *pwent;
  char *key_path;
  gcry_sexp_t key_sexp;
  char *key_string;
  unsigned int version;

  slot = -1;
  pin = NULL;
  key_path = NULL;
  key_sexp = NULL;
  key_string = NULL;
  account = NULL;
  challenge = NULL;
  signature = NULL;
  serialno = NULL;
  version = 0;

  err = challenge_generate (&challenge, &challenge_n);
  if (err)
    goto out;

  err = card_open (NULL, &slot);
  if (err)
    goto out;

  if (poldi_ctrl_opt.fake_wait_for_card)
    {
      printf ("Press ENTER when card is available...\n");
      getchar ();
    }
  else
    printf ("Waiting for card...\n");
  err = card_init (slot,
		   !poldi_ctrl_opt.fake_wait_for_card,
		   0,
		   poldi_ctrl_opt.require_card_switch);
  if (err)
    goto out;

  err = card_info (slot, &serialno, &version, NULL);
  if (err)
    goto out;

  printf ("Serial No: %s\n", serialno);
  printf ("Card version: %u\n", version);

  err = usersdb_lookup_by_serialno (serialno, &account);
  if (err)
    goto out;

  printf ("Account: %s\n", account);

  pwent = getpwnam (account);
  if (! pwent)
    {
      err = gpg_error (GPG_ERR_INTERNAL);	/* FIXME */
      goto out;
    }

  key_path = make_filename (POLDI_KEY_DIRECTORY, serialno, NULL);
  err = file_to_string (key_path, &key_string);
  if ((! err) && (! key_string))
    err = gpg_error (GPG_ERR_NO_PUBKEY);
  if (err)
    goto out;

  err = string_to_sexp (&key_sexp, key_string);
  if (err)
    goto out;

  /* FIXME?  */
  pin = getpass (POLDI_PIN2_QUERY_MSG);
  if (! pin)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  err = card_pin_provide (slot, 2, pin);
  if (err)
    goto out;

  err = card_sign (slot, challenge, challenge_n, &signature, &signature_n);
  if (err)
    goto out;

  card_close (slot);
  slot = -1;

  err = challenge_verify (key_sexp,
			  challenge, challenge_n, signature, signature_n);
  if (err)
    printf ("Authentication failed (%s)\n", gpg_strerror (err));
  else
    printf ("Authentication succeeded\n");

 out:

  if (slot != -1)
    card_close (slot);
  free (account);
  free (pin);
  free (serialno);
  free (key_string);
  free (key_path);
  gcry_sexp_release (key_sexp);

  return err;
}

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

  err = card_open (NULL, &slot);
  if (err)
    goto out;

  err = card_init (slot, 0, 0, 0);
  if (err)
    goto out;

  err = card_info (slot, &serialno, &version, NULL);
  if (err)
    goto out;

  if (version <= 0x0100)
    {
      /* These cards contain a bug, which makes it necessary to pass
	 CHV3 to the card before reading out the public key.  */

      printf (POLDI_OLD_CARD_KEY_RETRIVAL_EXPLANATION, version);

      pin = getpass (POLDI_PIN3_QUERY_MSG);

      err = card_pin_provide (slot, 3, pin);
      if (err)
	goto out;
    }

  err = card_read_key (slot, &key);
  if (err)
    goto out;

  err = sexp_to_string (key, &key_s);
  if (err)
    goto out;

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

static gpg_error_t
cmd_dump_shadowed_key (void)
{
  gcry_sexp_t key_public;
  gcry_sexp_t key_shadowed;
  gcry_sexp_t value_pair;
  char *key_s;
  gcry_mpi_t mpi_n;
  gcry_mpi_t mpi_e;
  gpg_error_t err;
  int slot;
  char *pin;
  char key_grip[41];
  unsigned char key_grip_raw[20];
  unsigned int i;

  slot = -1;
  key_public = NULL;
  key_shadowed = NULL;
  value_pair = NULL;
  mpi_n = NULL;
  mpi_e = NULL;
  key_s = NULL;

  pin = getpass (POLDI_PIN3_QUERY_MSG);

  err = card_open (NULL, &slot);
  if (err)
    goto out;

  err = card_init (slot, 0, 0, 0);
  if (err)
    goto out;

  err = card_pin_provide (slot, 3, pin);
  if (err)
    goto out;

  err = card_read_key (slot, &key_public);
  if (err)
    goto out;

  value_pair = gcry_sexp_find_token (key_public, "n", 0);
  if (! value_pair)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }
  mpi_n = gcry_sexp_nth_mpi (value_pair, 1, GCRYMPI_FMT_USG);
  if (! mpi_n)
    {
      err = gpg_error (GPG_ERR_INTERNAL); /* FIXME? */
      goto out;
    }

  gcry_sexp_release (value_pair);
  value_pair = gcry_sexp_find_token (key_public, "e", 0);
  if (! value_pair)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }
  mpi_e = gcry_sexp_nth_mpi (value_pair, 1, GCRYMPI_FMT_USG);
  if (! mpi_e)
    {
      err = gpg_error (GPG_ERR_INTERNAL); /* FIXME? */
      goto out;
    }

  err = gcry_sexp_build (&key_shadowed, NULL,
			 "(shadowed-private-key"
			 " (rsa"
			 "  (n %m)"
			 "  (e %m)))",
			 mpi_n, mpi_e);
  if (err)
    goto out;

  err = sexp_to_string (key_shadowed, &key_s);
  if (err)
    goto out;

  gcry_pk_get_keygrip (key_public, key_grip_raw);
  for (i = 0; i < 20; i++)
    sprintf (key_grip + 2 * i, "%02X", key_grip_raw[i]);

  printf ("Key grip:\n%s\n", key_grip);
  printf ("Key:\n%s\n", key_s);

 out:

  gcry_mpi_release (mpi_n);
  gcry_mpi_release (mpi_e);
  gcry_sexp_release (value_pair);

  if (slot != -1)
    card_close (slot);
  gcry_sexp_release (key_public);
  gcry_sexp_release (key_shadowed);
  gcry_free (key_s);
  free (pin);

  return err;
}

static gpg_error_t
cmd_list_users (void)
{
  char users_file[] = POLDI_USERS_DB_FILE;
  FILE *users_file_fp;
  gpg_error_t err;
  char *line;
  size_t line_n;
  char *serialno;
  char *account;
  int ret;
  char delimiters[] = "\t\n ";

  line = NULL;

  users_file_fp = fopen (users_file, "r");
  if (! users_file_fp)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  while (1)
    {
      free (line);
      line = NULL;

      ret = getline (&line, &line_n, users_file_fp);
      if (ret == -1)
	{
	  err = gpg_error_from_errno (errno);
	  break;
	}

      serialno = strtok (line, delimiters);
      if (! serialno)
	{
	  err = gpg_error (GPG_ERR_INTERNAL); /* FIXME?  */
	  break;
	}
      account = strtok (NULL, delimiters);
      if (! account)
	{
	  err = gpg_error (GPG_ERR_INTERNAL); /* FIXME?  */
	  break;
	}
      

      printf ("Account: %s; Serial No: %s\n", account, serialno);
    }

 out:

  free (line);
  if (users_file_fp)
    fclose (users_file_fp);	/* FIXME?  */

  return err;
}

static gpg_error_t
key_file_create (const char *account, const char *serialno)
{
  struct passwd *pwent;
  struct stat statbuf;
  gpg_error_t err;
  char *path;
  int ret;
  int fd;

  path = NULL;
  
  pwent = getpwnam (account);
  if (! pwent)
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto out;
    }

  path = make_filename (POLDI_KEY_DIRECTORY, serialno, NULL);
  fd = open (path, O_WRONLY | O_CREAT, 0644);
  if (fd == -1)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  ret = close (fd);
  if (ret == -1)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  ret = stat (path, &statbuf);
  if (ret == -1)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  ret = chown (path, pwent->pw_uid, statbuf.st_gid);
  if (ret == -1)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  err = 0;

 out:

  free (path);

  return err;
}

static gpg_error_t
key_file_remove (const char *serialno)
{
  gpg_error_t err;
  char *path;
  int ret;

  path = make_filename (POLDI_KEY_DIRECTORY, serialno, NULL);

  ret = unlink (path);
  if ((ret == -1) && (errno != ENOENT))
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  err = 0;

 out:

  free (path);

  return err;
}

static gpg_error_t
cmd_add_user (void)
{
  struct passwd *pwent;
  gpg_error_t err;
  char *serialno;
  char *account;

  serialno = poldi_ctrl_opt.serialno;
  account = poldi_ctrl_opt.account;

  if (! (serialno && account))
    {
      fprintf (stderr, "Error: Serial number and accounts needs to be given.\n");
      exit (EXIT_FAILURE);
    }

  pwent = getpwnam (account);
  if (! pwent)
    {
      fprintf (stderr, "Error: Unknown user `%s'.\n", account);
      exit (EXIT_FAILURE);
    }

  err = usersdb_lookup_by_serialno (serialno, NULL);
  if (! err)
    {
      fprintf (stderr, "Error: Serial number does already exist in database.\n");
      exit (EXIT_FAILURE);
    }

  err = usersdb_add_entry (account, serialno);
  if (err)
    goto out;

  err = key_file_create (account, serialno);
  if (err)
    goto out;

 out:

  return err;
}

static gpg_error_t
cmd_remove_user (void)
{
  gpg_error_t err;
  char *serialno;

  if (poldi_ctrl_opt.serialno)
    serialno = poldi_ctrl_opt.serialno;
  else if (poldi_ctrl_opt.account)
    {
      serialno = NULL;
      err = usersdb_lookup_by_username (poldi_ctrl_opt.account, &serialno);
      if (err)
	goto out;
    }
  else
    {
      fprintf (stderr, "Error: Account or Serial number needs to be given.\n");
      exit (EXIT_FAILURE);
    }

  err = usersdb_remove_entry (poldi_ctrl_opt.account, serialno);
  if (err)
    goto out;

  err = key_file_remove (serialno);
  if (err)
    goto out;

 out:

  if (serialno != poldi_ctrl_opt.serialno)
    free (serialno);

  return err;
}



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

  err = card_open (NULL, &slot);
  if (err)
    goto out;

  err = card_init (slot, 0, 0, 0);
  if (err)
    goto out;

  err = card_info (slot, &serialno, &version, NULL);
  if (err)
    goto out;

  path = make_filename (POLDI_KEY_DIRECTORY, serialno, NULL);

  if (version <= 0x0100)
    {
      /* These cards contain a bug, which makes it necessary to pass
	 CHV3 to the card before reading out the public key.  */

      printf (POLDI_OLD_CARD_KEY_RETRIVAL_EXPLANATION, version);

      pin = getpass (POLDI_PIN3_QUERY_MSG);

      err = card_pin_provide (slot, 3, pin);
      if (err)
	goto out;
    }

  err = card_read_key (slot, &key_sexp);
  if (err)
    goto out;

  card_close (slot);
  slot = -1;

  err = sexp_to_string (key_sexp, &key_string);
  if (err)
    goto out;
  
  path_fp = fopen (path, "w");
  if (! path_fp)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  fprintf (path_fp, "%s", key_string);

  ret = fclose (path_fp);
  path_fp = NULL;
  if (ret)
    {
      err = gpg_error_from_errno (errno);
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

static gpg_error_t
cmd_show_key (void)
{
  gpg_error_t err;
  char *path;
  char *key_string;
  uid_t uid;
  struct passwd *pwent;
  char *serialno;

  path = NULL;
  serialno = NULL;
  key_string = NULL;

  uid = getuid ();
  pwent = getpwuid (uid);
  if (! pwent)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      goto out;
    }

  err = usersdb_lookup_by_username (pwent->pw_name, &serialno);
  if (err)
    goto out;

  path = make_filename (POLDI_KEY_DIRECTORY, serialno, NULL);
  err = file_to_string (path, &key_string);
  if (err)
    goto out;

  if (key_string)
    printf ("%s", key_string);

 out:

  free (path);
  free (key_string);
  free (serialno);

  return err;
}


int
main (int argc, char **argv)
{
  int parsing_stage = 0;
  gpg_error_t err;

  set_strusage (my_strusage);
  log_set_prefix ("poldi-ctrl", 1); /* ? */

  err = options_parse_argv (poldi_ctrl_options_cb, &parsing_stage,
			    arg_opts, argc, argv);
  if (err)
    goto out;

  parsing_stage++;
  err = options_parse_conf (poldi_ctrl_options_cb, &parsing_stage,
			    arg_opts, poldi_ctrl_opt.config_file);
  if (err)
    goto out;

  parsing_stage++;
  err = options_parse_argv (poldi_ctrl_options_cb, &parsing_stage,
			    arg_opts, argc, argv);
  if (err)
    goto out;

  scd_init (poldi_ctrl_opt.debug,
	    poldi_ctrl_opt.debug_sc,
	    poldi_ctrl_opt.verbose,
	    poldi_ctrl_opt.ctapi_driver,
	    poldi_ctrl_opt.reader_port,
	    poldi_ctrl_opt.pcsc_driver,
	    poldi_ctrl_opt.disable_opensc,
	    poldi_ctrl_opt.disable_ccid,
	    poldi_ctrl_opt.debug_ccid_driver);

  if ((0
       + (poldi_ctrl_opt.cmd_test)
       + (poldi_ctrl_opt.cmd_set_key)
       + (poldi_ctrl_opt.cmd_show_key)
       + (poldi_ctrl_opt.cmd_add_user)
       + (poldi_ctrl_opt.cmd_remove_user)
       + (poldi_ctrl_opt.cmd_list_users)
       + (poldi_ctrl_opt.cmd_dump)
       + (poldi_ctrl_opt.cmd_dump_shadowed_key)) != 1)
    {
      fprintf (stderr, "Error: no command given (try --help).\n");
      exit (EXIT_FAILURE);
    }

  if (poldi_ctrl_opt.cmd_test)
    err = cmd_test ();
  else if (poldi_ctrl_opt.cmd_dump)
    err = cmd_dump ();
  else if (poldi_ctrl_opt.cmd_dump_shadowed_key)
    err = cmd_dump_shadowed_key ();
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
  
  if (err)
    {
      fprintf (stderr, "Error: %s\n", gpg_strerror (err));
      exit (1);
    }

  return 0;
}
