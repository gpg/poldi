/* poldi-ctrl.c - Poldi maintaince tool
   Copyright (C) 2004, 2005, 2007, 2008 g10 Code GmbH.
 
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

#include <poldi.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>

#include <gcrypt.h>

#include "util/simpleparse.h"
#include "util/simplelog.h"
#include "util/support.h"
#include "util/defs.h"
#include "util/util.h"
#include "scd/scd.h"

/* We use the Libgcrypt memory allocator. */
#define xtrymalloc(n)        gcry_malloc(n)
#define xtrymalloc_secure(n) gcry_malloc_secure(n)
#define xtrystrdup(p)        gcry_strdup(p)
#define xtryrealloc(p,n)     gcry_realloc(p,n)
#define xfree(p)             gcry_free(p)



/* Global flags.  */
struct poldi_ctrl_opt
{
  int cmd_dump;
  int cmd_print_key;
  int cmd_print_serialno;
} poldi_ctrl_opt;

/* Handle for simplelog subsystem. */
static log_handle_t loghandle;

/* Handle for scd access subsystem.  */
static scd_context_t scd_ctx;

/* Struct holding card info. */
static struct scd_cardinfo scd_cardinfo;

/* Set defaults.  */
struct poldi_ctrl_opt poldi_ctrl_opt =
  {
    0,
    0,
    0
  };

enum opt_ids
  {
    opt_none,
    opt_dump,
    opt_print_key,
    opt_print_serialno,
    opt_debug
  };

static simpleparse_opt_spec_t opt_specs[] =
  {
    /* Commands:  */
    { opt_dump, "dump",
      'd', SIMPLEPARSE_ARG_NONE, 0, N_("Dump certain card information") },
    { opt_print_key, "print-key",
      'k', SIMPLEPARSE_ARG_NONE, 0, N_("Print authentication key from card") },
    { opt_print_serialno, "print-serialno",
      's', SIMPLEPARSE_ARG_NONE, 0, N_("Print serial number from card") },

    /* Options:  */
    { opt_debug, "debug",
      0, SIMPLEPARSE_ARG_NONE, 0, N_("Enable debugging mode") },
    { 0 }
  };



/* Callback for parsing of command-line arguments. */
static gpg_error_t
poldi_ctrl_options_cb (void *cookie,
		       simpleparse_opt_spec_t spec, const char *arg)
{
  if (spec.id == opt_dump)
    poldi_ctrl_opt.cmd_dump = 1;
  else if (spec.id == opt_print_key)
    poldi_ctrl_opt.cmd_print_key = 1;
  else if (spec.id == opt_print_serialno)
    poldi_ctrl_opt.cmd_print_serialno = 1;
  else if (spec.id == opt_debug)
    log_set_min_level (loghandle, LOG_LEVEL_DEBUG);

  return 0;
}



/*
 * Command functions.
 */




/* Retrieve authentication key from card through the SCDaemon context
   CTX and store it as a S-Expression c-string in *KEY_STRING.
   Returns proper error code. */
static gpg_error_t
retrieve_key (scd_context_t ctx, char **key_string)
{
  gcry_sexp_t key;
  char *key_s;
  gpg_error_t err;

  *key_string = NULL;
  key = NULL;
  key_s = NULL;

  /* Retrieve key from card.  */
  err = scd_readkey (ctx, "OPENPGP.3", &key);
  if (err)
    {
      log_msg_error (loghandle,
		     "failed to retrieve key from card: %s",
		     gpg_strerror (err));
      goto out;
    }

  /* Convert key into a string.  */
  err = sexp_to_string (key, &key_s);
  if (err)
    {
      log_msg_error (loghandle,
		     "failed to convert key S-Expression "
		     "into C-String: %s",
		     gpg_strerror (err));
      goto out;
    }

  *key_string = key_s;

 out:

  gcry_sexp_release (key);

  return err;
}

/* Implementation of `dump' command; dumps information from card.  */
static gpg_error_t
cmd_dump (void)
{
  char *key_s;
  gpg_error_t err;
  char fpr[41];

  key_s = NULL;

  /* Retrieve key from card.  */

  err = retrieve_key (scd_ctx, &key_s);
  if (err)
    {
      log_msg_error (loghandle, "failed to retrieve key from card: %s",
		     gpg_strerror (err));
      goto out;
    }

  bin2hex (scd_cardinfo.fpr3, 20, fpr);

  printf ("Serial number: %s\n"
	  "Signing key fingerprint: %s\n"
	  "Key:\n%s\n",
	  scd_cardinfo.serialno, fpr, key_s);

 out:

  gcry_free (key_s);

  return err;
}

/* Implementation of `print-key' command; dumps information from card.  */
static gpg_error_t
cmd_print_key (void)
{
  char *key_s;
  gpg_error_t err;

  key_s = NULL;

  /* Retrieve key from card.  */

  err = retrieve_key (scd_ctx, &key_s);
  if (err)
    {
      log_msg_error (loghandle, "failed to retrieve key from card: %s",
		     gpg_strerror (err));
      goto out;
    }

  printf ("%s", key_s);

 out:

  gcry_free (key_s);

  return err;
}

/* Implementation of `print-serialno' command.  */
static gpg_error_t
cmd_print_serialno (void)
{
  printf ("%s\n", scd_cardinfo.serialno);
  return 0;
}

static const char *
i18n_cb (void *cookie, const char *msg)
{
  return _(msg);
}

/* Main.  */
int
main (int argc, const char **argv)
{
  simpleparse_handle_t parsehandle;
  unsigned int ncommands;
  gpg_error_t err;

  /** Initialize.  **/

  assert (argc > 0);

  /* I18n. */
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

  /* Initialize logging. */

  err = log_create (&loghandle);
  if (err)
    {
      fprintf (stderr, _("failed to initialize logging: %s\n"),
	       gpg_strerror (err));
      exit (1);
    }

  err = log_set_backend_stream (loghandle, stderr);
  if (err)
    {
      fprintf (stderr, _("failed to set logging backend: %s\n"),
	       gpg_strerror (err));
      exit (1);
    }

  log_set_prefix (loghandle, "poldi-ctrl:");
  log_set_flags (loghandle, LOG_FLAG_WITH_PREFIX);

  /* Parse arguments. */

  err = simpleparse_create (&parsehandle);
  if (err)
    goto out;

  simpleparse_set_loghandle (parsehandle, loghandle);
  simpleparse_set_streams (parsehandle, stdout, stderr);
  simpleparse_set_parse_cb (parsehandle, poldi_ctrl_options_cb, NULL);
  simpleparse_set_i18n_cb (parsehandle, i18n_cb, NULL);
  err = simpleparse_set_specs (parsehandle, opt_specs);
  if (err)
    goto out;

  simpleparse_set_name (parsehandle, "poldi-ctrl");
  simpleparse_set_package (parsehandle, "Poldi");
  simpleparse_set_version (parsehandle, PACKAGE_VERSION);
  simpleparse_set_bugaddress (parsehandle, PACKAGE_BUGREPORT);
  simpleparse_set_description (parsehandle, "Command line utility for Poldi");
  simpleparse_set_copyright (parsehandle,
			     "Copyright (C) 2008 g10 Code GmbH\n"
			     "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
			     "This is free software: you are free to change and redistribute it.\n"
			     "There is NO WARRANTY, to the extent permitted by law.");

  /* Parse command-line arguments.  */
  err = simpleparse_parse (parsehandle, 0, argc - 1, argv + 1, NULL);
  /* This causes compiler warning, who is correct? */
  if (err)
    {
      log_msg_error (loghandle,
		     _("parsing argument vector failed: %s"),
		     gpg_strerror (err));
      goto out;
    }

  ncommands = (0
	       + poldi_ctrl_opt.cmd_print_key
	       + poldi_ctrl_opt.cmd_print_serialno
	       + poldi_ctrl_opt.cmd_dump);
  if (ncommands > 1)
    {
      log_msg_error (loghandle,
		     _("more than one command specified (try --help)"));
      goto out;
    }
  else if (! ncommands)
    {
      log_msg_error (loghandle, _("no command specified (try --help)"));
      goto out;
    }

  /* Connect to scdaemon. */

  err = scd_connect (&scd_ctx, NULL, getenv ("GPG_AGENT_INFO"),
		     NULL, NULL, 0, loghandle);
  if (err)
    {
      log_msg_error (loghandle, _("failed to connect to scdaemon: %s"),
		     gpg_strerror (err));
      goto out;
    }

  err = scd_learn (scd_ctx, &scd_cardinfo);
  if (err)
    {
      log_msg_error (loghandle,
		     _("failed to retrieve smartcard data: %s"),
		     gpg_strerror (err));
      goto out;
    }

  if (poldi_ctrl_opt.cmd_dump)
    err = cmd_dump ();
  else if (poldi_ctrl_opt.cmd_print_key)
    err = cmd_print_key ();
  else if (poldi_ctrl_opt.cmd_print_serialno)
    err = cmd_print_serialno ();

 out:

  if (parsehandle)
    simpleparse_destroy (parsehandle);
  if (scd_ctx)
    scd_disconnect (scd_ctx);
  scd_release_cardinfo (scd_cardinfo);
  
  return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* END */
