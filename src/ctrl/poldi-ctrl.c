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

#include <config.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <assert.h>

#include <gcrypt.h>

#include "util/optparse.h"
#include "util/support.h"
#include "util/defs.h"
#include "util/util.h"
#include "scd/scd.h"



/* Global flags.  */
struct poldi_ctrl_opt
{
  unsigned int debug; /* debug flags (DBG_foo_VALUE) */
  int cmd_dump;
  int cmd_print_key;
  int cmd_print_serialno;
  int cmd_print_config;
} poldi_ctrl_opt;

/* Set defaults.  */
struct poldi_ctrl_opt poldi_ctrl_opt =
  {
    0,
    0,
    0,
    0,
    0
  };

enum arg_opt_ids
  {
    arg_dump = 'd',
    arg_print_key = 'k',
    arg_print_serialno = 's',
    arg_print_config = 'c',
    arg_debug = 500,
  };

static ARGPARSE_OPTS arg_opts[] =
  {
    /* Commands:  */

    { 300, NULL, 0, "@Commands:\n " },
    { arg_dump,
      "dump",        256, "Dump certain card information"      },
    { arg_print_key,
      "print-key",    256, "Print out authentication key from card"  },
    { arg_print_serialno,
      "print-serialno",    256, "Print out serialno from card"  },
    { arg_print_config,
      "print-config",    256, "Print out Poldi configuration"  },
    /* Options:  */
    { 301, NULL, 0, "@\nOptions:\n " },
    { arg_debug,
      "debug", 256, "Enable debugging mode" },
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

    case 14:
      p = "Copyright (C) 2005, 2007, 2008 g10 Code GmbH";
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

/* Option parser callback for options_parse_argv() and
   options_parse_conf(), which are jnlib wrappers.  */
static gpg_error_t
poldi_ctrl_options_cb (ARGPARSE_ARGS *parg, void *opaque)
{
  gpg_error_t err = 0;

  switch (parg->r_opt)
    {
    case arg_dump:
      poldi_ctrl_opt.cmd_dump = 1;
      break;

    case arg_print_key:
      poldi_ctrl_opt.cmd_print_key = 1;
      break;

    case arg_print_serialno:
      poldi_ctrl_opt.cmd_print_serialno = 1;
      break;

    case arg_print_config:
      poldi_ctrl_opt.cmd_print_config = 1;
      break;

    case arg_debug:
      poldi_ctrl_opt.debug = ~0;
      //poldi_ctrl_opt.verbose = 1;
      break;

    default:
      parg->err = 2;
      break;
    }

  return gpg_error (err);
}



/*
 * Command functions.
 */


static struct scd_cardinfo cardinfo_NULL;



/* Implementation of `dump' command; dumps information from card.  */
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
  //unsigned int version;
  struct scd_cardinfo cardinfo;
  char fpr[41];
  scd_context_t ctx;

  ctx = NULL;
  cardinfo = cardinfo_NULL;
  key_s = NULL;
  //pin = NULL;

  /* Connect.  */

  err = scd_connect (&ctx,
		     getenv ("GPG_AGENT_INFO"),
		     NULL,
		     0);
  if (err)
    {
      log_error ("Error: scd_connect() failed: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Retrieve more card information.  */

  err = scd_learn (ctx, &cardinfo);
  if (err)
    {
      log_error ("Error: scd_learn() failed: %s\n",
		 gpg_strerror (err));
      goto out;
    }

#if 0

  /* FIXME, moritz, dunno wether we still need this with
     gpg-agent.  */

  if (version <= 0x0100)
    {
      /* These cards contain a bug, which makes it necessary to pass
	 CHV3 to the card before reading out the public key.  */

      printf (POLDI_OLD_CARD_KEY_RETRIVAL_EXPLANATION, version);

      pin = getpass (POLDI_PIN3_QUERY_MSG);
      if (! pin)
	{
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

#endif

  /* Retrieve key from card.  */

  err = retrieve_key (ctx, &key_s);
  if (err)
    {
      log_error ("Error: failed to retrieve key from card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  bin2hex (cardinfo.fpr3, 20, fpr);

  printf ("Serial number: %s\n"
	  "Signing key fingerprint: %s\n"
	  "Key:\n%s\n",
	  cardinfo.serialno, fpr, key_s);

 out:

  scd_reset (ctx);

  gcry_free (key_s);
  //free (pin);

  scd_release_cardinfo (cardinfo);
  scd_disconnect (ctx);

  return err;
}

/* Implementation of `print-key' command; dumps information from card.  */
static gpg_error_t
cmd_print_key (void)
{
  char *key_s;
  gpg_error_t err;
  scd_context_t ctx;
  struct scd_cardinfo cardinfo;

  ctx = NULL;
  key_s = NULL;
  cardinfo = cardinfo_NULL;

  /* Connect.  */

  err = scd_connect (&ctx,
		     getenv ("GPG_AGENT_INFO"),
		     NULL,
		     0);
  if (err)
    {
      log_error ("Error: scd_connect() failed: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Init card.  */
  err = scd_learn (ctx, &cardinfo);
  if (err)
    {
      log_error ("Error: scd_learn() failed: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Retrieve key from card.  */

  err = retrieve_key (ctx, &key_s);
  if (err)
    {
      log_error ("Error: failed to retrieve key from card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  printf ("%s", key_s);

 out:

  gcry_free (key_s);

  scd_release_cardinfo (cardinfo);
  scd_disconnect (ctx);

  return err;
}

/* Implementation of `print-serialno' command.  */
static gpg_error_t
cmd_print_serialno (void)
{
  gpg_error_t err;
  scd_context_t ctx;
  struct scd_cardinfo cardinfo;

  ctx = NULL;
  cardinfo = cardinfo_NULL;

  /* Connect.  */

  err = scd_connect (&ctx,
		     getenv ("GPG_AGENT_INFO"),
		     NULL,
		     0);
  if (err)
    {
      log_error ("Error: scd_connect() failed: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Init card.  */
  err = scd_learn (ctx, &cardinfo);
  if (err)
    {
      log_error ("Error: scd_learn() failed: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Retrieve key from card.  */

  printf ("%s\n", cardinfo.serialno);

 out:

  scd_release_cardinfo (cardinfo);
  scd_disconnect (ctx);

  return err;
}

/* Implementation of `print-config' command; dumps general Poldi
   configuration information.  */
static gpg_error_t
cmd_print_config (void)
{
  char *key_s;
  gpg_error_t err;
  scd_context_t ctx;
  struct scd_cardinfo cardinfo;

  ctx = NULL;
  key_s = NULL;
  cardinfo = cardinfo_NULL;

  /* Connect.  */

  err = scd_connect (&ctx,
		     getenv ("GPG_AGENT_INFO"),
		     NULL,
		     0);
  if (err)
    {
      log_error ("Error: scd_connect() failed: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Init card.  */
  err = scd_learn (ctx, &cardinfo);
  if (err)
    {
      log_error ("Error: scd_learn() failed: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Retrieve key from card.  */

  err = retrieve_key (ctx, &key_s);
  if (err)
    {
      log_error ("Error: failed to retrieve key from card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  printf ("%s", key_s);

 out:

  gcry_free (key_s);

  scd_release_cardinfo (cardinfo);
  scd_disconnect (ctx);

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

  /* Initialize Libgcrypt.  */
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

  set_strusage (my_strusage);
  log_set_prefix ("poldi-ctrl", 1);

  /* And finally the argument vector, overwriting values from config
     file.  */
  parsing_stage = 1;
  err = options_parse_argv (poldi_ctrl_options_cb, &parsing_stage,
			    arg_opts, argc, argv, 0);
  if (err)
    {
      log_error ("Error: parsing argument vector (stage: %u) failed: %s\n",
		 parsing_stage, gpg_strerror (err));
      goto out;
    }

  ncommands = (0
	       + poldi_ctrl_opt.cmd_print_key
	       + poldi_ctrl_opt.cmd_print_serialno
	       + poldi_ctrl_opt.cmd_print_config
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

  if (poldi_ctrl_opt.cmd_dump)
    err = cmd_dump ();
  else if (poldi_ctrl_opt.cmd_print_key)
    err = cmd_print_key ();
  else if (poldi_ctrl_opt.cmd_print_serialno)
    err = cmd_print_serialno ();
  else if (poldi_ctrl_opt.cmd_print_config)
    err = cmd_print_config ();

 out:
  
  return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* END */
