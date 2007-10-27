/* pam_poldi.c - PAM authentication via OpenPGP smartcards.
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
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include <gcrypt.h>

#include <jnlib/xmalloc.h>
#include <jnlib/logging.h>

#include <common/support.h>
#include <common/optparse.h>
#include <common/defs.h>
#include <common/usersdb.h>

#include <scd/poldi-scd.h>

#include "common/poldi-ctx.h"

#include "wait-for-card.h"
#include "getpin-cb.h"
#include "conv.h"



/* Macros.  */



/* Option structure layout.  */
struct pam_poldi_opt
{
  const char *logfile;
  unsigned int wait_timeout;
};

static struct poldi_ctx_s poldi_ctx_NULL;

/* Option IDs.  */
enum arg_opt_ids
  {
    arg_logfile = 500,
    arg_wait_timeout
  };

/* Option specifications. */
static ARGPARSE_OPTS arg_opts[] =
  {
    { arg_logfile,
      "log-file", 2, "Specify file to use for logging" },
    { arg_wait_timeout,
      "wait-timeout", 1, "|SEC|Specify timeout for waiting" },
    { 0 }
  };

/* Option parser callback.  */
static gpg_error_t
pam_poldi_options_cb (ARGPARSE_ARGS *parg, void *opaque)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  poldi_ctx_t ctx = opaque;

  switch (parg->r_opt)
    {
    case arg_logfile:
      ctx->logfile = xstrdup (parg->r.ret_str);
      break;

    case arg_wait_timeout:
      ctx->wait_timeout = parg->r.ret_int;
      break;

    default:
      err = GPG_ERR_INTERNAL;	/* FIXME?  */
      break;
    }

  return gpg_error (err);
}



/*
 * PAM user interaction through PAM conversation functions.
 */



/*
 * Helper functions.
 */

/* This function parses the PAM argument vector ARGV of size ARGV */
static gpg_error_t
parse_argv (int argc, const char **argv)
{
  gpg_error_t err;
  //  unsigned int i;

  err = 0;
#if 0
  for (i = 0; i < argc; i++)
    {
      if (! strcmp (argv[i], "debug"))
	{
	  /* Handle "debug" option.  */
	  pam_poldi_opt.debug = ~0;
	  pam_poldi_opt.verbose = 1;
	}
      else if (! strncmp (argv[i], "timeout=", 8))
	/* Handle "timeout=" option.  */
	pam_poldi_opt.wait_timeout = atoi (argv[i] + 8);
      else
	{
	  log_error ("Error: Unknown PAM argument: %s", argv[i]);
	  err = gpg_error (GPG_ERR_UNKNOWN_NAME);
	}

      if (err)
	break;
    }
#endif

  return err;
}



/*
 * PAM interface.
 */

static struct scd_cardinfo cardinfo_null;

/* Uaaahahahh, ich will dir einloggen!  PAM authentication entry
   point.  */
PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pam_handle,
		     int flags, int argc, const char **argv)
{
  unsigned char *challenge;
  unsigned char *response;
  size_t challenge_n;
  size_t response_n;
  const void *conv_void;
  gcry_sexp_t key;
  gpg_error_t err;
  const void *username_void;
  const char *username;
  char *account;
  int ret;
  struct scd_cardinfo cardinfo;
  poldi_ctx_t ctx;

  challenge = NULL;
  response = NULL;
  cardinfo = cardinfo_null;
  username = NULL;
  account = NULL;
  key = NULL;
  ctx = NULL;

  /* Initialize Libgcrypt.  */

  /* Disable secure memory for now; because of priviledge dropping,
     enable this causes the following error:

     su: Authentication service cannot retrieve authentication
     info. */
  
  //gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  gcry_control (GCRYCTL_DISABLE_SECMEM);

  /* Create main context.  */

  ctx = malloc (sizeof (*ctx));
  if (!ctx)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  *ctx = poldi_ctx_NULL;

  ctx->pam_handle = pam_handle;

  err = poldi_scd_connect (ctx, getenv ("GPG_AGENT_INFO"), NULL, 0);
  if (err)
    {
      log_error ("Error: scd_connect() failed: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Parse options.  */
  err = options_parse_conf  (pam_poldi_options_cb, ctx,
			     arg_opts, POLDI_CONF_FILE);
  if (err)
    {
      log_error ("Error: failed to parse configuration file: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Parse argument vector provided by PAM.  */
  err = parse_argv (argc, argv);
  if (err)
    {
      log_error ("Error: failed to parse PAM argument vector: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Initialize logging: in case `logfile' has been set in the
     configuration file, initialize jnlib-logging the traditional
     file, loggin to the file (or socket special file) specified in
     the configuration file; in case `logfile' has NOT been set in the
     configuration file, log through Syslog.  */

  if (ctx->logfile)
    {
      log_set_file (ctx->logfile);
      if (! strcmp (ctx->logfile, "-"))
	/* We need to disable bufferring on stderr, since it might
	   have been enabled by log_set_file().  Buffering on stderr
	   will complicate PAM interaction, since e.g. libpam-misc's
	   misc_conv() function does expect stderr to be
	   unbuffered.  */
	setvbuf (stderr, NULL, _IONBF, 0);
    }
  else
    log_set_syslog ();

  log_set_prefix ("[Poldi] ",
		  JNLIB_LOG_WITH_PREFIX | JNLIB_LOG_WITH_TIME | JNLIB_LOG_WITH_PID);

  /*
   * Retrieve information from PAM.
   */

  /* Ask PAM for username.  */
  ret = pam_get_item (pam_handle, PAM_USER, &username_void);
  if (ret != PAM_SUCCESS)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      goto out;
    }
  username = username_void;

  /* Ask PAM for conv structure.  */
  ret = pam_get_item (pam_handle, PAM_CONV, &conv_void);
  if (ret != PAM_SUCCESS)
    {
      log_error ("Failed to retrieve conversation structure");
      err = GPG_ERR_INTERNAL;
      goto out;
    }
  ctx->pam_conv = conv_void;

  /*
   * Process authentication request.
   */

  /* Wait for card.  */
  err = wait_for_card (ctx, ctx->wait_timeout);
  if (err)
    goto out;

  err = poldi_scd_learn (ctx, &cardinfo);
  if (err)
    goto out;

  if (! username)
    {
      /* We didn't receive a username from PAM, therefore we need to
	 figure it out somehow...  */

      err = usersdb_lookup_by_serialno (cardinfo.serialno, &account);
      if (gcry_err_code (err) == GPG_ERR_AMBIGUOUS_NAME)
	err = conv_ask (ctx, 0, &account, "Need to figure out username: ");

      if (err)
	goto out;

      username = account;
    }

  /* FIXME: quiet?  */
  conv_tell (ctx, "Trying authentication as user `%s'...", username);

  /* Check if the given account is associated with the serial
     number.  */
  err = usersdb_check (cardinfo.serialno, username);
  if (err)
    {
      conv_tell (ctx, "Serial no %s is not associated with %s\n",
		 cardinfo.serialno, username);
      err = gcry_error (GPG_ERR_INV_NAME);
      goto out;
    }

  /* Retrieve key belonging to card.  */
  err = key_lookup_by_serialno (cardinfo.serialno, &key);
  if (err)
    goto out;

  /* Inform user about inserted card.  */

  err = conv_tell (ctx, "Serial no: %s", cardinfo.serialno);
  if (err)
    {
      /* FIXME?? do we need this?  */
      log_error ("Error: failed to inform user about inserted card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Generate challenge.  */
  err = challenge_generate (&challenge, &challenge_n);
  if (err)
    {
      log_error ("Error: failed to generate challenge: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Let card sign the challenge.  */
  err = poldi_scd_pksign (ctx, "OPENPGP.3",
			  getpin_cb, ctx,
			  challenge, challenge_n,
			  &response, &response_n);
  if (err)
    {
      log_error ("Error: failed to retrieve challenge signature "
		 "from card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Verify response.  */
  err = challenge_verify (key, challenge, challenge_n, response, response_n);
  if (err)
    {
      log_error ("Error: failed to verify challenge\n");
      goto out;
    }

  if (username == account)
    {
      /* Make username available to application.  */
      ret = pam_set_item (pam_handle, PAM_USER, username);
      if (ret != PAM_SUCCESS)
	{
	  err = gpg_error (GPG_ERR_INTERNAL);
	  goto out;
	}
    }

  /* Done.  */

 out:

  /* Release resources.  */
  gcry_sexp_release (key);
  poldi_scd_release_cardinfo (&cardinfo);
  if (username == account)
    free (account);

  /* Log result.  */
  if (err)
    log_error ("Failure: %s\n", gpg_strerror (err));
  else
    log_info ("Success\n");

  log_close ();

  poldi_scd_disconnect (ctx);
  free (challenge);
  free (response);

  /* Deallocate main context.  */
  free (ctx);

  /* Return to PAM.  */

  return err ? PAM_AUTH_ERR : PAM_SUCCESS;
}


/* PAM's `set-credentials' interface.  */
PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pam_handle,
		int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

/* END */
