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
#include "auth-methods.h"



/* Auth methods declarations. */

#ifdef ENABLE_AUTH_METHOD_SIMPLEDB
int auth_method_simpledb (poldi_ctx_t ctx);
#endif
#ifdef ENABLE_AUTH_METHOD_X509
int auth_method_x509 (poldi_ctx_t ctx);
#endif
#ifdef ENABLE_AUTH_METHOD_TEST
int auth_method_test (poldi_ctx_t ctx);
#endif




/* Auth methods list.  */

struct auth_method
{
  unsigned int id;
  const char *name;
  auth_method_func_t func;
};

/* CAREFUL: Make sure to hold synchronized with enum list in
   auth-methods.h!  */
static struct auth_method auth_methods[] =
  {
#ifdef ENABLE_AUTH_METHOD_SIMPLEDB
    { AUTH_METHOD_SIMPLEDB, "simpledb", auth_method_simpledb },
#endif
#ifdef ENABLE_AUTH_METHOD_X509
    { AUTH_METHOD_X509, "x509", &auth_method_x509 },
#endif
#ifdef ENABLE_AUTH_METHOD_TEST
    { AUTH_METHOD_TEST, "test", &auth_method_test },
#endif
    { AUTH_METHOD_NONE, NULL, NULL }
  };



/* Macros.  */



static struct poldi_ctx_s poldi_ctx_NULL;

/* Option IDs.  */
enum arg_opt_ids
  {
    arg_logfile = 500,
    arg_auth_method,
    arg_wait_timeout,
    arg_debug
  };

/* Option specifications. */
static ARGPARSE_OPTS arg_opts[] =
  {
    { arg_logfile,
      "log-file", 2, "Specify file to use for logging" },
    { arg_auth_method,
      "auth-method", 2, "|NAME|Specify authentication method" },
    { arg_wait_timeout,
      "wait-timeout", 1, "|SEC|Specify timeout for waiting" },
    { arg_debug,
      "debug", 256, "Enable debugging messages" },
    { 0 }
  };

static struct auth_method
auth_method_lookup (const char *name)
{
  int i;

  for (i = 0; auth_methods[i].name; i++)
    if (strcmp (auth_methods[i].name, name) == 0)
      return auth_methods[i];

  return auth_methods[i];
}

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

    case arg_auth_method:
      {
	struct auth_method method = auth_method_lookup (parg->r.ret_str);
	if (method.id == AUTH_METHOD_NONE)
	  err = GPG_ERR_GENERAL; /* FIXME!! */
	else
	  ctx->auth_method = method.id;
      }
      break;

    case arg_debug:
      ctx->debug = 1;
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
 * PAM interface.
 */

/* Uaaahahahh, ich will dir einloggen!  PAM authentication entry
   point.  */
PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pam_handle,
		     int flags, int argc, const char **argv)
{
  const void *conv_void;
  gpg_error_t err; 
  poldi_ctx_t ctx;
  int ret;

  ctx = NULL;
  err = 0;

  /*** Initialize Libgcrypt.  ***/

  /* Disable secure memory for now; because of priviledge dropping,
     enable this causes the following error:

     su: Authentication service cannot retrieve authentication
     info. */
  gcry_control (GCRYCTL_DISABLE_SECMEM);

  /*** Setup main context.  ***/

  ctx = malloc (sizeof (*ctx));
  if (!ctx)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  *ctx = poldi_ctx_NULL;

  ctx->auth_method = AUTH_METHOD_NONE;
  ctx->pam_handle = pam_handle;

  /*** Parse options.  ***/

  /* ... from configuration file. */
  err = options_parse_conf  (pam_poldi_options_cb, ctx,
			     arg_opts, POLDI_CONF_FILE);
  if (err)
    {
      log_error ("Error: failed to parse configuration file: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* ... from argument vector provided by PAM. */
  if (argc)
    {
      err = options_parse_argv_const (pam_poldi_options_cb,
				      ctx, arg_opts, argc, argv,
				      OPTPARSE_FLAG_DONT_SKIP_FIRST);
      if (err)
	{
	  log_error ("Error: failed to parse PAM argument vector: %s\n",
		     gpg_strerror (err));
	  goto out;
	}
    }

  /*** Initialize logging. ***/

  /* In case `logfile' has been set in the configuration file,
     initialize jnlib-logging the traditional file, loggin to the file
     (or socket special file) specified in the configuration file; in
     case `logfile' has NOT been set in the configuration file, log
     through Syslog.  */
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

  /*** Prepare PAM interaction.  ***/

  /* Ask PAM for conv structure.  */
  ret = pam_get_item (ctx->pam_handle, PAM_CONV, &conv_void);
  if (ret != PAM_SUCCESS)
    {
      log_error ("Failed to retrieve conversation structure");
      err = GPG_ERR_INTERNAL;
      goto out;
    }
  ctx->pam_conv = conv_void;

  /*** Connect to Scdaemon. ***/

  err = poldi_scd_connect (ctx, getenv ("GPG_AGENT_INFO"), NULL, 0);
  if (err)
    goto out;

  /*** Call authentication method. ***/

  if (ctx->auth_method == AUTH_METHOD_NONE)
    {
      log_error ("no authentication method specified\n");
      err = GPG_ERR_CONFIGURATION;
      goto out;
    }
  else
    {
      struct auth_method method = auth_methods[ctx->auth_method];

      if (! (*method.func) (ctx))
	/* Authentication failed.  */
	err = GPG_ERR_GENERAL;
    }

 out:

  /* Log result.  */
  if (err)
    log_error ("Failure: %s\n", gpg_strerror (err));
  else
    log_info ("Success\n");

  log_close ();

  /* Deallocate main context.  */
  poldi_scd_disconnect (ctx);
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
