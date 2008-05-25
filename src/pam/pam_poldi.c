/* pam_poldi.c - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004, 2005, 2007, 2008 g10 Code GmbH
 
   This file is part of Poldi.
 
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with this program; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <assert.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include <gcrypt.h>

#include "jnlib/xmalloc.h"
#include "jnlib/logging.h"
#include "util/optparse.h"
#include "util/defs.h"
#include "scd/scd.h"

#include "auth-support/wait-for-card.h"
#include "auth-support/pam-util.h"
#include "auth-support/conv.h"
#include "auth-methods.h"



/* Auth methods declarations. */



/* Auth methods list.  */

/* Declare authentication methods.  */
extern struct auth_method_s auth_method_localdb;
extern struct auth_method_s auth_method_x509;

/* List element type for AUTH_METHODS list.  */
struct auth_method
{
  const char *name;
  auth_method_t method;
};

/* List, associating authenting method definitions with their
   names.  */
static struct auth_method auth_methods[] =
  {
#ifdef ENABLE_AUTH_METHOD_LOCALDB
    { "localdb", &auth_method_localdb },
#endif
#ifdef ENABLE_AUTH_METHOD_X509
    { "x509", &auth_method_x509 },
#endif
    { NULL, NULL }
  };



/* Macros.  */



/* Option IDs for authentication method independent options. */
enum arg_opt_ids
  {
    arg_logfile = 500,
    arg_auth_method,
    arg_scdaemon_socket,
    arg_scdaemon_program,
    arg_debug
  };

/* According option specifications. */
static ARGPARSE_OPTS arg_opts[] =
  {
    { arg_logfile,
      "log-file", 2, "|FILENAME|Specify file to use for logging" },
    { arg_auth_method,
      "auth-method", 2, "|NAME|Specify authentication method" },
    { arg_debug,
      "debug", 256, "Enable debugging messages" },
    { arg_scdaemon_socket,
      "scdaemon-socket", 2, "|SOCKET|Specify socket of system scdaemon" },
    { arg_scdaemon_program,
      "scdaemon-program", 2, "|PATH|Specify scdaemon executable to use" },
    { 0 }
  };

/* Lookup an auth_method struct by it's NAME, return it's index in
   AUTH_METHODS list or -1 if lookup failed.  */
static int
auth_method_lookup (const char *name)
{
  int i;

  for (i = 0; auth_methods[i].name; i++)
    if (strcmp (auth_methods[i].name, name) == 0)
      break;

  if (auth_methods[i].name)
    return i;
  else
    return -1;
}

/* Callback for authentication method independent option parsing. */
static gpg_error_t
pam_poldi_options_cb (ARGPARSE_ARGS *parg, void *opaque)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  poldi_ctx_t ctx = opaque;

  switch (parg->r_opt)
    {
      /* LOGFILE.  */
    case arg_logfile:
      ctx->logfile = strdup (parg->r.ret_str);
      if (!ctx->logfile)
	{
	  err = gpg_error_from_errno (errno);
	  log_error ("failed to strdup logfile name: %s\n",
		     gpg_strerror (err));
	}
      break;

      /* SCDAEMON-SOCKET.  */
    case arg_scdaemon_socket:
      ctx->scdaemon_socket = strdup (parg->r.ret_str);
      if (!ctx->scdaemon_socket)
	{
	  err = gpg_error_from_errno (errno);
	  log_error ("failed to strdup scdaemon socket name: %s\n",
		     gpg_strerror (err));
	}
      break;

      /* SCDAEMON-PROGRAM.  */
    case arg_scdaemon_program:
      ctx->scdaemon_program = strdup (parg->r.ret_str);
      if (!ctx->scdaemon_program)
	{
	  err = gpg_error_from_errno (errno);
	  log_error ("failed to strdup scdaemon program name: %s\n",
		     gpg_strerror (err));
	}
      break;

      /* AUTH-METHOD.  */
    case arg_auth_method:
      {
	int method = auth_method_lookup (parg->r.ret_str);
	if (method >= 0)
	  ctx->auth_method = method;
	else
	  {
	    /* FIXME, better error handling? */
	    err = GPG_ERR_GENERAL;
	    log_error ("unknown auth-method in conffile `%s'\n", parg->r.ret_str);
	  }
      }
      break;

      /* DEBUG.  */
    case arg_debug:
      ctx->debug = 1;
      break;

    default:
      err = GPG_ERR_INTERNAL;	/* FIXME?  */
      break;
    }

  return gpg_error (err);
}



/* Create new, empty Poldi context.  Return proper error code.   */
static gpg_error_t
create_context (poldi_ctx_t *context)
{
  gpg_error_t err;
  poldi_ctx_t ctx;

  err = 0;

  /* Allocate. */
  ctx = malloc (sizeof (*ctx));
  if (!ctx)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  /* Initialize. */
  ctx->logfile = NULL;
  ctx->auth_method = -1;
  ctx->cookie = NULL;
  ctx->debug = 0;
  ctx->scdaemon_socket = NULL;
  ctx->scdaemon_program = NULL;
  ctx->scd = NULL;
  ctx->pam_handle = NULL;
  ctx->conv = NULL;
  ctx->username = NULL;
  ctx->cardinfo = scd_cardinfo_null;

  *context = ctx;

 out:

  return err;
}

/* Deallocates resources associated with context CTX. */
static void
destroy_context (poldi_ctx_t ctx)
{
  if (ctx)
    {
      scd_disconnect (ctx->scd);
      if (ctx->logfile)
	free (ctx->logfile);
      if (ctx->scdaemon_socket)
	free (ctx->scdaemon_socket);
      if (ctx->scdaemon_program)
	free (ctx->scdaemon_program);
      scd_release_cardinfo (ctx->cardinfo);
      free (ctx);
    }
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
  conv_t conv;
  scd_context_t scd_ctx;
  int ret;
  const char *pam_username;

  pam_username = NULL;
  scd_ctx = NULL;
  conv = NULL;
  ctx = NULL;
  err = 0;

  /*** Basic initialization. ***/

  /* Initialize Libgcrypt.  Disable secure memory for now; because of
     the implicit priviledge dropping, having secure memory enabled
     causes the following error:

     su: Authentication service cannot retrieve authentication
     info. */
  gcry_control (GCRYCTL_DISABLE_SECMEM);

  /* Setup logging prefix.  */
  log_set_prefix ("[Poldi] ",
		  JNLIB_LOG_WITH_PREFIX | JNLIB_LOG_WITH_TIME | JNLIB_LOG_WITH_PID);
  /* FIXME: I guess we should also call log_set_syslog() here - but
     i'm not sure if logging.c works fine when calling log_set_foo()
     and later on log_set_bar(). -mo */

  /*** Setup main context.  ***/

  err = create_context (&ctx);
  if (err)
    goto out;

  ctx->pam_handle = pam_handle;

  /*** Parse auth-method independent options.  ***/

  /* ... from configuration file:  */
  err = options_parse_conf  (pam_poldi_options_cb, ctx,
			     arg_opts, POLDI_CONF_FILE);
  if (err)
    {
      log_error ("Error: failed to parse configuration file: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* ... and from argument vector provided by PAM: */
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

  /*** Sanity checks. ***/

  /* Authentication method to use must be specified.  */
  if (ctx->auth_method < 0)
    {
      log_error ("Error: no authentication method specified\n");
      err = GPG_ERR_CONFIGURATION;
      goto out;
    }

  /* Authentication methods must provide a parser callback in case
     they have specific a configuration file.  */
  assert ((!auth_methods[ctx->auth_method].method->config)
	  || (auth_methods[ctx->auth_method].method->func_parsecb
	      && auth_methods[ctx->auth_method].method->arg_opts));

  if (ctx->debug)
    {
      log_info ("using authentication method `%s'\n",
		auth_methods[ctx->auth_method].name);
      if (ctx->scdaemon_socket)
	log_info ("using system scdaemon; socket is '%s'\n", ctx->scdaemon_socket);
    }

  /*** Init authentication method.  ***/
  
  if (auth_methods[ctx->auth_method].method->func_init)
    {
      err = (*auth_methods[ctx->auth_method].method->func_init) (&ctx->cookie);
      if (err)
	{
	  log_error ("failed to initialize authentication method %i: %s\n",
		     -1, gpg_strerror (err));
	  goto out;
	}
    }

  if (auth_methods[ctx->auth_method].method->config)
    {
      err = options_parse_conf (auth_methods[ctx->auth_method].method->func_parsecb,
				ctx->cookie,
				auth_methods[ctx->auth_method].method->arg_opts,
				auth_methods[ctx->auth_method].method->config);
      if (err)
	{
	  log_error ("failed to parse configuration for authentication method %i: %s\n",
		     -1, gpg_strerror (err));
	  goto out;
	}
    }

  /*** Prepare PAM interaction.  ***/

  /* Ask PAM for conv structure.  */
  ret = pam_get_item (ctx->pam_handle, PAM_CONV, &conv_void);
  if (ret != PAM_SUCCESS)
    {
      log_error ("failed to retrieve conversation structure");
      err = GPG_ERR_INTERNAL;
      goto out;
    }

  /* Init conv subsystem by creating a conv_t object.  */
  err = conv_create (&conv, conv_void);
  if (err)
    goto out;

  ctx->conv = conv;

  /*** Retrieve username from PAM.  ***/

  err = retrieve_username_from_pam (ctx->pam_handle, &pam_username);
  if (err)
    {
      log_error ("failed to retrieve username from PAM: %s\n",
		 gpg_strerror (err));
    }

  /*** Connect to Scdaemon. ***/

  err = scd_connect (&scd_ctx,
		     ctx->scdaemon_socket, getenv ("GPG_AGENT_INFO"),
		     ctx->scdaemon_program, 0);
  if (err)
    goto out;

  ctx->scd = scd_ctx;

  /*** Wait for card insertion.  ***/

  if (pam_username)
    conv_tell (ctx->conv, "Insert card for user `%s'...", pam_username);
  else
    conv_tell (ctx->conv, "Insert card...");

  err = wait_for_card (ctx->scd, 0);
  if (err)
    {
      log_error ("failed to wait for card insertion: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /*** Receive card info. ***/

  err = scd_learn (ctx->scd, &ctx->cardinfo);
  if (err)
    goto out;

  if (ctx->debug)
    log_info ("connected to card, serial number is: %s",
	      ctx->cardinfo.serialno);

  /*** Authenticate.  ***/

  if (pam_username)
    {
      /* Try to authenticate user as PAM_USERNAME.  */

#if 0
      err = conv_tell (ctx->conv,
		       "Trying to authenticate as user `%s'", pam_username);
      if (err)
	{
	  /* FIXME?? do we need this?  */
	  log_error ("failed to inform user: %s\n", gpg_strerror (err));
	  goto out;
	}
#endif

      if (!(*auth_methods[ctx->auth_method].method->func_auth_as) (ctx, ctx->cookie,
								   pam_username))
	/* Authentication failed.  */
	err = GPG_ERR_GENERAL;
    }
  else
    {
      /* Try to authenticate user, choosing an identity is up to the
	 user.  */

      char *username_authenticated = NULL;

      if (!(*auth_methods[ctx->auth_method].method->func_auth) (ctx, ctx->cookie,
								&username_authenticated))
	/* Authentication failed.  */
	err = GPG_ERR_GENERAL;
      else
	/* Send username received during authentication process back
	   to PAM.  */
	err = send_username_to_pam (ctx->pam_handle, username_authenticated);

      free (username_authenticated);
    }

 out:

  /* Log result.  */
  if (err)
    log_error ("Failure: %s\n", gpg_strerror (err));
  else
    log_info ("Success\n");

  log_close ();

  /* Call authentication method's deinit callback. */
  if ((ctx->auth_method >= 0)
      && auth_methods[ctx->auth_method].method->func_deinit)
    (*auth_methods[ctx->auth_method].method->func_deinit) (ctx->cookie);

  /* FIXME, cosmetics? */
  conv_destroy (conv);
  destroy_context (ctx);

  /* Return to PAM.  */

  return err ? PAM_AUTH_ERR : PAM_SUCCESS;
}


/* PAM's `set-credentials' interface.  */
PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pam_handle,
		int flags, int argc, const char **argv)
{
  /* FIXME: do we need this?  */
  return PAM_SUCCESS;
}

/* END */
