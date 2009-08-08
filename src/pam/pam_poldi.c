/* pam_poldi.c - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004, 2005, 2007, 2008, 2009 g10 Code GmbH
 
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

#include <poldi.h>

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <assert.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include "util/simplelog.h"
#include "util/simpleparse.h"
#include "util/defs.h"
#include "scd/scd.h"

#include "auth-support/wait-for-card.h"
#include "auth-support/pam-util.h"
#include "auth-support/conv.h"
#include "auth-support/getpin-cb.h"
#include "auth-methods.h"



/*** Auth methods declarations. ***/

/* Declare authentication methods.  */
extern struct auth_method_s auth_method_localdb;
extern struct auth_method_s auth_method_x509;

/* List element type for AUTH_METHODS list below.  */
struct auth_method
{
  const char *name;
  auth_method_t method;
};

/* List associating authenting method definitions with their
   names.  */
static struct auth_method auth_methods[] =
  {
#ifdef ENABLE_AUTH_METHOD_LOCALDB
    { "localdb", &auth_method_localdb },
#endif
#ifdef ENABLE_AUTH_METHOD_X509
    { "x509", &auth_method_x509 },
#endif
    { NULL }
  };



/*** Option parsing. ***/

/* IDs for supported options. */
enum opt_ids
  {
    opt_none,
    opt_logfile,
    opt_auth_method,
    opt_debug,
    opt_scdaemon_program,
    opt_scdaemon_options,
    opt_modify_environment,
    opt_quiet
  };

/* Full specifications for options. */
static simpleparse_opt_spec_t opt_specs[] =
  {
    { opt_logfile, "log-file",
      0, SIMPLEPARSE_ARG_REQUIRED, 0, "Specify file to user for logging" },
    { opt_auth_method, "auth-method",
      0, SIMPLEPARSE_ARG_REQUIRED, 0, "Specify authentication method" },
    { opt_debug, "debug",
      0, SIMPLEPARSE_ARG_NONE,     0, "Enable debugging mode" },
    { opt_scdaemon_program, "scdaemon-program",
      0, SIMPLEPARSE_ARG_REQUIRED, 0, "Specify scdaemon executable to use" },
    { opt_scdaemon_options, "scdaemon-options",
      0, SIMPLEPARSE_ARG_REQUIRED, 0, "Specify scdaemon configuration file to use" },
    { opt_modify_environment, "modify-environment",
      0, SIMPLEPARSE_ARG_NONE, 0, "Set Poldi related variables in the PAM environment" },
    { opt_quiet, "quiet",
      0, SIMPLEPARSE_ARG_NONE, 0, "Be more quiet during PAM conversation with user" },
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
pam_poldi_options_cb (void *cookie, simpleparse_opt_spec_t spec, const char *arg)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  poldi_ctx_t ctx = cookie;

  if (!strcmp (spec.long_opt, "log-file"))
    {
      /* LOG-FILE.  */
      ctx->logfile = xtrystrdup (arg);
      if (!ctx->logfile)
	{
	  err = gpg_error_from_errno (errno);
	  log_msg_error (ctx->loghandle,
			 _("failed to duplicate %s: %s"),
			 "logfile name", gpg_strerror (err));
	}
    }
  else if (!strcmp (spec.long_opt, "scdaemon-program"))
    {
      /* SCDAEMON-PROGRAM.  */

      ctx->scdaemon_program = strdup (arg);
      if (!ctx->scdaemon_program)
	{
	  err = gpg_error_from_errno (errno);
	  log_msg_error (ctx->loghandle,
			 _("failed to duplicate %s: %s"),
			 "scdaemon program name",
			 gpg_strerror (err));
	}
    }
  else if (!strcmp (spec.long_opt, "scdaemon-options"))
    {
      /* SCDAEMON-OPTIONS.  */

      ctx->scdaemon_options = strdup (arg);
      if (!ctx->scdaemon_options)
	{
	  err = gpg_error_from_errno (errno);
	  log_msg_error (ctx->loghandle,
			 _("failed to duplicate %s: %s"),
			 "scdaemon options name",
			 gpg_strerror (err));
	}
    }
  else if (!strcmp (spec.long_opt, "auth-method"))
    {
      /* AUTH-METHOD.  */

      int method = auth_method_lookup (arg);
      if (method >= 0)
	ctx->auth_method = method;
      else
	{
	  log_msg_error (ctx->loghandle,
			 _("unknown authentication method '%s'"),
			 arg);
	  err = GPG_ERR_INV_VALUE;
	}
    }
  else if (!strcmp (spec.long_opt, "debug"))
    {
      /* DEBUG.  */
      ctx->debug = 1;
      log_set_min_level (ctx->loghandle, LOG_LEVEL_DEBUG);
    }
  else if (!strcmp (spec.long_opt, "modify-environment"))
    {
      /* MODIFY-ENVIRONMENT.  */
      ctx->modify_environment = 1;
    }
  else if (!strcmp (spec.long_opt, "quiet"))
    {
      /* QUIET.  */
      ctx->quiet = 1;
    }

  return gpg_error (err);
}

/* This callback is used for simpleparse. */
static const char *
i18n_cb (void *cookie, const char *msg)
{
  return _(msg);
}



static struct poldi_ctx_s poldi_ctx_NULL; /* For initialization
					     purpose. */

/* Create new, empty Poldi context.  Return proper error code.   */
static gpg_error_t
create_context (poldi_ctx_t *context, pam_handle_t *pam_handle)
{
  gpg_error_t err;
  poldi_ctx_t ctx;

  err = 0;

  /* Allocate. */
  ctx = xtrymalloc (sizeof (*ctx));
  if (!ctx)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  /* Initialize. */

  *ctx = poldi_ctx_NULL;

  ctx->auth_method = -1;
  ctx->cardinfo = scd_cardinfo_null;
  ctx->pam_handle = pam_handle;

  err = log_create (&ctx->loghandle);
  if (err)
    goto out;

  err = simpleparse_create (&ctx->parsehandle);
  if (err)
    goto out;

  simpleparse_set_loghandle (ctx->parsehandle, ctx->loghandle);
  simpleparse_set_parse_cb (ctx->parsehandle, pam_poldi_options_cb, ctx);
  simpleparse_set_specs (ctx->parsehandle, opt_specs);
  simpleparse_set_i18n_cb (ctx->parsehandle, i18n_cb, NULL);

  *context = ctx;

 out:

  if (err)
    {
      if (ctx)
	{
	  simpleparse_destroy (ctx->parsehandle);
	  log_destroy (ctx->loghandle);
	  xfree (ctx);
	}
    }

  return err;
}

/* Deallocates resources associated with context CTX. */
static void
destroy_context (poldi_ctx_t ctx)
{
  if (ctx)
    {
      xfree (ctx->logfile);
      simpleparse_destroy (ctx->parsehandle);
      log_destroy (ctx->loghandle);
      xfree (ctx->scdaemon_program);
      xfree (ctx->scdaemon_options);
      scd_disconnect (ctx->scd);
      scd_release_cardinfo (ctx->cardinfo);
      /* FIXME: not very consistent: conv is (de-)allocated by caller. -mo */
      xfree (ctx);
    }
}



/*
 * Environment setting.
 */

static void
modify_environment_putenv (pam_handle_t *pam_handle, poldi_ctx_t ctx,
			   const char *name, const char *value)
{
  char *str;
  int ret;

  str = NULL;
  ret = asprintf (&str, "%s=%s", name, value);
  if (ret < 0)
    {
      log_msg_error (ctx->loghandle,
		     _("asprintf() failed in modify_environment_putenv(): %s"),
		     errno);
      return;
    }

  ret = pam_putenv (pam_handle, str);
  if (ret != PAM_SUCCESS)
    {
      log_msg_error (ctx->loghandle,
		     _("pam_putenv() failed in modify_environment_putenv(): %s"),
		     pam_strerror (pam_handle, ret));
    }
  free (str);
}

static void
modify_environment (pam_handle_t *pam_handle, poldi_ctx_t ctx)
{
  struct scd_cardinfo *cardinfo;

  assert (pam_handle);
  assert (ctx);

  cardinfo = &ctx->cardinfo;

  modify_environment_putenv (pam_handle, ctx,
			     "PAM_POLDI_AUTHENTICATED", "");
  modify_environment_putenv (pam_handle, ctx,
			     "PAM_POLDI_SERIALNO", cardinfo->serialno);
  modify_environment_putenv (pam_handle, ctx,
			     "PAM_POLDI_LANGUAGE", cardinfo->disp_lang);
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
  struct auth_method_parse_cookie method_parse_cookie = { NULL, NULL };
  simpleparse_handle_t method_parse;
  struct getpin_cb_data getpin_cb_data;

  pam_username = NULL;
  scd_ctx = NULL;
  conv = NULL;
  ctx = NULL;
  method_parse = NULL;
  err = 0;

  /*** Basic initialization. ***/

  bindtextdomain (PACKAGE, LOCALEDIR);

  /* Initialize Libgcrypt.  Disable secure memory for now; because of
     the implicit priviledge dropping, having secure memory enabled
     causes the following error:

     su: Authentication service cannot retrieve authentication
     info. */
  gcry_control (GCRYCTL_DISABLE_SECMEM);

  /*** Setup main context.  ***/

  err = create_context (&ctx, pam_handle);
  if (err)
    goto out;

  /* Setup logging prefix.  */
  log_set_flags (ctx->loghandle,
		 LOG_FLAG_WITH_PREFIX | LOG_FLAG_WITH_TIME | LOG_FLAG_WITH_PID);
  log_set_prefix (ctx->loghandle, "Poldi");
  log_set_backend_syslog (ctx->loghandle);

  /*** Parse auth-method independent options.  ***/

  /* ... from configuration file:  */
  err = simpleparse_parse_file (ctx->parsehandle, 0, POLDI_CONF_FILE);
  if (err)
    {
      log_msg_error (ctx->loghandle,
		     _("failed to parse configuration file '%s': %s"),
		     POLDI_CONF_FILE,
		     gpg_strerror (err));
      goto out;
    }

  /* ... and from argument vector provided by PAM: */
  if (argc)
    {
      err = simpleparse_parse (ctx->parsehandle, 0, argc, argv, NULL);
      if (err)
	{
	  log_msg_error (ctx->loghandle,
			 _("failed to parse PAM argument vector: %s"),
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
      gpg_error_t rc;

      rc = log_set_backend_file (ctx->loghandle, ctx->logfile);
      if (rc != 0)
	/* Last try...  */
	log_set_backend_syslog (ctx->loghandle);
    }

  /*** Sanity checks. ***/

  /* Authentication method to use must be specified.  */
  if (ctx->auth_method < 0)
    {
      log_msg_error (ctx->loghandle,
		     _("no authentication method specified"));
      err = GPG_ERR_CONFIGURATION;
      goto out;
    }

  /* Authentication methods must provide a parser callback in case
     they have specific a configuration file.  */
  assert ((!auth_methods[ctx->auth_method].method->config)
	  || (auth_methods[ctx->auth_method].method->parsecb
	      && auth_methods[ctx->auth_method].method->opt_specs));

  if (ctx->debug)
    {
      log_msg_debug (ctx->loghandle,
		     _("using authentication method `%s'"),
		     auth_methods[ctx->auth_method].name);
    }

  /*** Init authentication method.  ***/
  
  if (auth_methods[ctx->auth_method].method->func_init)
    {
      err = (*auth_methods[ctx->auth_method].method->func_init) (&ctx->cookie);
      if (err)
	{
	  log_msg_error (ctx->loghandle,
			 _("failed to initialize authentication method %i: %s"),
			 -1, gpg_strerror (err));
	  goto out;
	}
    }

  if (auth_methods[ctx->auth_method].method->config)
    {
      /* Do auth-method specific parsing. */

      err = simpleparse_create (&method_parse);
      if (err)
	{
	  log_msg_error (ctx->loghandle,
			 _("failed to initialize parsing of configuration file for authentication method %s: %s"),
			 auth_methods[ctx->auth_method].name, gpg_strerror (err));
	  goto out_parsing;
	}

      method_parse_cookie.poldi_ctx = ctx;
      method_parse_cookie.method_ctx = ctx->cookie;

      simpleparse_set_loghandle (method_parse, ctx->loghandle);
      simpleparse_set_parse_cb (method_parse,
				auth_methods[ctx->auth_method].method->parsecb,
				&method_parse_cookie);
      simpleparse_set_i18n_cb (method_parse, i18n_cb, NULL);
      simpleparse_set_specs (method_parse,
			     auth_methods[ctx->auth_method].method->opt_specs);

      err = simpleparse_parse_file (method_parse, 0, 
				    auth_methods[ctx->auth_method].method->config);
      if (err)
	{
	  log_msg_error (ctx->loghandle,
			 _("failed to parse configuration for authentication method %i: %s"),
			 auth_methods[ctx->auth_method].name, gpg_strerror (err));
	  goto out_parsing;
	}

    out_parsing:

      simpleparse_destroy (method_parse);
      if (err)
	goto out;
    }

  /*** Prepare PAM interaction.  ***/

  /* Ask PAM for conv structure.  */
  ret = pam_get_item (ctx->pam_handle, PAM_CONV, &conv_void);
  if (ret != PAM_SUCCESS)
    {
      log_msg_error (ctx->loghandle,
		     _("failed to retrieve PAM conversation structure"));
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
      log_msg_error (ctx->loghandle,
		     _("failed to retrieve username from PAM: %s"),
		     gpg_strerror (err));
    }

  /*** Connect to Scdaemon. ***/

  err = scd_connect (&scd_ctx,
		     NULL, getenv ("GPG_AGENT_INFO"),
		     ctx->scdaemon_program, ctx->scdaemon_options,
		     0, ctx->loghandle);
  if (err)
    goto out;

  ctx->scd = scd_ctx;

  /* Install PIN retrival callback. */
  getpin_cb_data.poldi_ctx = ctx;
  scd_set_pincb (ctx->scd, getpin_cb, &getpin_cb_data);

  /*** Wait for card insertion.  ***/

  if (pam_username)
    {
      if (ctx->debug)
	log_msg_debug (ctx->loghandle, _("Waiting for card for user `%s'..."), pam_username);
      if (!ctx->quiet)
	conv_tell (ctx->conv, _("Insert authentication card for user `%s'"), pam_username);
    }
  else
    {
      if (ctx->debug)
	log_msg_debug (ctx->loghandle, _("Waiting for card..."));
      if (!ctx->quiet)
	conv_tell (ctx->conv, _("Insert authentication card"));
    }

  err = wait_for_card (ctx->scd, 0);
  if (err)
    {
      log_msg_error (ctx->loghandle,
		     _("failed to wait for card insertion: %s"),
		     gpg_strerror (err));
      goto out;
    }

  /*** Receive card info. ***/

  err = scd_learn (ctx->scd, &ctx->cardinfo);
  if (err)
    goto out;

  if (ctx->debug)
    log_msg_debug (ctx->loghandle,
		   _("connected to card; serial number is: %s"),
		   ctx->cardinfo.serialno);

  /*** Authenticate.  ***/

  if (pam_username)
    {
      /* Try to authenticate user as PAM_USERNAME.  */

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
	{
	  /* Send username received during authentication process back
	     to PAM.  */
	  err = send_username_to_pam (ctx->pam_handle, username_authenticated);
	  xfree (username_authenticated);
	}
    }

 out:

  /* Log result.  */
  if (err)
    log_msg_error (ctx->loghandle, _("authentication failed: %s"), gpg_strerror (err));
  else
    {
      if (ctx->debug)
	log_msg_debug (ctx->loghandle, _("authentication succeeded"));
      if (ctx->modify_environment)
	modify_environment (pam_handle, ctx);
    }

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
  return PAM_SUCCESS;
}

/* END */
