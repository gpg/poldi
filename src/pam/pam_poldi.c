/* poldi.c - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004 g10 Code GmbH
 
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
#include <jnlib/stringhelp.h>
#include <jnlib/logging.h>
#include <common/support.h>
#include <common/options.h>
#include <common/card.h>
#include <common/defs.h>
#include <libscd/scd.h>

#define POLDI_LOG_FACILITY AUTH

#define STR_CONCAT(a, b) a ## b

#define POLDI_LOG_DO(facility, priority, format, args ...) \
  syslog (LOG_MAKEPRI (STR_CONCAT (LOG_, facility), LOG_ ## priority), \
          format, ## args)
#define POLDI_LOG(priority, format, args ...) \
  POLDI_LOG_DO (POLDI_LOG_FACILITY, priority, format, ## args)

/* Global flags.  */
struct pam_poldi_opt
{
  unsigned int debug; /* Enable debugging.  */
  int debug_sc;
  int verbose;
  const char *ctapi_driver; /* Library to access the ctAPI. */
  const char *pcsc_driver;  /* Library to access the PC/SC system. */
  const char *reader_port;  /* NULL or reder port to use. */
  int disable_opensc;  /* Disable the use of the OpenSC framework. */
  int disable_ccid;    /* Disable the use of the internal CCID driver. */
  int debug_ccid_driver;	/* Debug the internal CCID driver.  */
  int fake_wait_for_card;
  int require_card_switch;
  const char *logfile;
} pam_poldi_opt;

/* Set defaults.  */
struct pam_poldi_opt pam_poldi_opt =
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
    0,
    0,
    NULL
  };


/* Option IDs.  */
enum arg_opt_ids
  {
    arg_debug = 500,
    arg_debug_sc,
    arg_verbose,
    arg_ctapi_driver,
    arg_pcsc_driver,
    arg_reader_port,
    arg_disable_opensc,
    arg_disable_ccid,
    arg_debug_ccid_driver,
    arg_fake_wait_for_card,
    arg_require_card_switch,
    arg_logfile
  };

/* Option specifications. */
static ARGPARSE_OPTS arg_opts[] =
  {
    { arg_debug,
      "debug", 256, "Debug PAM-Poldi" },
    { arg_debug_sc,
      "debug-sc", 256, "Debug sc FIXME" },
    { arg_ctapi_driver,
      "ctapi-driver", 2, "|NAME|use NAME as ct-API driver" },
    { arg_pcsc_driver,
      "pcsc-driver", 2,  "|NAME|use NAME as PC/SC driver" },
    { arg_reader_port,
      "reader-port", 2, "|N|connect to reader at port N" },
#ifdef HAVE_LIBUSB
    { arg_disable_ccid,
      "disable-ccid", 0, "do not use the internal CCID driver" },
    { arg_debug_ccid_driver,
      "debug-ccid-driver", 0, "debug the  internal CCID driver" },
#endif
#ifdef HAVE_OPENSC
    { arg_disable_opensc,
      "disable-opensc", 0, "do not use the OpenSC layer" },
#endif
    { arg_fake_wait_for_card,
      "fake-wait-for-card", 0, "fake wait-for-card-feature" },
    { arg_require_card_switch,
      "require-card-switch", 0, "Require re-insertion of card" },
    { arg_logfile,
      "log-file", 2, "Specify file to use for logging" },
    { 0 }
  };

static gpg_error_t
pam_poldi_options_cb (ARGPARSE_ARGS *parg, void *opaque)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  switch (parg->r_opt)
    {
    case arg_debug:
      pam_poldi_opt.debug = 1;
      break;

    case arg_debug_sc:
      pam_poldi_opt.debug_sc = 1;
      break;

    case arg_ctapi_driver:
      pam_poldi_opt.ctapi_driver = xstrdup (parg->r.ret_str);
      break;

    case arg_pcsc_driver:
      pam_poldi_opt.pcsc_driver = xstrdup (parg->r.ret_str);
      break;

    case arg_reader_port:
      pam_poldi_opt.reader_port = xstrdup (parg->r.ret_str);
      break;

    case arg_disable_ccid:
      pam_poldi_opt.disable_ccid = 1;
      break;

    case arg_disable_opensc:
      pam_poldi_opt.disable_opensc = 1;
      break;

    case arg_debug_ccid_driver:
      pam_poldi_opt.debug_ccid_driver = 1;
      break;

    case arg_fake_wait_for_card:
      pam_poldi_opt.fake_wait_for_card = 1;
      break;

    case arg_require_card_switch:
      pam_poldi_opt.require_card_switch = 1;
      break;

    case arg_logfile:
      pam_poldi_opt.logfile = xstrdup (parg->r.ret_str);
      break;

    default:
      err = GPG_ERR_INTERNAL;	/* FIXME?  */
      break;
    }

  return gpg_error (err);
}

static gpg_error_t
ask_user (const struct pam_conv *conv, const char *text, char **response)
{
  struct pam_message messages[1] = { { PAM_PROMPT_ECHO_OFF, text } };
  const struct pam_message *pmessages[1] = { &messages[0] };
  struct pam_response *responses = NULL;
  char *response_new;
  gpg_error_t err;
  int ret;

  response_new = NULL;

  ret = (*conv->conv) (sizeof (messages) / (sizeof (*messages)), pmessages,
		       &responses, conv->appdata_ptr);
  if (ret != PAM_SUCCESS)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      goto out;
    }

  if (response)
    {
      response_new = strdup (responses[0].resp);
      if (! response_new)
	{
	  err = gpg_error_from_errno (errno);
	  goto out;
	}
    }

  err = 0;
  if (response)
    *response = response_new;

 out:

  return err;
}

static gpg_error_t
tell_user (const struct pam_conv *conv, char *fmt, ...)
{
  struct pam_message messages[1] = { { PAM_TEXT_INFO, NULL } };
  const struct pam_message *pmessages[1] = { &messages[0] };
  struct pam_response *responses = NULL;
  gpg_error_t err;
  char *string;
  va_list ap;
  int ret;

  string = NULL;

  va_start (ap, fmt);
  ret = vasprintf (&string, fmt, ap);
  if (ret < 0)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }
  va_end (ap);

  messages[0].msg = string;
  
  ret = (*conv->conv) (sizeof (messages) / (sizeof (*messages)), pmessages,
		       &responses, conv->appdata_ptr);
  if (ret != PAM_SUCCESS)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      goto out;
    }

  err = 0;

 out:

  free (string);

  return err;
}

static gpg_error_t
do_auth (int slot, const struct pam_conv *conv, gcry_sexp_t key)
{
  unsigned char *challenge;
  unsigned char *response;
  size_t challenge_n;
  size_t response_n;
  gpg_error_t err;
  char *pin;

  challenge = NULL;
  response = NULL;
  pin = NULL;

  err = ask_user (conv, POLDI_PIN2_QUERY_MSG, &pin);
  if (err)
    goto out;

  err = card_pin_provide (slot, 2, pin);
  if (err)
    goto out;

  err = challenge_generate (&challenge, &challenge_n);
  if (err)
    goto out;

  err = card_sign (slot, challenge, challenge_n, &response, &response_n);
  if (err)
    goto out;

  /* Verify response.  */
  err = challenge_verify (key, challenge, challenge_n, response, response_n);

 out:

  free (challenge);
  free (response);
  free (pin);

  return err;
}

static gpg_error_t
lookup_key (const char *username, gcry_sexp_t *key)
{
  gcry_sexp_t key_sexp;
  char *key_string;
  char *key_path;
  const char *serialno;
  gpg_error_t err;

  serialno = NULL;
  key_path = NULL;
  key_string = NULL;

  err = username_to_serialno (username, &serialno);
  if (err)
    goto out;

  key_path = make_filename (POLDI_KEY_DIRECTORY, serialno, NULL);
  err = file_to_string (key_path, &key_string);
  if ((! err) && (! key_string))
    err = gpg_error (GPG_ERR_NO_PUBKEY);
  if (err)
    goto out;

  err = string_to_sexp (&key_sexp, key_string);
  if (err)
    goto out;

  *key = key_sexp;

 out:

  free (key_path);
  free (key_string);
  free ((void *) serialno);

  return err;
}

static gpg_error_t
wait_for_card (int slot, int fake, int require_card_switch,
	       const struct pam_conv *conv, const char **serialno)
{
  const char *serialno_new;
  gpg_error_t err;

  if (fake)
    err = ask_user (conv, "Press ENTER when card is available ...", NULL);
  else
    err = tell_user (conv, "Insert card ...");
  if (err)
    goto out;

  err = card_init (slot, ! fake, require_card_switch);
  if (err)
    goto out;

  err = card_info (slot, &serialno_new, NULL);
  if (err)
    goto out;

  *serialno = serialno_new;

 out:

  return err;
}

static gpg_error_t
parse_argv (int argc, const char **argv)
{
  gpg_error_t err;
  unsigned int i;

  err = 0;
  for (i = 0; i < argc; i++)
    if (! strcmp (argv[i], "debug"))
      {
	pam_poldi_opt.debug = ~0;
	pam_poldi_opt.debug_sc = 1;
	pam_poldi_opt.verbose = 1;
	pam_poldi_opt.debug_ccid_driver = 1;
      }
    else
      {
	err = gpg_error (GPG_ERR_INTERNAL);
	break;
      }

  return err;
}

/* Uaaahahahh, ich will dir einloggen!  */
PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pam_handle, int flags, int argc, const char **argv)
{
  const struct pam_conv *conv;
  gcry_sexp_t key;
  gpg_error_t err;
  char *username;
  const char *serialno;
  const char *account;
  int slot;
  int ret;

  serialno = NULL;
  account = NULL;
  slot = -1;
  key = NULL;
  
  openlog ("poldi", LOG_PID, LOG_USER);

  /* Parse options.  */
  err = options_parse_conf  (pam_poldi_options_cb, NULL,
			     arg_opts, POLDI_CONF_FILE);
  if (err)
    goto out;

  err = parse_argv (argc, argv);
  if (err)
    goto out;

  log_set_file (pam_poldi_opt.logfile);

  scd_init (pam_poldi_opt.debug,
	    pam_poldi_opt.debug_sc,
	    pam_poldi_opt.verbose,
	    pam_poldi_opt.ctapi_driver,
	    pam_poldi_opt.reader_port,
	    pam_poldi_opt.pcsc_driver,
	    pam_poldi_opt.disable_opensc,
	    pam_poldi_opt.disable_ccid,
	    pam_poldi_opt.debug_ccid_driver);

  /* Ask PAM for username.  */
  ret = pam_get_item (pam_handle, PAM_USER, (const void **) &username);
  if (ret != PAM_SUCCESS)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      goto out;
    }

  /* Ask PAM for conv structure.  */
  ret = pam_get_item (pam_handle, PAM_CONV, (const void **) &conv);
  if (ret != PAM_SUCCESS)
    {
      POLDI_LOG (ERR, "Failed to retrieve conversation structure");
      err = GPG_ERR_INTERNAL;
      goto out;
    }

  /* Open card slot.  */
  err = card_open (NULL, &slot);
  if (err)
    goto out;

  if (username)
    {
      /* Got a username from PAM.  */
      
      err = lookup_key (username, &key);
      if (err)
	goto out;

      /* Got key.  */

      err = wait_for_card (slot, pam_poldi_opt.fake_wait_for_card,
			   pam_poldi_opt.require_card_switch, conv, &serialno);
      if (err)
	goto out;

      err = serialno_to_username (serialno, &account);

      if (err || strcmp (account, username))
	{
	  tell_user (conv, "Serial no %s is not associated with %s",
		     serialno, username);
	  if (! err)
	    err = gpg_error (GPG_ERR_INTERNAL); /* FIXME */
	}
      else
	err = tell_user (conv, "Serial no: %s", serialno);
      if (err)
	goto out;

      err = do_auth (slot, conv, key);
      if (err)
	goto out;
    }
  else
    {
      err = wait_for_card (slot, pam_poldi_opt.fake_wait_for_card,
			   pam_poldi_opt.require_card_switch, conv, &serialno);
      if (err)
	goto out;

      err = tell_user (conv, "Serial no: %s", serialno);
      if (err)
	goto out;

      err = serialno_to_username (serialno, &account);
      if (err)
	goto out;

      err = tell_user (conv, "Account: %s", account);
      if (err)
	goto out;

      err = lookup_key (account, &key);
      if (err)
	goto out;

      err = do_auth (slot, conv, key);
      if (err)
	goto out;
  
      /* Make username available to application.  */
      ret = pam_set_item (pam_handle, PAM_USER, account);
      if (ret != PAM_SUCCESS)
	{
	  err = gpg_error (GPG_ERR_INTERNAL);
	  goto out;
	}
    }

  /* Done.  */

 out:
  
  gcry_sexp_release (key);
  free ((void *) serialno);
  free ((void *) account);
  if (slot != -1)
    card_close (slot);

  if (err)
    POLDI_LOG (ERR, "Failure: %s\n", gpg_strerror (err));
  else
    POLDI_LOG (INFO, "Success\n");

  closelog ();

  return err ? PAM_AUTH_ERR : PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pam_handle, int flags, int argc, const char **argv)
{
  /* FIXME?  */
  return PAM_SUCCESS;
}
