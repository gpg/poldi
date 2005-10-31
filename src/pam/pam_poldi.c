/* poldi.c - PAM authentication via OpenPGP smartcards.
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
#include <common/options.h>
#include <common/card.h>
#include <common/defs.h>
#include <libscd/scd.h>



/* Macros.  */



/* Option structure layout.  */
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
  int require_card_switch;
  const char *logfile;
  unsigned int wait_timeout;
};

/* Option structure definition.  */
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
    NULL,
    0
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
    arg_require_card_switch,
    arg_logfile,
    arg_wait_timeout
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
    { arg_require_card_switch,
      "require-card-switch", 0, "Require re-insertion of card" },
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

    case arg_require_card_switch:
      pam_poldi_opt.require_card_switch = 1;
      break;

    case arg_logfile:
      pam_poldi_opt.logfile = xstrdup (parg->r.ret_str);
      break;

    case arg_wait_timeout:
      pam_poldi_opt.wait_timeout = parg->r.ret_int;
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

/* We need this wrapper type, since PAM's CONV function is declared
   const, but Poldi's conversation callback interface includes a
   non-const "void *opaque" argument.  */
typedef struct conv_opaque
{
  const struct pam_conv *conv;
} conv_opaque_t;

/* This function queries the PAM user for input through the
   conversation function CONV; TEXT will be displayed as prompt, the
   user's response will be stored in *RESPONSE.  Returns proper error
   code.  */
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

/* This function queries the PAM user for input through the
   conversation function CONV; TEXT will be displayed as prompt, the
   user's response will be stored in *RESPONSE.  Returns proper error
   code.  */
static gpg_error_t
tell_user (const struct pam_conv *conv, const char *fmt, ...)
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
pam_conversation (conversation_type_t type, void *opaque,
		  const char *info, char **response)
{
  conv_opaque_t *conv_opaque = opaque;
  gpg_error_t err;

  switch (type)
    {
    case CONVERSATION_TELL:
      err = tell_user (conv_opaque->conv, info, response);
      break;

    case CONVERSATION_ASK_SECRET:
      err = ask_user (conv_opaque->conv, info, response);
      break;

    default:
      /* This CANNOT happen.  */
      abort ();
    }

  return err;
}



/*
 * Helper functions.
 */

/* This function parses the PAM argument vector ARGV of size ARGV */
static gpg_error_t
parse_argv (int argc, const char **argv)
{
  gpg_error_t err;
  unsigned int i;

  err = 0;
  for (i = 0; i < argc; i++)
    {
      if (! strcmp (argv[i], "debug"))
	{
	  /* Handle "debug" option.  */
	  pam_poldi_opt.debug = ~0;
	  pam_poldi_opt.debug_sc = 1;
	  pam_poldi_opt.verbose = 1;
	  pam_poldi_opt.debug_ccid_driver = 1;
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

  return err;
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
  conv_opaque_t conv_opaque;
  const struct pam_conv *conv;
  gcry_sexp_t key;
  gpg_error_t err;
  const void *username_void;
  const char *username;
  char *serialno;
  char *account;
  int slot;
  int ret;

  serialno = NULL;
  account = NULL;
  slot = -1;
  key = NULL;

  /* Parse options.  */
  err = options_parse_conf  (pam_poldi_options_cb, NULL,
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

  if (pam_poldi_opt.logfile)
    {
      log_set_file (pam_poldi_opt.logfile);
      if (! strcmp (pam_poldi_opt.logfile, "-"))
	/* We need to disable bufferring on stderr, since it might
	   have been enabled by log_set_file().  Buffering on stderr
	   will complicate PAM interaction, since e.g. libpam-misc's
	   misc_conv() function does expect stderr to be
	   unbuffered.  */
	setvbuf (stderr, NULL, _IONBF, 0);
    }
  else
    log_set_syslog ("poldi", LOG_AUTH);

  /* Initialize libscd.  */
  scd_init (pam_poldi_opt.debug,
	    pam_poldi_opt.debug_sc,
	    pam_poldi_opt.verbose,
	    pam_poldi_opt.ctapi_driver,
	    pam_poldi_opt.reader_port,
	    pam_poldi_opt.pcsc_driver,
	    pam_poldi_opt.disable_opensc,
	    pam_poldi_opt.disable_ccid,
	    pam_poldi_opt.debug_ccid_driver);

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
  conv = conv_void;
  conv_opaque.conv = conv;

  /* Open card slot.  */
  err = card_open (NULL, &slot);
  if (err)
    goto out;

  /*
   * Process authentication request.
   */

  if (username)
    {
      /* We got a username from PAM, thus we are waiting for a
	 specific card.  */

      /* We do not need the key right now already, but it seems to be
	 a good idea to make the login fail before waiting for card in
	 case no key has been installed for that card.  */
      err = key_lookup_by_username (username, &key);
      if (err)
	goto out;

      /* Wait for card.  */
      err = wait_for_card (slot, pam_poldi_opt.require_card_switch,
			   pam_poldi_opt.wait_timeout,
			   pam_conversation, &conv_opaque, &serialno,
			   NULL, NULL);
      if (err)
	goto out;

      /* Lookup account for given card.  */
      err = usersdb_lookup_by_serialno (serialno, &account);
      if (err || strcmp (account, username))
	{
	  /* Either the account could not be found or it is not the
	     expected one -> fail.  */

	  if (! err)
	    {
	      tell_user (conv, "Serial no %s is not associated with %s",
			 serialno, username);
	      err = gpg_error (GPG_ERR_INV_NAME);
	    }
	  else
	    log_error ("Error: failed to lookup username for "
		       "serial number `%s': %s\n",
		       serialno, gpg_strerror (err));
	}
      else
	{
	  /* Inform user about inserted card.  */
	
	  err = tell_user (conv, "Serial no: %s", serialno);
	  if (err)
	    log_error ("Error: failed to inform user about inserted card: %s\n",
		       gpg_strerror (err));
	}

      if (err)
	goto out;

      /* It is the correct card, try authentication with given
	 key.  */
      err = authenticate (slot, key, pam_conversation, &conv_opaque);
      if (err)
	goto out;
    }
  else
    {
      /* No username has been provided by PAM, thus we accept any
	 card.  */

      /* Wait for card.  */
      err = wait_for_card (slot, pam_poldi_opt.require_card_switch,
			   pam_poldi_opt.wait_timeout,
			   pam_conversation, &conv_opaque, &serialno,
			   NULL, NULL);
      if (err)
	goto out;

      /* Inform user about inserted card.  */
      err = tell_user (conv, "Serial no: %s", serialno);
      if (err)
	{
	  log_error ("Error: failed to inform user about inserted card: %s\n",
		     gpg_strerror (err));
	  goto out;
	}

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
      err = tell_user (conv, "Account: %s", account);
      if (err)
	{
	  log_error ("Error: failed to inform user about inserted card: %s\n",
		     gpg_strerror (err));
	  goto out;
	}

      /* Lookup key for looked up account.  */
      err = key_lookup_by_username (account, &key);
      if (err)
	goto out;

      /* Try authentication with looked up key.  */
      err = authenticate (slot, key, pam_conversation, &conv_opaque);
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

  /* Release resources.  */
  gcry_sexp_release (key);
  free (serialno);
  free (account);
  if (slot != -1)
    card_close (slot);

  /* Log result.  */
  if (err)
    log_error ("Failure: %s\n", gpg_strerror (err));
  else
    log_info ("Success\n");

  /* FIXME, should be done by logging.c somehow.  */
  closelog ();

  /* Return to PAM.  */

  return err ? PAM_AUTH_ERR : PAM_SUCCESS;
}


/* PAM's `set-credentials' interface.  */
PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pam_handle,
		int flags, int argc, const char **argv)
{
  /* FIXME?  */
  return PAM_SUCCESS;
}

/* END */
