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

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#define PAM_SM_AUTH

#include <security/pam_modules.h>

#include "card.h"
#include "support.h"
#include "options.h"

#define POLDI_LOG_FACILITY AUTH

#define STR_CONCAT(a, b) a ## b

#define POLDI_LOG_DO(facility, priority, format, args ...) \
  syslog (LOG_MAKEPRI (STR_CONCAT (LOG_, facility), LOG_ ## priority), \
          format, ## args)
#define POLDI_LOG(priority, format, args ...) \
  POLDI_LOG_DO (POLDI_LOG_FACILITY, priority, format, ## args)

/* Uaaahahahh, ich will dir einloggen!  */
PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pam_handle, int flags, int argc, const char **argv)
{
  struct pam_message messages[1] = { { PAM_PROMPT_ECHO_OFF,
				       "Give me your PIN: " } };
  const struct pam_message *pmessages[1] = { &messages[0] };
  struct pam_response *responses = NULL;
  const struct pam_conv *conv = NULL;
  unsigned char *username = NULL, key_fpr[41] = {};
  gpg_error_t err = GPG_ERR_NO_ERROR;
  unsigned char *challenge = NULL, *response = NULL;
  size_t challenge_n = 0, response_n = 0;
  poldi_key_t key = NULL;
  int slot = -1;
  unsigned char *serialno = NULL;
  size_t serialno_n = 0;
  unsigned char *login = NULL;
  int ret = PAM_SUCCESS;
  unsigned int i = 0;
  unsigned int debug = 0;

  openlog ("poldi", LOG_PID, LOG_USER);

  /* Parse arguments.  */
  for (i = 0; i < argc; i++)
    {
      if (! strcmp (argv[i], "debug"))
	{
	  if (! debug)
	    debug = 1;
	}
      else
	POLDI_LOG (WARNING, "Unknown argument: %s", argv[i]);
    }

  if (debug)
    POLDI_LOG (DEBUG, "Executing in debugging mode");

  /* Parse options.  */
  err = options_init ();
  if (err)
    {
      POLDI_LOG (ERR, "Failed to parse options file: %s",
		 gpg_strerror (err));
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Parsed options file");
    }

  /* Open card.  */
  err = card_open (NULL, &slot, &serialno, &serialno_n);
  if (err)
    {
      POLDI_LOG (ERR, "Failed to open card: %s", gpg_strerror (err));
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Opened card");	/* FIXME */
    }

  /* Lookup card information.  */
  err = card_info (slot, key_fpr);
  if (err)
    {
      POLDI_LOG (ERR, "Failed to retrieve information from card: %s",
		 gpg_strerror (err));
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Retrieved information"); /* FIXME */
    }

  /* Lookup the Unix username associated with the given key
     fingerprint.  */
  err = keyid_to_username (key_fpr, &login);
  if (err)
    {
      POLDI_LOG (ERR, "Failed to lookup username: %s", gpg_strerror (err));
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Looked up username"); /* FIXME */
    }

  /* Lookup Key.  */
  err = key_get (&key, key_fpr);
  if (err)
    {
      POLDI_LOG (ERR, "Failed to lookup key: %s", gpg_strerror (err));
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Looked up key");
    }

  /* Ask PAM for username.  */
  ret = pam_get_user (pam_handle, (const char **) &username, NULL);
  if (ret != PAM_SUCCESS)
    {
      POLDI_LOG (ERR, "Failed to retrieve username");
      err = GPG_ERR_INTERNAL;	/* errno? */
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Username: %s", username);
    }
  
  /* Compare looked up username with the one retrieved through PAM.  */
  if (strcmp (username, login))
    {
      err = GPG_ERR_WRONG_CARD;
      POLDI_LOG (ERR, "Username mismatch");
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Username matches");
    }

  /* Ask PAM for conv structure.  */
  ret = pam_get_item (pam_handle, PAM_CONV, (const void **) &conv);
  if (ret != PAM_SUCCESS)
    {
      POLDI_LOG (ERR, "Failed to retrieve conversation structure");
      err = GPG_ERR_INTERNAL;
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Retrieved conversation structure");
    }

  /* Ask for PIN.  */
  ret = (*conv->conv) (sizeof (messages) / (sizeof (*messages)), pmessages,
		       &responses, conv->appdata_ptr);
  if (ret != PAM_SUCCESS)
    {
      POLDI_LOG (ERR, "Failed to retrieve PIN from user");
      err = GPG_ERR_INTERNAL;
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Retrieved PIN from user");
    }

  /* Generate challenge.  */
  err = challenge_generate (&challenge, &challenge_n);
  if (err)
    {
      POLDI_LOG (ERR, "Failed to generate challenge: %s", gpg_strerror (err));
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Generated challenge");
    }

  /* Provide PIN.  */
  err = card_pin_provide (slot, responses[0].resp);
  if (err)
    {
      POLDI_LOG (ERR, "Failed to provide PIN: %s", gpg_strerror (err));
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Provided PIN");
    }

  /* Send challenge to card, retrieve signature.  */
  err = card_sign (slot, challenge, challenge_n, &response, &response_n);
  if (err)
    {
      POLDI_LOG (ERR, "Failed to retrieve signature from card: %s",
		 gpg_strerror (err));
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Retrieved signature from card");
    }

  /* Verify response.  */
  err = challenge_verify (key, challenge, challenge_n, response, response_n);
  if (err)
    {
      POLDI_LOG (ERR, "Signature does not match data: %s", gpg_strerror (err));
      goto out;
    }
  else
    {
      if (debug)
	POLDI_LOG (DEBUG, "Signature matches data");
    }

  /* Done.  */

 out:
  if (serialno)
    free (serialno);
  if (login)
    free (login);
  if (response)
    free (response);
  if (challenge)
    free (challenge);
  if (key)
    key_destroy (key);

  if (slot != -1)
    card_close (slot);

  closelog ();

  return err ? PAM_AUTH_ERR : PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pam_handle, int flags, int argc, const char **argv)
{
  /* FIXME?  */
  return PAM_SUCCESS;
}
