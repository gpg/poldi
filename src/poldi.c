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

#define PAM_SM_AUTH

#include <security/pam_modules.h>

#include "card.h"
#include "support.h"

/* Uaaahahahh, ich will dir einloggen!  */
PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pam_handle, int flags, int argc, const char **argv)
{
  struct pam_message messages[1] = { { PAM_PROMPT_ECHO_OFF,
				       "PIN: " } };
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
  size_t login_n = 0;
  int ret = PAM_SUCCESS;
  
  /* Ask PAM for conv structure.  */
  ret = pam_get_item (pam_handle, PAM_CONV, (const void **) &conv);
  if (ret != PAM_SUCCESS)
    {
      err = GPG_ERR_INTERNAL;
      goto out;
    }
  
  /* Open card.  */
  err = card_open (NULL, &slot, &serialno, &serialno_n);
  if (err)
    goto out;

  /* Lookup card information.  */
  err = card_info (slot, key_fpr, &login, &login_n);
  if (err)
    goto out;

  ret = pam_get_item (pam_handle, PAM_USER, (const void **) &username);
  if (ret != PAM_SUCCESS)
    err = GPG_ERR_INTERNAL;
  else if (strcmp (username, login))
    /* User identity does not match card login data.  */
    err = GPG_ERR_INTERNAL;
  if (err)
    goto out;

  /* Lookup Key.  */
  err = key_get (&key, key_fpr);
  if (err)
    goto out;

  /* Generate challenge.  */
  err = challenge_generate (&challenge, &challenge_n);
  if (err)
    goto out;

  /* Ask for PIN.  */
  ret = (*conv->conv) (sizeof (messages) / (sizeof (*messages)), pmessages,
		       &responses, conv->appdata_ptr);
  if (ret != PAM_SUCCESS)
    err = GPG_ERR_INTERNAL;
  else
    err = card_pin_provide (slot, responses[0].resp);
  if (err)
    goto out;

  /* Send challenge to card.  */
  err = card_sign (slot, challenge, challenge_n, &response, &response_n);
  if (err)
    goto out;

  /* Verify response.  */
  err = challenge_verify (key, challenge, challenge_n, response, response_n);
  if (err)
    goto out;

  /* Done.  */

 out:
  if (response)
    free (response);
  if (challenge)
    free (challenge);
  if (key)
    key_destroy (key);

  return err ? PAM_AUTH_ERR : PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pam_handle, int flags, int argc, const char **argv)
{
  /* FIXME?  */
  return PAM_SUCCESS;
}
