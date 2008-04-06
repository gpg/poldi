/* conv.c - PAM conversation abstraction for Poldi.
   Copyright (C) 2004, 2005, 2007, 2008 g10 Code GmbH
 
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include <gpg-error.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "util/util.h"
#include "conv.h"



struct conv_s
{
  const struct pam_conv *pam_conv;
};



/* Create a new PAM conversation object based in PAM_CONV and store it
   in *CONV.  Returns proper error code. */
gpg_error_t
conv_create (conv_t *conv, const struct pam_conv *pam_conv)
{
  conv_t conv_new;
  gpg_error_t err;

  err = 0;

  conv_new = malloc (sizeof (*conv_new));
  if (!conv_new)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  conv_new->pam_conv = pam_conv;
  *conv = conv_new;

 out:

  return err;
}

/* Destroy the conv object CONV.  */
void
conv_destroy (conv_t conv)
{
  if (conv)
    free (conv);
}



/* This function queries the PAM user for input through the
   conversation function CONV; TEXT will be displayed as prompt, the
   user's response will be stored in *RESPONSE.  Returns proper error
   code.  */
static gpg_error_t
ask_user (const struct pam_conv *conv, int secret,
	  const char *text, char **response)
{
  struct pam_message messages[1] = { { 0, text } };
  const struct pam_message *pmessages[1] = { &messages[0] };
  struct pam_response *responses = NULL;
  char *response_new;
  gpg_error_t err;
  int ret;

  if (secret)
    messages[0].msg_style = PAM_PROMPT_ECHO_OFF;
  else
    messages[0].msg_style = PAM_PROMPT_ECHO_ON;
  
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
tell_user (const struct pam_conv *conv, const char *msg)
{
  struct pam_message messages[1] = { { PAM_TEXT_INFO, NULL } };
  const struct pam_message *pmessages[1] = { &messages[0] };
  struct pam_response *responses = NULL;
  gpg_error_t err;
  int ret;

  messages[0].msg = msg;
  
  ret = (*conv->conv) (sizeof (messages) / (sizeof (*messages)), pmessages,
		       &responses, conv->appdata_ptr);
  if (ret != PAM_SUCCESS)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      goto out;
    }

  err = 0;

 out:

  return err;
}

gpg_error_t
conv_tell (conv_t conv, const char *fmt, ...)
{
  gpg_error_t err = 0;
  char *msg = NULL;
  va_list ap;
  int ret;

  va_start (ap, fmt);

  ret = vasprintf (&msg, fmt, ap);
  if (ret < 0)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  err = tell_user (conv->pam_conv, msg);

 out:

  va_end (ap);
  free (msg);

  return err;
}

gpg_error_t
conv_ask (conv_t conv, int ask_secret,
	  char **response, const char *fmt, ...)
{
  gpg_error_t err = 0;
  char *msg = NULL;
  va_list ap;
  int ret;

  va_start (ap, fmt);

  ret = vasprintf (&msg, fmt, ap);
  if (ret < 0)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  err = ask_user (conv->pam_conv, ask_secret, msg, response);

 out:

  va_end (ap);
  free (msg);

  return err;
}

/* END */
