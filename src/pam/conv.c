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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include <gpg-error.h>
#include <security/pam_modules.h>

#include "common/poldi-ctx.h"

#include "conv.h"

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
conv_tell (poldi_ctx_t ctx, const char *fmt, ...)
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

  err = tell_user (ctx->pam_conv, msg);

 out:

  va_end (ap);
  free (msg);

  return err;
}

gpg_error_t
conv_ask (poldi_ctx_t ctx, int ask_secret,
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

  err = ask_user (ctx->pam_conv, ask_secret, msg, response);

 out:

  va_end (ap);
  free (msg);

  return err;
}

