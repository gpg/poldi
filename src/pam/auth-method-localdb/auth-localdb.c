/* auth-localdb.c - localdb authentication method for Poldi.
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

#include <gpg-error.h>
#include <gcrypt.h>

#include <stdlib.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "auth-methods.h"
#include "conv.h"
#include "util/util.h"

#include "scd/scd.h"
#include "util/support.h"
#include "auth-support/ctx.h"
#include "auth-support/wait-for-card.h"
#include "auth-support/pam-util.h"

#include "usersdb.h"
#include "key-lookup.h"



#if 0
/* Currently, the localdb method doesn't require a special cookie. */

static gpg_error_t
auth_method_localdb_init (void **cookie)
{
  *cookie = NULL;
  return 0;
}

static void
auth_method_localdb_deinit (void *cookie)
{
  return;
}

static gpg_error_t
auth_method_localdb_parsecb (ARGPARSE_ARGS *parg, void *cookie)
{
  /* Do we support any localdb specific options?  */
  return 0;
}

#endif



/* Entry point for the local-db authentication method. Returns TRUE
   (1) if authentication succeeded and FALSE (0) otherwise. */
static int
auth_method_localdb_auth_do (poldi_ctx_t ctx,
			     const char *username_desired, char **username_authenticated)
{
  unsigned char *challenge;
  unsigned char *response;
  size_t challenge_n;
  size_t response_n;
  gcry_sexp_t key;
  gpg_error_t err;
  char *card_username;
  const char *username;

  card_username = NULL;

  challenge = NULL;
  response = NULL;
  username = NULL;
  key = NULL;

  /*
   * Process authentication request.
   */

  if (!username_desired)
    {
      /* We didn't receive a username from PAM, therefore we need to
	 figure it out somehow. We use the card's serialno for looking
	 up an account.  */

      err = usersdb_lookup_by_serialno (ctx->cardinfo.serialno, &card_username);
      if (gcry_err_code (err) == GPG_ERR_AMBIGUOUS_NAME)
	/* Given serialno is associated with more than one account =>
	   ask the user for desired identity.  */
	err = conv_ask (ctx->conv, 0, &card_username,
			_("Please enter username: "));

      if (err)
	goto out;

      username = card_username;
    }
  else
    username = username_desired;

  if (ctx->debug)
    conv_tell (ctx->conv,
	       _("Trying authentication as user `%s'..."), username);

  /* Verify (again) that the given account is associated with the
     serial number.  */
  err = usersdb_check (ctx->cardinfo.serialno, username);
  if (err)
    {
      conv_tell (ctx->conv,
		 _("Serial number %s is not associated with user %s"),
		 ctx->cardinfo.serialno, username);
      err = gcry_error (GPG_ERR_INV_NAME);
      goto out;
    }

  /* Retrieve key belonging to card.  */
  err = key_lookup_by_serialno (ctx, ctx->cardinfo.serialno, &key);
  if (err)
    goto out;

  /* Generate challenge.  */
  err = challenge_generate (&challenge, &challenge_n);
  if (err)
    {
      log_msg_error (ctx->loghandle,
		     _("failed to generate challenge: %s"),
		     gpg_strerror (err));
      goto out;
    }

  /* Let card sign the challenge.  */
  err = scd_pksign (ctx->scd, "OPENPGP.3",
		    challenge, challenge_n,
		    &response, &response_n);
  if (err)
    {
      log_msg_error (ctx->loghandle,
		     _("failed to retrieve challenge signature from card: %s"),
		     gpg_strerror (err));
      goto out;
    }

  /* Verify response.  */
  err = challenge_verify (key, challenge, challenge_n, response, response_n);
  if (err)
    {
      log_msg_error (ctx->loghandle,
		     _("failed to verify challenge"));
      goto out;
    }

  if (!username_desired)
    *username_authenticated = card_username;

  /* Done.  */

 out:

  /* Release resources.  */
  gcry_sexp_release (key);

  challenge_release (challenge);
  xfree (response);

  if (err)
    xfree (card_username);

  return !err;
}

/* Entry point for the local-db authentication method. Returns TRUE
   (1) if authentication succeeded and FALSE (0) otherwise. */
static int
auth_method_localdb_auth (poldi_ctx_t ctx, void *cookie, char **username)
{
  return auth_method_localdb_auth_do (ctx, NULL, username);
}

/* Entry point for the local-db authentication method. Returns TRUE
   (1) if authentication succeeded and FALSE (0) otherwise. */
static int
auth_method_localdb_auth_as (poldi_ctx_t ctx, void *cookie, const char *username)
{
  return auth_method_localdb_auth_do (ctx, username, NULL);
}




struct auth_method_s auth_method_localdb =
  {
    NULL,
    NULL,
    auth_method_localdb_auth,
    auth_method_localdb_auth_as,
    NULL,
    NULL,
    NULL
  };
