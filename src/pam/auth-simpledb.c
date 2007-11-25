/* auth-simpledb.c - simple authentication backend for Poldi.
 * Copyright (C) 2004, 2005, 2007 g10 Code GmbH
 *
 * This file is part of Poldi.
 *
 * Poldi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Poldi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>

// FIXME, define required?
#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include <gpg-error.h>
#include <gcrypt.h>

#include "poldi-ctx.h"

#include "scd/poldi-scd.h"
#include "common/usersdb.h"
#include "common/util.h"
#include "common/support.h"
#include "getpin-cb.h"
#include "wait-for-card.h"
#include "conv.h"

#include "pam-util.h"

static struct scd_cardinfo cardinfo_null;

int
auth_method_simpledb (poldi_ctx_t ctx)
{
  unsigned char *challenge;
  unsigned char *response;
  size_t challenge_n;
  size_t response_n;
  gcry_sexp_t key;
  gpg_error_t err;
  const char *username;
  char *account;
  int ret;
  struct scd_cardinfo cardinfo;

  challenge = NULL;
  response = NULL;
  cardinfo = cardinfo_null;
  username = NULL;
  account = NULL;
  key = NULL;

  /*** Ask PAM for username. ***/

  err = retrieve_username_from_pam (ctx, &username);

  /*
   * Process authentication request.
   */

  /* Wait for card.  */
  err = wait_for_card (ctx, ctx->wait_timeout);
  if (err)
    goto out;

  err = poldi_scd_learn (ctx, &cardinfo);
  if (err)
    goto out;

  if (! username)
    {
      /* We didn't receive a username from PAM, therefore we need to
	 figure it out somehow...  */

      err = usersdb_lookup_by_serialno (cardinfo.serialno, &account);
      if (gcry_err_code (err) == GPG_ERR_AMBIGUOUS_NAME)
	err = conv_ask (ctx, 0, &account, "Need to figure out username: ");

      if (err)
	goto out;

      username = account;
    }

  /* FIXME: quiet?  */
  conv_tell (ctx, "Trying authentication as user `%s'...", username);

  /* Check if the given account is associated with the serial
     number.  */
  err = usersdb_check (cardinfo.serialno, username);
  if (err)
    {
      conv_tell (ctx, "Serial no %s is not associated with %s\n",
		 cardinfo.serialno, username);
      err = gcry_error (GPG_ERR_INV_NAME);
      goto out;
    }

  /* Retrieve key belonging to card.  */
  err = key_lookup_by_serialno (cardinfo.serialno, &key);
  if (err)
    goto out;

  /* Inform user about inserted card.  */

  err = conv_tell (ctx, "Serial no: %s", cardinfo.serialno);
  if (err)
    {
      /* FIXME?? do we need this?  */
      log_error ("Error: failed to inform user about inserted card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Generate challenge.  */
  err = challenge_generate (&challenge, &challenge_n);
  if (err)
    {
      log_error ("Error: failed to generate challenge: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Let card sign the challenge.  */
  err = poldi_scd_pksign (ctx, "OPENPGP.3",
			  getpin_cb, ctx,
			  challenge, challenge_n,
			  &response, &response_n);
  if (err)
    {
      log_error ("Error: failed to retrieve challenge signature "
		 "from card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /* Verify response.  */
  err = challenge_verify (key, challenge, challenge_n, response, response_n);
  if (err)
    {
      log_error ("Error: failed to verify challenge\n");
      goto out;
    }

  
  if (username == account)
    {
      err = send_username_to_pam (ctx, username);
      if (err)
	goto out;
    }

  /* Done.  */

 out:

  /* Release resources.  */
  gcry_sexp_release (key);
  poldi_scd_release_cardinfo (&cardinfo);
  if (username == account)
    free (account);

  /* Log result.  */
  if (err)
    log_error ("Failure: %s\n", gpg_strerror (err));
  else
    log_info ("Success\n");

  free (challenge);
  free (response);

  return !err;
}
