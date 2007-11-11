/* auth-x509.c - x509 authentication backend for Poldi.
 * Copyright (C) 2007 g10 Code GmbH
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
#include <stdio.h>		/* FIXME, so far only required for
				   ksba.h. */
#include <ksba.h>

#include "poldi-ctx.h"

#include "scd/poldi-scd.h"
#include "dirmngr/poldi-dirmngr.h"
#include "common/usersdb.h"
#include "common/util.h"
#include "common/support.h"
#include "getpin-cb.h"
#include "wait-for-card.h"
#include "conv.h"

static struct scd_cardinfo cardinfo_null;

static gpg_error_t
extract_public_key_from_cert (poldi_ctx_t ctx, ksba_cert_t cert,
			      gcry_sexp_t *public_key)
{
  gcry_sexp_t pubkey;
  gpg_error_t err;
  size_t sexp_len;
  ksba_sexp_t ksba_sexp;

  pubkey = NULL;
  ksba_sexp = NULL;
  err = 0;

  ksba_sexp = ksba_cert_get_public_key (cert);
  sexp_len = gcry_sexp_canon_len (ksba_sexp, 0, NULL, NULL);
  if (!sexp_len)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      err = GPG_ERR_BUG;
      goto out;
    }

  err = gcry_sexp_sscan (&pubkey, NULL, (char *) ksba_sexp, sexp_len);
  if (err)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (err));
      goto out;
    }

  *public_key = pubkey;

 out:

  ksba_free (ksba_sexp);

  return err;
}

static gpg_error_t
verify_challenge_sig (poldi_ctx_t ctx, ksba_cert_t cert,
		      void *challenge, size_t challenge_n,
		      void *response, size_t response_n)
{
  gcry_sexp_t pubkey;
  gpg_error_t err;

  pubkey = NULL;

  err = extract_public_key_from_cert (ctx, cert, &pubkey);
  if (err)
    goto out;

  /* FIXME: probably we need to pass some flags to challenge_verify
     for x509 verification, no? */
  err = challenge_verify (pubkey, challenge, challenge_n,
			  response, response_n);

 out:

  gcry_sexp_release (pubkey);

  return err;
}


int
auth_method_x509 (poldi_ctx_t ctx)
{
  unsigned char *challenge;
  unsigned char *response;
  size_t challenge_n;
  size_t response_n;
  gpg_error_t err;
  const void *username_void;
  const char *username;
  int ret;
  struct scd_cardinfo cardinfo;
  ksba_cert_t cert;

  cardinfo = cardinfo_null;
  challenge = NULL;
  response = NULL;
  username = NULL;
  cert = NULL;

  /*** Connect to Dirmngr. ***/

  err = poldi_dirmngr_connect (ctx, getenv ("DIRMNGR_INFO"), NULL, 0);
  if (err)
    goto out;

  /*** Ask PAM for username. ***/

  ret = pam_get_item (ctx->pam_handle, PAM_USER, &username_void);
  if (ret != PAM_SUCCESS)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      goto out;
    }
  username = username_void;

  /*
   * Receive card info.
   */

  err = poldi_scd_learn (ctx, &cardinfo);
  if (err)
    goto out;

  if (ctx->debug)
    {
      conv_tell (ctx, "NOTE: debug mode activated, overwriting pubkey url!\n");

      xfree (cardinfo.pubkey_url);
      cardinfo.pubkey_url = xstrdup ("ldap://...");
    }

  conv_tell (ctx,
	     "SERIALNO: %s\n"
	     "PUBKEY-URL: %s\n",
	     cardinfo.serialno, cardinfo.pubkey_url);

  /*** Fetch certificate. ***/

  if ((!cardinfo.pubkey_url) || (strncmp (cardinfo.pubkey_url, "ldap://", 7) != 0))
    {
      conv_tell (ctx, "`%s' is no valid ldap url...\n", cardinfo.pubkey_url);
      err = GPG_ERR_GENERAL;	/* FIXME!! NO_CERT or something? */
      goto out;
    }

  conv_tell (ctx, "Looking up `%s' through dirmngr...\n", cardinfo.pubkey_url);

  err = poldi_dirmngr_lookup_url (ctx, cardinfo.pubkey_url, &cert);
  if (err)
    {
      conv_tell (ctx, "failed! dirmngr said: %s\n", gpg_strerror (err));
      goto out;
    }

  /*** Valide cert. ***/

  /* FIXME: specify issuer? */

  err = poldi_dirmngr_isvalid (ctx, cert);
  if (err)
    goto out;

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

  err = verify_challenge_sig (ctx, cert,
			      challenge, challenge_n,
			      response, response_n);
  if (err)
    {
      log_error ("Error: failed to verify challenge\n");
      goto out;
    }

  /* FIXME: how to handle username?  */

  conv_tell (ctx, "FIXME: authentication not implemented yet\n");
  err = GPG_ERR_NOT_IMPLEMENTED;

 out:

  /* Release resources.  */
  poldi_scd_release_cardinfo (&cardinfo);

  /* Log result.  */
  if (err)
    log_error ("Failure: %s\n", gpg_strerror (err));
  else
    log_info ("Success\n");

  return !err;
}
